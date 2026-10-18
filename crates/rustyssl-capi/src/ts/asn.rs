//! The Time-Stamp Protocol's structures and their ASN.1 (`ts_asn1.c`, RFC 3161):
//! MessageImprint, TimeStampReq, Accuracy, TSTInfo, PKIStatusInfo, and TimeStampResp, whose
//! TSTInfo is decoded from its token when it is.
//!
//! The structures are opaque in `ts.h`; their layouts here are OpenSSL's internal ones
//! (`ts_local.h`), which the templates describe.

use core::ffi::{c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_BOOLEAN, ASN1_GENERALIZEDTIME, ASN1_INTEGER, ASN1_ITEM, ASN1_OBJECT,
    ASN1_OCTET_STRING, ASN1_OP_D2I_POST, ASN1_OP_FREE_POST, ASN1_OP_NEW_POST, ASN1_TFLG_IMPLICIT,
    ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF, ASN1_VALUE, BIO, ERR_LIB_ASN1, ERR_LIB_TS,
    GENERAL_NAME, NID_id_smime_ct_TSTInfo, NID_pkcs7_signed, PKCS7, TS_ACCURACY, TS_MSG_IMPRINT,
    TS_R_BAD_PKCS7_TYPE, TS_R_BAD_TYPE, TS_R_DETACHED_CONTENT, TS_R_PKCS7_TO_TS_TST_INFO_FAILED,
    TS_R_TOKEN_NOT_PRESENT, TS_R_TOKEN_PRESENT, TS_REQ, TS_RESP, TS_STATUS_INFO, TS_TST_INFO,
    V_ASN1_OCTET_STRING, X509_ALGOR,
};

use crate::asn1::integer::ASN1_INTEGER_get;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio, ASN1_item_d2i_fp, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_FBOOLEAN_it, ASN1_GENERALIZEDTIME_it, ASN1_INTEGER_it, ASN1_OBJECT_it,
    ASN1_OCTET_STRING_it, ASN1_UTF8STRING_it, X509_ALGOR_it,
};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::asn1::tpl::statics::{Aux, Templates, aux, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Item, template_at};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::objects::OBJ_obj2nid;
use crate::pkcs7::{PKCS7_ctrl, PKCS7_it};
use crate::x509::ext::X509_EXTENSION_it;
use crate::x509v3::genn::GENERAL_NAME_it;

/// A stack, as `STACK_OF(...)` is to C.
pub(crate) type Stack = rustyssl_abi::OPENSSL_STACK;

#[repr(C)]
pub(crate) struct MsgImprint {
    pub(crate) hash_algo: *mut X509_ALGOR,
    pub(crate) hashed_msg: *mut ASN1_OCTET_STRING,
}

#[repr(C)]
pub(crate) struct Resp {
    pub(crate) status_info: *mut StatusInfo,
    pub(crate) token: *mut PKCS7,
    /// The token's TSTInfo, decoded from it; not encoded.
    pub(crate) tst_info: *mut TstInfo,
}

#[repr(C)]
pub(crate) struct Req {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) msg_imprint: *mut MsgImprint,
    pub(crate) policy_id: *mut ASN1_OBJECT,
    pub(crate) nonce: *mut ASN1_INTEGER,
    pub(crate) cert_req: ASN1_BOOLEAN,
    pub(crate) extensions: *mut Stack,
}

#[repr(C)]
pub(crate) struct Accuracy {
    pub(crate) seconds: *mut ASN1_INTEGER,
    pub(crate) millis: *mut ASN1_INTEGER,
    pub(crate) micros: *mut ASN1_INTEGER,
}

#[repr(C)]
pub(crate) struct TstInfo {
    pub(crate) version: *mut ASN1_INTEGER,
    pub(crate) policy_id: *mut ASN1_OBJECT,
    pub(crate) msg_imprint: *mut MsgImprint,
    pub(crate) serial: *mut ASN1_INTEGER,
    pub(crate) time: *mut ASN1_GENERALIZEDTIME,
    pub(crate) accuracy: *mut Accuracy,
    pub(crate) ordering: ASN1_BOOLEAN,
    pub(crate) nonce: *mut ASN1_INTEGER,
    pub(crate) tsa: *mut GENERAL_NAME,
    pub(crate) extensions: *mut Stack,
}

#[repr(C)]
pub(crate) struct StatusInfo {
    pub(crate) status: *mut ASN1_INTEGER,
    pub(crate) text: *mut Stack,
    pub(crate) failure_info: *mut ASN1_BIT_STRING,
}

const SIMPLE: c_int = 0;
const OPT: c_int = ASN1_TFLG_OPTIONAL;
const IMP_OPT: c_int = ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL;
const EXP_OPT: c_int = rustyssl_abi::ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL;
const SEQ_OF_OPT: c_int = ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;
const IMP_SEQ_OF_OPT: c_int = ASN1_TFLG_IMPLICIT | ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL;

macro_rules! tt {
    ($t:ty; $($flags:expr, $tag:expr, $field:ident, $name:literal, $it:expr;)*) => {
        Templates([$(template_at($flags, $tag, offset_of!($t, $field), $name, $it),)*])
    };
}

static MI_TT: Templates<2> = tt![MsgImprint;
    SIMPLE, 0, hash_algo, c"hash_algo", X509_ALGOR_it;
    SIMPLE, 0, hashed_msg, c"hashed_msg", ASN1_OCTET_STRING_it;
];

static REQ_TT: Templates<6> = tt![Req;
    SIMPLE, 0, version, c"version", ASN1_INTEGER_it;
    SIMPLE, 0, msg_imprint, c"msg_imprint", msg_imprint_it;
    OPT, 0, policy_id, c"policy_id", ASN1_OBJECT_it;
    OPT, 0, nonce, c"nonce", ASN1_INTEGER_it;
    OPT, 0, cert_req, c"cert_req", ASN1_FBOOLEAN_it;
    IMP_SEQ_OF_OPT, 0, extensions, c"extensions", X509_EXTENSION_it;
];

static ACC_TT: Templates<3> = tt![Accuracy;
    OPT, 0, seconds, c"seconds", ASN1_INTEGER_it;
    IMP_OPT, 0, millis, c"millis", ASN1_INTEGER_it;
    IMP_OPT, 1, micros, c"micros", ASN1_INTEGER_it;
];

static TST_TT: Templates<10> = tt![TstInfo;
    SIMPLE, 0, version, c"version", ASN1_INTEGER_it;
    SIMPLE, 0, policy_id, c"policy_id", ASN1_OBJECT_it;
    SIMPLE, 0, msg_imprint, c"msg_imprint", msg_imprint_it;
    SIMPLE, 0, serial, c"serial", ASN1_INTEGER_it;
    SIMPLE, 0, time, c"time", ASN1_GENERALIZEDTIME_it;
    OPT, 0, accuracy, c"accuracy", accuracy_it;
    OPT, 0, ordering, c"ordering", ASN1_FBOOLEAN_it;
    OPT, 0, nonce, c"nonce", ASN1_INTEGER_it;
    EXP_OPT, 0, tsa, c"tsa", GENERAL_NAME_it;
    IMP_SEQ_OF_OPT, 1, extensions, c"extensions", X509_EXTENSION_it;
];

static SI_TT: Templates<3> = tt![StatusInfo;
    SIMPLE, 0, status, c"status", ASN1_INTEGER_it;
    SEQ_OF_OPT, 0, text, c"text", ASN1_UTF8STRING_it;
    OPT, 0, failure_info, c"failure_info", ASN1_BIT_STRING_it;
];

static RESP_TT: Templates<2> = tt![Resp;
    SIMPLE, 0, status_info, c"status_info", status_info_it;
    OPT, 0, token, c"token", PKCS7_it;
];

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_TS, reason, f);
}

/// `ts_resp_set_tst_info`: the token's TSTInfo, decoded, if the status says it should be
/// there.
fn set_tst_info(a: &mut Resp) -> bool {
    const F: &str = "ts_resp_set_tst_info";
    // SAFETY: its status info, made with it, and its status.
    let status =
        unsafe { a.status_info.as_ref() }.map_or(0, |s| unsafe { ASN1_INTEGER_get(s.status) });
    if !a.token.is_null() {
        if status != 0 && status != 1 {
            raise(TS_R_TOKEN_PRESENT, F);
            return false;
        }
        // SAFETY: the response's own TSTInfo, or NULL.
        unsafe { TS_TST_INFO_free(a.tst_info.cast()) };
        // SAFETY: its token.
        a.tst_info = unsafe { PKCS7_to_TS_TST_INFO(a.token) }.cast();
        if a.tst_info.is_null() {
            raise(TS_R_PKCS7_TO_TS_TST_INFO_FAILED, F);
            return false;
        }
    } else if status == 0 || status == 1 {
        raise(TS_R_TOKEN_NOT_PRESENT, F);
        return false;
    }
    true
}

ffi_callback! {
    /// `ts_resp_cb`: the response's TSTInfo, cleared when made, freed with it, and decoded from
    /// its token when it is.
    ///
    /// # Safety
    /// As the template engine calls it.
    pub(crate) unsafe extern "C" fn ts_resp_cb(op: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the value's slot; the value, NULL or live.
        let Some(r) = (unsafe { pval.as_ref() }).and_then(|&v| unsafe { v.cast::<Resp>().as_mut() }) else {
            return 1;
        };
        match op {
            ASN1_OP_NEW_POST => r.tst_info = ptr::null_mut(),
            // SAFETY: its own TSTInfo, or NULL.
            ASN1_OP_FREE_POST => unsafe { TS_TST_INFO_free(r.tst_info.cast()) },
            ASN1_OP_D2I_POST if !set_tst_info(r) => return 0,
            _ => {}
        }
        1
    }
}

static RESP_AUX: Aux = aux(ts_resp_cb);

macro_rules! private_item {
    ($($(#[$attr:meta])* fn $name:ident = $item:expr;)*) => {$(
        $(#[$attr])*
        pub(crate) unsafe extern "C" fn $name() -> *const ASN1_ITEM {
            static ITEM: Item = $item;
            &raw const ITEM.0
        }
    )*};
}

private_item! {
    /// `TS_MSG_IMPRINT_it`, which OpenSSL keeps static.
    fn msg_imprint_it = sequence::<MsgImprint, 2>(&MI_TT, None, c"TS_MSG_IMPRINT");
    /// `TS_REQ_it`.
    fn req_it = sequence::<Req, 6>(&REQ_TT, None, c"TS_REQ");
    /// `TS_ACCURACY_it`.
    fn accuracy_it = sequence::<Accuracy, 3>(&ACC_TT, None, c"TS_ACCURACY");
    /// `TS_TST_INFO_it`.
    fn tst_info_it = sequence::<TstInfo, 10>(&TST_TT, None, c"TS_TST_INFO");
    /// `TS_STATUS_INFO_it`.
    fn status_info_it = sequence::<StatusInfo, 3>(&SI_TT, None, c"TS_STATUS_INFO");
    /// `TS_RESP_it`.
    fn resp_it = sequence::<Resp, 2>(&RESP_TT, Some(&RESP_AUX), c"TS_RESP");
}

/// A new value of the item, or NULL.
fn new_of(it: unsafe extern "C" fn() -> *const ASN1_ITEM) -> *mut c_void {
    // SAFETY: no preconditions.
    let i = unsafe { it() };
    // SAFETY: the item.
    unsafe { ASN1_item_new(i) }.cast()
}

/// Frees a value of the item (nothing for NULL).
///
/// # Safety
/// `v` is NULL or a value of the item not used after.
unsafe fn free_of(v: *mut c_void, it: unsafe extern "C" fn() -> *const ASN1_ITEM) {
    // SAFETY: no preconditions.
    let i = unsafe { it() };
    // SAFETY: the caller's guarantee.
    unsafe { ASN1_item_free(v.cast(), i) };
}

/// Encodes a value of the item.
///
/// # Safety
/// As for `ASN1_item_i2d`.
unsafe fn i2d_of(
    v: *const c_void,
    out: *mut *mut u8,
    it: unsafe extern "C" fn() -> *const ASN1_ITEM,
) -> c_int {
    // SAFETY: no preconditions.
    let i = unsafe { it() };
    // SAFETY: the caller's guarantee.
    unsafe { ASN1_item_i2d(v.cast(), out, i) }
}

/// Decodes a value of the item.
///
/// # Safety
/// As for `ASN1_item_d2i`.
unsafe fn d2i_of(
    a: *mut *mut c_void,
    pp: *mut *const u8,
    len: core::ffi::c_long,
    it: unsafe extern "C" fn() -> *const ASN1_ITEM,
) -> *mut c_void {
    // SAFETY: no preconditions.
    let i = unsafe { it() };
    // SAFETY: the caller's guarantee.
    unsafe { crate::asn1::tpl::decode::ASN1_item_d2i(a.cast(), pp, len, i) }.cast()
}

/// A copy of a value of the item, or NULL.
///
/// # Safety
/// `v` is NULL or a live value of the item.
unsafe fn dup_of(v: *const c_void, it: unsafe extern "C" fn() -> *const ASN1_ITEM) -> *mut c_void {
    // SAFETY: no preconditions.
    let i = unsafe { it() };
    // SAFETY: the caller's guarantee.
    unsafe { ASN1_item_dup(i, v) }
}

ffi_export! {
    /// A new, empty message imprint, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn TS_MSG_IMPRINT_new() -> *mut TS_MSG_IMPRINT
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        new_of(msg_imprint_it).cast()
    }
}

ffi_export! {
    /// Frees a message imprint (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a message imprint not used after.
    pub unsafe extern "C" fn TS_MSG_IMPRINT_free(a: *mut TS_MSG_IMPRINT)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_of(a.cast(), msg_imprint_it) };
    }
}

ffi_export! {
    /// Encodes a message imprint (`ASN1_item_i2d`).
    ///
    /// # Safety
    /// As for `ASN1_item_i2d`.
    pub unsafe extern "C" fn i2d_TS_MSG_IMPRINT(a: *const TS_MSG_IMPRINT, pp: *mut *mut u8) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_of(a.cast(), pp, msg_imprint_it) }
    }
}

ffi_export! {
    /// Decodes a message imprint (`ASN1_item_d2i`).
    ///
    /// # Safety
    /// As for `ASN1_item_d2i`.
    pub unsafe extern "C" fn d2i_TS_MSG_IMPRINT(a: *mut *mut TS_MSG_IMPRINT, pp: *mut *const u8, length: core::ffi::c_long) -> *mut TS_MSG_IMPRINT
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_of(a.cast(), pp, length, msg_imprint_it) }.cast()
    }
}

ffi_export! {
    /// A copy of the message imprint, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live message imprint.
    pub unsafe extern "C" fn TS_MSG_IMPRINT_dup(a: *const TS_MSG_IMPRINT) -> *mut TS_MSG_IMPRINT
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), msg_imprint_it) }.cast()
    }
}

ffi_export! {
    /// Reads a message imprint's DER from a BIO, or NULL.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` NULL or holding NULL or a live message imprint.
    pub unsafe extern "C" fn d2i_TS_MSG_IMPRINT_bio(bp: *mut BIO, a: *mut *mut TS_MSG_IMPRINT) -> *mut TS_MSG_IMPRINT
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { msg_imprint_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_bio(i, bp, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a message imprint's DER to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` a live message imprint.
    pub unsafe extern "C" fn i2d_TS_MSG_IMPRINT_bio(bp: *mut BIO, a: *const TS_MSG_IMPRINT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { msg_imprint_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(i, bp, a.cast()) }
    }
}

ffi_export! {
    /// Reads a message imprint's DER from a file, or NULL.
    ///
    /// # Safety
    /// `fp` is a live file; `a` NULL or holding NULL or a live message imprint.
    pub unsafe extern "C" fn d2i_TS_MSG_IMPRINT_fp(fp: *mut FILE, a: *mut *mut TS_MSG_IMPRINT) -> *mut TS_MSG_IMPRINT
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { msg_imprint_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp(i, fp, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a message imprint's DER to a file: 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live file; `a` a live message imprint.
    pub unsafe extern "C" fn i2d_TS_MSG_IMPRINT_fp(fp: *mut FILE, a: *const TS_MSG_IMPRINT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { msg_imprint_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(i, fp, a.cast()) }
    }
}

ffi_export! {
    /// A new, empty time-stamp request, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn TS_REQ_new() -> *mut TS_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        new_of(req_it).cast()
    }
}

ffi_export! {
    /// Frees a time-stamp request (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a time-stamp request not used after.
    pub unsafe extern "C" fn TS_REQ_free(a: *mut TS_REQ)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_of(a.cast(), req_it) };
    }
}

ffi_export! {
    /// Encodes a time-stamp request (`ASN1_item_i2d`).
    ///
    /// # Safety
    /// As for `ASN1_item_i2d`.
    pub unsafe extern "C" fn i2d_TS_REQ(a: *const TS_REQ, pp: *mut *mut u8) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_of(a.cast(), pp, req_it) }
    }
}

ffi_export! {
    /// Decodes a time-stamp request (`ASN1_item_d2i`).
    ///
    /// # Safety
    /// As for `ASN1_item_d2i`.
    pub unsafe extern "C" fn d2i_TS_REQ(a: *mut *mut TS_REQ, pp: *mut *const u8, length: core::ffi::c_long) -> *mut TS_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_of(a.cast(), pp, length, req_it) }.cast()
    }
}

ffi_export! {
    /// A copy of the time-stamp request, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live time-stamp request.
    pub unsafe extern "C" fn TS_REQ_dup(a: *const TS_REQ) -> *mut TS_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), req_it) }.cast()
    }
}

ffi_export! {
    /// Reads a time-stamp request's DER from a BIO, or NULL.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` NULL or holding NULL or a live time-stamp request.
    pub unsafe extern "C" fn d2i_TS_REQ_bio(bp: *mut BIO, a: *mut *mut TS_REQ) -> *mut TS_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { req_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_bio(i, bp, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a time-stamp request's DER to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` a live time-stamp request.
    pub unsafe extern "C" fn i2d_TS_REQ_bio(bp: *mut BIO, a: *const TS_REQ) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { req_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(i, bp, a.cast()) }
    }
}

ffi_export! {
    /// Reads a time-stamp request's DER from a file, or NULL.
    ///
    /// # Safety
    /// `fp` is a live file; `a` NULL or holding NULL or a live time-stamp request.
    pub unsafe extern "C" fn d2i_TS_REQ_fp(fp: *mut FILE, a: *mut *mut TS_REQ) -> *mut TS_REQ
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { req_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp(i, fp, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a time-stamp request's DER to a file: 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live file; `a` a live time-stamp request.
    pub unsafe extern "C" fn i2d_TS_REQ_fp(fp: *mut FILE, a: *const TS_REQ) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { req_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(i, fp, a.cast()) }
    }
}

ffi_export! {
    /// A new, empty accuracy, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn TS_ACCURACY_new() -> *mut TS_ACCURACY
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        new_of(accuracy_it).cast()
    }
}

ffi_export! {
    /// Frees a accuracy (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a accuracy not used after.
    pub unsafe extern "C" fn TS_ACCURACY_free(a: *mut TS_ACCURACY)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_of(a.cast(), accuracy_it) };
    }
}

ffi_export! {
    /// Encodes a accuracy (`ASN1_item_i2d`).
    ///
    /// # Safety
    /// As for `ASN1_item_i2d`.
    pub unsafe extern "C" fn i2d_TS_ACCURACY(a: *const TS_ACCURACY, pp: *mut *mut u8) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_of(a.cast(), pp, accuracy_it) }
    }
}

ffi_export! {
    /// Decodes a accuracy (`ASN1_item_d2i`).
    ///
    /// # Safety
    /// As for `ASN1_item_d2i`.
    pub unsafe extern "C" fn d2i_TS_ACCURACY(a: *mut *mut TS_ACCURACY, pp: *mut *const u8, length: core::ffi::c_long) -> *mut TS_ACCURACY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_of(a.cast(), pp, length, accuracy_it) }.cast()
    }
}

ffi_export! {
    /// A copy of the accuracy, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live accuracy.
    pub unsafe extern "C" fn TS_ACCURACY_dup(a: *const TS_ACCURACY) -> *mut TS_ACCURACY
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), accuracy_it) }.cast()
    }
}

ffi_export! {
    /// A new, empty TSTInfo, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn TS_TST_INFO_new() -> *mut TS_TST_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        new_of(tst_info_it).cast()
    }
}

ffi_export! {
    /// Frees a TSTInfo (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a TSTInfo not used after.
    pub unsafe extern "C" fn TS_TST_INFO_free(a: *mut TS_TST_INFO)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_of(a.cast(), tst_info_it) };
    }
}

ffi_export! {
    /// Encodes a TSTInfo (`ASN1_item_i2d`).
    ///
    /// # Safety
    /// As for `ASN1_item_i2d`.
    pub unsafe extern "C" fn i2d_TS_TST_INFO(a: *const TS_TST_INFO, pp: *mut *mut u8) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_of(a.cast(), pp, tst_info_it) }
    }
}

ffi_export! {
    /// Decodes a TSTInfo (`ASN1_item_d2i`).
    ///
    /// # Safety
    /// As for `ASN1_item_d2i`.
    pub unsafe extern "C" fn d2i_TS_TST_INFO(a: *mut *mut TS_TST_INFO, pp: *mut *const u8, length: core::ffi::c_long) -> *mut TS_TST_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_of(a.cast(), pp, length, tst_info_it) }.cast()
    }
}

ffi_export! {
    /// A copy of the TSTInfo, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_dup(a: *const TS_TST_INFO) -> *mut TS_TST_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), tst_info_it) }.cast()
    }
}

ffi_export! {
    /// Reads a TSTInfo's DER from a BIO, or NULL.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` NULL or holding NULL or a live TSTInfo.
    pub unsafe extern "C" fn d2i_TS_TST_INFO_bio(bp: *mut BIO, a: *mut *mut TS_TST_INFO) -> *mut TS_TST_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { tst_info_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_bio(i, bp, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a TSTInfo's DER to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` a live TSTInfo.
    pub unsafe extern "C" fn i2d_TS_TST_INFO_bio(bp: *mut BIO, a: *const TS_TST_INFO) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { tst_info_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(i, bp, a.cast()) }
    }
}

ffi_export! {
    /// Reads a TSTInfo's DER from a file, or NULL.
    ///
    /// # Safety
    /// `fp` is a live file; `a` NULL or holding NULL or a live TSTInfo.
    pub unsafe extern "C" fn d2i_TS_TST_INFO_fp(fp: *mut FILE, a: *mut *mut TS_TST_INFO) -> *mut TS_TST_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { tst_info_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp(i, fp, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a TSTInfo's DER to a file: 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live file; `a` a live TSTInfo.
    pub unsafe extern "C" fn i2d_TS_TST_INFO_fp(fp: *mut FILE, a: *const TS_TST_INFO) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { tst_info_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(i, fp, a.cast()) }
    }
}

ffi_export! {
    /// A new, empty status info, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn TS_STATUS_INFO_new() -> *mut TS_STATUS_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        new_of(status_info_it).cast()
    }
}

ffi_export! {
    /// Frees a status info (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a status info not used after.
    pub unsafe extern "C" fn TS_STATUS_INFO_free(a: *mut TS_STATUS_INFO)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_of(a.cast(), status_info_it) };
    }
}

ffi_export! {
    /// Encodes a status info (`ASN1_item_i2d`).
    ///
    /// # Safety
    /// As for `ASN1_item_i2d`.
    pub unsafe extern "C" fn i2d_TS_STATUS_INFO(a: *const TS_STATUS_INFO, pp: *mut *mut u8) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_of(a.cast(), pp, status_info_it) }
    }
}

ffi_export! {
    /// Decodes a status info (`ASN1_item_d2i`).
    ///
    /// # Safety
    /// As for `ASN1_item_d2i`.
    pub unsafe extern "C" fn d2i_TS_STATUS_INFO(a: *mut *mut TS_STATUS_INFO, pp: *mut *const u8, length: core::ffi::c_long) -> *mut TS_STATUS_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_of(a.cast(), pp, length, status_info_it) }.cast()
    }
}

ffi_export! {
    /// A copy of the status info, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live status info.
    pub unsafe extern "C" fn TS_STATUS_INFO_dup(a: *const TS_STATUS_INFO) -> *mut TS_STATUS_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), status_info_it) }.cast()
    }
}

ffi_export! {
    /// A new, empty time-stamp response, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn TS_RESP_new() -> *mut TS_RESP
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        new_of(resp_it).cast()
    }
}

ffi_export! {
    /// Frees a time-stamp response (nothing for NULL).
    ///
    /// # Safety
    /// `a` is NULL or a time-stamp response not used after.
    pub unsafe extern "C" fn TS_RESP_free(a: *mut TS_RESP)
    where failure = (), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_of(a.cast(), resp_it) };
    }
}

ffi_export! {
    /// Encodes a time-stamp response (`ASN1_item_i2d`).
    ///
    /// # Safety
    /// As for `ASN1_item_i2d`.
    pub unsafe extern "C" fn i2d_TS_RESP(a: *const TS_RESP, pp: *mut *mut u8) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_of(a.cast(), pp, resp_it) }
    }
}

ffi_export! {
    /// Decodes a time-stamp response (`ASN1_item_d2i`).
    ///
    /// # Safety
    /// As for `ASN1_item_d2i`.
    pub unsafe extern "C" fn d2i_TS_RESP(a: *mut *mut TS_RESP, pp: *mut *const u8, length: core::ffi::c_long) -> *mut TS_RESP
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_of(a.cast(), pp, length, resp_it) }.cast()
    }
}

ffi_export! {
    /// A copy of the time-stamp response, or NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live time-stamp response.
    pub unsafe extern "C" fn TS_RESP_dup(a: *const TS_RESP) -> *mut TS_RESP
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_of(a.cast(), resp_it) }.cast()
    }
}

ffi_export! {
    /// Reads a time-stamp response's DER from a BIO, or NULL.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` NULL or holding NULL or a live time-stamp response.
    pub unsafe extern "C" fn d2i_TS_RESP_bio(bp: *mut BIO, a: *mut *mut TS_RESP) -> *mut TS_RESP
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { resp_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_bio(i, bp, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a time-stamp response's DER to a BIO: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` a live time-stamp response.
    pub unsafe extern "C" fn i2d_TS_RESP_bio(bp: *mut BIO, a: *const TS_RESP) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { resp_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_bio(i, bp, a.cast()) }
    }
}

ffi_export! {
    /// Reads a time-stamp response's DER from a file, or NULL.
    ///
    /// # Safety
    /// `fp` is a live file; `a` NULL or holding NULL or a live time-stamp response.
    pub unsafe extern "C" fn d2i_TS_RESP_fp(fp: *mut FILE, a: *mut *mut TS_RESP) -> *mut TS_RESP
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { resp_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_d2i_fp(i, fp, a.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a time-stamp response's DER to a file: 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live file; `a` a live time-stamp response.
    pub unsafe extern "C" fn i2d_TS_RESP_fp(fp: *mut FILE, a: *const TS_RESP) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: no preconditions.
        let i = unsafe { resp_it() };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_item_i2d_fp(i, fp, a.cast()) }
    }
}

ffi_export! {
    /// The TSTInfo a time-stamp token (SignedData of id-ct-TSTInfo) carries, decoded, or NULL.
    ///
    /// # Safety
    /// `token` is a live PKCS#7 object.
    pub unsafe extern "C" fn PKCS7_to_TS_TST_INFO(token: *mut PKCS7) -> *mut TS_TST_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_TS
    {
        const F: &str = "PKCS7_to_TS_TST_INFO";
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { token.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: its type.
        if unsafe { OBJ_obj2nid(t.type_) } != NID_pkcs7_signed {
            raise(TS_R_BAD_PKCS7_TYPE, F);
            return ptr::null_mut();
        }
        // SAFETY: a live object.
        if unsafe { PKCS7_ctrl(token, rustyssl_abi::PKCS7_OP_GET_DETACHED_SIGNATURE, 0, ptr::null_mut()) } != 0 {
            raise(TS_R_DETACHED_CONTENT, F);
            return ptr::null_mut();
        }
        // SAFETY: the content of its type, made with it.
        let sign = unsafe { t.d.sign };
        // SAFETY: as above, or NULL; its contents, or NULL.
        let Some(enveloped) = (unsafe { sign.as_ref() }).and_then(|s| unsafe { s.contents.as_ref() }) else {
            raise(TS_R_BAD_PKCS7_TYPE, F);
            return ptr::null_mut();
        };
        // SAFETY: its type.
        if unsafe { OBJ_obj2nid(enveloped.type_) } != NID_id_smime_ct_TSTInfo {
            raise(TS_R_BAD_PKCS7_TYPE, F);
            return ptr::null_mut();
        }
        // SAFETY: the content of another type.
        let wrapper = unsafe { enveloped.d.other };
        // SAFETY: NULL or live.
        let Some(w) = (unsafe { wrapper.as_ref() }).filter(|w| w.type_ == V_ASN1_OCTET_STRING) else {
            raise(TS_R_BAD_TYPE, F);
            return ptr::null_mut();
        };
        // SAFETY: an OCTET STRING's value.
        let der = unsafe { w.value.octet_string };
        // SAFETY: NULL or live.
        let Some(d) = (unsafe { der.as_ref() }) else { return ptr::null_mut() };
        let mut p = d.data.cast_const();
        // SAFETY: the TSTInfo's DER, of its length.
        unsafe { d2i_TS_TST_INFO(ptr::null_mut(), &mut p, d.length.into()) }
    }
}
