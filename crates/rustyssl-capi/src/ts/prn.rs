//! Printing (`ts_lib.c`, `ts_req_print.c`, `ts_rsp_print.c`): requests, responses, and their
//! parts as `openssl ts -text` shows them.

use core::ffi::{c_char, c_int, c_long, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_OBJECT, BIO, ERR_LIB_TS, NID_undef, TS_INFO_ADD_INFO_NOT_AVAILABLE,
    TS_INFO_BAD_ALG, TS_INFO_BAD_DATA_FORMAT, TS_INFO_BAD_REQUEST, TS_INFO_SYSTEM_FAILURE,
    TS_INFO_TIME_NOT_AVAILABLE, TS_INFO_UNACCEPTED_EXTENSION, TS_INFO_UNACCEPTED_POLICY,
    TS_MSG_IMPRINT, TS_REQ, TS_RESP, TS_STATUS_INFO, TS_TST_INFO, X509_ALGOR,
    stack_st_X509_EXTENSION,
};

use super::asn::{Accuracy, MsgImprint, Req, Resp, StatusInfo, TstInfo};
use super::utils::of;
use crate::asn1::bit_string::ASN1_BIT_STRING_get_bit;
use crate::asn1::integer::ASN1_INTEGER_get;
use crate::asn1::string::{ASN1_STRING_get0_data, ASN1_STRING_length};
use crate::asn1::text::{ASN1_STRING_print, ASN1_STRING_print_ex};
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::bio::BIO_write;
use crate::bio::dump::BIO_dump_indent;
use crate::bn::BN_free;
use crate::bn::conv::{ASN1_INTEGER_to_BN, BN_bn2hex};
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_nid2ln, OBJ_obj2nid, OBJ_obj2txt, i2a_ASN1_OBJECT};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509::ext::{
    X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object,
    X509v3_get_ext, X509v3_get_ext_count,
};
use crate::x509v3::X509V3_conf_free;
use crate::x509v3::registry::{X509V3_EXT_print, X509V3_EXT_val_prn};
use crate::x509v3::san::i2v_GENERAL_NAME;

/// Writes the bytes: how many, or -1.
fn out_bytes(bp: *mut BIO, s: &[u8]) -> c_int {
    let Ok(n) = c_int::try_from(s.len()) else {
        return -1;
    };
    if n == 0 {
        return 0;
    }
    // SAFETY: the caller's BIO; the bytes.
    unsafe { BIO_write(bp, s.as_ptr().cast(), n) }
}

/// Writes the text: how many bytes, or -1.
fn out(bp: *mut BIO, s: &str) -> c_int {
    out_bytes(bp, s.as_bytes())
}

/// The value as C converts a `long` to an `int` (`int v = ...` in OpenSSL's printers).
#[expect(
    clippy::cast_possible_truncation,
    reason = "C's conversion of long to int"
)]
fn as_int(v: c_long) -> c_int {
    v as c_int
}

ffi_export! {
    /// Writes the integer as `0x` and its hexadecimal value: 1, 0 when writing fails, or -1.
    ///
    /// # Safety
    /// `bio` is a live BIO; `num` NULL or a live integer.
    pub unsafe extern "C" fn TS_ASN1_INTEGER_print_bio(bio: *mut BIO, num: *const ASN1_INTEGER) -> c_int
    where failure = -1, library = ERR_LIB_TS
    {
        // SAFETY: the caller's integer, or NULL.
        let bn = unsafe { ASN1_INTEGER_to_BN(num, ptr::null_mut()) };
        if bn.is_null() {
            return -1;
        }
        // SAFETY: the number made here.
        let hex = unsafe { BN_bn2hex(bn) };
        let mut result = 0;
        if !hex.is_null() {
            // SAFETY: a NUL-terminated string.
            let h = unsafe { core::ffi::CStr::from_ptr(hex) };
            result = c_int::from(out(bio, "0x") > 0 && out_bytes(bio, h.to_bytes()) > 0);
            // SAFETY: from `CRYPTO_malloc`.
            unsafe { mem::release(hex.cast()) };
        }
        // SAFETY: as above.
        unsafe { BN_free(bn) };
        result
    }
}

ffi_export! {
    /// Writes the object as its name or dotted OID (up to 127 characters) and a newline: 1.
    ///
    /// # Safety
    /// `bio` is a live BIO; `obj` NULL or a live object.
    pub unsafe extern "C" fn TS_OBJ_print_bio(bio: *mut BIO, obj: *const ASN1_OBJECT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        let mut txt = [0 as c_char; 128];
        // SAFETY: `txt`'s room; the caller's object.
        if unsafe { OBJ_obj2txt(txt.as_mut_ptr(), 128, obj, 0) } < 0 {
            txt[0] = 0;
        }
        // SAFETY: NUL-terminated by `OBJ_obj2txt`, or emptied.
        let s = unsafe { core::ffi::CStr::from_ptr(txt.as_ptr()) };
        out_bytes(bio, s.to_bytes());
        out(bio, "\n");
        1
    }
}

ffi_export! {
    /// Writes `Extensions:` and each extension, printed or dumped: 1, or 0.
    ///
    /// # Safety
    /// `bio` is a live BIO; `extensions` NULL or a live list.
    pub unsafe extern "C" fn TS_ext_print_bio(bio: *mut BIO, extensions: *const stack_st_X509_EXTENSION) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        out(bio, "Extensions:\n");
        // SAFETY: the caller's list, or NULL.
        let n = unsafe { X509v3_get_ext_count(extensions) };
        for i in 0..n {
            // SAFETY: as above, an index in range.
            let ex = unsafe { X509v3_get_ext(extensions, i) };
            // SAFETY: the extension.
            let obj = unsafe { X509_EXTENSION_get_object(ex) };
            // SAFETY: the caller's BIO; its object.
            if unsafe { i2a_ASN1_OBJECT(bio, obj) } < 0 {
                return 0;
            }
            // SAFETY: the extension.
            let critical = unsafe { X509_EXTENSION_get_critical(ex) } != 0;
            out(bio, if critical { ": critical\n" } else { ":\n" });
            // SAFETY: the caller's BIO; the extension.
            if unsafe { X509V3_EXT_print(bio, ex, 0, 4) } == 0 {
                out(bio, "    ");
                // SAFETY: the extension.
                let data = unsafe { X509_EXTENSION_get_data(ex) };
                // SAFETY: the caller's BIO; its value.
                unsafe { ASN1_STRING_print(bio, data) };
            }
            out(bio, "\n");
        }
        1
    }
}

ffi_export! {
    /// Writes `Hash Algorithm:` and the algorithm's long name: the bytes written, or -1.
    ///
    /// # Safety
    /// `bio` is a live BIO; `alg` a live algorithm.
    pub unsafe extern "C" fn TS_X509_ALGOR_print_bio(bio: *mut BIO, alg: *const X509_ALGOR) -> c_int
    where failure = -1, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { alg.as_ref() }) else { return -1 };
        // SAFETY: its algorithm.
        let nid = unsafe { OBJ_obj2nid(a.algorithm) };
        let name = if nid == NID_undef {
            "UNKNOWN".into()
        } else {
            // SAFETY: a known NID's static name.
            let p = unsafe { OBJ_nid2ln(nid) };
            if p.is_null() {
                "(null)".into()
            } else {
                // SAFETY: as above.
                unsafe { core::ffi::CStr::from_ptr(p) }.to_string_lossy()
            }
        };
        out(bio, &format!("Hash Algorithm: {name}\n"))
    }
}

/// `TS_MSG_IMPRINT_print_bio` over the mirror.
///
/// # Safety
/// `bio` is a live BIO; `a`'s members are live.
unsafe fn imprint_print(bio: *mut BIO, a: &MsgImprint) {
    // SAFETY: its algorithm.
    unsafe { TS_X509_ALGOR_print_bio(bio, a.hash_algo) };
    out(bio, "Message data:\n");
    // SAFETY: its hash.
    let d = unsafe { ASN1_STRING_get0_data(a.hashed_msg) };
    // SAFETY: as above.
    let n = unsafe { ASN1_STRING_length(a.hashed_msg) };
    // SAFETY: its `n` bytes.
    unsafe { BIO_dump_indent(bio, d.cast::<c_void>(), n, 4) };
}

ffi_export! {
    /// Writes the imprint's algorithm and a dump of its hash: 1.
    ///
    /// # Safety
    /// `bio` is a live BIO; `a` a live imprint.
    pub unsafe extern "C" fn TS_MSG_IMPRINT_print_bio(bio: *mut BIO, a: *mut TS_MSG_IMPRINT) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { of::<MsgImprint, _>(a) }) else { return 0 };
        // SAFETY: a live imprint.
        unsafe { imprint_print(bio, m) };
        1
    }
}

/// The imprint, or nothing when there is none (where OpenSSL would crash).
///
/// # Safety
/// `bio` is a live BIO; `a` NULL or a live imprint.
unsafe fn imprint_of(bio: *mut BIO, a: *mut MsgImprint) {
    // SAFETY: the caller's guarantee.
    if let Some(m) = unsafe { a.as_ref() } {
        // SAFETY: a live imprint.
        unsafe { imprint_print(bio, m) };
    }
}

/// The integer in hexadecimal, or `unspecified`.
///
/// # Safety
/// `bio` is a live BIO; `v` NULL or a live integer.
unsafe fn int_or_unspecified(bio: *mut BIO, v: *const ASN1_INTEGER) {
    if v.is_null() {
        out(bio, "unspecified");
    } else {
        // SAFETY: the caller's integer.
        unsafe { TS_ASN1_INTEGER_print_bio(bio, v) };
    }
}

ffi_export! {
    /// Writes the request as `openssl ts -query -text` does: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `bio` is a live BIO; `a` NULL or a live request.
    pub unsafe extern "C" fn TS_REQ_print_bio(bio: *mut BIO, a: *mut TS_REQ) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Req, _>(a) }) else { return 0 };
        // SAFETY: its version.
        let v = as_int(unsafe { ASN1_INTEGER_get(r.version) });
        out(bio, &format!("Version: {v}\n"));
        // SAFETY: its imprint, or NULL.
        unsafe { imprint_of(bio, r.msg_imprint) };
        out(bio, "Policy OID: ");
        if r.policy_id.is_null() {
            out(bio, "unspecified\n");
        } else {
            // SAFETY: its policy.
            unsafe { TS_OBJ_print_bio(bio, r.policy_id) };
        }
        out(bio, "Nonce: ");
        // SAFETY: its nonce, or NULL.
        unsafe { int_or_unspecified(bio, r.nonce) };
        out(bio, "\n");
        out(bio, if r.cert_req != 0 { "Certificate required: yes\n" } else { "Certificate required: no\n" });
        // SAFETY: its extensions, or NULL.
        unsafe { TS_ext_print_bio(bio, r.extensions.cast()) };
        1
    }
}

const STATUS_MAP: [&str; 6] = [
    "Granted.",
    "Granted with modifications.",
    "Rejected.",
    "Waiting.",
    "Revocation warning.",
    "Revoked.",
];

const FAILURE_MAP: [(c_int, &str); 8] = [
    (
        TS_INFO_BAD_ALG,
        "unrecognized or unsupported algorithm identifier",
    ),
    (
        TS_INFO_BAD_REQUEST,
        "transaction not permitted or supported",
    ),
    (
        TS_INFO_BAD_DATA_FORMAT,
        "the data submitted has the wrong format",
    ),
    (
        TS_INFO_TIME_NOT_AVAILABLE,
        "the TSA's time source is not available",
    ),
    (
        TS_INFO_UNACCEPTED_POLICY,
        "the requested TSA policy is not supported by the TSA",
    ),
    (
        TS_INFO_UNACCEPTED_EXTENSION,
        "the requested extension is not supported by the TSA",
    ),
    (
        TS_INFO_ADD_INFO_NOT_AVAILABLE,
        "the additional information requested could not be understood or is not available",
    ),
    (
        TS_INFO_SYSTEM_FAILURE,
        "the request cannot be handled due to system failure",
    ),
];

/// `TS_STATUS_INFO_print_bio` over the mirror.
///
/// # Safety
/// `bio` is a live BIO; `a`'s members are NULL or live.
unsafe fn status_print(bio: *mut BIO, a: &StatusInfo) {
    out(bio, "Status: ");
    // SAFETY: its status.
    let status = unsafe { ASN1_INTEGER_get(a.status) };
    let text = usize::try_from(status)
        .ok()
        .and_then(|i| STATUS_MAP.get(i))
        .copied()
        .unwrap_or("out of bounds");
    out(bio, &format!("{text}\n"));
    out(bio, "Status description: ");
    // SAFETY: its text, or NULL (0).
    let n = unsafe { OPENSSL_sk_num(a.text.cast()) };
    for i in 0..n {
        if i > 0 {
            out(bio, "\t");
        }
        // SAFETY: an index in range.
        let s = unsafe { OPENSSL_sk_value(a.text.cast(), i) };
        // SAFETY: the caller's BIO; the string.
        unsafe { ASN1_STRING_print_ex(bio, s.cast(), 0) };
        out(bio, "\n");
    }
    if n <= 0 {
        out(bio, "unspecified\n");
    }
    out(bio, "Failure info: ");
    let mut lines = 0;
    if !a.failure_info.is_null() {
        for (bit, text) in FAILURE_MAP {
            // SAFETY: its failure info.
            if unsafe { ASN1_BIT_STRING_get_bit(a.failure_info, bit) } != 0 {
                lines += 1;
                if lines > 1 {
                    out(bio, ", ");
                }
                out(bio, text);
            }
        }
    }
    if lines == 0 {
        out(bio, "unspecified");
    }
    out(bio, "\n");
}

ffi_export! {
    /// Writes the status info: 1.
    ///
    /// # Safety
    /// `bio` is a live BIO; `a` a live status info.
    pub unsafe extern "C" fn TS_STATUS_INFO_print_bio(bio: *mut BIO, a: *mut TS_STATUS_INFO) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { of::<StatusInfo, _>(a) }) else { return 0 };
        // SAFETY: a live status info.
        unsafe { status_print(bio, s) };
        1
    }
}

/// `CONF_VALUE`'s free function, as a stack's.
unsafe extern "C" fn conf_free(p: *mut c_void) {
    // SAFETY: an element of a list of values.
    unsafe { X509V3_conf_free(p.cast()) };
}

/// `ts_ACCURACY_print_bio`.
///
/// # Safety
/// `bio` is a live BIO; `a`'s members are NULL or live.
unsafe fn accuracy_print(bio: *mut BIO, a: &Accuracy) {
    // SAFETY: its parts, or NULL.
    unsafe { int_or_unspecified(bio, a.seconds) };
    out(bio, " seconds, ");
    // SAFETY: as above.
    unsafe { int_or_unspecified(bio, a.millis) };
    out(bio, " millis, ");
    // SAFETY: as above.
    unsafe { int_or_unspecified(bio, a.micros) };
    out(bio, " micros");
}

ffi_export! {
    /// Writes the TSTInfo as `openssl ts -reply -text` does: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `bio` is a live BIO; `a` NULL or a live TSTInfo.
    pub unsafe extern "C" fn TS_TST_INFO_print_bio(bio: *mut BIO, a: *mut TS_TST_INFO) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { of::<TstInfo, _>(a) }) else { return 0 };
        // SAFETY: its version.
        let v = as_int(unsafe { ASN1_INTEGER_get(t.version) });
        out(bio, &format!("Version: {v}\nPolicy OID: "));
        // SAFETY: its policy, or NULL.
        unsafe { TS_OBJ_print_bio(bio, t.policy_id) };
        // SAFETY: its imprint, or NULL.
        unsafe { imprint_of(bio, t.msg_imprint) };
        out(bio, "Serial number: ");
        // SAFETY: its serial, or NULL.
        unsafe { int_or_unspecified(bio, t.serial) };
        out(bio, "\nTime stamp: ");
        // SAFETY: its time.
        unsafe { ASN1_GENERALIZEDTIME_print(bio, t.time) };
        out(bio, "\nAccuracy: ");
        // SAFETY: its accuracy, or NULL.
        match unsafe { t.accuracy.as_ref() } {
            // SAFETY: a live accuracy.
            Some(acc) => unsafe { accuracy_print(bio, acc) },
            None => {
                out(bio, "unspecified");
            }
        }
        out(bio, "\n");
        out(bio, if t.ordering != 0 { "Ordering: yes\n" } else { "Ordering: no\n" });
        out(bio, "Nonce: ");
        // SAFETY: its nonce, or NULL.
        unsafe { int_or_unspecified(bio, t.nonce) };
        out(bio, "\nTSA: ");
        if t.tsa.is_null() {
            out(bio, "unspecified");
        } else {
            // SAFETY: its name.
            let nval = unsafe { i2v_GENERAL_NAME(ptr::null_mut(), t.tsa, ptr::null_mut()) };
            if !nval.is_null() {
                // SAFETY: the values made here.
                unsafe { X509V3_EXT_val_prn(bio, nval, 0, 0) };
            }
            // SAFETY: as above, or NULL.
            unsafe { OPENSSL_sk_pop_free(nval.cast(), Some(conf_free)) };
        }
        out(bio, "\n");
        // SAFETY: its extensions, or NULL.
        unsafe { TS_ext_print_bio(bio, t.extensions.cast()) };
        1
    }
}

ffi_export! {
    /// Writes the response's status info and TSTInfo: 1.
    ///
    /// # Safety
    /// `bio` is a live BIO; `a` a live response.
    pub unsafe extern "C" fn TS_RESP_print_bio(bio: *mut BIO, a: *mut TS_RESP) -> c_int
    where failure = 0, library = ERR_LIB_TS
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Resp, _>(a) }) else { return 0 };
        out(bio, "Status info:\n");
        // SAFETY: its status info, or NULL.
        unsafe { TS_STATUS_INFO_print_bio(bio, r.status_info.cast()) };
        out(bio, "\nTST info:\n");
        if r.tst_info.is_null() {
            out(bio, "Not included.\n");
        } else {
            // SAFETY: its TSTInfo.
            unsafe { TS_TST_INFO_print_bio(bio, r.tst_info.cast()) };
        }
        1
    }
}
