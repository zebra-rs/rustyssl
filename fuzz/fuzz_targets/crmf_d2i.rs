//! Fuzzes CRMF on untrusted input: the input decoded as certificate request messages, an
//! encrypted value, an encrypted key, and password-based MAC parameters, each encoded again
//! (decoding to the same encoding); each message's template and controls read, and its
//! proof-of-possession checked. Nothing may crash or read out of bounds (ASan).

#![no_main]

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libfuzzer_sys::fuzz_target;
use rustyssl_abi::{
    ASN1_INTEGER, OSSL_CRMF_CERTTEMPLATE, OSSL_CRMF_ENCRYPTEDKEY, OSSL_CRMF_ENCRYPTEDVALUE,
    OSSL_CRMF_MSG, OSSL_CRMF_MSGS, OSSL_CRMF_PBMPARAMETER, OSSL_LIB_CTX, X509_NAME,
};
// Linked for its exports, which the declarations below resolve to.
use rustyssl_capi as _;

unsafe extern "C" {
    fn d2i_OSSL_CRMF_MSGS(a: *mut *mut OSSL_CRMF_MSGS, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CRMF_MSGS;
    fn i2d_OSSL_CRMF_MSGS(a: *const OSSL_CRMF_MSGS, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CRMF_MSGS_free(a: *mut OSSL_CRMF_MSGS);
    fn OSSL_CRMF_MSGS_verify_popo(reqs: *const OSSL_CRMF_MSGS, rid: c_int, acceptRAVerified: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int;
    fn d2i_OSSL_CRMF_MSG(a: *mut *mut OSSL_CRMF_MSG, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CRMF_MSG;
    fn i2d_OSSL_CRMF_MSG(a: *const OSSL_CRMF_MSG, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CRMF_MSG_free(a: *mut OSSL_CRMF_MSG);
    fn OSSL_CRMF_MSG_get0_tmpl(crm: *const OSSL_CRMF_MSG) -> *mut OSSL_CRMF_CERTTEMPLATE;
    fn OSSL_CRMF_MSG_get_certReqId(crm: *const OSSL_CRMF_MSG) -> c_int;
    fn OSSL_CRMF_MSG_centralkeygen_requested(crm: *const OSSL_CRMF_MSG, p10cr: *const c_void) -> c_int;
    fn OSSL_CRMF_MSG_get0_regCtrl_regToken(msg: *const OSSL_CRMF_MSG) -> *mut c_void;
    fn OSSL_CRMF_MSG_get0_regCtrl_oldCertID(msg: *const OSSL_CRMF_MSG) -> *mut c_void;
    fn OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(msg: *const OSSL_CRMF_MSG) -> *mut c_void;
    fn OSSL_CRMF_CERTID_get0_issuer(cid: *const c_void) -> *const c_void;
    fn OSSL_CRMF_CERTTEMPLATE_get0_subject(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *const X509_NAME;
    fn OSSL_CRMF_CERTTEMPLATE_get0_issuer(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *const X509_NAME;
    fn OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *const ASN1_INTEGER;
    fn OSSL_CRMF_CERTTEMPLATE_get0_extensions(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *mut c_void;
    fn OSSL_CRMF_CERTTEMPLATE_get0_publicKey(tmpl: *const OSSL_CRMF_CERTTEMPLATE) -> *mut c_void;
    fn d2i_OSSL_CRMF_ENCRYPTEDVALUE(a: *mut *mut OSSL_CRMF_ENCRYPTEDVALUE, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CRMF_ENCRYPTEDVALUE;
    fn i2d_OSSL_CRMF_ENCRYPTEDVALUE(a: *const OSSL_CRMF_ENCRYPTEDVALUE, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CRMF_ENCRYPTEDVALUE_free(a: *mut OSSL_CRMF_ENCRYPTEDVALUE);
    fn d2i_OSSL_CRMF_ENCRYPTEDKEY(a: *mut *mut OSSL_CRMF_ENCRYPTEDKEY, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CRMF_ENCRYPTEDKEY;
    fn i2d_OSSL_CRMF_ENCRYPTEDKEY(a: *const OSSL_CRMF_ENCRYPTEDKEY, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CRMF_ENCRYPTEDKEY_free(a: *mut OSSL_CRMF_ENCRYPTEDKEY);
    fn d2i_OSSL_CRMF_PBMPARAMETER(a: *mut *mut OSSL_CRMF_PBMPARAMETER, pp: *mut *const c_uchar, len: c_long) -> *mut OSSL_CRMF_PBMPARAMETER;
    fn i2d_OSSL_CRMF_PBMPARAMETER(a: *const OSSL_CRMF_PBMPARAMETER, out: *mut *mut c_uchar) -> c_int;
    fn OSSL_CRMF_PBMPARAMETER_free(a: *mut OSSL_CRMF_PBMPARAMETER);
    fn OPENSSL_sk_num(st: *const c_void) -> c_int;
    fn OPENSSL_sk_value(st: *const c_void, i: c_int) -> *mut c_void;
    fn CRYPTO_free(p: *mut c_void, file: *const c_char, line: c_int);
    fn ERR_clear_error();
}

/// Encodes, decodes, and encodes again: the encodings must agree.
fn round_trip<T>(x: *mut T, i2d: unsafe extern "C" fn(*const T, *mut *mut c_uchar) -> c_int, d2i: unsafe extern "C" fn(*mut *mut T, *mut *const c_uchar, c_long) -> *mut T, free: unsafe extern "C" fn(*mut T)) {
    let mut der: *mut c_uchar = ptr::null_mut();
    // SAFETY: a live object.
    let n = unsafe { i2d(x, &mut der) };
    if n > 0 {
        let mut q = der.cast_const();
        // SAFETY: the encoding's `n` octets.
        let again = unsafe { d2i(ptr::null_mut(), &mut q, c_long::from(n)) };
        assert!(!again.is_null(), "an encoding that doesn't decode");
        let mut der2: *mut c_uchar = ptr::null_mut();
        // SAFETY: as above.
        let n2 = unsafe { i2d(again, &mut der2) };
        assert_eq!(n, n2, "the encoding changed");
        // SAFETY: both encodings' `n` octets.
        let (a, b) = unsafe { (core::slice::from_raw_parts(der, n as usize), core::slice::from_raw_parts(der2, n as usize)) };
        assert_eq!(a, b, "the encoding changed");
        // SAFETY: as above, freed once.
        unsafe { CRYPTO_free(der2.cast(), ptr::null(), 0) };
        // SAFETY: as above.
        unsafe { free(again) };
    }
    // SAFETY: the encoding, or NULL.
    unsafe { CRYPTO_free(der.cast(), ptr::null(), 0) };
}

/// Decodes the input as a `T` and, if it is one, round-trips it.
fn decode<T>(data: &[u8], i2d: unsafe extern "C" fn(*const T, *mut *mut c_uchar) -> c_int, d2i: unsafe extern "C" fn(*mut *mut T, *mut *const c_uchar, c_long) -> *mut T, free: unsafe extern "C" fn(*mut T)) {
    let Ok(len) = c_long::try_from(data.len()) else {
        return;
    };
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let x = unsafe { d2i(ptr::null_mut(), &mut p, len) };
    if !x.is_null() {
        round_trip(x, i2d, d2i, free);
        // SAFETY: the object decoded, freed once.
        unsafe { free(x) };
    }
}

/// Reads everything a message's getters reach.
fn read(m: *const OSSL_CRMF_MSG) {
    // SAFETY: a live message, for each call.
    unsafe {
        OSSL_CRMF_MSG_get_certReqId(m);
        OSSL_CRMF_MSG_centralkeygen_requested(m, ptr::null());
        OSSL_CRMF_MSG_get0_regCtrl_regToken(m);
        OSSL_CRMF_MSG_get0_regCtrl_pkiPublicationInfo(m);
        OSSL_CRMF_CERTID_get0_issuer(OSSL_CRMF_MSG_get0_regCtrl_oldCertID(m));
    }
    // SAFETY: as above.
    let t = unsafe { OSSL_CRMF_MSG_get0_tmpl(m) };
    // SAFETY: the template, or NULL, for each call.
    unsafe {
        OSSL_CRMF_CERTTEMPLATE_get0_subject(t);
        OSSL_CRMF_CERTTEMPLATE_get0_issuer(t);
        OSSL_CRMF_CERTTEMPLATE_get0_serialNumber(t);
        OSSL_CRMF_CERTTEMPLATE_get0_extensions(t);
        OSSL_CRMF_CERTTEMPLATE_get0_publicKey(t);
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(len) = c_long::try_from(data.len()) else {
        return;
    };
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let msgs = unsafe { d2i_OSSL_CRMF_MSGS(ptr::null_mut(), &mut p, len) };
    if !msgs.is_null() {
        round_trip(msgs, i2d_OSSL_CRMF_MSGS, d2i_OSSL_CRMF_MSGS, OSSL_CRMF_MSGS_free);
        // SAFETY: a live list.
        let n = unsafe { OPENSSL_sk_num(msgs.cast()) };
        for i in 0..n.min(8) {
            // SAFETY: an index in range.
            read(unsafe { OPENSSL_sk_value(msgs.cast(), i) }.cast());
            // SAFETY: the list; the default library context.
            unsafe { OSSL_CRMF_MSGS_verify_popo(msgs, i, i & 1, ptr::null_mut(), ptr::null()) };
        }
        // SAFETY: the object decoded, freed once.
        unsafe { OSSL_CRMF_MSGS_free(msgs) };
    }
    let mut p = data.as_ptr();
    // SAFETY: the input's octets.
    let msg = unsafe { d2i_OSSL_CRMF_MSG(ptr::null_mut(), &mut p, len) };
    if !msg.is_null() {
        round_trip(msg, i2d_OSSL_CRMF_MSG, d2i_OSSL_CRMF_MSG, OSSL_CRMF_MSG_free);
        read(msg);
        // SAFETY: the object decoded, freed once.
        unsafe { OSSL_CRMF_MSG_free(msg) };
    }
    decode(data, i2d_OSSL_CRMF_ENCRYPTEDVALUE, d2i_OSSL_CRMF_ENCRYPTEDVALUE, OSSL_CRMF_ENCRYPTEDVALUE_free);
    decode(data, i2d_OSSL_CRMF_ENCRYPTEDKEY, d2i_OSSL_CRMF_ENCRYPTEDKEY, OSSL_CRMF_ENCRYPTEDKEY_free);
    decode(data, i2d_OSSL_CRMF_PBMPARAMETER, d2i_OSSL_CRMF_PBMPARAMETER, OSSL_CRMF_PBMPARAMETER_free);
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
});
