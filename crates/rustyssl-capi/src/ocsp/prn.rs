//! Printing (`ocsp_prn.c`): requests and responses as `openssl ocsp -text` shows them, and
//! the names of statuses and reasons.

use core::ffi::{c_char, c_int, c_long, c_ulong};
use core::ptr;

use rustyssl_abi::{
    BIO, ERR_LIB_OCSP, NID_id_pkix_OCSP_basic, OCSP_REQUEST, OCSP_RESPONSE,
    OCSP_RESPONSE_STATUS_INTERNALERROR, OCSP_RESPONSE_STATUS_MALFORMEDREQUEST,
    OCSP_RESPONSE_STATUS_SIGREQUIRED, OCSP_RESPONSE_STATUS_SUCCESSFUL,
    OCSP_RESPONSE_STATUS_TRYLATER, OCSP_RESPONSE_STATUS_UNAUTHORIZED,
    OCSP_REVOKED_STATUS_AACOMPROMISE, OCSP_REVOKED_STATUS_AFFILIATIONCHANGED,
    OCSP_REVOKED_STATUS_CACOMPROMISE, OCSP_REVOKED_STATUS_CERTIFICATEHOLD,
    OCSP_REVOKED_STATUS_CESSATIONOFOPERATION, OCSP_REVOKED_STATUS_KEYCOMPROMISE,
    OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN, OCSP_REVOKED_STATUS_REMOVEFROMCRL,
    OCSP_REVOKED_STATUS_SUPERSEDED, OCSP_REVOKED_STATUS_UNSPECIFIED, V_OCSP_CERTSTATUS_GOOD,
    V_OCSP_CERTSTATUS_REVOKED, V_OCSP_CERTSTATUS_UNKNOWN, V_OCSP_RESPID_KEY, V_OCSP_RESPID_NAME,
    XN_FLAG_ONELINE,
};

use super::asn::{
    CertId, CertStatus, OCSP_BASICRESP_free, OneReq, Request, RespBytes, Response, RevokedInfo,
    SingleResp, of,
};
use super::cl::{OCSP_response_get1_basic, basic};
use crate::asn1::hex::i2a_ASN1_STRING;
use crate::asn1::integer::{ASN1_ENUMERATED_get, ASN1_INTEGER_get, i2a_ASN1_INTEGER};
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::bio::BIO_write;
use crate::ffi::ffi_export;
use crate::objects::{OBJ_obj2nid, i2a_ASN1_OBJECT};
use crate::pem_pkey::PEM_write_bio_X509;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::name::X509_NAME_print_ex;
use crate::x509::tprint::{X509_print, X509_signature_print};
use crate::x509v3::registry::X509V3_extensions_print;
use crate::x509v3::san::GENERAL_NAME_print;

/// Writes the text: whether all of it was written.
fn out(bp: *mut BIO, s: &str) -> bool {
    let Ok(n) = c_int::try_from(s.len()) else {
        return false;
    };
    // SAFETY: the caller's BIO; the text.
    n == 0 || unsafe { BIO_write(bp, s.as_ptr().cast(), n) } > 0
}

/// `ocsp_certid_print`.
///
/// # Safety
/// `bp` is a live BIO; `a` a live CertID.
unsafe fn certid_print(bp: *mut BIO, a: &mut CertId, indent: usize) -> bool {
    let pad = " ".repeat(indent);
    let pad2 = " ".repeat(indent + 2);
    out(bp, &format!("{pad}Certificate ID:\n{pad2}Hash Algorithm: "));
    // SAFETY: the caller's BIO; the CertID's fields.
    unsafe { i2a_ASN1_OBJECT(bp, a.hash_algorithm.algorithm) };
    out(bp, &format!("\n{pad2}Issuer Name Hash: "));
    // SAFETY: as above.
    unsafe { i2a_ASN1_STRING(bp, &a.issuer_name_hash, 0) };
    out(bp, &format!("\n{pad2}Issuer Key Hash: "));
    // SAFETY: as above.
    unsafe { i2a_ASN1_STRING(bp, &a.issuer_key_hash, 0) };
    out(bp, &format!("\n{pad2}Serial Number: "));
    // SAFETY: as above.
    unsafe { i2a_ASN1_INTEGER(bp, &a.serial_number) };
    out(bp, "\n");
    true
}

/// `do_table2string`: the name of `s` in the table, else `(UNKNOWN)`.
fn table2string(s: c_long, tbl: &[(c_int, &'static core::ffi::CStr)]) -> *const c_char {
    tbl.iter()
        .find(|(t, _)| c_long::from(*t) == s)
        .map_or(c"(UNKNOWN)", |(_, m)| m)
        .as_ptr()
}

const RSTAT: [(c_int, &core::ffi::CStr); 6] = [
    (OCSP_RESPONSE_STATUS_SUCCESSFUL, c"successful"),
    (OCSP_RESPONSE_STATUS_MALFORMEDREQUEST, c"malformedrequest"),
    (OCSP_RESPONSE_STATUS_INTERNALERROR, c"internalerror"),
    (OCSP_RESPONSE_STATUS_TRYLATER, c"trylater"),
    (OCSP_RESPONSE_STATUS_SIGREQUIRED, c"sigrequired"),
    (OCSP_RESPONSE_STATUS_UNAUTHORIZED, c"unauthorized"),
];

const CSTAT: [(c_int, &core::ffi::CStr); 3] = [
    (V_OCSP_CERTSTATUS_GOOD, c"good"),
    (V_OCSP_CERTSTATUS_REVOKED, c"revoked"),
    (V_OCSP_CERTSTATUS_UNKNOWN, c"unknown"),
];

const REASONS: [(c_int, &core::ffi::CStr); 10] = [
    (OCSP_REVOKED_STATUS_UNSPECIFIED, c"unspecified"),
    (OCSP_REVOKED_STATUS_KEYCOMPROMISE, c"keyCompromise"),
    (OCSP_REVOKED_STATUS_CACOMPROMISE, c"cACompromise"),
    (
        OCSP_REVOKED_STATUS_AFFILIATIONCHANGED,
        c"affiliationChanged",
    ),
    (OCSP_REVOKED_STATUS_SUPERSEDED, c"superseded"),
    (
        OCSP_REVOKED_STATUS_CESSATIONOFOPERATION,
        c"cessationOfOperation",
    ),
    (OCSP_REVOKED_STATUS_CERTIFICATEHOLD, c"certificateHold"),
    (OCSP_REVOKED_STATUS_REMOVEFROMCRL, c"removeFromCRL"),
    (
        OCSP_REVOKED_STATUS_PRIVILEGEWITHDRAWN,
        c"privilegeWithdrawn",
    ),
    (OCSP_REVOKED_STATUS_AACOMPROMISE, c"aACompromise"),
];

ffi_export! {
    /// The name of a response status, or `(UNKNOWN)`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OCSP_response_status_str(s: c_long) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        table2string(s, &RSTAT)
    }
}

ffi_export! {
    /// The name of a certificate status, or `(UNKNOWN)`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OCSP_cert_status_str(s: c_long) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        table2string(s, &CSTAT)
    }
}

ffi_export! {
    /// The name of a revocation reason, or `(UNKNOWN)`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OCSP_crl_reason_str(s: c_long) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_OCSP
    {
        table2string(s, &REASONS)
    }
}

/// The name, as a Rust string.
fn name(p: *const c_char) -> String {
    // SAFETY: a static name from the tables.
    unsafe { core::ffi::CStr::from_ptr(p) }
        .to_string_lossy()
        .into_owned()
}

/// `Version: <v+1> (0x<v>)`, as `%lu` and `%lx` print a `long`.
fn version(l: c_long) -> String {
    let u = l.cast_unsigned();
    format!("Version: {} (0x{u:x})", u.wrapping_add(1))
}

/// The certificates, printed and as PEM.
///
/// # Safety
/// `bp` is a live BIO; `certs` NULL or a live list.
unsafe fn print_certs(bp: *mut BIO, certs: *mut rustyssl_abi::OPENSSL_STACK) {
    // SAFETY: the list, or NULL.
    for i in 0..unsafe { OPENSSL_sk_num(certs) } {
        // SAFETY: an index within it.
        let x = unsafe { OPENSSL_sk_value(certs, i) }.cast();
        // SAFETY: the BIO; a certificate.
        unsafe { X509_print(bp, x) };
        // SAFETY: as above.
        unsafe { PEM_write_bio_X509(bp, x) };
    }
}

ffi_export! {
    /// Prints the request: 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `o` a live request.
    pub unsafe extern "C" fn OCSP_REQUEST_print(bp: *mut BIO, o: *mut OCSP_REQUEST, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Request, _>(o) }) else { return 0 };
        let inf = &mut r.tbs_request;
        if !out(bp, "OCSP Request Data:\n") {
            return 0;
        }
        // SAFETY: its version, or NULL.
        let l = unsafe { ASN1_INTEGER_get(inf.version) };
        if !out(bp, &format!("    {}", version(l))) {
            return 0;
        }
        if !inf.requestor_name.is_null() {
            if !out(bp, "\n    Requestor Name: ") {
                return 0;
            }
            // SAFETY: the BIO; its name.
            unsafe { GENERAL_NAME_print(bp, inf.requestor_name) };
        }
        if !out(bp, "\n    Requestor List:\n") {
            return 0;
        }
        // SAFETY: its list.
        for i in 0..unsafe { OPENSSL_sk_num(inf.request_list) } {
            // SAFETY: an index within it.
            let op = unsafe { OPENSSL_sk_value(inf.request_list, i) };
            // SAFETY: a request of the list.
            let Some(one) = (unsafe { of::<OneReq, _>(op) }) else { continue };
            // SAFETY: the request's CertID, made with it.
            if let Some(cid) = unsafe { of::<CertId, _>(one.req_cert) } {
                // SAFETY: the BIO; the CertID.
                unsafe { certid_print(bp, cid, 8) };
            }
            // SAFETY: the BIO; the request's extensions, or NULL.
            if unsafe { X509V3_extensions_print(bp, c"Request Single Extensions".as_ptr(), one.single_request_extensions.cast(), flags, 8) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        if unsafe { X509V3_extensions_print(bp, c"Request Extensions".as_ptr(), inf.request_extensions.cast(), flags, 4) } == 0 {
            return 0;
        }
        // SAFETY: its signature, or NULL.
        if let Some(sig) = unsafe { r.optional_signature.as_mut() } {
            // SAFETY: the BIO; the signature's algorithm and value.
            unsafe { X509_signature_print(bp, &sig.signature_algorithm, sig.signature) };
            // SAFETY: as above; its certificates, or NULL.
            unsafe { print_certs(bp, sig.certs) };
        }
        1
    }
}

ffi_export! {
    /// Prints the response (a basic response in full): 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `o` a live response.
    pub unsafe extern "C" fn OCSP_RESPONSE_print(bp: *mut BIO, o: *mut OCSP_RESPONSE, flags: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { of::<Response, _>(o) }) else { return 0 };
        if !out(bp, "OCSP Response Data:\n") {
            return 0;
        }
        // SAFETY: its status.
        let l = unsafe { ASN1_ENUMERATED_get(r.response_status) };
        if !out(bp, &format!("    OCSP Response Status: {} (0x{:x})\n", name(table2string(l, &RSTAT)), l.cast_unsigned())) {
            return 0;
        }
        // SAFETY: its bytes, or NULL.
        let Some(rb) = (unsafe { of::<RespBytes, _>(r.response_bytes) }) else { return 1 };
        if !out(bp, "    Response Type: ") {
            return 0;
        }
        // SAFETY: the BIO; the type.
        if unsafe { i2a_ASN1_OBJECT(bp, rb.response_type) } <= 0 {
            return 0;
        }
        // SAFETY: the type.
        if unsafe { OBJ_obj2nid(rb.response_type) } != NID_id_pkix_OCSP_basic {
            out(bp, " (unknown response type)\n");
            return 1;
        }
        // SAFETY: the caller's response.
        let br = unsafe { OCSP_response_get1_basic(o) };
        // SAFETY: the basic response, or NULL.
        let ret = match unsafe { basic(br) } {
            // SAFETY: the BIO; the basic response.
            Some(b) => c_int::from(unsafe { print_basic(bp, b, flags) }),
            None => 0,
        };
        // SAFETY: the basic response decoded here, or NULL.
        unsafe { OCSP_BASICRESP_free(br) };
        ret
    }
}

/// The rest of `OCSP_RESPONSE_print`: the basic response.
///
/// # Safety
/// `bp` is a live BIO; `br` a live basic response.
unsafe fn print_basic(bp: *mut BIO, br: &mut super::asn::BasicResp, flags: c_ulong) -> bool {
    let rd = &mut br.tbs_response_data;
    // SAFETY: its version, or NULL.
    let l = unsafe { ASN1_INTEGER_get(rd.version) };
    if !out(bp, &format!("\n    {}\n", version(l))) || !out(bp, "    Responder Id: ") {
        return false;
    }
    let rid = &rd.responder_id;
    match rid.type_ {
        // SAFETY: the BIO; the choice's name.
        V_OCSP_RESPID_NAME => unsafe {
            X509_NAME_print_ex(
                bp,
                rid.value.cast(),
                0,
                c_ulong::from(XN_FLAG_ONELINE.cast_unsigned()),
            )
        },
        // SAFETY: the BIO; the choice's key hash.
        V_OCSP_RESPID_KEY => unsafe { i2a_ASN1_STRING(bp, rid.value.cast(), 0) },
        _ => 0,
    };
    if !out(bp, "\n    Produced At: ") {
        return false;
    }
    // SAFETY: the BIO; its time.
    if unsafe { ASN1_GENERALIZEDTIME_print(bp, rd.produced_at) } == 0 {
        return false;
    }
    if !out(bp, "\n    Responses:\n") {
        return false;
    }
    // SAFETY: its responses.
    for i in 0..unsafe { OPENSSL_sk_num(rd.responses) } {
        // SAFETY: an index within them.
        let sp = unsafe { OPENSSL_sk_value(rd.responses, i) };
        // SAFETY: a single response of the list.
        let Some(single) = (unsafe { of::<SingleResp, _>(sp) }) else {
            continue;
        };
        // SAFETY: its CertID, made with it.
        let Some(cid) = (unsafe { of::<CertId, _>(single.cert_id) }) else {
            return false;
        };
        // SAFETY: the BIO; the CertID.
        if !unsafe { certid_print(bp, cid, 4) } {
            return false;
        }
        // SAFETY: its status, made with it.
        let Some(cst) = (unsafe { of::<CertStatus, _>(single.cert_status) }) else {
            return false;
        };
        if !out(
            bp,
            &format!(
                "    Cert Status: {}",
                name(table2string(c_long::from(cst.type_), &CSTAT))
            ),
        ) {
            return false;
        }
        if cst.type_ == V_OCSP_CERTSTATUS_REVOKED {
            // SAFETY: the choice's value.
            let Some(rev) = (unsafe { of::<RevokedInfo, _>(cst.value) }) else {
                return false;
            };
            if !out(bp, "\n    Revocation Time: ") {
                return false;
            }
            // SAFETY: the BIO; its time.
            if unsafe { ASN1_GENERALIZEDTIME_print(bp, rev.revocation_time) } == 0 {
                return false;
            }
            if !rev.revocation_reason.is_null() {
                // SAFETY: its reason.
                let l = unsafe { ASN1_ENUMERATED_get(rev.revocation_reason) };
                if !out(
                    bp,
                    &format!(
                        "\n    Revocation Reason: {} (0x{:x})",
                        name(table2string(l, &REASONS)),
                        l.cast_unsigned()
                    ),
                ) {
                    return false;
                }
            }
        }
        if !out(bp, "\n    This Update: ") {
            return false;
        }
        // SAFETY: the BIO; its time.
        if unsafe { ASN1_GENERALIZEDTIME_print(bp, single.this_update) } == 0 {
            return false;
        }
        if !single.next_update.is_null() {
            if !out(bp, "\n    Next Update: ") {
                return false;
            }
            // SAFETY: as above.
            if unsafe { ASN1_GENERALIZEDTIME_print(bp, single.next_update) } == 0 {
                return false;
            }
        }
        if !out(bp, "\n") {
            return false;
        }
        // SAFETY: the BIO; its extensions, or NULL.
        if unsafe {
            X509V3_extensions_print(
                bp,
                c"Response Single Extensions".as_ptr(),
                single.single_extensions.cast(),
                flags,
                8,
            )
        } == 0
        {
            return false;
        }
        if !out(bp, "\n") {
            return false;
        }
    }
    // SAFETY: as above.
    if unsafe {
        X509V3_extensions_print(
            bp,
            c"Response Extensions".as_ptr(),
            rd.response_extensions.cast(),
            flags,
            4,
        )
    } == 0
    {
        return false;
    }
    // SAFETY: the BIO; the signature's algorithm and value.
    if unsafe { X509_signature_print(bp, &br.signature_algorithm, br.signature) } <= 0 {
        return false;
    }
    // SAFETY: as above; its certificates, or NULL.
    unsafe { print_certs(bp, br.certs) };
    true
}
