//! OCSP's X.509v3 extension methods (`v3_ocsp.c`): CrlID, archive cutoff, nonce, noCheck,
//! and service locator.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OCTET_STRING, BIO, ERR_LIB_OCSP, ERR_R_ASN1_LIB, NID_id_pkix_OCSP_CrlID,
    NID_id_pkix_OCSP_Nonce, NID_id_pkix_OCSP_archiveCutoff, NID_id_pkix_OCSP_noCheck,
    NID_id_pkix_OCSP_serviceLocator, V_ASN1_OCTET_STRING, X509V3_CTX, X509V3_EXT_METHOD,
    XN_FLAG_ONELINE,
};

use super::asn::{CrlId, OCSP_CRLID_it, OCSP_SERVICELOC_it, ServiceLoc, of};
use crate::asn1::hex::i2a_ASN1_STRING;
use crate::asn1::integer::i2a_ASN1_INTEGER;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::text::ASN1_STRING_print;
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::asn1::tpl::items::ASN1_NULL_new;
use crate::asn1::tpl::items::{ASN1_GENERALIZEDTIME_it, ASN1_NULL_it};
use crate::bio::BIO_write;
use crate::err;
use crate::ffi::ffi_callback;
use crate::objects::i2a_ASN1_OBJECT;
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_value};
use crate::x509::name::X509_NAME_print_ex;
use crate::x509v3::registry::{Method, method};
use crate::x509v3::san::GENERAL_NAME_print;

/// Writes the text: whether all of it was written.
fn out(bp: *mut BIO, s: &str) -> bool {
    let Ok(n) = c_int::try_from(s.len()) else {
        return false;
    };
    // SAFETY: the caller's BIO; the text.
    n == 0 || unsafe { BIO_write(bp, s.as_ptr().cast(), n) } > 0
}

/// `indent` spaces.
fn pad(indent: c_int) -> String {
    " ".repeat(usize::try_from(indent).unwrap_or(0))
}

ffi_callback! {
    /// `i2r_ocsp_crlid`: the CrlID's URL, number, and time, each on its line.
    ///
    /// # Safety
    /// `ext` is a live CrlID; `bp` a live BIO.
    pub(crate) unsafe extern "C" fn i2r_crlid(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, bp: *mut BIO, ind: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { of::<CrlId, _>(ext) }) else { return 0 };
        if !a.crl_url.is_null() {
            // SAFETY: the BIO; the URL.
            if !out(bp, &format!("{}crlUrl: ", pad(ind))) || unsafe { ASN1_STRING_print(bp, a.crl_url) } == 0 || !out(bp, "\n") {
                return 0;
            }
        }
        if !a.crl_num.is_null() {
            // SAFETY: the BIO; the number.
            if !out(bp, &format!("{}crlNum: ", pad(ind))) || unsafe { i2a_ASN1_INTEGER(bp, a.crl_num) } <= 0 || !out(bp, "\n") {
                return 0;
            }
        }
        if !a.crl_time.is_null() {
            // SAFETY: the BIO; the time.
            if !out(bp, &format!("{}crlTime: ", pad(ind))) || unsafe { ASN1_GENERALIZEDTIME_print(bp, a.crl_time) } == 0 || !out(bp, "\n") {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `i2r_ocsp_acutoff`: the archive cutoff time.
    ///
    /// # Safety
    /// `cutoff` is a live time; `bp` a live BIO.
    pub(crate) unsafe extern "C" fn i2r_acutoff(_method: *const X509V3_EXT_METHOD, cutoff: *mut c_void, bp: *mut BIO, ind: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the BIO; the caller's time.
        c_int::from(out(bp, &pad(ind)) && unsafe { ASN1_GENERALIZEDTIME_print(bp, cutoff.cast()) } != 0)
    }
}

ffi_callback! {
    /// `ocsp_nonce_new`: an empty OCTET STRING.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn nonce_new() -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        unsafe { ASN1_OCTET_STRING_new() }.cast()
    }
}

ffi_callback! {
    /// `ocsp_nonce_free`.
    ///
    /// # Safety
    /// `a` is NULL or the method's value.
    pub(crate) unsafe extern "C" fn nonce_free(a: *mut c_void)
    where failure = (), library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_OCTET_STRING_free(a.cast()) };
    }
}

ffi_callback! {
    /// `i2d_ocsp_nonce`: the nonce's octets, as they are (some nonces aren't DER).
    ///
    /// # Safety
    /// `a` is a live OCTET STRING; `pp` NULL or holding room for its octets.
    pub(crate) unsafe extern "C" fn i2d_nonce(a: *const c_void, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(os) = (unsafe { a.cast::<ASN1_OCTET_STRING>().as_ref() }) else { return -1 };
        // SAFETY: its octets.
        let data = unsafe { crate::asn1::text::octets(os.data, os.length) };
        // SAFETY: the caller's room, or NULL.
        if let Some(p) = unsafe { pp.as_mut() } {
            // SAFETY: room for the octets.
            unsafe { ptr::copy_nonoverlapping(data.as_ptr(), *p, data.len()) };
            // SAFETY: just past them.
            *p = unsafe { p.add(data.len()) };
        }
        os.length
    }
}

ffi_callback! {
    /// `d2i_ocsp_nonce`: the octets as the nonce, into `*a` if it holds one.
    ///
    /// # Safety
    /// `a` is NULL or holds NULL or a live OCTET STRING; `*pp` holds `length` octets.
    pub(crate) unsafe extern "C" fn d2i_nonce(a: *mut c_void, pp: *mut *const c_uchar, length: c_long) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        let pos = a.cast::<*mut ASN1_OCTET_STRING>();
        // SAFETY: the caller's slot, or NULL.
        let held = unsafe { pos.as_ref() }.map_or(ptr::null_mut(), |&p| p);
        let os = if held.is_null() {
            // SAFETY: no preconditions.
            unsafe { ASN1_OCTET_STRING_new() }
        } else {
            held
        };
        let ok = !os.is_null() && c_int::try_from(length).is_ok_and(|n| {
            // SAFETY: the caller's slot.
            let p = unsafe { *pp };
            // SAFETY: the string; the caller's octets.
            (unsafe { ASN1_OCTET_STRING_set(os, p, n) }) != 0
        });
        if !ok {
            if held != os {
                // SAFETY: the string made here, or NULL.
                unsafe { ASN1_OCTET_STRING_free(os) };
            }
            err::raise(ERR_LIB_OCSP, ERR_R_ASN1_LIB, "d2i_ocsp_nonce");
            return ptr::null_mut();
        }
        // SAFETY: the caller's slot.
        let p = unsafe { *pp };
        // SAFETY: past the octets read, within them.
        let past = unsafe { p.add(usize::try_from(length).unwrap_or(0)) };
        // SAFETY: the caller's slot.
        unsafe { *pp = past };
        // SAFETY: the caller's slot, or NULL.
        if let Some(p) = unsafe { pos.as_mut() } {
            *p = os;
        }
        os.cast()
    }
}

ffi_callback! {
    /// `i2r_ocsp_nonce`: the nonce in hex.
    ///
    /// # Safety
    /// `nonce` is a live OCTET STRING; `out` a live BIO.
    pub(crate) unsafe extern "C" fn i2r_nonce(_method: *const X509V3_EXT_METHOD, nonce: *mut c_void, out_: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the BIO; the caller's string.
        c_int::from(out(out_, &pad(indent)) && unsafe { i2a_ASN1_STRING(out_, nonce.cast(), V_ASN1_OCTET_STRING) } > 0)
    }
}

ffi_callback! {
    /// `i2r_ocsp_nocheck`: nothing to print.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn i2r_nocheck(_method: *const X509V3_EXT_METHOD, _nocheck: *mut c_void, _out: *mut BIO, _indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        1
    }
}

ffi_callback! {
    /// `s2i_ocsp_nocheck`: a NULL, whatever the text.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn s2i_nocheck(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, _str: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_OCSP
    {
        // SAFETY: no preconditions.
        unsafe { ASN1_NULL_new() }.cast()
    }
}

ffi_callback! {
    /// `i2r_ocsp_serviceloc`: the issuer, then each locator's method and location.
    ///
    /// # Safety
    /// `in_` is a live ServiceLocator; `bp` a live BIO.
    pub(crate) unsafe extern "C" fn i2r_serviceloc(_method: *const X509V3_EXT_METHOD, in_: *mut c_void, bp: *mut BIO, ind: c_int) -> c_int
    where failure = 0, library = ERR_LIB_OCSP
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { of::<ServiceLoc, _>(in_) }) else { return 0 };
        // SAFETY: the BIO; the issuer.
        if !out(bp, &format!("{}Issuer: ", pad(ind))) || unsafe { X509_NAME_print_ex(bp, a.issuer, 0, core::ffi::c_ulong::from(XN_FLAG_ONELINE.cast_unsigned())) } <= 0 {
            return 0;
        }
        // SAFETY: the locators, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(a.locator) } {
            // SAFETY: an index within them.
            let ad = unsafe { OPENSSL_sk_value(a.locator, i) }.cast::<rustyssl_abi::ACCESS_DESCRIPTION>();
            // SAFETY: a description of the list.
            let Some(d) = (unsafe { ad.as_ref() }) else { return 0 };
            if !out(bp, &format!("\n{}", pad(ind.saturating_mul(2)))) {
                return 0;
            }
            // SAFETY: the BIO; its method.
            if unsafe { i2a_ASN1_OBJECT(bp, d.method) } <= 0 || !out(bp, " - ") {
                return 0;
            }
            // SAFETY: the BIO; its location.
            if unsafe { GENERAL_NAME_print(bp, d.location) } <= 0 {
                return 0;
            }
        }
        1
    }
}

pub(crate) static OCSP_CRLID: Method = Method({
    let mut m = method(NID_id_pkix_OCSP_CrlID, 0);
    m.it = Some(OCSP_CRLID_it);
    m.i2r = Some(i2r_crlid);
    m
});

pub(crate) static OCSP_ACUTOFF: Method = Method({
    let mut m = method(NID_id_pkix_OCSP_archiveCutoff, 0);
    m.it = Some(ASN1_GENERALIZEDTIME_it);
    m.i2r = Some(i2r_acutoff);
    m
});

pub(crate) static OCSP_NONCE: Method = Method({
    let mut m = method(NID_id_pkix_OCSP_Nonce, 0);
    m.ext_new = Some(nonce_new);
    m.ext_free = Some(nonce_free);
    m.d2i = Some(d2i_nonce);
    m.i2d = Some(i2d_nonce);
    m.i2r = Some(i2r_nonce);
    m
});

pub(crate) static OCSP_NOCHECK: Method = Method({
    let mut m = method(NID_id_pkix_OCSP_noCheck, 0);
    m.it = Some(ASN1_NULL_it);
    m.s2i = Some(s2i_nocheck);
    m.i2r = Some(i2r_nocheck);
    m
});

pub(crate) static OCSP_SERVICELOC: Method = Method({
    let mut m = method(NID_id_pkix_OCSP_serviceLocator, 0);
    m.it = Some(OCSP_SERVICELOC_it);
    m.i2r = Some(i2r_serviceloc);
    m
});
