//! The X509V3 string conversions that ASN.1 printing uses ahead of the X.509 phase
//! (`i2s_ASN1_INTEGER`, `i2s_ASN1_ENUMERATED`, `i2s_ASN1_ENUMERATED_TABLE`,
//! `i2s_ASN1_OCTET_STRING`, `s2i_ASN1_INTEGER`, `s2i_ASN1_OCTET_STRING`), as OpenSSL's
//! `v3_utl.c`, `v3_enum.c`, and `v3_skid.c` do them. Numbers go through
//! `rustyssl_asn1::number` rather than BIGNUM, with the same text: decimal below 128 bits, `0x`
//! and hex above.

use core::ffi::{CStr, c_char, c_int, c_long};
use core::ptr;

use rustyssl_abi::{
    ASN1_ENUMERATED, ASN1_INTEGER, ASN1_OCTET_STRING, ASN1_R_WRONG_INTEGER_TYPE, ENUMERATED_NAMES,
    ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB, ERR_R_X509V3_LIB, V_ASN1_ENUMERATED,
    V_ASN1_INTEGER, V_ASN1_NEG, V_ASN1_OCTET_STRING, X509V3_CTX, X509V3_EXT_METHOD,
    X509V3_R_BN_DEC2BN_ERROR, X509V3_R_BN_TO_ASN1_INTEGER_ERROR, X509V3_R_INVALID_NULL_VALUE,
};
use rustyssl_asn1::number;

use crate::asn1::{integer, string};
use crate::err;
use crate::ffi::ffi_export;
use crate::objects::c_string;

/// `i2s_ASN1_INTEGER` and `i2s_ASN1_ENUMERATED`: `a`'s value as text in C memory, or NULL
/// (raising errors as `ASN1_*_to_BN` and `bignum_to_string` do).
///
/// # Safety
/// `a` is NULL or a live string whose data holds its length.
unsafe fn to_text(a: *const ASN1_INTEGER, kind: c_int, function: &str) -> *mut c_char {
    if a.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let a = unsafe { &*a };
    if a.type_ & !V_ASN1_NEG != kind {
        err::raise(ERR_LIB_ASN1, ASN1_R_WRONG_INTEGER_TYPE, "asn1_string_to_bn");
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, function);
        return ptr::null_mut();
    }
    let magnitude = match usize::try_from(a.length) {
        // SAFETY: the caller's guarantee.
        Ok(n) if n > 0 && !a.data.is_null() => unsafe { core::slice::from_raw_parts(a.data, n) },
        _ => &[],
    };
    let text = number::to_text(magnitude, a.type_ & V_ASN1_NEG != 0);
    let s = c_string(text.as_bytes());
    if s.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB, function);
    }
    s
}

ffi_export! {
    /// `a`'s value as text (decimal below 128 bits, else `0x` and hex), for the caller to
    /// free, or NULL. `method` is unused.
    ///
    /// # Safety
    /// `a` is NULL or a live INTEGER.
    pub unsafe extern "C" fn i2s_ASN1_INTEGER(method: *mut X509V3_EXT_METHOD, a: *const ASN1_INTEGER) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let _ = method;
        // SAFETY: the caller's guarantee.
        unsafe { to_text(a, V_ASN1_INTEGER, "i2s_ASN1_INTEGER") }
    }
}

ffi_export! {
    /// `i2s_ASN1_INTEGER` for an ENUMERATED.
    ///
    /// # Safety
    /// `a` is NULL or a live ENUMERATED.
    pub unsafe extern "C" fn i2s_ASN1_ENUMERATED(method: *mut X509V3_EXT_METHOD, a: *const ASN1_ENUMERATED) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let _ = method;
        // SAFETY: the caller's guarantee.
        unsafe { to_text(a, V_ASN1_ENUMERATED, "i2s_ASN1_ENUMERATED") }
    }
}

ffi_export! {
    /// The long name the method's table (`usr_data`, an `ENUMERATED_NAMES` array ending with a
    /// NULL `lname`) gives `e`'s value, or `i2s_ASN1_ENUMERATED` of it.
    ///
    /// Unlike OpenSSL, a NULL `method` reads no table rather than crashing
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `method` is NULL or a live method whose `usr_data` is such a table; `e` is NULL or a
    /// live ENUMERATED.
    pub unsafe extern "C" fn i2s_ASN1_ENUMERATED_TABLE(method: *mut X509V3_EXT_METHOD, e: *const ASN1_ENUMERATED) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let value = unsafe { integer::ASN1_ENUMERATED_get(e) };
        if !method.is_null() {
            // SAFETY: the caller's guarantee.
            let mut name: *const ENUMERATED_NAMES = unsafe { (*method).usr_data }.cast_const().cast();
            // SAFETY: a table ending with a NULL long name.
            while !name.is_null() && !unsafe { (*name).lname }.is_null() {
                // SAFETY: as above.
                let entry = unsafe { &*name };
                if value == c_long::from(entry.bitnum) {
                    // SAFETY: a string.
                    return c_string(unsafe { CStr::from_ptr(entry.lname) }.to_bytes());
                }
                name = name.wrapping_add(1);
            }
        }
        // SAFETY: as above.
        unsafe { i2s_ASN1_ENUMERATED(method, e) }
    }
}

ffi_export! {
    /// `oct`'s octets as colon-separated uppercase hex (`OPENSSL_buf2hexstr`), or NULL.
    ///
    /// Unlike OpenSSL, NULL `oct` is NULL rather than a crash (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `oct` is NULL or a live string.
    pub unsafe extern "C" fn i2s_ASN1_OCTET_STRING(method: *mut X509V3_EXT_METHOD, oct: *const ASN1_OCTET_STRING) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let _ = method;
        if oct.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let s = unsafe { &*oct };
        // SAFETY: a string's data holds its length.
        unsafe { crate::string::OPENSSL_buf2hexstr(s.data, c_long::from(s.length)) }
    }
}

ffi_export! {
    /// The INTEGER `value` denotes: decimal, or hex after `0x`, with an optional `-`. NULL
    /// (`X509V3_R_BN_DEC2BN_ERROR`) for anything else.
    ///
    /// # Safety
    /// `value` is NULL or a string.
    pub unsafe extern "C" fn s2i_ASN1_INTEGER(method: *mut X509V3_EXT_METHOD, value: *const c_char) -> *mut ASN1_INTEGER
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let _ = method;
        if value.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_VALUE, "s2i_ASN1_INTEGER");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let text = unsafe { CStr::from_ptr(value) }.to_bytes();
        let Some((magnitude, negative)) = number::from_text(text) else {
            err::raise(ERR_LIB_X509V3, X509V3_R_BN_DEC2BN_ERROR, "s2i_ASN1_INTEGER");
            return ptr::null_mut();
        };
        let octets: &[u8] = if magnitude.is_empty() { &[0] } else { &magnitude };
        let aint = string::type_new(V_ASN1_INTEGER);
        // SAFETY: a new string.
        if aint.is_null() || unsafe { string::set(aint, octets.as_ptr().cast(), c_int::try_from(octets.len()).unwrap_or(c_int::MAX)) } == 0 {
            // SAFETY: the string, or NULL.
            unsafe { string::ASN1_STRING_free(aint) };
            err::raise(ERR_LIB_X509V3, X509V3_R_BN_TO_ASN1_INTEGER_ERROR, "s2i_ASN1_INTEGER");
            return ptr::null_mut();
        }
        if negative {
            // SAFETY: a live string.
            unsafe { (*aint).type_ |= V_ASN1_NEG };
        }
        aint
    }
}

ffi_export! {
    /// The OCTET STRING of the hex in `str` (`OPENSSL_hexstr2buf`: pairs of digits, colons
    /// allowed between them), or NULL.
    ///
    /// # Safety
    /// `str` is a string (as `OPENSSL_hexstr2buf` takes it).
    pub unsafe extern "C" fn s2i_ASN1_OCTET_STRING(method: *mut X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, str: *const c_char) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let _ = (method, ctx);
        let oct = string::type_new(V_ASN1_OCTET_STRING);
        if oct.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, "s2i_ASN1_OCTET_STRING");
            return ptr::null_mut();
        }
        let mut length: c_long = 0;
        // SAFETY: the caller's guarantee.
        let data = unsafe { crate::string::OPENSSL_hexstr2buf(str, &raw mut length) };
        if data.is_null() {
            // SAFETY: the string made above.
            unsafe { string::ASN1_STRING_free(oct) };
            return ptr::null_mut();
        }
        // SAFETY: a new string, given the buffer.
        unsafe { string::ASN1_STRING_set0(oct, data.cast(), c_int::try_from(length).unwrap_or(c_int::MAX)) };
        oct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_arguments_are_safe() {
        // SAFETY: NULL is refused.
        assert!(unsafe { i2s_ASN1_OCTET_STRING(ptr::null_mut(), ptr::null()) }.is_null());
        let e = string::type_new(V_ASN1_ENUMERATED);
        // SAFETY: a live ENUMERATED.
        unsafe { integer::ASN1_ENUMERATED_set(e, 3) };
        // SAFETY: a NULL method has no table.
        let s = unsafe { i2s_ASN1_ENUMERATED_TABLE(ptr::null_mut(), e) };
        // SAFETY: a string.
        assert_eq!(unsafe { CStr::from_ptr(s) }, c"3");
        // SAFETY: the string and the ENUMERATED made here.
        unsafe { crate::mem::release(s.cast()) };
        // SAFETY: as above.
        unsafe { string::ASN1_STRING_free(e) };
    }
}
