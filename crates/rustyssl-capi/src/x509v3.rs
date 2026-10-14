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

/// `x509v3_add_len_value`: a new `CONF_VALUE` of `name` and `value` (copied; no section)
/// pushed onto `*extlist`, made if NULL (and freed again if this fails).
///
/// # Safety
/// `extlist` is valid for reads and writes, holding NULL or a stack of `CONF_VALUE`s.
unsafe fn add_value(
    name: Option<&[u8]>,
    value: Option<&[u8]>,
    extlist: *mut *mut rustyssl_abi::stack_st_CONF_VALUE,
) -> bool {
    use crate::conf::c_dup;
    use crate::stack::{OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_push};
    // SAFETY: the caller's guarantee.
    let allocated = unsafe { extlist.read() }.is_null();
    let n = name.map_or(ptr::null_mut(), c_dup);
    let v = value.map_or(ptr::null_mut(), c_dup);
    let entry =
        crate::mem::alloc(size_of::<rustyssl_abi::CONF_VALUE>()).cast::<rustyssl_abi::CONF_VALUE>();
    let failed = |sk_new: bool| {
        if sk_new {
            // SAFETY: the caller's guarantee.
            let sk = unsafe { extlist.read() };
            // SAFETY: the stack made here.
            unsafe { OPENSSL_sk_free(sk.cast()) };
            // SAFETY: as above.
            unsafe { extlist.write(ptr::null_mut()) };
        }
        // SAFETY: what was made here.
        unsafe { crate::mem::release(entry.cast()) };
        // SAFETY: as above.
        unsafe { crate::mem::release(n.cast()) };
        // SAFETY: as above.
        unsafe { crate::mem::release(v.cast()) };
        false
    };
    if (name.is_some() && n.is_null()) || (value.is_some() && v.is_null()) || entry.is_null() {
        return failed(false);
    }
    if allocated {
        // SAFETY: no preconditions.
        let sk = unsafe { OPENSSL_sk_new_null() };
        if sk.is_null() {
            err::raise(
                ERR_LIB_X509V3,
                rustyssl_abi::ERR_R_CRYPTO_LIB,
                "x509v3_add_len_value",
            );
            return failed(false);
        }
        // SAFETY: the caller's guarantee.
        unsafe { extlist.write(sk.cast()) };
    }
    // SAFETY: a new allocation of a CONF_VALUE.
    unsafe {
        entry.write(rustyssl_abi::CONF_VALUE {
            section: ptr::null_mut(),
            name: n,
            value: v,
        });
    };
    // SAFETY: the caller's guarantee.
    let sk = unsafe { extlist.read() };
    // SAFETY: the list, and the new entry it takes.
    if unsafe { OPENSSL_sk_push(sk.cast(), entry.cast()) } == 0 {
        return failed(allocated);
    }
    true
}

ffi_export! {
    /// Pushes a new `CONF_VALUE` of `name` and `value` (either may be NULL; both copied) onto
    /// `*extlist`, making the stack if it's NULL. Returns 1, or 0.
    ///
    /// # Safety
    /// `name` and `value` are NULL or C strings; `extlist` is valid for reads and writes,
    /// holding NULL or a stack of `CONF_VALUE`s.
    pub unsafe extern "C" fn X509V3_add_value(name: *const c_char, value: *const c_char, extlist: *mut *mut rustyssl_abi::stack_st_CONF_VALUE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if extlist.is_null() {
            return 0;
        }
        // SAFETY: the caller's strings.
        let name = (!name.is_null()).then(|| unsafe { CStr::from_ptr(name) }.to_bytes());
        // SAFETY: as above.
        let value = (!value.is_null()).then(|| unsafe { CStr::from_ptr(value) }.to_bytes());
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { add_value(name, value, extlist) })
    }
}

ffi_export! {
    /// Frees a `CONF_VALUE` and its strings (its section too); NULL does nothing.
    ///
    /// # Safety
    /// `conf` is NULL or a `CONF_VALUE` whose strings were allocated with `OPENSSL_malloc`.
    pub unsafe extern "C" fn X509V3_conf_free(conf: *mut rustyssl_abi::CONF_VALUE)
    where failure = (), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { conf.as_ref() }) else { return };
        // SAFETY: the entry's strings.
        unsafe { crate::mem::release(c.name.cast()) };
        // SAFETY: as above.
        unsafe { crate::mem::release(c.value.cast()) };
        // SAFETY: as above.
        unsafe { crate::mem::release(c.section.cast()) };
        // SAFETY: the entry.
        unsafe { crate::mem::release(conf.cast()) };
    }
}

/// `X509V3_conf_free` as a stack's free function.
unsafe extern "C" fn conf_free_item(item: *mut core::ffi::c_void) {
    // SAFETY: an item of a stack of CONF_VALUEs.
    unsafe { X509V3_conf_free(item.cast()) };
}

ffi_export! {
    /// The `name:value` items of `line` (separated by commas; a value may be absent) as a new
    /// stack of `CONF_VALUE`s, or NULL with `X509V3_R_INVALID_EMPTY_NAME` or
    /// `X509V3_R_INVALID_NULL_VALUE`.
    ///
    /// # Safety
    /// `line` is NULL or a C string.
    pub unsafe extern "C" fn X509V3_parse_list(line: *const c_char) -> *mut rustyssl_abi::stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        if line.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's string.
        let text = unsafe { CStr::from_ptr(line) }.to_bytes();
        let items = match rustyssl_conf::name_value_list(text) {
            Ok(items) => items,
            Err(e) => {
                let reason = match e {
                    rustyssl_conf::NameValueError::EmptyName => rustyssl_abi::X509V3_R_INVALID_EMPTY_NAME,
                    rustyssl_conf::NameValueError::NullValue => X509V3_R_INVALID_NULL_VALUE,
                };
                err::raise(ERR_LIB_X509V3, reason, "X509V3_parse_list");
                return ptr::null_mut();
            }
        };
        let mut list: *mut rustyssl_abi::stack_st_CONF_VALUE = ptr::null_mut();
        for (name, value) in &items {
            // SAFETY: a local list.
            if !unsafe { add_value(Some(name), value.as_deref(), &raw mut list) } {
                // SAFETY: the list made here, with its entries.
                unsafe { crate::stack::OPENSSL_sk_pop_free(list.cast(), Some(conf_free_item)) };
                return ptr::null_mut();
            }
        }
        list
    }
}

ffi_export! {
    /// The boolean `value->value` names: `TRUE`/`true`/`Y`/`y`/`YES`/`yes` give 0xff,
    /// `FALSE`/`false`/`N`/`n`/`NO`/`no` give 0. Returns 1, or 0 with
    /// `X509V3_R_INVALID_BOOLEAN_STRING` and the name and value as data.
    ///
    /// # Safety
    /// `value` is a live `CONF_VALUE`; `asn1_bool` is valid for a write.
    pub unsafe extern "C" fn X509V3_get_value_bool(value: *const rustyssl_abi::CONF_VALUE, asn1_bool: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { value.as_ref() }) else { return 0 };
        // SAFETY: the value's strings.
        let text = (!v.value.is_null()).then(|| unsafe { CStr::from_ptr(v.value) }.to_bytes());
        let parsed = match text {
            Some(b"TRUE" | b"true" | b"Y" | b"y" | b"YES" | b"yes") => Some(0xff),
            Some(b"FALSE" | b"false" | b"N" | b"n" | b"NO" | b"no") => Some(0),
            _ => None,
        };
        if let Some(b) = parsed {
            if !asn1_bool.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { asn1_bool.write(b) };
            }
            return 1;
        }
        err::raise(ERR_LIB_X509V3, rustyssl_abi::X509V3_R_INVALID_BOOLEAN_STRING, "X509V3_get_value_bool");
        // SAFETY: as above.
        let name = (!v.name.is_null()).then(|| unsafe { CStr::from_ptr(v.name) }.to_bytes());
        err::add_error_data([Some(&b"name="[..]), name, Some(b", value="), text]);
        0
    }
}
