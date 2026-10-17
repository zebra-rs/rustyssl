//! The simple extensions (`v3_bitst.c`, `v3_ia5.c`, `v3_utf8.c`, `v3_int.c`, `v3_enum.c`,
//! `v3_skid.c`, `v3_bcons.c`, `v3_extku.c`, `v3_pku.c`, and the value helpers of `v3_utl.c`):
//! key usage and Netscape's certificate type as named bits, Netscape's strings, the signing
//! tools' UTF8String, the CRL numbers and reason, inhibitAnyPolicy, the subject key
//! identifier, basic constraints, the extended key usages (and the OCSP and attribute
//! certificate extensions that share their type), and the private key usage period.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_IA5STRING, ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE,
    ASN1_OCTET_STRING, ASN1_TFLG_IMPLICIT, ASN1_TFLG_OPTIONAL, ASN1_TFLG_SEQUENCE_OF,
    ASN1_UTF8STRING, BASIC_CONSTRAINTS, BIO, BIT_STRING_BITNAME, CONF_VALUE,
    CRL_REASON_AA_COMPROMISE, CRL_REASON_AFFILIATION_CHANGED, CRL_REASON_CA_COMPROMISE,
    CRL_REASON_CERTIFICATE_HOLD, CRL_REASON_CESSATION_OF_OPERATION, CRL_REASON_KEY_COMPROMISE,
    CRL_REASON_PRIVILEGE_WITHDRAWN, CRL_REASON_REMOVE_FROM_CRL, CRL_REASON_SUPERSEDED,
    CRL_REASON_UNSPECIFIED, ENUMERATED_NAMES, ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB,
    ERR_R_CRYPTO_LIB, ERR_R_PASSED_NULL_PARAMETER, EXTENDED_KEY_USAGE,
    NID_acceptable_cert_policies, NID_acceptable_privilege_policies, NID_basic_constraints,
    NID_crl_number, NID_crl_reason, NID_delta_crl, NID_ext_key_usage,
    NID_id_pkix_OCSP_acceptableResponses, NID_inhibit_any_policy, NID_key_usage,
    NID_netscape_base_url, NID_netscape_ca_policy_url, NID_netscape_ca_revocation_url,
    NID_netscape_cert_type, NID_netscape_comment, NID_netscape_renewal_url,
    NID_netscape_revocation_url, NID_netscape_ssl_server_name, NID_private_key_usage_period,
    NID_subject_key_identifier, NID_subjectSignTool, PKEY_USAGE_PERIOD, X509V3_CTX,
    X509V3_CTX_TEST, X509V3_EXT_METHOD, X509V3_R_INVALID_NAME, X509V3_R_INVALID_NULL_ARGUMENT,
    X509V3_R_INVALID_OBJECT_IDENTIFIER, X509V3_R_NO_PUBLIC_KEY, X509V3_R_NO_SUBJECT_DETAILS,
    X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT, stack_st_CONF_VALUE,
};

use super::registry::{Method, method};
use super::{
    X509V3_add_value, X509V3_get_value_bool, i2s_ASN1_ENUMERATED_TABLE, i2s_ASN1_INTEGER,
    i2s_ASN1_OCTET_STRING, s2i_ASN1_INTEGER, s2i_ASN1_OCTET_STRING,
};
use crate::asn1::bit_string::{ASN1_BIT_STRING_get_bit, ASN1_BIT_STRING_set_bit};
use crate::asn1::string::{
    ASN1_BIT_STRING_free, ASN1_BIT_STRING_new, ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new,
    ASN1_OCTET_STRING_set, ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_type_new,
};
use crate::asn1::time::ASN1_GENERALIZEDTIME_print;
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, ASN1_ENUMERATED_it, ASN1_FBOOLEAN_it, ASN1_GENERALIZEDTIME_it,
    ASN1_IA5STRING_it, ASN1_INTEGER_it, ASN1_OBJECT_it, ASN1_OCTET_STRING_it, ASN1_UTF8STRING_it,
    d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::bio::BIO_write;
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::md_ctx::EVP_Digest;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_txt2obj, i2t_ASN1_OBJECT};
use crate::stack::{
    OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::cert::cert_of;
use crate::x509::pubkey::{X509_PUBKEY_get0_param, libctx_of};
use crate::x509::req::req_of;

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

// The value helpers (`v3_utl.c`).

ffi_export! {
    /// Adds `name` with the value `value` (both copied; a NULL value is none): 1, or 0.
    ///
    /// # Safety
    /// `name` and `value` are NULL or C strings; `extlist` holds NULL or a live stack.
    pub unsafe extern "C" fn X509V3_add_value_uchar(name: *const c_char, value: *const u8, extlist: *mut *mut stack_st_CONF_VALUE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509V3_add_value(name, value.cast(), extlist) }
    }
}

ffi_export! {
    /// Adds `name` with `TRUE` or `FALSE`: 1, or 0.
    ///
    /// # Safety
    /// `name` is NULL or a C string; `extlist` holds NULL or a live stack.
    pub unsafe extern "C" fn X509V3_add_value_bool(name: *const c_char, asn1_bool: c_int, extlist: *mut *mut stack_st_CONF_VALUE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        let v = if asn1_bool != 0 { c"TRUE" } else { c"FALSE" };
        // SAFETY: the caller's guarantee; a static value.
        unsafe { X509V3_add_value(name, v.as_ptr(), extlist) }
    }
}

ffi_export! {
    /// Adds `name` with `TRUE` if `asn1_bool` is, and nothing otherwise: 1, or 0.
    ///
    /// # Safety
    /// As for [`X509V3_add_value_bool`].
    pub unsafe extern "C" fn X509V3_add_value_bool_nf(name: *const c_char, asn1_bool: c_int, extlist: *mut *mut stack_st_CONF_VALUE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if asn1_bool == 0 {
            return 1;
        }
        // SAFETY: the caller's guarantee; a static value.
        unsafe { X509V3_add_value(name, c"TRUE".as_ptr(), extlist) }
    }
}

ffi_export! {
    /// Adds `name` with `aint` as text (`i2s_ASN1_INTEGER`); nothing for NULL. 1, or 0.
    ///
    /// # Safety
    /// `name` is NULL or a C string; `aint` is NULL or a live INTEGER; `extlist` holds NULL
    /// or a live stack.
    pub unsafe extern "C" fn X509V3_add_value_int(name: *const c_char, aint: *const ASN1_INTEGER, extlist: *mut *mut stack_st_CONF_VALUE) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        if aint.is_null() {
            return 1;
        }
        // SAFETY: the caller's INTEGER.
        let s = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), aint) };
        if s.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee; the text.
        let ret = unsafe { X509V3_add_value(name, s, extlist) };
        // SAFETY: made above.
        unsafe { mem::release(s.cast()) };
        ret
    }
}

/// `X509V3_conf_add_error_name_value`: the value's name and value as the error's data.
///
/// # Safety
/// `v` is a live `CONF_VALUE`.
pub(crate) unsafe fn add_error_name_value(v: &CONF_VALUE) {
    // SAFETY: the value's strings.
    let name = unsafe { text(v.name) };
    // SAFETY: as above.
    let value = unsafe { text(v.value) };
    err::add_error_data([Some(&b"name="[..]), name, Some(b", value="), value]);
}

ffi_export! {
    /// `value->value` as a new INTEGER (`s2i_ASN1_INTEGER`) into `*aint`: 1, or 0 with the
    /// name and value as the error's data.
    ///
    /// # Safety
    /// `value` is a live `CONF_VALUE`; `aint` is writable.
    pub unsafe extern "C" fn X509V3_get_value_int(value: *const CONF_VALUE, aint: *mut *mut ASN1_INTEGER) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { value.as_ref() }) else { return 0 };
        // SAFETY: its value, NULL or a string.
        let itmp = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), v.value) };
        if itmp.is_null() {
            // SAFETY: as above.
            unsafe { add_error_name_value(v) };
            return 0;
        }
        // As OpenSSL's, an INTEGER already there is left to the caller.
        // SAFETY: the caller's guarantee.
        unsafe { aint.write(itmp) };
        1
    }
}

// Named bits (`v3_bitst.c`).

/// A table of named bits in a static, ended by a NULL name.
pub(crate) struct BitNames<const N: usize>(pub(crate) [BIT_STRING_BITNAME; N]);

// SAFETY: immutable, with pointers only to static strings.
unsafe impl<const N: usize> Sync for BitNames<N> {}

const fn bit(bitnum: c_int, lname: &'static CStr, sname: &'static CStr) -> BIT_STRING_BITNAME {
    BIT_STRING_BITNAME {
        bitnum,
        lname: lname.as_ptr(),
        sname: sname.as_ptr(),
    }
}

const BIT_END: BIT_STRING_BITNAME = BIT_STRING_BITNAME {
    bitnum: -1,
    lname: ptr::null(),
    sname: ptr::null(),
};

static NS_CERT_TYPE: BitNames<9> = BitNames([
    bit(0, c"SSL Client", c"client"),
    bit(1, c"SSL Server", c"server"),
    bit(2, c"S/MIME", c"email"),
    bit(3, c"Object Signing", c"objsign"),
    bit(4, c"Unused", c"reserved"),
    bit(5, c"SSL CA", c"sslCA"),
    bit(6, c"S/MIME CA", c"emailCA"),
    bit(7, c"Object Signing CA", c"objCA"),
    BIT_END,
]);

static KEY_USAGE: BitNames<10> = BitNames([
    bit(0, c"Digital Signature", c"digitalSignature"),
    bit(1, c"Non Repudiation", c"nonRepudiation"),
    bit(2, c"Key Encipherment", c"keyEncipherment"),
    bit(3, c"Data Encipherment", c"dataEncipherment"),
    bit(4, c"Key Agreement", c"keyAgreement"),
    bit(5, c"Certificate Sign", c"keyCertSign"),
    bit(6, c"CRL Sign", c"cRLSign"),
    bit(7, c"Encipher Only", c"encipherOnly"),
    bit(8, c"Decipher Only", c"decipherOnly"),
    BIT_END,
]);

/// The named bits of a method's table (its `usr_data`), up to the NULL name.
///
/// # Safety
/// `method` is a live method whose `usr_data` is such a table.
unsafe fn bit_names<'a>(
    method: *const X509V3_EXT_METHOD,
) -> impl Iterator<Item = &'a BIT_STRING_BITNAME> {
    // SAFETY: the caller's guarantee.
    let mut b = unsafe { (*method).usr_data }
        .cast::<BIT_STRING_BITNAME>()
        .cast_const();
    core::iter::from_fn(move || {
        // SAFETY: within the table, which ends with a NULL name.
        let n = unsafe { b.as_ref() }?;
        if n.lname.is_null() {
            return None;
        }
        b = b.wrapping_add(1);
        Some(n)
    })
}

ffi_export! {
    /// The long names of the bits set in `bits`, from the method's table, added to `extlist`
    /// (made if NULL), which is returned.
    ///
    /// # Safety
    /// `method` is a live method whose `usr_data` is a table of named bits; `bits` is a live
    /// BIT STRING; `extlist` is NULL or a live stack.
    pub unsafe extern "C" fn i2v_ASN1_BIT_STRING(method: *mut X509V3_EXT_METHOD, bits: *mut ASN1_BIT_STRING, extlist: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let mut ret = extlist;
        // SAFETY: the caller's guarantee.
        for b in unsafe { bit_names(method) } {
            // SAFETY: the caller's BIT STRING.
            if unsafe { ASN1_BIT_STRING_get_bit(bits, b.bitnum) } != 0 {
                // SAFETY: a static name; the list.
                unsafe { X509V3_add_value(b.lname, ptr::null(), &raw mut ret) };
            }
        }
        ret
    }
}

ffi_export! {
    /// A BIT STRING with the bits each value names (by its short or long name in the method's
    /// table), or NULL with `X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT` and the name.
    ///
    /// # Safety
    /// `method` as for [`i2v_ASN1_BIT_STRING`]; `nval` is NULL or a live stack of
    /// `CONF_VALUE`s.
    pub unsafe extern "C" fn v2i_ASN1_BIT_STRING(method: *mut X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut ASN1_BIT_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_ASN1_BIT_STRING";
        // SAFETY: no preconditions.
        let bs = unsafe { ASN1_BIT_STRING_new() };
        if bs.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(nval.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let v = unsafe { OPENSSL_sk_value(nval.cast(), i) }.cast::<CONF_VALUE>();
            // SAFETY: as above.
            let Some(v) = (unsafe { v.as_ref() }) else { continue };
            // SAFETY: its name, NULL or a string.
            let name = unsafe { text(v.name) };
            // SAFETY: the caller's guarantee.
            let found = unsafe { bit_names(method) }.find(|b| {
                // SAFETY: static names.
                let s = unsafe { text(b.sname) };
                // SAFETY: as above.
                let l = unsafe { text(b.lname) };
                name.is_some() && (name == s || name == l)
            });
            let Some(b) = found else {
                err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT, F, name.unwrap_or_default());
                // SAFETY: made above.
                unsafe { ASN1_BIT_STRING_free(bs) };
                return ptr::null_mut();
            };
            // SAFETY: the new BIT STRING.
            if unsafe { ASN1_BIT_STRING_set_bit(bs, b.bitnum, 1) } == 0 {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                // SAFETY: as above.
                unsafe { ASN1_BIT_STRING_free(bs) };
                return ptr::null_mut();
            }
        }
        bs
    }
}

ffi_callback! {
    /// `i2v_ASN1_BIT_STRING` as a method's `i2v`.
    ///
    /// # Safety
    /// As for [`i2v_ASN1_BIT_STRING`].
    pub(crate) unsafe extern "C" fn bits_i2v(method: *const X509V3_EXT_METHOD, ext: *mut c_void, extlist: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2v_ASN1_BIT_STRING(method.cast_mut(), ext.cast(), extlist) }
    }
}

ffi_callback! {
    /// `v2i_ASN1_BIT_STRING` as a method's `v2i`.
    ///
    /// # Safety
    /// As for [`v2i_ASN1_BIT_STRING`].
    pub(crate) unsafe extern "C" fn bits_v2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, values: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { v2i_ASN1_BIT_STRING(method.cast_mut(), ctx, values) }.cast()
    }
}

/// `EXT_BITSTRING`: a BIT STRING extension of named bits.
const fn bitstring<const N: usize>(nid: c_int, table: &'static BitNames<N>) -> X509V3_EXT_METHOD {
    let mut m = method(nid, 0);
    m.it = Some(ASN1_BIT_STRING_it);
    m.i2v = Some(bits_i2v);
    m.v2i = Some(bits_v2i);
    m.usr_data = (&raw const table.0).cast_mut().cast();
    m
}

pub(crate) static NSCERT: Method = Method(bitstring(NID_netscape_cert_type, &NS_CERT_TYPE));
pub(crate) static KEY_USAGE_METHOD: Method = Method(bitstring(NID_key_usage, &KEY_USAGE));

// Strings (`v3_ia5.c`, `v3_utf8.c`).

/// A copy of a string's octets as a C string in C memory.
fn copy_out(data: &[u8]) -> *mut c_char {
    let p: *mut u8 = mem::alloc(data.len().saturating_add(1)).cast();
    if p.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: room for the octets and a NUL.
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) };
    // SAFETY: as above.
    unsafe { p.wrapping_add(data.len()).write(0) };
    p.cast()
}

/// A string's octets, if it has any (`length > 0`).
///
/// # Safety
/// `s` is NULL or a live string whose data holds its length.
unsafe fn octets<'a>(s: *const rustyssl_abi::ASN1_STRING) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    let s = unsafe { s.as_ref() }?;
    let n = usize::try_from(s.length).ok().filter(|&n| n > 0)?;
    // SAFETY: as above.
    Some(unsafe { core::slice::from_raw_parts(s.data, n) })
}

ffi_export! {
    /// The IA5String's text as a new C string, or NULL (also for an empty one).
    ///
    /// # Safety
    /// `ia5` is NULL or a live string.
    pub unsafe extern "C" fn i2s_ASN1_IA5STRING(_method: *mut X509V3_EXT_METHOD, ia5: *mut ASN1_IA5STRING) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { octets(ia5) }.map_or(ptr::null_mut(), copy_out)
    }
}

/// A new string of `type_` with `str`'s text, or NULL (`X509V3_R_INVALID_NULL_ARGUMENT` for
/// NULL); `asn1_err` raises `ERR_R_ASN1_LIB` when setting it fails too.
///
/// # Safety
/// `str` is NULL or a C string.
unsafe fn string_of(
    str: *const c_char,
    type_: c_int,
    f: &str,
    asn1_err: bool,
) -> *mut rustyssl_abi::ASN1_STRING {
    // SAFETY: the caller's guarantee.
    let Some(t) = (unsafe { text(str) }) else {
        err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_ARGUMENT, f);
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let s = unsafe { ASN1_STRING_type_new(type_) };
    if s.is_null() {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, f);
        return ptr::null_mut();
    }
    let Ok(n) = c_int::try_from(t.len()) else {
        // SAFETY: made above.
        unsafe { ASN1_STRING_free(s) };
        return ptr::null_mut();
    };
    // SAFETY: the new string; the text's octets.
    if unsafe { ASN1_STRING_set(s, t.as_ptr().cast(), n) } == 0 {
        if asn1_err {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, f);
        }
        // SAFETY: made above.
        unsafe { ASN1_STRING_free(s) };
        return ptr::null_mut();
    }
    s
}

ffi_export! {
    /// A new IA5String of `str`'s text, or NULL (`X509V3_R_INVALID_NULL_ARGUMENT` for NULL).
    ///
    /// # Safety
    /// `str` is NULL or a C string.
    pub unsafe extern "C" fn s2i_ASN1_IA5STRING(_method: *mut X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, str: *const c_char) -> *mut ASN1_IA5STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { string_of(str, rustyssl_abi::V_ASN1_IA5STRING, "s2i_ASN1_IA5STRING", false) }
    }
}

ffi_export! {
    /// The UTF8String's text as a new C string, or NULL with `ERR_R_PASSED_NULL_PARAMETER`
    /// for NULL or an empty one.
    ///
    /// # Safety
    /// `utf8` is NULL or a live string.
    pub unsafe extern "C" fn i2s_ASN1_UTF8STRING(_method: *mut X509V3_EXT_METHOD, utf8: *mut ASN1_UTF8STRING) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let empty = unsafe { utf8.as_ref() }.is_none_or(|s| s.length == 0);
        if empty {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER, "i2s_ASN1_UTF8STRING");
            return ptr::null_mut();
        }
        // SAFETY: as above.
        unsafe { octets(utf8) }.map_or(ptr::null_mut(), copy_out)
    }
}

ffi_export! {
    /// A new UTF8String of `str`'s text, or NULL (`X509V3_R_INVALID_NULL_ARGUMENT` for NULL).
    ///
    /// # Safety
    /// `str` is NULL or a C string.
    pub unsafe extern "C" fn s2i_ASN1_UTF8STRING(_method: *mut X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, str: *const c_char) -> *mut ASN1_UTF8STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { string_of(str, rustyssl_abi::V_ASN1_UTF8STRING, "s2i_ASN1_UTF8STRING", true) }
    }
}

ffi_callback! {
    /// `i2s_ASN1_IA5STRING` as a method's `i2s`.
    ///
    /// # Safety
    /// `ext` is NULL or a live IA5String.
    pub(crate) unsafe extern "C" fn ia5_i2s(method: *const X509V3_EXT_METHOD, ext: *mut c_void) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2s_ASN1_IA5STRING(method.cast_mut(), ext.cast()) }
    }
}

ffi_callback! {
    /// `s2i_ASN1_IA5STRING` as a method's `s2i`.
    ///
    /// # Safety
    /// `str` is NULL or a C string.
    pub(crate) unsafe extern "C" fn ia5_s2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, str: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { s2i_ASN1_IA5STRING(method.cast_mut(), ctx, str) }.cast()
    }
}

ffi_callback! {
    /// `i2s_ASN1_UTF8STRING` as a method's `i2s`.
    ///
    /// # Safety
    /// `ext` is NULL or a live UTF8String.
    pub(crate) unsafe extern "C" fn utf8_i2s(method: *const X509V3_EXT_METHOD, ext: *mut c_void) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2s_ASN1_UTF8STRING(method.cast_mut(), ext.cast()) }
    }
}

ffi_callback! {
    /// `s2i_ASN1_UTF8STRING` as a method's `s2i`.
    ///
    /// # Safety
    /// `str` is NULL or a C string.
    pub(crate) unsafe extern "C" fn utf8_s2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, str: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { s2i_ASN1_UTF8STRING(method.cast_mut(), ctx, str) }.cast()
    }
}

/// `EXT_IA5STRING`.
const fn ia5(nid: c_int) -> Method {
    let mut m = method(nid, 0);
    m.it = Some(ASN1_IA5STRING_it);
    m.i2s = Some(ia5_i2s);
    m.s2i = Some(ia5_s2i);
    Method(m)
}

/// `EXT_UTF8STRING`.
const fn utf8(nid: c_int) -> Method {
    let mut m = method(nid, 0);
    m.it = Some(ASN1_UTF8STRING_it);
    m.i2s = Some(utf8_i2s);
    m.s2i = Some(utf8_s2i);
    Method(m)
}

pub(crate) static NS_IA5: [Method; 7] = [
    ia5(NID_netscape_base_url),
    ia5(NID_netscape_revocation_url),
    ia5(NID_netscape_ca_revocation_url),
    ia5(NID_netscape_renewal_url),
    ia5(NID_netscape_ca_policy_url),
    ia5(NID_netscape_ssl_server_name),
    ia5(NID_netscape_comment),
];
pub(crate) static SIGN_TOOL: Method = utf8(NID_subjectSignTool);

// Numbers (`v3_int.c`, `v3_enum.c`).

ffi_callback! {
    /// `i2s_ASN1_INTEGER` as a method's `i2s`.
    ///
    /// # Safety
    /// `ext` is NULL or a live INTEGER.
    pub(crate) unsafe extern "C" fn int_i2s(method: *const X509V3_EXT_METHOD, ext: *mut c_void) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2s_ASN1_INTEGER(method.cast_mut(), ext.cast()) }
    }
}

ffi_callback! {
    /// `s2i_asn1_int`: `s2i_ASN1_INTEGER` as a method's `s2i`.
    ///
    /// # Safety
    /// `value` is NULL or a C string.
    pub(crate) unsafe extern "C" fn int_s2i(method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, value: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { s2i_ASN1_INTEGER(method.cast_mut(), value) }.cast()
    }
}

ffi_callback! {
    /// `i2s_ASN1_ENUMERATED_TABLE` as a method's `i2s`.
    ///
    /// # Safety
    /// `method` has a table of names; `ext` is NULL or a live ENUMERATED.
    pub(crate) unsafe extern "C" fn enum_i2s(method: *const X509V3_EXT_METHOD, ext: *mut c_void) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2s_ASN1_ENUMERATED_TABLE(method.cast_mut(), ext.cast()) }
    }
}

const fn integer(nid: c_int, s2i: bool) -> Method {
    let mut m = method(nid, 0);
    m.it = Some(ASN1_INTEGER_it);
    m.i2s = Some(int_i2s);
    if s2i {
        m.s2i = Some(int_s2i);
    }
    Method(m)
}

pub(crate) static CRL_NUM: Method = integer(NID_crl_number, false);
pub(crate) static DELTA_CRL: Method = integer(NID_delta_crl, false);
pub(crate) static INHIBIT_ANYP: Method = integer(NID_inhibit_any_policy, true);

/// A table of enumerated names in a static, ended by a NULL name.
pub(crate) struct EnumNames<const N: usize>(pub(crate) [ENUMERATED_NAMES; N]);

// SAFETY: immutable, with pointers only to static strings.
unsafe impl<const N: usize> Sync for EnumNames<N> {}

const fn reason(n: c_int, lname: &'static CStr, sname: &'static CStr) -> ENUMERATED_NAMES {
    ENUMERATED_NAMES {
        bitnum: n,
        lname: lname.as_ptr(),
        sname: sname.as_ptr(),
    }
}

static CRL_REASONS: EnumNames<11> = EnumNames([
    reason(CRL_REASON_UNSPECIFIED, c"Unspecified", c"unspecified"),
    reason(
        CRL_REASON_KEY_COMPROMISE,
        c"Key Compromise",
        c"keyCompromise",
    ),
    reason(CRL_REASON_CA_COMPROMISE, c"CA Compromise", c"CACompromise"),
    reason(
        CRL_REASON_AFFILIATION_CHANGED,
        c"Affiliation Changed",
        c"affiliationChanged",
    ),
    reason(CRL_REASON_SUPERSEDED, c"Superseded", c"superseded"),
    reason(
        CRL_REASON_CESSATION_OF_OPERATION,
        c"Cessation Of Operation",
        c"cessationOfOperation",
    ),
    reason(
        CRL_REASON_CERTIFICATE_HOLD,
        c"Certificate Hold",
        c"certificateHold",
    ),
    reason(
        CRL_REASON_REMOVE_FROM_CRL,
        c"Remove From CRL",
        c"removeFromCRL",
    ),
    reason(
        CRL_REASON_PRIVILEGE_WITHDRAWN,
        c"Privilege Withdrawn",
        c"privilegeWithdrawn",
    ),
    reason(CRL_REASON_AA_COMPROMISE, c"AA Compromise", c"AACompromise"),
    ENUMERATED_NAMES {
        bitnum: -1,
        lname: ptr::null(),
        sname: ptr::null(),
    },
]);

pub(crate) static CRL_REASON: Method = Method({
    let mut m = method(NID_crl_reason, 0);
    m.it = Some(ASN1_ENUMERATED_it);
    m.i2s = Some(enum_i2s);
    m.usr_data = (&raw const CRL_REASONS.0).cast_mut().cast();
    m
});

// The subject key identifier (`v3_skid.c`).

ffi_callback! {
    /// `i2s_ASN1_OCTET_STRING` as a method's `i2s`.
    ///
    /// # Safety
    /// `ext` is a live OCTET STRING.
    pub(crate) unsafe extern "C" fn octet_i2s(method: *const X509V3_EXT_METHOD, ext: *mut c_void) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2s_ASN1_OCTET_STRING(method.cast_mut(), ext.cast()) }
    }
}

/// `ossl_x509_pubkey_hash`: the SHA-1 of the SubjectPublicKeyInfo's key octets (in its
/// library context), or NULL (`X509V3_R_NO_PUBLIC_KEY` without a key).
///
/// # Safety
/// `pubkey` is NULL or a live SubjectPublicKeyInfo.
pub(crate) unsafe fn pubkey_hash(pubkey: *mut rustyssl_abi::X509_PUBKEY) -> *mut ASN1_OCTET_STRING {
    if pubkey.is_null() {
        err::raise(
            ERR_LIB_X509V3,
            X509V3_R_NO_PUBLIC_KEY,
            "ossl_x509_pubkey_hash",
        );
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let (libctx, propq) = unsafe { libctx_of(pubkey) };
    // SAFETY: the key's library context and properties; a static name.
    let md = unsafe { EVP_MD_fetch(libctx, rustyssl_abi::SN_sha1.as_ptr(), propq) };
    if md.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let oct = unsafe { ASN1_OCTET_STRING_new() };
    let mut pk: *const u8 = ptr::null();
    let mut pklen: c_int = 0;
    let mut dig = [0u8; rustyssl_abi::EVP_MAX_MD_SIZE as usize];
    let mut diglen: core::ffi::c_uint = 0;
    let ok = !oct.is_null()
        // SAFETY: the caller's SubjectPublicKeyInfo; writable outputs.
        && unsafe { X509_PUBKEY_get0_param(ptr::null_mut(), &raw mut pk, &raw mut pklen, ptr::null_mut(), pubkey) } != 0
        && {
            let n = usize::try_from(pklen).unwrap_or(0);
            // SAFETY: the key's `pklen` octets; room for the digest.
            (unsafe { EVP_Digest(pk.cast(), n, dig.as_mut_ptr(), &raw mut diglen, md, ptr::null_mut()) } != 0)
        }
        // SAFETY: the new string; the digest.
        && unsafe { ASN1_OCTET_STRING_set(oct, dig.as_ptr(), c_int::try_from(diglen).unwrap_or(0)) } != 0;
    // SAFETY: fetched above.
    unsafe { EVP_MD_free(md) };
    if !ok {
        // SAFETY: made above, or NULL.
        unsafe { ASN1_OCTET_STRING_free(oct) };
        return ptr::null_mut();
    }
    oct
}

ffi_callback! {
    /// `s2i_skey_id`: `none` (an empty identifier), `hash` (the SHA-1 of the subject's key,
    /// from the context's certificate or request; empty in a test context), or hex.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `str` is a C string.
    pub(crate) unsafe extern "C" fn skey_id_s2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, str: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let t = unsafe { text(str) };
        if t == Some(b"none") {
            // SAFETY: no preconditions.
            return unsafe { ASN1_OCTET_STRING_new() }.cast();
        }
        if t != Some(b"hash") {
            // SAFETY: the caller's guarantee.
            return unsafe { s2i_ASN1_OCTET_STRING(method.cast_mut(), ctx, str) }.cast();
        }
        // SAFETY: as above.
        let c = unsafe { ctx.as_ref() };
        if c.is_some_and(|c| c.flags & X509V3_CTX_TEST != 0) {
            // SAFETY: no preconditions.
            return unsafe { ASN1_OCTET_STRING_new() }.cast();
        }
        let key = match c {
            // SAFETY: the context's certificate.
            Some(c) if !c.subject_cert.is_null() => unsafe { cert_of(c.subject_cert) }.map(|x| x.cert_info.key),
            // SAFETY: the context's request.
            Some(c) if !c.subject_req.is_null() => unsafe { req_of(c.subject_req) }.map(|r| r.req_info.pubkey),
            _ => None,
        };
        let Some(key) = key else {
            err::raise(ERR_LIB_X509V3, X509V3_R_NO_SUBJECT_DETAILS, "s2i_skey_id");
            return ptr::null_mut();
        };
        // SAFETY: the subject's SubjectPublicKeyInfo.
        unsafe { pubkey_hash(key) }.cast()
    }
}

pub(crate) static SKEY_ID: Method = Method({
    let mut m = method(NID_subject_key_identifier, 0);
    m.it = Some(ASN1_OCTET_STRING_it);
    m.i2s = Some(octet_i2s);
    m.s2i = Some(skey_id_s2i);
    m
});

// Basic constraints (`v3_bcons.c`).

static BCONS_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(BASIC_CONSTRAINTS, ca),
        c"ca",
        ASN1_FBOOLEAN_it,
    ),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(BASIC_CONSTRAINTS, pathlen),
        c"pathlen",
        ASN1_INTEGER_it,
    ),
]);

item_fns! {
    /// BasicConstraints: SEQUENCE { cA BOOLEAN DEFAULT FALSE, pathLenConstraint INTEGER OPTIONAL }.
    pub unsafe extern "C" fn BASIC_CONSTRAINTS_it = sequence::<BASIC_CONSTRAINTS, 2>(&BCONS_TT, None, c"BASIC_CONSTRAINTS");
}

new_free! {
    pub unsafe extern "C" fn BASIC_CONSTRAINTS_new, pub unsafe extern "C" fn BASIC_CONSTRAINTS_free(BASIC_CONSTRAINTS) = BASIC_CONSTRAINTS_it;
}

i2d! {
    /// Encodes BasicConstraints.
    pub unsafe extern "C" fn i2d_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS) = BASIC_CONSTRAINTS_it;
}

d2i! {
    /// Decodes BasicConstraints (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_BASIC_CONSTRAINTS(BASIC_CONSTRAINTS) = BASIC_CONSTRAINTS_it;
}

ffi_callback! {
    /// `i2v_BASIC_CONSTRAINTS`: `CA:TRUE`/`FALSE`, and the path length if there's one.
    ///
    /// # Safety
    /// `ext` is a live BasicConstraints; `extlist` is NULL or a live stack.
    pub(crate) unsafe extern "C" fn bcons_i2v(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, extlist: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(b) = (unsafe { ext.cast::<BASIC_CONSTRAINTS>().as_ref() }) else { return extlist };
        let mut list = extlist;
        // SAFETY: static names; the list.
        unsafe { X509V3_add_value_bool(c"CA".as_ptr(), b.ca, &raw mut list) };
        // SAFETY: as above; its path length, or NULL.
        unsafe { X509V3_add_value_int(c"pathlen".as_ptr(), b.pathlen, &raw mut list) };
        list
    }
}

ffi_callback! {
    /// `v2i_BASIC_CONSTRAINTS`: `CA` (a boolean) and `pathlen` (an integer); any other name
    /// fails with `X509V3_R_INVALID_NAME`.
    ///
    /// # Safety
    /// `values` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn bcons_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, values: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: no preconditions.
        let bcons = unsafe { BASIC_CONSTRAINTS_new() };
        // SAFETY: new, or NULL.
        let Some(b) = (unsafe { bcons.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, "v2i_BASIC_CONSTRAINTS");
            return ptr::null_mut();
        };
        let fail = || {
            // SAFETY: made above.
            unsafe { BASIC_CONSTRAINTS_free(bcons) };
            ptr::null_mut()
        };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(values.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let vp = unsafe { OPENSSL_sk_value(values.cast(), i) }.cast::<CONF_VALUE>();
            // SAFETY: as above.
            let Some(v) = (unsafe { vp.as_ref() }) else { continue };
            // SAFETY: its name.
            match unsafe { text(v.name) } {
                Some(b"CA") => {
                    // SAFETY: the value; the structure's field.
                    if unsafe { X509V3_get_value_bool(vp, &raw mut b.ca) } == 0 {
                        return fail();
                    }
                }
                Some(b"pathlen") => {
                    // SAFETY: as above.
                    if unsafe { X509V3_get_value_int(vp, &raw mut b.pathlen) } == 0 {
                        return fail();
                    }
                }
                _ => {
                    err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NAME, "v2i_BASIC_CONSTRAINTS");
                    // SAFETY: as above.
                    unsafe { add_error_name_value(v) };
                    return fail();
                }
            }
        }
        bcons.cast()
    }
}

pub(crate) static BCONS: Method = Method({
    let mut m = method(NID_basic_constraints, 0);
    m.it = Some(BASIC_CONSTRAINTS_it);
    m.i2v = Some(bcons_i2v);
    m.v2i = Some(bcons_v2i);
    m
});

// Extended key usage (`v3_extku.c`).

static EKU_TT: Template = template(
    ASN1_TFLG_SEQUENCE_OF,
    0,
    c"EXTENDED_KEY_USAGE",
    ASN1_OBJECT_it,
);

item_fns! {
    /// ExtKeyUsageSyntax: SEQUENCE OF KeyPurposeId.
    pub unsafe extern "C" fn EXTENDED_KEY_USAGE_it = item(ASN1_ITYPE_PRIMITIVE, -1, &raw const EKU_TT.0, 0, ptr::null(), 0, c"EXTENDED_KEY_USAGE");
}

new_free! {
    pub unsafe extern "C" fn EXTENDED_KEY_USAGE_new, pub unsafe extern "C" fn EXTENDED_KEY_USAGE_free(EXTENDED_KEY_USAGE) = EXTENDED_KEY_USAGE_it;
}

i2d! {
    /// Encodes ExtKeyUsageSyntax.
    pub unsafe extern "C" fn i2d_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE) = EXTENDED_KEY_USAGE_it;
}

d2i! {
    /// Decodes ExtKeyUsageSyntax (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_EXTENDED_KEY_USAGE(EXTENDED_KEY_USAGE) = EXTENDED_KEY_USAGE_it;
}

ffi_callback! {
    /// `i2v_EXTENDED_KEY_USAGE`: each purpose's name (`i2t_ASN1_OBJECT`, at most 79 octets).
    ///
    /// # Safety
    /// `a` is a live stack of objects; `ext_list` is NULL or a live stack.
    pub(crate) unsafe extern "C" fn eku_i2v(_method: *const X509V3_EXT_METHOD, a: *mut c_void, ext_list: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let mut list = ext_list;
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(a.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let obj = unsafe { OPENSSL_sk_value(a.cast(), i) };
            let mut tmp = [0 as c_char; 80];
            // SAFETY: room for 80 octets; an object of the stack.
            unsafe { i2t_ASN1_OBJECT(tmp.as_mut_ptr(), 80, obj.cast()) };
            // SAFETY: the name, NUL-terminated; the list.
            unsafe { X509V3_add_value(ptr::null(), tmp.as_ptr(), &raw mut list) };
        }
        list
    }
}

/// `ASN1_OBJECT_free` as a stack's free function.
unsafe extern "C" fn free_obj(o: *mut c_void) {
    // SAFETY: an object of the stack, which the stack owned.
    unsafe { ASN1_OBJECT_free(o.cast()) };
}

ffi_callback! {
    /// `v2i_EXTENDED_KEY_USAGE`: each value (or name, without one) as an object's name or
    /// numbers; one that isn't fails with `X509V3_R_INVALID_OBJECT_IDENTIFIER` and the text.
    ///
    /// # Safety
    /// `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn eku_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's stack, or NULL.
        let num = unsafe { OPENSSL_sk_num(nval.cast()) };
        // SAFETY: no preconditions.
        let extku = unsafe { OPENSSL_sk_new_reserve(None, num) };
        if extku.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, "v2i_EXTENDED_KEY_USAGE");
            return ptr::null_mut();
        }
        for i in 0..num {
            // SAFETY: an index within the stack; a `CONF_VALUE`.
            let v = unsafe { OPENSSL_sk_value(nval.cast(), i) }.cast::<CONF_VALUE>();
            // SAFETY: as above.
            let Some(v) = (unsafe { v.as_ref() }) else { continue };
            let extval = if v.value.is_null() { v.name } else { v.value };
            // SAFETY: a C string, or NULL.
            let obj = if extval.is_null() { ptr::null_mut() } else { unsafe { OBJ_txt2obj(extval, 0) } };
            if obj.is_null() {
                // SAFETY: the stack made above, with its objects.
                unsafe { OPENSSL_sk_pop_free(extku, Some(free_obj)) };
                // SAFETY: as above.
                let t = unsafe { text(extval) }.unwrap_or_default();
                err::raise_with_bytes(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER, "v2i_EXTENDED_KEY_USAGE", t);
                return ptr::null_mut();
            }
            // SAFETY: the stack, with room reserved; the object, which it takes.
            unsafe { OPENSSL_sk_push(extku, obj.cast()) };
        }
        extku.cast()
    }
}

const fn eku(nid: c_int) -> Method {
    let mut m = method(nid, 0);
    m.it = Some(EXTENDED_KEY_USAGE_it);
    m.i2v = Some(eku_i2v);
    m.v2i = Some(eku_v2i);
    Method(m)
}

pub(crate) static EXT_KU: Method = eku(NID_ext_key_usage);
pub(crate) static OCSP_ACCRESP: Method = eku(NID_id_pkix_OCSP_acceptableResponses);
pub(crate) static ACC_CERT_POLICIES: Method = eku(NID_acceptable_cert_policies);
pub(crate) static ACC_PRIV_POLICIES: Method = eku(NID_acceptable_privilege_policies);

// The private key usage period (`v3_pku.c`).

static PKU_TT: Templates<2> = Templates([
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(PKEY_USAGE_PERIOD, notBefore),
        c"notBefore",
        ASN1_GENERALIZEDTIME_it,
    ),
    template_at(
        ASN1_TFLG_IMPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(PKEY_USAGE_PERIOD, notAfter),
        c"notAfter",
        ASN1_GENERALIZEDTIME_it,
    ),
]);

item_fns! {
    /// PrivateKeyUsagePeriod: SEQUENCE { notBefore [0] GeneralizedTime OPTIONAL, notAfter [1]
    /// GeneralizedTime OPTIONAL }.
    pub unsafe extern "C" fn PKEY_USAGE_PERIOD_it = sequence::<PKEY_USAGE_PERIOD, 2>(&PKU_TT, None, c"PKEY_USAGE_PERIOD");
}

new_free! {
    pub unsafe extern "C" fn PKEY_USAGE_PERIOD_new, pub unsafe extern "C" fn PKEY_USAGE_PERIOD_free(PKEY_USAGE_PERIOD) = PKEY_USAGE_PERIOD_it;
}

i2d! {
    /// Encodes PrivateKeyUsagePeriod.
    pub unsafe extern "C" fn i2d_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD) = PKEY_USAGE_PERIOD_it;
}

d2i! {
    /// Decodes PrivateKeyUsagePeriod (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_PKEY_USAGE_PERIOD(PKEY_USAGE_PERIOD) = PKEY_USAGE_PERIOD_it;
}

ffi_callback! {
    /// `i2r_PKEY_USAGE_PERIOD`: `Not Before: <time>, Not After: <time>` (each if present).
    ///
    /// # Safety
    /// `ext` is a live PrivateKeyUsagePeriod; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn pku_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { ext.cast::<PKEY_USAGE_PERIOD>().as_ref() }) else { return 0 };
        // SAFETY: the caller's BIO.
        unsafe { super::registry::indent_to(out, indent) };
        if !u.notBefore.is_null() {
            // SAFETY: as above; static text.
            unsafe { BIO_write(out, c"Not Before: ".as_ptr().cast(), 12) };
            // SAFETY: as above; its time.
            unsafe { ASN1_GENERALIZEDTIME_print(out, u.notBefore) };
            if !u.notAfter.is_null() {
                // SAFETY: as above.
                unsafe { BIO_write(out, c", ".as_ptr().cast(), 2) };
            }
        }
        if !u.notAfter.is_null() {
            // SAFETY: as above.
            unsafe { BIO_write(out, c"Not After: ".as_ptr().cast(), 11) };
            // SAFETY: as above.
            unsafe { ASN1_GENERALIZEDTIME_print(out, u.notAfter) };
        }
        1
    }
}

pub(crate) static PKEY_USAGE_PERIOD_METHOD: Method = Method({
    let mut m = method(NID_private_key_usage_period, 0);
    m.it = Some(PKEY_USAGE_PERIOD_it);
    m.i2r = Some(pku_i2r);
    m
});
