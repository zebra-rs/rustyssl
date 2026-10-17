//! The smaller extensions (`v3_sxnet.c`, `v3_tlsf.c`, `v3_ist.c`, `v3_audit_id.c`): Thawte's
//! strong extranet IDs, the TLS feature (OCSP must-staple), the issuer's signing tools, and an
//! attribute certificate's audit identity.

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_INTEGER, ASN1_ITEM, ASN1_ITYPE_PRIMITIVE, ASN1_OCTET_STRING, ASN1_TFLG_SEQUENCE_OF, BIO,
    CONF_VALUE, ERR_LIB_ASN1, ERR_LIB_X509V3, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB,
    ERR_R_PASSED_INVALID_ARGUMENT, ISSUER_SIGN_TOOL, NID_ac_auditIdentity, NID_issuerSignTool,
    NID_sxnet, NID_tlsfeature, SXNET, SXNETID, TLS_FEATURE, X509V3_CTX, X509V3_EXT_METHOD,
    X509V3_EXT_MULTILINE, X509V3_R_DUPLICATE_ZONE_ID, X509V3_R_ERROR_CONVERTING_ZONE,
    X509V3_R_INVALID_NULL_ARGUMENT, X509V3_R_INVALID_SYNTAX, X509V3_R_USER_TOO_LONG,
    stack_st_CONF_VALUE,
};

use super::registry::{Method, method};
use super::simple::{X509V3_add_value_int, add_error_name_value, octet_i2s};
use super::{X509V3_add_value, i2s_ASN1_INTEGER, item_at, s2i_ASN1_INTEGER, s2i_ASN1_OCTET_STRING};
use crate::asn1::integer::{
    ASN1_INTEGER_cmp, ASN1_INTEGER_get, ASN1_INTEGER_get_int64, ASN1_INTEGER_set,
};
use crate::asn1::string::{
    ASN1_INTEGER_free, ASN1_INTEGER_new, ASN1_OCTET_STRING_set, ASN1_STRING_set,
};
use crate::asn1::text::ASN1_STRING_print;
use crate::asn1::tpl::items::{
    ASN1_INTEGER_it, ASN1_OCTET_STRING_it, ASN1_UTF8STRING_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{Template, item, item_fns, template, template_at};
use crate::bio::BIO_write;
use crate::bio::print::BIO_printf;
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::stack::{OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_push};

/// A C string's bytes, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes())
}

// Strong extranet IDs (`v3_sxnet.c`).

static SXNETID_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(SXNETID, zone), c"zone", ASN1_INTEGER_it),
    template_at(
        0,
        0,
        offset_of!(SXNETID, user),
        c"user",
        ASN1_OCTET_STRING_it,
    ),
]);

item_fns! {
    /// SXNETID: SEQUENCE { zone INTEGER, user OCTET STRING }.
    pub unsafe extern "C" fn SXNETID_it = sequence::<SXNETID, 2>(&SXNETID_TT, None, c"SXNETID");
}

new_free! {
    pub unsafe extern "C" fn SXNETID_new, pub unsafe extern "C" fn SXNETID_free(SXNETID) = SXNETID_it;
}

i2d! {
    /// Encodes an SXNETID.
    pub unsafe extern "C" fn i2d_SXNETID(SXNETID) = SXNETID_it;
}

d2i! {
    /// Decodes an SXNETID (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_SXNETID(SXNETID) = SXNETID_it;
}

static SXNET_TT: Templates<2> = Templates([
    template_at(
        0,
        0,
        offset_of!(SXNET, version),
        c"version",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_SEQUENCE_OF,
        0,
        offset_of!(SXNET, ids),
        c"ids",
        SXNETID_it,
    ),
]);

item_fns! {
    /// SXNET: SEQUENCE { version INTEGER, ids SEQUENCE OF SXNETID }.
    pub unsafe extern "C" fn SXNET_it = sequence::<SXNET, 2>(&SXNET_TT, None, c"SXNET");
}

new_free! {
    pub unsafe extern "C" fn SXNET_new, pub unsafe extern "C" fn SXNET_free(SXNET) = SXNET_it;
}

i2d! {
    /// Encodes an SXNET.
    pub unsafe extern "C" fn i2d_SXNET(SXNET) = SXNET_it;
}

d2i! {
    /// Decodes an SXNET (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_SXNET(SXNET) = SXNET_it;
}

ffi_callback! {
    /// `sxnet_i2r`: the version and each zone with its user.
    ///
    /// # Safety
    /// `ext` is a live SXNET; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn sxnet_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(sx) = (unsafe { ext.cast::<SXNET>().as_ref() }) else { return 0 };
        let mut v: i64 = 0;
        // SAFETY: its version; a writable number.
        let got = unsafe { ASN1_INTEGER_get_int64(&raw mut v, sx.version) } != 0;
        match c_long::try_from(v).ok().filter(|&vl| got && vl < c_long::MAX) {
            // SAFETY: the caller's BIO; a static format and its arguments.
            Some(vl) => unsafe { BIO_printf(out, c"%*sVersion: %ld (0x%lX)".as_ptr(), indent, c"".as_ptr(), vl.wrapping_add(1), vl) },
            // SAFETY: as above.
            None => unsafe { BIO_printf(out, c"%*sVersion: <unsupported>".as_ptr(), indent, c"".as_ptr()) },
        };
        // SAFETY: its IDs.
        let n = unsafe { OPENSSL_sk_num(sx.ids.cast()) };
        for i in 0..n {
            // SAFETY: an index within the IDs.
            let Some(id) = (unsafe { item_at::<SXNETID>(sx.ids.cast(), i) }) else { continue };
            // SAFETY: its zone.
            let tmp = unsafe { i2s_ASN1_INTEGER(ptr::null_mut(), id.zone) };
            if tmp.is_null() {
                return 0;
            }
            // SAFETY: as above; the text.
            unsafe { BIO_printf(out, c"\n%*sZone: %s, User: ".as_ptr(), indent, c"".as_ptr(), tmp) };
            // SAFETY: made above.
            unsafe { mem::release(tmp.cast()) };
            // SAFETY: as above; its user.
            unsafe { ASN1_STRING_print(out, id.user) };
        }
        1
    }
}

ffi_callback! {
    /// `sxnet_v2i`: each `zone:user`.
    ///
    /// # Safety
    /// `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn sxnet_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let mut sx: *mut SXNET = ptr::null_mut();
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(nval.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let Some(cnf) = (unsafe { item_at::<CONF_VALUE>(nval.cast(), i) }) else { continue };
            // SAFETY: a local slot; its strings.
            if unsafe { SXNET_add_id_asc(&raw mut sx, cnf.name, cnf.value, -1) } == 0 {
                // SAFETY: made here, or NULL.
                unsafe { SXNET_free(sx) };
                return ptr::null_mut();
            }
        }
        sx.cast()
    }
}

ffi_export! {
    /// Adds the user for the zone given in text (`s2i_ASN1_INTEGER`): 1, or 0.
    ///
    /// # Safety
    /// `psx` holds NULL or a live SXNET; `zone` is NULL or a C string; `user` holds `userlen`
    /// octets (a C string for -1).
    pub unsafe extern "C" fn SXNET_add_id_asc(psx: *mut *mut SXNET, zone: *const c_char, user: *const c_char, userlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let izone = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), zone) };
        if izone.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_ERROR_CONVERTING_ZONE, "SXNET_add_id_asc");
            return 0;
        }
        // SAFETY: as above; the zone, which it takes on success.
        if unsafe { SXNET_add_id_INTEGER(psx, izone, user, userlen) } == 0 {
            // SAFETY: made above.
            unsafe { ASN1_INTEGER_free(izone) };
            return 0;
        }
        1
    }
}

/// A new INTEGER of `lzone`, or NULL with `ERR_R_ASN1_LIB`.
fn zone_of(lzone: c_ulong, f: &str) -> *mut ASN1_INTEGER {
    // SAFETY: no preconditions.
    let izone = unsafe { ASN1_INTEGER_new() };
    let v = c_long::from_ne_bytes(lzone.to_ne_bytes());
    // SAFETY: the new INTEGER, or NULL.
    if izone.is_null() || unsafe { ASN1_INTEGER_set(izone, v) } == 0 {
        err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, f);
        // SAFETY: made above, or NULL.
        unsafe { ASN1_INTEGER_free(izone) };
        return ptr::null_mut();
    }
    izone
}

ffi_export! {
    /// Adds the user for the zone `lzone`: 1, or 0.
    ///
    /// # Safety
    /// As for [`SXNET_add_id_asc`].
    pub unsafe extern "C" fn SXNET_add_id_ulong(psx: *mut *mut SXNET, lzone: c_ulong, user: *const c_char, userlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        let izone = zone_of(lzone, "SXNET_add_id_ulong");
        if izone.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee; the zone, which it takes on success.
        if unsafe { SXNET_add_id_INTEGER(psx, izone, user, userlen) } == 0 {
            // SAFETY: made above.
            unsafe { ASN1_INTEGER_free(izone) };
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Adds the user (at most 64 octets) for `zone`, which the SXNET takes on success, making
    /// `*psx` (version 1) if NULL: 1, or 0 (`X509V3_R_DUPLICATE_ZONE_ID` for a zone it has).
    ///
    /// # Safety
    /// `psx` is NULL or holds NULL or a live SXNET; `zone` is NULL or a live INTEGER; `user`
    /// holds `userlen` octets (a C string for -1).
    pub unsafe extern "C" fn SXNET_add_id_INTEGER(psx: *mut *mut SXNET, zone: *mut ASN1_INTEGER, user: *const c_char, userlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        const F: &str = "SXNET_add_id_INTEGER";
        if psx.is_null() || zone.is_null() || user.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_ARGUMENT, F);
            return 0;
        }
        let len = if userlen == -1 {
            // SAFETY: a C string.
            c_int::try_from(unsafe { CStr::from_ptr(user) }.count_bytes()).unwrap_or(c_int::MAX)
        } else {
            userlen
        };
        if len > 64 {
            err::raise(ERR_LIB_X509V3, X509V3_R_USER_TOO_LONG, F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let given = unsafe { psx.read() };
        let sx = if given.is_null() {
            // SAFETY: no preconditions.
            let sx = unsafe { SXNET_new() };
            // SAFETY: new, or NULL.
            let version = unsafe { sx.as_ref() }.map_or(ptr::null_mut(), |s| s.version);
            // SAFETY: its version, or NULL.
            if version.is_null() || unsafe { ASN1_INTEGER_set(version, 0) } == 0 {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                // SAFETY: made above, or NULL.
                unsafe { SXNET_free(sx) };
                return 0;
            }
            sx
        } else {
            given
        };
        let fail = |id: *mut SXNETID| {
            // SAFETY: made here, or NULL.
            unsafe { SXNETID_free(id) };
            if given.is_null() {
                // SAFETY: made above.
                unsafe { SXNET_free(sx) };
            }
            0
        };
        // SAFETY: the SXNET; the caller's zone.
        if !unsafe { SXNET_get_id_INTEGER(sx, zone) }.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_DUPLICATE_ZONE_ID, F);
            return fail(ptr::null_mut());
        }
        // SAFETY: no preconditions.
        let id = unsafe { SXNETID_new() };
        // SAFETY: new, or NULL.
        let Some(i) = (unsafe { id.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return fail(id);
        };
        // SAFETY: its user; the caller's octets.
        if unsafe { ASN1_OCTET_STRING_set(i.user, user.cast(), len) } == 0 {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return fail(id);
        }
        // SAFETY: the SXNET, given or made.
        let ids = unsafe { (*sx).ids };
        // SAFETY: its IDs; the ID, which they take.
        if unsafe { OPENSSL_sk_push(ids.cast(), id.cast()) } == 0 {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            return fail(id);
        }
        // SAFETY: its own zone.
        unsafe { ASN1_INTEGER_free(i.zone) };
        i.zone = zone;
        // SAFETY: the caller's slot.
        unsafe { psx.write(sx) };
        1
    }
}

ffi_export! {
    /// The user for the zone given in text, or NULL.
    ///
    /// # Safety
    /// `sx` is a live SXNET; `zone` is NULL or a C string.
    pub unsafe extern "C" fn SXNET_get_id_asc(sx: *mut SXNET, zone: *const c_char) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let izone = unsafe { s2i_ASN1_INTEGER(ptr::null_mut(), zone) };
        if izone.is_null() {
            err::raise(ERR_LIB_X509V3, X509V3_R_ERROR_CONVERTING_ZONE, "SXNET_get_id_asc");
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let oct = unsafe { SXNET_get_id_INTEGER(sx, izone) };
        // SAFETY: made above.
        unsafe { ASN1_INTEGER_free(izone) };
        oct
    }
}

ffi_export! {
    /// The user for the zone `lzone`, or NULL.
    ///
    /// # Safety
    /// `sx` is a live SXNET.
    pub unsafe extern "C" fn SXNET_get_id_ulong(sx: *mut SXNET, lzone: c_ulong) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let izone = zone_of(lzone, "SXNET_get_id_ulong");
        if izone.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let oct = unsafe { SXNET_get_id_INTEGER(sx, izone) };
        // SAFETY: made above.
        unsafe { ASN1_INTEGER_free(izone) };
        oct
    }
}

ffi_export! {
    /// The user for `zone` (the SXNET keeps it), or NULL.
    ///
    /// # Safety
    /// `sx` is NULL or a live SXNET; `zone` is a live INTEGER.
    pub unsafe extern "C" fn SXNET_get_id_INTEGER(sx: *mut SXNET, zone: *mut ASN1_INTEGER) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { sx.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: its IDs.
        let n = unsafe { OPENSSL_sk_num(s.ids.cast()) };
        for i in 0..n {
            // SAFETY: an index within the IDs.
            let Some(id) = (unsafe { item_at::<SXNETID>(s.ids.cast(), i) }) else { continue };
            // SAFETY: its zone; the caller's.
            if unsafe { ASN1_INTEGER_cmp(id.zone, zone) } == 0 {
                return id.user;
            }
        }
        ptr::null_mut()
    }
}

pub(crate) static SXNET_METHOD: Method = Method({
    let mut m = method(NID_sxnet, X509V3_EXT_MULTILINE);
    m.it = Some(SXNET_it);
    m.v2i = Some(sxnet_v2i);
    m.i2r = Some(sxnet_i2r);
    m
});

// The TLS feature (`v3_tlsf.c`).

static TLSF_T: Template = template(ASN1_TFLG_SEQUENCE_OF, 0, c"TLS_FEATURE", ASN1_INTEGER_it);

/// `TLS_FEATURE_it`, which OpenSSL doesn't export.
unsafe extern "C" fn tls_feature_it() -> *const ASN1_ITEM {
    static ITEM: crate::asn1::tpl::Item = item(
        ASN1_ITYPE_PRIMITIVE,
        -1,
        &raw const TLSF_T.0,
        0,
        ptr::null(),
        0,
        c"TLS_FEATURE",
    );
    &raw const ITEM.0
}

new_free! {
    pub unsafe extern "C" fn TLS_FEATURE_new, pub unsafe extern "C" fn TLS_FEATURE_free(TLS_FEATURE) = tls_feature_it;
}

/// The features with names.
const TLS_FEATURES: [(c_long, &CStr); 2] = [(5, c"status_request"), (17, c"status_request_v2")];

ffi_callback! {
    /// `i2v_TLS_FEATURE`: each feature's name, or its number.
    ///
    /// # Safety
    /// `ext` is a live stack of INTEGERs; `ext_list` is NULL or a live stack.
    pub(crate) unsafe extern "C" fn tlsf_i2v(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, ext_list: *mut stack_st_CONF_VALUE) -> *mut stack_st_CONF_VALUE
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        let mut list = ext_list;
        // SAFETY: the caller's stack.
        let n = unsafe { OPENSSL_sk_num(ext.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let ai = unsafe { crate::stack::OPENSSL_sk_value(ext.cast(), i) }.cast::<ASN1_INTEGER>();
            // SAFETY: a feature.
            let id = unsafe { ASN1_INTEGER_get(ai) };
            if let Some((_, name)) = TLS_FEATURES.iter().find(|f| f.0 == id) {
                // SAFETY: a static name; the list.
                unsafe { X509V3_add_value(ptr::null(), name.as_ptr(), &raw mut list) };
            } else {
                // SAFETY: the feature; the list.
                unsafe { X509V3_add_value_int(ptr::null(), ai, &raw mut list) };
            }
        }
        list
    }
}

/// `ASN1_INTEGER_free` as a stack's free function.
unsafe extern "C" fn free_int(p: *mut c_void) {
    // SAFETY: an INTEGER of the stack, which the stack owned.
    unsafe { ASN1_INTEGER_free(p.cast()) };
}

/// `strtol(extval, &end, 10)` with nothing left over, or `None`.
fn decimal(t: &[u8]) -> Option<c_long> {
    let s = core::str::from_utf8(t).ok()?;
    // `strtol` skips leading white space and takes a sign.
    let s = s.trim_start_matches([' ', '\t', '\n', '\x0b', '\x0c', '\r']);
    if s.is_empty() {
        return None;
    }
    s.parse::<c_long>().ok()
}

ffi_callback! {
    /// `v2i_TLS_FEATURE`: each value (or name) as a feature's name (any case) or a number from
    /// 0 to 65535.
    ///
    /// # Safety
    /// `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn tlsf_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_TLS_FEATURE";
        // SAFETY: no preconditions.
        let tlsf = unsafe { OPENSSL_sk_new_null() };
        if tlsf.is_null() {
            err::raise(ERR_LIB_X509V3, ERR_R_CRYPTO_LIB, F);
            return ptr::null_mut();
        }
        let fail = || {
            // SAFETY: made above, with its INTEGERs.
            unsafe { OPENSSL_sk_pop_free(tlsf, Some(free_int)) };
            ptr::null_mut()
        };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(nval.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let Some(val) = (unsafe { item_at::<CONF_VALUE>(nval.cast(), i) }) else { continue };
            let extval = if val.value.is_null() { val.name } else { val.value };
            // SAFETY: a C string, or NULL.
            let t = unsafe { text(extval) }.unwrap_or_default();
            let named = TLS_FEATURES.iter().find(|f| f.1.to_bytes().eq_ignore_ascii_case(t)).map(|f| f.0);
            let id = match named.or_else(|| decimal(t).filter(|v| (0..=65535).contains(v))) {
                Some(v) => v,
                None => {
                    err::raise(ERR_LIB_X509V3, X509V3_R_INVALID_SYNTAX, F);
                    // SAFETY: the value.
                    unsafe { add_error_name_value(val) };
                    return fail();
                }
            };
            // SAFETY: no preconditions.
            let ai = unsafe { ASN1_INTEGER_new() };
            // SAFETY: new, or NULL; the stack, which takes it.
            if ai.is_null() || unsafe { ASN1_INTEGER_set(ai, id) } == 0 || unsafe { OPENSSL_sk_push(tlsf, ai.cast()) } <= 0 {
                err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
                // SAFETY: made above, or NULL.
                unsafe { ASN1_INTEGER_free(ai) };
                return fail();
            }
        }
        tlsf.cast()
    }
}

pub(crate) static TLS_FEATURE_METHOD: Method = Method({
    let mut m = method(NID_tlsfeature, 0);
    m.it = Some(tls_feature_it);
    m.i2v = Some(tlsf_i2v);
    m.v2i = Some(tlsf_v2i);
    m
});

// The issuer's signing tools (`v3_ist.c`).

static IST_TT: Templates<4> = Templates([
    template_at(
        0,
        0,
        offset_of!(ISSUER_SIGN_TOOL, signTool),
        c"signTool",
        ASN1_UTF8STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(ISSUER_SIGN_TOOL, cATool),
        c"cATool",
        ASN1_UTF8STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(ISSUER_SIGN_TOOL, signToolCert),
        c"signToolCert",
        ASN1_UTF8STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(ISSUER_SIGN_TOOL, cAToolCert),
        c"cAToolCert",
        ASN1_UTF8STRING_it,
    ),
]);

item_fns! {
    /// IssuerSignTool: SEQUENCE of four UTF8Strings.
    pub unsafe extern "C" fn ISSUER_SIGN_TOOL_it = sequence::<ISSUER_SIGN_TOOL, 4>(&IST_TT, None, c"ISSUER_SIGN_TOOL");
}

new_free! {
    pub unsafe extern "C" fn ISSUER_SIGN_TOOL_new, pub unsafe extern "C" fn ISSUER_SIGN_TOOL_free(ISSUER_SIGN_TOOL) = ISSUER_SIGN_TOOL_it;
}

i2d! {
    /// Encodes an IssuerSignTool.
    pub unsafe extern "C" fn i2d_ISSUER_SIGN_TOOL(ISSUER_SIGN_TOOL) = ISSUER_SIGN_TOOL_it;
}

d2i! {
    /// Decodes an IssuerSignTool (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_ISSUER_SIGN_TOOL(ISSUER_SIGN_TOOL) = ISSUER_SIGN_TOOL_it;
}

ffi_callback! {
    /// `v2i_issuer_sign_tool`: `signTool`, `cATool`, `signToolCert`, and `cAToolCert`.
    ///
    /// # Safety
    /// `nval` is NULL or a live stack of `CONF_VALUE`s.
    pub(crate) unsafe extern "C" fn ist_v2i(_method: *const X509V3_EXT_METHOD, _ctx: *mut X509V3_CTX, nval: *mut stack_st_CONF_VALUE) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        const F: &str = "v2i_issuer_sign_tool";
        // SAFETY: no preconditions.
        let ist = unsafe { ISSUER_SIGN_TOOL_new() };
        // SAFETY: new, or NULL.
        let Some(t) = (unsafe { ist.as_mut() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        let fail = |reason| {
            err::raise(ERR_LIB_X509V3, reason, F);
            // SAFETY: made above.
            unsafe { ISSUER_SIGN_TOOL_free(ist) };
            ptr::null_mut()
        };
        // SAFETY: the caller's stack, or NULL.
        let n = unsafe { OPENSSL_sk_num(nval.cast()) };
        for i in 0..n {
            // SAFETY: an index within the stack.
            let Some(cnf) = (unsafe { item_at::<CONF_VALUE>(nval.cast(), i) }) else { continue };
            // SAFETY: its name.
            let field = match unsafe { text(cnf.name) } {
                Some(b"signTool") => t.signTool,
                Some(b"cATool") => t.cATool,
                Some(b"signToolCert") => t.signToolCert,
                Some(b"cAToolCert") => t.cAToolCert,
                _ => return fail(ERR_R_PASSED_INVALID_ARGUMENT),
            };
            // SAFETY: its value.
            let Some(v) = (unsafe { text(cnf.value) }) else { return fail(ERR_R_ASN1_LIB) };
            let len = c_int::try_from(v.len()).unwrap_or(c_int::MAX);
            // SAFETY: the field, made with the structure; the value's octets.
            if field.is_null() || unsafe { ASN1_STRING_set(field, v.as_ptr().cast(), len) } == 0 {
                return fail(ERR_R_ASN1_LIB);
            }
        }
        ist.cast()
    }
}

ffi_callback! {
    /// `i2r_issuer_sign_tool`: each tool present, on lines of its own.
    ///
    /// # Safety
    /// `ext` is NULL or a live IssuerSignTool; `out` is a live BIO.
    pub(crate) unsafe extern "C" fn ist_i2r(_method: *const X509V3_EXT_METHOD, ext: *mut c_void, out: *mut BIO, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        let Some(t) = (unsafe { ext.cast::<ISSUER_SIGN_TOOL>().as_ref() }) else {
            err::raise(ERR_LIB_X509V3, ERR_R_PASSED_INVALID_ARGUMENT, "i2r_issuer_sign_tool");
            return 0;
        };
        let mut new_line = false;
        for (label, s) in [
            (c"signTool    : ", t.signTool),
            (c"cATool      : ", t.cATool),
            (c"signToolCert: ", t.signToolCert),
            (c"cAToolCert  : ", t.cAToolCert),
        ] {
            // SAFETY: the tool's string, or NULL.
            let Some(st) = (unsafe { s.as_ref() }) else { continue };
            if new_line {
                // SAFETY: the caller's BIO.
                unsafe { BIO_write(out, c"\n".as_ptr().cast(), 1) };
            }
            // SAFETY: as above; a static format and its arguments.
            unsafe { BIO_printf(out, c"%*s%s".as_ptr(), indent, c"".as_ptr(), label.as_ptr()) };
            // SAFETY: as above; the string's octets.
            unsafe { BIO_write(out, st.data.cast(), st.length) };
            new_line = true;
        }
        1
    }
}

pub(crate) static ISSUER_SIGN_TOOL_METHOD: Method = Method({
    let mut m = method(NID_issuerSignTool, X509V3_EXT_MULTILINE);
    m.it = Some(ISSUER_SIGN_TOOL_it);
    m.v2i = Some(ist_v2i);
    m.i2r = Some(ist_i2r);
    m
});

// The audit identity (`v3_audit_id.c`).

ffi_callback! {
    /// `s2i_ASN1_OCTET_STRING` as a method's `s2i`.
    ///
    /// # Safety
    /// `str` is NULL or a C string.
    pub(crate) unsafe extern "C" fn octet_s2i(method: *const X509V3_EXT_METHOD, ctx: *mut X509V3_CTX, str: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_X509V3
    {
        // SAFETY: the caller's guarantee.
        unsafe { s2i_ASN1_OCTET_STRING(method.cast_mut(), ctx, str) }.cast()
    }
}

pub(crate) static AUDIT_IDENTITY: Method = Method({
    let mut m = method(NID_ac_auditIdentity, 0);
    m.it = Some(ASN1_OCTET_STRING_it);
    m.i2s = Some(octet_i2s);
    m.s2i = Some(octet_s2i);
    m
});
