//! A group as `OSSL_PARAM`s (`EC_GROUP_to_params`, `EC_GROUP_new_from_params`;
//! `ec_backend.c`'s `ossl_ec_group_todata` and `ec_lib.c`): its point format, encoding, and
//! curve name, or its explicit parameters, each way. The key manager reuses the conversion to
//! fill a caller's array (4.4d).

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_CTX, EC_GROUP, EC_POINT, EC_R_FIELD_TOO_LARGE, EC_R_INVALID_A, EC_R_INVALID_B,
    EC_R_INVALID_COFACTOR, EC_R_INVALID_CURVE, EC_R_INVALID_ENCODING, EC_R_INVALID_FIELD,
    EC_R_INVALID_FORM, EC_R_INVALID_GENERATOR, EC_R_INVALID_GROUP_ORDER,
    EC_R_INVALID_NAMED_GROUP_CONVERSION, EC_R_INVALID_P, EC_R_INVALID_SEED,
    EC_R_PASSED_NULL_PARAMETER, EC_R_UNSUPPORTED_FIELD, EC_R_WRONG_CURVE_PARAMETERS, ERR_LIB_EC,
    ERR_R_BN_LIB, ERR_R_CRYPTO_LIB, ERR_R_EC_LIB, NID_X9_62_characteristic_two_field,
    NID_X9_62_prime_field, NID_secp224r1, NID_undef, NID_wap_wsg_idm_ecid_wtls12,
    OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE, OPENSSL_ECC_MAX_FIELD_BITS, OSSL_LIB_CTX,
    OSSL_PARAM, OSSL_PARAM_BLD, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_PTR,
    OSSL_PARAM_UTF8_STRING, OSSL_PKEY_EC_ENCODING_EXPLICIT, OSSL_PKEY_EC_ENCODING_GROUP,
    OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED, OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID,
    OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED, OSSL_PKEY_PARAM_EC_A, OSSL_PKEY_PARAM_EC_B,
    OSSL_PKEY_PARAM_EC_COFACTOR, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
    OSSL_PKEY_PARAM_EC_ENCODING, OSSL_PKEY_PARAM_EC_FIELD_TYPE, OSSL_PKEY_PARAM_EC_GENERATOR,
    OSSL_PKEY_PARAM_EC_ORDER, OSSL_PKEY_PARAM_EC_P, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
    OSSL_PKEY_PARAM_EC_SEED, OSSL_PKEY_PARAM_GROUP_NAME, POINT_CONVERSION_COMPRESSED,
    POINT_CONVERSION_HYBRID, POINT_CONVERSION_UNCOMPRESSED, SN_X9_62_characteristic_two_field,
    SN_X9_62_prime_field, point_conversion_form_t,
};
use rustyssl_crypto::ec::curves::{self, Method};

use super::asn1::Encoded;
use super::curves::OSSL_EC_curve_nid2name;
use super::group::{
    EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get_asn1_flag, EC_GROUP_get_curve,
    EC_GROUP_get_curve_name, EC_GROUP_get_degree, EC_GROUP_get_field_type,
    EC_GROUP_get_point_conversion_form, EC_GROUP_get_seed_len, EC_GROUP_get0_cofactor,
    EC_GROUP_get0_generator, EC_GROUP_get0_order, EC_GROUP_get0_seed,
    EC_GROUP_new_by_curve_name_ex, EC_GROUP_new_curve_GF2m, EC_GROUP_new_curve_GFp,
    EC_GROUP_set_asn1_flag, EC_GROUP_set_generator, EC_GROUP_set_point_conversion_form,
    EC_GROUP_set_seed, curve_nid_from_params, decoded_from_explicit, set_decoded_from_explicit,
};
use super::point::{EC_POINT_free, EC_POINT_new, EC_POINT_oct2point};
use crate::bn::{BN_free, BN_is_negative, BN_is_zero, BN_new, BN_num_bits};
use crate::err;
use crate::ffi::ffi_export;
use crate::params::bn::{OSSL_PARAM_get_BN, OSSL_PARAM_set_BN};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN, OSSL_PARAM_BLD_push_int,
    OSSL_PARAM_BLD_push_octet_string, OSSL_PARAM_BLD_push_utf8_string, OSSL_PARAM_BLD_to_param,
};
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_utf8_ptr, OSSL_PARAM_locate, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_int, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string,
};

/// The parameter types, as `data_type` holds them.
const UTF8_STRING: u32 = OSSL_PARAM_UTF8_STRING.cast_unsigned();
const UTF8_PTR: u32 = OSSL_PARAM_UTF8_PTR.cast_unsigned();
const OCTET_STRING: u32 = OSSL_PARAM_OCTET_STRING.cast_unsigned();

/// Raises an EC error from `func`.
fn raise(reason: c_int, func: &'static str) {
    err::raise(ERR_LIB_EC, reason, func);
}

/// The encodings' names (`encoding_nameid_map`).
const ENCODINGS: [(c_int, &CStr); 2] = [
    (OPENSSL_EC_EXPLICIT_CURVE, OSSL_PKEY_EC_ENCODING_EXPLICIT),
    (OPENSSL_EC_NAMED_CURVE, OSSL_PKEY_EC_ENCODING_GROUP),
];

/// The point formats' names (`format_nameid_map`).
const FORMATS: [(point_conversion_form_t, &CStr); 3] = [
    (
        POINT_CONVERSION_UNCOMPRESSED,
        OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED,
    ),
    (
        POINT_CONVERSION_COMPRESSED,
        OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_COMPRESSED,
    ),
    (
        POINT_CONVERSION_HYBRID,
        OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_HYBRID,
    ),
];

/// A string parameter's text as OpenSSL's EC code reads it: a UTF-8 string's data up to its
/// NUL (within its size here, where OpenSSL reads on), or what a UTF-8 pointer points to.
/// `Some(None)` is a pointer parameter holding NULL; `None` is no string at all.
///
/// # Safety
/// `p` is a live parameter.
pub(crate) unsafe fn text<'a>(p: *const OSSL_PARAM) -> Option<Option<&'a [u8]>> {
    // SAFETY: the caller's guarantee.
    let prm = unsafe { &*p };
    match prm.data_type {
        UTF8_STRING => {
            if prm.data.is_null() {
                return None;
            }
            // SAFETY: the parameter's data of its size.
            let all = unsafe { core::slice::from_raw_parts(prm.data.cast::<u8>(), prm.data_size) };
            let end = all.iter().position(|&b| b == 0).unwrap_or(all.len());
            Some(all.get(..end))
        }
        UTF8_PTR => {
            let mut s: *const c_char = ptr::null();
            // SAFETY: the parameter; a local.
            if unsafe { OSSL_PARAM_get_utf8_ptr(p, &raw mut s) } == 0 {
                return None;
            }
            // SAFETY: NULL or the string it points to.
            Some((!s.is_null()).then(|| unsafe { CStr::from_ptr(s) }.to_bytes()))
        }
        _ => None,
    }
}

/// `ossl_ec_encoding_param2id`: the ASN.1 flag a parameter names (the named-curve flag for no
/// name), or `None`.
///
/// # Safety
/// `p` is a live parameter.
pub(crate) unsafe fn encoding_param2id(p: *const OSSL_PARAM) -> Option<c_int> {
    // SAFETY: the caller's guarantee.
    match unsafe { text(p) }? {
        None => Some(OPENSSL_EC_NAMED_CURVE),
        Some(name) => ENCODINGS
            .iter()
            .find(|(_, n)| n.to_bytes().eq_ignore_ascii_case(name))
            .map(|(id, _)| *id),
    }
}

/// `ossl_ec_pt_format_param2id`: the conversion form a parameter names (uncompressed for no
/// name), or `None`.
///
/// # Safety
/// `p` is a live parameter.
pub(crate) unsafe fn pt_format_param2id(p: *const OSSL_PARAM) -> Option<point_conversion_form_t> {
    // SAFETY: the caller's guarantee.
    match unsafe { text(p) }? {
        None => Some(POINT_CONVERSION_UNCOMPRESSED),
        Some(name) => FORMATS
            .iter()
            .find(|(_, n)| n.to_bytes().eq_ignore_ascii_case(name))
            .map(|(id, _)| *id),
    }
}

/// Where a group's parameters go: a builder, or an array to fill.
#[derive(Clone, Copy)]
pub(crate) enum Target {
    Builder(*mut OSSL_PARAM_BLD),
    #[expect(dead_code, reason = "the key manager's get_params fills arrays (4.4d)")]
    Params(*mut OSSL_PARAM),
}

impl Target {
    fn is_builder(self) -> bool {
        matches!(self, Self::Builder(_))
    }

    /// Whether the array asks for `key` (a builder takes everything).
    ///
    /// # Safety
    /// The target is live.
    unsafe fn wants(self, key: &CStr) -> bool {
        match self {
            Self::Builder(_) => true,
            // SAFETY: the caller's guarantee.
            Self::Params(p) => !unsafe { OSSL_PARAM_locate_const(p, key.as_ptr()) }.is_null(),
        }
    }

    /// The array's parameter `key`, or NULL.
    ///
    /// # Safety
    /// `p` is a live array.
    unsafe fn locate(p: *mut OSSL_PARAM, key: &CStr) -> *mut OSSL_PARAM {
        // SAFETY: the caller's guarantee.
        unsafe { OSSL_PARAM_locate(p, key.as_ptr()) }
    }

    /// `ossl_param_build_set_int`.
    ///
    /// # Safety
    /// The target is live.
    unsafe fn int(self, key: &CStr, v: c_int) -> bool {
        match self {
            // SAFETY: the caller's guarantee; a static key.
            Self::Builder(b) => (unsafe { OSSL_PARAM_BLD_push_int(b, key.as_ptr(), v) }) != 0,
            Self::Params(p) => {
                // SAFETY: as above.
                let q = unsafe { Self::locate(p, key) };
                // SAFETY: a parameter of the array.
                q.is_null() || unsafe { OSSL_PARAM_set_int(q, v) } != 0
            }
        }
    }

    /// `ossl_param_build_set_utf8_string`.
    ///
    /// # Safety
    /// The target is live.
    unsafe fn utf8(self, key: &CStr, v: &'static CStr) -> bool {
        match self {
            Self::Builder(b) => {
                // SAFETY: the caller's guarantee; static strings.
                (unsafe { OSSL_PARAM_BLD_push_utf8_string(b, key.as_ptr(), v.as_ptr(), 0) }) != 0
            }
            Self::Params(p) => {
                // SAFETY: as above.
                let q = unsafe { Self::locate(p, key) };
                // SAFETY: a parameter of the array.
                q.is_null() || unsafe { OSSL_PARAM_set_utf8_string(q, v.as_ptr()) } != 0
            }
        }
    }

    /// `ossl_param_build_set_octet_string`; a builder reads `v` when it makes its array.
    ///
    /// # Safety
    /// The target is live; `v` lives until a builder makes its array.
    unsafe fn octets(self, key: &CStr, v: &[u8]) -> bool {
        let (d, n) = (v.as_ptr().cast::<c_void>(), v.len());
        match self {
            Self::Builder(b) => {
                // SAFETY: the caller's guarantee.
                (unsafe { OSSL_PARAM_BLD_push_octet_string(b, key.as_ptr(), d, n) }) != 0
            }
            Self::Params(p) => {
                // SAFETY: as above.
                let q = unsafe { Self::locate(p, key) };
                // SAFETY: a parameter of the array.
                q.is_null() || unsafe { OSSL_PARAM_set_octet_string(q, d, n) } != 0
            }
        }
    }

    /// `ossl_param_build_set_bn`; a builder reads `v` when it makes its array.
    ///
    /// # Safety
    /// The target is live; `v` is a live number that lives until a builder makes its array.
    unsafe fn bn(self, key: &CStr, v: *const BIGNUM) -> bool {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Builder(b) => (unsafe { OSSL_PARAM_BLD_push_BN(b, key.as_ptr(), v) }) != 0,
            Self::Params(p) => {
                // SAFETY: as above.
                let q = unsafe { Self::locate(p, key) };
                // SAFETY: a parameter of the array.
                q.is_null() || unsafe { OSSL_PARAM_set_BN(q, v) } != 0
            }
        }
    }
}

/// What a builder reads when it makes its array: numbers and the generator's encoding.
#[derive(Default)]
pub(crate) struct Kept {
    numbers: Vec<*mut BIGNUM>,
    generator: Option<Encoded>,
}

impl Kept {
    /// A new number kept until the array is made, or NULL.
    fn number(&mut self) -> *mut BIGNUM {
        // SAFETY: no preconditions.
        let b = unsafe { BN_new() };
        if !b.is_null() {
            self.numbers.push(b);
        }
        b
    }
}

impl Drop for Kept {
    fn drop(&mut self) {
        for &b in &self.numbers {
            // SAFETY: numbers made by `number`, each freed once.
            unsafe { BN_free(b) };
        }
    }
}

/// `ec_group_explicit_todata`.
///
/// # Safety
/// `group` is a live group; the target is live.
unsafe fn explicit_todata(group: *const EC_GROUP, target: Target, kept: &mut Kept) -> bool {
    const F: &str = "ec_group_explicit_todata";
    // SAFETY: the caller's guarantee, here and below.
    let fid = unsafe { EC_GROUP_get_field_type(group) };
    let field_type = if fid == NID_X9_62_prime_field {
        SN_X9_62_prime_field
    } else if fid == NID_X9_62_characteristic_two_field {
        SN_X9_62_characteristic_two_field
    } else {
        raise(EC_R_INVALID_FIELD, F);
        return false;
    };
    // SAFETY: as above.
    let wants = |key: &CStr| unsafe { target.wants(key) };
    if wants(OSSL_PKEY_PARAM_EC_P) || wants(OSSL_PKEY_PARAM_EC_A) || wants(OSSL_PKEY_PARAM_EC_B) {
        let (p, a, b) = (kept.number(), kept.number(), kept.number());
        if p.is_null() || a.is_null() || b.is_null() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        // SAFETY: as above; live numbers.
        if unsafe { EC_GROUP_get_curve(group, p, a, b, ptr::null_mut()) } == 0 {
            raise(EC_R_INVALID_CURVE, F);
            return false;
        }
        // SAFETY: as above; numbers kept until the array is made.
        let set = unsafe { target.bn(OSSL_PKEY_PARAM_EC_P, p) }
            // SAFETY: as above.
            && unsafe { target.bn(OSSL_PKEY_PARAM_EC_A, a) }
            // SAFETY: as above.
            && unsafe { target.bn(OSSL_PKEY_PARAM_EC_B, b) };
        if !set {
            raise(ERR_R_CRYPTO_LIB, F);
            return false;
        }
    }
    if wants(OSSL_PKEY_PARAM_EC_ORDER) {
        // SAFETY: as above.
        let order = unsafe { EC_GROUP_get0_order(group) };
        if order.is_null() {
            raise(EC_R_INVALID_GROUP_ORDER, F);
            return false;
        }
        // SAFETY: as above; the group's own number.
        if !unsafe { target.bn(OSSL_PKEY_PARAM_EC_ORDER, order) } {
            raise(ERR_R_CRYPTO_LIB, F);
            return false;
        }
    }
    if wants(OSSL_PKEY_PARAM_EC_FIELD_TYPE)
        // SAFETY: as above.
        && !unsafe { target.utf8(OSSL_PKEY_PARAM_EC_FIELD_TYPE, field_type) }
    {
        raise(ERR_R_CRYPTO_LIB, F);
        return false;
    }
    if wants(OSSL_PKEY_PARAM_EC_GENERATOR) {
        // SAFETY: as above.
        let genpt = unsafe { EC_GROUP_get0_generator(group) };
        // SAFETY: as above.
        let form = unsafe { EC_GROUP_get_point_conversion_form(group) };
        if genpt.is_null() {
            raise(EC_R_INVALID_GENERATOR, F);
            return false;
        }
        // SAFETY: the group and its generator.
        let Some(encoded) = (unsafe { Encoded::of(group, genpt, form) }) else {
            raise(EC_R_INVALID_GENERATOR, F);
            return false;
        };
        let generator = kept.generator.insert(encoded);
        // SAFETY: as above; the encoding kept until the array is made.
        if !unsafe { target.octets(OSSL_PKEY_PARAM_EC_GENERATOR, generator.bytes()) } {
            raise(ERR_R_CRYPTO_LIB, F);
            return false;
        }
    }
    if wants(OSSL_PKEY_PARAM_EC_COFACTOR) {
        // SAFETY: as above.
        let cofactor = unsafe { EC_GROUP_get0_cofactor(group) };
        // SAFETY: as above; the group's own number.
        if !cofactor.is_null() && !unsafe { target.bn(OSSL_PKEY_PARAM_EC_COFACTOR, cofactor) } {
            raise(ERR_R_CRYPTO_LIB, F);
            return false;
        }
    }
    if wants(OSSL_PKEY_PARAM_EC_SEED) {
        // SAFETY: as above.
        let seed = unsafe { EC_GROUP_get0_seed(group) };
        // SAFETY: as above.
        let len = unsafe { EC_GROUP_get_seed_len(group) };
        if !seed.is_null() && len > 0 {
            // SAFETY: the group's seed of its length, which outlives the array.
            let s = unsafe { core::slice::from_raw_parts(seed, len) };
            // SAFETY: as above.
            if !unsafe { target.octets(OSSL_PKEY_PARAM_EC_SEED, s) } {
                raise(ERR_R_CRYPTO_LIB, F);
                return false;
            }
        }
    }
    true
}

/// `ossl_ec_group_todata`: the group's format, encoding, and curve name, and its explicit
/// parameters when it has no name or the target is an array.
///
/// # Safety
/// `group` is NULL or a live group; the target is live; `kept` lives until a builder makes
/// its array.
pub(crate) unsafe fn group_todata(group: *const EC_GROUP, target: Target, kept: &mut Kept) -> bool {
    const F: &str = "ossl_ec_group_todata";
    if group.is_null() {
        raise(EC_R_PASSED_NULL_PARAMETER, F);
        return false;
    }
    // SAFETY: the caller's guarantee, here and below.
    let form = unsafe { EC_GROUP_get_point_conversion_form(group) };
    let format = FORMATS.iter().find(|(f, _)| *f == form).map(|(_, n)| *n);
    // SAFETY: as above.
    let set = format
        .is_some_and(|n| unsafe { target.utf8(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, n) });
    if !set {
        raise(EC_R_INVALID_FORM, F);
        return false;
    }
    // SAFETY: as above.
    let flag = unsafe { EC_GROUP_get_asn1_flag(group) } & OPENSSL_EC_NAMED_CURVE;
    let encoding = ENCODINGS.iter().find(|(f, _)| *f == flag).map(|(_, n)| *n);
    // SAFETY: as above.
    let set = encoding.is_some_and(|n| unsafe { target.utf8(OSSL_PKEY_PARAM_EC_ENCODING, n) });
    if !set {
        raise(EC_R_INVALID_ENCODING, F);
        return false;
    }
    // SAFETY: as above.
    let decoded = c_int::from(unsafe { decoded_from_explicit(group) });
    // SAFETY: as above.
    if !unsafe { target.int(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, decoded) } {
        return false;
    }
    // SAFETY: as above.
    let nid = unsafe { EC_GROUP_get_curve_name(group) };
    if (!target.is_builder() || nid == NID_undef)
        // SAFETY: as above.
        && !unsafe { explicit_todata(group, target, kept) }
    {
        return false;
    }
    if nid != NID_undef {
        // SAFETY: no preconditions.
        let name = unsafe { OSSL_EC_curve_nid2name(nid) };
        let set = !name.is_null() && {
            // SAFETY: a static name of the table.
            let n = unsafe { CStr::from_ptr(name) };
            // SAFETY: as above.
            unsafe { target.utf8(OSSL_PKEY_PARAM_GROUP_NAME, n) }
        };
        if !set {
            raise(EC_R_INVALID_CURVE, F);
            return false;
        }
    }
    true
}

ffi_export! {
    /// The group as parameters (its explicit parameters when it has no curve name), or NULL.
    ///
    /// # Safety
    /// `group` is NULL or a live group; `bnctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn EC_GROUP_to_params(group: *const EC_GROUP, libctx: *mut OSSL_LIB_CTX, propq: *const c_char, bnctx: *mut BN_CTX) -> *mut OSSL_PARAM
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        let _ = (libctx, propq, bnctx);
        if group.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let bld = unsafe { OSSL_PARAM_BLD_new() };
        if bld.is_null() {
            return ptr::null_mut();
        }
        let mut kept = Kept::default();
        // SAFETY: the caller's group; the builder; `kept` outlives the array's making.
        let params = if unsafe { group_todata(group, Target::Builder(bld), &mut kept) } {
            // SAFETY: the builder.
            unsafe { OSSL_PARAM_BLD_to_param(bld) }
        } else {
            ptr::null_mut()
        };
        // SAFETY: the builder made above.
        unsafe { OSSL_PARAM_BLD_free(bld) };
        params
    }
}

/// `group_new_from_name`: the named group a parameter names, or NULL (with
/// `EC_R_INVALID_CURVE` for an unknown name).
///
/// # Safety
/// `p` is a live parameter.
unsafe fn group_new_from_name(
    p: *const OSSL_PARAM,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EC_GROUP {
    // SAFETY: the caller's guarantee.
    let Some(Some(name)) = (unsafe { text(p) }) else {
        return ptr::null_mut();
    };
    let Some(nid) = curves::nid_by_name(name) else {
        raise(EC_R_INVALID_CURVE, "group_new_from_name");
        return ptr::null_mut();
    };
    // SAFETY: the caller's library context and query.
    unsafe { EC_GROUP_new_by_curve_name_ex(libctx, propq, nid) }
}

/// `ossl_ec_group_set_params`: the format, encoding, and seed parameters into the group.
///
/// # Safety
/// `group` is a live group; `params` is a live array.
pub(crate) unsafe fn group_set_params(group: *mut EC_GROUP, params: *const OSSL_PARAM) -> bool {
    const F: &str = "ossl_ec_group_set_params";
    // SAFETY: the caller's guarantee, here and below.
    let locate = |key: &CStr| unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    let p = locate(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT);
    if !p.is_null() {
        // SAFETY: a parameter of the array.
        let Some(form) = (unsafe { pt_format_param2id(p) }) else {
            raise(EC_R_INVALID_FORM, F);
            return false;
        };
        // SAFETY: as above.
        unsafe { EC_GROUP_set_point_conversion_form(group, form) };
    }
    let p = locate(OSSL_PKEY_PARAM_EC_ENCODING);
    if !p.is_null() {
        // SAFETY: a parameter of the array.
        let Some(flag) = (unsafe { encoding_param2id(p) }) else {
            raise(EC_R_INVALID_FORM, F);
            return false;
        };
        // SAFETY: as above.
        unsafe { EC_GROUP_set_asn1_flag(group, flag) };
    }
    let p = locate(OSSL_PKEY_PARAM_EC_SEED);
    if !p.is_null() {
        // SAFETY: a parameter of the array.
        let prm = unsafe { &*p };
        let set = prm.data_type == OCTET_STRING
            // SAFETY: the group; the parameter's data of its size (the seed may be NULL).
            && unsafe { EC_GROUP_set_seed(group, prm.data.cast(), prm.data_size) } != 0;
        if !set {
            raise(EC_R_INVALID_SEED, F);
            return false;
        }
    }
    true
}

/// `ec_group_explicit_to_named`: the named group with `group`'s parameters (with the explicit
/// flag, and no seed if `group` has none), `group` itself if there's none, or NULL.
///
/// # Safety
/// `group` is a live group with a generator.
unsafe fn explicit_to_named(
    group: *mut EC_GROUP,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut EC_GROUP {
    // SAFETY: the caller's guarantee, here and below.
    let point = unsafe { EC_GROUP_get0_generator(group) };
    // SAFETY: as above.
    let order = unsafe { EC_GROUP_get0_order(group) };
    // SAFETY: as above.
    let no_seed = unsafe { EC_GROUP_get0_seed(group) }.is_null();
    // SAFETY: as above.
    let dup = unsafe { EC_GROUP_dup(group) };
    let mut ret = ptr::null_mut();
    let ok = (|| {
        let copied = !dup.is_null()
            // SAFETY: the copy.
            && unsafe { EC_GROUP_set_seed(dup, ptr::null(), 0) } == 1
            // SAFETY: the copy; the group's generator and order.
            && unsafe { EC_GROUP_set_generator(dup, point, order, ptr::null()) } != 0;
        if !copied {
            return false;
        }
        // SAFETY: the copy.
        let mut nid = unsafe { curve_nid_from_params(dup, ptr::null()) };
        if nid == NID_undef {
            ret = group;
            return true;
        }
        // wtls12 and secp224r1 are one curve; the latter has the specialized method.
        if nid == NID_wap_wsg_idm_ecid_wtls12
            && curves::by_nid(NID_secp224r1).is_some_and(|c| c.method == Method::Nistp224)
        {
            nid = NID_secp224r1;
        }
        // SAFETY: the caller's library context and query.
        ret = unsafe { EC_GROUP_new_by_curve_name_ex(libctx, propq, nid) };
        if ret.is_null() {
            return false;
        }
        // SAFETY: the group made above.
        unsafe { EC_GROUP_set_asn1_flag(ret, OPENSSL_EC_EXPLICIT_CURVE) };
        // SAFETY: as above.
        !no_seed || unsafe { EC_GROUP_set_seed(ret, ptr::null(), 0) } == 1
    })();
    // SAFETY: NULL or the copy.
    unsafe { EC_GROUP_free(dup) };
    if ok {
        return ret;
    }
    if ret != group {
        // SAFETY: NULL or the named group made above.
        unsafe { EC_GROUP_free(ret) };
    }
    ptr::null_mut()
}

/// `OSSL_PARAM_get_BN` into `*b`, as a success.
///
/// # Safety
/// `p` is NULL or a live parameter; `b` holds a live number.
unsafe fn get_bn(p: *const OSSL_PARAM, b: &mut *mut BIGNUM) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { OSSL_PARAM_get_BN(p, b) }) != 0
}

/// `EC_GROUP_new_from_params`' explicit case; `Err` with the group made so far, to free.
///
/// # Safety
/// `params` is a live array.
unsafe fn from_explicit(
    params: *const OSSL_PARAM,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    nums: &mut Kept,
) -> Result<*mut EC_GROUP, *mut EC_GROUP> {
    const F: &str = "EC_GROUP_new_from_params";
    // SAFETY: the caller's guarantee, here and below.
    let locate = |key: &CStr| unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    let (mut p, mut a, mut b, mut order) =
        (nums.number(), nums.number(), nums.number(), nums.number());
    if order.is_null() {
        raise(ERR_R_BN_LIB, F);
        return Err(ptr::null_mut());
    }
    let ft = locate(OSSL_PKEY_PARAM_EC_FIELD_TYPE);
    // SAFETY: NULL or a parameter of the array.
    let ft_text = (!ft.is_null() && unsafe { (*ft).data_type } == UTF8_STRING)
        .then(|| unsafe { text(ft) })
        .flatten()
        .flatten();
    let Some(ft_text) = ft_text else {
        raise(EC_R_INVALID_FIELD, F);
        return Err(ptr::null_mut());
    };
    let is_prime = if ft_text.eq_ignore_ascii_case(SN_X9_62_prime_field.to_bytes()) {
        true
    } else if ft_text.eq_ignore_ascii_case(SN_X9_62_characteristic_two_field.to_bytes()) {
        false
    } else {
        raise(EC_R_UNSUPPORTED_FIELD, F);
        return Err(ptr::null_mut());
    };
    // SAFETY: NULL or a parameter; a live number.
    if !unsafe { get_bn(locate(OSSL_PKEY_PARAM_EC_A), &mut a) } {
        raise(EC_R_INVALID_A, F);
        return Err(ptr::null_mut());
    }
    // SAFETY: as above.
    if !unsafe { get_bn(locate(OSSL_PKEY_PARAM_EC_B), &mut b) } {
        raise(EC_R_INVALID_B, F);
        return Err(ptr::null_mut());
    }
    // SAFETY: as above.
    if !unsafe { get_bn(locate(OSSL_PKEY_PARAM_EC_P), &mut p) } {
        raise(EC_R_INVALID_P, F);
        return Err(ptr::null_mut());
    }
    let group;
    let field_bits;
    if is_prime {
        // SAFETY: a live number.
        if unsafe { BN_is_negative(p) } != 0 || unsafe { BN_is_zero(p) } != 0 {
            raise(EC_R_INVALID_P, F);
            return Err(ptr::null_mut());
        }
        // SAFETY: as above.
        field_bits = unsafe { BN_num_bits(p) };
        if field_bits > OPENSSL_ECC_MAX_FIELD_BITS {
            raise(EC_R_FIELD_TOO_LARGE, F);
            return Err(ptr::null_mut());
        }
        // SAFETY: live numbers.
        group = unsafe { EC_GROUP_new_curve_GFp(p, a, b, ptr::null_mut()) };
    } else {
        // SAFETY: as above.
        group = unsafe { EC_GROUP_new_curve_GF2m(p, a, b, ptr::null_mut()) };
        if group.is_null() {
            field_bits = 0;
        } else {
            // SAFETY: the group made above.
            field_bits = unsafe { EC_GROUP_get_degree(group) };
            if field_bits > OPENSSL_ECC_MAX_FIELD_BITS {
                raise(EC_R_FIELD_TOO_LARGE, F);
                return Err(group);
            }
        }
    }
    if group.is_null() {
        raise(ERR_R_EC_LIB, F);
        return Err(group);
    }
    let seed = locate(OSSL_PKEY_PARAM_EC_SEED);
    if !seed.is_null() {
        // SAFETY: a parameter of the array.
        let s = unsafe { &*seed };
        if s.data_type != OCTET_STRING {
            raise(EC_R_INVALID_SEED, F);
            return Err(group);
        }
        // SAFETY: the group; the parameter's data of its size.
        if unsafe { EC_GROUP_set_seed(group, s.data.cast(), s.data_size) } == 0 {
            return Err(group);
        }
    }
    let gp = locate(OSSL_PKEY_PARAM_EC_GENERATOR);
    // SAFETY: NULL or a parameter of the array.
    let gen_param = unsafe { gp.as_ref() }
        .filter(|g| g.data_type == OCTET_STRING && g.data_size != 0 && !g.data.is_null());
    let Some(gen_param) = gen_param else {
        raise(EC_R_INVALID_GENERATOR, F);
        return Err(group);
    };
    // SAFETY: the parameter's data of its size.
    let buf =
        unsafe { core::slice::from_raw_parts(gen_param.data.cast::<u8>(), gen_param.data_size) };
    // SAFETY: the group.
    let point: *mut EC_POINT = unsafe { EC_POINT_new(group) };
    let r = (|| {
        if point.is_null() {
            return false;
        }
        let first = buf.first().copied().unwrap_or(0);
        // SAFETY: the group.
        unsafe { EC_GROUP_set_point_conversion_form(group, (first & !1).into()) };
        // SAFETY: the group and its point; the encoding.
        if unsafe { EC_POINT_oct2point(group, point, buf.as_ptr(), buf.len(), ptr::null_mut()) }
            == 0
        {
            raise(EC_R_INVALID_GENERATOR, F);
            return false;
        }
        // SAFETY: NULL or a parameter; a live number.
        let order_ok = unsafe { get_bn(locate(OSSL_PKEY_PARAM_EC_ORDER), &mut order) }
            // SAFETY: a live number.
            && unsafe { BN_is_negative(order) } == 0
            // SAFETY: as above.
            && unsafe { BN_is_zero(order) } == 0
            // The Hasse bound.
            // SAFETY: as above.
            && unsafe { BN_num_bits(order) } <= field_bits.saturating_add(1);
        if !order_ok {
            raise(EC_R_INVALID_GROUP_ORDER, F);
            return false;
        }
        let cp = locate(OSSL_PKEY_PARAM_EC_COFACTOR);
        let mut cofactor: *mut BIGNUM = ptr::null_mut();
        if !cp.is_null() {
            cofactor = nums.number();
            // SAFETY: a parameter; a live number.
            if cofactor.is_null() || !unsafe { get_bn(cp, &mut cofactor) } {
                raise(EC_R_INVALID_COFACTOR, F);
                return false;
            }
        }
        // SAFETY: the group and its point; live numbers (or NULL).
        if unsafe { EC_GROUP_set_generator(group, point, order, cofactor) } == 0 {
            raise(EC_R_INVALID_GENERATOR, F);
            return false;
        }
        true
    })();
    // SAFETY: NULL or the point made above.
    unsafe { EC_POINT_free(point) };
    if !r {
        return Err(group);
    }
    // SAFETY: the group, with its generator.
    let named = unsafe { explicit_to_named(group, libctx, propq) };
    if named.is_null() {
        raise(EC_R_INVALID_NAMED_GROUP_CONVERSION, F);
        return Err(group);
    }
    let ret = if named == group {
        let ep = locate(OSSL_PKEY_PARAM_EC_ENCODING);
        let mut flag = -1;
        if !ep.is_null() {
            // SAFETY: a parameter of the array.
            match unsafe { encoding_param2id(ep) } {
                Some(f) => flag = f,
                None => {
                    raise(EC_R_INVALID_ENCODING, F);
                    return Err(group);
                }
            }
        }
        if flag == OPENSSL_EC_NAMED_CURVE {
            raise(EC_R_INVALID_ENCODING, F);
            return Err(group);
        }
        // SAFETY: the group.
        unsafe { EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE) };
        group
    } else {
        // SAFETY: the group made above, replaced by the named one.
        unsafe { EC_GROUP_free(group) };
        named
    };
    // SAFETY: the group.
    unsafe { set_decoded_from_explicit(ret, true) };
    Ok(ret)
}

ffi_export! {
    /// A group from parameters: a named group (with the format, encoding, and seed given), or
    /// explicit parameters (the named group when they're a built-in curve's). NULL on failure.
    ///
    /// # Safety
    /// `params` is NULL or a live array; `propq` is NULL or a string.
    pub unsafe extern "C" fn EC_GROUP_new_from_params(params: *const OSSL_PARAM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EC_GROUP
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        const F: &str = "EC_GROUP_new_from_params";
        // SAFETY: the caller's guarantee.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME.as_ptr()) };
        if !p.is_null() {
            // SAFETY: a parameter of the array; the caller's context and query.
            let group = unsafe { group_new_from_name(p, libctx, propq) };
            if group.is_null() {
                return ptr::null_mut();
            }
            // SAFETY: the group; the caller's array.
            if !unsafe { group_set_params(group, params) } {
                // SAFETY: the group made above.
                unsafe { EC_GROUP_free(group) };
                return ptr::null_mut();
            }
            // SAFETY: as above.
            let d = unsafe {
                OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS.as_ptr())
            };
            let mut decoded = 0;
            // SAFETY: a parameter of the array; a local.
            if !d.is_null() && unsafe { OSSL_PARAM_get_int(d, &raw mut decoded) } == 0 {
                raise(EC_R_WRONG_CURVE_PARAMETERS, F);
                // SAFETY: the group made above.
                unsafe { EC_GROUP_free(group) };
                return ptr::null_mut();
            }
            // SAFETY: the group.
            unsafe { set_decoded_from_explicit(group, decoded > 0) };
            return group;
        }
        let mut nums = Kept::default();
        // SAFETY: the caller's array, context, and query.
        match unsafe { from_explicit(params, libctx, propq, &mut nums) } {
            Ok(g) => g,
            Err(g) => {
                // SAFETY: NULL or the group made so far.
                unsafe { EC_GROUP_free(g) };
                ptr::null_mut()
            }
        }
    }
}
