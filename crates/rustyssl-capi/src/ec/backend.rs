//! An EC key's parts as `OSSL_PARAM`s, each way (`ec_backend.c`, with `ec_kmgmt.c`'s
//! `key_to_params` and `otherparams_to_params`): the group, the public and private keys, and
//! the other parameters (point format, check type, whether encodings carry the public key,
//! cofactor mode). The key manager and the EC ASN.1 method's export and import share them.

use core::ffi::{CStr, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_FLG_CONSTTIME, EC_FLAG_CHECK_NAMED_GROUP, EC_FLAG_CHECK_NAMED_GROUP_MASK,
    EC_FLAG_CHECK_NAMED_GROUP_NIST, EC_FLAG_COFACTOR_ECDH, EC_KEY, EC_PKEY_NO_PUBKEY, EC_POINT,
    EC_R_INVALID_FORM, ERR_LIB_EC, OSSL_PARAM, OSSL_PKEY_EC_GROUP_CHECK_DEFAULT,
    OSSL_PKEY_EC_GROUP_CHECK_NAMED, OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST,
    OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
    OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, OSSL_PKEY_PARAM_EC_PUB_X, OSSL_PKEY_PARAM_EC_PUB_Y,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
};

use super::group::{
    EC_GROUP_free, EC_GROUP_get0_cofactor, EC_GROUP_get0_order, EC_GROUP_order_bits,
};
use super::key::{
    EC_KEY_clear_flags, EC_KEY_get_conv_form, EC_KEY_get_enc_flags, EC_KEY_get_flags,
    EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_set_conv_form,
    EC_KEY_set_enc_flags, EC_KEY_set_flags, EC_KEY_set_group, EC_KEY_set_private_key,
    EC_KEY_set_public_key, key,
};
use super::params::{
    EC_GROUP_new_from_params, Kept, Target, format_name, pt_format_param2id, text,
};
use super::point::{
    EC_POINT_free, EC_POINT_get_affine_coordinates, EC_POINT_new, EC_POINT_oct2point,
    EC_POINT_point2buf,
};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::{BN_clear_free, BN_is_one, BN_is_zero, BN_secure_new, BN_set_flags};
use crate::err;
use crate::mem::CRYPTO_free;
use crate::params::bn::OSSL_PARAM_get_BN;
use crate::params::{OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_locate_const};

/// The check types' names (`check_group_type_nameid_map`).
const CHECK_TYPES: [(c_int, &CStr); 3] = [
    (0, OSSL_PKEY_EC_GROUP_CHECK_DEFAULT),
    (EC_FLAG_CHECK_NAMED_GROUP, OSSL_PKEY_EC_GROUP_CHECK_NAMED),
    (
        EC_FLAG_CHECK_NAMED_GROUP_NIST,
        OSSL_PKEY_EC_GROUP_CHECK_NAMED_NIST,
    ),
];

/// The parameter `name` of `params`, or NULL.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn locate(params: *const OSSL_PARAM, name: &CStr) -> *const OSSL_PARAM {
    // SAFETY: the caller's guarantee; a static name.
    unsafe { OSSL_PARAM_locate_const(params, name.as_ptr()) }
}

/// `ossl_ec_set_check_group_type_from_name`: the check type a name (any case; the default for
/// none) stands for into the key's flags. False for an unknown name.
///
/// # Safety
/// `ec` is a live key.
pub(crate) unsafe fn set_check_group_type_from_name(ec: *mut EC_KEY, name: Option<&[u8]>) -> bool {
    let flags = match name {
        None => 0,
        Some(n) => match CHECK_TYPES
            .iter()
            .find(|(_, s)| s.to_bytes().eq_ignore_ascii_case(n))
        {
            Some((id, _)) => *id,
            None => return false,
        },
    };
    // SAFETY: the caller's guarantee.
    unsafe { EC_KEY_clear_flags(ec, EC_FLAG_CHECK_NAMED_GROUP_MASK) };
    // SAFETY: as above.
    unsafe { EC_KEY_set_flags(ec, flags) };
    true
}

/// `ossl_ec_set_ecdh_cofactor_mode`: 1 sets cofactor ECDH, 0 clears it (neither matters for a
/// cofactor of 1). False for another mode or a key without a group.
///
/// # Safety
/// `ec` is a live key.
pub(crate) unsafe fn set_ecdh_cofactor_mode(ec: *mut EC_KEY, mode: c_int) -> bool {
    if !(0..=1).contains(&mode) {
        return false;
    }
    // SAFETY: the caller's guarantee.
    let group = unsafe { EC_KEY_get0_group(ec) };
    if group.is_null() {
        return false;
    }
    // SAFETY: the key's group.
    let cofactor = unsafe { EC_GROUP_get0_cofactor(group) };
    if cofactor.is_null() {
        return false;
    }
    // SAFETY: the group's cofactor.
    if unsafe { BN_is_one(cofactor) } != 0 {
        return true;
    }
    if mode == 1 {
        // SAFETY: the caller's guarantee.
        unsafe { EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH) };
    } else {
        // SAFETY: as above.
        unsafe { EC_KEY_clear_flags(ec, EC_FLAG_COFACTOR_ECDH) };
    }
    true
}

/// `ossl_ec_group_fromdata`: the group `params` describe, set on the key (which loses its group
/// when they describe none).
///
/// # Safety
/// `ec` is NULL or a live key; `params` is NULL or a parameter array.
pub(crate) unsafe fn group_fromdata(ec: *mut EC_KEY, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { key(ec) }) else {
        return false;
    };
    // SAFETY: the caller's array; the key's library context and query.
    let group = unsafe { EC_GROUP_new_from_params(params, k.get().libctx.0, k.propq()) };
    // SAFETY: the key; the group, or NULL.
    let ok = unsafe { EC_KEY_set_group(ec, group) } != 0;
    // SAFETY: the group made above, or NULL.
    unsafe { EC_GROUP_free(group) };
    ok
}

/// `ossl_ec_key_fromdata`: the public key (an encoded point of the key's group) and, with
/// `include_private`, the private key, as given.
///
/// # Safety
/// `ec` is a live key; `params` is NULL or a parameter array.
pub(crate) unsafe fn key_fromdata(
    ec: *mut EC_KEY,
    params: *const OSSL_PARAM,
    include_private: bool,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { key(ec) }) else {
        return false;
    };
    // SAFETY: as above.
    let group = unsafe { EC_KEY_get0_group(ec) };
    if group.is_null() {
        return false;
    }
    // SAFETY: the caller's array.
    let pub_param = unsafe { locate(params, OSSL_PKEY_PARAM_PUB_KEY) };
    let priv_param = if include_private {
        // SAFETY: as above.
        unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) }
    } else {
        ptr::null()
    };
    // SAFETY: the key's library context.
    let ctx = unsafe { BN_CTX_new_ex(k.get().libctx.0) };
    let mut buf: *mut c_void = ptr::null_mut();
    let mut point: *mut EC_POINT = ptr::null_mut();
    let mut priv_key: *mut BIGNUM = ptr::null_mut();
    let ok = (|| {
        if ctx.is_null() {
            return false;
        }
        if !pub_param.is_null() {
            let mut len = 0usize;
            // SAFETY: a parameter of the array; places for a new copy and its length.
            if unsafe { OSSL_PARAM_get_octet_string(pub_param, &raw mut buf, 0, &raw mut len) } == 0
            {
                return false;
            }
            // SAFETY: the key's group.
            point = unsafe { EC_POINT_new(group) };
            if point.is_null() {
                return false;
            }
            // SAFETY: the group; the point; the copy of `len` octets; the context.
            if unsafe { EC_POINT_oct2point(group, point, buf.cast::<c_uchar>(), len, ctx) } == 0 {
                return false;
            }
        }
        if !priv_param.is_null() {
            // SAFETY: the key's group.
            let order = unsafe { EC_GROUP_get0_order(group) };
            // SAFETY: the group's order.
            if order.is_null() || unsafe { BN_is_zero(order) } != 0 {
                return false;
            }
            // SAFETY: no preconditions.
            priv_key = unsafe { BN_secure_new() };
            if priv_key.is_null() {
                return false;
            }
            // SAFETY: the number just made.
            unsafe { BN_set_flags(priv_key, BN_FLG_CONSTTIME) };
            // SAFETY: a parameter of the array; the number.
            if unsafe { OSSL_PARAM_get_BN(priv_param, &raw mut priv_key) } == 0 {
                return false;
            }
        }
        // SAFETY: the key; the number, copied.
        if !priv_key.is_null() && unsafe { EC_KEY_set_private_key(ec, priv_key) } == 0 {
            return false;
        }
        // SAFETY: the key; the point, copied.
        !(!point.is_null() && unsafe { EC_KEY_set_public_key(ec, point) } == 0)
    })();
    // SAFETY: the context made above, or NULL.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: the number made above, or NULL.
    unsafe { BN_clear_free(priv_key) };
    // SAFETY: the copy made above, or NULL.
    unsafe { CRYPTO_free(buf, c"".as_ptr(), 0) };
    // SAFETY: the point made above, or NULL.
    unsafe { EC_POINT_free(point) };
    ok
}

/// `ossl_ec_key_otherparams_fromdata`: the cofactor mode, whether encodings carry the public
/// key, the point format, and the check type.
///
/// # Safety
/// `ec` is NULL or a live key; `params` is NULL or a parameter array.
pub(crate) unsafe fn otherparams_fromdata(ec: *mut EC_KEY, params: *const OSSL_PARAM) -> bool {
    if ec.is_null() {
        return false;
    }
    // SAFETY: the caller's array.
    let p = unsafe { locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH) };
    if !p.is_null() {
        let mut mode = 0;
        // SAFETY: a parameter of the array; a local.
        if unsafe { OSSL_PARAM_get_int(p, &raw mut mode) } == 0
            // SAFETY: the caller's key.
            || !unsafe { set_ecdh_cofactor_mode(ec, mode) }
        {
            return false;
        }
    }
    // SAFETY: as above.
    let p = unsafe { locate(params, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC) };
    if !p.is_null() {
        let mut include = 1;
        // SAFETY: a parameter of the array; a local.
        if unsafe { OSSL_PARAM_get_int(p, &raw mut include) } == 0 {
            return false;
        }
        // SAFETY: the caller's key.
        let flags = unsafe { EC_KEY_get_enc_flags(ec) };
        let flags = if include == 0 {
            flags | EC_PKEY_NO_PUBKEY.cast_unsigned()
        } else {
            flags & !EC_PKEY_NO_PUBKEY.cast_unsigned()
        };
        // SAFETY: as above.
        unsafe { EC_KEY_set_enc_flags(ec, flags) };
    }
    // SAFETY: as above.
    let p = unsafe { locate(params, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT) };
    if !p.is_null() {
        // SAFETY: a parameter of the array.
        let Some(form) = (unsafe { pt_format_param2id(p) }) else {
            err::raise(
                ERR_LIB_EC,
                EC_R_INVALID_FORM,
                "ec_key_point_format_fromdata",
            );
            return false;
        };
        // SAFETY: the caller's key.
        unsafe { EC_KEY_set_conv_form(ec, form) };
    }
    // SAFETY: as above.
    let p = unsafe { locate(params, OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE) };
    if !p.is_null() {
        // A string's data, or a pointer parameter's string (none for NULL); not other types.
        // SAFETY: a parameter of the array.
        let Some(name) = (unsafe { text(p) }) else {
            return false;
        };
        // SAFETY: the caller's key.
        return unsafe { set_check_group_type_from_name(ec, name) };
    }
    true
}

/// `key_to_params`: the public key (encoded in the key's point format; for an array, also as
/// coordinates when asked for) and, with `include_private`, the private key, padded to the
/// order's length so its own length doesn't show.
///
/// # Safety
/// `ec` is NULL or a live key; the target is live; `kept` lives until a builder makes its array.
pub(crate) unsafe fn key_todata(
    ec: *const EC_KEY,
    target: Target,
    kept: &mut Kept,
    include_private: bool,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { key(ec) }) else {
        return false;
    };
    // SAFETY: as above.
    let group = unsafe { EC_KEY_get0_group(ec) };
    if group.is_null() {
        return false;
    }
    // SAFETY: as above.
    let priv_key = unsafe { EC_KEY_get0_private_key(ec) };
    // SAFETY: as above.
    let pub_point = unsafe { EC_KEY_get0_public_key(ec) };
    if !pub_point.is_null() {
        // SAFETY: the key's library context.
        let ctx = unsafe { BN_CTX_new_ex(k.get().libctx.0) };
        // SAFETY: the target is live.
        let ok = !ctx.is_null() && unsafe { public_todata(ec, target, kept, ctx.cast()) };
        // SAFETY: the context made above, or NULL.
        unsafe { BN_CTX_free(ctx) };
        if !ok {
            return false;
        }
    }
    if !priv_key.is_null() && include_private {
        // SAFETY: the key's group.
        let bits = unsafe { EC_GROUP_order_bits(group) };
        let Ok(bits) = usize::try_from(bits) else {
            return false;
        };
        if bits == 0 {
            return false;
        }
        // SAFETY: the target; the key's number, alive until the builder makes its array.
        return unsafe { target.bn_pad(OSSL_PKEY_PARAM_PRIV_KEY, priv_key, bits.div_ceil(8)) };
    }
    true
}

/// `key_to_params`' public part.
///
/// # Safety
/// `ec` is a live key with a group and a public key; the target is live; `ctx` is a live
/// `BN_CTX`.
unsafe fn public_todata(
    ec: *const EC_KEY,
    target: Target,
    kept: &mut Kept,
    ctx: *mut rustyssl_abi::BN_CTX,
) -> bool {
    // SAFETY: the caller's guarantee, here and below.
    let group = unsafe { EC_KEY_get0_group(ec) };
    // SAFETY: as above.
    let pub_point = unsafe { EC_KEY_get0_public_key(ec) };
    // SAFETY: as above.
    if unsafe { target.wants(OSSL_PKEY_PARAM_PUB_KEY) } {
        // SAFETY: as above.
        let form = unsafe { EC_KEY_get_conv_form(ec) };
        let mut buf: *mut c_uchar = ptr::null_mut();
        // SAFETY: the key's group and point; a place for a new buffer.
        let len = unsafe { EC_POINT_point2buf(group, pub_point, form, &raw mut buf, ctx) };
        if len == 0 {
            return false;
        }
        // SAFETY: the buffer of `len` octets just made.
        let octets = unsafe { core::slice::from_raw_parts(buf, len) }.to_vec();
        // SAFETY: the buffer, freed once.
        unsafe { CRYPTO_free(buf.cast(), c"".as_ptr(), 0) };
        let octets = kept.octets(octets);
        // SAFETY: the target; `kept` holds the octets until the builder makes its array.
        if !unsafe { target.octets(OSSL_PKEY_PARAM_PUB_KEY, octets) } {
            return false;
        }
    }
    let Target::Params(_) = target else {
        return true;
    };
    // SAFETY: the target is live.
    let want_x = unsafe { target.wants(OSSL_PKEY_PARAM_EC_PUB_X) };
    // SAFETY: as above.
    let want_y = unsafe { target.wants(OSSL_PKEY_PARAM_EC_PUB_Y) };
    if !want_x && !want_y {
        return true;
    }
    let x = if want_x {
        kept.number()
    } else {
        ptr::null_mut()
    };
    let y = if want_y {
        kept.number()
    } else {
        ptr::null_mut()
    };
    if (want_x && x.is_null()) || (want_y && y.is_null()) {
        return false;
    }
    // SAFETY: the key's group and point; numbers or NULL.
    if unsafe { EC_POINT_get_affine_coordinates(group, pub_point, x, y, ctx) } == 0 {
        return false;
    }
    // SAFETY: the target; the numbers, live.
    !(want_x && !unsafe { target.bn(OSSL_PKEY_PARAM_EC_PUB_X, x) })
        // SAFETY: as above.
        && !(want_y && !unsafe { target.bn(OSSL_PKEY_PARAM_EC_PUB_Y, y) })
}

/// `otherparams_to_params`: the point format, check type, a 0 for encodings without the
/// public key, and the cofactor mode.
///
/// # Safety
/// `ec` is NULL or a live key; the target is live.
pub(crate) unsafe fn otherparams_todata(ec: *const EC_KEY, target: Target) -> bool {
    if ec.is_null() {
        return false;
    }
    // SAFETY: the caller's guarantee, here and below.
    let form = unsafe { EC_KEY_get_conv_form(ec) };
    if let Some(name) = format_name(form)
        // SAFETY: as above.
        && !unsafe { target.utf8(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, name) }
    {
        return false;
    }
    // SAFETY: as above.
    let flags = unsafe { EC_KEY_get_flags(ec) };
    let check = flags & EC_FLAG_CHECK_NAMED_GROUP_MASK;
    if let Some((_, name)) = CHECK_TYPES.iter().find(|(id, _)| *id == check)
        // SAFETY: as above.
        && !unsafe { target.utf8(OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, name) }
    {
        return false;
    }
    // SAFETY: as above.
    if unsafe { EC_KEY_get_enc_flags(ec) } & EC_PKEY_NO_PUBKEY.cast_unsigned() != 0
        // SAFETY: as above.
        && !unsafe { target.int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, 0) }
    {
        return false;
    }
    let mode = c_int::from(flags & EC_FLAG_COFACTOR_ECDH != 0);
    // SAFETY: as above.
    unsafe { target.int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, mode) }
}
