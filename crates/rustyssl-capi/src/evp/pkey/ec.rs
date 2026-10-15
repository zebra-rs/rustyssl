//! EC keys in `EVP_PKEY` (`EVP_PKEY_set1_EC_KEY(3)`; `p_legacy.c`, `ec_ameth.c`): the built-in
//! EC ASN.1 method's functions for a key whose legacy data is an `EC_KEY` (SM2's type is an
//! alias of it), and the `EC_KEY` of a key.
//!
//! A key moves between its legacy and provided forms (`export_to`, `import_from`) through the
//! parameters the EC key manager takes (`crate::ec::backend`). `EVP_PKEY_get_field_type` and
//! `EVP_PKEY_get_ec_point_conv_form` read either form.

use core::ffi::{CStr, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_PCTX, ASN1_PKEY_CTRL_DEFAULT_MD_NID, ASN1_PKEY_CTRL_GET1_TLS_ENCPT,
    ASN1_PKEY_CTRL_SET1_TLS_ENCPT, BIO, EC_FLAG_COFACTOR_ECDH, EC_KEY, EC_R_MISSING_PARAMETERS,
    EC_R_MISSING_PRIVATE_KEY, ERR_LIB_EC, ERR_LIB_EVP, ERR_R_EC_LIB, EVP_PKEY, EVP_PKEY_EC,
    EVP_PKEY_SM2, EVP_R_EXPECTING_A_EC_KEY, NID_X9_62_characteristic_two_field,
    NID_X9_62_prime_field, NID_sha256, NID_sm3, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PKEY_PARAM_EC_FIELD_TYPE,
    OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
    POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_HYBRID, POINT_CONVERSION_UNCOMPRESSED,
    SN_X9_62_characteristic_two_field, SN_X9_62_prime_field,
};

use super::params::EVP_PKEY_get_utf8_string_param;
use super::{
    EVP_PKEY_assign, EVP_PKEY_get_base_id, EVP_PKEY_get_id, get_legacy, legacy_data, pkey,
};
use crate::ec::backend::{group_fromdata, key_fromdata, key_todata, otherparams_fromdata};
use crate::ec::ecdsa::ECDSA_size;
use crate::ec::group::{
    EC_GROUP_check, EC_GROUP_cmp, EC_GROUP_free, EC_GROUP_get_field_type, EC_GROUP_order_bits,
};
use crate::ec::key::{
    EC_KEY_check_key, EC_KEY_dup, EC_KEY_free, EC_KEY_get_conv_form, EC_KEY_get_flags,
    EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key, EC_KEY_key2buf, EC_KEY_new,
    EC_KEY_oct2key, EC_KEY_set_group, EC_KEY_up_ref, key, new_key,
};
use crate::ec::key_asn1::{Print, d2i_ECParameters, d2i_ECPrivateKey, i2d_ECParameters, print_key};
use crate::ec::params::{Kept, Target, group_todata};
use crate::ec::point::EC_POINT_cmp;
use crate::err;
use crate::ffi::ffi_export;
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;

/// The key's legacy data as an `EC_KEY` (NULL without).
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn data(p: *const EVP_PKEY) -> *mut EC_KEY {
    // SAFETY: the caller's guarantee.
    unsafe { legacy_data(p) }.cast()
}

/// The group of a key's `EC_KEY`, or NULL.
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn group(p: *const EVP_PKEY) -> *const rustyssl_abi::EC_GROUP {
    // SAFETY: the caller's guarantee.
    let ec = unsafe { data(p) };
    if ec.is_null() {
        return ptr::null();
    }
    // SAFETY: the key's `EC_KEY`.
    unsafe { EC_KEY_get0_group(ec) }
}

/// `eckey_pub_cmp`: 1 for the same public point (on `b`'s group), 0 for another, -2 when
/// either is missing.
pub(crate) unsafe extern "C" fn eckey_pub_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int {
    // SAFETY: the keys the caller compares.
    let (ea, eb) = (unsafe { data(a) }, unsafe { data(b) });
    if ea.is_null() || eb.is_null() {
        return -2;
    }
    // SAFETY: their `EC_KEY`s.
    let g = unsafe { EC_KEY_get0_group(eb) };
    // SAFETY: as above.
    let (pa, pb) = (unsafe { EC_KEY_get0_public_key(ea) }, unsafe {
        EC_KEY_get0_public_key(eb)
    });
    if g.is_null() || pa.is_null() || pb.is_null() {
        return -2;
    }
    // SAFETY: the group and points.
    match unsafe { EC_POINT_cmp(g, pa, pb, ptr::null_mut()) } {
        0 => 1,
        1 => 0,
        _ => -2,
    }
}

/// `int_ec_size`: `ECDSA_size`.
pub(crate) unsafe extern "C" fn int_ec_size(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let ec = unsafe { data(p) };
    // SAFETY: the method's key; its `EC_KEY`, or NULL.
    unsafe { ECDSA_size(ec) }
}

/// `ec_bits`: the order's bits.
pub(crate) unsafe extern "C" fn ec_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let g = unsafe { group(p) };
    if g.is_null() {
        return 0;
    }
    // SAFETY: its group.
    unsafe { EC_GROUP_order_bits(g) }
}

/// `ec_security_bits`: from the order's bits, by SP 800-57's steps.
pub(crate) unsafe extern "C" fn ec_security_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    crate::provider::ec_kmgmt::security_bits(unsafe { ec_bits(p) })
}

/// `ec_missing_parameters`: 1 without an `EC_KEY` or its group.
pub(crate) unsafe extern "C" fn ec_missing_parameters(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    c_int::from(unsafe { group(p) }.is_null())
}

/// `ec_copy_parameters`: `to`'s `EC_KEY` (made if it has none) gets `from`'s group. 1, or 0.
pub(crate) unsafe extern "C" fn ec_copy_parameters(
    to: *mut EVP_PKEY,
    from: *const EVP_PKEY,
) -> c_int {
    // SAFETY: the method's keys.
    let g = unsafe { group(from) };
    // SAFETY: NULL or the key's group.
    let copy = unsafe { crate::ec::group::EC_GROUP_dup(g) };
    if copy.is_null() {
        return 0;
    }
    let ok = (|| {
        // SAFETY: as above.
        let mut ec = unsafe { data(to) };
        if ec.is_null() {
            // SAFETY: no preconditions.
            ec = unsafe { EC_KEY_new() };
            if ec.is_null() {
                return false;
            }
            // SAFETY: the key; the new `EC_KEY` it takes.
            if let Some(k) = unsafe { pkey(to) } {
                k.lock().legacy = crate::provider::Ptr(ec.cast());
            }
        }
        // SAFETY: the `EC_KEY` and the copy.
        (unsafe { EC_KEY_set_group(ec, copy) }) != 0
    })();
    // SAFETY: the copy made above.
    unsafe { EC_GROUP_free(copy) };
    c_int::from(ok)
}

/// `ec_cmp_parameters`: 1 for the same group, 0 for another, -2 when either is missing.
pub(crate) unsafe extern "C" fn ec_cmp_parameters(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's keys.
    let (ga, gb) = (unsafe { group(a) }, unsafe { group(b) });
    if ga.is_null() || gb.is_null() {
        return -2;
    }
    // SAFETY: the groups.
    c_int::from(unsafe { EC_GROUP_cmp(ga, gb, ptr::null_mut()) } == 0)
}

/// `int_ec_free`: drops the key's reference to its `EC_KEY`.
pub(crate) unsafe extern "C" fn int_ec_free(p: *mut EVP_PKEY) {
    // SAFETY: the method's key.
    let ec = unsafe { data(p) };
    // SAFETY: the method's key; its `EC_KEY`, or NULL.
    unsafe { EC_KEY_free(ec) };
}

/// `ec_pkey_ctrl`: the default digest (SHA-256; SM3, mandatory, for SM2's type) and the TLS
/// encoded point both ways; -2 for other controls.
pub(crate) unsafe extern "C" fn ec_pkey_ctrl(
    p: *mut EVP_PKEY,
    op: c_int,
    arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    match op {
        ASN1_PKEY_CTRL_DEFAULT_MD_NID => {
            // SAFETY: the method's key.
            let sm2 = unsafe { EVP_PKEY_get_id(p) } == EVP_PKEY_SM2;
            let (nid, ret) = if sm2 { (NID_sm3, 2) } else { (NID_sha256, 1) };
            if !arg2.is_null() {
                // SAFETY: the control's `int *`.
                unsafe { arg2.cast::<c_int>().write(nid) };
            }
            ret
        }
        ASN1_PKEY_CTRL_SET1_TLS_ENCPT => {
            let Ok(len) = usize::try_from(arg1) else {
                return 0;
            };
            // SAFETY: the method's key.
            let ec = unsafe { data(p) };
            // SAFETY: the method's key; the control's octets of `arg1`.
            unsafe { EC_KEY_oct2key(ec, arg2.cast(), len, ptr::null_mut()) }
        }
        ASN1_PKEY_CTRL_GET1_TLS_ENCPT => {
            // SAFETY: the method's key.
            let ec = unsafe { EVP_PKEY_get0_EC_KEY(p) };
            // SAFETY: its `EC_KEY`, or NULL; the control's `unsigned char **`.
            let n = unsafe {
                EC_KEY_key2buf(
                    ec,
                    POINT_CONVERSION_UNCOMPRESSED,
                    arg2.cast(),
                    ptr::null_mut(),
                )
            };
            c_int::try_from(n).unwrap_or(0)
        }
        _ => -2,
    }
}

/// The print functions' common part.
///
/// # Safety
/// `bp` is a live BIO; `p` is a live key.
unsafe fn print(bp: *mut BIO, p: *const EVP_PKEY, indent: c_int, what: Print) -> c_int {
    // SAFETY: the caller's key.
    let ec = unsafe { data(p) };
    // SAFETY: the caller's BIO; the key's `EC_KEY`, or NULL.
    unsafe { print_key(bp, ec, indent, what) }
}

/// `eckey_pub_print`.
pub(crate) unsafe extern "C" fn eckey_pub_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    indent: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: the method's BIO and key.
    unsafe { print(bp, p, indent, Print::Public) }
}

/// `eckey_priv_print`.
pub(crate) unsafe extern "C" fn eckey_priv_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    indent: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: as above.
    unsafe { print(bp, p, indent, Print::Private) }
}

/// `eckey_param_print`.
pub(crate) unsafe extern "C" fn eckey_param_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    indent: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: as above.
    unsafe { print(bp, p, indent, Print::Param) }
}

/// `eckey_param_decode`: ECParameters as the key's `EC_KEY`. 1, or 0.
pub(crate) unsafe extern "C" fn eckey_param_decode(
    p: *mut EVP_PKEY,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the method's octets.
    let ec = unsafe { d2i_ECParameters(ptr::null_mut(), pder, c_long::from(derlen)) };
    if ec.is_null() {
        return 0;
    }
    // SAFETY: the key; the `EC_KEY` it takes.
    unsafe { EVP_PKEY_assign(p, EVP_PKEY_EC, ec.cast()) };
    1
}

/// `eckey_param_encode`: the key's ECParameters.
pub(crate) unsafe extern "C" fn eckey_param_encode(
    p: *const EVP_PKEY,
    pder: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the method's key.
    let ec = unsafe { data(p) };
    // SAFETY: the method's key; the caller's buffer.
    unsafe { i2d_ECParameters(ec, pder) }
}

/// `old_ec_priv_decode`: an ECPrivateKey as the key's `EC_KEY`. 1, or 0.
pub(crate) unsafe extern "C" fn old_ec_priv_decode(
    p: *mut EVP_PKEY,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the method's octets.
    let ec = unsafe { d2i_ECPrivateKey(ptr::null_mut(), pder, c_long::from(derlen)) };
    if ec.is_null() {
        return 0;
    }
    // SAFETY: the key; the `EC_KEY` it takes.
    unsafe { EVP_PKEY_assign(p, EVP_PKEY_EC, ec.cast()) };
    1
}

/// `ec_pkey_check`: a private key, then `EC_KEY_check_key`.
pub(crate) unsafe extern "C" fn ec_pkey_check(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let ec = unsafe { data(p) };
    // SAFETY: its `EC_KEY`, or NULL.
    if ec.is_null() || unsafe { EC_KEY_get0_private_key(ec) }.is_null() {
        err::raise(ERR_LIB_EC, EC_R_MISSING_PRIVATE_KEY, "ec_pkey_check");
        return 0;
    }
    // SAFETY: as above.
    unsafe { EC_KEY_check_key(ec) }
}

/// `ec_pkey_public_check`: `EC_KEY_check_key`.
pub(crate) unsafe extern "C" fn ec_pkey_public_check(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let ec = unsafe { data(p) };
    // SAFETY: the method's key; its `EC_KEY`, or NULL.
    unsafe { EC_KEY_check_key(ec) }
}

/// `ec_pkey_param_check`: a group, then `EC_GROUP_check`.
pub(crate) unsafe extern "C" fn ec_pkey_param_check(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let g = unsafe { group(p) };
    if g.is_null() {
        err::raise(ERR_LIB_EC, EC_R_MISSING_PARAMETERS, "ec_pkey_param_check");
        return 0;
    }
    // SAFETY: its group.
    unsafe { EC_GROUP_check(g, ptr::null_mut()) }
}

/// `ec_pkey_dirty_cnt`.
pub(crate) unsafe fn ec_pkey_dirty_cnt(p: *const EVP_PKEY) -> usize {
    // SAFETY: the method's key.
    let ec = unsafe { data(p) };
    // SAFETY: the method's key; its `EC_KEY`, or NULL.
    unsafe { key(ec) }.map_or(0, crate::ec::key::EcKey::dirty_count)
}

/// `ec_pkey_copy`: `to` gets a copy of `from`'s `EC_KEY` (or just its type without one). 1,
/// or 0.
pub(crate) unsafe extern "C" fn ec_pkey_copy(to: *mut EVP_PKEY, from: *mut EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let ec = unsafe { data(from) };
    // SAFETY: as above.
    let type_ = unsafe { pkey(from) }.map_or(EVP_PKEY_EC, super::Pkey::type_);
    if ec.is_null() {
        // SAFETY: the caller's key.
        return unsafe { super::EVP_PKEY_set_type(to, type_) };
    }
    // SAFETY: a live `EC_KEY`.
    let dup = unsafe { EC_KEY_dup(ec) };
    if dup.is_null() {
        return 0;
    }
    // SAFETY: the key; the copy it takes.
    let ret = unsafe { EVP_PKEY_assign(to, EVP_PKEY_EC, dup.cast()) };
    if ret == 0 {
        // SAFETY: the copy made above.
        unsafe { EC_KEY_free(dup) };
    }
    ret
}

/// `ec_pkey_export_to`: the group, the public key (in the key's point format), and the
/// private key (padded to the order's length) with the cofactor mode, to `importer`.
///
/// # Safety
/// `from` is a live key with EC legacy data.
pub(crate) unsafe fn ec_pkey_export_to(
    from: *const EVP_PKEY,
    importer: &mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int,
) -> c_int {
    // SAFETY: the method's key.
    let ec = unsafe { data(from) };
    let group = if ec.is_null() {
        ptr::null()
    } else {
        // SAFETY: the key's `EC_KEY`.
        unsafe { EC_KEY_get0_group(ec) }
    };
    if group.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let bld = unsafe { OSSL_PARAM_BLD_new() };
    if bld.is_null() {
        return 0;
    }
    let target = Target::Builder(bld);
    let mut kept = Kept::default();
    let mut selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
    let ok = (|| {
        // SAFETY: the key's group; the builder; `kept` outlives the array's making.
        if !unsafe { group_todata(group, target, &mut kept) } {
            return false;
        }
        // SAFETY: the key's `EC_KEY`.
        let has_pub = !unsafe { EC_KEY_get0_public_key(ec) }.is_null();
        // SAFETY: as above.
        let has_priv = !unsafe { EC_KEY_get0_private_key(ec) }.is_null();
        // SAFETY: as above.
        if !unsafe { key_todata(ec, target, &mut kept, true) } {
            return false;
        }
        if has_pub {
            selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
        }
        if has_priv {
            selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
            // SAFETY: as above.
            let mode = c_int::from(unsafe { EC_KEY_get_flags(ec) } & EC_FLAG_COFACTOR_ECDH != 0);
            // SAFETY: the builder; a static key.
            return unsafe { target.int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, mode) };
        }
        true
    })();
    let mut rv = 0;
    if ok {
        // SAFETY: the builder; what it reads is kept until here.
        let params = unsafe { OSSL_PARAM_BLD_to_param(bld) };
        rv = importer(selection, params);
        // SAFETY: the array made above, or NULL.
        unsafe { OSSL_PARAM_free(params) };
    }
    // SAFETY: the builder made above.
    unsafe { OSSL_PARAM_BLD_free(bld) };
    rv
}

/// `ec_pkey_import_from`: a new `EC_KEY` from `params` (group, other parameters, key pair),
/// assigned to `to` (as SM2's type on SM2's curve).
///
/// # Safety
/// `params` is a parameter array; `to` is a live key.
pub(crate) unsafe fn ec_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    // SAFETY: the library context; no query.
    let ec = unsafe { new_key(libctx, ptr::null()) };
    if ec.is_null() {
        err::raise(ERR_LIB_EC, ERR_R_EC_LIB, "ec_pkey_import_from");
        return 0;
    }
    // SAFETY: the key just made; the caller's array.
    let ok = unsafe { group_fromdata(ec, params) }
        // SAFETY: as above.
        && unsafe { otherparams_fromdata(ec, params) }
        // SAFETY: as above.
        && unsafe { key_fromdata(ec, params, true) }
        // SAFETY: the caller's key; the `EC_KEY`, which it takes.
        && unsafe { EVP_PKEY_assign(to, EVP_PKEY_EC, ec.cast()) } != 0;
    if !ok {
        // SAFETY: the key made above.
        unsafe { EC_KEY_free(ec) };
    }
    c_int::from(ok)
}

/// `evp_pkey_get0_EC_KEY_int`: the key's `EC_KEY`, or NULL with `EVP_R_EXPECTING_A_EC_KEY` for
/// another type.
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn get0_ec(p: *const EVP_PKEY) -> *mut EC_KEY {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { pkey(p) }) else {
        return ptr::null_mut();
    };
    // SAFETY: as above.
    if unsafe { EVP_PKEY_get_base_id(p) } != EVP_PKEY_EC {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_EXPECTING_A_EC_KEY,
            "evp_pkey_get0_EC_KEY_int",
        );
        return ptr::null_mut();
    }
    get_legacy(k).cast()
}

ffi_export! {
    /// Gives the key `key` (with a reference of its own) as EC legacy data (of SM2's type on
    /// SM2's curve). 1, or 0.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key` is NULL or a live `EC_KEY`.
    pub unsafe extern "C" fn EVP_PKEY_set1_EC_KEY(pkey: *mut EVP_PKEY, key: *mut EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if unsafe { EC_KEY_up_ref(key) } == 0 {
            return 0;
        }
        // SAFETY: as above; the reference taken, which the key keeps on success.
        let ret = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, key.cast()) };
        if ret == 0 {
            // SAFETY: the reference taken above.
            unsafe { EC_KEY_free(key) };
        }
        ret
    }
}

ffi_export! {
    /// The key's `EC_KEY`, or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_EC_KEY(pkey: *const EVP_PKEY) -> *const EC_KEY
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_ec(pkey) }
    }
}

ffi_export! {
    /// The key's `EC_KEY` with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get1_EC_KEY(pkey: *mut EVP_PKEY) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let ec = unsafe { get0_ec(pkey) };
        // SAFETY: the key's `EC_KEY`, or NULL.
        if ec.is_null() || unsafe { EC_KEY_up_ref(ec) } == 0 {
            return ptr::null_mut();
        }
        ec
    }
}

/// A provided key's UTF-8 parameter `name` (at most 79 characters), or `None`.
///
/// # Safety
/// `pkey` is a live key.
unsafe fn utf8_param(pkey: *const EVP_PKEY, name: &CStr) -> Option<Vec<u8>> {
    let mut buf = [0u8; 80];
    let mut len = 0usize;
    // SAFETY: the caller's key; a static name; a buffer of its size; a local.
    let ok = unsafe {
        EVP_PKEY_get_utf8_string_param(
            pkey,
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            &raw mut len,
        )
    };
    (ok != 0).then(|| buf.get(..len).unwrap_or_default().to_vec())
}

/// Whether a key is held by a key manager (with data), rather than in legacy form.
///
/// # Safety
/// `pkey` is a live key.
unsafe fn is_provided(pkey: *const EVP_PKEY) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { super::pkey(pkey) }.is_some_and(|k| {
        let (km, kd) = k.provided();
        km.is_some() && kd.is_some()
    })
}

ffi_export! {
    /// The point conversion form of an EC key's public key encodings; 0 for another key or on
    /// failure.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_ec_point_conv_form(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if pkey.is_null() {
            return 0;
        }
        // SAFETY: the caller's key.
        if !unsafe { is_provided(pkey) } {
            // SAFETY: as above.
            let ec = unsafe { get0_ec(pkey) };
            if ec.is_null() {
                return 0;
            }
            // SAFETY: the key's `EC_KEY`.
            return unsafe { EC_KEY_get_conv_form(ec) }.cast_signed();
        }
        // SAFETY: as above.
        let Some(name) = (unsafe { utf8_param(pkey, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT) }) else {
            return 0;
        };
        let form = match name.as_slice() {
            b"uncompressed" => POINT_CONVERSION_UNCOMPRESSED,
            b"compressed" => POINT_CONVERSION_COMPRESSED,
            b"hybrid" => POINT_CONVERSION_HYBRID,
            _ => return 0,
        };
        form.cast_signed()
    }
}

ffi_export! {
    /// The field type (`NID_X9_62_prime_field` or `NID_X9_62_characteristic_two_field`) of an
    /// EC key's group; 0 for another key or on failure. OpenSSL's check of a provided key's
    /// field type is inverted, so a provided key over a characteristic-two field gives 0, and
    /// one of an unknown field type gives the characteristic-two NID; this does the same.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_field_type(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if pkey.is_null() {
            return 0;
        }
        // SAFETY: the caller's key.
        if !unsafe { is_provided(pkey) } {
            // SAFETY: as above.
            let ec = unsafe { get0_ec(pkey) };
            let group = if ec.is_null() {
                ptr::null()
            } else {
                // SAFETY: the key's `EC_KEY`.
                unsafe { EC_KEY_get0_group(ec) }
            };
            if group.is_null() {
                return 0;
            }
            // SAFETY: its group.
            return unsafe { EC_GROUP_get_field_type(group) };
        }
        // SAFETY: as above.
        let Some(name) = (unsafe { utf8_param(pkey, OSSL_PKEY_PARAM_EC_FIELD_TYPE) }) else {
            return 0;
        };
        if name == SN_X9_62_prime_field.to_bytes() {
            NID_X9_62_prime_field
        } else if name != SN_X9_62_characteristic_two_field.to_bytes() {
            NID_X9_62_characteristic_two_field
        } else {
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL's takes a reference to the NULL key.
    #[test]
    fn set1_of_null_fails() {
        // SAFETY: no preconditions.
        let k = unsafe { super::super::EVP_PKEY_new() };
        // SAFETY: a live key; NULL.
        assert_eq!(unsafe { EVP_PKEY_set1_EC_KEY(k, ptr::null_mut()) }, 0);
        // SAFETY: made above, freed once.
        unsafe { super::super::EVP_PKEY_free(k) };
    }

    /// docs/DEVIATIONS.md: OpenSSL's calls the missing callback.
    #[test]
    fn export_without_a_callback_fails() {
        // SAFETY: no preconditions.
        let k = unsafe { super::super::EVP_PKEY_new() };
        // SAFETY: no preconditions.
        let ec = unsafe { EC_KEY_new() };
        // SAFETY: live objects; the key takes a reference.
        assert_eq!(unsafe { EVP_PKEY_set1_EC_KEY(k, ec) }, 1);
        // SAFETY: a live key; no callback.
        let r = unsafe {
            super::super::EVP_PKEY_export(k, rustyssl_abi::EVP_PKEY_KEYPAIR, None, ptr::null_mut())
        };
        assert_eq!(r, 0);
        // SAFETY: made above, each freed once.
        unsafe { EC_KEY_free(ec) };
        // SAFETY: as above.
        unsafe { super::super::EVP_PKEY_free(k) };
    }
}
