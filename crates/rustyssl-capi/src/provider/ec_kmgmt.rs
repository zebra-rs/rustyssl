//! The default provider's EC key manager (`ec_kmgmt.c`, with `ec_backend.c` through
//! `crate::ec::backend`): keys are `EC_KEY` objects (`crate::ec::key`), made empty, filled
//! from parameters (`EVP_PKEY_fromdata`), described (`EVP_PKEY_get_params`), changed
//! (`EVP_PKEY_set_params`), exported, compared, copied by selection, validated, loaded from a
//! reference, and generated: from a named group, explicit parameters, or a template's group,
//! and (RFC 9180's `DeriveKeyPair`) from DHKEM input key material.
//!
//! As in OpenSSL, the import and export always carry the domain parameters, and a private key
//! goes with its public key; the other parameters are optional. SM2's curve belongs to the SM2
//! key manager (step 4.4e), so this one refuses it.

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    BIGNUM, EC_FLAG_CHECK_NAMED_GROUP, EC_FLAG_CHECK_NAMED_GROUP_NIST, EC_FLAG_COFACTOR_ECDH,
    EC_GROUP, EC_KEY, ERR_LIB_EC, ERR_LIB_PROV, ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER,
    NID_X9_62_characteristic_two_field, NID_X9_62_ppBasis, NID_X9_62_tpBasis, NID_sm2,
    OSSL_CALLBACK, OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
    OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_VALIDATE,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
    OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
    OSSL_KEYMGMT_VALIDATE_QUICK_CHECK, OSSL_LIB_CTX, OSSL_OP_KEYEXCH, OSSL_OP_SIGNATURE,
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_DEFAULT_DIGEST,
    OSSL_PKEY_PARAM_DHKEM_IKM, OSSL_PKEY_PARAM_EC_A, OSSL_PKEY_PARAM_EC_B,
    OSSL_PKEY_PARAM_EC_CHAR2_M, OSSL_PKEY_PARAM_EC_CHAR2_PP_K1, OSSL_PKEY_PARAM_EC_CHAR2_PP_K2,
    OSSL_PKEY_PARAM_EC_CHAR2_PP_K3, OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS,
    OSSL_PKEY_PARAM_EC_CHAR2_TYPE, OSSL_PKEY_PARAM_EC_COFACTOR,
    OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, OSSL_PKEY_PARAM_EC_ENCODING,
    OSSL_PKEY_PARAM_EC_FIELD_TYPE, OSSL_PKEY_PARAM_EC_GENERATOR,
    OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
    OSSL_PKEY_PARAM_EC_ORDER, OSSL_PKEY_PARAM_EC_P, OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
    OSSL_PKEY_PARAM_EC_PUB_X, OSSL_PKEY_PARAM_EC_PUB_Y, OSSL_PKEY_PARAM_EC_SEED,
    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_MAX_SIZE,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
    OSSL_PKEY_PARAM_SECURITY_CATEGORY, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
    POINT_CONVERSION_UNCOMPRESSED, PROV_R_INVALID_CURVE, PROV_R_NO_PARAMETERS_SET,
    PROV_R_NOT_A_PUBLIC_KEY, SN_X9_62_ppBasis, SN_X9_62_tpBasis,
};

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::{BN_cmp, BN_free, BN_new};
use crate::ec::backend::{
    group_fromdata, key_fromdata, key_todata, otherparams_fromdata, otherparams_todata,
    set_check_group_type_from_name, set_ecdh_cofactor_mode,
};
use crate::ec::ecdsa::ECDSA_size;
use crate::ec::group::EC_GROUP_get0_order;
use crate::ec::group::{
    EC_GROUP_check, EC_GROUP_check_named_curve, EC_GROUP_cmp, EC_GROUP_dup, EC_GROUP_free,
    EC_GROUP_get_basis_type, EC_GROUP_get_curve_name, EC_GROUP_get_degree, EC_GROUP_get_field_type,
    EC_GROUP_get_pentanomial_basis, EC_GROUP_get_trinomial_basis, EC_GROUP_order_bits,
    EC_GROUP_set_asn1_flag, EC_GROUP_set_point_conversion_form,
};
use crate::ec::key::EC_KEY_new_by_curve_name_ex;
use crate::ec::key::{
    EC_KEY_decoded_from_explicit_params, EC_KEY_generate_key, EC_KEY_get_flags, EC_KEY_get0_group,
    EC_KEY_get0_public_key, EC_KEY_oct2key, EC_KEY_set_group, dup, free, generate_dhkem, key,
    new_key, pairwise_check, private_check, public_check, public_check_quick,
};
use crate::ec::params::{
    EC_GROUP_new_from_params, Kept, Target, encoding_name2id, group_set_params, group_todata,
    pt_format_name2id, text,
};
use crate::ec::point::{EC_POINT_cmp, EC_POINT_point2oct};
use crate::err;
use crate::ffi::ffi_callback;
use crate::generated::err_strings::SM2_R_INVALID_PRIVATE_KEY;
use crate::mem::OPENSSL_cleanse;
use crate::params::bn::OSSL_PARAM_get_BN;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN,
    OSSL_PARAM_BLD_push_octet_string, OSSL_PARAM_BLD_push_utf8_string, OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_locate, OSSL_PARAM_locate_const, OSSL_PARAM_set_int,
    OSSL_PARAM_set_utf8_string,
};

/// `EC_DEFAULT_MD` and `SM2_DEFAULT_MD`.
const EC_DEFAULT_MD: &CStr = c"SHA256";
const SM2_DEFAULT_MD: &CStr = c"SM3";

const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
const DOMAIN: c_int = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
const OTHER: c_int = OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
/// `EC_POSSIBLE_SELECTIONS`.
const POSSIBLE: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;

/// The parameter types, as `defn` takes them.
const INT: c_int = OSSL_PARAM_INTEGER;
const BN: c_int = OSSL_PARAM_UNSIGNED_INTEGER;
const UTF8: c_int = OSSL_PARAM_UTF8_STRING;
const OCTETS: c_int = OSSL_PARAM_OCTET_STRING;
const UTF8_TYPE: u32 = OSSL_PARAM_UTF8_STRING.cast_unsigned();
const OCTETS_TYPE: u32 = OSSL_PARAM_OCTET_STRING.cast_unsigned();
const INT_SIZE: usize = size_of::<c_int>();

/// The security strength of a key whose order has `bits` bits, by SP 800-57's steps.
pub(crate) fn security_bits(bits: c_int) -> c_int {
    match bits {
        512.. => 256,
        384.. => 192,
        256.. => 128,
        224.. => 112,
        160.. => 80,
        _ => bits / 2,
    }
}

/// The key behind key data.
///
/// # Safety
/// `keydata` is NULL or a live `EC_KEY`.
unsafe fn ec<'a>(keydata: *const c_void) -> Option<&'a crate::ec::key::EcKey> {
    // SAFETY: the caller's guarantee.
    unsafe { key(keydata.cast()) }
}

/// The parameter `name` of `params`, or NULL.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn find(params: *mut OSSL_PARAM, name: &CStr) -> *mut OSSL_PARAM {
    // SAFETY: the caller's guarantee; a static name.
    unsafe { OSSL_PARAM_locate(params, name.as_ptr()) }
}

ffi_callback! {
    /// `ec_query_operation_name`: EC keys run ECDH and ECDSA.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ec_query_operation_name(operation_id: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        match operation_id {
            OSSL_OP_KEYEXCH => c"ECDH".as_ptr(),
            OSSL_OP_SIGNATURE => c"ECDSA".as_ptr(),
            _ => ptr::null(),
        }
    }
}

ffi_callback! {
    /// `ec_newdata`: an empty key in the provider's library context.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn ec_newdata(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let libctx = unsafe { libctx_of(provctx) };
        // SAFETY: no query.
        unsafe { new_key(libctx, ptr::null()) }.cast()
    }
}

ffi_callback! {
    /// `ec_freedata` (`EC_KEY_free`).
    ///
    /// # Safety
    /// `keydata` is NULL or key data whose reference the caller gives up.
    pub(crate) unsafe extern "C" fn ec_freedata(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(keydata.cast()) };
    }
}

ffi_callback! {
    /// `ec_has`: the public key, private key, and group as selected (other parameters are
    /// always there).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ec_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ec(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 1;
        }
        let f = k.get();
        let mut ok = true;
        if selection & PUBLIC != 0 {
            ok &= !f.pub_key.0.is_null();
        }
        if selection & PRIVATE != 0 {
            ok &= !f.priv_key.0.is_null();
        }
        if selection & DOMAIN != 0 {
            ok &= !f.group.0.is_null();
        }
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `ec_match`: the groups for the domain parameters; for a key pair selection the public
    /// keys (or, without them, the private keys), which must be there.
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are live key data.
    pub(crate) unsafe extern "C" fn ec_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let (Some(a), Some(b)) = (unsafe { ec(keydata1) }, unsafe { ec(keydata2) }) else { return 0 };
        let (fa, fb) = (a.get(), b.get());
        // SAFETY: the first key's library context.
        let ctx = unsafe { BN_CTX_new_ex(fa.libctx.0) };
        if ctx.is_null() {
            return 0;
        }
        let mut ok = true;
        if selection & DOMAIN != 0 {
            ok = !fa.group.0.is_null()
                && !fb.group.0.is_null()
                // SAFETY: the keys' groups; the context.
                && unsafe { EC_GROUP_cmp(fa.group.0, fb.group.0, ctx) } == 0;
        }
        if selection & KEYPAIR != 0 {
            let mut checked = false;
            if selection & PUBLIC != 0 && !fa.pub_key.0.is_null() && !fb.pub_key.0.is_null() {
                // SAFETY: the second key's group; the keys' points; the context.
                ok = ok && unsafe { EC_POINT_cmp(fb.group.0, fa.pub_key.0, fb.pub_key.0, ctx) } == 0;
                checked = true;
            }
            if !checked
                && selection & PRIVATE != 0
                && !fa.priv_key.0.is_null()
                && !fb.priv_key.0.is_null()
            {
                // SAFETY: the keys' numbers.
                ok = ok && unsafe { BN_cmp(fa.priv_key.0, fb.priv_key.0) } == 0;
                checked = true;
            }
            ok = ok && checked;
        }
        // SAFETY: the context made above.
        unsafe { BN_CTX_free(ctx) };
        c_int::from(ok)
    }
}

/// `common_check_sm2`: whether the key has a group, on SM2's curve exactly when `sm2_wanted`.
///
/// # Safety
/// `ec` is a live key.
unsafe fn check_sm2(ec: *const EC_KEY, sm2_wanted: bool) -> bool {
    // SAFETY: the caller's guarantee.
    let group = unsafe { EC_KEY_get0_group(ec) };
    // SAFETY: the key's group.
    !group.is_null() && sm2_wanted == (unsafe { EC_GROUP_get_curve_name(group) } == NID_sm2)
}

/// `common_import`: the domain parameters (which must be selected, and on SM2's curve exactly
/// when `sm2`), then the key pair and the other parameters as selected.
///
/// # Safety
/// `keydata` is NULL or live key data; `params` is NULL or an array.
unsafe fn import(
    keydata: *mut c_void,
    selection: c_int,
    params: *const OSSL_PARAM,
    sm2: bool,
) -> c_int {
    let h = keydata.cast::<EC_KEY>();
    if h.is_null() || selection & DOMAIN == 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let mut ok = unsafe { group_fromdata(h, params) };
    // SAFETY: as above.
    if !unsafe { check_sm2(h, sm2) } {
        return 0;
    }
    if selection & KEYPAIR != 0 {
        // SAFETY: as above.
        ok = ok && unsafe { key_fromdata(h, params, selection & PRIVATE != 0) };
    }
    if selection & OTHER != 0 {
        // SAFETY: as above.
        ok = ok && unsafe { otherparams_fromdata(h, params) };
    }
    c_int::from(ok)
}

ffi_callback! {
    /// `ec_import`: as `common_import`, not on SM2's curve.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ec_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { import(keydata, selection, params, false) }
    }
}

ffi_callback! {
    /// `ec_export`: the domain parameters (which must be selected), the key pair (a private key
    /// only with the public key), and the other parameters, to `param_cb`, called once.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` takes `cbarg`.
    pub(crate) unsafe extern "C" fn ec_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let h = keydata.cast::<EC_KEY>().cast_const();
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ec(keydata) }) else { return 0 };
        if selection & DOMAIN == 0 || (selection & PRIVATE != 0 && selection & PUBLIC == 0) {
            return 0;
        }
        // SAFETY: no preconditions.
        let bld = unsafe { OSSL_PARAM_BLD_new() };
        if bld.is_null() {
            return 0;
        }
        let target = Target::Builder(bld);
        let mut kept = Kept::default();
        // SAFETY: the key's library context.
        let ctx = unsafe { BN_CTX_new_ex(k.get().libctx.0) };
        // SAFETY: the key's group; the builder; `kept` outlives the array's making.
        let mut ok = !ctx.is_null() && unsafe { group_todata(k.get().group.0, target, &mut kept) };
        if selection & KEYPAIR != 0 {
            // SAFETY: as above.
            ok = ok && unsafe { key_todata(h, target, &mut kept, selection & PRIVATE != 0) };
        }
        if selection & OTHER != 0 {
            // SAFETY: as above.
            ok = ok && unsafe { otherparams_todata(h, target) };
        }
        let mut ret = 0;
        if ok {
            // SAFETY: the builder; what it reads is kept until here.
            let params = unsafe { OSSL_PARAM_BLD_to_param(bld) };
            if !params.is_null() {
                if let Some(cb) = param_cb {
                    // SAFETY: the caller's callback and argument; the array, freed after.
                    ret = unsafe { cb(params, cbarg) };
                }
                // SAFETY: the array made above.
                unsafe { OSSL_PARAM_free(params) };
            }
        }
        // SAFETY: the builder made above.
        unsafe { OSSL_PARAM_BLD_free(bld) };
        // SAFETY: the context made above, or NULL.
        unsafe { BN_CTX_free(ctx) };
        ret
    }
}

/// Builds `EC_IMEXPORTABLE_*` lists: the private key, the public key, the domain parameters,
/// and the other parameters, in that order, as named.
macro_rules! imexport {
    ($($name:ident: $n:literal = [$($part:ident)*];)*) => {
        $( static $name: Params<$n> = Params(imexport!(@build [] $($part)*)); )*
    };
    (@build [$($e:expr),*] priv $($rest:ident)*) => {
        imexport!(@build [$($e,)* defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0)] $($rest)*)
    };
    (@build [$($e:expr),*] pub $($rest:ident)*) => {
        imexport!(@build [$($e,)* defn(OSSL_PKEY_PARAM_PUB_KEY, OCTETS, 0)] $($rest)*)
    };
    (@build [$($e:expr),*] dom $($rest:ident)*) => {
        imexport!(@build [
            $($e,)*
            defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
            defn(OSSL_PKEY_PARAM_EC_ENCODING, UTF8, 0),
            defn(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, UTF8, 0),
            defn(OSSL_PKEY_PARAM_EC_FIELD_TYPE, UTF8, 0),
            defn(OSSL_PKEY_PARAM_EC_P, BN, 0),
            defn(OSSL_PKEY_PARAM_EC_A, BN, 0),
            defn(OSSL_PKEY_PARAM_EC_B, BN, 0),
            defn(OSSL_PKEY_PARAM_EC_GENERATOR, OCTETS, 0),
            defn(OSSL_PKEY_PARAM_EC_ORDER, BN, 0),
            defn(OSSL_PKEY_PARAM_EC_COFACTOR, BN, 0),
            defn(OSSL_PKEY_PARAM_EC_SEED, OCTETS, 0),
            defn(OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, INT, INT_SIZE)
        ] $($rest)*)
    };
    (@build [$($e:expr),*] other $($rest:ident)*) => {
        imexport!(@build [
            $($e,)*
            defn(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, INT, INT_SIZE),
            defn(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, INT, INT_SIZE)
        ] $($rest)*)
    };
    (@build [$($e:expr),*]) => { [$($e,)* PARAM_END] };
}

imexport! {
    TYPES_1: 2 = [priv];
    TYPES_2: 2 = [pub];
    TYPES_3: 3 = [priv pub];
    TYPES_4: 13 = [dom];
    TYPES_5: 14 = [priv dom];
    TYPES_6: 14 = [pub dom];
    TYPES_7: 15 = [priv pub dom];
    TYPES_8: 3 = [other];
    TYPES_9: 4 = [priv other];
    TYPES_10: 4 = [pub other];
    TYPES_11: 5 = [priv pub other];
    TYPES_12: 15 = [dom other];
    TYPES_13: 16 = [priv dom other];
    TYPES_14: 16 = [pub dom other];
    TYPES_15: 17 = [priv pub dom other];
}

ffi_callback! {
    /// `ec_import_types` and `ec_export_types` (`ec_imexport_types`): the parameters of the
    /// selected parts; NULL for none.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ec_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        let mut which = 0;
        for (bit, add) in [(PRIVATE, 1), (PUBLIC, 2), (DOMAIN, 4), (OTHER, 8)] {
            if selection & bit != 0 {
                which += add;
            }
        }
        match which {
            1 => TYPES_1.0.as_ptr(),
            2 => TYPES_2.0.as_ptr(),
            3 => TYPES_3.0.as_ptr(),
            4 => TYPES_4.0.as_ptr(),
            5 => TYPES_5.0.as_ptr(),
            6 => TYPES_6.0.as_ptr(),
            7 => TYPES_7.0.as_ptr(),
            8 => TYPES_8.0.as_ptr(),
            9 => TYPES_9.0.as_ptr(),
            10 => TYPES_10.0.as_ptr(),
            11 => TYPES_11.0.as_ptr(),
            12 => TYPES_12.0.as_ptr(),
            13 => TYPES_13.0.as_ptr(),
            14 => TYPES_14.0.as_ptr(),
            15 => TYPES_15.0.as_ptr(),
            _ => ptr::null(),
        }
    }
}

/// `ec_get_ecm_params`: a characteristic-two group's degree, basis, and its exponents.
///
/// # Safety
/// `group` is a live group; `params` is a live array.
unsafe fn ecm_params(group: *const EC_GROUP, params: *mut OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee, here and below.
    if unsafe { EC_GROUP_get_field_type(group) } != NID_X9_62_characteristic_two_field {
        return true;
    }
    let target = Target::Params(params);
    // SAFETY: as above.
    let basis = unsafe { EC_GROUP_get_basis_type(group) };
    let name = if basis == NID_X9_62_tpBasis {
        SN_X9_62_tpBasis
    } else if basis == NID_X9_62_ppBasis {
        SN_X9_62_ppBasis
    } else {
        return false;
    };
    // SAFETY: as above.
    let m = unsafe { EC_GROUP_get_degree(group) };
    // SAFETY: as above.
    if !unsafe { target.int(OSSL_PKEY_PARAM_EC_CHAR2_M, m) }
        // SAFETY: as above.
        || !unsafe { target.utf8(OSSL_PKEY_PARAM_EC_CHAR2_TYPE, name) }
    {
        return false;
    }
    let (mut k1, mut k2, mut k3): (c_uint, c_uint, c_uint) = (0, 0, 0);
    if basis == NID_X9_62_tpBasis {
        // SAFETY: as above; a local.
        return unsafe { EC_GROUP_get_trinomial_basis(group, &raw mut k1) } != 0
            // SAFETY: as above.
            && unsafe { target.int(OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS, k1.cast_signed()) };
    }
    // SAFETY: as above; locals.
    (unsafe { EC_GROUP_get_pentanomial_basis(group, &raw mut k1, &raw mut k2, &raw mut k3) } != 0)
        // SAFETY: as above.
        && unsafe { target.int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K1, k1.cast_signed()) }
        // SAFETY: as above.
        && unsafe { target.int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K2, k2.cast_signed()) }
        // SAFETY: as above.
        && unsafe { target.int(OSSL_PKEY_PARAM_EC_CHAR2_PP_K3, k3.cast_signed()) }
}

/// Sets `params`' parameter `name` to `v` if it's there; false if it can't be.
///
/// # Safety
/// `params` is NULL or a live array.
unsafe fn set_int(params: *mut OSSL_PARAM, name: &CStr, v: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    let p = unsafe { find(params, name) };
    // SAFETY: a parameter of the array.
    p.is_null() || unsafe { OSSL_PARAM_set_int(p, v) } != 0
}

/// `common_get_params`' work after the group's check.
///
/// # Safety
/// `h` is a live key with the group `group`; `params` is NULL or a live array; `ctx` is a live
/// `BN_CTX`.
unsafe fn get_params(
    h: *const EC_KEY,
    group: *const EC_GROUP,
    params: *mut OSSL_PARAM,
    ctx: *mut rustyssl_abi::BN_CTX,
    sm2: bool,
) -> bool {
    // SAFETY: the caller's guarantee, here and below.
    let bits = unsafe { EC_GROUP_order_bits(group) };
    // SAFETY: as above.
    let max_size = unsafe { ECDSA_size(h) };
    // SAFETY: as above.
    if !unsafe { set_int(params, OSSL_PKEY_PARAM_MAX_SIZE, max_size) }
        // SAFETY: as above.
        || !unsafe { set_int(params, OSSL_PKEY_PARAM_BITS, bits) }
        // SAFETY: as above.
        || !unsafe { set_int(params, OSSL_PKEY_PARAM_SECURITY_BITS, security_bits(bits)) }
        // 3.6: classical keys are in no NIST post-quantum category.
        // SAFETY: as above.
        || !unsafe { set_int(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY, 0) }
    {
        return false;
    }
    // SAFETY: as above.
    if !unsafe { find(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS) }.is_null() {
        // SAFETY: as above.
        let explicit = unsafe { EC_KEY_decoded_from_explicit_params(h) };
        if explicit < 0
            // SAFETY: as above.
            || !unsafe { set_int(params, OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS, explicit) }
        {
            return false;
        }
    }
    // SAFETY: as above.
    let p = unsafe { find(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST) };
    let md = if sm2 { SM2_DEFAULT_MD } else { EC_DEFAULT_MD };
    // SAFETY: a parameter of the array; a static string.
    if !p.is_null() && unsafe { OSSL_PARAM_set_utf8_string(p, md.as_ptr()) } == 0 {
        return false;
    }
    // SM2 has no cofactor mode.
    if !sm2 {
        // SAFETY: as above.
        let cofactor = c_int::from(unsafe { EC_KEY_get_flags(h) } & EC_FLAG_COFACTOR_ECDH != 0);
        // SAFETY: as above.
        if !unsafe { set_int(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, cofactor) } {
            return false;
        }
    }
    // SAFETY: as above.
    let p = unsafe { find(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) };
    // SAFETY: NULL or a parameter of the array.
    if let Some(prm) = unsafe { p.as_mut() } {
        // SAFETY: as above.
        let point = unsafe { EC_KEY_get0_public_key(h) };
        if point.is_null() {
            err::raise(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY, "common_get_params");
            return false;
        }
        // SAFETY: the group and point; the parameter's buffer of its size (or NULL, to learn
        // the length); the context.
        prm.return_size = unsafe {
            EC_POINT_point2oct(
                group,
                point,
                POINT_CONVERSION_UNCOMPRESSED,
                prm.data.cast(),
                prm.data_size,
                ctx,
            )
        };
        if prm.return_size == 0 {
            return false;
        }
    }
    let target = Target::Params(params);
    let mut kept = Kept::default();
    // SAFETY: as above.
    (unsafe { ecm_params(group, params) })
        // SAFETY: as above.
        && unsafe { group_todata(group, target, &mut kept) }
        // SAFETY: as above.
        && unsafe { key_todata(h, target, &mut kept, true) }
        // SAFETY: as above.
        && unsafe { otherparams_todata(h, target) }
}

/// `common_get_params`: the sizes, strengths, default digest, cofactor mode (not SM2's),
/// uncompressed public key, then the group, key, and other parameters. Fails with
/// `PROV_R_NO_PARAMETERS_SET` for a key without a group.
///
/// # Safety
/// `keydata` is NULL or live key data; `params` is NULL or an array.
unsafe fn common_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM, sm2: bool) -> c_int {
    let h = keydata.cast::<EC_KEY>().cast_const();
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { ec(keydata) }) else {
        return 0;
    };
    let f = k.get();
    if f.group.0.is_null() {
        err::raise(ERR_LIB_PROV, PROV_R_NO_PARAMETERS_SET, "common_get_params");
        return 0;
    }
    // SAFETY: the key's library context.
    let ctx = unsafe { BN_CTX_new_ex(f.libctx.0) };
    if ctx.is_null() {
        return 0;
    }
    // SAFETY: the key, its group, the caller's array, the context.
    let ok = unsafe { get_params(h, f.group.0, params, ctx, sm2) };
    // SAFETY: the context made above.
    unsafe { BN_CTX_free(ctx) };
    c_int::from(ok)
}

ffi_callback! {
    /// `ec_get_params` (`common_get_params`).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ec_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { common_get_params(keydata, params, false) }
    }
}

/// `ec_known_gettable_params`.
static GETTABLE: Params<32> = Params([
    defn(OSSL_PKEY_PARAM_BITS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_CATEGORY, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_DEFAULT_DIGEST, UTF8, 0),
    defn(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OCTETS, 0),
    defn(
        OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
        INT,
        INT_SIZE,
    ),
    defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_ENCODING, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_FIELD_TYPE, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_A, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_B, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_GENERATOR, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_EC_ORDER, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_SEED, OCTETS, 0),
    defn(
        OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
        INT,
        INT_SIZE,
    ),
    defn(OSSL_PKEY_PARAM_EC_CHAR2_M, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_EC_CHAR2_TYPE, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_CHAR2_TP_BASIS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_EC_CHAR2_PP_K1, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_EC_CHAR2_PP_K2, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_EC_CHAR2_PP_K3, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_EC_PUB_X, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_PUB_Y, BN, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0),
    defn(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, INT, INT_SIZE),
    PARAM_END,
]);

ffi_callback! {
    /// `ec_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ec_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        GETTABLE.0.as_ptr()
    }
}

/// `ec_known_settable_params`.
static SETTABLE: Params<8> = Params([
    defn(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_EC_ENCODING, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_SEED, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE, UTF8, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ec_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ec_settable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `ec_set_params`: the group's format, encoding, and seed, an encoded public key (an
    /// octet string), and the other parameters.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ec_set_params(keydata: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let h = keydata.cast::<EC_KEY>();
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ec(keydata) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let f = k.get();
        // A key without a group, which no EVP function makes, takes nothing (OpenSSL's
        // dereferences the missing group).
        // SAFETY: the key's group; the caller's array.
        if f.group.0.is_null() || !unsafe { group_set_params(f.group.0, params) } {
            return 0;
        }
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr()) };
        // SAFETY: NULL or a parameter of the array.
        if let Some(prm) = unsafe { p.as_ref() } {
            // SAFETY: the key's library context.
            let ctx = unsafe { BN_CTX_new_ex(f.libctx.0) };
            let ok = !ctx.is_null()
                && prm.data_type == OCTETS_TYPE
                // SAFETY: the key; the parameter's data of its size; the context.
                && unsafe { EC_KEY_oct2key(h, prm.data.cast(), prm.data_size, ctx) } != 0;
            // SAFETY: the context made above, or NULL.
            unsafe { BN_CTX_free(ctx) };
            if !ok {
                return 0;
            }
        }
        // SAFETY: the key; the caller's array.
        c_int::from(unsafe { otherparams_fromdata(h, params) })
    }
}

ffi_callback! {
    /// `ec_validate`: the group (as a named curve under a named-group check type), the public
    /// key (quickly or fully), the private key's range, and the pair together.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ec_validate(keydata: *const c_void, selection: c_int, checktype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ec(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 1;
        }
        let f = k.get();
        // SAFETY: the key's library context.
        let ctx = unsafe { BN_CTX_new_ex(f.libctx.0) };
        if ctx.is_null() {
            return 0;
        }
        let mut ok = true;
        if selection & DOMAIN != 0 {
            ok = if f.flags & EC_FLAG_CHECK_NAMED_GROUP != 0 {
                let nist = c_int::from(f.flags & EC_FLAG_CHECK_NAMED_GROUP_NIST != 0);
                // SAFETY: the key's group, or NULL; the context.
                (unsafe { EC_GROUP_check_named_curve(f.group.0, nist, ctx) }) > 0
            } else {
                // SAFETY: as above.
                (unsafe { EC_GROUP_check(f.group.0, ctx) }) != 0
            };
        }
        if selection & PUBLIC != 0 {
            ok = ok
                && if checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK {
                    // SAFETY: the key's objects, or NULL; the context.
                    unsafe { public_check_quick(&f, ctx) }
                } else {
                    // SAFETY: as above.
                    unsafe { public_check(&f, ctx) }
                };
        }
        if selection & PRIVATE != 0 {
            // SAFETY: as above.
            ok = ok && unsafe { private_check(&f) };
        }
        if selection & KEYPAIR == KEYPAIR {
            // SAFETY: as above.
            ok = ok && unsafe { pairwise_check(&f, ctx) };
        }
        // SAFETY: the context made above.
        unsafe { BN_CTX_free(ctx) };
        c_int::from(ok)
    }
}

/// `struct ec_gen_ctx`: what generation is asked for.
struct GenCtx {
    libctx: *mut OSSL_LIB_CTX,
    group_name: Option<CString>,
    encoding: Option<CString>,
    pt_format: Option<CString>,
    group_check: Option<CString>,
    field_type: Option<CString>,
    p: *mut BIGNUM,
    a: *mut BIGNUM,
    b: *mut BIGNUM,
    order: *mut BIGNUM,
    cofactor: *mut BIGNUM,
    generator: Option<Vec<u8>>,
    seed: Option<Vec<u8>>,
    selection: c_int,
    ecdh_mode: c_int,
    gen_group: *mut EC_GROUP,
    dhkem_ikm: Option<Vec<u8>>,
}

impl Drop for GenCtx {
    fn drop(&mut self) {
        if let Some(ikm) = &mut self.dhkem_ikm {
            // SAFETY: the vector's own octets.
            unsafe { OPENSSL_cleanse(ikm.as_mut_ptr().cast(), ikm.len()) };
        }
        // SAFETY: the context's group, or NULL, freed once.
        unsafe { EC_GROUP_free(self.gen_group) };
        for b in [self.p, self.a, self.b, self.order, self.cofactor] {
            // SAFETY: the context's numbers, or NULL, each freed once.
            unsafe { BN_free(b) };
        }
    }
}

/// The generation context behind `genctx`.
///
/// # Safety
/// `genctx` is NULL or a live context from `ec_gen_init`.
unsafe fn gen_ctx<'a>(genctx: *mut c_void) -> Option<&'a mut GenCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<GenCtx>(genctx) }
}

ffi_callback! {
    /// `ec_gen_init`: a context for the selection (which must name something EC keys have),
    /// with `params` set.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ec_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        if selection & POSSIBLE == 0 {
            return ptr::null_mut();
        }
        let g = boxed(GenCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            group_name: None,
            encoding: None,
            pt_format: None,
            group_check: None,
            field_type: None,
            p: ptr::null_mut(),
            a: ptr::null_mut(),
            b: ptr::null_mut(),
            order: ptr::null_mut(),
            cofactor: ptr::null_mut(),
            generator: None,
            seed: None,
            selection,
            ecdh_mode: 0,
            gen_group: ptr::null_mut(),
            dhkem_ikm: None,
        });
        // SAFETY: the context just made; the caller's array.
        if unsafe { ec_gen_set_params(g, params) } != 1 {
            // SAFETY: the context just made, freed once.
            unsafe { unbox::<GenCtx>(g) };
            return ptr::null_mut();
        }
        g
    }
}

ffi_callback! {
    /// `ec_gen_set_template`: a copy of the template key's group, which generation then uses.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `templ` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ec_gen_set_template(genctx: *mut c_void, templ: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return 0 };
        // SAFETY: as above.
        let Some(t) = (unsafe { ec(templ) }) else { return 0 };
        let group = t.get().group.0;
        if group.is_null() {
            return 0;
        }
        // SAFETY: the template's group.
        let copy = unsafe { EC_GROUP_dup(group) };
        if copy.is_null() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_CURVE, "ec_gen_set_group");
            return 0;
        }
        // SAFETY: the old group, or NULL, freed once.
        unsafe { EC_GROUP_free(core::mem::replace(&mut g.gen_group, copy)) };
        1
    }
}

/// `COPY_UTF8_PARAM`: a UTF-8 string parameter's text, or `Err` for another type (the old
/// value is dropped either way).
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn copy_utf8(
    params: *const OSSL_PARAM,
    name: &CStr,
    val: &mut Option<CString>,
) -> Result<(), ()> {
    // SAFETY: the caller's guarantee; a static name.
    let p = unsafe { OSSL_PARAM_locate_const(params, name.as_ptr()) };
    // SAFETY: NULL or a parameter of the array.
    let Some(prm) = (unsafe { p.as_ref() }) else {
        return Ok(());
    };
    if prm.data_type != UTF8_TYPE {
        return Err(());
    }
    *val = None;
    // SAFETY: a parameter of the array.
    let Some(Some(s)) = (unsafe { text(p) }) else {
        return Err(());
    };
    *val = Some(CString::new(s).map_err(|_| ())?);
    Ok(())
}

/// `COPY_OCTET_PARAM`: an octet string parameter's octets (at least one), or `Err` for another
/// type or none (the old value is dropped either way).
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn copy_octets(
    params: *const OSSL_PARAM,
    name: &CStr,
    val: &mut Option<Vec<u8>>,
) -> Result<(), ()> {
    // SAFETY: the caller's guarantee; a static name.
    let p = unsafe { OSSL_PARAM_locate_const(params, name.as_ptr()) };
    // SAFETY: NULL or a parameter of the array.
    let Some(prm) = (unsafe { p.as_ref() }) else {
        return Ok(());
    };
    if prm.data_type != OCTETS_TYPE {
        return Err(());
    }
    if let Some(old) = val.as_mut() {
        // SAFETY: the vector's own octets.
        unsafe { OPENSSL_cleanse(old.as_mut_ptr().cast(), old.len()) };
    }
    *val = None;
    if prm.data.is_null()
        || prm.data_size == 0
        || prm.data_size >= usize::try_from(c_int::MAX).unwrap_or(usize::MAX)
    {
        return Err(());
    }
    // SAFETY: the parameter's data of its size.
    *val =
        Some(unsafe { core::slice::from_raw_parts(prm.data.cast::<u8>(), prm.data_size) }.to_vec());
    Ok(())
}

/// `COPY_BN_PARAM`: a number parameter into `bn` (made if NULL), or `Err`.
///
/// # Safety
/// `params` is NULL or a parameter array; `bn` is NULL or a live number.
unsafe fn copy_bn(params: *const OSSL_PARAM, name: &CStr, bn: &mut *mut BIGNUM) -> Result<(), ()> {
    // SAFETY: the caller's guarantee; a static name.
    let p = unsafe { OSSL_PARAM_locate_const(params, name.as_ptr()) };
    if p.is_null() {
        return Ok(());
    }
    if bn.is_null() {
        // SAFETY: no preconditions.
        *bn = unsafe { BN_new() };
    }
    // SAFETY: a parameter of the array; the number.
    if bn.is_null() || unsafe { OSSL_PARAM_get_BN(p, bn) } == 0 {
        return Err(());
    }
    Ok(())
}

/// `ec_gen_set_params`' work, each parameter committed as it's read.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn gen_set_params(g: &mut GenCtx, params: *const OSSL_PARAM) -> Result<(), ()> {
    // SAFETY: the caller's guarantee; a static name.
    let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH.as_ptr()) };
    // SAFETY: a parameter of the array; the context's field.
    if !p.is_null() && unsafe { OSSL_PARAM_get_int(p, &raw mut g.ecdh_mode) } == 0 {
        return Err(());
    }
    // SAFETY: the caller's guarantee, here and below.
    unsafe {
        copy_utf8(params, OSSL_PKEY_PARAM_GROUP_NAME, &mut g.group_name)?;
    }
    // SAFETY: as above.
    unsafe { copy_utf8(params, OSSL_PKEY_PARAM_EC_FIELD_TYPE, &mut g.field_type)? };
    // SAFETY: as above.
    unsafe { copy_utf8(params, OSSL_PKEY_PARAM_EC_ENCODING, &mut g.encoding)? };
    // SAFETY: as above.
    unsafe {
        copy_utf8(
            params,
            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT,
            &mut g.pt_format,
        )?
    };
    // SAFETY: as above.
    unsafe {
        copy_utf8(
            params,
            OSSL_PKEY_PARAM_EC_GROUP_CHECK_TYPE,
            &mut g.group_check,
        )?
    };
    // SAFETY: as above; the context's numbers.
    unsafe { copy_bn(params, OSSL_PKEY_PARAM_EC_P, &mut g.p)? };
    // SAFETY: as above.
    unsafe { copy_bn(params, OSSL_PKEY_PARAM_EC_A, &mut g.a)? };
    // SAFETY: as above.
    unsafe { copy_bn(params, OSSL_PKEY_PARAM_EC_B, &mut g.b)? };
    // SAFETY: as above.
    unsafe { copy_bn(params, OSSL_PKEY_PARAM_EC_ORDER, &mut g.order)? };
    // SAFETY: as above.
    unsafe { copy_bn(params, OSSL_PKEY_PARAM_EC_COFACTOR, &mut g.cofactor)? };
    // SAFETY: as above.
    unsafe { copy_octets(params, OSSL_PKEY_PARAM_EC_SEED, &mut g.seed)? };
    // SAFETY: as above.
    unsafe { copy_octets(params, OSSL_PKEY_PARAM_EC_GENERATOR, &mut g.generator)? };
    // SAFETY: as above.
    unsafe { copy_octets(params, OSSL_PKEY_PARAM_DHKEM_IKM, &mut g.dhkem_ikm) }
}

ffi_callback! {
    /// `ec_gen_set_params`: the cofactor mode, the group's name or explicit parameters, its
    /// encoding and point format, the check type, and a DHKEM input.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ec_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { gen_set_params(g, params) }.is_ok())
    }
}

/// `ec_gen_set_group_from_params`: the group the context's parameters describe (a named one
/// alone if it has a name; otherwise a field type, `p`, `a`, `b`, the order, and the
/// generator, with the cofactor and seed if given), through `EC_GROUP_new_from_params`.
///
/// # Safety
/// `g`'s numbers are NULL or live.
unsafe fn gen_set_group_from_params(g: &mut GenCtx) -> bool {
    // SAFETY: no preconditions.
    let bld = unsafe { OSSL_PARAM_BLD_new() };
    if bld.is_null() {
        return false;
    }
    let push_utf8 = |key: &CStr, v: &Option<CString>| {
        v.as_ref().is_none_or(|s| {
            // SAFETY: the builder; a static key; the context's string, alive until the array.
            (unsafe { OSSL_PARAM_BLD_push_utf8_string(bld, key.as_ptr(), s.as_ptr(), 0) }) != 0
        })
    };
    let push_bn = |key: &CStr, v: *const BIGNUM| {
        // SAFETY: the builder; a static key; the context's number, alive until the array.
        !v.is_null() && unsafe { OSSL_PARAM_BLD_push_BN(bld, key.as_ptr(), v) } != 0
    };
    let push_octets = |key: &CStr, v: &[u8]| {
        // SAFETY: the builder; a static key; the context's octets, alive until the array.
        (unsafe { OSSL_PARAM_BLD_push_octet_string(bld, key.as_ptr(), v.as_ptr().cast(), v.len()) })
            != 0
    };
    let described = (|| {
        if !push_utf8(OSSL_PKEY_PARAM_EC_ENCODING, &g.encoding)
            || !push_utf8(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, &g.pt_format)
        {
            return false;
        }
        if g.group_name.is_some() {
            return push_utf8(OSSL_PKEY_PARAM_GROUP_NAME, &g.group_name);
        }
        if g.field_type.is_none() || !push_utf8(OSSL_PKEY_PARAM_EC_FIELD_TYPE, &g.field_type) {
            return false;
        }
        if !push_bn(OSSL_PKEY_PARAM_EC_P, g.p)
            || !push_bn(OSSL_PKEY_PARAM_EC_A, g.a)
            || !push_bn(OSSL_PKEY_PARAM_EC_B, g.b)
            || !push_bn(OSSL_PKEY_PARAM_EC_ORDER, g.order)
        {
            return false;
        }
        if !g.cofactor.is_null() && !push_bn(OSSL_PKEY_PARAM_EC_COFACTOR, g.cofactor) {
            return false;
        }
        if let Some(seed) = &g.seed
            && !push_octets(OSSL_PKEY_PARAM_EC_SEED, seed)
        {
            return false;
        }
        g.generator
            .as_ref()
            .is_some_and(|gen_| push_octets(OSSL_PKEY_PARAM_EC_GENERATOR, gen_))
    })();
    let mut ok = false;
    if described {
        // SAFETY: the builder; what it reads lives in the context.
        let params = unsafe { OSSL_PARAM_BLD_to_param(bld) };
        if !params.is_null() {
            // SAFETY: the array; the context's library context; no query.
            let group = unsafe { EC_GROUP_new_from_params(params, g.libctx, ptr::null()) };
            if !group.is_null() {
                // SAFETY: the old group, or NULL, freed once.
                unsafe { EC_GROUP_free(core::mem::replace(&mut g.gen_group, group)) };
                ok = true;
            }
            // SAFETY: the array made above.
            unsafe { OSSL_PARAM_free(params) };
        }
    }
    // SAFETY: the builder made above.
    unsafe { OSSL_PARAM_BLD_free(bld) };
    ok
}

/// `ec_gen`'s work on the new key `h`.
///
/// # Safety
/// `h` is a live key; `g`'s objects are NULL or live.
unsafe fn gen_into(g: &mut GenCtx, h: *mut EC_KEY, sm2: bool) -> bool {
    if g.gen_group.is_null() {
        // SAFETY: the caller's guarantee.
        if !unsafe { gen_set_group_from_params(g) } {
            return false;
        }
    } else {
        if let Some(e) = &g.encoding {
            let Some(flag) = encoding_name2id(e.to_bytes()) else {
                return false;
            };
            // SAFETY: the context's group.
            unsafe { EC_GROUP_set_asn1_flag(g.gen_group, flag) };
        }
        if let Some(f) = &g.pt_format {
            let Some(form) = pt_format_name2id(f.to_bytes()) else {
                return false;
            };
            // SAFETY: as above.
            unsafe { EC_GROUP_set_point_conversion_form(g.gen_group, form) };
        }
    }
    // `ec_gen_assign_group`.
    let mut ok = if g.gen_group.is_null() {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_NO_PARAMETERS_SET,
            "ec_gen_assign_group",
        );
        false
    } else {
        // SAFETY: the key; the context's group.
        (unsafe { EC_KEY_set_group(h, g.gen_group) }) > 0
    };
    // `sm2_gen` has no DHKEM input, cofactor mode, or check type.
    if sm2 {
        if g.selection & KEYPAIR != 0 {
            // SAFETY: the key, with its group.
            ok = ok && (unsafe { EC_KEY_generate_key(h) }) != 0;
        }
        return ok;
    }
    if g.selection & KEYPAIR != 0 {
        ok = ok
            && match g.dhkem_ikm.as_deref() {
                // SAFETY: the key, with its group.
                Some(ikm) if !ikm.is_empty() => unsafe { generate_dhkem(h, ikm) },
                // SAFETY: as above.
                _ => (unsafe { EC_KEY_generate_key(h) }) != 0,
            };
    }
    if g.ecdh_mode != -1 {
        // SAFETY: the key.
        ok = ok && unsafe { set_ecdh_cofactor_mode(h, g.ecdh_mode) };
    }
    if let Some(c) = &g.group_check {
        // SAFETY: as above.
        ok = ok && unsafe { set_check_group_type_from_name(h, Some(c.to_bytes())) };
    }
    ok
}

ffi_callback! {
    /// `ec_gen`: a new key with the context's group (and a key pair, if selected), or NULL.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context.
    pub(crate) unsafe extern "C" fn ec_gen(genctx: *mut c_void, _cb: OSSL_CALLBACK, _cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return ptr::null_mut() };
        // SAFETY: the context's library context; no query.
        let h = unsafe { new_key(g.libctx, ptr::null()) };
        if h.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the key just made; the context's objects.
        if unsafe { gen_into(g, h, false) } {
            return h.cast();
        }
        // SAFETY: the key made above.
        unsafe { free(h) };
        ptr::null_mut()
    }
}

ffi_callback! {
    /// `ec_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn ec_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

/// `ec_gen_settable_params`' list.
static GEN_SETTABLE: Params<14> = Params([
    defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
    defn(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_EC_ENCODING, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_FIELD_TYPE, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_A, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_B, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_GENERATOR, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_EC_ORDER, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_SEED, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_DHKEM_IKM, OCTETS, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ec_gen_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ec_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

/// `ec_gen_gettable_params`' list: nothing outside the FIPS provider.
static GEN_GETTABLE: Params<1> = Params([PARAM_END]);

ffi_callback! {
    /// `ec_gen_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ec_gen_gettable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        GEN_GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `ec_gen_get_params`: nothing to report outside the FIPS provider; 1 for a context.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context.
    pub(crate) unsafe extern "C" fn ec_gen_get_params(genctx: *mut c_void, _params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        c_int::from(!genctx.is_null())
    }
}

/// `common_load`: the key the reference points to, if it's on SM2's curve exactly when `sm2`;
/// the reference is cleared, its key passing to the result.
///
/// # Safety
/// `reference` is NULL or points to `reference_sz` writable octets holding a live key's
/// pointer.
unsafe fn load(reference: *const c_void, reference_sz: usize, sm2: bool) -> *mut c_void {
    if reference.is_null() || reference_sz != size_of::<*mut EC_KEY>() {
        return ptr::null_mut();
    }
    let slot = reference.cast::<*mut EC_KEY>().cast_mut();
    // SAFETY: the caller's guarantee: a key's pointer.
    let h = unsafe { slot.read_unaligned() };
    // SAFETY: as above.
    if unsafe { ec(h.cast()) }.is_none() || !unsafe { check_sm2(h, sm2) } {
        return ptr::null_mut();
    }
    // SAFETY: as above: writable.
    unsafe { slot.write_unaligned(ptr::null_mut()) };
    h.cast()
}

ffi_callback! {
    /// `ec_load` (`common_load`): not on SM2's curve.
    ///
    /// # Safety
    /// As for `common_load`.
    pub(crate) unsafe extern "C" fn ec_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { load(reference, reference_sz, false) }
    }
}

ffi_callback! {
    /// `ec_dup` (`ossl_ec_key_dup`): a copy of the selected parts.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ec_dup(keydata: *const c_void, selection: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup(keydata.cast(), selection) }.cast()
    }
}

// ---------------------------------------------------------------------------------------------
// SM2 (`ossl_sm2_keymgmt_functions`): the EC key manager's functions for keys on SM2's curve,
// with SM3 as the default digest, no cofactor mode, and SM2's private-key range.

ffi_callback! {
    /// `sm2_query_operation_name`: SM2 keys sign with SM2.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sm2_query_operation_name(operation_id: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        match operation_id {
            OSSL_OP_SIGNATURE => c"SM2".as_ptr(),
            _ => ptr::null(),
        }
    }
}

ffi_callback! {
    /// `sm2_newdata`: a key on SM2's curve in the provider's library context.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn sm2_newdata(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let libctx = unsafe { libctx_of(provctx) };
        // SAFETY: the provider's library context; no query.
        unsafe { EC_KEY_new_by_curve_name_ex(libctx, ptr::null(), NID_sm2) }.cast()
    }
}

ffi_callback! {
    /// `sm2_import`: as `common_import`, only on SM2's curve.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { import(keydata, selection, params, true) }
    }
}

ffi_callback! {
    /// `sm2_get_params` (`common_get_params` for SM2).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { common_get_params(keydata, params, true) }
    }
}

/// `sm2_known_gettable_params`.
static SM2_GETTABLE: Params<23> = Params([
    defn(OSSL_PKEY_PARAM_BITS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_DEFAULT_DIGEST, UTF8, 0),
    defn(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OCTETS, 0),
    defn(
        OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
        INT,
        INT_SIZE,
    ),
    defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_ENCODING, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_FIELD_TYPE, UTF8, 0),
    defn(OSSL_PKEY_PARAM_EC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_A, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_B, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_GENERATOR, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_EC_ORDER, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_SEED, OCTETS, 0),
    defn(
        OSSL_PKEY_PARAM_EC_DECODED_FROM_EXPLICIT_PARAMS,
        INT,
        INT_SIZE,
    ),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_EC_PUB_X, BN, 0),
    defn(OSSL_PKEY_PARAM_EC_PUB_Y, BN, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `sm2_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sm2_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        SM2_GETTABLE.0.as_ptr()
    }
}

/// `sm2_known_settable_params`.
static SM2_SETTABLE: Params<2> = Params([
    defn(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OCTETS, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `sm2_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sm2_settable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        SM2_SETTABLE.0.as_ptr()
    }
}

/// `ossl_sm2_key_private_check`: the private key is in `[1, n-2]`.
///
/// # Safety
/// `f`'s objects are NULL or live.
unsafe fn sm2_private_check(f: &crate::ec::key::Fields) -> bool {
    const F: &str = "ossl_sm2_key_private_check";
    let order = if f.group.0.is_null() {
        None
    } else {
        // SAFETY: the key's group.
        let o = unsafe { EC_GROUP_get0_order(f.group.0) };
        // SAFETY: the group's number, or NULL.
        unsafe { crate::bn::value(o) }
    };
    // SAFETY: the key's number, or NULL.
    let d = unsafe { crate::bn::value(f.priv_key.0) };
    let (Some(order), Some(d)) = (order, d) else {
        err::raise(ERR_LIB_SM2, ERR_R_PASSED_NULL_PARAMETER, F);
        return false;
    };
    let mut max = order;
    if max.sub_word(1).is_err() {
        return false;
    }
    let one = rustyssl_crypto::bn::BigNum::one();
    if rustyssl_crypto::bn::cmp(&d, &one).is_lt() || rustyssl_crypto::bn::cmp(&d, &max).is_ge() {
        err::raise(ERR_LIB_SM2, SM2_R_INVALID_PRIVATE_KEY, F);
        return false;
    }
    true
}

ffi_callback! {
    /// `sm2_validate`: the group, the public key (quickly or fully), SM2's private-key range,
    /// and the pair together.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn sm2_validate(keydata: *const c_void, selection: c_int, checktype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ec(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 1;
        }
        let f = k.get();
        // SAFETY: the key's library context.
        let ctx = unsafe { BN_CTX_new_ex(f.libctx.0) };
        if ctx.is_null() {
            return 0;
        }
        let mut ok = true;
        if selection & DOMAIN != 0 {
            // SAFETY: the key's group, or NULL; the context.
            ok = (unsafe { EC_GROUP_check(f.group.0, ctx) }) != 0;
        }
        if selection & PUBLIC != 0 {
            ok = ok
                && if checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK {
                    // SAFETY: the key's objects, or NULL; the context.
                    unsafe { public_check_quick(&f, ctx) }
                } else {
                    // SAFETY: as above.
                    unsafe { public_check(&f, ctx) }
                };
        }
        if selection & PRIVATE != 0 {
            // SAFETY: as above.
            ok = ok && unsafe { sm2_private_check(&f) };
        }
        if selection & KEYPAIR == KEYPAIR {
            // SAFETY: as above.
            ok = ok && unsafe { pairwise_check(&f, ctx) };
        }
        // SAFETY: the context made above.
        unsafe { BN_CTX_free(ctx) };
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `sm2_gen_init`: as `ec_gen_init`, on SM2's curve unless a group is named.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let g = unsafe { ec_gen_init(provctx, selection, params) };
        // SAFETY: the context just made, or NULL.
        if let Some(c) = unsafe { gen_ctx(g) }
            && c.group_name.is_none()
        {
            c.group_name = Some(c"sm2".to_owned());
        }
        g
    }
}

ffi_callback! {
    /// `sm2_gen`: a new key with the context's group (and a key pair, if selected), or NULL.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context.
    pub(crate) unsafe extern "C" fn sm2_gen(genctx: *mut c_void, _cb: OSSL_CALLBACK, _cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return ptr::null_mut() };
        // SAFETY: the context's library context; no query.
        let h = unsafe { new_key(g.libctx, ptr::null()) };
        if h.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the key just made; the context's objects.
        if unsafe { gen_into(g, h, true) } {
            return h.cast();
        }
        // SAFETY: the key made above.
        unsafe { free(h) };
        ptr::null_mut()
    }
}

ffi_callback! {
    /// `sm2_load` (`common_load`): only on SM2's curve.
    ///
    /// # Safety
    /// As for `common_load`.
    pub(crate) unsafe extern "C" fn sm2_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { load(reference, reference_sz, true) }
    }
}

type NewFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type HasFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;
type MatchFn = unsafe extern "C" fn(*const c_void, *const c_void, c_int) -> c_int;
type ImportFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> c_int;
type TypesFn = unsafe extern "C" fn(c_int) -> *const OSSL_PARAM;
type ExportFn = unsafe extern "C" fn(*mut c_void, c_int, OSSL_CALLBACK, *mut c_void) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type DupFn = unsafe extern "C" fn(*const c_void, c_int) -> *mut c_void;
type QueryFn = unsafe extern "C" fn(c_int) -> *const c_char;
type GenInitFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type GenTemplateFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type GenListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type GenFn = unsafe extern "C" fn(*mut c_void, OSSL_CALLBACK, *mut c_void) -> *mut c_void;
type LoadFn = unsafe extern "C" fn(*const c_void, usize) -> *mut c_void;
type ValidateFn = unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int;

/// `ossl_ec_keymgmt_functions`.
pub(crate) static EC_KEYMGMT: Dispatch<25> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, ec_newdata, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, ec_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        ec_gen_set_template,
        GenTemplateFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        ec_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        ec_gen_settable_params,
        GenListFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS,
        ec_gen_get_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS,
        ec_gen_gettable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, ec_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, ec_gen_cleanup, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_LOAD, ec_load, LoadFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, ec_freedata, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, ec_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        ec_gettable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, ec_set_params, SetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        ec_settable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, ec_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, ec_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_VALIDATE, ec_validate, ValidateFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, ec_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, ec_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, ec_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, ec_imexport_types, TypesFn),
    entry!(
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        ec_query_operation_name,
        QueryFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_DUP, ec_dup, DupFn),
    END,
]);

/// `ossl_sm2_keymgmt_functions`.
pub(crate) static SM2_KEYMGMT: Dispatch<23> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, sm2_newdata, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, sm2_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        ec_gen_set_template,
        GenTemplateFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        ec_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        ec_gen_settable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, sm2_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, ec_gen_cleanup, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_LOAD, sm2_load, LoadFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, ec_freedata, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, sm2_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        sm2_gettable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, ec_set_params, SetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        sm2_settable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, ec_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, ec_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_VALIDATE, sm2_validate, ValidateFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, sm2_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, ec_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, ec_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, ec_imexport_types, TypesFn),
    entry!(
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        sm2_query_operation_name,
        QueryFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_DUP, ec_dup, DupFn),
    END,
]);

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL's `strdup`s a generation parameter's string, reading on
    /// past its size to a NUL, and crashes on NULL data.
    #[test]
    fn strings_are_read_within_their_size() {
        let mut name = *b"P-256X";
        let mut params = [
            OSSL_PARAM {
                key: OSSL_PKEY_PARAM_GROUP_NAME.as_ptr(),
                data_type: UTF8_TYPE,
                data: name.as_mut_ptr().cast(),
                data_size: 5,
                return_size: 0,
            },
            PARAM_END,
        ];
        let mut got = None;
        // SAFETY: an array of one parameter.
        let r = unsafe { copy_utf8(params.as_ptr(), OSSL_PKEY_PARAM_GROUP_NAME, &mut got) };
        assert!(r.is_ok());
        assert_eq!(got.as_deref(), Some(c"P-256"));
        if let Some(p) = params.first_mut() {
            p.data = ptr::null_mut();
        }
        // SAFETY: as above.
        let r = unsafe { copy_utf8(params.as_ptr(), OSSL_PKEY_PARAM_GROUP_NAME, &mut got) };
        assert!(r.is_err());
        assert!(got.is_none());
    }
}
