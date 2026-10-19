//! The default provider's DH and DHX key managers (`dh_kmgmt.c`, with `crate::dh_backend`):
//! keys are `DH` objects (`crate::dh`), PKCS #3 DH or X9.42 DHX by their type flag, made empty,
//! filled from parameters, described, given an encoded public key, exported, compared, copied
//! by selection, validated, loaded from a reference, and generated: parameters from a named
//! group (by name, or by size), as a safe prime with a generator, or by FIPS 186-4 or 186-2
//! (with their seed, index, counter, and digest), and keys from those or a template's.
//!
//! As in OpenSSL, both key managers take DH's generation parameters at `gen_init`, so DHX's
//! own (the index, seed, and so on) are refused there and only taken by `gen_set_params`; a
//! group name makes generation use that group whatever its type; and DHX keys run DH's
//! operations.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    BN_GENCB, DH, DH_GENERATOR_2, DH_PARAMGEN_TYPE_FIPS_186_2, DH_PARAMGEN_TYPE_GENERATOR,
    DH_PARAMGEN_TYPE_GROUP, ERR_LIB_DH, ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT,
    ERR_R_UNSUPPORTED, OSSL_CALLBACK, OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT,
    OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN,
    OSSL_FUNC_KEYMGMT_GEN_CLEANUP, OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
    OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_VALIDATE,
    OSSL_GEN_PARAM_ITERATION, OSSL_GEN_PARAM_POTENTIAL, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
    OSSL_KEYMGMT_VALIDATE_QUICK_CHECK, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_BITS,
    OSSL_PKEY_PARAM_DH_GENERATOR, OSSL_PKEY_PARAM_DH_PRIV_LEN, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
    OSSL_PKEY_PARAM_FFC_COFACTOR, OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
    OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_H,
    OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PKEY_PARAM_FFC_PCOUNTER,
    OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_FFC_QBITS, OSSL_PKEY_PARAM_FFC_SEED,
    OSSL_PKEY_PARAM_FFC_TYPE, OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_MAX_SIZE,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
    OSSL_PKEY_PARAM_SECURITY_CATEGORY,
};
use rustyssl_crypto::ffc as groups;

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::bn::prime::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set};
use crate::dh::{DH_bits, DH_get0_pub_key, DH_security_bits, DH_size, Dh, dh};
use crate::dh_backend::{
    self as backend, check_pairwise, check_priv_key, check_pub_key_partial, dup, enable_flags,
    is_named_safe_prime_group, key_fromdata, key_todata, params_fromdata, params_todata,
};
use crate::dh_meth::DH_generate_key;
use crate::dh_ops::{
    DH_check_ex, DH_check_params_ex, DH_check_pub_key_ex, DH_generate_parameters_ex,
};
use crate::ec::params::{Kept, Target, text};
use crate::err;
use crate::ffc;
use crate::ffi::ffi_callback;
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_get_int, OSSL_PARAM_get_size_t, OSSL_PARAM_locate,
    OSSL_PARAM_set_int, end,
};

const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
const DOMAIN: c_int = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
/// `DH_POSSIBLE_SELECTIONS`.
const POSSIBLE: c_int = KEYPAIR | DOMAIN;

/// The parameter types, as `defn` takes them.
const INT: c_int = OSSL_PARAM_INTEGER;
const BN: c_int = OSSL_PARAM_UNSIGNED_INTEGER;
const UTF8: c_int = OSSL_PARAM_UTF8_STRING;
const OCTETS: c_int = OSSL_PARAM_OCTET_STRING;
const INT_SIZE: usize = size_of::<c_int>();
const SIZE_T_SIZE: usize = size_of::<usize>();

/// The key behind key data.
///
/// # Safety
/// `keydata` is NULL or a live `DH`.
unsafe fn key<'a>(keydata: *const c_void) -> Option<&'a Dh> {
    // SAFETY: the caller's guarantee.
    unsafe { dh(keydata.cast()) }
}

/// A new empty key of the provider's library context, typed DH or DHX.
///
/// # Safety
/// `provctx` is the default provider's context.
unsafe fn newdata(provctx: *mut c_void, dhx: bool) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let h = Dh::new_handle_in(unsafe { libctx_of(provctx) });
    // SAFETY: just made, or NULL.
    if let Some(k) = unsafe { dh(h) } {
        k.set_type(dhx);
    }
    h.cast()
}

ffi_callback! {
    /// `dh_newdata`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn dh_newdata(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { newdata(provctx, false) }
    }
}

ffi_callback! {
    /// `dhx_newdata`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn dhx_newdata(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { newdata(provctx, true) }
    }
}

ffi_callback! {
    /// `dh_freedata` (`DH_free`).
    ///
    /// # Safety
    /// `keydata` is NULL or key data whose reference the caller gives up.
    pub(crate) unsafe extern "C" fn dh_freedata(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { crate::dh::free(keydata.cast()) };
    }
}

ffi_callback! {
    /// `dh_has`: the public key, private key, and p and g, as selected.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn dh_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 1;
        }
        let st = k.snapshot();
        let mut ok = true;
        if selection & PUBLIC != 0 {
            ok &= st.pub_key.is_some();
        }
        if selection & PRIVATE != 0 {
            ok &= st.priv_key.is_some();
        }
        if selection & DOMAIN != 0 {
            ok &= st.params.p.is_some() && st.params.g.is_some();
        }
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `dh_match`: the public keys (or, without them, the private keys) for key pair
    /// selections, and p and g for the parameters.
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are live key data.
    pub(crate) unsafe extern "C" fn dh_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let (Some(a), Some(b)) = (unsafe { key(keydata1) }, unsafe { key(keydata2) }) else { return 0 };
        let (sa, sb) = (a.snapshot(), b.snapshot());
        let eq = |x: &rustyssl_crypto::bn::BigNum, y| rustyssl_crypto::bn::cmp(x, y).is_eq();
        let mut ok = true;
        if selection & KEYPAIR != 0 {
            let mut checked = false;
            if selection & PUBLIC != 0
                && let (Some(x), Some(y)) = (&sa.pub_key, &sb.pub_key)
            {
                ok &= eq(x, y);
                checked = true;
            }
            if !checked
                && selection & PRIVATE != 0
                && let (Some(x), Some(y)) = (&sa.priv_key, &sb.priv_key)
            {
                ok &= eq(x, y);
                checked = true;
            }
            ok &= checked;
        }
        if selection & DOMAIN != 0 {
            ok &= sa.params.cmp(&sb.params, true);
        }
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `dh_import`: the parameters (always), then the key pair as selected.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dh_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 0;
        }
        let mut st = k.snapshot();
        // SAFETY: the caller's guarantee.
        let ok = unsafe { params_fromdata(&mut st, params) }
            && (selection & KEYPAIR == 0
                // SAFETY: as above.
                || unsafe { key_fromdata(&mut st, params, selection & PRIVATE != 0) });
        if ok {
            k.replace(st);
        }
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `dh_export`: the parameters and key pair, as selected, to `param_cb` (called once).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` takes `cbarg`.
    pub(crate) unsafe extern "C" fn dh_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 0;
        }
        let st = k.snapshot();
        // SAFETY: no preconditions.
        let bld = unsafe { OSSL_PARAM_BLD_new() };
        if bld.is_null() {
            return 0;
        }
        let target = Target::Builder(bld);
        let mut kept = Kept::default();
        // SAFETY: the builder; `st` and `kept` outlive the array's making.
        let mut ok = selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS == 0
            || unsafe { params_todata(&st, target, &mut kept) };
        if ok && selection & KEYPAIR != 0 {
            // SAFETY: as above.
            ok = unsafe { key_todata(&st, target, &mut kept, selection & PRIVATE != 0) };
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
        ret
    }
}

/// `dh_all_types`: the parameters (`DH_IMEXPORTABLE_PARAMETERS`), then the public and
/// private keys; the other lists are slices of it.
static ALL_TYPES: Params<13> = Params([
    defn(OSSL_PKEY_PARAM_FFC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_Q, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_G, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_GINDEX, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_PCOUNTER, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_H, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_DH_PRIV_LEN, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_SEED, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, BN, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0),
    PARAM_END,
]);

/// `dh_parameter_types`.
static PARAMETER_TYPES: Params<11> = Params([
    defn(OSSL_PKEY_PARAM_FFC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_Q, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_G, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_GINDEX, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_PCOUNTER, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_H, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_DH_PRIV_LEN, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_SEED, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
    PARAM_END,
]);

/// `dh_key_types`.
static KEY_TYPES: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PUB_KEY, BN, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `dh_import_types` and `dh_export_types` (`dh_imexport_types`): the parameters for any
    /// parameter selection, the keys for a key pair selection.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dh_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        let params = selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS != 0;
        let keys = selection & KEYPAIR != 0;
        match (params, keys) {
            (false, false) => ptr::null(),
            (true, false) => PARAMETER_TYPES.0.as_ptr(),
            (false, true) => KEY_TYPES.0.as_ptr(),
            (true, true) => ALL_TYPES.0.as_ptr(),
        }
    }
}

/// Sets `params`' parameter `name` to `v` if it's there; false if it can't be.
///
/// # Safety
/// `params` is NULL or a live array.
unsafe fn set_int(params: *mut OSSL_PARAM, name: &CStr, v: c_int) -> bool {
    // SAFETY: the caller's guarantee; a static name.
    let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
    // SAFETY: a parameter of the array.
    p.is_null() || unsafe { OSSL_PARAM_set_int(p, v) } != 0
}

ffi_callback! {
    /// `dh_get_params`: the bits, strength, and size, the encoded public key (padded to the
    /// prime's length), then the parameters and key pair.
    ///
    /// # Safety
    /// `keydata` is a live key; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dh_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        let h = keydata.cast::<DH>();
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        // SAFETY: the caller's key (for each below).
        let ints = [
            (OSSL_PKEY_PARAM_BITS, unsafe { DH_bits(h) }),
            (OSSL_PKEY_PARAM_SECURITY_BITS, unsafe { DH_security_bits(h) }),
            (OSSL_PKEY_PARAM_MAX_SIZE, unsafe { DH_size(h) }),
        ];
        for (name, v) in ints {
            // SAFETY: the caller's array.
            if !unsafe { set_int(params, name, v) } {
                return 0;
            }
        }
        let st = k.snapshot();
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr()) };
        // SAFETY: NULL or a parameter of the array.
        if let Some(prm) = unsafe { p.as_mut() } {
            if prm.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
                return 0;
            }
            let out = if prm.data.is_null() {
                None
            } else {
                // SAFETY: the parameter's buffer of its size.
                Some(unsafe { core::slice::from_raw_parts_mut(prm.data.cast::<u8>(), prm.data_size) })
            };
            prm.return_size = backend::key2buf(&st, out);
            if prm.return_size == 0 {
                return 0;
            }
        }
        // 3.6: classical keys are in no NIST post-quantum category (after the encoded key).
        // SAFETY: the caller's array.
        if !unsafe { set_int(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY, 0) } {
            return 0;
        }
        let target = Target::Params(params);
        let mut kept = Kept::default();
        // SAFETY: the caller's array; `st` and `kept` live through the call.
        c_int::from(unsafe { params_todata(&st, target, &mut kept) }
            // SAFETY: as above.
            && unsafe { key_todata(&st, target, &mut kept, true) })
    }
}

/// `dh_params`: what `dh_get_params` reports.
static GETTABLE: Params<18> = Params([
    defn(OSSL_PKEY_PARAM_BITS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_CATEGORY, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_FFC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_Q, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_G, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_GINDEX, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_PCOUNTER, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_H, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_DH_PRIV_LEN, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_SEED, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, BN, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `dh_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dh_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        GETTABLE.0.as_ptr()
    }
}

/// `dh_known_settable_params`.
static SETTABLE: Params<2> = Params([
    defn(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OCTETS, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `dh_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dh_settable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `dh_set_params`: the public key from its encoding (an octet string), if it passes the
    /// partial check.
    ///
    /// # Safety
    /// `keydata` is a live key; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dh_set_params(keydata: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        // SAFETY: the caller's array.
        let Some(p) = (unsafe { locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) }) else {
            return 1;
        };
        if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
            return 0;
        }
        let buf = if p.data.is_null() {
            &[][..]
        } else {
            // SAFETY: the parameter's data of its size.
            unsafe { core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) }
        };
        c_int::from(backend::buf2key(k, buf))
    }
}

ffi_callback! {
    /// `dh_validate`: the parameters (lightly for a quick check), the public key (partially
    /// for a safe-prime group), the private key's range, and the pair.
    ///
    /// # Safety
    /// `keydata` is a live key.
    pub(crate) unsafe extern "C" fn dh_validate(keydata: *const c_void, selection: c_int, checktype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        let h = keydata.cast::<DH>().cast_mut();
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 1;
        }
        let mut ok = true;
        if selection & DOMAIN != 0 {
            ok = if checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK {
                // SAFETY: the caller's key.
                (unsafe { DH_check_params_ex(h) }) != 0
            } else {
                // SAFETY: as above.
                (unsafe { DH_check_ex(h) }) != 0
            };
        }
        if ok && selection & PUBLIC != 0 {
            let st = k.snapshot();
            ok = match &st.pub_key {
                None => false,
                Some(y) if is_named_safe_prime_group(&st) => check_pub_key_partial(&st, y),
                Some(_) => {
                    // SAFETY: the caller's key.
                    let y = unsafe { DH_get0_pub_key(h) };
                    // SAFETY: the key and its own public key.
                    (unsafe { DH_check_pub_key_ex(h, y) }) != 0
                }
            };
        }
        if ok && selection & PRIVATE != 0 {
            let st = k.snapshot();
            ok = st.priv_key.as_ref().is_some_and(|x| check_priv_key(&st, x));
        }
        if ok && selection & KEYPAIR == KEYPAIR {
            // SAFETY: the caller's key.
            ok = unsafe { check_pairwise(h, false) };
        }
        c_int::from(ok)
    }
}

/// `struct dh_gen_ctx`: what generation is asked for.
struct GenCtx {
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    /// The template's parameters (a copy, taken when it's set).
    ffc_params: Option<ffc::Params>,
    selection: c_int,
    group_nid: c_int,
    pbits: usize,
    qbits: usize,
    seed: Option<Vec<u8>>,
    gindex: c_int,
    gen_type: c_int,
    generator: c_int,
    pcounter: c_int,
    hindex: c_int,
    priv_len: c_int,
    mdname: Option<CString>,
    mdprops: Option<CString>,
    cb: OSSL_CALLBACK,
    cbarg: *mut c_void,
    dhx: bool,
}

/// The generation context behind `genctx`.
///
/// # Safety
/// `genctx` is NULL or a live context from `gen_init`.
unsafe fn gen_ctx<'a>(genctx: *mut c_void) -> Option<&'a mut GenCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<GenCtx>(genctx) }
}

/// `dh_gen_init_base`: a context with OpenSSL's defaults (2048 and 224 bits; safe primes with
/// generator 2 for DH, FIPS 186-2 for DHX) and then DH's generation parameters from `params`.
///
/// # Safety
/// `provctx` is the default provider's context; `params` is NULL or an array.
unsafe fn gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OSSL_PARAM,
    dhx: bool,
) -> *mut c_void {
    if selection & POSSIBLE == 0 {
        return ptr::null_mut();
    }
    let g = boxed(GenCtx {
        // SAFETY: the caller's guarantee.
        libctx: unsafe { libctx_of(provctx) },
        ffc_params: None,
        selection,
        group_nid: 0,
        pbits: 2048,
        qbits: 224,
        seed: None,
        gindex: -1,
        gen_type: if dhx {
            DH_PARAMGEN_TYPE_FIPS_186_2
        } else {
            DH_PARAMGEN_TYPE_GENERATOR
        },
        generator: DH_GENERATOR_2,
        pcounter: -1,
        hindex: 0,
        priv_len: 0,
        mdname: None,
        mdprops: None,
        cb: None,
        cbarg: ptr::null_mut(),
        dhx,
    });
    // SAFETY: the context just made; the caller's array.
    if unsafe { dh_gen_set_params(g, params) } != 1 {
        // SAFETY: the context just made, freed once.
        unsafe { unbox::<GenCtx>(g) };
        return ptr::null_mut();
    }
    g
}

ffi_callback! {
    /// `dh_gen_init`.
    ///
    /// # Safety
    /// As for `gen_init`.
    pub(crate) unsafe extern "C" fn dh_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { gen_init(provctx, selection, params, false) }
    }
}

ffi_callback! {
    /// `dhx_gen_init`.
    ///
    /// # Safety
    /// As for `gen_init`.
    pub(crate) unsafe extern "C" fn dhx_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { gen_init(provctx, selection, params, true) }
    }
}

ffi_callback! {
    /// `dh_gen_set_template`: generation takes the template key's parameters.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `templ` is NULL or a live key.
    pub(crate) unsafe extern "C" fn dh_gen_set_template(genctx: *mut c_void, templ: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let (Some(g), Some(t)) = (unsafe { gen_ctx(genctx) }, unsafe { key(templ) }) else { return 0 };
        g.ffc_params = Some(t.snapshot().params);
        1
    }
}

/// Raises `reason` in the provider's library.
fn invalid(reason: c_int) -> c_int {
    err::raise(ERR_LIB_PROV, reason, "dh_gen_set_params");
    0
}

/// An int parameter into `slot`; false if it isn't one.
///
/// # Safety
/// `p` is a live parameter.
unsafe fn read_int(p: &OSSL_PARAM, slot: &mut c_int) -> bool {
    // SAFETY: the caller's guarantee; the slot.
    (unsafe { OSSL_PARAM_get_int(p, slot) }) == 1
}

/// A `size_t` parameter into `slot`; false if it isn't one.
///
/// # Safety
/// `p` is a live parameter.
unsafe fn read_size(p: &OSSL_PARAM, slot: &mut usize) -> bool {
    // SAFETY: the caller's guarantee; the slot.
    (unsafe { OSSL_PARAM_get_size_t(p, slot) }) == 1
}

/// `dh_gen_common_set_params`: the generation type (by name, or "default"), group name, prime
/// size, and private key length, each committed as it's read.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn common_set_params(g: &mut GenCtx, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee (for each lookup below).
    let find = |name: &CStr| unsafe { locate(params, name) };
    if let Some(p) = find(OSSL_PKEY_PARAM_FFC_TYPE) {
        // SAFETY: a parameter of the array.
        let name = unsafe { text(p) }.flatten();
        let id = match name {
            Some(b"default") if g.dhx => Some(DH_PARAMGEN_TYPE_FIPS_186_2),
            Some(b"default") => Some(DH_PARAMGEN_TYPE_GENERATOR),
            Some(n) => backend::gen_type_name2id(n, g.dhx),
            None => None,
        };
        let Some(id) = id else {
            invalid(ERR_R_PASSED_INVALID_ARGUMENT);
            return false;
        };
        g.gen_type = id;
    }
    if let Some(p) = find(OSSL_PKEY_PARAM_GROUP_NAME) {
        // SAFETY: a parameter of the array.
        let name = unsafe { text(p) }.flatten();
        let uid = name
            .and_then(|n| core::str::from_utf8(n).ok())
            .and_then(groups::by_name)
            .map_or(0, |gr| gr.uid);
        if uid == 0 {
            invalid(ERR_R_PASSED_INVALID_ARGUMENT);
            return false;
        }
        g.group_nid = uid;
    }
    if let Some(p) = find(OSSL_PKEY_PARAM_FFC_PBITS)
        // SAFETY: a parameter of the array.
        && !unsafe { read_size(p, &mut g.pbits) }
    {
        return false;
    }
    if let Some(p) = find(OSSL_PKEY_PARAM_DH_PRIV_LEN)
        // SAFETY: as above.
        && !unsafe { read_int(p, &mut g.priv_len) }
    {
        return false;
    }
    true
}

ffi_callback! {
    /// `dh_gen_set_params`: the common parameters and the generator; the FIPS 186 ones are
    /// refused (`ERR_R_PASSED_INVALID_ARGUMENT`).
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dh_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        if !unsafe { common_set_params(g, params) } {
            return 0;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_DH_GENERATOR) }
            // SAFETY: a parameter of the array.
            && !unsafe { read_int(p, &mut g.generator) }
        {
            return 0;
        }
        let refused = [
            OSSL_PKEY_PARAM_FFC_GINDEX,
            OSSL_PKEY_PARAM_FFC_PCOUNTER,
            OSSL_PKEY_PARAM_FFC_H,
            OSSL_PKEY_PARAM_FFC_SEED,
            OSSL_PKEY_PARAM_FFC_QBITS,
            OSSL_PKEY_PARAM_FFC_DIGEST,
            OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
        ];
        // SAFETY: as above.
        if refused.iter().any(|name| unsafe { locate(params, name) }.is_some()) {
            return invalid(ERR_R_PASSED_INVALID_ARGUMENT);
        }
        1
    }
}

ffi_callback! {
    /// `dhx_gen_set_params`: the common parameters and the FIPS 186 ones (index, counter, h,
    /// seed, q's size, digest); the generator is refused (`ERR_R_UNSUPPORTED`).
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dhx_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        if !unsafe { common_set_params(g, params) } {
            return 0;
        }
        // SAFETY: as above (for each lookup below).
        let find = |name: &CStr| unsafe { locate(params, name) };
        let ints = [
            (OSSL_PKEY_PARAM_FFC_GINDEX, &mut g.gindex),
            (OSSL_PKEY_PARAM_FFC_PCOUNTER, &mut g.pcounter),
            (OSSL_PKEY_PARAM_FFC_H, &mut g.hindex),
        ];
        for (name, slot) in ints {
            // SAFETY: a parameter of the array.
            if let Some(p) = find(name) && !unsafe { read_int(p, slot) } {
                return 0;
            }
        }
        if let Some(p) = find(OSSL_PKEY_PARAM_FFC_SEED) {
            if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
                return 0;
            }
            g.seed = (!p.data.is_null() && p.data_size > 0).then(|| {
                // SAFETY: the parameter's data of its size.
                unsafe { core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) }.to_vec()
            });
        }
        // SAFETY: as above.
        if let Some(p) = find(OSSL_PKEY_PARAM_FFC_QBITS) && !unsafe { read_size(p, &mut g.qbits) } {
            return 0;
        }
        for (name, slot) in [
            (OSSL_PKEY_PARAM_FFC_DIGEST, &mut g.mdname),
            (OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, &mut g.mdprops),
        ] {
            if let Some(p) = find(name) {
                if p.data_type != OSSL_PARAM_UTF8_STRING.cast_unsigned() {
                    return 0;
                }
                // SAFETY: a parameter of the array.
                let Some(v) = (unsafe { backend::utf8(p) }) else { return 0 };
                *slot = Some(v);
            }
        }
        if find(OSSL_PKEY_PARAM_DH_GENERATOR).is_some() {
            return invalid(ERR_R_UNSUPPORTED);
        }
        1
    }
}

/// `dh_gen_settable`.
static GEN_SETTABLE: Params<6> = Params([
    defn(OSSL_PKEY_PARAM_FFC_TYPE, UTF8, 0),
    defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
    defn(OSSL_PKEY_PARAM_DH_PRIV_LEN, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_PBITS, BN, SIZE_T_SIZE),
    defn(OSSL_PKEY_PARAM_DH_GENERATOR, INT, INT_SIZE),
    PARAM_END,
]);

ffi_callback! {
    /// `dh_gen_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dh_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

/// `dhx_gen_settable`.
static DHX_GEN_SETTABLE: Params<12> = Params([
    defn(OSSL_PKEY_PARAM_FFC_TYPE, UTF8, 0),
    defn(OSSL_PKEY_PARAM_GROUP_NAME, UTF8, 0),
    defn(OSSL_PKEY_PARAM_DH_PRIV_LEN, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_PBITS, BN, SIZE_T_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_QBITS, BN, SIZE_T_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_DIGEST, UTF8, 0),
    defn(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, UTF8, 0),
    defn(OSSL_PKEY_PARAM_FFC_GINDEX, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_SEED, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_FFC_PCOUNTER, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_H, INT, INT_SIZE),
    PARAM_END,
]);

ffi_callback! {
    /// `dhx_gen_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dhx_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        DHX_GEN_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `dh_gencb`: reports a generation step to the application's callback.
    ///
    /// # Safety
    /// `cb` is a live `BN_GENCB` whose argument is a live generation context.
    pub(crate) unsafe extern "C" fn dh_gencb(p: c_int, n: c_int, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let arg = unsafe { BN_GENCB_get_arg(cb) };
        // SAFETY: as above.
        let Some(g) = (unsafe { gen_ctx(arg) }) else { return 0 };
        let (f, cbarg) = (g.cb, g.cbarg);
        let (mut p, mut n) = (p, n);
        let params = [
            // SAFETY: locals that outlive the call.
            unsafe { OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL.as_ptr(), &raw mut p) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION.as_ptr(), &raw mut n) },
            end(),
        ];
        match f {
            // SAFETY: the application's callback and argument; no lock is held.
            Some(f) => unsafe { f(params.as_ptr(), cbarg) },
            // EVP always passes a callback; going on is all one can do without.
            None => 1,
        }
    }
}

/// A `size_t` as the C's `int` conversion: its low 32 bits.
fn c_int_cast(v: usize) -> c_int {
    let low = u32::try_from(v & 0xffff_ffff).unwrap_or(0);
    c_int::from_ne_bytes(low.to_ne_bytes())
}

/// What `dh_gen` generates, read from the context before anything calls back into it.
struct Plan {
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    template: Option<ffc::Params>,
    selection: c_int,
    group_nid: c_int,
    pbits: usize,
    qbits: usize,
    seed: Option<Vec<u8>>,
    gindex: c_int,
    gen_type: c_int,
    generator: c_int,
    pcounter: c_int,
    hindex: c_int,
    priv_len: c_int,
    mdname: Option<CString>,
    mdprops: Option<CString>,
    dhx: bool,
}

/// `dh_gen`'s work after the plan is read: the new key, or NULL (freed on failure).
///
/// # Safety
/// `genctx` is a live generation context (the callback's argument).
unsafe fn generate(plan: Plan, genctx: *mut c_void) -> *mut DH {
    let mut gen_type = plan.gen_type;
    // A group name means that group, whatever type was asked for.
    if plan.group_nid != 0 {
        gen_type = DH_PARAMGEN_TYPE_GROUP;
    }
    let mut gencb = ptr::null_mut();
    let h = if gen_type == DH_PARAMGEN_TYPE_GROUP && plan.template.is_none() {
        let nid = if plan.group_nid != 0 {
            plan.group_nid
        } else {
            backend::named_group_uid_from_size(plan.pbits)
        };
        if nid == 0 {
            return ptr::null_mut();
        }
        let h = crate::dh::new_by_nid_ex(plan.libctx, nid);
        if h.is_null() {
            return ptr::null_mut();
        }
        h
    } else {
        let h = Dh::new_handle_in(plan.libctx);
        // SAFETY: just made, or NULL.
        let Some(k) = (unsafe { dh(h) }) else {
            return ptr::null_mut();
        };
        let mut st = k.snapshot();
        if let Some(t) = plan.template {
            st.params = t;
        }
        st.params.seed = plan.seed;
        if plan.gindex != -1 {
            st.params.gindex = plan.gindex;
            if plan.pcounter != -1 {
                st.params.pcounter = plan.pcounter;
            }
        } else if plan.hindex != 0 {
            st.params.h = plan.hindex;
        }
        if plan.mdname.is_some() {
            st.params.mdname = plan.mdname;
            st.params.mdprops = plan.mdprops;
        }
        k.replace(st);
        // SAFETY: no preconditions.
        gencb = unsafe { BN_GENCB_new() };
        if !gencb.is_null() {
            // SAFETY: the holder just made; the callback reads the context, live for the call.
            unsafe { BN_GENCB_set(gencb, Some(dh_gencb), genctx) };
        }
        if plan.selection & DOMAIN != 0 {
            let ret = if gen_type == DH_PARAMGEN_TYPE_GENERATOR {
                // SAFETY: the key; the holder, or NULL.
                unsafe {
                    DH_generate_parameters_ex(h, c_int_cast(plan.pbits), plan.generator, gencb)
                }
            } else {
                let (pbits, qbits) = (c_int_cast(plan.pbits), c_int_cast(plan.qbits));
                match (usize::try_from(pbits), usize::try_from(qbits)) {
                    // SAFETY: as above.
                    (Ok(l), Ok(n)) => unsafe {
                        backend::generate_ffc_parameters(h, gen_type, l, n, gencb)
                    },
                    _ => 0,
                }
            };
            if ret <= 0 {
                // SAFETY: the holder made above, or NULL; the key made above.
                unsafe { BN_GENCB_free(gencb) };
                // SAFETY: as above.
                unsafe { crate::dh::free(h) };
                return ptr::null_mut();
            }
        }
        h
    };
    // SAFETY: the holder made above, or NULL.
    unsafe { BN_GENCB_free(gencb) };
    // SAFETY: the key made above.
    let Some(k) = (unsafe { dh(h) }) else {
        return ptr::null_mut();
    };
    if plan.selection & KEYPAIR != 0 {
        let mut st = k.snapshot();
        let ok = st.params.p.is_some() && st.params.g.is_some();
        if ok {
            if plan.priv_len > 0 {
                st.length = plan.priv_len;
            }
            enable_flags(
                &mut st.params,
                ffc::VALIDATE_LEGACY,
                gen_type == DH_PARAMGEN_TYPE_FIPS_186_2,
            );
            k.replace(st);
        }
        // SAFETY: the key, with no lock held.
        if !ok || unsafe { DH_generate_key(h) } <= 0 {
            // SAFETY: the key made above.
            unsafe { crate::dh::free(h) };
            return ptr::null_mut();
        }
    }
    k.set_type(plan.dhx);
    h
}

ffi_callback! {
    /// `dh_gen`: parameters (a named group's, or generated) and, if selected, a key pair. The
    /// key, or NULL.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `osslcb` takes `cbarg`.
    pub(crate) unsafe extern "C" fn dh_gen(genctx: *mut c_void, osslcb: OSSL_CALLBACK, cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        let plan = {
            // SAFETY: the caller's guarantee.
            let Some(g) = (unsafe { gen_ctx(genctx) }) else { return ptr::null_mut() };
            g.cb = osslcb;
            g.cbarg = cbarg;
            Plan {
                libctx: g.libctx,
                template: g.ffc_params.clone(),
                selection: g.selection,
                group_nid: g.group_nid,
                pbits: g.pbits,
                qbits: g.qbits,
                seed: g.seed.clone(),
                gindex: g.gindex,
                gen_type: g.gen_type,
                generator: g.generator,
                pcounter: g.pcounter,
                hindex: g.hindex,
                priv_len: g.priv_len,
                mdname: g.mdname.clone(),
                mdprops: g.mdprops.clone(),
                dhx: g.dhx,
            }
        };
        // SAFETY: the caller's context, no longer borrowed here.
        unsafe { generate(plan, genctx) }.cast()
    }
}

ffi_callback! {
    /// `dh_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn dh_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

ffi_callback! {
    /// `dh_load`: the key the reference points to; the reference is cleared, its key passing
    /// to the result.
    ///
    /// # Safety
    /// `reference` is NULL or points to `reference_sz` writable octets holding a live key's
    /// pointer.
    pub(crate) unsafe extern "C" fn dh_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        if reference.is_null() || reference_sz != size_of::<*mut DH>() {
            return ptr::null_mut();
        }
        let slot = reference.cast::<*mut DH>().cast_mut();
        // SAFETY: the caller's guarantee: a key's pointer.
        let h = unsafe { slot.read_unaligned() };
        // SAFETY: as above; the reference is detached.
        unsafe { slot.write_unaligned(ptr::null_mut()) };
        h.cast()
    }
}

ffi_callback! {
    /// `dh_dup` (`ossl_dh_dup`).
    ///
    /// # Safety
    /// `keydata_from` is a live key.
    pub(crate) unsafe extern "C" fn dh_dup(keydata_from: *const c_void, selection: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup(keydata_from.cast(), selection) }.cast()
    }
}

ffi_callback! {
    /// `dhx_query_operation_name`: DHX keys run DH's operations.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dhx_query_operation_name(_operation_id: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_DH
    {
        c"DH".as_ptr()
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

/// `ossl_dh_keymgmt_functions`.
pub(crate) static DH_KEYMGMT: Dispatch<22> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, dh_newdata, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, dh_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        dh_gen_set_template,
        GenTemplateFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        dh_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        dh_gen_settable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, dh_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, dh_gen_cleanup, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_LOAD, dh_load, LoadFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, dh_freedata, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, dh_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        dh_gettable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, dh_set_params, SetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        dh_settable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, dh_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, dh_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_VALIDATE, dh_validate, ValidateFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, dh_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, dh_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, dh_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, dh_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_DUP, dh_dup, DupFn),
    END,
]);

/// `ossl_dhx_keymgmt_functions`.
pub(crate) static DHX_KEYMGMT: Dispatch<23> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, dhx_newdata, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, dhx_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        dh_gen_set_template,
        GenTemplateFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        dhx_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        dhx_gen_settable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, dh_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, dh_gen_cleanup, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_LOAD, dh_load, LoadFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, dh_freedata, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, dh_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        dh_gettable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, dh_set_params, SetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        dh_settable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, dh_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, dh_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_VALIDATE, dh_validate, ValidateFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, dh_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, dh_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, dh_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, dh_imexport_types, TypesFn),
    entry!(
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        dhx_query_operation_name,
        QueryFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_DUP, dh_dup, DupFn),
    END,
]);

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: `EVP_PKEY_CTX_set_dh_paramgen_type`'s translation passes the type
    /// as a NULL string, which OpenSSL's key manager reads.
    #[test]
    fn a_null_type_name_is_refused() {
        let g = boxed(GenCtx {
            libctx: ptr::null_mut(),
            ffc_params: None,
            selection: DOMAIN,
            group_nid: 0,
            pbits: 2048,
            qbits: 224,
            seed: None,
            gindex: -1,
            gen_type: DH_PARAMGEN_TYPE_GENERATOR,
            generator: DH_GENERATOR_2,
            pcounter: -1,
            hindex: 0,
            priv_len: 0,
            mdname: None,
            mdprops: None,
            cb: None,
            cbarg: ptr::null_mut(),
            dhx: false,
        });
        let params = [
            // SAFETY: a static key; no data, as the translation passes it.
            unsafe {
                crate::params::OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_FFC_TYPE.as_ptr(),
                    ptr::null_mut(),
                    2,
                )
            },
            end(),
        ];
        // SAFETY: the context above; the array.
        assert_eq!(unsafe { dh_gen_set_params(g, params.as_ptr()) }, 0);
        // SAFETY: the context above; the array.
        assert_eq!(unsafe { dhx_gen_set_params(g, params.as_ptr()) }, 0);
        // SAFETY: made above, freed once.
        unsafe { unbox::<GenCtx>(g) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
