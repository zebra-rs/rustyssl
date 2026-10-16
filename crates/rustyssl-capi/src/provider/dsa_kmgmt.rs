//! The default provider's DSA key manager (`dsa_kmgmt.c`, with `crate::dsa_backend`): keys are
//! `DSA` objects (`crate::dsa`), made empty, filled from parameters (the FFC parameters and the
//! key pair), described, exported, compared, copied by selection, validated, loaded from a
//! reference, and generated: FIPS 186-4 or 186-2 parameters (by default 186-4 from 2048 bits,
//! 186-2 below), with the seed, index, counter, h, and digest asked for, or a template's, and
//! keys from those.

use core::ffi::{CStr, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    BN_GENCB, DSA, ERR_LIB_DSA, ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, OSSL_CALLBACK,
    OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_VALIDATE,
    OSSL_GEN_PARAM_ITERATION, OSSL_GEN_PARAM_POTENTIAL, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_DEFAULT_DIGEST,
    OSSL_PKEY_PARAM_FFC_COFACTOR, OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PKEY_PARAM_FFC_DIGEST_PROPS,
    OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_H,
    OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PKEY_PARAM_FFC_PCOUNTER,
    OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_FFC_QBITS, OSSL_PKEY_PARAM_FFC_SEED,
    OSSL_PKEY_PARAM_FFC_TYPE, OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
};

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::bn::prime::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set};
use crate::dh_backend::{enable_flags, utf8};
use crate::dsa::{DSA_bits, DSA_security_bits, Dsa, dsa};
use crate::dsa_backend::{
    check_pairwise, check_params, check_priv_key, check_pub_key, dup, key_fromdata, key_todata,
    params_fromdata, params_todata,
};
use crate::dsa_ops::{DSA_generate_key, DSA_size, generate_ffc_parameters};
use crate::ec::params::{Kept, Target, text};
use crate::err;
use crate::ffc;
use crate::ffi::ffi_callback;
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_get_int, OSSL_PARAM_get_size_t, OSSL_PARAM_locate,
    OSSL_PARAM_set_int, OSSL_PARAM_set_utf8_string, end,
};

/// `DSA_DEFAULT_MD`.
const DSA_DEFAULT_MD: &CStr = c"SHA256";

const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
const DOMAIN: c_int = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
/// `DSA_POSSIBLE_SELECTIONS`.
const POSSIBLE: c_int = KEYPAIR | DOMAIN;

const INT: c_int = OSSL_PARAM_INTEGER;
const BN: c_int = OSSL_PARAM_UNSIGNED_INTEGER;
const UTF8: c_int = OSSL_PARAM_UTF8_STRING;
const OCTETS: c_int = OSSL_PARAM_OCTET_STRING;
const INT_SIZE: usize = size_of::<c_int>();
const SIZE_T_SIZE: usize = size_of::<usize>();

/// `DSA_PARAMGEN_TYPE_*` (OpenSSL's internal `crypto/dsa.h`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum GenType {
    Fips1864,
    Fips1862,
    /// 186-4 from 2048 bits, 186-2 below.
    Default,
}

/// `dsa_gen_type_name2id`: case-insensitively.
fn gen_type_name2id(name: &[u8]) -> Option<GenType> {
    [
        (&b"default"[..], GenType::Default),
        (b"fips186_4", GenType::Fips1864),
        (b"fips186_2", GenType::Fips1862),
    ]
    .into_iter()
    .find(|(n, _)| n.eq_ignore_ascii_case(name))
    .map(|(_, t)| t)
}

/// The key behind key data.
///
/// # Safety
/// `keydata` is NULL or a live `DSA`.
unsafe fn key<'a>(keydata: *const c_void) -> Option<&'a Dsa> {
    // SAFETY: the caller's guarantee.
    unsafe { dsa(keydata.cast()) }
}

ffi_callback! {
    /// `dsa_newdata`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn dsa_newdata(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        Dsa::new_handle_in(unsafe { libctx_of(provctx) }).cast()
    }
}

ffi_callback! {
    /// `dsa_freedata` (`DSA_free`).
    ///
    /// # Safety
    /// `keydata` is NULL or key data whose reference the caller gives up.
    pub(crate) unsafe extern "C" fn dsa_freedata(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { crate::dsa::free(keydata.cast()) };
    }
}

ffi_callback! {
    /// `dsa_has`: the public key, private key, and p and g, as selected.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn dsa_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DSA
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
    /// `dsa_match`: the public keys (or, without them, the private keys) for key pair
    /// selections, and p and g for the parameters.
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are live key data.
    pub(crate) unsafe extern "C" fn dsa_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DSA
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
    /// `dsa_import`: the parameters (always), then the key pair as selected.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dsa_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
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
    /// `dsa_export`: the parameters and key pair, as selected, to `param_cb` (called once).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` takes `cbarg`.
    pub(crate) unsafe extern "C" fn dsa_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DSA
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

/// `dsa_all_types`: the parameters (`DSA_IMEXPORTABLE_PARAMETERS`), then the keys.
static ALL_TYPES: Params<11> = Params([
    defn(OSSL_PKEY_PARAM_FFC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_Q, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_G, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_GINDEX, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_PCOUNTER, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_H, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_SEED, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, BN, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0),
    PARAM_END,
]);

/// `dsa_parameter_types`.
static PARAMETER_TYPES: Params<9> = Params([
    defn(OSSL_PKEY_PARAM_FFC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_Q, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_G, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_GINDEX, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_PCOUNTER, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_H, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_SEED, OCTETS, 0),
    PARAM_END,
]);

/// `dsa_key_types`.
static KEY_TYPES: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PUB_KEY, BN, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `dsa_import_types` and `dsa_export_types`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dsa_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DSA
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
    /// `dsa_get_params`: the bits, strength, signature size, default digest (SHA-256), then
    /// the parameters and key pair.
    ///
    /// # Safety
    /// `keydata` is a live key; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dsa_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        let h = keydata.cast::<DSA>();
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        // SAFETY: the caller's key (for each below).
        let ints = [
            (OSSL_PKEY_PARAM_BITS, unsafe { DSA_bits(h) }),
            (OSSL_PKEY_PARAM_SECURITY_BITS, unsafe { DSA_security_bits(h) }),
            (OSSL_PKEY_PARAM_MAX_SIZE, unsafe { DSA_size(h) }),
        ];
        for (name, v) in ints {
            // SAFETY: the caller's array.
            if !unsafe { set_int(params, name, v) } {
                return 0;
            }
        }
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST.as_ptr()) };
        // SAFETY: a parameter of the array; a static string.
        if !p.is_null() && unsafe { OSSL_PARAM_set_utf8_string(p, DSA_DEFAULT_MD.as_ptr()) } == 0 {
            return 0;
        }
        let st = k.snapshot();
        let target = Target::Params(params);
        let mut kept = Kept::default();
        // SAFETY: the caller's array; `st` and `kept` live through the call.
        c_int::from(unsafe { params_todata(&st, target, &mut kept) }
            // SAFETY: as above.
            && unsafe { key_todata(&st, target, &mut kept, true) })
    }
}

/// `dsa_params`: what `dsa_get_params` reports.
static GETTABLE: Params<15> = Params([
    defn(OSSL_PKEY_PARAM_BITS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_DEFAULT_DIGEST, UTF8, 0),
    defn(OSSL_PKEY_PARAM_FFC_P, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_Q, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_G, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_COFACTOR, BN, 0),
    defn(OSSL_PKEY_PARAM_FFC_GINDEX, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_PCOUNTER, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_H, INT, INT_SIZE),
    defn(OSSL_PKEY_PARAM_FFC_SEED, OCTETS, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, BN, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, BN, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `dsa_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dsa_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `dsa_validate`: the parameters (simply for a quick check, fully otherwise), the public
    /// key, the private key's range, and the pair.
    ///
    /// # Safety
    /// `keydata` is a live key.
    pub(crate) unsafe extern "C" fn dsa_validate(keydata: *const c_void, selection: c_int, checktype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 1;
        }
        let st = k.snapshot();
        let mut ok = true;
        if selection & DOMAIN != 0 {
            // SAFETY: the key's library context.
            ok = unsafe { check_params(k.libctx.0, &st, checktype) };
        }
        if ok && selection & PUBLIC != 0 {
            ok = st.pub_key.as_ref().is_some_and(|y| check_pub_key(&st, y));
        }
        if ok && selection & PRIVATE != 0 {
            ok = st.priv_key.as_ref().is_some_and(|x| check_priv_key(&st, x));
        }
        if ok && selection & KEYPAIR == KEYPAIR {
            ok = check_pairwise(&st);
        }
        c_int::from(ok)
    }
}

/// `struct dsa_gen_ctx`.
struct GenCtx {
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    /// The template's parameters (a copy, taken when it's set).
    ffc_params: Option<ffc::Params>,
    selection: c_int,
    pbits: usize,
    qbits: usize,
    seed: Option<Vec<u8>>,
    gindex: c_int,
    gen_type: GenType,
    pcounter: c_int,
    hindex: c_int,
    mdname: Option<CString>,
    mdprops: Option<CString>,
    cb: OSSL_CALLBACK,
    cbarg: *mut c_void,
}

/// The generation context behind `genctx`.
///
/// # Safety
/// `genctx` is NULL or a live context from `dsa_gen_init`.
unsafe fn gen_ctx<'a>(genctx: *mut c_void) -> Option<&'a mut GenCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<GenCtx>(genctx) }
}

ffi_callback! {
    /// `dsa_gen_init`: 2048 and 224 bits, the type by size, then the parameters.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dsa_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        if selection & POSSIBLE == 0 {
            return ptr::null_mut();
        }
        let g = boxed(GenCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            ffc_params: None,
            selection,
            pbits: 2048,
            qbits: 224,
            seed: None,
            gindex: -1,
            gen_type: GenType::Default,
            pcounter: -1,
            hindex: 0,
            mdname: None,
            mdprops: None,
            cb: None,
            cbarg: ptr::null_mut(),
        });
        // SAFETY: the context just made; the caller's array.
        if unsafe { dsa_gen_set_params(g, params) } != 1 {
            // SAFETY: the context just made, freed once.
            unsafe { unbox::<GenCtx>(g) };
            return ptr::null_mut();
        }
        g
    }
}

ffi_callback! {
    /// `dsa_gen_set_template`: generation takes the template key's parameters.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `templ` is NULL or a live key.
    pub(crate) unsafe extern "C" fn dsa_gen_set_template(genctx: *mut c_void, templ: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let (Some(g), Some(t)) = (unsafe { gen_ctx(genctx) }, unsafe { key(templ) }) else { return 0 };
        g.ffc_params = Some(t.snapshot().params);
        1
    }
}

ffi_callback! {
    /// `dsa_gen_set_params`: the type (by name, any case), index, counter, h, seed, sizes, and
    /// digest, each committed as it's read.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn dsa_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above (for each lookup below).
        let find = |name: &CStr| unsafe { locate(params, name) };
        if let Some(p) = find(OSSL_PKEY_PARAM_FFC_TYPE) {
            // SAFETY: a parameter of the array.
            let id = unsafe { text(p) }.flatten().and_then(gen_type_name2id);
            let Some(id) = id else {
                err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, "dsa_gen_set_params");
                return 0;
            };
            g.gen_type = id;
        }
        for (name, slot) in [
            (OSSL_PKEY_PARAM_FFC_GINDEX, &mut g.gindex),
            (OSSL_PKEY_PARAM_FFC_PCOUNTER, &mut g.pcounter),
            (OSSL_PKEY_PARAM_FFC_H, &mut g.hindex),
        ] {
            // SAFETY: a parameter of the array; the slot.
            if let Some(p) = find(name) && unsafe { OSSL_PARAM_get_int(p, slot) } != 1 {
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
        for (name, slot) in [
            (OSSL_PKEY_PARAM_FFC_PBITS, &mut g.pbits),
            (OSSL_PKEY_PARAM_FFC_QBITS, &mut g.qbits),
        ] {
            // SAFETY: a parameter of the array; the slot.
            if let Some(p) = find(name) && unsafe { OSSL_PARAM_get_size_t(p, slot) } != 1 {
                return 0;
            }
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
                let Some(v) = (unsafe { utf8(p) }) else { return 0 };
                *slot = Some(v);
            }
        }
        1
    }
}

/// `dsa_gen_settable_params`' list.
static GEN_SETTABLE: Params<10> = Params([
    defn(OSSL_PKEY_PARAM_FFC_TYPE, UTF8, 0),
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
    /// `dsa_gen_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dsa_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

/// `dsa_gen_gettable_params`' list: nothing outside the FIPS provider.
static GEN_GETTABLE: Params<1> = Params([PARAM_END]);

ffi_callback! {
    /// `dsa_gen_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn dsa_gen_gettable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_DSA
    {
        GEN_GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `dsa_gen_get_params`: nothing to report outside the FIPS provider; 1 for a context.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context.
    pub(crate) unsafe extern "C" fn dsa_gen_get_params(genctx: *mut c_void, _params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        c_int::from(!genctx.is_null())
    }
}

ffi_callback! {
    /// `dsa_gencb`: reports a generation step to the application's callback.
    ///
    /// # Safety
    /// `cb` is a live `BN_GENCB` whose argument is a live generation context.
    pub(crate) unsafe extern "C" fn dsa_gencb(p: c_int, n: c_int, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_DSA
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
            None => 1,
        }
    }
}

/// What `dsa_gen` generates, read from the context before anything calls back into it.
struct Plan {
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    template: Option<ffc::Params>,
    selection: c_int,
    pbits: usize,
    qbits: usize,
    seed: Option<Vec<u8>>,
    gindex: c_int,
    gen_type: GenType,
    pcounter: c_int,
    hindex: c_int,
    mdname: Option<CString>,
    mdprops: Option<CString>,
}

/// `dsa_gen`'s work after the plan is read: the new key, or NULL (freed on failure).
///
/// # Safety
/// `genctx` is a live generation context (the callback's argument).
unsafe fn generate(plan: Plan, genctx: *mut c_void) -> *mut DSA {
    let h = Dsa::new_handle_in(plan.libctx);
    // SAFETY: just made, or NULL.
    let Some(k) = (unsafe { dsa(h) }) else {
        return ptr::null_mut();
    };
    let gen_type = match plan.gen_type {
        GenType::Default if plan.pbits >= 2048 => GenType::Fips1864,
        GenType::Default => GenType::Fips1862,
        t => t,
    };
    // SAFETY: no preconditions.
    let gencb = unsafe { BN_GENCB_new() };
    if !gencb.is_null() {
        // SAFETY: the holder just made; the callback reads the context, live for the call.
        unsafe { BN_GENCB_set(gencb, Some(dsa_gencb), genctx) };
    }
    let ok = (|| {
        let mut st = k.snapshot();
        if let Some(t) = plan.template {
            st.params = t;
        }
        if plan.seed.is_some() {
            st.params.seed = plan.seed;
        }
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
        if plan.selection & DOMAIN != 0 {
            // SAFETY: the key; the holder, or NULL.
            let ret = unsafe {
                generate_ffc_parameters(
                    h,
                    gen_type == GenType::Fips1862,
                    plan.pbits,
                    plan.qbits,
                    gencb,
                )
            };
            if ret <= 0 {
                return false;
            }
        }
        let mut st = k.snapshot();
        enable_flags(
            &mut st.params,
            ffc::VALIDATE_LEGACY,
            gen_type == GenType::Fips1862,
        );
        let complete = st.params.p.is_some() && st.params.q.is_some() && st.params.g.is_some();
        k.replace(st);
        if plan.selection & KEYPAIR != 0 {
            // SAFETY: the key, with no lock held.
            return complete && unsafe { DSA_generate_key(h) } > 0;
        }
        true
    })();
    // SAFETY: the holder made above, or NULL.
    unsafe { BN_GENCB_free(gencb) };
    if !ok {
        // SAFETY: the key made above.
        unsafe { crate::dsa::free(h) };
        return ptr::null_mut();
    }
    h
}

ffi_callback! {
    /// `dsa_gen`: parameters (generated, or a template's) and, if selected, a key pair. The
    /// key, or NULL.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `osslcb` takes `cbarg`.
    pub(crate) unsafe extern "C" fn dsa_gen(genctx: *mut c_void, osslcb: OSSL_CALLBACK, cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
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
                pbits: g.pbits,
                qbits: g.qbits,
                seed: g.seed.clone(),
                gindex: g.gindex,
                gen_type: g.gen_type,
                pcounter: g.pcounter,
                hindex: g.hindex,
                mdname: g.mdname.clone(),
                mdprops: g.mdprops.clone(),
            }
        };
        // SAFETY: the caller's context, no longer borrowed here.
        unsafe { generate(plan, genctx) }.cast()
    }
}

ffi_callback! {
    /// `dsa_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn dsa_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

ffi_callback! {
    /// `dsa_load`: the key the reference points to; the reference is cleared, its key passing
    /// to the result.
    ///
    /// # Safety
    /// `reference` is NULL or points to `reference_sz` writable octets holding a live key's
    /// pointer.
    pub(crate) unsafe extern "C" fn dsa_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        if reference.is_null() || reference_sz != size_of::<*mut DSA>() {
            return ptr::null_mut();
        }
        let slot = reference.cast::<*mut DSA>().cast_mut();
        // SAFETY: the caller's guarantee: a key's pointer.
        let h = unsafe { slot.read_unaligned() };
        // SAFETY: as above; the reference is detached.
        unsafe { slot.write_unaligned(ptr::null_mut()) };
        h.cast()
    }
}

ffi_callback! {
    /// `dsa_dup` (`ossl_dsa_dup`).
    ///
    /// # Safety
    /// `keydata_from` is a live key.
    pub(crate) unsafe extern "C" fn dsa_dup(keydata_from: *const c_void, selection: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup(keydata_from.cast(), selection) }.cast()
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
type GenInitFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type GenTemplateFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type GenListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type GenFn = unsafe extern "C" fn(*mut c_void, OSSL_CALLBACK, *mut c_void) -> *mut c_void;
type LoadFn = unsafe extern "C" fn(*const c_void, usize) -> *mut c_void;
type ValidateFn = unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int;

/// `ossl_dsa_keymgmt_functions`.
pub(crate) static DSA_KEYMGMT: Dispatch<22> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, dsa_newdata, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, dsa_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
        dsa_gen_set_template,
        GenTemplateFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        dsa_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        dsa_gen_settable_params,
        GenListFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS,
        dsa_gen_get_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS,
        dsa_gen_gettable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, dsa_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, dsa_gen_cleanup, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_LOAD, dsa_load, LoadFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, dsa_freedata, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, dsa_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        dsa_gettable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, dsa_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, dsa_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_VALIDATE, dsa_validate, ValidateFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, dsa_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, dsa_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, dsa_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, dsa_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_DUP, dsa_dup, DupFn),
    END,
]);
