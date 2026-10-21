//! The default provider's RSA and RSA-PSS key managers (`rsa_kmgmt.c`, with `rsa_backend.c`'s
//! import and export): keys are `RSA` objects (`crate::rsa`), made empty, filled from
//! parameters (`EVP_PKEY_fromdata`), described (`EVP_PKEY_get_params`), exported, compared,
//! copied, generated (`crate::rsa_gen`), validated, and loaded from a reference.
//!
//! As in OpenSSL, the import takes the numbers as given: no primality or consistency checks,
//! only that each is no longer than the modulus. The primes past the second are kept in the
//! order OpenSSL keeps them, which reverses them for four or more (`ossl_rsa_set0_all_params`
//! pops them from the end), and exported in that order.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_GENCB, ERR_LIB_PROV, ERR_LIB_RSA, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER,
    NID_mgf1, NID_sha1, NID_sha224, NID_sha256, NID_sha384, NID_sha512, NID_sha512_224,
    NID_sha512_256, OSSL_CALLBACK, OSSL_DIGEST_NAME_SHA1, OSSL_DIGEST_NAME_SHA2_224,
    OSSL_DIGEST_NAME_SHA2_256, OSSL_DIGEST_NAME_SHA2_384, OSSL_DIGEST_NAME_SHA2_512,
    OSSL_DIGEST_NAME_SHA2_512_224, OSSL_DIGEST_NAME_SHA2_512_256, OSSL_FUNC_KEYMGMT_DUP,
    OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_FREE,
    OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP, OSSL_FUNC_KEYMGMT_GEN_INIT,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
    OSSL_FUNC_KEYMGMT_VALIDATE, OSSL_GEN_PARAM_ITERATION, OSSL_GEN_PARAM_POTENTIAL,
    OSSL_KEYMGMT_SELECT_KEYPAIR, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_BLD, OSSL_PARAM_INTEGER, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING,
    OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_DEFAULT_DIGEST, OSSL_PKEY_PARAM_MANDATORY_DIGEST,
    OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PKEY_PARAM_RSA_BITS, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT2, OSSL_PKEY_PARAM_RSA_COEFFICIENT3,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT4, OSSL_PKEY_PARAM_RSA_COEFFICIENT5,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT6, OSSL_PKEY_PARAM_RSA_COEFFICIENT7,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT8, OSSL_PKEY_PARAM_RSA_COEFFICIENT9, OSSL_PKEY_PARAM_RSA_D,
    OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ, OSSL_PKEY_PARAM_RSA_DIGEST,
    OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, OSSL_PKEY_PARAM_RSA_E, OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT2, OSSL_PKEY_PARAM_RSA_EXPONENT3, OSSL_PKEY_PARAM_RSA_EXPONENT4,
    OSSL_PKEY_PARAM_RSA_EXPONENT5, OSSL_PKEY_PARAM_RSA_EXPONENT6, OSSL_PKEY_PARAM_RSA_EXPONENT7,
    OSSL_PKEY_PARAM_RSA_EXPONENT8, OSSL_PKEY_PARAM_RSA_EXPONENT9, OSSL_PKEY_PARAM_RSA_EXPONENT10,
    OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR2, OSSL_PKEY_PARAM_RSA_FACTOR3,
    OSSL_PKEY_PARAM_RSA_FACTOR4, OSSL_PKEY_PARAM_RSA_FACTOR5, OSSL_PKEY_PARAM_RSA_FACTOR6,
    OSSL_PKEY_PARAM_RSA_FACTOR7, OSSL_PKEY_PARAM_RSA_FACTOR8, OSSL_PKEY_PARAM_RSA_FACTOR9,
    OSSL_PKEY_PARAM_RSA_FACTOR10, OSSL_PKEY_PARAM_RSA_MASKGENFUNC, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST,
    OSSL_PKEY_PARAM_RSA_N, OSSL_PKEY_PARAM_RSA_PRIMES, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
    OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PKEY_PARAM_SECURITY_CATEGORY, PROV_R_KEY_SIZE_TOO_SMALL,
    RSA, RSA_DEFAULT_PRIME_NUM, RSA_F4, RSA_R_INVALID_KEYPAIR, SN_mgf1,
};
use rustyssl_crypto::bn::{self, BigNum};
use rustyssl_crypto::rsa::{ExtraPrime, Key, ifc_ffc_security_bits};

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::bn::prime::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set};
use crate::bn::{BN_clear_free, new_bignum, value};
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_is_a};
use crate::ffi::ffi_callback;
use crate::params::bn::{OSSL_PARAM_get_BN, OSSL_PARAM_set_BN};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_BN, OSSL_PARAM_BLD_push_int,
    OSSL_PARAM_BLD_push_utf8_string, OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_get_int, OSSL_PARAM_get_size_t, OSSL_PARAM_locate,
    OSSL_PARAM_set_int, OSSL_PARAM_set_utf8_string, end,
};
use crate::rsa::{Kind, Pss30, Rsa, RsaState, rsa};
use crate::rsa_gen::{
    MIN_MODULUS_BITS, derive_crt, generate_key, multip_cap, validate_keypair, validate_private,
    validate_public,
};

/// `RSA_DEFAULT_MD` (`rsa_kmgmt.c`; no public header names it): the default digest's name.
const RSA_DEFAULT_MD: &CStr = c"SHA256";

/// `RSA_POSSIBLE_SELECTIONS`.
const POSSIBLE: c_int =
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) as c_int;
const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR as c_int;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int;
const OTHER: c_int = OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as c_int;

/// `ossl_rsa_mp_factor_names`.
const FACTORS: [&CStr; 10] = [
    OSSL_PKEY_PARAM_RSA_FACTOR1,
    OSSL_PKEY_PARAM_RSA_FACTOR2,
    OSSL_PKEY_PARAM_RSA_FACTOR3,
    OSSL_PKEY_PARAM_RSA_FACTOR4,
    OSSL_PKEY_PARAM_RSA_FACTOR5,
    OSSL_PKEY_PARAM_RSA_FACTOR6,
    OSSL_PKEY_PARAM_RSA_FACTOR7,
    OSSL_PKEY_PARAM_RSA_FACTOR8,
    OSSL_PKEY_PARAM_RSA_FACTOR9,
    OSSL_PKEY_PARAM_RSA_FACTOR10,
];

/// `ossl_rsa_mp_exp_names`.
const EXPONENTS: [&CStr; 10] = [
    OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT2,
    OSSL_PKEY_PARAM_RSA_EXPONENT3,
    OSSL_PKEY_PARAM_RSA_EXPONENT4,
    OSSL_PKEY_PARAM_RSA_EXPONENT5,
    OSSL_PKEY_PARAM_RSA_EXPONENT6,
    OSSL_PKEY_PARAM_RSA_EXPONENT7,
    OSSL_PKEY_PARAM_RSA_EXPONENT8,
    OSSL_PKEY_PARAM_RSA_EXPONENT9,
    OSSL_PKEY_PARAM_RSA_EXPONENT10,
];

/// `ossl_rsa_mp_coeff_names`.
const COEFFICIENTS: [&CStr; 9] = [
    OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT2,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT3,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT4,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT5,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT6,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT7,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT8,
    OSSL_PKEY_PARAM_RSA_COEFFICIENT9,
];

/// `oaeppss_name_nid_map`: the digests a PSS restriction or OAEP names.
pub(crate) const OAEPPSS_DIGESTS: [(c_int, &CStr); 7] = [
    (NID_sha1, OSSL_DIGEST_NAME_SHA1),
    (NID_sha224, OSSL_DIGEST_NAME_SHA2_224),
    (NID_sha256, OSSL_DIGEST_NAME_SHA2_256),
    (NID_sha384, OSSL_DIGEST_NAME_SHA2_384),
    (NID_sha512, OSSL_DIGEST_NAME_SHA2_512),
    (NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224),
    (NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256),
];

/// `ossl_rsa_oaeppss_md2nid`.
///
/// # Safety
/// `md` is NULL or a live digest.
pub(crate) unsafe fn oaeppss_md2nid(md: *const rustyssl_abi::EVP_MD) -> c_int {
    if md.is_null() {
        return rustyssl_abi::NID_undef;
    }
    OAEPPSS_DIGESTS
        .iter()
        // SAFETY: the caller's digest; a static name.
        .find(|(_, name)| unsafe { EVP_MD_is_a(md, name.as_ptr()) } != 0)
        .map_or(rustyssl_abi::NID_undef, |&(nid, _)| nid)
}

/// `ossl_rsa_oaeppss_nid2name`.
pub(crate) fn oaeppss_nid2name(nid: c_int) -> Option<&'static CStr> {
    OAEPPSS_DIGESTS
        .iter()
        .find(|(n, _)| *n == nid)
        .map(|&(_, name)| name)
}

/// `ossl_rsa_pss_params_30_set_defaults`: SHA-1, MGF1 with SHA-1, a salt of 20, trailer 1.
pub(crate) const PSS_DEFAULTS: Pss30 = Pss30 {
    hash: NID_sha1,
    mask_gen: NID_mgf1,
    mask_gen_hash: NID_sha1,
    salt_len: 20,
    trailer: 1,
};

/// The RSA object behind key data.
///
/// # Safety
/// `keydata` is NULL or live key data from these key managers.
unsafe fn key<'a>(keydata: *const c_void) -> Option<&'a Rsa> {
    // SAFETY: the caller's guarantee.
    unsafe { rsa(keydata.cast()) }
}

/// The number in `params`' parameter `name`: `Ok(None)` when there's none, `Err` when it
/// isn't a number (with `OSSL_PARAM_get_BN`'s errors raised).
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn get_bn(params: *const OSSL_PARAM, name: &CStr) -> Result<Option<BigNum>, ()> {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { locate(params, name) }) else {
        return Ok(None);
    };
    let mut b: *mut BIGNUM = ptr::null_mut();
    // SAFETY: a parameter of the array; a place for a new number.
    if unsafe { OSSL_PARAM_get_BN(p, &raw mut b) } != 1 {
        return Err(());
    }
    // SAFETY: the number just made, freed once.
    let v = unsafe { value(b) };
    // SAFETY: as above.
    unsafe { BN_clear_free(b) };
    v.map(Some).ok_or(())
}

/// Where key parts go: a builder (`export`), or an array to fill (`get_params`).
#[derive(Clone, Copy)]
enum Target {
    Builder(*mut OSSL_PARAM_BLD),
    Params(*mut OSSL_PARAM),
}

/// The numbers a builder reads when it makes its array: their handles live until then.
struct Pushed(Vec<*mut BIGNUM>);

impl Drop for Pushed {
    fn drop(&mut self) {
        for &b in &self.0 {
            // SAFETY: handles made by `set_bn`, each freed once.
            unsafe { BN_clear_free(b) };
        }
    }
}

/// `ossl_param_build_set_bn`: `v` (NULL for `None`) to the builder, or into `params`' `name`
/// if it asks for it.
fn set_bn(target: Target, pushed: &mut Pushed, name: &CStr, v: Option<&BigNum>) -> bool {
    let b = match v {
        Some(v) => {
            let b = new_bignum(v.clone(), false);
            if b.is_null() {
                return false;
            }
            pushed.0.push(b);
            b
        }
        None => ptr::null_mut(),
    };
    match target {
        // SAFETY: a live builder; a static name; a live number or NULL, kept until the array.
        Target::Builder(bld) => (unsafe { OSSL_PARAM_BLD_push_BN(bld, name.as_ptr(), b) }) == 1,
        Target::Params(params) => {
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            // SAFETY: a parameter of it; a live number or NULL.
            p.is_null() || unsafe { OSSL_PARAM_set_BN(p, b) } > 0
        }
    }
}

/// `ossl_param_build_set_multi_key_bn`: each present number under its name, in order.
fn set_multi(
    target: Target,
    pushed: &mut Pushed,
    names: &[&CStr],
    values: &[Option<&BigNum>],
) -> bool {
    for (name, v) in names.iter().zip(values) {
        let Some(v) = v else { continue };
        if let Target::Params(params) = target {
            // SAFETY: the caller's array; a static name.
            if unsafe { OSSL_PARAM_locate(params, name.as_ptr()) }.is_null() {
                continue;
            }
        }
        if !set_bn(target, pushed, name, Some(v)) {
            return false;
        }
    }
    true
}

/// A list of a key's numbers, each possibly absent.
type Numbers<'a> = Vec<Option<&'a BigNum>>;

/// `ossl_rsa_get0_all_params`: the primes, exponents, and coefficients, from `p` on (none
/// without `p`).
fn all_params(k: &Key) -> (Numbers<'_>, Numbers<'_>, Numbers<'_>) {
    if k.p.is_none() {
        return (Vec::new(), Vec::new(), Vec::new());
    }
    let mut primes = vec![k.p.as_ref(), k.q.as_ref()];
    let mut exps = vec![k.dmp1.as_ref(), k.dmq1.as_ref()];
    let mut coeffs = vec![k.iqmp.as_ref()];
    for ex in &k.extra {
        primes.push(Some(&ex.r));
        exps.push(Some(&ex.d));
        coeffs.push(Some(&ex.t));
    }
    (primes, exps, coeffs)
}

/// `ossl_rsa_todata`: `n` and `e`, then (if `include_private` and the key has `d`) `d` and the
/// primes, exponents, and coefficients.
fn todata(k: &Key, target: Target, pushed: &mut Pushed, include_private: bool) -> bool {
    if !set_bn(target, pushed, OSSL_PKEY_PARAM_RSA_N, k.n.as_ref())
        || !set_bn(target, pushed, OSSL_PKEY_PARAM_RSA_E, k.e.as_ref())
    {
        return false;
    }
    if include_private && k.d.is_some() {
        let (primes, exps, coeffs) = all_params(k);
        if !set_bn(target, pushed, OSSL_PKEY_PARAM_RSA_D, k.d.as_ref())
            || !set_multi(target, pushed, &FACTORS, &primes)
            || !set_multi(target, pushed, &EXPONENTS, &exps)
            || !set_multi(target, pushed, &COEFFICIENTS, &coeffs)
        {
            return false;
        }
    }
    true
}

/// `ossl_rsa_pss_params_30_todata`: a restricted key's digest (unless SHA-1), MGF1's digest
/// (unless SHA-1), and always the salt length.
fn pss_todata(pss: &Pss30, target: Target) -> bool {
    if !pss.restricted() {
        return true;
    }
    let mut strings: Vec<(&CStr, &CStr)> = Vec::new();
    if pss.hash != NID_sha1
        && let Some(name) = oaeppss_nid2name(pss.hash)
    {
        strings.push((OSSL_PKEY_PARAM_RSA_DIGEST, name));
    }
    if pss.mask_gen_hash != NID_sha1
        && let Some(name) = oaeppss_nid2name(pss.mask_gen_hash)
    {
        strings.push((OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, name));
    }
    for (key, value) in strings {
        let ok = match target {
            Target::Builder(b) => {
                // SAFETY: a live builder; static strings.
                let r =
                    unsafe { OSSL_PARAM_BLD_push_utf8_string(b, key.as_ptr(), value.as_ptr(), 0) };
                r == 1
            }
            Target::Params(params) => {
                // SAFETY: the caller's array; a static name.
                let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
                // SAFETY: a parameter of it; a static string.
                p.is_null() || unsafe { OSSL_PARAM_set_utf8_string(p, value.as_ptr()) } == 1
            }
        };
        if !ok {
            return false;
        }
    }
    match target {
        Target::Builder(b) => {
            let key = OSSL_PKEY_PARAM_RSA_PSS_SALTLEN.as_ptr();
            // SAFETY: a live builder; a static name.
            let r = unsafe { OSSL_PARAM_BLD_push_int(b, key, pss.salt_len) };
            r == 1
        }
        Target::Params(params) => {
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN.as_ptr()) };
            // SAFETY: a parameter of it.
            p.is_null() || unsafe { OSSL_PARAM_set_int(p, pss.salt_len) } == 1
        }
    }
}

/// A UTF-8 string parameter's text, or `None` for another type.
fn utf8(p: &OSSL_PARAM) -> Option<&CStr> {
    if p.data_type != OSSL_PARAM_UTF8_STRING as u32 || p.data.is_null() {
        return None;
    }
    // SAFETY: a UTF-8 string parameter's data is a string.
    Some(unsafe { CStr::from_ptr(p.data.cast()) })
}

/// `ossl_rsa_pss_params_30_fromdata`: restrictions from the digest, MGF, MGF1 digest, and salt
/// length parameters, the defaults first when any is given.
///
/// # Safety
/// `params` is NULL or a parameter array; `libctx` is NULL or a live library context.
unsafe fn pss_fromdata(
    pss: &mut Pss30,
    defaults_set: &mut bool,
    params: *const OSSL_PARAM,
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
) -> bool {
    let find = |key: &CStr| {
        // SAFETY: the caller's guarantee; a static name.
        unsafe { locate(params, key) }
    };
    let propq = find(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
    let md = find(OSSL_PKEY_PARAM_RSA_DIGEST);
    let mgf = find(OSSL_PKEY_PARAM_RSA_MASKGENFUNC);
    let mgf1md = find(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST);
    let saltlen = find(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);
    let propq = propq.and_then(utf8).map_or(ptr::null(), CStr::as_ptr);
    if !*defaults_set && (md.is_some() || mgf.is_some() || mgf1md.is_some() || saltlen.is_some()) {
        *pss = PSS_DEFAULTS;
        *defaults_set = true;
    }
    // The MGF must be MGF1. (OpenSSL compares a pointer parameter's pointer as text, which
    // can't match.)
    if let Some(p) = mgf {
        // SAFETY: a static name.
        let mgf1 = unsafe { CStr::from_ptr(SN_mgf1.as_ptr()) };
        if !utf8(p).is_some_and(|m| m.to_bytes().eq_ignore_ascii_case(mgf1.to_bytes())) {
            return false;
        }
    }
    // A digest's name must be a string parameter: OpenSSL reads any other kind through the
    // MGF parameter, which fails.
    for (p, mask) in [(md, false), (mgf1md, true)] {
        let Some(p) = p else { continue };
        let Some(name) = utf8(p) else {
            return false;
        };
        // SAFETY: the caller's library context; the name and query.
        let m = unsafe { EVP_MD_fetch(libctx, name.as_ptr(), propq) };
        if m.is_null() {
            return false;
        }
        // SAFETY: the digest just fetched.
        let nid = unsafe { oaeppss_md2nid(m) };
        // SAFETY: as above.
        unsafe { EVP_MD_free(m) };
        if mask {
            pss.mask_gen_hash = nid;
        } else {
            pss.hash = nid;
        }
    }
    if let Some(p) = saltlen {
        let mut s: c_int = 0;
        // SAFETY: a parameter of the array; a local.
        if unsafe { OSSL_PARAM_get_int(p, &raw mut s) } != 1 {
            return false;
        }
        pss.salt_len = s;
    }
    true
}

/// `ossl_rsa_fromdata`: the key's numbers from `params`. False on failure, with OpenSSL's
/// errors raised; the key may keep what was set before the failure, as OpenSSL's does.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn fromdata(st: &mut RsaState, params: *const OSSL_PARAM, include_private: bool) -> bool {
    const F: &str = "ossl_rsa_fromdata";
    let null_param = || {
        err::raise(ERR_LIB_RSA, ERR_R_PASSED_NULL_PARAMETER, F);
        false
    };
    // SAFETY: the caller's guarantee, here and below.
    let (Ok(Some(n)), Ok(Some(e))) = (unsafe { get_bn(params, OSSL_PKEY_PARAM_RSA_N) }, unsafe {
        get_bn(params, OSSL_PKEY_PARAM_RSA_E)
    }) else {
        return null_param();
    };
    let mut d = None;
    let mut derive = false;
    if include_private {
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_RSA_DERIVE_FROM_PQ) } {
            let mut v: c_int = 0;
            // SAFETY: a parameter of the array; a local.
            if unsafe { OSSL_PARAM_get_int(p, &raw mut v) } != 1 {
                return false;
            }
            derive = v != 0;
        }
        // SAFETY: as above.
        match unsafe { get_bn(params, OSSL_PKEY_PARAM_RSA_D) } {
            Ok(v) => d = v,
            Err(()) => return null_param(),
        }
        if derive {
            // SAFETY: as above.
            let (Ok(Some(_)), Ok(Some(_))) = (
                unsafe { get_bn(params, OSSL_PKEY_PARAM_RSA_FACTOR1) },
                unsafe { get_bn(params, OSSL_PKEY_PARAM_RSA_FACTOR2) },
            ) else {
                return null_param();
            };
        }
    }
    let d_given = d.is_some();
    st.key.n = Some(n);
    st.key.e = Some(e);
    if d.is_some() {
        st.key.d = d;
    }
    if d_given {
        let collect = |names: &[&CStr]| -> Option<Vec<BigNum>> {
            let mut v = Vec::new();
            for name in names {
                // SAFETY: as above.
                match unsafe { get_bn(params, name) } {
                    Ok(Some(b)) => v.push(b),
                    Ok(None) => {}
                    Err(()) => return None,
                }
            }
            Some(v)
        };
        let (Some(mut factors), Some(mut exps), Some(mut coeffs)) = (
            collect(&FACTORS),
            collect(&EXPONENTS),
            collect(&COEFFICIENTS),
        ) else {
            return false;
        };
        if derive && exps.is_empty() && coeffs.is_empty() {
            if factors.len() < 2 {
                return null_param();
            }
            let (Some(e), Some(d)) = (st.key.e.clone(), st.key.d.clone()) else {
                return null_param();
            };
            let Some((x, c)) = derive_crt(&e, &d, &factors) else {
                err::raise(ERR_LIB_RSA, ERR_R_INTERNAL_ERROR, F);
                return false;
            };
            if factors.len() == 2 {
                set_all(&mut st.key, &mut factors, &mut x.clone(), &mut c.clone());
                exps.clear();
                coeffs.clear();
            } else {
                exps = x;
                coeffs = c;
                if !set_all(&mut st.key, &mut factors, &mut exps, &mut coeffs) {
                    err::raise(ERR_LIB_RSA, ERR_R_INTERNAL_ERROR, F);
                    return false;
                }
            }
        } else if !factors.is_empty() && !set_all(&mut st.key, &mut factors, &mut exps, &mut coeffs)
        {
            return false;
        }
        if !factors.is_empty() || !exps.is_empty() || !coeffs.is_empty() {
            err::raise_with_text(
                ERR_LIB_RSA,
                ERR_R_INTERNAL_ERROR,
                F,
                &format!(
                    "There are {}, {}, {} elements left on our factors, exps, coeffs stacks\n",
                    factors.len(),
                    exps.len(),
                    coeffs.len()
                ),
            );
            return false;
        }
    }
    if !check_factors(&st.key) {
        err::raise_with_text(
            ERR_LIB_RSA,
            RSA_R_INVALID_KEYPAIR,
            F,
            "RSA factors/exponents are too big for for n-modulus\n",
        );
        return false;
    }
    true
}

/// `ossl_rsa_set0_all_params`: the first two primes, the CRT numbers when there are as many
/// exponents as primes and one coefficient fewer, and the other primes (popped from the end,
/// as OpenSSL's are). Consumes what it uses from the lists; false (raising nothing) with fewer
/// than two primes or an extra prime short of its numbers.
fn set_all(
    k: &mut Key,
    primes: &mut Vec<BigNum>,
    exps: &mut Vec<BigNum>,
    coeffs: &mut Vec<BigNum>,
) -> bool {
    let pnum = primes.len();
    if pnum < 2 {
        return false;
    }
    let mut it = primes.drain(..2);
    k.p = it.next();
    k.q = it.next();
    drop(it);
    if pnum == exps.len() && pnum == coeffs.len().saturating_add(1) {
        let mut x = exps.drain(..2);
        k.dmp1 = x.next();
        k.dmq1 = x.next();
        drop(x);
        k.iqmp = Some(coeffs.remove(0));
    }
    let mut extra = Vec::new();
    for _ in 2..pnum {
        let (Some(r), Some(d), Some(t)) = (primes.pop(), exps.pop(), coeffs.pop()) else {
            return false;
        };
        extra.push(ExtraPrime { r, d, t });
    }
    k.multi = pnum > 2;
    k.extra = extra;
    true
}

/// `ossl_rsa_check_factors`: no number of the key longer than the modulus.
pub(crate) fn check_factors(k: &Key) -> bool {
    let n = k.n.as_ref().map_or(0, BigNum::num_bits);
    let bits = |b: Option<&BigNum>| b.map_or(0, BigNum::num_bits);
    if bits(k.d.as_ref()) > n {
        return false;
    }
    let (primes, exps, coeffs) = all_params(k);
    primes
        .iter()
        .chain(&exps)
        .chain(&coeffs)
        .all(|b| bits(*b) <= n)
}

/// `RSA_security_bits`.
pub(crate) fn security_bits(k: &Key) -> c_int {
    let bits = k.bits();
    if k.multi {
        let ex = k.extra.len();
        if ex == 0 || ex.saturating_add(2) > multip_cap(bits) {
            return 0;
        }
    }
    c_int::from(ifc_ffc_security_bits(bits))
}

ffi_callback! {
    /// `rsa_newdata`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn rsa_newdata(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        Rsa::new_handle_in(unsafe { libctx_of(provctx) }, Kind::Rsa).cast()
    }
}

ffi_callback! {
    /// `rsapss_newdata`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn rsapss_newdata(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        Rsa::new_handle_in(unsafe { libctx_of(provctx) }, Kind::RsaPss).cast()
    }
}

ffi_callback! {
    /// `rsa_freedata` (`RSA_free`): drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `keydata` is NULL or key data whose reference the caller gives up.
    pub(crate) unsafe extern "C" fn rsa_freedata(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { crate::rsa::free(keydata.cast()) };
    }
}

ffi_callback! {
    /// `rsa_has`: `n` for any key pair part, `e` for the public key, `d` for the private key.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn rsa_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 1;
        }
        let st = r.lock();
        let k = &st.key;
        let mut ok = true;
        if selection & KEYPAIR != 0 {
            ok &= k.n.is_some();
        }
        if selection & PUBLIC != 0 {
            ok &= k.e.is_some();
        }
        if selection & PRIVATE != 0 {
            ok &= k.d.is_some();
        }
        c_int::from(ok)
    }
}

/// `BN_cmp` with NULL equal to NULL only.
fn same(a: Option<&BigNum>, b: Option<&BigNum>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => bn::cmp(a, b).is_eq(),
        _ => false,
    }
}

ffi_callback! {
    /// `rsa_match`: the public exponents always, then the moduli (or, without them, the
    /// private exponents) for key pair selections.
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are live key data.
    pub(crate) unsafe extern "C" fn rsa_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let (Some(a), Some(b)) = (unsafe { key(keydata1) }, unsafe { key(keydata2) }) else { return 0 };
        // Copies, so one key's lock isn't held while taking the other's.
        let (ka, kb) = (a.snapshot().key, b.snapshot().key);
        if !same(ka.e.as_ref(), kb.e.as_ref()) {
            return 0;
        }
        if selection & KEYPAIR == 0 {
            return 1;
        }
        let mut checked = false;
        if selection & PUBLIC != 0
            && let (Some(x), Some(y)) = (&ka.n, &kb.n)
        {
            if !bn::cmp(x, y).is_eq() {
                return 0;
            }
            checked = true;
        }
        if !checked && selection & PRIVATE != 0
            && let (Some(x), Some(y)) = (&ka.d, &kb.d)
        {
            if !bn::cmp(x, y).is_eq() {
                return 0;
            }
            checked = true;
        }
        c_int::from(checked)
    }
}

ffi_callback! {
    /// `rsa_import`: PSS restrictions (other parameters), then the numbers (key pair).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 0;
        }
        r.touch();
        let mut st = r.lock();
        let mut ok = true;
        if selection & OTHER != 0 {
            let mut defaults_set = false;
            let mut pss = st.pss;
            // SAFETY: the caller's guarantee; the key's library context.
            ok = unsafe { pss_fromdata(&mut pss, &mut defaults_set, params, r.libctx.get()) };
            st.pss = pss;
            // A plain RSA key takes no restrictions.
            if ok && st.kind != Kind::RsaPss && pss.restricted() {
                ok = false;
            }
        }
        if ok && selection & KEYPAIR != 0 {
            // SAFETY: the caller's guarantee.
            ok = unsafe { fromdata(&mut st, params, selection & PRIVATE != 0) };
        }
        c_int::from(ok)
    }
}

/// The numbers `import`, `export`, and `get_params` take (`rsa_key_types`).
static KEY_TYPES: Params<33> = Params([
    defn(OSSL_PKEY_PARAM_RSA_N, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_E, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_D, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR2, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR3, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR4, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR5, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR6, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR7, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR8, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR9, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR10, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT1,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT2,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT3,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT4,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT5,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT6,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT7,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT8,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT9,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT10,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT2,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT3,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT4,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT5,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT6,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT7,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT8,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT9,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `rsa_import_types` and `rsa_export_types`: the numbers, for a key pair selection.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsa_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        if selection & KEYPAIR != 0 {
            KEY_TYPES.0.as_ptr()
        } else {
            ptr::null()
        }
    }
}

ffi_callback! {
    /// `rsa_export`: PSS restrictions (other parameters) and the numbers (key pair) to
    /// `param_cb`, which is called once.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` takes `cbarg`.
    pub(crate) unsafe extern "C" fn rsa_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 0;
        }
        let st = r.snapshot();
        // SAFETY: no preconditions.
        let bld = unsafe { OSSL_PARAM_BLD_new() };
        if bld.is_null() {
            return 0;
        }
        let mut pushed = Pushed(Vec::new());
        let target = Target::Builder(bld);
        let mut ok = true;
        if selection & OTHER != 0 {
            ok = pss_todata(&st.pss, target);
        }
        if ok && selection & KEYPAIR != 0 {
            ok = todata(&st.key, target, &mut pushed, selection & PRIVATE != 0);
        }
        let mut ret = 0;
        if ok {
            // SAFETY: the builder; the numbers are still alive.
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

ffi_callback! {
    /// `rsa_get_params`: the size, security strength, maximum output, default (or a restricted
    /// PSS key's mandatory) digest, the restrictions, and the numbers.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { key(keydata) }) else { return 0 };
        let st = r.snapshot();
        let k = &st.key;
        let ints = [
            (OSSL_PKEY_PARAM_BITS, c_int::try_from(k.bits()).unwrap_or(0)),
            (OSSL_PKEY_PARAM_SECURITY_BITS, security_bits(k)),
            (OSSL_PKEY_PARAM_MAX_SIZE, c_int::try_from(k.size()).unwrap_or(0)),
            // 3.6: classical keys are in no NIST post-quantum category.
            (OSSL_PKEY_PARAM_SECURITY_CATEGORY, 0),
        ];
        for (name, v) in ints {
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            if p.is_null() {
                continue;
            }
            // SAFETY: a parameter of the array.
            if k.n.is_none() || unsafe { OSSL_PARAM_set_int(p, v) } != 1 {
                return 0;
            }
        }
        let pss_restricted = st.kind == Kind::RsaPss && st.pss.restricted();
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST.as_ptr()) };
        // SAFETY: a parameter of the array; a static string.
        if !p.is_null() && !pss_restricted && unsafe { OSSL_PARAM_set_utf8_string(p, RSA_DEFAULT_MD.as_ptr()) } != 1 {
            return 0;
        }
        if pss_restricted {
            // SAFETY: as above.
            let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST.as_ptr()) };
            if !p.is_null() {
                let Some(name) = oaeppss_nid2name(st.pss.hash) else { return 0 };
                // SAFETY: a parameter of the array; a static string.
                if unsafe { OSSL_PARAM_set_utf8_string(p, name.as_ptr()) } != 1 {
                    return 0;
                }
            }
        }
        if st.kind == Kind::RsaPss && !pss_todata(&st.pss, Target::Params(params)) {
            return 0;
        }
        let mut pushed = Pushed(Vec::new());
        c_int::from(todata(k, Target::Params(params), &mut pushed, true))
    }
}

/// `rsa_gettable_params`'s list.
static GETTABLE: Params<38> = Params([
    // `OSSL_PARAM_int`s.
    defn(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, size_of::<c_int>()),
    defn(
        OSSL_PKEY_PARAM_SECURITY_BITS,
        OSSL_PARAM_INTEGER,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_PKEY_PARAM_MAX_SIZE,
        OSSL_PARAM_INTEGER,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
        OSSL_PARAM_INTEGER,
        size_of::<c_int>(),
    ),
    defn(OSSL_PKEY_PARAM_DEFAULT_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_RSA_N, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_E, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_D, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR2, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR3, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR4, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR5, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR6, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR7, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR8, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR9, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(OSSL_PKEY_PARAM_RSA_FACTOR10, OSSL_PARAM_UNSIGNED_INTEGER, 0),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT1,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT2,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT3,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT4,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT5,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT6,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT7,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT8,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT9,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_EXPONENT10,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT2,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT3,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT4,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT5,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT6,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT7,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT8,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_COEFFICIENT9,
        OSSL_PARAM_UNSIGNED_INTEGER,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `rsa_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsa_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `rsa_dup` (`ossl_rsa_dup`): a copy with the public numbers for any key pair
    /// selection, and the private ones for a private selection; the kind and restrictions
    /// always. NULL without a key pair selection.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn rsa_dup(keydata: *const c_void, selection: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { key(keydata) }) else { return ptr::null_mut() };
        if selection & KEYPAIR == 0 {
            return ptr::null_mut();
        }
        let st = r.snapshot();
        let copy = Rsa::new_handle_in(r.libctx.get(), st.kind);
        // SAFETY: the handle just made.
        let Some(c) = (unsafe { rsa(copy) }) else { return ptr::null_mut() };
        {
            let mut d = c.lock();
            d.pss = st.pss;
            d.key.blinding = st.key.blinding;
            d.key.multi = st.key.multi;
            d.key.n = st.key.n.clone();
            d.key.e = st.key.e.clone();
            if selection & PRIVATE != 0 {
                d.key.d = st.key.d.clone();
                d.key.p = st.key.p.clone();
                d.key.q = st.key.q.clone();
                d.key.dmp1 = st.key.dmp1.clone();
                d.key.dmq1 = st.key.dmq1.clone();
                d.key.iqmp = st.key.iqmp.clone();
                d.key.extra = st.key.extra.clone();
            }
        }
        copy.cast()
    }
}

ffi_callback! {
    /// `rsapss_query_operation_name`: RSA-PSS keys run RSA's operations.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsapss_query_operation_name(_operation_id: c_int) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        c"RSA".as_ptr()
    }
}

type NewFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type HasFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;
/// `struct rsa_gen_ctx`.
struct GenCtx {
    libctx: *mut OSSL_LIB_CTX,
    kind: Kind,
    nbits: usize,
    pub_exp: BigNum,
    primes: usize,
    pss: Pss30,
    pss_defaults_set: bool,
    cb: OSSL_CALLBACK,
    cbarg: *mut c_void,
}

/// The generation context behind `genctx`.
///
/// # Safety
/// `genctx` is NULL or a live context from `gen_init`.
unsafe fn gen_ctx<'a>(genctx: *mut c_void) -> Option<&'a mut GenCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<GenCtx>(genctx) }
}

/// `gen_init`.
///
/// # Safety
/// `provctx` is the default provider's context; `params` is NULL or an array.
unsafe fn gen_init(
    provctx: *mut c_void,
    selection: c_int,
    kind: Kind,
    params: *const OSSL_PARAM,
) -> *mut c_void {
    if selection & KEYPAIR == 0 {
        return ptr::null_mut();
    }
    let g = boxed(GenCtx {
        // SAFETY: the caller's guarantee.
        libctx: unsafe { libctx_of(provctx) },
        kind,
        nbits: 2048,
        pub_exp: BigNum::from_word(RSA_F4.unsigned_abs()),
        primes: usize::try_from(RSA_DEFAULT_PRIME_NUM).unwrap_or(2),
        pss: Pss30::default(),
        pss_defaults_set: false,
        cb: None,
        cbarg: ptr::null_mut(),
    });
    // SAFETY: the context just made; the caller's array.
    if unsafe { rsa_gen_set_params(g, params) } != 1 {
        // SAFETY: the context just made, freed once.
        unsafe { unbox::<GenCtx>(g) };
        return ptr::null_mut();
    }
    g
}

ffi_callback! {
    /// `rsa_gen_init`.
    ///
    /// # Safety
    /// As for `gen_init`.
    pub(crate) unsafe extern "C" fn rsa_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { gen_init(provctx, selection, Kind::Rsa, params) }
    }
}

ffi_callback! {
    /// `rsapss_gen_init`.
    ///
    /// # Safety
    /// As for `gen_init`.
    pub(crate) unsafe extern "C" fn rsapss_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { gen_init(provctx, selection, Kind::RsaPss, params) }
    }
}

ffi_callback! {
    /// `rsa_gen_set_params`: the size, the number of primes, the public exponent, and (for
    /// RSA-PSS) the restrictions, each committed as it's read.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn rsa_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_RSA_BITS) } {
            // SAFETY: a parameter of the array; the context's field.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut g.nbits) } != 1 {
                return 0;
            }
            if g.nbits < MIN_MODULUS_BITS {
                err::raise(ERR_LIB_PROV, PROV_R_KEY_SIZE_TOO_SMALL, "rsa_gen_set_params");
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_RSA_PRIMES) } {
            // SAFETY: as above.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut g.primes) } != 1 {
                return 0;
            }
        }
        // SAFETY: the caller's array.
        match unsafe { get_bn(params, OSSL_PKEY_PARAM_RSA_E) } {
            Ok(Some(e)) => g.pub_exp = e,
            Ok(None) => {}
            Err(()) => return 0,
        }
        if g.kind == Kind::RsaPss {
            // SAFETY: the caller's array; the context's library context.
            let ok = unsafe { pss_fromdata(&mut g.pss, &mut g.pss_defaults_set, params, g.libctx) };
            if !ok {
                return 0;
            }
        }
        1
    }
}

/// `rsa_gen_basic`, then (for RSA-PSS) `rsa_gen_pss`.
static GEN_SETTABLE: Params<4> = Params([
    defn(
        OSSL_PKEY_PARAM_RSA_BITS,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<usize>(),
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_PRIMES,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<usize>(),
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_E,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        0,
    ),
    PARAM_END,
]);
static PSS_GEN_SETTABLE: Params<9> = Params([
    defn(
        OSSL_PKEY_PARAM_RSA_BITS,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<usize>(),
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_PRIMES,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<usize>(),
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_E,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_DIGEST,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_DIGEST_PROPS,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_MASKGENFUNC,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_MGF1_DIGEST,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(
        OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `rsa_gen_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsa_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `rsapss_gen_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rsapss_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        PSS_GEN_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `rsa_gencb`: a progress event, passed to the generation's callback as `potential` and
    /// `iteration`.
    ///
    /// # Safety
    /// `cb` is a live `BN_GENCB` whose argument is a live generation context.
    pub(crate) unsafe extern "C" fn rsa_gencb(p: c_int, n: c_int, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let arg = unsafe { BN_GENCB_get_arg(cb) };
        // SAFETY: as above.
        let Some(g) = (unsafe { gen_ctx(arg) }) else { return 0 };
        let (mut p, mut n) = (p, n);
        let params = [
            // SAFETY: locals that outlive the call.
            unsafe { OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL.as_ptr(), &raw mut p) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION.as_ptr(), &raw mut n) },
            end(),
        ];
        match g.cb {
            // SAFETY: the application's callback and argument; no lock is held.
            Some(f) => unsafe { f(params.as_ptr(), g.cbarg) },
            // EVP always passes a callback; going on is all one can do without.
            None => 1,
        }
    }
}

/// A `size_t` as the C's `int` cast: its low 32 bits, as `RSA_generate_multi_prime_key`'s
/// arguments get them.
fn c_int_cast(v: usize) -> c_int {
    let low = u32::try_from(v & 0xffff_ffff).unwrap_or(0);
    c_int::from_ne_bytes(low.to_ne_bytes())
}

ffi_callback! {
    /// `rsa_gen`: a new key, or NULL with the generator's errors raised.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `cb` is NULL or a callback taking
    /// `cbarg`.
    pub(crate) unsafe extern "C" fn rsa_gen(genctx: *mut c_void, cb: OSSL_CALLBACK, cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return ptr::null_mut() };
        if g.kind == Kind::Rsa && g.pss.restricted() {
            return ptr::null_mut();
        }
        g.cb = cb;
        g.cbarg = cbarg;
        let (libctx, bits, primes, e) =
            (g.libctx, c_int_cast(g.nbits), c_int_cast(g.primes), g.pub_exp.clone());
        let (kind, pss) = (g.kind, g.pss);
        // SAFETY: no preconditions.
        let gencb = unsafe { BN_GENCB_new() };
        if !gencb.is_null() {
            // SAFETY: the holder just made; the callback reads the context, live for the call.
            unsafe { BN_GENCB_set(gencb, Some(rsa_gencb), genctx) };
        }
        // SAFETY: the context's library context; the holder, or NULL.
        let key = unsafe { generate_key(libctx, bits, primes, Some(&e), gencb) };
        // SAFETY: the holder made above, or NULL.
        unsafe { BN_GENCB_free(gencb) };
        let Some(key) = key else { return ptr::null_mut() };
        let h = Rsa::new_handle_in(libctx, kind);
        // SAFETY: the handle just made.
        let Some(r) = (unsafe { rsa(h) }) else { return ptr::null_mut() };
        {
            let mut st = r.lock();
            st.key = key;
            st.pss = pss;
        }
        h.cast()
    }
}

ffi_callback! {
    /// `rsa_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn rsa_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

/// `common_load`: the key the reference points to, if it's of `kind`, detached from the
/// reference (which then holds NULL).
///
/// # Safety
/// `reference` is NULL or points to `reference_sz` octets holding a live key's pointer.
unsafe fn common_load(reference: *const c_void, reference_sz: usize, kind: Kind) -> *mut c_void {
    if reference.is_null() || reference_sz != size_of::<*mut RSA>() {
        return ptr::null_mut();
    }
    let slot = reference.cast::<*mut RSA>().cast_mut();
    // SAFETY: the caller's guarantee: a key's pointer.
    let h = unsafe { slot.read_unaligned() };
    // SAFETY: as above.
    if !unsafe { rsa(h) }.is_some_and(|r| r.lock().kind == kind) {
        return ptr::null_mut();
    }
    // SAFETY: as above: writable. The key is detached from the reference, as OpenSSL's.
    unsafe { slot.write_unaligned(ptr::null_mut()) };
    h.cast()
}

ffi_callback! {
    /// `rsa_load`.
    ///
    /// # Safety
    /// As for `common_load`.
    pub(crate) unsafe extern "C" fn rsa_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { common_load(reference, reference_sz, Kind::Rsa) }
    }
}

ffi_callback! {
    /// `rsapss_load`.
    ///
    /// # Safety
    /// As for `common_load`.
    pub(crate) unsafe extern "C" fn rsapss_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { common_load(reference, reference_sz, Kind::RsaPss) }
    }
}

ffi_callback! {
    /// `rsa_validate`: the whole key pairwise (`RSA_check_key`'s checks), or the private key's
    /// range and the public key's SP 800-56B checks.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn rsa_validate(keydata: *const c_void, selection: c_int, _checktype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(r) = (unsafe { key(keydata) }) else { return 0 };
        if selection & POSSIBLE == 0 {
            return 1;
        }
        let st = r.snapshot();
        if selection & KEYPAIR == KEYPAIR {
            // SAFETY: the key's library context; no callback.
            return c_int::from(unsafe { validate_keypair(r.libctx.get(), &st.key, ptr::null_mut()) } > 0);
        }
        let mut ok = true;
        if selection & PRIVATE != 0 {
            ok = validate_private(&st.key);
        }
        if selection & PUBLIC != 0 {
            // SAFETY: the key's library context.
            ok = ok && unsafe { validate_public(r.libctx.get(), &st.key) };
        }
        c_int::from(ok)
    }
}

type MatchFn = unsafe extern "C" fn(*const c_void, *const c_void, c_int) -> c_int;
type ImportFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> c_int;
type TypesFn = unsafe extern "C" fn(c_int) -> *const OSSL_PARAM;
type ExportFn = unsafe extern "C" fn(*mut c_void, c_int, OSSL_CALLBACK, *mut c_void) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type GettableFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type DupFn = unsafe extern "C" fn(*const c_void, c_int) -> *mut c_void;
type QueryFn = unsafe extern "C" fn(c_int) -> *const c_char;
type GenInitFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type GenListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type GenFn = unsafe extern "C" fn(*mut c_void, OSSL_CALLBACK, *mut c_void) -> *mut c_void;
type LoadFn = unsafe extern "C" fn(*const c_void, usize) -> *mut c_void;
type ValidateFn = unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int;

/// `ossl_rsa_keymgmt_functions`.
pub(crate) static RSA_KEYMGMT: Dispatch<19> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, rsa_newdata, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, rsa_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        rsa_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        rsa_gen_settable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, rsa_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, rsa_gen_cleanup, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_LOAD, rsa_load, LoadFn),
    entry!(OSSL_FUNC_KEYMGMT_VALIDATE, rsa_validate, ValidateFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, rsa_freedata, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, rsa_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        rsa_gettable_params,
        GettableFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, rsa_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, rsa_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, rsa_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, rsa_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, rsa_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, rsa_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_DUP, rsa_dup, DupFn),
    END,
]);

/// `ossl_rsapss_keymgmt_functions`.
pub(crate) static RSAPSS_KEYMGMT: Dispatch<20> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, rsapss_newdata, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, rsapss_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        rsa_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        rsapss_gen_settable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, rsa_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, rsa_gen_cleanup, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_LOAD, rsapss_load, LoadFn),
    entry!(OSSL_FUNC_KEYMGMT_VALIDATE, rsa_validate, ValidateFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, rsa_freedata, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, rsa_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        rsa_gettable_params,
        GettableFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, rsa_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, rsa_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, rsa_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, rsa_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, rsa_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, rsa_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_DUP, rsa_dup, DupFn),
    entry!(
        OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        rsapss_query_operation_name,
        QueryFn
    ),
    END,
]);
