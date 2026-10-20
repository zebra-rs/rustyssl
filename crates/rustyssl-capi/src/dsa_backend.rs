//! DSA's backend for the key manager and the legacy ASN.1 method (`dsa_backend.c`,
//! `dsa_check.c`): the key from and to parameters (the FFC parameters through
//! `crate::dh_backend`'s, which DH and DSA share), copies by selection, and the checks.

use core::ffi::c_int;
use core::ptr;

use rustyssl_abi::{
    CRYPTO_EX_INDEX_DSA, DSA, DSA_R_BAD_FFC_PARAMETERS, DSA_R_BAD_Q_VALUE, DSA_R_MODULUS_TOO_LARGE,
    ERR_LIB_BN, ERR_LIB_DSA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, OPENSSL_DSA_MAX_MODULUS_BITS,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_KEYMGMT_VALIDATE_QUICK_CHECK, OSSL_PARAM,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum};

use crate::dh_backend::{ffc_fromdata, ffc_todata};
use crate::dsa::{Dsa, DsaState, dsa};
use crate::ec::params::{Kept, Target};
use crate::err;
use crate::ex_data::CRYPTO_dup_ex_data;
use crate::ffc::{self, Type};

/// `ossl_dsa_ffc_params_fromdata`.
///
/// # Safety
/// `params` is NULL or a parameter array.
pub(crate) unsafe fn params_fromdata(st: &mut DsaState, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { ffc_fromdata(&mut st.params, params) }
}

/// `ossl_dsa_key_fromdata`: the public key and (if `include_private`) the private key, each
/// replacing the key's when given.
///
/// # Safety
/// `params` is NULL or a parameter array.
pub(crate) unsafe fn key_fromdata(
    st: &mut DsaState,
    params: *const OSSL_PARAM,
    include_private: bool,
) -> bool {
    let mut dh = crate::dh::DhState {
        pub_key: st.pub_key.take(),
        priv_key: st.priv_key.take(),
        ..crate::dh::DhState::default()
    };
    // SAFETY: the caller's guarantee.
    let ok = unsafe { crate::dh_backend::key_fromdata(&mut dh, params, include_private) };
    st.pub_key = dh.pub_key;
    st.priv_key = dh.priv_key;
    st.secure_private();
    ok
}

/// `dsa_key_todata`: the private key (if `include_private`) and the public key, those the key
/// has.
///
/// # Safety
/// The target is live; `st` and `kept` outlive a builder's making its array.
pub(crate) unsafe fn key_todata(
    st: &DsaState,
    target: Target,
    kept: &mut Kept,
    include_private: bool,
) -> bool {
    for (name, v, wanted) in [
        (OSSL_PKEY_PARAM_PRIV_KEY, &st.priv_key, include_private),
        (OSSL_PKEY_PARAM_PUB_KEY, &st.pub_key, true),
    ] {
        let Some(v) = v.as_ref().filter(|_| wanted) else {
            continue;
        };
        // SAFETY: the caller's guarantee.
        if !unsafe { target.wants(name) } {
            continue;
        }
        let b = kept.number();
        if b.is_null() {
            return false;
        }
        // SAFETY: the number just made.
        let stored = unsafe { crate::bn::store(b, v.clone()) };
        // SAFETY: the caller's target; the number lives as long as `kept`.
        if !stored || !unsafe { target.bn(name, b) } {
            return false;
        }
    }
    true
}

/// `ossl_ffc_params_todata` of the key's parameters.
///
/// # Safety
/// As for [`key_todata`].
pub(crate) unsafe fn params_todata(st: &DsaState, target: Target, kept: &mut Kept) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { ffc_todata(&st.params, target, kept) }
}

/// `ossl_dsa_is_foreign`: the key's method isn't OpenSSL's.
pub(crate) fn is_foreign(k: &Dsa) -> bool {
    // SAFETY: no preconditions.
    k.meth() != unsafe { crate::dsa_meth::DSA_OpenSSL() }
}

/// `ossl_dsa_dup`: a new key with the flags and (as selected) the parameters and key pair (a
/// key part only with the parameters), and a copy of the application data. NULL for a foreign
/// key.
///
/// # Safety
/// `h` is a live key.
pub(crate) unsafe fn dup(h: *const DSA, selection: c_int) -> *mut DSA {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dsa(h) }) else {
        return ptr::null_mut();
    };
    if is_foreign(k) {
        return ptr::null_mut();
    }
    let src = k.snapshot();
    let domain = selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS != 0;
    if !domain
        && selection & (OSSL_KEYMGMT_SELECT_PUBLIC_KEY | OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
    {
        return ptr::null_mut();
    }
    let mut st = DsaState::default();
    if domain {
        st.params = src.params.clone();
    }
    if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
        st.pub_key = src.pub_key.clone();
    }
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        st.priv_key = src.priv_key.clone();
        st.secure_private();
    }
    let out = if k.is_in_libctx() {
        Dsa::new_handle_provided(k.libctx.get())
    } else {
        Dsa::new_handle_in(k.libctx.get())
    };
    // SAFETY: just made, or NULL.
    let Some(d) = (unsafe { dsa(out) }) else {
        return ptr::null_mut();
    };
    d.replace(st);
    d.set_flags_to(k.flags());
    // SAFETY: both keys' own application data.
    if unsafe { CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DSA, d.ex_data(), k.ex_data()) } == 0 {
        // SAFETY: the key made above.
        unsafe { crate::dsa::free(out) };
        return ptr::null_mut();
    }
    out
}

/// `dsa_precheck_params`: p and q, p not too long, q shorter than p; else the error.
fn precheck(st: &DsaState) -> bool {
    const F: &str = "dsa_precheck_params";
    let (Some(p), Some(q)) = (&st.params.p, &st.params.q) else {
        err::raise(ERR_LIB_DSA, DSA_R_BAD_FFC_PARAMETERS, F);
        return false;
    };
    if p.num_bits() > usize::try_from(OPENSSL_DSA_MAX_MODULUS_BITS).unwrap_or(10000) {
        err::raise(ERR_LIB_DSA, DSA_R_MODULUS_TOO_LARGE, F);
        return false;
    }
    if q.num_bits() >= p.num_bits() {
        err::raise(ERR_LIB_DSA, DSA_R_BAD_Q_VALUE, F);
        return false;
    }
    true
}

/// `ossl_dsa_check_params`: the simple validation for a quick check, else the full one.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn check_params(
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    st: &DsaState,
    checktype: c_int,
) -> bool {
    if !precheck(st) {
        return false;
    }
    let mut res = 0;
    if checktype == OSSL_KEYMGMT_VALIDATE_QUICK_CHECK {
        // SAFETY: the caller's guarantee.
        unsafe { ffc::simple_validate(libctx, &st.params, Type::Dsa, &mut res) }
    } else {
        // SAFETY: as above.
        unsafe { ffc::full_validate(libctx, &st.params, Type::Dsa, &mut res) }
    }
}

/// `ossl_dsa_check_pub_key`.
pub(crate) fn check_pub_key(st: &DsaState, y: &BigNum) -> bool {
    if !precheck(st) {
        return false;
    }
    let mut res = 0;
    ffc::validate_public_key(&st.params, y, &mut res) && res == 0
}

/// `ossl_dsa_check_priv_key`: `1 <= x < q`.
pub(crate) fn check_priv_key(st: &DsaState, x: &BigNum) -> bool {
    if !precheck(st) {
        return false;
    }
    let Some(q) = &st.params.q else {
        return false;
    };
    let mut res = 0;
    ffc::validate_private_key(q, x, &mut res)
}

/// `ossl_dsa_generate_public_key`: `g^x mod p` (`BN_mod_exp` with a constant-time exponent: an
/// odd p only).
pub(crate) fn generate_public_key(st: &DsaState, x: &BigNum) -> Option<BigNum> {
    let (p, g) = (st.params.p.as_ref()?, st.params.g.as_ref()?);
    if !p.is_odd() {
        err::raise(
            ERR_LIB_BN,
            ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
            "BN_mod_exp_recp",
        );
        return None;
    }
    core_bn::modular::exp_mod(g, x, p).ok()
}

/// `ossl_dsa_check_pairwise`: the public key is `g^x mod p`.
pub(crate) fn check_pairwise(st: &DsaState) -> bool {
    if !precheck(st) {
        return false;
    }
    let (Some(_), Some(x), Some(y)) = (&st.params.g, &st.priv_key, &st.pub_key) else {
        return false;
    };
    generate_public_key(st, x).is_some_and(|y2| core_bn::cmp(&y2, y).is_eq())
}
