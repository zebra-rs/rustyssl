//! DH's backend for the key managers and the legacy ASN.1 method (`dh_backend.c`,
//! `ffc_backend.c`, `ffc_params.c`'s `ossl_ffc_params_todata`, `dh_key.c`'s
//! `ossl_dh_key2buf` and `ossl_dh_buf2key`, `dh_check.c`'s private-key and pairwise checks,
//! `dh_gen.c`'s FFC generation, and `dh_support.c`'s generation types).
//!
//! Unlike OpenSSL's, a key here keeps its own copy of the FFC digest's name and properties:
//! OpenSSL's keeps the pointers it's given, which dangle once the parameter array (or the
//! generation context) that held them is gone (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_int, c_long, c_uint};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    BIGNUM, BN_GENCB, CRYPTO_EX_INDEX_DH, DH, DH_PARAMGEN_TYPE_FIPS_186_2,
    DH_PARAMGEN_TYPE_FIPS_186_4, DH_PARAMGEN_TYPE_GENERATOR, DH_PARAMGEN_TYPE_GROUP, DH_R_BN_ERROR,
    DH_R_INVALID_PUBKEY, DH_R_INVALID_SIZE, DH_R_NO_PARAMETERS_SET, ERR_LIB_DH, NID_ffdhe2048,
    NID_ffdhe3072, NID_ffdhe4096, NID_ffdhe6144, NID_ffdhe8192,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PARAM, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING,
    OSSL_PKEY_PARAM_DH_PRIV_LEN, OSSL_PKEY_PARAM_FFC_COFACTOR, OSSL_PKEY_PARAM_FFC_DIGEST,
    OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_GINDEX,
    OSSL_PKEY_PARAM_FFC_H, OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_PCOUNTER,
    OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_FFC_SEED, OSSL_PKEY_PARAM_FFC_VALIDATE_G,
    OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY, OSSL_PKEY_PARAM_FFC_VALIDATE_PQ,
    OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};
use rustyssl_crypto::bn::{BigNum, Endian};
use rustyssl_crypto::ffc as groups;

use crate::bn::{BN_clear_free, store, value};
use crate::dh::{Dh, DhState, dh};
use crate::ec::params::{Kept, Target, text};
use crate::err;
use crate::ex_data::CRYPTO_dup_ex_data;
use crate::ffc::{self, Type};
use crate::params::bn::OSSL_PARAM_get_BN;
use crate::params::{OSSL_PARAM_get_int, OSSL_PARAM_get_long};
use crate::provider::macs::locate;
use crate::rsa_gen::Env;

/// The private key length as `DH_set_length` keeps it: the low 32 bits.
pub(crate) fn length_of(l: c_long) -> i32 {
    let low = u32::try_from(l.rem_euclid(1 << 32)).unwrap_or(0);
    i32::from_ne_bytes(low.to_ne_bytes())
}

/// The number in a parameter (`OSSL_PARAM_get_BN`), or `None` with its errors raised.
///
/// # Safety
/// `p` is a live parameter.
unsafe fn get_bn(p: &OSSL_PARAM) -> Option<BigNum> {
    let mut b: *mut BIGNUM = ptr::null_mut();
    // SAFETY: the caller's guarantee; a place for a new number.
    if unsafe { OSSL_PARAM_get_BN(p, &raw mut b) } != 1 {
        return None;
    }
    // SAFETY: the number just made, freed once.
    let v = unsafe { value(b) };
    // SAFETY: as above.
    unsafe { BN_clear_free(b) };
    v
}

/// An int parameter (`OSSL_PARAM_get_int`), or `None`.
///
/// # Safety
/// `p` is a live parameter.
unsafe fn get_int(p: &OSSL_PARAM) -> Option<c_int> {
    let mut v = 0;
    // SAFETY: the caller's guarantee; a local.
    (unsafe { OSSL_PARAM_get_int(p, &raw mut v) } == 1).then_some(v)
}

/// A UTF-8 string parameter's text as a C string (up to its first NUL), or `None` for another
/// type or no data.
///
/// # Safety
/// `p` is a live parameter.
pub(crate) unsafe fn utf8(p: &OSSL_PARAM) -> Option<CString> {
    // SAFETY: the caller's guarantee.
    let t = unsafe { text(p) }??;
    CString::new(t).ok()
}

/// `ossl_ffc_params_fromdata`: the named group (setting p, q, and g), p, q, g, the index,
/// counter, cofactor (replaced, or cleared without one), h, seed, validation flags, and digest,
/// as `params` has them. False for a malformed parameter or an unknown group (nothing raised
/// for those, as in OpenSSL).
///
/// # Safety
/// `params` is NULL or a parameter array.
pub(crate) unsafe fn ffc_fromdata(f: &mut ffc::Params, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee (for each lookup below).
    let find = |name: &CStr| unsafe { locate(params, name) };
    if let Some(p) = find(OSSL_PKEY_PARAM_GROUP_NAME) {
        if p.data_type != OSSL_PARAM_UTF8_STRING.cast_unsigned() || p.data.is_null() {
            return false;
        }
        // SAFETY: a parameter of the array.
        let Some(name) = (unsafe { utf8(p) }) else {
            return false;
        };
        let Some(group) = name.to_str().ok().and_then(groups::by_name) else {
            return false;
        };
        f.set_named_group(group);
    }
    let mut pqg = [None, None, None];
    for (slot, name) in pqg.iter_mut().zip([
        OSSL_PKEY_PARAM_FFC_P,
        OSSL_PKEY_PARAM_FFC_Q,
        OSSL_PKEY_PARAM_FFC_G,
    ]) {
        if let Some(p) = find(name) {
            // SAFETY: a parameter of the array.
            let Some(v) = (unsafe { get_bn(p) }) else {
                return false;
            };
            *slot = Some(v);
        }
    }
    let ints = [
        (OSSL_PKEY_PARAM_FFC_GINDEX, &mut f.gindex),
        (OSSL_PKEY_PARAM_FFC_PCOUNTER, &mut f.pcounter),
    ];
    for (name, slot) in ints {
        if let Some(p) = find(name) {
            // SAFETY: a parameter of the array.
            let Some(v) = (unsafe { get_int(p) }) else {
                return false;
            };
            *slot = v;
        }
    }
    let mut j = None;
    if let Some(p) = find(OSSL_PKEY_PARAM_FFC_COFACTOR) {
        // SAFETY: a parameter of the array.
        let Some(v) = (unsafe { get_bn(p) }) else {
            return false;
        };
        j = Some(v);
    }
    if let Some(p) = find(OSSL_PKEY_PARAM_FFC_H) {
        // SAFETY: a parameter of the array.
        let Some(v) = (unsafe { get_int(p) }) else {
            return false;
        };
        f.h = v;
    }
    if let Some(p) = find(OSSL_PKEY_PARAM_FFC_SEED) {
        if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
            return false;
        }
        f.seed = if p.data.is_null() || p.data_size == 0 {
            None
        } else {
            // SAFETY: the parameter's data of its size.
            Some(unsafe { core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) }.to_vec())
        };
    }
    let flags = [
        (OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, ffc::VALIDATE_PQ),
        (OSSL_PKEY_PARAM_FFC_VALIDATE_G, ffc::VALIDATE_G),
        (OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY, ffc::VALIDATE_LEGACY),
    ];
    for (name, flag) in flags {
        if let Some(p) = find(name) {
            // SAFETY: a parameter of the array.
            let Some(v) = (unsafe { get_int(p) }) else {
                return false;
            };
            enable_flags(f, flag, v != 0);
        }
    }
    if let Some(p) = find(OSSL_PKEY_PARAM_FFC_DIGEST) {
        if p.data_type != OSSL_PARAM_UTF8_STRING.cast_unsigned() {
            return false;
        }
        let mut props = None;
        if let Some(q) = find(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS) {
            if q.data_type != OSSL_PARAM_UTF8_STRING.cast_unsigned() {
                return false;
            }
            // SAFETY: a parameter of the array.
            props = unsafe { utf8(q) };
        }
        // SAFETY: as above.
        f.mdname = unsafe { utf8(p) };
        f.mdprops = props;
    }
    let [p, q, g] = pqg;
    if p.is_some() {
        f.p = p;
    }
    if q.is_some() {
        f.q = q;
    }
    if g.is_some() {
        f.g = g;
    }
    f.j = j;
    true
}

/// `ossl_ffc_params_enable_flags`.
pub(crate) fn enable_flags(f: &mut ffc::Params, flags: c_uint, enable: bool) {
    if enable {
        f.flags |= flags;
    } else {
        f.flags &= !flags;
    }
}

/// `ossl_dh_params_fromdata`: the FFC parameters (with the named group they are cached), then
/// the private key length.
///
/// # Safety
/// `params` is NULL or a parameter array.
pub(crate) unsafe fn params_fromdata(st: &mut DhState, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    if !unsafe { ffc_fromdata(&mut st.params, params) } {
        return false;
    }
    Dh::cache_named_group(st);
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_DH_PRIV_LEN) } {
        let mut l: c_long = 0;
        // SAFETY: a parameter of the array; a local.
        if unsafe { OSSL_PARAM_get_long(p, &raw mut l) } != 1 {
            return false;
        }
        st.length = length_of(l);
    }
    true
}

/// `ossl_dh_key_fromdata`: the public key and (if `include_private`) the private key, each
/// replacing the key's when given.
///
/// # Safety
/// `params` is NULL or a parameter array.
pub(crate) unsafe fn key_fromdata(
    st: &mut DhState,
    params: *const OSSL_PARAM,
    include_private: bool,
) -> bool {
    // SAFETY: the caller's guarantee (for each lookup below).
    let find = |name: &CStr| unsafe { locate(params, name) };
    let mut priv_key = None;
    if include_private && let Some(p) = find(OSSL_PKEY_PARAM_PRIV_KEY) {
        // SAFETY: a parameter of the array.
        let Some(v) = (unsafe { get_bn(p) }) else {
            return false;
        };
        priv_key = Some(v);
    }
    let mut pub_key = None;
    if let Some(p) = find(OSSL_PKEY_PARAM_PUB_KEY) {
        // SAFETY: as above.
        let Some(v) = (unsafe { get_bn(p) }) else {
            return false;
        };
        pub_key = Some(v);
    }
    if pub_key.is_some() {
        st.pub_key = pub_key;
    }
    if priv_key.is_some() {
        st.priv_key = priv_key;
    }
    true
}

/// `ossl_param_build_set_bn` of a number, kept until a builder makes its array.
///
/// # Safety
/// The target is live.
unsafe fn set_bn(target: Target, kept: &mut Kept, name: &CStr, v: &BigNum) -> bool {
    // SAFETY: the caller's guarantee.
    if !unsafe { target.wants(name) } {
        return true;
    }
    let b = kept.number();
    // SAFETY: the number just made.
    if b.is_null() || !unsafe { store(b, v.clone()) } {
        return false;
    }
    // SAFETY: the caller's guarantee; the number lives as long as `kept`.
    unsafe { target.bn(name, b) }
}

/// `ossl_ffc_params_todata`: p, q, g, j, the index, counter, h, seed, group name, validation
/// flags, and digest.
///
/// # Safety
/// The target is live; `f` and `kept` outlive a builder's making its array.
pub(crate) unsafe fn ffc_todata(f: &ffc::Params, target: Target, kept: &mut Kept) -> bool {
    let numbers = [
        (OSSL_PKEY_PARAM_FFC_P, &f.p),
        (OSSL_PKEY_PARAM_FFC_Q, &f.q),
        (OSSL_PKEY_PARAM_FFC_G, &f.g),
        (OSSL_PKEY_PARAM_FFC_COFACTOR, &f.j),
    ];
    for (name, v) in numbers {
        if let Some(v) = v
            // SAFETY: the caller's guarantee.
            && !unsafe { set_bn(target, kept, name, v) }
        {
            return false;
        }
    }
    let ints = [
        (OSSL_PKEY_PARAM_FFC_GINDEX, f.gindex),
        (OSSL_PKEY_PARAM_FFC_PCOUNTER, f.pcounter),
        (OSSL_PKEY_PARAM_FFC_H, f.h),
    ];
    for (name, v) in ints {
        // SAFETY: the caller's guarantee.
        if !unsafe { target.int(name, v) } {
            return false;
        }
    }
    if let Some(seed) = f.seed.as_deref()
        // SAFETY: the caller's guarantee; the seed outlives the array's making.
        && !unsafe { target.octets(OSSL_PKEY_PARAM_FFC_SEED, seed) }
    {
        return false;
    }
    if f.nid != 0 {
        let Some(name) = groups::by_uid(f.nid).and_then(|g| CString::new(g.name).ok()) else {
            return false;
        };
        let name = kept.string(name);
        // SAFETY: as above; the name is kept.
        if !unsafe { target.utf8(OSSL_PKEY_PARAM_GROUP_NAME, name) } {
            return false;
        }
    }
    let flags = [
        (OSSL_PKEY_PARAM_FFC_VALIDATE_PQ, ffc::VALIDATE_PQ),
        (OSSL_PKEY_PARAM_FFC_VALIDATE_G, ffc::VALIDATE_G),
        (OSSL_PKEY_PARAM_FFC_VALIDATE_LEGACY, ffc::VALIDATE_LEGACY),
    ];
    for (name, flag) in flags {
        // SAFETY: as above.
        if !unsafe { target.int(name, c_int::from(f.flags & flag != 0)) } {
            return false;
        }
    }
    for (name, v) in [
        (OSSL_PKEY_PARAM_FFC_DIGEST, &f.mdname),
        (OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, &f.mdprops),
    ] {
        if let Some(v) = v
            // SAFETY: as above; `f` outlives the array's making.
            && !unsafe { target.utf8(name, v) }
        {
            return false;
        }
    }
    true
}

/// `ossl_dh_params_todata`: the FFC parameters, and the private key length if set.
///
/// # Safety
/// As for [`ffc_todata`].
pub(crate) unsafe fn params_todata(st: &DhState, target: Target, kept: &mut Kept) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { ffc_todata(&st.params, target, kept) })
        // SAFETY: as above.
        && (st.length <= 0 || unsafe { target.long(OSSL_PKEY_PARAM_DH_PRIV_LEN, c_long::from(st.length)) })
}

/// `ossl_dh_key_todata`: the private key (if `include_private`) and the public key, those the
/// key has.
///
/// # Safety
/// As for [`ffc_todata`].
pub(crate) unsafe fn key_todata(
    st: &DhState,
    target: Target,
    kept: &mut Kept,
    include_private: bool,
) -> bool {
    if include_private
        && let Some(x) = &st.priv_key
        // SAFETY: the caller's guarantee.
        && !unsafe { set_bn(target, kept, OSSL_PKEY_PARAM_PRIV_KEY, x) }
    {
        return false;
    }
    if let Some(y) = &st.pub_key
        // SAFETY: as above.
        && !unsafe { set_bn(target, kept, OSSL_PKEY_PARAM_PUB_KEY, y) }
    {
        return false;
    }
    true
}

/// `ossl_dh_key2buf` into a caller's buffer: the public key padded to the prime's length (RFC
/// 8446 4.2.8.1) into `out` if given (and big enough), and that length; 0 with
/// `DH_R_INVALID_PUBKEY` without a prime or public key, or `DH_R_INVALID_SIZE` for too little
/// room.
pub(crate) fn key2buf(st: &DhState, out: Option<&mut [u8]>) -> usize {
    const F: &str = "ossl_dh_key2buf";
    let (Some(p), Some(y)) = (&st.params.p, &st.pub_key) else {
        err::raise(ERR_LIB_DH, DH_R_INVALID_PUBKEY, F);
        return 0;
    };
    let p_size = p.num_bytes();
    if p_size == 0 || y.num_bytes() == 0 {
        err::raise(ERR_LIB_DH, DH_R_INVALID_PUBKEY, F);
        return 0;
    }
    if let Some(out) = out {
        let Some(dst) = out.get_mut(..p_size) else {
            err::raise(ERR_LIB_DH, DH_R_INVALID_SIZE, F);
            return 0;
        };
        let Some(v) = y.to_bin(Some(p_size), Endian::Big, false) else {
            err::raise(ERR_LIB_DH, DH_R_BN_ERROR, F);
            return 0;
        };
        dst.copy_from_slice(&v);
    }
    p_size
}

/// `ossl_dh_check_pub_key_partial`: `2 <= y <= p - 2`.
pub(crate) fn check_pub_key_partial(st: &DhState, y: &BigNum) -> bool {
    let mut res = 0;
    ffc::validate_public_key_partial(&st.params, y, &mut res) && res == 0
}

/// `ossl_dh_buf2key`: the public key from big-endian octets, if the key has a prime and the
/// value passes the partial check (RFC 8446 4.2.8.1). False with the error raised.
pub(crate) fn buf2key(k: &Dh, buf: &[u8]) -> bool {
    const F: &str = "ossl_dh_buf2key";
    let Ok(y) = BigNum::from_bin(buf, Endian::Big, false) else {
        err::raise(ERR_LIB_DH, DH_R_BN_ERROR, F);
        return false;
    };
    let mut st = k.snapshot();
    if st.params.p.as_ref().is_none_or(|p| p.num_bytes() == 0) {
        err::raise(ERR_LIB_DH, DH_R_NO_PARAMETERS_SET, F);
        return false;
    }
    if !check_pub_key_partial(&st, &y) {
        err::raise(ERR_LIB_DH, DH_R_INVALID_PUBKEY, F);
        return false;
    }
    st.pub_key = Some(y);
    k.replace(st);
    true
}

/// `ossl_dh_is_foreign`: the key's method isn't OpenSSL's.
pub(crate) fn is_foreign(k: &Dh) -> bool {
    // SAFETY: no preconditions.
    k.meth() != unsafe { crate::dh_meth::DH_OpenSSL() }
}

/// `ossl_dh_is_named_safe_prime_group`: a named group other than RFC 5114's (uids 1 to 3),
/// whose q is (p - 1) / 2.
pub(crate) fn is_named_safe_prime_group(st: &DhState) -> bool {
    st.params.nid > 3
}

/// `ossl_dh_dup`: a new key with the length, flags, and (as selected) the parameters and key
/// pair (a key part only with the parameters), and a copy of the application data. NULL for a
/// foreign key.
///
/// # Safety
/// `h` is a live key.
pub(crate) unsafe fn dup(h: *const DH, selection: c_int) -> *mut DH {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dh(h) }) else {
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
    let mut st = DhState {
        length: src.length,
        ..DhState::default()
    };
    if domain {
        st.params = src.params.clone();
    }
    if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
        st.pub_key = src.pub_key.clone();
    }
    if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        st.priv_key = src.priv_key.clone();
    }
    let out = Dh::new_handle_in(k.libctx.get());
    // SAFETY: just made, or NULL.
    let Some(d) = (unsafe { dh(out) }) else {
        return ptr::null_mut();
    };
    d.replace(st);
    d.set_flags_to(k.flags());
    // SAFETY: both keys' own application data.
    if unsafe { CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_DH, d.ex_data(), k.ex_data()) } == 0 {
        // SAFETY: the key made above.
        unsafe { crate::dh::free(out) };
        return ptr::null_mut();
    }
    out
}

/// `ossl_dh_check_priv_key`: with q, `1 <= x < q` (below `2^length` instead for a named group
/// with a shorter length); without q, x of `length` bits, or (without a length) between 2 and
/// `p`'s bits less one.
pub(crate) fn check_priv_key(st: &DhState, x: &BigNum) -> bool {
    let Some(q) = &st.params.q else {
        let Some(p) = &st.params.p else {
            return false;
        };
        let bits = x.num_bits();
        return if st.length == 0 {
            bits <= p.num_bits().saturating_sub(1) && bits > 1
        } else {
            usize::try_from(st.length).is_ok_and(|l| bits == l)
        };
    };
    let mut upper = q.clone();
    if st.params.nid != 0
        && st.length != 0
        && let Ok(l) = usize::try_from(st.length)
    {
        let mut two_pow = BigNum::zero();
        if two_pow.set_bit(l).is_err() {
            return false;
        }
        if rustyssl_crypto::bn::cmp(&two_pow, q).is_lt() {
            upper = two_pow;
        }
    }
    let mut res = 0;
    ffc::validate_private_key(&upper, x, &mut res)
}

/// `ossl_dh_check_pairwise`: the public key is `g^x mod p` (with the key's method's
/// `bn_mod_exp`); `return_on_null` when a number is missing.
///
/// # Safety
/// `h` is a live key.
pub(crate) unsafe fn check_pairwise(h: *mut DH, return_on_null: bool) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dh(h) }) else {
        return false;
    };
    let st = k.snapshot();
    let (Some(_), Some(_), Some(x), Some(y)) =
        (&st.params.p, &st.params.g, &st.priv_key, &st.pub_key)
    else {
        return return_on_null;
    };
    // SAFETY: the caller's guarantee.
    unsafe { crate::dh_meth::generate_public_key(h, &st, x) }
        .is_some_and(|y2| rustyssl_crypto::bn::cmp(&y2, y).is_eq())
}

/// `ossl_dh_get_named_group_uid_from_size`: the FFDHE group of `pbits`, or 0.
pub(crate) fn named_group_uid_from_size(pbits: usize) -> c_int {
    match pbits {
        2048 => NID_ffdhe2048,
        3072 => NID_ffdhe3072,
        4096 => NID_ffdhe4096,
        6144 => NID_ffdhe6144,
        8192 => NID_ffdhe8192,
        _ => 0,
    }
}

/// `dhtype2id`: each generation type's name, and whether it's DH's only (`Some(false)`),
/// DHX's only (`Some(true)`), or either's.
const GEN_TYPES: [(&str, c_int, Option<bool>); 4] = [
    ("group", DH_PARAMGEN_TYPE_GROUP, None),
    ("generator", DH_PARAMGEN_TYPE_GENERATOR, Some(false)),
    ("fips186_4", DH_PARAMGEN_TYPE_FIPS_186_4, Some(true)),
    ("fips186_2", DH_PARAMGEN_TYPE_FIPS_186_2, Some(true)),
];

/// `ossl_dh_gen_type_name2id`: the generation type `name` names for DH (or DHX), if that key
/// type may use it.
pub(crate) fn gen_type_name2id(name: &[u8], dhx: bool) -> Option<c_int> {
    GEN_TYPES
        .iter()
        .find(|(n, _, ty)| ty.is_none_or(|t| t == dhx) && n.as_bytes() == name)
        .map(|&(_, id, _)| id)
}

/// `ossl_dh_generate_ffc_parameters`: FIPS 186-2 (for `DH_PARAMGEN_TYPE_FIPS_186_2`) or
/// 186-4 parameters of `pbits` and `qbits` into the key's, reporting to `cb`. 1 (2 for an
/// unverifiable generator), or 0.
///
/// # Safety
/// `h` is a live key; `cb` is NULL or a live `BN_GENCB`.
pub(crate) unsafe fn generate_ffc_parameters(
    h: *mut DH,
    gen_type: c_int,
    pbits: usize,
    qbits: usize,
    cb: *mut BN_GENCB,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dh(h) }) else {
        return 0;
    };
    // SAFETY: the key's library context; the caller's callback.
    let Some(env) = (unsafe { Env::new(k.libctx.get(), cb) }) else {
        return 0;
    };
    let mut st = k.snapshot();
    let mut res = 0;
    let ret = if gen_type == DH_PARAMGEN_TYPE_FIPS_186_2 {
        // SAFETY: the key's library context; the context made above.
        unsafe {
            ffc::generate_186_2(
                k.libctx.get(),
                &env,
                &mut st.params,
                Type::Dh,
                pbits,
                qbits,
                &mut res,
            )
        }
    } else {
        // SAFETY: as above.
        unsafe {
            ffc::generate_186_4(
                k.libctx.get(),
                &env,
                &mut st.params,
                Type::Dh,
                pbits,
                qbits,
                &mut res,
            )
        }
    };
    if ret > 0 {
        k.replace(st);
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_types_by_key_type() {
        assert_eq!(
            gen_type_name2id(b"group", false),
            Some(DH_PARAMGEN_TYPE_GROUP)
        );
        assert_eq!(
            gen_type_name2id(b"group", true),
            Some(DH_PARAMGEN_TYPE_GROUP)
        );
        assert_eq!(gen_type_name2id(b"generator", true), None);
        assert_eq!(gen_type_name2id(b"fips186_4", false), None);
        assert_eq!(
            gen_type_name2id(b"fips186_2", true),
            Some(DH_PARAMGEN_TYPE_FIPS_186_2)
        );
        assert_eq!(gen_type_name2id(b"default", true), None);
    }

    /// docs/DEVIATIONS.md: OpenSSL's keeps a pointer to the parameter's data.
    #[test]
    fn the_digest_name_is_copied() {
        let mut f = ffc::Params::default();
        let mut name = *b"SHA256\0";
        let params = [
            // SAFETY: a static key; the local buffer, read during the call.
            unsafe {
                crate::params::OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_FFC_DIGEST.as_ptr(),
                    name.as_mut_ptr().cast(),
                    0,
                )
            },
            crate::params::end(),
        ];
        // SAFETY: the array above.
        assert!(unsafe { ffc_fromdata(&mut f, params.as_ptr()) });
        name.fill(b'x');
        assert_eq!(f.mdname.as_deref(), Some(c"SHA256"));
    }

    #[test]
    fn lengths_keep_32_bits() {
        assert_eq!(length_of(224), 224);
        assert_eq!(length_of(-1), -1);
        assert_eq!(length_of((1 << 32) + 5), 5);
    }
}
