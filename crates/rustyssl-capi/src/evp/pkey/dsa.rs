//! DSA keys in `EVP_PKEY` (`EVP_PKEY_set1_DSA(3)`; `p_lib.c`, `dsa_ameth.c`, `dsa_prn.c`): the
//! built-in DSA ASN.1 method's functions for a key whose legacy data is a `DSA`, the `DSA` of a
//! key, and `DSA_print`/`DSAparams_print`, which print a `DSA` through a key.
//!
//! As in OpenSSL, the method's printing (`do_dsa_print`) heads the parameters and the public
//! key "Public-Key:" without indentation (only a private key gets its own heading, indented),
//! and a key moves between its legacy and provided forms through the parameters the DSA key
//! manager takes.

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_PCTX, ASN1_PKEY_CTRL_DEFAULT_MD_NID, BIO, DSA, ERR_LIB_DSA, ERR_LIB_EVP, ERR_R_DSA_LIB,
    EVP_PKEY, EVP_PKEY_DSA, EVP_R_EXPECTING_A_DSA_KEY, NID_sha256, OSSL_KEYMGMT_SELECT_ALL,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PKEY_PARAM_FFC_G,
    OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PUB_KEY,
};
use rustyssl_crypto::bn::BigNum;

use super::{EVP_PKEY_assign, get_legacy, legacy_data, pkey};
use crate::bio::print::BIO_printf;
use crate::dh_asn1::{bn_print, ffc_print, indent};
use crate::dsa::{DSA_new, Dsa, DsaState, dsa, free, up_ref};
use crate::dsa_asn1::{d2i_DSAPrivateKey, d2i_DSAparams, i2d_DSAparams};
use crate::dsa_backend::{self as backend, key_fromdata, params_fromdata};
use crate::ec::params::{Kept, Target};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;

/// The key's legacy data as a `DSA` (NULL without).
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn data(p: *const EVP_PKEY) -> *mut DSA {
    // SAFETY: the caller's guarantee.
    unsafe { legacy_data(p) }.cast()
}

/// A copy of the state of the key's `DSA`, or `None` without one.
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn state(p: *const EVP_PKEY) -> Option<DsaState> {
    // SAFETY: the caller's guarantee.
    let d = unsafe { data(p) };
    // SAFETY: the key's `DSA`, or NULL.
    unsafe { dsa(d) }.map(Dsa::snapshot)
}

/// `dsa_cmp_parameters`: p, q, and g equal (q ignored, as OpenSSL's call does); -2 when either
/// has no `DSA`.
pub(crate) unsafe extern "C" fn dsa_cmp_parameters(
    a: *const EVP_PKEY,
    b: *const EVP_PKEY,
) -> c_int {
    // SAFETY: the method's keys.
    let (Some(sa), Some(sb)) = (unsafe { state(a) }, unsafe { state(b) }) else {
        return -2;
    };
    c_int::from(sa.params.cmp(&sb.params, true))
}

/// `dsa_pub_cmp`: the same public key (missing ones equal only each other).
pub(crate) unsafe extern "C" fn dsa_pub_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's keys.
    let (Some(sa), Some(sb)) = (unsafe { state(a) }, unsafe { state(b) }) else {
        return -2;
    };
    let same = match (&sa.pub_key, &sb.pub_key) {
        (Some(x), Some(y)) => rustyssl_crypto::bn::cmp(x, y).is_eq(),
        (None, None) => true,
        _ => false,
    };
    c_int::from(same)
}

/// `int_dsa_size`: `DSA_size`.
pub(crate) unsafe extern "C" fn int_dsa_size(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DSA`, or NULL.
    unsafe { crate::dsa_ops::DSA_size(d) }
}

/// `dsa_bits`: `DSA_bits`.
pub(crate) unsafe extern "C" fn dsa_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DSA`, or NULL.
    unsafe { crate::dsa::DSA_bits(d) }
}

/// `dsa_security_bits`: `DSA_security_bits`.
pub(crate) unsafe extern "C" fn dsa_security_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DSA`, or NULL.
    unsafe { crate::dsa::DSA_security_bits(d) }
}

/// `dsa_param_decode`: DSAparams as the key's `DSA`. 1, or 0.
pub(crate) unsafe extern "C" fn dsa_param_decode(
    p: *mut EVP_PKEY,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the method's octets.
    let d = unsafe { d2i_DSAparams(ptr::null_mut(), pder, c_long::from(derlen)) };
    // SAFETY: the new key, or NULL.
    let Some(k) = (unsafe { dsa(d) }) else {
        return 0;
    };
    k.touch();
    // SAFETY: the method's key; the `DSA`, which it takes.
    unsafe { EVP_PKEY_assign(p, EVP_PKEY_DSA, d.cast()) };
    1
}

/// `dsa_param_encode`: the key's DSAparams.
pub(crate) unsafe extern "C" fn dsa_param_encode(
    p: *const EVP_PKEY,
    pder: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DSA`; the method's output.
    unsafe { i2d_DSAparams(d, pder) }
}

/// `dsa_missing_parameters`: 1 without a `DSA`, or its p, q, or g.
pub(crate) unsafe extern "C" fn dsa_missing_parameters(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let st = unsafe { state(p) };
    c_int::from(
        st.is_none_or(|s| s.params.p.is_none() || s.params.q.is_none() || s.params.g.is_none()),
    )
}

/// `dsa_copy_parameters`: `to`'s `DSA` (made if it has none) gets `from`'s parameters. 1, or 0.
pub(crate) unsafe extern "C" fn dsa_copy_parameters(
    to: *mut EVP_PKEY,
    from: *const EVP_PKEY,
) -> c_int {
    // SAFETY: the method's key.
    let Some(src) = (unsafe { state(from) }) else {
        return 0;
    };
    // SAFETY: as above.
    let mut d = unsafe { data(to) };
    if d.is_null() {
        // SAFETY: no preconditions.
        d = unsafe { DSA_new() };
        if d.is_null() {
            return 0;
        }
        // SAFETY: the method's key; the new `DSA` it takes.
        if let Some(k) = unsafe { pkey(to) } {
            k.lock().legacy = crate::provider::Ptr(d.cast());
        }
    }
    // SAFETY: the key's `DSA`.
    let Some(k) = (unsafe { dsa(d) }) else {
        return 0;
    };
    let mut st = k.snapshot();
    st.params = src.params;
    k.replace(st);
    1
}

/// `do_dsa_print`: a private key under its indented heading, else "Public-Key" unindented
/// (for the parameters too, as OpenSSL prints them), the keys asked for, and the FFC fields.
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn do_print(bp: *mut BIO, st: &DsaState, off: c_int, ptype: c_int) -> c_int {
    let mod_len = st
        .params
        .p
        .as_ref()
        .map_or(0, |p| c_int::try_from(p.num_bits()).unwrap_or(c_int::MAX));
    let priv_key = if ptype == 2 {
        st.priv_key.as_ref()
    } else {
        None
    };
    let pub_key = if ptype > 0 { st.pub_key.as_ref() } else { None };
    let ktype = match ptype {
        2 => c"Private-Key",
        1 => c"Public-Key",
        _ => c"DSA-Parameters",
    };
    let heading = if priv_key.is_some() {
        // SAFETY: the caller's BIO.
        (unsafe { indent(bp, off) })
            // SAFETY: as above; a format and its arguments.
            && (unsafe { BIO_printf(bp, c"%s: (%d bit)\n".as_ptr(), ktype.as_ptr(), mod_len) }) > 0
    } else {
        // SAFETY: as above.
        (unsafe { BIO_printf(bp, c"Public-Key: (%d bit)\n".as_ptr(), mod_len) }) > 0
    };
    // SAFETY: as above (for each below).
    let ok = heading
        && unsafe { bn_print(bp, c"priv:", priv_key, off) }
        // SAFETY: as above.
        && unsafe { bn_print(bp, c"pub: ", pub_key, off) }
        // SAFETY: as above.
        && unsafe { ffc_print(bp, &st.params, off) };
    c_int::from(ok)
}

/// The print functions' common part.
///
/// # Safety
/// `bp` is a live BIO; `p` is a live key.
unsafe fn print(bp: *mut BIO, p: *const EVP_PKEY, off: c_int, ptype: c_int) -> c_int {
    // SAFETY: the method's key.
    let st = unsafe { state(p) }.unwrap_or_default();
    // SAFETY: the method's BIO.
    unsafe { do_print(bp, &st, off, ptype) }
}

/// `dsa_param_print`.
pub(crate) unsafe extern "C" fn dsa_param_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    off: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: the method's BIO and key.
    unsafe { print(bp, p, off, 0) }
}

/// `dsa_pub_print`.
pub(crate) unsafe extern "C" fn dsa_pub_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    off: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: the method's BIO and key.
    unsafe { print(bp, p, off, 1) }
}

/// `dsa_priv_print`.
pub(crate) unsafe extern "C" fn dsa_priv_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    off: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: the method's BIO and key.
    unsafe { print(bp, p, off, 2) }
}

/// `int_dsa_free`: drops the key's reference to its `DSA`.
pub(crate) unsafe extern "C" fn int_dsa_free(p: *mut EVP_PKEY) {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DSA`, or NULL.
    unsafe { free(d) };
}

/// `dsa_pkey_ctrl`: SHA-256 as the default digest; -2 for other controls.
pub(crate) unsafe extern "C" fn dsa_pkey_ctrl(
    _p: *mut EVP_PKEY,
    op: c_int,
    _arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    if op != ASN1_PKEY_CTRL_DEFAULT_MD_NID {
        return -2;
    }
    if !arg2.is_null() {
        // SAFETY: the control's `int *`.
        unsafe { arg2.cast::<c_int>().write(NID_sha256) };
    }
    1
}

/// `old_dsa_priv_decode`: a traditional DSAPrivateKey as the key's `DSA`. 1, or 0.
pub(crate) unsafe extern "C" fn old_dsa_priv_decode(
    p: *mut EVP_PKEY,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the method's octets.
    let d = unsafe { d2i_DSAPrivateKey(ptr::null_mut(), pder, c_long::from(derlen)) };
    // SAFETY: the new key, or NULL.
    let Some(k) = (unsafe { dsa(d) }) else {
        err::raise(ERR_LIB_DSA, ERR_R_DSA_LIB, "old_dsa_priv_decode");
        return 0;
    };
    k.touch();
    // SAFETY: the method's key; the `DSA`, which it takes.
    unsafe { EVP_PKEY_assign(p, EVP_PKEY_DSA, d.cast()) };
    1
}

/// `dsa_pkey_dirty_cnt`.
pub(crate) unsafe fn dsa_pkey_dirty_cnt(p: *const EVP_PKEY) -> usize {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DSA`, or NULL.
    unsafe { dsa(d) }.map_or(0, Dsa::dirty_count)
}

/// `dsa_pkey_export_to`: p, q, and g (the domain parameters) and the keys the `DSA` has, to
/// `importer`.
///
/// # Safety
/// `from` is a live key with DSA legacy data.
pub(crate) unsafe fn dsa_pkey_export_to(
    from: *const EVP_PKEY,
    importer: &mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int,
) -> c_int {
    // SAFETY: the method's key.
    let Some(st) = (unsafe { state(from) }) else {
        return 0;
    };
    let (Some(p), Some(q), Some(g)) = (&st.params.p, &st.params.q, &st.params.g) else {
        return 0;
    };
    // SAFETY: no preconditions.
    let bld = unsafe { OSSL_PARAM_BLD_new() };
    if bld.is_null() {
        return 0;
    }
    let target = Target::Builder(bld);
    let mut kept = Kept::default();
    let mut selection = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
    let mut push = |name, v: &BigNum| {
        let b = kept.number();
        // SAFETY: the number just made; the builder; the number lives as long as `kept`.
        !b.is_null() && unsafe { crate::bn::store(b, v.clone()) } && unsafe { target.bn(name, b) }
    };
    let mut ok = push(OSSL_PKEY_PARAM_FFC_P, p)
        && push(OSSL_PKEY_PARAM_FFC_Q, q)
        && push(OSSL_PKEY_PARAM_FFC_G, g);
    if ok && let Some(y) = &st.pub_key {
        ok = push(OSSL_PKEY_PARAM_PUB_KEY, y);
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }
    if ok && let Some(x) = &st.priv_key {
        ok = push(OSSL_PKEY_PARAM_PRIV_KEY, x);
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    }
    let mut rv = 0;
    if ok {
        // SAFETY: the builder; what it reads is kept until here.
        let params = unsafe { OSSL_PARAM_BLD_to_param(bld) };
        if !params.is_null() {
            rv = importer(selection, params);
            // SAFETY: the array made above.
            unsafe { OSSL_PARAM_free(params) };
        }
    }
    // SAFETY: the builder made above.
    unsafe { OSSL_PARAM_BLD_free(bld) };
    rv
}

/// `dsa_pkey_import_from`: a new `DSA` in `libctx` from `params` (parameters and both keys),
/// assigned to `to`.
///
/// # Safety
/// `params` is a parameter array; `to` is a live key.
pub(crate) unsafe fn dsa_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    let h = Dsa::new_handle_provided(libctx);
    // SAFETY: just made, or NULL.
    let Some(k) = (unsafe { dsa(h) }) else {
        err::raise(ERR_LIB_DSA, ERR_R_DSA_LIB, "dsa_pkey_import_from");
        return 0;
    };
    let mut st = k.snapshot();
    // SAFETY: the caller's array.
    let mut ok = unsafe { params_fromdata(&mut st, params) }
        // SAFETY: as above.
        && unsafe { key_fromdata(&mut st, params, true) };
    if ok {
        k.replace(st);
        // SAFETY: the caller's key; the `DSA`, which it takes.
        ok = unsafe { EVP_PKEY_assign(to, EVP_PKEY_DSA, h.cast()) } != 0;
    }
    if !ok {
        // SAFETY: the key made above.
        unsafe { free(h) };
    }
    c_int::from(ok)
}

/// `dsa_pkey_copy`: `to` gets a copy of `from`'s `DSA` (`ossl_dsa_dup` of all of it). 1, or 0
/// (also for a key without one, or a foreign one).
pub(crate) unsafe extern "C" fn dsa_pkey_copy(to: *mut EVP_PKEY, from: *mut EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(from) };
    let mut copy = ptr::null_mut();
    if !d.is_null() {
        // SAFETY: the key's `DSA`.
        copy = unsafe { backend::dup(d, OSSL_KEYMGMT_SELECT_ALL) };
        if copy.is_null() {
            return 0;
        }
    }
    // SAFETY: the caller's key; the copy, which it takes.
    let ret = unsafe { EVP_PKEY_assign(to, EVP_PKEY_DSA, copy.cast()) };
    if ret == 0 {
        // SAFETY: the copy made above, or NULL.
        unsafe { free(copy) };
    }
    ret
}

/// `evp_pkey_get0_DSA_int`: the key's `DSA` (a provided key's made and cached), or NULL with
/// `EVP_R_EXPECTING_A_DSA_KEY` for another type.
///
/// # Safety
/// `p` is NULL or a live key.
pub(crate) unsafe fn get0_dsa(p: *const EVP_PKEY) -> *mut DSA {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { pkey(p) }) else {
        return ptr::null_mut();
    };
    if k.type_() != EVP_PKEY_DSA {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_EXPECTING_A_DSA_KEY,
            "evp_pkey_get0_DSA_int",
        );
        return ptr::null_mut();
    }
    get_legacy(k).cast()
}

ffi_export! {
    /// Gives the key `key` (with a reference of its own) as DSA legacy data. 1, or 0.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key` is NULL or a live `DSA`.
    pub unsafe extern "C" fn EVP_PKEY_set1_DSA(pkey: *mut EVP_PKEY, key: *mut DSA) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { up_ref(key) } {
            return 0;
        }
        // SAFETY: as above; the reference taken, which the key keeps on success.
        let ret = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, key.cast()) };
        if ret == 0 {
            // SAFETY: the reference taken above.
            unsafe { free(key) };
        }
        ret
    }
}

ffi_export! {
    /// The key's `DSA` (made from a provided key's data, and kept with the key), or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_DSA(pkey: *const EVP_PKEY) -> *const DSA
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_dsa(pkey) }
    }
}

ffi_export! {
    /// The key's `DSA` with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get1_DSA(pkey: *mut EVP_PKEY) -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let d = unsafe { get0_dsa(pkey) };
        // SAFETY: the key's `DSA`, or NULL.
        if d.is_null() || !unsafe { up_ref(d) } {
            return ptr::null_mut();
        }
        d
    }
}

/// `DSA_print` and `DSAparams_print`: the `DSA` in a new key, printed by `f`.
///
/// # Safety
/// `bp` is NULL or a live BIO; `x` is NULL or a live key.
unsafe fn print_through_key(
    bp: *mut BIO,
    x: *const DSA,
    f: impl FnOnce(*mut BIO, *const EVP_PKEY) -> c_int,
) -> c_int {
    // SAFETY: no preconditions.
    let pk = unsafe { super::EVP_PKEY_new() };
    if pk.is_null() {
        return 0;
    }
    // SAFETY: a new key; the caller's `DSA`, which it references.
    let mut ret = unsafe { EVP_PKEY_set1_DSA(pk, x.cast_mut()) };
    if ret != 0 {
        ret = f(bp, pk);
    }
    // SAFETY: the key made above.
    unsafe { super::EVP_PKEY_free(pk) };
    ret
}

ffi_export! {
    /// Prints a key as `EVP_PKEY_print_private` prints it in a DSA `EVP_PKEY`. 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `x` is NULL or a live key.
    pub unsafe extern "C" fn DSA_print(bp: *mut BIO, x: *const DSA, off: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        let print = |b: *mut BIO, k: *const EVP_PKEY| {
            // SAFETY: the caller's BIO; the key made for it.
            unsafe { super::print::EVP_PKEY_print_private(b, k, off, ptr::null_mut()) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { print_through_key(bp, x, print) }
    }
}

ffi_export! {
    /// Prints a key's parameters as `EVP_PKEY_print_params` (indented 4) prints them. 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `x` is NULL or a live key.
    pub unsafe extern "C" fn DSAparams_print(bp: *mut BIO, x: *const DSA) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        let print = |b: *mut BIO, k: *const EVP_PKEY| {
            // SAFETY: the caller's BIO; the key made for it.
            unsafe { super::print::EVP_PKEY_print_params(b, k, 4, ptr::null_mut()) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { print_through_key(bp, x, print) }
    }
}

/// A FILE's BIO (closing nothing) for `f`, or 0 with `ERR_R_BUF_LIB`.
///
/// # Safety
/// `fp` is a live FILE.
unsafe fn with_fp(fp: *mut libc::FILE, func: &str, f: impl FnOnce(*mut BIO) -> c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let b = unsafe { crate::bio::file::BIO_new_fp(fp, rustyssl_abi::BIO_NOCLOSE) };
    if b.is_null() {
        err::raise(ERR_LIB_DSA, rustyssl_abi::ERR_R_BUF_LIB, func);
        return 0;
    }
    let ret = f(b);
    // SAFETY: the BIO made above.
    unsafe { crate::bio::BIO_free(b) };
    ret
}

ffi_export! {
    /// [`DSA_print`] to a `FILE`, which stays open.
    ///
    /// # Safety
    /// `fp` is a live FILE; `x` is NULL or a live key.
    pub unsafe extern "C" fn DSA_print_fp(fp: *mut libc::FILE, x: *const DSA, off: c_int) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        let print = |b: *mut BIO| {
            // SAFETY: the BIO made for it; the caller's key.
            unsafe { DSA_print(b, x, off) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "DSA_print_fp", print) }
    }
}

ffi_export! {
    /// [`DSAparams_print`] to a `FILE`, which stays open.
    ///
    /// # Safety
    /// `fp` is a live FILE; `x` is NULL or a live key.
    pub unsafe extern "C" fn DSAparams_print_fp(fp: *mut libc::FILE, x: *const DSA) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        let print = |b: *mut BIO| {
            // SAFETY: the BIO made for it; the caller's key.
            unsafe { DSAparams_print(b, x) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "DSAparams_print_fp", print) }
    }
}

/// Whether a key's `DSA` has an application's method.
///
/// # Safety
/// `key` is NULL or a live `DSA`.
pub(crate) unsafe fn is_foreign(key: *const DSA) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { dsa(key) }.is_some_and(backend::is_foreign)
}

ffi_callback! {
    /// `dsa_pub_decode`: the key's parameters (a SEQUENCE, or none for NULL or absent) and its
    /// public key (an INTEGER), assigned to the key.
    ///
    /// # Safety
    /// `pkey` is a live key typed DSA; `pubkey` is a live SubjectPublicKeyInfo.
    pub(crate) unsafe extern "C" fn dsa_pub_decode(pkey: *mut EVP_PKEY, pubkey: *const rustyssl_abi::X509_PUBKEY) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        use crate::x509::pubkey::{IntError, int_decode, sequence_octets};
        use rustyssl_abi::{
            DSA_R_BN_DECODE_ERROR, DSA_R_DECODE_ERROR, DSA_R_PARAMETER_ENCODING_ERROR,
            ERR_R_DSA_LIB, V_ASN1_NULL, V_ASN1_SEQUENCE, V_ASN1_UNDEF,
        };
        const F: &str = "dsa_pub_decode";
        let (mut p, mut pklen, mut palg) = (ptr::null(), 0, ptr::null_mut());
        // SAFETY: the caller's structure; locals.
        if unsafe { crate::x509::pubkey::X509_PUBKEY_get0_param(ptr::null_mut(), &raw mut p, &raw mut pklen, &raw mut palg, pubkey) } == 0 {
            return 0;
        }
        let (mut ptype, mut pval) = (0, ptr::null());
        // SAFETY: its AlgorithmIdentifier; locals.
        unsafe { crate::x509::algor::X509_ALGOR_get0(ptr::null_mut(), &raw mut ptype, &raw mut pval, palg) };
        let d = if ptype == V_ASN1_SEQUENCE {
            // SAFETY: a SEQUENCE parameter is an `ASN1_STRING`.
            let (mut pm, pmlen) = unsafe { sequence_octets(pval) };
            // SAFETY: its octets.
            let d = unsafe { d2i_DSAparams(ptr::null_mut(), &raw mut pm, pmlen) };
            if d.is_null() {
                err::raise(ERR_LIB_DSA, DSA_R_DECODE_ERROR, F);
                return 0;
            }
            d
        } else if ptype == V_ASN1_NULL || ptype == V_ASN1_UNDEF {
            // SAFETY: no preconditions.
            let d = unsafe { DSA_new() };
            if d.is_null() {
                err::raise(ERR_LIB_DSA, ERR_R_DSA_LIB, F);
                return 0;
            }
            d
        } else {
            err::raise(ERR_LIB_DSA, DSA_R_PARAMETER_ENCODING_ERROR, F);
            return 0;
        };
        // SAFETY: the structure's `pklen` octets.
        let pub_key = match unsafe { int_decode(p, c_long::from(pklen), false) } {
            Ok(b) => b,
            Err(e) => {
                let reason = match e {
                    IntError::Decode => DSA_R_DECODE_ERROR,
                    IntError::Bn => DSA_R_BN_DECODE_ERROR,
                };
                err::raise(ERR_LIB_DSA, reason, F);
                // SAFETY: made above.
                unsafe { free(d) };
                return 0;
            }
        };
        // SAFETY: the new key takes the number.
        unsafe { crate::dsa::DSA_set0_key(d, pub_key, ptr::null_mut()) };
        // SAFETY: the caller's key takes the new one.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, d.cast()) };
        1
    }
}

ffi_callback! {
    /// `dsa_pub_encode`: the public key as an INTEGER, with the parameters (a SEQUENCE) when the
    /// key saves them and has them all, else none.
    ///
    /// # Safety
    /// `pk` is a live SubjectPublicKeyInfo; `pkey` is a live DSA key.
    pub(crate) unsafe extern "C" fn dsa_pub_encode(pk: *mut rustyssl_abi::X509_PUBKEY, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        use crate::x509::pubkey::{int_encode, sequence_param};
        use rustyssl_abi::{ERR_R_ASN1_LIB, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE, V_ASN1_UNDEF};
        const F: &str = "dsa_pub_encode";
        // SAFETY: the caller's guarantee.
        let d = unsafe { data(pkey) };
        // SAFETY: as above.
        let save = unsafe { super::pkey(pkey) }.is_some_and(|k| k.save_parameters() != 0);
        // SAFETY: as above.
        let full = unsafe { state(pkey) }.is_some_and(|st| {
            st.params.p.is_some() && st.params.q.is_some() && st.params.g.is_some()
        });
        let (ptype, str_) = if save && full {
            let i2d = |out: *mut *mut c_uchar| {
                // SAFETY: the key; the caller's place for a new encoding.
                unsafe { i2d_DSAparams(d, out) }
            };
            // SAFETY: the closure writes a new buffer through its argument.
            match unsafe { sequence_param(V_ASN1_OCTET_STRING, i2d) } {
                Some(s) => (V_ASN1_SEQUENCE, s),
                None => {
                    err::raise(ERR_LIB_DSA, ERR_R_ASN1_LIB, F);
                    return 0;
                }
            }
        } else {
            (V_ASN1_UNDEF, ptr::null_mut())
        };
        // SAFETY: the key's public key.
        let pubk = unsafe { crate::dsa::DSA_get0_pub_key(d) };
        // SAFETY: as above.
        let Ok((penc, penclen)) = (unsafe { int_encode(pubk) }) else {
            err::raise(ERR_LIB_DSA, ERR_R_ASN1_LIB, F);
            // SAFETY: made above, or NULL.
            unsafe { crate::asn1::string::ASN1_STRING_free(str_) };
            return 0;
        };
        // SAFETY: no preconditions.
        let aobj = unsafe { crate::objects::OBJ_nid2obj(EVP_PKEY_DSA) };
        // SAFETY: the caller's structure takes the object, parameter, and octets.
        if !aobj.is_null() && unsafe { crate::x509::pubkey::X509_PUBKEY_set0_param(pk, aobj, ptype, str_.cast(), penc, penclen) } != 0 {
            return 1;
        }
        // SAFETY: made above.
        unsafe { crate::mem::release(penc.cast()) };
        // SAFETY: as above, or NULL.
        unsafe { crate::asn1::string::ASN1_STRING_free(str_) };
        0
    }
}

/// `ossl_dsa_key_from_pkcs8`: a PrivateKeyInfo's private key (a non-negative INTEGER) with the
/// AlgorithmIdentifier's parameters and the public key made from them, or NULL.
///
/// # Safety
/// `p8` is a live PrivateKeyInfo.
pub(crate) unsafe fn key_from_pkcs8(p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO) -> *mut DSA {
    use rustyssl_abi::{
        DSA_R_BN_ERROR, DSA_R_DECODE_ERROR, ERR_R_INTERNAL_ERROR, V_ASN1_NEG_INTEGER,
        V_ASN1_SEQUENCE,
    };
    const F: &str = "ossl_dsa_key_from_pkcs8";
    let (mut p, mut pklen, mut palg) = (ptr::null(), 0, ptr::null());
    // SAFETY: the caller's structure; locals.
    if unsafe {
        crate::x509::p8::PKCS8_pkey_get0(
            ptr::null_mut(),
            &raw mut p,
            &raw mut pklen,
            &raw mut palg,
            p8,
        )
    } == 0
    {
        return ptr::null_mut();
    }
    let (mut ptype, mut pval) = (0, ptr::null());
    // SAFETY: its AlgorithmIdentifier; locals.
    unsafe {
        crate::x509::algor::X509_ALGOR_get0(ptr::null_mut(), &raw mut ptype, &raw mut pval, palg)
    };
    // SAFETY: the structure's `pklen` octets.
    let privkey = unsafe {
        crate::asn1::tpl::items::d2i_ASN1_INTEGER(ptr::null_mut(), &raw mut p, c_long::from(pklen))
    };
    let done = |d: *mut DSA| {
        // SAFETY: decoded above, or NULL; wiped and freed once.
        unsafe { crate::asn1::string::ASN1_STRING_clear_free(privkey) };
        d
    };
    let decerr = || {
        err::raise(ERR_LIB_DSA, DSA_R_DECODE_ERROR, F);
        done(ptr::null_mut())
    };
    // SAFETY: the INTEGER, or NULL.
    let Some(ai) = (unsafe { privkey.as_ref() }) else {
        return decerr();
    };
    if ai.type_ == V_ASN1_NEG_INTEGER || ptype != V_ASN1_SEQUENCE {
        return decerr();
    }
    // SAFETY: a SEQUENCE parameter is an `ASN1_STRING`.
    let (mut pm, pmlen) = unsafe { crate::x509::pubkey::sequence_octets(pval) };
    // SAFETY: its octets.
    let d = unsafe { d2i_DSAparams(ptr::null_mut(), &raw mut pm, pmlen) };
    if d.is_null() {
        return decerr();
    }
    let dsaerr = |reason: c_int, privbn: *mut rustyssl_abi::BIGNUM| {
        err::raise(ERR_LIB_DSA, reason, F);
        // SAFETY: made here, or NULL.
        unsafe { crate::bn::BN_free(privbn) };
        // SAFETY: as above.
        unsafe { free(d) };
        done(ptr::null_mut())
    };
    // SAFETY: no preconditions.
    let privbn = unsafe { crate::bn::BN_secure_new() };
    // SAFETY: the INTEGER; the new number, or NULL.
    if privbn.is_null() || unsafe { crate::bn::conv::ASN1_INTEGER_to_BN(privkey, privbn) }.is_null()
    {
        return dsaerr(DSA_R_BN_ERROR, privbn);
    }
    // SAFETY: the new number.
    unsafe { crate::bn::BN_set_flags(privbn, rustyssl_abi::BN_FLG_CONSTTIME) };
    // SAFETY: the parameters' key; the new number.
    let (st, x) = (unsafe { dsa(d) }.map(Dsa::snapshot), unsafe {
        crate::bn::value(privbn)
    });
    let y = st
        .zip(x)
        .and_then(|(st, x)| backend::generate_public_key(&st, &x));
    let Some(y) = y else {
        return dsaerr(DSA_R_BN_ERROR, privbn);
    };
    let pubbn = crate::bn::new_bignum(y, false);
    if pubbn.is_null() {
        return dsaerr(rustyssl_abi::ERR_R_BN_LIB, privbn);
    }
    // SAFETY: the key takes both numbers.
    if unsafe { crate::dsa::DSA_set0_key(d, pubbn, privbn) } == 0 {
        // SAFETY: made above, not taken.
        unsafe { crate::bn::BN_free(pubbn) };
        return dsaerr(ERR_R_INTERNAL_ERROR, privbn);
    }
    done(d)
}

ffi_callback! {
    /// `dsa_priv_decode`: a PrivateKeyInfo's key assigned to the key.
    ///
    /// # Safety
    /// `pkey` is a live key typed DSA; `p8` is a live PrivateKeyInfo.
    pub(crate) unsafe extern "C" fn dsa_priv_decode(pkey: *mut EVP_PKEY, p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let d = unsafe { key_from_pkcs8(p8) };
        if d.is_null() {
            return 0;
        }
        // SAFETY: the caller's key takes the new one.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, d.cast()) };
        1
    }
}

ffi_callback! {
    /// `dsa_priv_encode`: the private key as an INTEGER with the parameters (a SEQUENCE).
    ///
    /// # Safety
    /// `p8` is a live PrivateKeyInfo; `pkey` is a live DSA key.
    pub(crate) unsafe extern "C" fn dsa_priv_encode(p8: *mut rustyssl_abi::PKCS8_PRIV_KEY_INFO, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        use crate::x509::pubkey::{int_encode, sequence_param};
        use rustyssl_abi::{DSA_R_BN_ERROR, DSA_R_MISSING_PARAMETERS, ERR_R_ASN1_LIB, V_ASN1_SEQUENCE};
        const F: &str = "dsa_priv_encode";
        // SAFETY: the caller's guarantee.
        let d = unsafe { data(pkey) };
        // SAFETY: the key's `DSA`, or NULL.
        let x = if d.is_null() { ptr::null() } else { unsafe { crate::dsa::DSA_get0_priv_key(d) } };
        if x.is_null() {
            err::raise(ERR_LIB_DSA, DSA_R_MISSING_PARAMETERS, F);
            return 0;
        }
        let i2d = |out: *mut *mut c_uchar| {
            // SAFETY: the key; the caller's place for a new encoding.
            unsafe { i2d_DSAparams(d, out) }
        };
        // SAFETY: the closure writes a new buffer through its argument.
        let Some(params) = (unsafe { sequence_param(V_ASN1_SEQUENCE, i2d) }) else {
            err::raise(ERR_LIB_DSA, ERR_R_ASN1_LIB, F);
            return 0;
        };
        // SAFETY: the key's private key.
        let Ok((dp, dplen)) = (unsafe { int_encode(x) }) else {
            err::raise(ERR_LIB_DSA, DSA_R_BN_ERROR, F);
            // SAFETY: made above.
            unsafe { crate::asn1::string::ASN1_STRING_free(params) };
            return 0;
        };
        // SAFETY: no preconditions.
        let obj = unsafe { crate::objects::OBJ_nid2obj(EVP_PKEY_DSA) };
        // SAFETY: the caller's structure takes the object, parameters, and octets.
        if unsafe { crate::x509::p8::PKCS8_pkey_set0(p8, obj, 0, V_ASN1_SEQUENCE, params.cast(), dp, dplen) } != 0 {
            return 1;
        }
        // SAFETY: made above, `dplen` octets.
        unsafe { crate::mem::release_clean(dp.cast(), usize::try_from(dplen).unwrap_or(0)) };
        // SAFETY: as above.
        unsafe { crate::asn1::string::ASN1_STRING_free(params) };
        0
    }
}
