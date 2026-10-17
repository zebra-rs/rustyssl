//! DH keys in `EVP_PKEY` (`EVP_PKEY_set1_DH(3)`; `p_lib.c`, `dh_ameth.c`): the built-in DH and
//! DHX ASN.1 methods' functions for a key whose legacy data is a `DH`, and the `DH` of a key.
//!
//! A key moves between its legacy and provided forms (`export_to`, `import_from`) through the
//! parameters the DH key managers take (`crate::dh_backend`). As in OpenSSL, `EVP_PKEY_set1_DH`
//! types a key DHX when it has q and isn't a safe-prime named group; a DHX key's parameters
//! encode as X9.42's and compare with q.

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_PCTX, ASN1_PKEY_CTRL_GET1_TLS_ENCPT, ASN1_PKEY_CTRL_SET1_TLS_ENCPT, BIO, DH,
    DH_R_MISSING_PUBKEY, ERR_LIB_DH, ERR_LIB_EVP, ERR_R_DH_LIB, EVP_PKEY, EVP_PKEY_DH,
    EVP_PKEY_DHX, EVP_R_EXPECTING_A_DH_KEY, OSSL_KEYMGMT_SELECT_ALL,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PKEY_PARAM_DH_PRIV_LEN, OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_P,
    OSSL_PKEY_PARAM_FFC_Q, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
};
use rustyssl_crypto::bn::BigNum;

use super::{EVP_PKEY_assign, get_legacy, legacy_data, pkey};
use crate::dh::{DH_get0_pub_key, DH_new, Dh, DhState, dh, free, up_ref};
use crate::dh_asn1::{Part, d2i_DHparams, d2i_DHxparams, do_print, i2d_DHparams, i2d_DHxparams};
use crate::dh_backend::{self as backend, key_fromdata, params_fromdata};
use crate::dh_ops::{DH_check_ex, DH_check_pub_key_ex};
use crate::ec::params::{Kept, Target};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::params::build::{OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_to_param};
use crate::params::dup::OSSL_PARAM_free;

/// The key's legacy data as a `DH` (NULL without).
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn data(p: *const EVP_PKEY) -> *mut DH {
    // SAFETY: the caller's guarantee.
    unsafe { legacy_data(p) }.cast()
}

/// A copy of the state of the key's `DH`, or `None` without one.
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn state(p: *const EVP_PKEY) -> Option<DhState> {
    // SAFETY: the caller's guarantee.
    let d = unsafe { data(p) };
    // SAFETY: the key's `DH`, or NULL.
    unsafe { dh(d) }.map(Dh::snapshot)
}

/// Whether the key is DHX's type (its method is the X9.42 one).
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn is_dhx(p: *const EVP_PKEY) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { pkey(p) }.is_some_and(|k| k.type_() == EVP_PKEY_DHX)
}

/// `dh_cmp_parameters`: p, g, and (for a DHX `a`) q equal; -2 when either has no `DH`.
pub(crate) unsafe extern "C" fn dh_cmp_parameters(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's keys.
    let (Some(sa), Some(sb)) = (unsafe { state(a) }, unsafe { state(b) }) else {
        return -2;
    };
    // SAFETY: as above.
    let ignore_q = !unsafe { is_dhx(a) };
    c_int::from(sa.params.cmp(&sb.params, ignore_q))
}

/// `dh_pub_cmp`: the same parameters and public key (missing ones equal only each other).
pub(crate) unsafe extern "C" fn dh_pub_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's keys.
    match unsafe { dh_cmp_parameters(a, b) } {
        1 => {}
        0 => return 0,
        r => return r,
    }
    // SAFETY: as above.
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

/// `int_dh_size`: `DH_size`.
pub(crate) unsafe extern "C" fn int_dh_size(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DH`, or NULL.
    unsafe { crate::dh::DH_size(d) }
}

/// `dh_bits`: `DH_bits`.
pub(crate) unsafe extern "C" fn dh_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DH`, or NULL.
    unsafe { crate::dh::DH_bits(d) }
}

/// `dh_security_bits`: `DH_security_bits`.
pub(crate) unsafe extern "C" fn dh_security_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DH`, or NULL.
    unsafe { crate::dh::DH_security_bits(d) }
}

/// `dh_param_decode`: DHparams (X9.42's for a DHX key) as the key's `DH`. 1, or 0.
pub(crate) unsafe extern "C" fn dh_param_decode(
    p: *mut EVP_PKEY,
    pder: *mut *const c_uchar,
    derlen: c_int,
) -> c_int {
    // SAFETY: the method's key.
    let x942 = unsafe { is_dhx(p) };
    let len = c_long::from(derlen);
    let d = if x942 {
        // SAFETY: the method's octets.
        unsafe { d2i_DHxparams(ptr::null_mut(), pder, len) }
    } else {
        // SAFETY: as above.
        unsafe { d2i_DHparams(ptr::null_mut(), pder, len) }
    };
    // SAFETY: the new key, or NULL.
    let Some(k) = (unsafe { dh(d) }) else {
        return 0;
    };
    k.touch();
    let type_ = if x942 { EVP_PKEY_DHX } else { EVP_PKEY_DH };
    // SAFETY: the method's key; the `DH`, which it takes.
    unsafe { EVP_PKEY_assign(p, type_, d.cast()) };
    1
}

/// `dh_param_encode`: the key's DHparams (X9.42's for a DHX key).
pub(crate) unsafe extern "C" fn dh_param_encode(
    p: *const EVP_PKEY,
    pder: *mut *mut c_uchar,
) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: as above.
    if unsafe { is_dhx(p) } {
        // SAFETY: its `DH`; the method's output.
        unsafe { i2d_DHxparams(d, pder) }
    } else {
        // SAFETY: as above.
        unsafe { i2d_DHparams(d, pder) }
    }
}

/// `dh_missing_parameters`: 1 without a `DH`, or its p or g.
pub(crate) unsafe extern "C" fn dh_missing_parameters(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let st = unsafe { state(p) };
    c_int::from(st.is_none_or(|s| s.params.p.is_none() || s.params.g.is_none()))
}

/// `dh_copy_parameters` (`int_dh_param_copy`): `to`'s `DH` (made if it has none) gets
/// `from`'s parameters, and (unless `from` is DHX) its private key length. 1, or 0.
pub(crate) unsafe extern "C" fn dh_copy_parameters(
    to: *mut EVP_PKEY,
    from: *const EVP_PKEY,
) -> c_int {
    // SAFETY: the method's key.
    let Some(src) = (unsafe { state(from) }) else {
        return 0;
    };
    // SAFETY: as above.
    let x942 = unsafe { is_dhx(from) };
    // SAFETY: as above.
    let mut d = unsafe { data(to) };
    if d.is_null() {
        // SAFETY: no preconditions.
        d = unsafe { DH_new() };
        if d.is_null() {
            return 0;
        }
        // SAFETY: the method's key; the new `DH` it takes.
        if let Some(k) = unsafe { pkey(to) } {
            k.lock().legacy = crate::provider::Ptr(d.cast());
        }
    }
    // SAFETY: the key's `DH`.
    let Some(k) = (unsafe { dh(d) }) else {
        return 0;
    };
    let mut st = k.snapshot();
    st.params = src.params;
    if !x942 {
        st.length = src.length;
    }
    k.replace(st);
    1
}

/// The print functions' common part.
///
/// # Safety
/// `bp` is a live BIO; `p` is a live key.
unsafe fn print(bp: *mut BIO, p: *const EVP_PKEY, indent: c_int, part: Part) -> c_int {
    // SAFETY: the method's key.
    let st = unsafe { state(p) }.unwrap_or_default();
    // SAFETY: the method's BIO.
    unsafe { do_print(bp, &st, indent, part) }
}

/// `dh_param_print`.
pub(crate) unsafe extern "C" fn dh_param_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    indent: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: the method's BIO and key.
    unsafe { print(bp, p, indent, Part::Params) }
}

/// `dh_public_print`.
pub(crate) unsafe extern "C" fn dh_public_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    indent: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: the method's BIO and key.
    unsafe { print(bp, p, indent, Part::Public) }
}

/// `dh_private_print`.
pub(crate) unsafe extern "C" fn dh_private_print(
    bp: *mut BIO,
    p: *const EVP_PKEY,
    indent: c_int,
    _ctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: the method's BIO and key.
    unsafe { print(bp, p, indent, Part::Private) }
}

/// `int_dh_free`: drops the key's reference to its `DH`.
pub(crate) unsafe extern "C" fn int_dh_free(p: *mut EVP_PKEY) {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DH`, or NULL.
    unsafe { free(d) };
}

/// `dh_pkey_ctrl`: the TLS encoded public key both ways (a legacy key's set; padded to the
/// prime's length); -2 for other controls.
pub(crate) unsafe extern "C" fn dh_pkey_ctrl(
    p: *mut EVP_PKEY,
    op: c_int,
    arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    match op {
        ASN1_PKEY_CTRL_SET1_TLS_ENCPT => {
            // SAFETY: the method's key.
            let d = unsafe { get0_dh(p) };
            // SAFETY: its `DH`, or NULL.
            let Some(k) = (unsafe { dh(d) }) else {
                return 0;
            };
            let Ok(len) = usize::try_from(arg1) else {
                return 0;
            };
            let buf = if arg2.is_null() || len == 0 {
                &[][..]
            } else {
                // SAFETY: the control's octets of `arg1`.
                unsafe { core::slice::from_raw_parts(arg2.cast::<u8>(), len) }
            };
            c_int::from(backend::buf2key(k, buf))
        }
        ASN1_PKEY_CTRL_GET1_TLS_ENCPT => {
            // SAFETY: the method's key.
            let d = unsafe { get0_dh(p) };
            // SAFETY: its `DH`, or NULL.
            let Some(st) = (unsafe { dh(d) }).map(Dh::snapshot) else {
                return 0;
            };
            let n = backend::key2buf(&st, None);
            if n == 0 {
                return 0;
            }
            let buf = mem::alloc(n).cast::<u8>();
            if buf.is_null() {
                return 0;
            }
            // SAFETY: the buffer just allocated, of `n` octets.
            let out = unsafe { core::slice::from_raw_parts_mut(buf, n) };
            if backend::key2buf(&st, Some(out)) == 0 {
                // SAFETY: as above.
                unsafe { mem::release(buf.cast()) };
                return 0;
            }
            if !arg2.is_null() {
                // SAFETY: the control's `unsigned char **`.
                unsafe { arg2.cast::<*mut u8>().write(buf) };
            } else {
                // SAFETY: as above.
                unsafe { mem::release(buf.cast()) };
            }
            c_int::try_from(n).unwrap_or(0)
        }
        _ => -2,
    }
}

/// `dhx_pkey_ctrl`: no controls.
pub(crate) unsafe extern "C" fn dhx_pkey_ctrl(
    _p: *mut EVP_PKEY,
    _op: c_int,
    _arg1: c_long,
    _arg2: *mut c_void,
) -> c_int {
    -2
}

/// `dh_pkey_public_check`: a public key, then `DH_check_pub_key_ex`.
pub(crate) unsafe extern "C" fn dh_pkey_public_check(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DH`, or NULL.
    let y = unsafe { DH_get0_pub_key(d) };
    if y.is_null() {
        err::raise(ERR_LIB_DH, DH_R_MISSING_PUBKEY, "dh_pkey_public_check");
        return 0;
    }
    // SAFETY: the key's `DH` and its public key.
    unsafe { DH_check_pub_key_ex(d, y) }
}

/// `dh_pkey_param_check`: `DH_check_ex`.
pub(crate) unsafe extern "C" fn dh_pkey_param_check(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DH`, or NULL.
    unsafe { DH_check_ex(d) }
}

/// `dh_pkey_dirty_cnt`.
pub(crate) unsafe fn dh_pkey_dirty_cnt(p: *const EVP_PKEY) -> usize {
    // SAFETY: the method's key.
    let d = unsafe { data(p) };
    // SAFETY: its `DH`, or NULL.
    unsafe { dh(d) }.map_or(0, Dh::dirty_count)
}

/// `dh_pkey_export_to`: p, g, and q (the domain parameters), the private key length (other
/// parameters), and the keys the `DH` has, to `importer`.
///
/// # Safety
/// `from` is a live key with DH legacy data.
pub(crate) unsafe fn dh_pkey_export_to(
    from: *const EVP_PKEY,
    importer: &mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int,
) -> c_int {
    // SAFETY: the method's key.
    let Some(st) = (unsafe { state(from) }) else {
        return 0;
    };
    let (Some(p), Some(g)) = (&st.params.p, &st.params.g) else {
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
    let mut ok = push(OSSL_PKEY_PARAM_FFC_P, p) && push(OSSL_PKEY_PARAM_FFC_G, g);
    if ok && let Some(q) = &st.params.q {
        ok = push(OSSL_PKEY_PARAM_FFC_Q, q);
    }
    if ok && let Some(y) = &st.pub_key {
        ok = push(OSSL_PKEY_PARAM_PUB_KEY, y);
        selection |= OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
    }
    if ok && let Some(x) = &st.priv_key {
        ok = push(OSSL_PKEY_PARAM_PRIV_KEY, x);
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    }
    if ok && st.length > 0 {
        // SAFETY: the builder.
        ok = unsafe { target.long(OSSL_PKEY_PARAM_DH_PRIV_LEN, c_long::from(st.length)) };
        selection |= OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS;
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

/// `dh_pkey_import_from_type`: a new `DH` of `type_` in `libctx` from `params` (parameters and
/// both keys), assigned to `to`.
///
/// # Safety
/// `params` is a parameter array; `to` is a live key.
unsafe fn import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
    type_: c_int,
) -> c_int {
    let h = Dh::new_handle_in(libctx);
    // SAFETY: just made, or NULL.
    let Some(k) = (unsafe { dh(h) }) else {
        err::raise(ERR_LIB_DH, ERR_R_DH_LIB, "dh_pkey_import_from_type");
        return 0;
    };
    k.set_type(type_ == EVP_PKEY_DHX);
    let mut st = k.snapshot();
    // SAFETY: the caller's array.
    let mut ok = unsafe { params_fromdata(&mut st, params) }
        // SAFETY: as above.
        && unsafe { key_fromdata(&mut st, params, true) };
    if ok {
        k.replace(st);
        // SAFETY: the caller's key; the `DH`, which it takes.
        ok = unsafe { EVP_PKEY_assign(to, type_, h.cast()) } != 0;
    }
    if !ok {
        // SAFETY: the key made above.
        unsafe { free(h) };
    }
    c_int::from(ok)
}

/// `dh_pkey_import_from`.
pub(crate) unsafe fn dh_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { import_from(params, to, libctx, EVP_PKEY_DH) }
}

/// `dhx_pkey_import_from`.
pub(crate) unsafe fn dhx_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { import_from(params, to, libctx, EVP_PKEY_DHX) }
}

/// `dh_pkey_copy`: `to` gets a copy of `from`'s `DH` (`ossl_dh_dup` of all of it), as
/// `from`'s type. 1, or 0 (also for a key without one, or a foreign one).
pub(crate) unsafe extern "C" fn dh_pkey_copy(to: *mut EVP_PKEY, from: *mut EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let d = unsafe { data(from) };
    // SAFETY: as above.
    let type_ = unsafe { pkey(from) }.map_or(EVP_PKEY_DH, super::Pkey::type_);
    let mut copy = ptr::null_mut();
    if !d.is_null() {
        // SAFETY: the key's `DH`.
        copy = unsafe { backend::dup(d, OSSL_KEYMGMT_SELECT_ALL) };
        if copy.is_null() {
            return 0;
        }
    }
    // SAFETY: the caller's key; the copy, which it takes.
    let ret = unsafe { EVP_PKEY_assign(to, type_, copy.cast()) };
    if ret == 0 {
        // SAFETY: the copy made above, or NULL.
        unsafe { free(copy) };
    }
    ret
}

/// `evp_pkey_get0_DH_int`: the key's `DH` (a provided key's made and cached), or NULL with
/// `EVP_R_EXPECTING_A_DH_KEY` for another type.
///
/// # Safety
/// `p` is NULL or a live key.
pub(crate) unsafe fn get0_dh(p: *const EVP_PKEY) -> *mut DH {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { pkey(p) }) else {
        return ptr::null_mut();
    };
    let t = k.type_();
    if t != EVP_PKEY_DH && t != EVP_PKEY_DHX {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_EXPECTING_A_DH_KEY,
            "evp_pkey_get0_DH_int",
        );
        return ptr::null_mut();
    }
    get_legacy(k).cast()
}

ffi_export! {
    /// Gives the key `key` (with a reference of its own) as DH legacy data: DHX's type for
    /// parameters with q that aren't a safe-prime named group, DH's otherwise. 1, or 0.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key` is NULL or a live `DH`.
    pub unsafe extern "C" fn EVP_PKEY_set1_DH(pkey: *mut EVP_PKEY, key: *mut DH) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(st) = (unsafe { dh(key) }).map(Dh::snapshot) else { return 0 };
        let type_ = if backend::is_named_safe_prime_group(&st) || st.params.q.is_none() {
            EVP_PKEY_DH
        } else {
            EVP_PKEY_DHX
        };
        // SAFETY: the caller's guarantee.
        if !unsafe { up_ref(key) } {
            return 0;
        }
        // SAFETY: as above; the reference taken, which the key keeps on success.
        let ret = unsafe { EVP_PKEY_assign(pkey, type_, key.cast()) };
        if ret == 0 {
            // SAFETY: the reference taken above.
            unsafe { free(key) };
        }
        ret
    }
}

ffi_export! {
    /// The key's `DH` (made from a provided key's data, and kept with the key), or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_DH(pkey: *const EVP_PKEY) -> *const DH
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_dh(pkey) }
    }
}

ffi_export! {
    /// The key's `DH` with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get1_DH(pkey: *mut EVP_PKEY) -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let d = unsafe { get0_dh(pkey) };
        // SAFETY: the key's `DH`, or NULL.
        if d.is_null() || !unsafe { up_ref(d) } {
            return ptr::null_mut();
        }
        d
    }
}

/// Whether a key's `DH` (EVP_PKEY_DH's type only, as OpenSSL checks) has an application's
/// method.
///
/// # Safety
/// `key` is NULL or a live `DH`.
pub(crate) unsafe fn is_foreign(key: *const DH) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { dh(key) }.is_some_and(backend::is_foreign)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL's dereferences the NULL key.
    #[test]
    fn set1_and_get0_of_null_fail() {
        // SAFETY: no preconditions.
        let k = unsafe { super::super::EVP_PKEY_new() };
        // SAFETY: a live key; NULL.
        assert_eq!(unsafe { EVP_PKEY_set1_DH(k, ptr::null_mut()) }, 0);
        // SAFETY: NULL.
        assert!(unsafe { EVP_PKEY_get0_DH(ptr::null()) }.is_null());
        // SAFETY: made above, freed once.
        unsafe { super::super::EVP_PKEY_free(k) };
    }
}

ffi_callback! {
    /// `dh_pub_decode`: the key's parameters (a SEQUENCE: DHparams, or DHxparams for DHX) and
    /// its public key (an INTEGER), assigned to the key.
    ///
    /// # Safety
    /// `pkey` is a live key typed DH or DHX; `pubkey` is a live SubjectPublicKeyInfo.
    pub(crate) unsafe extern "C" fn dh_pub_decode(pkey: *mut EVP_PKEY, pubkey: *const rustyssl_abi::X509_PUBKEY) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        use crate::x509::pubkey::{IntError, int_decode, sequence_octets};
        use rustyssl_abi::{
            DH_R_BN_DECODE_ERROR, DH_R_DECODE_ERROR, DH_R_PARAMETER_ENCODING_ERROR, V_ASN1_SEQUENCE,
        };
        const F: &str = "dh_pub_decode";
        let (mut p, mut pklen, mut palg) = (ptr::null(), 0, ptr::null_mut());
        // SAFETY: the caller's structure; locals.
        if unsafe { crate::x509::pubkey::X509_PUBKEY_get0_param(ptr::null_mut(), &raw mut p, &raw mut pklen, &raw mut palg, pubkey) } == 0 {
            return 0;
        }
        let (mut ptype, mut pval) = (0, ptr::null());
        // SAFETY: its AlgorithmIdentifier; locals.
        unsafe { crate::x509::algor::X509_ALGOR_get0(ptr::null_mut(), &raw mut ptype, &raw mut pval, palg) };
        if ptype != V_ASN1_SEQUENCE {
            err::raise(ERR_LIB_DH, DH_R_PARAMETER_ENCODING_ERROR, F);
            return 0;
        }
        // SAFETY: a SEQUENCE parameter is an `ASN1_STRING`.
        let (mut pm, pmlen) = unsafe { sequence_octets(pval) };
        // SAFETY: the caller's key; the parameter's octets.
        let dh = if unsafe { is_dhx(pkey) } {
            // SAFETY: as above.
            unsafe { d2i_DHxparams(ptr::null_mut(), &raw mut pm, pmlen) }
        } else {
            // SAFETY: as above.
            unsafe { d2i_DHparams(ptr::null_mut(), &raw mut pm, pmlen) }
        };
        if dh.is_null() {
            err::raise(ERR_LIB_DH, DH_R_DECODE_ERROR, F);
            return 0;
        }
        // SAFETY: the structure's `pklen` octets.
        let pub_key = match unsafe { int_decode(p, c_long::from(pklen), false) } {
            Ok(b) => b,
            Err(e) => {
                let reason = match e {
                    IntError::Decode => DH_R_DECODE_ERROR,
                    IntError::Bn => DH_R_BN_DECODE_ERROR,
                };
                err::raise(ERR_LIB_DH, reason, F);
                // SAFETY: made above.
                unsafe { crate::dh::DH_free(dh) };
                return 0;
            }
        };
        // SAFETY: the new key takes the number.
        unsafe { crate::dh::DH_set0_key(dh, pub_key, ptr::null_mut()) };
        // SAFETY: the caller's key.
        let id = unsafe { super::EVP_PKEY_get_id(pkey) };
        // SAFETY: the caller's key takes the new one.
        unsafe { EVP_PKEY_assign(pkey, id, dh.cast()) };
        1
    }
}

ffi_callback! {
    /// `dh_pub_encode`: the key's parameters (DHparams, or DHxparams for DHX) and its public
    /// key as an INTEGER.
    ///
    /// # Safety
    /// `pk` is a live SubjectPublicKeyInfo; `pkey` is a live DH or DHX key.
    pub(crate) unsafe extern "C" fn dh_pub_encode(pk: *mut rustyssl_abi::X509_PUBKEY, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        use crate::x509::pubkey::{int_encode, sequence_param};
        use rustyssl_abi::{ERR_R_ASN1_LIB, V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE};
        const F: &str = "dh_pub_encode";
        // SAFETY: the caller's guarantee.
        let dh = unsafe { data(pkey) };
        // SAFETY: as above.
        let dhx = unsafe { is_dhx(pkey) };
        let i2d = |out: *mut *mut core::ffi::c_uchar| {
            if dhx {
                // SAFETY: the key; the caller's place for a new encoding.
                unsafe { i2d_DHxparams(dh, out) }
            } else {
                // SAFETY: as above.
                unsafe { i2d_DHparams(dh, out) }
            }
        };
        // SAFETY: the closure writes a new buffer through its argument.
        let Some(str_) = (unsafe { sequence_param(V_ASN1_OCTET_STRING, i2d) }) else {
            err::raise(ERR_LIB_DH, ERR_R_ASN1_LIB, F);
            return 0;
        };
        // SAFETY: the key's public key.
        let pubk = unsafe { crate::dh::DH_get0_pub_key(dh) };
        // SAFETY: as above.
        let (penc, penclen) = match unsafe { int_encode(pubk) } {
            Ok(v) => v,
            Err(no_integer) => {
                if !no_integer {
                    err::raise(ERR_LIB_DH, ERR_R_ASN1_LIB, F);
                }
                // SAFETY: made above.
                unsafe { crate::asn1::string::ASN1_STRING_free(str_) };
                return 0;
            }
        };
        // SAFETY: the caller's key.
        let id = unsafe { super::EVP_PKEY_get_id(pkey) };
        // SAFETY: no preconditions.
        let obj = unsafe { crate::objects::OBJ_nid2obj(id) };
        // SAFETY: the caller's structure takes the object, parameter, and octets.
        if unsafe { crate::x509::pubkey::X509_PUBKEY_set0_param(pk, obj, V_ASN1_SEQUENCE, str_.cast(), penc, penclen) } != 0 {
            return 1;
        }
        // SAFETY: made above.
        unsafe { crate::mem::release(penc.cast()) };
        // SAFETY: as above.
        unsafe { crate::asn1::string::ASN1_STRING_free(str_) };
        0
    }
}
