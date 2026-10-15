//! RSA keys in `EVP_PKEY` (`EVP_PKEY_set1_RSA(3)`; `p_legacy.c`, `rsa_ameth.c`): the built-in
//! RSA and RSA-PSS ASN.1 methods' functions for a key whose legacy data is an `RSA`, and the
//! `RSA` of a key, made from a provided key's data when it has none (cached, as OpenSSL's
//! `legacy_cache_pkey`).
//!
//! As in OpenSSL, a legacy RSA key reaches the providers through a copy of its numbers
//! (`export_to`), remade when the `RSA` changes (`dirty_cnt`), and a provided key's `RSA` is a
//! copy too (`import_from`): the `RSA` and the provider's key are separate objects.

use core::ffi::{c_int, c_long, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_PKEY_CTRL_DEFAULT_MD_NID, ERR_LIB_EVP, EVP_PKEY, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
    EVP_R_EXPECTING_AN_RSA_KEY, NID_sha256, OSSL_CALLBACK, OSSL_KEYMGMT_SELECT_ALL,
    OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM, RSA, RSA_METHOD_FLAG_NO_CHECK,
};

use super::{EVP_PKEY_assign, get_legacy, legacy_data, pkey};
use crate::err;
use crate::ffi::ffi_export;
use crate::provider::rsa_kmgmt::{rsa_dup, rsa_export, rsa_import};
use crate::rsa::{Kind, Rsa, free, rsa, up_ref};
use crate::rsa_lib::{RSA_bits, RSA_flags, RSA_security_bits, RSA_size};
use crate::rsa_ops::RSA_check_key_ex;

/// The key's legacy data as an `RSA` (NULL without).
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn data(p: *const EVP_PKEY) -> *mut RSA {
    // SAFETY: the caller's guarantee.
    unsafe { legacy_data(p) }.cast()
}

/// `rsa_pub_cmp`: the same modulus and public exponent (1), unless a method asks for no check.
pub(crate) unsafe extern "C" fn rsa_pub_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int {
    // SAFETY: the keys the caller compares.
    let ra = unsafe { data(a) };
    // SAFETY: as above.
    let rb = unsafe { data(b) };
    // SAFETY: their `RSA`s, or NULL.
    let no_check = |r: *mut RSA| unsafe { RSA_flags(r) } & RSA_METHOD_FLAG_NO_CHECK != 0;
    if no_check(ra) || no_check(rb) {
        return 1;
    }
    // SAFETY: as above.
    let (Some(ka), Some(kb)) = (unsafe { rsa(ra) }, unsafe { rsa(rb) }) else {
        return 0;
    };
    let (sa, sb) = (ka.snapshot().key, kb.snapshot().key);
    c_int::from(sa.n == sb.n && sa.e == sb.e)
}

/// `int_rsa_size`.
pub(crate) unsafe extern "C" fn int_rsa_size(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { RSA_size(r) }
}

/// `rsa_bits`.
pub(crate) unsafe extern "C" fn rsa_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { RSA_bits(r) }
}

/// `rsa_security_bits`.
pub(crate) unsafe extern "C" fn rsa_security_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { RSA_security_bits(r) }
}

/// `int_rsa_free`: drops the key's reference to its `RSA`.
pub(crate) unsafe extern "C" fn int_rsa_free(p: *mut EVP_PKEY) {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { free(r) };
}

/// `rsa_pkey_ctrl`: the default digest is SHA-256 (decoded RSASSA-PSS parameters, which
/// would name theirs, come with the ASN.1 items); other controls -2.
pub(crate) unsafe extern "C" fn rsa_pkey_ctrl(
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

/// `rsa_pkey_check`: `RSA_check_key_ex`.
pub(crate) unsafe extern "C" fn rsa_pkey_check(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { RSA_check_key_ex(r, ptr::null_mut()) }
}

/// `rsa_pkey_copy`: `to` gets a copy of `from`'s `RSA`. 1, or 0.
pub(crate) unsafe extern "C" fn rsa_pkey_copy(to: *mut EVP_PKEY, from: *mut EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(from) };
    let dup = if r.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: a live key's data.
        let d = unsafe { rsa_dup(r.cast_const().cast(), OSSL_KEYMGMT_SELECT_ALL as c_int) };
        if d.is_null() {
            return 0;
        }
        d
    };
    // SAFETY: the caller's key.
    let type_ = unsafe { pkey(from) }.map_or(EVP_PKEY_RSA, super::Pkey::type_);
    // SAFETY: as above; the copy, which `to` takes.
    let ret = unsafe { EVP_PKEY_assign(to, type_, dup) };
    if ret == 0 {
        // SAFETY: the copy made above.
        unsafe { free(dup.cast()) };
    }
    ret
}

/// `rsa_pkey_dirty_cnt`.
pub(crate) unsafe fn rsa_pkey_dirty_cnt(p: *const EVP_PKEY) -> usize {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { rsa(r) }.map_or(0, Rsa::dirty_cnt)
}

/// What `rsa_pkey_export_to`'s callback hands the importer.
struct Exporting<'a> {
    selection: c_int,
    importer: &'a mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int,
}

/// The key manager's export callback: the parameters to the importer.
unsafe extern "C" fn exported(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    // SAFETY: `rsa_pkey_export_to`'s `Exporting`, live for the call.
    let Some(e) = (unsafe { arg.cast::<Exporting<'_>>().as_mut() }) else {
        return 0;
    };
    (e.importer)(e.selection, params)
}

/// `rsa_int_export_to`: the public key (and the private key, and an RSA-PSS key's
/// restrictions, when it has them) to `importer`.
pub(crate) unsafe fn rsa_pkey_export_to(
    from: *const EVP_PKEY,
    importer: &mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int,
) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(from) };
    // SAFETY: its `RSA`.
    let Some(k) = (unsafe { rsa(r) }) else {
        return 0;
    };
    let st = k.snapshot();
    if st.key.n.is_none() || st.key.e.is_none() {
        return 0;
    }
    let mut selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int;
    if st.key.d.is_some() {
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int;
    }
    if st.pss.restricted() {
        selection |= OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as c_int;
    }
    let mut e = Exporting {
        selection,
        importer,
    };
    let cb: OSSL_CALLBACK = Some(exported);
    // SAFETY: the `RSA` as key data; the callback takes `e`, which outlives the call.
    unsafe { rsa_export(r.cast(), selection, cb, (&raw mut e).cast()) }
}

/// `rsa_int_import_from`: a new `RSA` of `kind` in `libctx` from `params`, assigned to `to`.
///
/// # Safety
/// `params` is a parameter array; `to` is a live key.
unsafe fn import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
    kind: Kind,
) -> c_int {
    let r = Rsa::new_handle_in(libctx, kind);
    if r.is_null() {
        return 0;
    }
    // SAFETY: the key just made; the caller's array.
    let mut ok = unsafe { rsa_import(r.cast(), OSSL_KEYMGMT_SELECT_ALL as c_int, params) } != 0;
    if ok {
        let type_ = if kind == Kind::Rsa {
            EVP_PKEY_RSA
        } else {
            EVP_PKEY_RSA_PSS
        };
        // SAFETY: the caller's key; the `RSA`, which it takes.
        ok = unsafe { EVP_PKEY_assign(to, type_, r.cast()) } != 0;
    }
    if !ok {
        // SAFETY: the key made above.
        unsafe { free(r) };
    }
    c_int::from(ok)
}

/// `rsa_pkey_import_from`.
pub(crate) unsafe fn rsa_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { import_from(params, to, libctx, Kind::Rsa) }
}

/// `rsa_pss_pkey_import_from`.
pub(crate) unsafe fn rsa_pss_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { import_from(params, to, libctx, Kind::RsaPss) }
}

/// `evp_pkey_get0_RSA_int`: the key's `RSA` (a provided key's made and cached), or NULL with
/// `EVP_R_EXPECTING_AN_RSA_KEY` for another type.
///
/// # Safety
/// `p` is NULL or a live key.
pub(crate) unsafe fn get0_rsa(p: *const EVP_PKEY) -> *mut RSA {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { pkey(p) }) else {
        return ptr::null_mut();
    };
    let t = k.type_();
    if t != EVP_PKEY_RSA && t != EVP_PKEY_RSA_PSS {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_EXPECTING_AN_RSA_KEY,
            "evp_pkey_get0_RSA_int",
        );
        return ptr::null_mut();
    }
    get_legacy(k).cast()
}

ffi_export! {
    /// Gives the key `key` (with a reference of its own) as RSA legacy data. 1, or 0.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key` is NULL or a live `RSA`.
    pub unsafe extern "C" fn EVP_PKEY_set1_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { up_ref(key) } {
            return 0;
        }
        // SAFETY: as above; the reference taken, which the key keeps on success.
        let ret = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_RSA, key.cast()) };
        if ret == 0 {
            // SAFETY: the reference taken above.
            unsafe { free(key) };
        }
        ret
    }
}

ffi_export! {
    /// The key's `RSA` (made from a provided key's data, and kept with the key), or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_RSA(pkey: *const EVP_PKEY) -> *const RSA
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_rsa(pkey) }
    }
}

ffi_export! {
    /// The key's `RSA` with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get1_RSA(pkey: *mut EVP_PKEY) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe { get0_rsa(pkey) };
        // SAFETY: the key's `RSA`, or NULL.
        if r.is_null() || !unsafe { up_ref(r) } {
            return ptr::null_mut();
        }
        r
    }
}
