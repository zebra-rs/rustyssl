//! The default provider's ECDH key exchange (`ecdh_exch.c`): the shared secret of a key and a
//! peer's on the same group (cut short to a smaller buffer), with or without the cofactor
//! (the key's own flag, or the context's `ecdh-cofactor-mode` over it), and optionally through
//! X9.63's KDF (`kdf-type` `X963KDF`, with its digest, output length, and user keying
//! material).
//!
//! The context follows OpenSSL's: an init resets the cofactor mode and the KDF type but keeps
//! the KDF's digest, length, and keying material; a digest refused as an XOF stays set (so a
//! derivation fails in the KDF), and one that can't be fetched leaves none (so a derivation
//! fails without an error).

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    EC_FLAG_COFACTOR_ECDH, EC_KEY, ERR_LIB_PROV, ERR_R_BN_LIB,
    OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, OSSL_EXCHANGE_PARAM_KDF_DIGEST,
    OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS, OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
    OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_FUNC_KEYEXCH_DERIVE,
    OSSL_FUNC_KEYEXCH_DUPCTX, OSSL_FUNC_KEYEXCH_FREECTX, OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
    OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS, OSSL_FUNC_KEYEXCH_INIT, OSSL_FUNC_KEYEXCH_NEWCTX,
    OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS, OSSL_FUNC_KEYEXCH_SET_PEER,
    OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS, OSSL_KDF_NAME_X963KDF, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_STRING, PROV_R_MISMATCHING_DOMAIN_PARAMETERS, PROV_R_MISSING_KEY,
    PROV_R_OUTPUT_BUFFER_TOO_SMALL, PROV_R_XOF_DIGESTS_NOT_ALLOWED,
};

use super::builtin::libctx_of;
use super::macs::{INT, SIZE_T, boxed, context, is_empty, locate, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::bn::BN_is_one;
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::ec::ecdsa::{ECDH_compute_key, kdf_x9_63};
use crate::ec::group::{EC_GROUP_cmp, EC_GROUP_get_degree, EC_GROUP_get0_cofactor};
use crate::ec::key::{
    EC_KEY_clear_flags, EC_KEY_dup, EC_KEY_free, EC_KEY_get_flags, EC_KEY_get0_group,
    EC_KEY_get0_public_key, EC_KEY_set_flags, EC_KEY_up_ref, key,
};
use crate::err;
use crate::evp::digest::EVP_MD_get0_name;
use crate::evp::md_ctx::EVP_MD_xof;
use crate::ffi::{bytes, ffi_callback};
use crate::mem;
use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t,
    OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate, OSSL_PARAM_set_int, OSSL_PARAM_set_octet_ptr,
    OSSL_PARAM_set_size_t, OSSL_PARAM_set_utf8_string,
};
use crate::rsa::Md;

/// The size of the name buffers `ecdh_set_ctx_params` reads into.
const NAME: usize = 80;

/// `PROV_ECDH_CTX`.
struct EcdhCtx {
    libctx: *mut OSSL_LIB_CTX,
    /// The key and the peer's, each with a reference this holds, or NULL.
    k: *mut EC_KEY,
    peerk: *mut EC_KEY,
    /// 0 off, 1 on, -1 the key's own flag.
    cofactor_mode: c_int,
    /// Whether X9.63's KDF derives from the shared secret.
    kdf_x963: bool,
    kdf_md: Option<Md>,
    kdf_ukm: Option<Vec<u8>>,
    kdf_outlen: usize,
}

impl Drop for EcdhCtx {
    fn drop(&mut self) {
        // SAFETY: the references this holds, or NULL.
        unsafe { EC_KEY_free(self.k) };
        // SAFETY: as above.
        unsafe { EC_KEY_free(self.peerk) };
        if let Some(u) = self.kdf_ukm.as_mut() {
            wipe(u);
        }
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `ecdh_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut EcdhCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<EcdhCtx>(vctx) }
}

/// The key's cofactor mode from its flag.
///
/// # Safety
/// `k` is NULL or a live key.
unsafe fn key_cofactor_mode(k: *const EC_KEY) -> c_int {
    // SAFETY: the caller's guarantee.
    c_int::from(unsafe { EC_KEY_get_flags(k) } & EC_FLAG_COFACTOR_ECDH != 0)
}

ffi_callback! {
    /// `ecdh_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn ecdh_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(EcdhCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            k: ptr::null_mut(),
            peerk: ptr::null_mut(),
            cofactor_mode: -1,
            kdf_x963: false,
            kdf_md: None,
            kdf_ukm: None,
            kdf_outlen: 0,
        })
    }
}

ffi_callback! {
    /// `ecdh_init`: the key (which must have a group), the cofactor mode and KDF type reset,
    /// then the parameters.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vecdh` is NULL or a live EC key; `params` is NULL or
    /// an array.
    pub(crate) unsafe extern "C" fn ecdh_init(vctx: *mut c_void, vecdh: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let k = vecdh.cast::<EC_KEY>();
        // SAFETY: the caller's key, if any.
        if k.is_null() || unsafe { EC_KEY_get0_group(k) }.is_null() {
            return 0;
        }
        // SAFETY: as above.
        if unsafe { EC_KEY_up_ref(k) } == 0 {
            return 0;
        }
        // SAFETY: the reference the context held, or NULL.
        unsafe { EC_KEY_free(c.k) };
        c.k = k;
        c.cofactor_mode = -1;
        c.kdf_x963 = false;
        // SAFETY: the caller's guarantee.
        unsafe { ecdh_set_ctx_params(vctx, params) }
    }
}

/// `ecdh_match_params`: whether the keys' groups are equal (raising an error if not).
///
/// # Safety
/// `k` and `peer` are NULL or live keys.
unsafe fn match_params(k: *const EC_KEY, peer: *const EC_KEY) -> bool {
    const F: &str = "ecdh_match_params";
    // SAFETY: the caller's key.
    let libctx = unsafe { key(k) }.map_or(ptr::null_mut(), |e| e.get().libctx.0);
    // SAFETY: the key's library context, or NULL.
    let bnctx = unsafe { BN_CTX_new_ex(libctx) };
    if bnctx.is_null() {
        err::raise(ERR_LIB_PROV, ERR_R_BN_LIB, F);
        return false;
    }
    // SAFETY: the caller's key.
    let gk = unsafe { EC_KEY_get0_group(k) };
    // SAFETY: as above.
    let gp = unsafe { EC_KEY_get0_group(peer) };
    // SAFETY: the groups and the context.
    let ok = !gk.is_null() && !gp.is_null() && unsafe { EC_GROUP_cmp(gk, gp, bnctx) } == 0;
    if !ok {
        err::raise(ERR_LIB_PROV, PROV_R_MISMATCHING_DOMAIN_PARAMETERS, F);
    }
    // SAFETY: made above.
    unsafe { BN_CTX_free(bnctx) };
    ok
}

ffi_callback! {
    /// `ecdh_set_peer`: the peer's key, on the key's group.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vecdh` is NULL or a live EC key.
    pub(crate) unsafe extern "C" fn ecdh_set_peer(vctx: *mut c_void, vecdh: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let peer = vecdh.cast::<EC_KEY>();
        // SAFETY: the context's key and the caller's.
        if peer.is_null() || !unsafe { match_params(c.k, peer) } {
            return 0;
        }
        // SAFETY: the caller's key.
        if unsafe { EC_KEY_up_ref(peer) } == 0 {
            return 0;
        }
        // SAFETY: the reference the context held, or NULL.
        unsafe { EC_KEY_free(c.peerk) };
        c.peerk = peer;
        1
    }
}

ffi_callback! {
    /// `ecdh_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn ecdh_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<EcdhCtx>(vctx) };
    }
}

ffi_callback! {
    /// `ecdh_dupctx`: references to the keys and digest, a copy of the keying material.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn ecdh_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        let mut copy = EcdhCtx {
            libctx: c.libctx,
            k: ptr::null_mut(),
            peerk: ptr::null_mut(),
            cofactor_mode: c.cofactor_mode,
            kdf_x963: c.kdf_x963,
            kdf_md: c.kdf_md.clone(),
            kdf_ukm: c.kdf_ukm.clone().filter(|u| !u.is_empty()),
            kdf_outlen: c.kdf_outlen,
        };
        for (src, dst) in [(c.k, &mut copy.k), (c.peerk, &mut copy.peerk)] {
            if !src.is_null() {
                // SAFETY: the context's live key.
                if unsafe { EC_KEY_up_ref(src) } == 0 {
                    return ptr::null_mut();
                }
                *dst = src;
            }
        }
        boxed(copy)
    }
}

/// `OSSL_PARAM_get_utf8_string` into a buffer of `NAME` octets.
///
/// # Safety
/// `p` is a parameter.
unsafe fn read_name(p: &OSSL_PARAM) -> Option<CString> {
    let mut buf = [0 as c_char; NAME];
    let mut s = buf.as_mut_ptr();
    // SAFETY: the parameter; the buffer.
    if unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, NAME) } != 1 {
        return None;
    }
    // SAFETY: NUL-terminated by the call.
    Some(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_owned())
}

ffi_callback! {
    /// `ecdh_set_ctx_params`: the cofactor mode (-1 to 1), the KDF type (none or X963KDF), the
    /// KDF's digest (fetched with the properties given, empty if none are), output length,
    /// and keying material.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecdh_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { locate(params, key) }
        };
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE) {
            let mut mode: c_int = 0;
            // SAFETY: a parameter of the array; a local.
            if unsafe { OSSL_PARAM_get_int(p, &raw mut mode) } != 1 || !(-1..=1).contains(&mode) {
                return 0;
            }
            c.cofactor_mode = mode;
        }
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_KDF_TYPE) {
            // SAFETY: a parameter of the array.
            let Some(name) = (unsafe { read_name(p) }) else { return 0 };
            if name.is_empty() {
                c.kdf_x963 = false;
            } else if name.as_c_str() == OSSL_KDF_NAME_X963KDF {
                c.kdf_x963 = true;
            } else {
                return 0;
            }
        }
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_KDF_DIGEST) {
            // SAFETY: a parameter of the array.
            let Some(name) = (unsafe { read_name(p) }) else { return 0 };
            let props = match find(OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS) {
                // SAFETY: as above.
                Some(q) => match unsafe { read_name(q) } {
                    Some(v) => v,
                    None => return 0,
                },
                None => CString::default(),
            };
            // SAFETY: the context's library context; a name and a query.
            c.kdf_md = unsafe { Md::fetch(c.libctx, &name, props.as_ptr()) };
            let Some(md) = c.kdf_md.as_ref() else { return 0 };
            // SAFETY: the digest.
            if unsafe { EVP_MD_xof(md.ptr()) } != 0 {
                err::raise(ERR_LIB_PROV, PROV_R_XOF_DIGESTS_NOT_ALLOWED, "ecdh_set_ctx_params");
                return 0;
            }
        }
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_KDF_OUTLEN) {
            let mut outlen: usize = 0;
            // SAFETY: a parameter of the array; a local.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut outlen) } != 1 {
                return 0;
            }
            c.kdf_outlen = outlen;
        }
        if let Some(p) = find(OSSL_EXCHANGE_PARAM_KDF_UKM) {
            let mut data: *mut c_void = ptr::null_mut();
            let mut n: usize = 0;
            // SAFETY: a parameter of the array; a place for a new allocation.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut data, 0, &raw mut n) } != 1 {
                return 0;
            }
            // SAFETY: the allocation just made holds `n` octets.
            let ukm = unsafe { bytes(data.cast::<u8>(), n) }.unwrap_or_default().to_vec();
            // SAFETY: the allocation just made, freed once.
            unsafe { mem::release(data) };
            if let Some(old) = c.kdf_ukm.as_mut() {
                wipe(old);
            }
            c.kdf_ukm = Some(ukm);
        }
        1
    }
}

/// `known_settable_ctx_params`.
static SETTABLE: Params<7> = Params([
    defn(
        OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
        OSSL_PARAM_INTEGER,
        INT,
    ),
    defn(OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS,
        OSSL_PARAM_UTF8_STRING,
        0,
    ),
    defn(
        OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ecdh_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecdh_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `ecdh_get_ctx_params`: the cofactor mode (the key's for -1), the KDF type, digest,
    /// output length, and keying material (as a pointer to the context's).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecdh_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let find = |key: &CStr| {
            // SAFETY: the caller's array; a static name.
            unsafe { OSSL_PARAM_locate(params, key.as_ptr()) }
        };
        let p = find(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE);
        if !p.is_null() {
            let mode = if c.cofactor_mode == -1 {
                // SAFETY: the context's key, or NULL.
                unsafe { key_cofactor_mode(c.k) }
            } else {
                c.cofactor_mode
            };
            // SAFETY: a parameter of the array.
            if unsafe { OSSL_PARAM_set_int(p, mode) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_EXCHANGE_PARAM_KDF_TYPE);
        if !p.is_null() {
            let name = if c.kdf_x963 { OSSL_KDF_NAME_X963KDF } else { c"" };
            // SAFETY: a parameter of the array; a static string.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name.as_ptr()) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_EXCHANGE_PARAM_KDF_DIGEST);
        if !p.is_null() {
            let name = match &c.kdf_md {
                // SAFETY: the context's digest.
                Some(m) => unsafe { EVP_MD_get0_name(m.ptr()) },
                None => c"".as_ptr(),
            };
            // SAFETY: a parameter of the array; a string.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name) } != 1 {
                return 0;
            }
        }
        let p = find(OSSL_EXCHANGE_PARAM_KDF_OUTLEN);
        // SAFETY: a parameter of the array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_size_t(p, c.kdf_outlen) } != 1 {
            return 0;
        }
        let p = find(OSSL_EXCHANGE_PARAM_KDF_UKM);
        if !p.is_null() {
            let (u, n) = c.kdf_ukm.as_deref().map_or((ptr::null(), 0), |u| (u.as_ptr(), u.len()));
            // SAFETY: a parameter of the array; the context's keying material, which stays in
            // place until it's set again or the context is freed.
            if unsafe { OSSL_PARAM_set_octet_ptr(p, u.cast(), n) } != 1 {
                return 0;
            }
        }
        1
    }
}

/// `known_gettable_ctx_params`.
static GETTABLE: Params<6> = Params([
    defn(
        OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
        OSSL_PARAM_INTEGER,
        INT,
    ),
    defn(OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(
        OSSL_EXCHANGE_PARAM_KDF_OUTLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_PARAM_OCTET_PTR, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ecdh_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn ecdh_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

/// `ecdh_size`: the field's octets, 0 without a group.
///
/// # Safety
/// `k` is NULL or a live key.
unsafe fn ecdh_size(k: *const EC_KEY) -> usize {
    if k.is_null() {
        return 0;
    }
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(k) };
    if group.is_null() {
        return 0;
    }
    // SAFETY: the key's group.
    let degree = usize::try_from(unsafe { EC_GROUP_get_degree(group) }).unwrap_or(0);
    degree.div_ceil(8)
}

/// `ecdh_plain_derive`: the shared secret into `secret` (cut to `outlen`), or its size for
/// NULL `secret`.
///
/// # Safety
/// `secret` is NULL or has room for `outlen` octets; `psecretlen` is writable.
unsafe fn plain_derive(
    c: &EcdhCtx,
    secret: *mut c_uchar,
    psecretlen: *mut usize,
    outlen: usize,
) -> c_int {
    if c.k.is_null() || c.peerk.is_null() {
        err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "ecdh_plain_derive");
        return 0;
    }
    // SAFETY: the context's key.
    let ecdhsize = unsafe { ecdh_size(c.k) };
    if secret.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { psecretlen.write(ecdhsize) };
        return 1;
    }
    // SAFETY: the context's key.
    let group = unsafe { EC_KEY_get0_group(c.k) };
    if group.is_null() {
        return 0;
    }
    // SAFETY: the key's group.
    let cofactor = unsafe { EC_GROUP_get0_cofactor(group) };
    if cofactor.is_null() {
        return 0;
    }
    // SAFETY: the group's number.
    let has_cofactor = unsafe { BN_is_one(cofactor) } == 0;
    let size = outlen.min(ecdhsize);
    // The context's mode overrides the key's: with a cofactor that matters, a copy of the key
    // takes the mode.
    // SAFETY: the context's key.
    let key_mode = unsafe { key_cofactor_mode(c.k) };
    let privk = if c.cofactor_mode != -1 && c.cofactor_mode != key_mode && has_cofactor {
        // SAFETY: the context's key.
        let d = unsafe { EC_KEY_dup(c.k) };
        if d.is_null() {
            return 0;
        }
        if c.cofactor_mode == 1 {
            // SAFETY: the copy.
            unsafe { EC_KEY_set_flags(d, EC_FLAG_COFACTOR_ECDH) };
        } else {
            // SAFETY: as above.
            unsafe { EC_KEY_clear_flags(d, EC_FLAG_COFACTOR_ECDH) };
        }
        d
    } else {
        c.k
    };
    // SAFETY: the peer's key.
    let ppubkey = unsafe { EC_KEY_get0_public_key(c.peerk) };
    // SAFETY: the caller's room for `size` octets; the peer's point; the key.
    let retlen = unsafe { ECDH_compute_key(secret.cast(), size, ppubkey, privk, None) };
    if privk != c.k {
        // SAFETY: the copy made above.
        unsafe { EC_KEY_free(privk) };
    }
    let Ok(n) = usize::try_from(retlen) else {
        return 0;
    };
    if n == 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { psecretlen.write(n) };
    1
}

/// `ecdh_X9_63_kdf_derive`: X9.63's KDF of the shared secret, `kdf_outlen` octets.
///
/// # Safety
/// As for `plain_derive`.
unsafe fn x963_derive(
    c: &EcdhCtx,
    secret: *mut c_uchar,
    psecretlen: *mut usize,
    outlen: usize,
) -> c_int {
    if secret.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { psecretlen.write(c.kdf_outlen) };
        return 1;
    }
    if c.kdf_outlen > outlen {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "ecdh_X9_63_kdf_derive",
        );
        return 0;
    }
    let mut zlen = 0;
    // SAFETY: a local.
    if unsafe { plain_derive(c, ptr::null_mut(), &raw mut zlen, 0) } != 1 {
        return 0;
    }
    let mut z = vec![0u8; zlen];
    // SAFETY: room for `zlen` octets; a local.
    let mut ok = unsafe { plain_derive(c, z.as_mut_ptr(), &raw mut zlen, zlen) } == 1;
    if ok {
        let ukm = c.kdf_ukm.as_deref().unwrap_or_default();
        let md = c
            .kdf_md
            .as_ref()
            .map_or(ptr::null(), |m| m.ptr().cast_const());
        let secret_z = z.get(..zlen).unwrap_or(&z);
        // SAFETY: the caller's room (at least `kdf_outlen`); the digest, or NULL; the context's
        // library context.
        ok = unsafe {
            kdf_x9_63(
                secret,
                c.kdf_outlen,
                secret_z,
                ukm,
                md,
                c.libctx,
                ptr::null(),
            )
        };
        if ok {
            // SAFETY: the caller's guarantee.
            unsafe { psecretlen.write(c.kdf_outlen) };
        }
    }
    wipe(&mut z);
    c_int::from(ok)
}

ffi_callback! {
    /// `ecdh_derive`: the shared secret, or X9.63's KDF of it.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `secret` is NULL or has room for `outlen` octets;
    /// `psecretlen` is writable.
    pub(crate) unsafe extern "C" fn ecdh_derive(vctx: *mut c_void, secret: *mut c_uchar, psecretlen: *mut usize, outlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        if c.kdf_x963 {
            // SAFETY: the caller's guarantee.
            unsafe { x963_derive(c, secret, psecretlen, outlen) }
        } else {
            // SAFETY: as above.
            unsafe { plain_derive(c, secret, psecretlen, outlen) }
        }
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type SetPeerFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type DeriveFn = unsafe extern "C" fn(*mut c_void, *mut c_uchar, *mut usize, usize) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `ossl_ecdh_keyexch_functions`.
pub(crate) static ECDH_KEYEXCH: Dispatch<11> = Dispatch([
    entry!(OSSL_FUNC_KEYEXCH_NEWCTX, ecdh_newctx, NewCtxFn),
    entry!(OSSL_FUNC_KEYEXCH_INIT, ecdh_init, InitFn),
    entry!(OSSL_FUNC_KEYEXCH_DERIVE, ecdh_derive, DeriveFn),
    entry!(OSSL_FUNC_KEYEXCH_SET_PEER, ecdh_set_peer, SetPeerFn),
    entry!(OSSL_FUNC_KEYEXCH_FREECTX, ecdh_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_KEYEXCH_DUPCTX, ecdh_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_KEYEXCH_SET_CTX_PARAMS,
        ecdh_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
        ecdh_settable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_KEYEXCH_GET_CTX_PARAMS,
        ecdh_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYEXCH_GETTABLE_CTX_PARAMS,
        ecdh_gettable_ctx_params,
        ListFn
    ),
    END,
]);
