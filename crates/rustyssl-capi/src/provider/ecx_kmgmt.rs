//! The default provider's X25519 and Ed25519 key managers (`ecx_kmgmt.c`, with `ecx_backend.c`
//! through `crate::ecx`): keys made empty, from their raw public and private keys (the public
//! key derived when it's absent), described (sizes, strengths, the keys, X25519's encoded
//! public key, EdDSA's empty mandatory digest), changed (X25519's encoded public key, which
//! drops the private key, and the properties), exported, compared, copied by selection,
//! validated (the parts present, and the pair), loaded, and generated (random, or for X25519
//! from RFC 9180 DHKEM input key material), with an optional group name that must be the
//! key type's own.
//!
//! The functions are written once for the four ECX types; X448 and Ed448, whose arithmetic
//! comes with step 4.5b, aren't offered yet.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_EC, ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, OSSL_CALLBACK, OSSL_FUNC_KEYMGMT_DUP,
    OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_FREE,
    OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP, OSSL_FUNC_KEYMGMT_GEN_INIT,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_VALIDATE, OSSL_KDF_PARAM_PROPERTIES,
    OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_BITS,
    OSSL_PKEY_PARAM_DHKEM_IKM, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OSSL_PKEY_PARAM_GROUP_NAME,
    OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PROPERTIES, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
    PROV_R_ALGORITHM_MISMATCH, PROV_R_INVALID_INPUT_LENGTH,
};
use rustyssl_crypto::ec::dhkem::{self, ECX_KEMS};

use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ecx::{self, EcxKey, EcxType, MAX_KEYLEN};
use crate::err;
use crate::ffi::{bytes, ffi_callback};
use crate::mem::CRYPTO_memcmp;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_octet_string,
    OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_locate, OSSL_PARAM_set_int,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string,
};
use crate::rand_lib::RAND_priv_bytes_ex;

const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
/// `ECX_POSSIBLE_SELECTIONS`.
const POSSIBLE: c_int = KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
const OCTETS_TYPE: u32 = OSSL_PARAM_OCTET_STRING.cast_unsigned();
const UTF8_TYPE: u32 = OSSL_PARAM_UTF8_STRING.cast_unsigned();
const INT_SIZE: usize = size_of::<c_int>();

/// A type's bits, security bits, and largest output (a signature's, or X25519's secret).
const fn sizes(kind: EcxType) -> (c_int, c_int, c_int) {
    match kind {
        EcxType::X25519 => (253, 128, 32),
        EcxType::X448 => (448, 224, 56),
        EcxType::Ed25519 => (256, 128, 64),
        EcxType::Ed448 => (456, 224, 114),
    }
}

/// The key behind key data.
///
/// # Safety
/// `keydata` is NULL or live ECX key data.
unsafe fn ecx_key<'a>(keydata: *const c_void) -> Option<&'a EcxKey> {
    // SAFETY: the caller's guarantee.
    unsafe { ecx::key(keydata) }
}

ffi_callback! {
    /// `ecx_has`: parameters always; a public key or private key if it has one.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ecx_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ecx_key(keydata) }) else { return 0 };
        let s = k.lock();
        let mut ok = true;
        if selection & PUBLIC != 0 {
            ok = ok && s.haspubkey;
        }
        if selection & PRIVATE != 0 {
            ok = ok && s.privkey.is_some();
        }
        c_int::from(ok)
    }
}

/// Constant-time equality of two keys' octets of the same length.
fn same(a: &[u8], b: &[u8]) -> bool {
    // SAFETY: two buffers of `a.len()` octets (the caller's lengths are equal).
    a.len() == b.len()
        && unsafe { CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) } == 0
}

ffi_callback! {
    /// `ecx_match`: the types for parameters; the public keys if both have one, else the private
    /// keys if both have one.
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are live key data.
    pub(crate) unsafe extern "C" fn ecx_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let (Some(k1), Some(k2)) = (unsafe { ecx_key(keydata1) }, unsafe { ecx_key(keydata2) }) else {
            return 0;
        };
        let mut ok = true;
        if selection & rustyssl_abi::OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS != 0 {
            ok = k1.kind == k2.kind;
        }
        if selection & KEYPAIR != 0 {
            let (s1, s2) = if core::ptr::eq(k1, k2) {
                let s = k1.lock();
                let copy = (s.haspubkey, s.pubkey, s.privkey.clone());
                drop(s);
                (copy.clone(), copy)
            } else {
                let a = k1.lock();
                let b = k2.lock();
                ((a.haspubkey, a.pubkey, a.privkey.clone()), (b.haspubkey, b.pubkey, b.privkey.clone()))
            };
            let (l1, l2) = (k1.keylen(), k2.keylen());
            let mut checked = false;
            if selection & PUBLIC != 0 && s1.0 && s2.0 {
                ok = ok
                    && k1.kind == k2.kind
                    && l1 == l2
                    && same(s1.1.get(..l1).unwrap_or_default(), s2.1.get(..l2).unwrap_or_default());
                checked = true;
            }
            if !checked
                && selection & PRIVATE != 0
                && let (Some(a), Some(b)) = (&s1.2, &s2.2)
            {
                ok = ok && k1.kind == k2.kind && l1 == l2 && same(a, b);
                checked = true;
            }
            let zap = |v: Option<Vec<u8>>| {
                if let Some(mut v) = v {
                    wipe(&mut v);
                }
            };
            zap(s1.2);
            zap(s2.2);
            ok = ok && checked;
        }
        c_int::from(ok)
    }
}

/// An octet-string parameter's octets, if it is one.
fn octet_param(p: &OSSL_PARAM) -> Option<&[u8]> {
    if p.data_type != OCTETS_TYPE {
        return None;
    }
    // SAFETY: an octet-string parameter's data holds its size.
    unsafe { bytes(p.data.cast(), p.data_size) }
}

/// `ossl_ecx_key_fromdata`: the private key (if `include_private`) and the public key, each of
/// the key's length, the public key derived when it's absent.
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn key_fromdata(k: &EcxKey, params: *const OSSL_PARAM, include_private: bool) -> bool {
    // SAFETY: the caller's array; static names.
    let p_pub = unsafe { locate(params, OSSL_PKEY_PARAM_PUB_KEY) };
    let p_priv = if include_private {
        // SAFETY: as above.
        unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) }
    } else {
        None
    };
    if p_pub.is_none() && p_priv.is_none() {
        return false;
    }
    let keylen = k.keylen();
    let mut s = k.lock();
    if let Some(p) = p_priv {
        // `OSSL_PARAM_get_octet_string` with room for the key's length.
        let Some(d) = octet_param(p).filter(|d| d.len() <= keylen) else {
            return false;
        };
        if d.len() != keylen {
            return false;
        }
        if let Some(old) = s.privkey.as_mut() {
            wipe(old);
        }
        s.privkey = Some(d.to_vec());
    }
    if let Some(p) = p_pub {
        let Some(q) = octet_param(p).filter(|q| q.len() <= MAX_KEYLEN) else {
            return false;
        };
        if let Some(dst) = s.pubkey.get_mut(..q.len()) {
            dst.copy_from_slice(q);
        }
        if q.len() != keylen {
            return false;
        }
    } else if !ecx::public_from_private(k, &mut s) {
        err::raise(
            ERR_LIB_EC,
            rustyssl_abi::EC_R_FAILED_MAKING_PUBLIC_KEY,
            "ossl_ecx_public_from_private",
        );
        return false;
    }
    s.haspubkey = true;
    true
}

ffi_callback! {
    /// `ecx_import`: the key pair (which must be selected).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecx_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ecx_key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { key_fromdata(k, params, selection & PRIVATE != 0) })
    }
}

ffi_callback! {
    /// `ecx_export`: the public key (always) and the private key (if selected and present).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` is called with `cbarg`.
    pub(crate) unsafe extern "C" fn ecx_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ecx_key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 0;
        }
        let keylen = k.keylen();
        let (public, private) = {
            let s = k.lock();
            let private = if selection & PRIVATE != 0 { s.privkey.clone() } else { None };
            (s.pubkey, private)
        };
        // SAFETY: no preconditions.
        let bld = unsafe { OSSL_PARAM_BLD_new() };
        if bld.is_null() {
            return 0;
        }
        let mut ret = 0;
        // SAFETY: the builder; static names; octets that outlive the array's making.
        let ok = unsafe { OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY.as_ptr(), public.as_ptr().cast(), keylen) } != 0
            && private.as_ref().is_none_or(|d| {
                // SAFETY: as above.
                (unsafe { OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY.as_ptr(), d.as_ptr().cast(), keylen) }) != 0
            });
        if ok {
            // SAFETY: the builder.
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
        if let Some(mut d) = private {
            wipe(&mut d);
        }
        ret
    }
}

/// `ecx_key_types`.
static KEY_TYPES: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ecx_imexport_types`.
    pub(crate) unsafe extern "C" fn ecx_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        if selection & KEYPAIR != 0 { KEY_TYPES.0.as_ptr() } else { ptr::null() }
    }
}

/// Sets the parameter named `name` to the octets, if the array has it.
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn set_octets(params: *mut OSSL_PARAM, name: &CStr, v: &[u8]) -> bool {
    // SAFETY: the caller's array; a static name.
    let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
    // SAFETY: a parameter of the array; the octets.
    p.is_null() || unsafe { OSSL_PARAM_set_octet_string(p, v.as_ptr().cast(), v.len()) } != 0
}

/// Sets the parameter named `name` to `v`, if the array has it.
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn set_int(params: *mut OSSL_PARAM, name: &CStr, v: c_int) -> bool {
    // SAFETY: the caller's array; a static name.
    let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
    // SAFETY: a parameter of the array.
    p.is_null() || unsafe { OSSL_PARAM_set_int(p, v) } != 0
}

/// `ecx_get_params` (and `ed_get_params`): the sizes, X25519's and X448's encoded public key,
/// the public and private keys, and EdDSA's mandatory digest (none).
///
/// # Safety
/// `keydata` is NULL or live key data; `params` is NULL or an array.
unsafe fn get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { ecx_key(keydata) }) else {
        return 0;
    };
    let (bits, secbits, size) = sizes(k.kind);
    let keylen = k.keylen();
    let (public, private) = {
        let s = k.lock();
        (s.pubkey, s.privkey.clone())
    };
    let pubkey = public.get(..keylen).unwrap_or_default();
    // SAFETY: the caller's array, for each.
    let mut ok = unsafe { set_int(params, OSSL_PKEY_PARAM_BITS, bits) }
        // SAFETY: as above.
        && unsafe { set_int(params, OSSL_PKEY_PARAM_SECURITY_BITS, secbits) }
        // SAFETY: as above.
        && unsafe { set_int(params, OSSL_PKEY_PARAM_MAX_SIZE, size) };
    if ok && !k.kind.is_ed() {
        // SAFETY: as above.
        ok = unsafe { set_octets(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pubkey) };
    }
    // `key_to_params`.
    // SAFETY: as above.
    ok = ok && unsafe { set_octets(params, OSSL_PKEY_PARAM_PUB_KEY, pubkey) };
    if let Some(d) = private.as_deref() {
        // SAFETY: as above.
        ok = ok && unsafe { set_octets(params, OSSL_PKEY_PARAM_PRIV_KEY, d) };
    }
    if let Some(mut d) = private {
        wipe(&mut d);
    }
    if ok && k.kind.is_ed() {
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST.as_ptr()) };
        // SAFETY: a parameter of the array; a static string.
        ok = p.is_null() || unsafe { OSSL_PARAM_set_utf8_string(p, c"".as_ptr()) } != 0;
    }
    c_int::from(ok)
}

/// `ecx_gettable_params`.
static ECX_GETTABLE: Params<7> = Params([
    defn(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

/// `ed_gettable_params`.
static ED_GETTABLE: Params<7> = Params([
    defn(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

/// `ecx_set_params` (X25519 and X448): an encoded public key of the key's length (which drops
/// the private key), and the properties.
///
/// # Safety
/// `keydata` is NULL or live key data; `params` is NULL or an array.
unsafe fn set_params(keydata: *mut c_void, params: *const OSSL_PARAM) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { is_empty(params) } {
        return 1;
    }
    // SAFETY: as above.
    let Some(k) = (unsafe { ecx_key(keydata) }) else {
        return 0;
    };
    // SAFETY: the caller's array; a static name.
    if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) } {
        let keylen = k.keylen();
        if p.data_size != keylen {
            return 0;
        }
        let mut buf = [0u8; MAX_KEYLEN];
        let mut out = buf.as_mut_ptr().cast::<c_void>();
        // SAFETY: the parameter; room for the largest key.
        if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut out, MAX_KEYLEN, ptr::null_mut()) } == 0
        {
            return 0;
        }
        let mut s = k.lock();
        if let Some(dst) = s.pubkey.get_mut(..keylen) {
            dst.copy_from_slice(buf.get(..keylen).unwrap_or_default());
        }
        if let Some(mut old) = s.privkey.take() {
            wipe(&mut old);
        }
        s.haspubkey = true;
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PROPERTIES) } {
        if p.data_type != UTF8_TYPE || p.data.is_null() {
            return 0;
        }
        // SAFETY: a UTF-8 string parameter's data is a string.
        let v = unsafe { CStr::from_ptr(p.data.cast::<c_char>()) }.to_owned();
        k.lock().propq = Some(v);
    }
    1
}

/// `ecx_settable_params`.
static ECX_SETTABLE: Params<3> = Params([
    defn(
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

/// `ed_settable_params`: none.
static ED_SETTABLE: Params<1> = Params([PARAM_END]);

/// `ecx_key_pairwise_check` and `ecd_key_pairwise_check`: the private key's public key is the
/// key's.
fn pairwise(k: &EcxKey) -> bool {
    let mut s = k.lock();
    let have = s.pubkey;
    if !ecx::public_from_private(k, &mut s) {
        return false;
    }
    let derived = s.pubkey;
    s.pubkey = have;
    let n = k.keylen();
    same(
        have.get(..n).unwrap_or_default(),
        derived.get(..n).unwrap_or_default(),
    )
}

/// `ecx_validate`: the type's key length, then the parts the selection names, and the pair.
///
/// # Safety
/// `keydata` is NULL or live key data.
unsafe fn validate(keydata: *const c_void, selection: c_int, kind: EcxType) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { ecx_key(keydata) }) else {
        return 0;
    };
    let mut ok = k.kind.keylen() == kind.keylen();
    if selection & POSSIBLE == 0 {
        return 1;
    }
    if !ok {
        err::raise(ERR_LIB_PROV, PROV_R_ALGORITHM_MISMATCH, "ecx_validate");
        return 0;
    }
    {
        let s = k.lock();
        if selection & PUBLIC != 0 {
            ok = ok && s.haspubkey;
        }
        if selection & PRIVATE != 0 {
            ok = ok && s.privkey.is_some();
        }
    }
    if selection & KEYPAIR != KEYPAIR {
        return c_int::from(ok);
    }
    c_int::from(ok && pairwise(k))
}

/// `struct ecx_gen_ctx`.
struct GenCtx {
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    propq: Option<CString>,
    kind: EcxType,
    selection: c_int,
    dhkem_ikm: Option<Vec<u8>>,
}

impl Drop for GenCtx {
    fn drop(&mut self) {
        if let Some(ikm) = self.dhkem_ikm.as_mut() {
            wipe(ikm);
        }
    }
}

ffi_callback! {
    /// `ecx_gen_set_params`: a group name (only X25519's and X448's own), the properties, and the
    /// DHKEM input key material.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ecx_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_GROUP_NAME) } {
            let groupname: Option<&[u8]> = match g.kind {
                EcxType::X25519 => Some(b"x25519"),
                EcxType::X448 => Some(b"x448"),
                _ => None,
            };
            let matches = p.data_type == UTF8_TYPE
                && !p.data.is_null()
                && groupname.is_some_and(|n| {
                    // SAFETY: a UTF-8 string parameter's data is a string.
                    unsafe { CStr::from_ptr(p.data.cast::<c_char>()) }.to_bytes().eq_ignore_ascii_case(n)
                });
            if !matches {
                err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, "ecx_gen_set_params");
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_PROPERTIES) } {
            if p.data_type != UTF8_TYPE || p.data.is_null() {
                return 0;
            }
            // SAFETY: as above.
            g.propq = Some(unsafe { CStr::from_ptr(p.data.cast::<c_char>()) }.to_owned());
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_DHKEM_IKM) }
            && p.data_size != 0
            && !p.data.is_null()
        {
            let Some(ikm) = octet_param(p) else { return 0 };
            if let Some(old) = g.dhkem_ikm.as_mut() {
                wipe(old);
            }
            g.dhkem_ikm = Some(ikm.to_vec());
        }
        1
    }
}

/// `ecx_gen_settable_params`' list.
static GEN_SETTABLE: Params<4> = Params([
    defn(OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_KDF_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_DHKEM_IKM, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ecx_gen_settable_params`.
    pub(crate) unsafe extern "C" fn ecx_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

/// `ecx_gen_init`.
///
/// # Safety
/// `provctx` is the default provider's context; `params` is NULL or an array.
unsafe fn gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OSSL_PARAM,
    kind: EcxType,
) -> *mut c_void {
    let g = boxed(GenCtx {
        // SAFETY: the caller's guarantee.
        libctx: unsafe { libctx_of(provctx) },
        propq: None,
        kind,
        selection,
        dhkem_ikm: None,
    });
    // SAFETY: the context just made; the caller's array.
    if unsafe { ecx_gen_set_params(g, params) } == 0 {
        // SAFETY: the context just made, freed once.
        unsafe { unbox::<GenCtx>(g) };
        return ptr::null_mut();
    }
    g
}

ffi_callback! {
    /// `ecx_gen`: an empty key for parameter generation; otherwise a private key (random, or from
    /// the DHKEM input for X25519 and X448), clamped for X25519 and X448, and its public key.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context.
    pub(crate) unsafe extern "C" fn ecx_gen(genctx: *mut c_void, _cb: OSSL_CALLBACK, _cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else { return ptr::null_mut() };
        let h = ecx::new(g.libctx, g.kind, g.propq.as_deref());
        if g.selection & KEYPAIR == 0 {
            return h;
        }
        // SAFETY: the key just made.
        let Some(k) = (unsafe { ecx_key(h) }) else { return ptr::null_mut() };
        let keylen = k.keylen();
        let mut privkey = vec![0u8; keylen];
        let drawn = match g.dhkem_ikm.as_deref().filter(|i| !i.is_empty()) {
            Some(ikm) => {
                if g.kind.is_ed() {
                    false
                } else {
                    let kem = if g.kind == EcxType::X25519 { &ECX_KEMS[0] } else { &ECX_KEMS[1] };
                    match dhkem::derive_ecx_private(kem, ikm) {
                        Ok(sk) => {
                            privkey.copy_from_slice(sk.get(..keylen).unwrap_or_default());
                            true
                        }
                        Err(dhkem::Error::ShortInput { len, min }) => {
                            err::raise_with_text(
                                ERR_LIB_PROV,
                                PROV_R_INVALID_INPUT_LENGTH,
                                "ossl_ecx_dhkem_derive_private",
                                &format!("ikm length is :{len}, should be at least {min}"),
                            );
                            false
                        }
                        Err(_) => false,
                    }
                }
            }
            // SAFETY: the key's library context; room for the key.
            None => (unsafe { RAND_priv_bytes_ex(g.libctx, privkey.as_mut_ptr(), keylen, 0) }) > 0,
        };
        if !drawn {
            wipe(&mut privkey);
            // SAFETY: the key made above.
            unsafe { ecx::free(h) };
            return ptr::null_mut();
        }
        match g.kind {
            EcxType::X25519 => {
                if let [first, .., last] = privkey.as_mut_slice() {
                    *first &= 248;
                    *last &= 127;
                    *last |= 64;
                }
            }
            EcxType::X448 => {
                if let [first, .., last] = privkey.as_mut_slice() {
                    *first &= 252;
                    *last |= 128;
                }
            }
            EcxType::Ed25519 | EcxType::Ed448 => {}
        }
        let ok = {
            let mut s = k.lock();
            s.privkey = Some(privkey);
            let ok = ecx::public_from_private(k, &mut s);
            s.haspubkey = ok;
            ok
        };
        if !ok {
            // SAFETY: the key made above.
            unsafe { ecx::free(h) };
            return ptr::null_mut();
        }
        h
    }
}

ffi_callback! {
    /// `ecx_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn ecx_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

ffi_callback! {
    /// `ecx_load`: the key the reference points to; the reference is cleared, its key passing to the
    /// result.
    ///
    /// # Safety
    /// `reference` is NULL or points to `reference_sz` writable octets holding live key data's
    /// pointer.
    pub(crate) unsafe extern "C" fn ecx_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        if reference.is_null() || reference_sz != size_of::<*mut c_void>() {
            return ptr::null_mut();
        }
        let slot = reference.cast::<*mut c_void>().cast_mut();
        // SAFETY: the caller's guarantee.
        let h = unsafe { slot.read_unaligned() };
        // SAFETY: as above: writable.
        unsafe { slot.write_unaligned(ptr::null_mut()) };
        h
    }
}

ffi_callback! {
    /// `ecx_dup` (`ossl_ecx_key_dup`).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ecx_dup(keydata: *const c_void, selection: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ecx_key(keydata) }) else { return ptr::null_mut() };
        ecx::dup(k, selection & PUBLIC != 0, selection & PRIVATE != 0)
    }
}

ffi_callback! {
    /// `ecx_free_key`.
    ///
    /// # Safety
    /// `keydata` is NULL or key data whose reference the caller gives up.
    pub(crate) unsafe extern "C" fn ecx_free_key(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { ecx::free(keydata) };
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
type GenInitFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type GenListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type GenFn = unsafe extern "C" fn(*mut c_void, OSSL_CALLBACK, *mut c_void) -> *mut c_void;
type LoadFn = unsafe extern "C" fn(*const c_void, usize) -> *mut c_void;
type DupFn = unsafe extern "C" fn(*const c_void, c_int) -> *mut c_void;
type ValidateFn = unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int;

/// `MAKE_KEYMGMT_FUNCTIONS`: one type's functions and dispatch table.
macro_rules! ecx_keymgmt {
    ($table:ident, $kind:expr, $ed:literal, $new:ident, $get:ident, $gettable:ident, $set:ident, $settable:ident, $validate:ident, $gen_init:ident) => {
        ffi_callback! {
            /// The type's `*_new_key`.
            ///
            /// # Safety
            /// `provctx` is the default provider's context.
            pub(crate) unsafe extern "C" fn $new(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_EC
            {
                // SAFETY: the caller's guarantee.
                ecx::new(unsafe { libctx_of(provctx) }, $kind, None)
            }
        }
        ffi_callback! {
            /// The type's `*_get_params`.
            ///
            /// # Safety
            /// As for `get_params`.
            pub(crate) unsafe extern "C" fn $get(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_EC
            {
                // SAFETY: the caller's guarantee.
                unsafe { get_params(keydata, params) }
            }
        }
        ffi_callback! {
            /// The type's `*_gettable_params`.
            ///
            /// # Safety
            /// No preconditions.
            pub(crate) unsafe extern "C" fn $gettable(_provctx: *mut c_void) -> *const OSSL_PARAM
            where failure = ptr::null(), library = ERR_LIB_EC
            {
                if $ed { ED_GETTABLE.0.as_ptr() } else { ECX_GETTABLE.0.as_ptr() }
            }
        }
        ffi_callback! {
            /// The type's `*_set_params` (EdDSA's takes nothing and succeeds).
            ///
            /// # Safety
            /// As for `set_params`.
            pub(crate) unsafe extern "C" fn $set(keydata: *mut c_void, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_EC
            {
                if $ed {
                    return 1;
                }
                // SAFETY: the caller's guarantee.
                unsafe { set_params(keydata, params) }
            }
        }
        ffi_callback! {
            /// The type's `*_settable_params`.
            ///
            /// # Safety
            /// No preconditions.
            pub(crate) unsafe extern "C" fn $settable(_provctx: *mut c_void) -> *const OSSL_PARAM
            where failure = ptr::null(), library = ERR_LIB_EC
            {
                if $ed { ED_SETTABLE.0.as_ptr() } else { ECX_SETTABLE.0.as_ptr() }
            }
        }
        ffi_callback! {
            /// The type's `*_validate`.
            ///
            /// # Safety
            /// As for `validate`.
            pub(crate) unsafe extern "C" fn $validate(keydata: *const c_void, selection: c_int, _checktype: c_int) -> c_int
            where failure = 0, library = ERR_LIB_EC
            {
                // SAFETY: the caller's guarantee.
                unsafe { validate(keydata, selection, $kind) }
            }
        }
        ffi_callback! {
            /// The type's `*_gen_init`.
            ///
            /// # Safety
            /// As for `gen_init`.
            pub(crate) unsafe extern "C" fn $gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_EC
            {
                // SAFETY: the caller's guarantee.
                unsafe { gen_init(provctx, selection, params, $kind) }
            }
        }
        /// `ossl_*_keymgmt_functions`.
        pub(crate) static $table: Dispatch<21> = Dispatch([
            entry!(OSSL_FUNC_KEYMGMT_NEW, $new, NewFn),
            entry!(OSSL_FUNC_KEYMGMT_FREE, ecx_free_key, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, $get, GetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, $gettable, ListFn),
            entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, $set, SetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, $settable, ListFn),
            entry!(OSSL_FUNC_KEYMGMT_HAS, ecx_has, HasFn),
            entry!(OSSL_FUNC_KEYMGMT_MATCH, ecx_match, MatchFn),
            entry!(OSSL_FUNC_KEYMGMT_VALIDATE, $validate, ValidateFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT, ecx_import, ImportFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, ecx_imexport_types, TypesFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT, ecx_export, ExportFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, ecx_imexport_types, TypesFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, $gen_init, GenInitFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, ecx_gen_set_params, SetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, ecx_gen_settable_params, GenListFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN, ecx_gen, GenFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, ecx_gen_cleanup, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_LOAD, ecx_load, LoadFn),
            entry!(OSSL_FUNC_KEYMGMT_DUP, ecx_dup, DupFn),
            END,
        ]);
    };
}

ecx_keymgmt!(
    X25519_KEYMGMT,
    EcxType::X25519,
    false,
    x25519_new_key,
    x25519_get_params,
    x25519_gettable_params,
    x25519_set_params,
    x25519_settable_params,
    x25519_validate,
    x25519_gen_init
);
ecx_keymgmt!(
    ED25519_KEYMGMT,
    EcxType::Ed25519,
    true,
    ed25519_new_key,
    ed25519_get_params,
    ed25519_gettable_params,
    ed25519_set_params,
    ed25519_settable_params,
    ed25519_validate,
    ed25519_gen_init
);
