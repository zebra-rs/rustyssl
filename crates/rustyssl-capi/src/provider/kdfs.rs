//! The default provider's KDFs (`deflt_kdfs` in `providers/defltprov.c`): HKDF and TLS13-KDF
//! (`hkdf.c`), PBKDF2 (`pbkdf2.c`), TLS1-PRF (`tls1_prf.c`), SSKDF and X963KDF (`sskdf.c`),
//! SSHKDF (`sshkdf.c`), KBKDF (`kbkdf.c`), X942KDF-ASN1 (`x942kdf.c`), and scrypt (`scrypt.c`)
//! here, and the rest in `kdfs_more.rs`, with the table of them all.
//!
//! Like the reference's, they run over the EVP layer: HMAC through `EVP_Q_mac` and the legacy
//! `HMAC_*` functions, digests through `EVP_MD_CTX`, and MACs through `EVP_MAC_CTX`, with the
//! digests and MACs fetched from the provider's library context by name (and `properties`).
//! So any provider's digest works, and what the inner calls raise is what the reference's raise.
//! Their parameters, defaults, and checks are the reference's, quirks included (a TLS13-KDF
//! parameter call clears its `data`; an SSKDF derivation keeps the default salt it made;
//! KBKDF's `mode` matches a prefix). scrypt's computation is the KDF backend's
//! (`rustyssl_crypto::kdf::scrypt`), after the reference's checks, as is X9.42's DER
//! `OtherInfo`; X9.42's hashing is over `EVP_MD_CTX`.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_LIB_PROV, EVP_KDF_HKDF_MODE_EXPAND_ONLY, EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND,
    EVP_KDF_HKDF_MODE_EXTRACT_ONLY, EVP_MAC_CTX, EVP_MAX_MD_SIZE, EVP_MD,
    EVP_R_MEMORY_LIMIT_EXCEEDED, EVP_R_PBKDF2_ERROR, NID_id_aes128_wrap, NID_id_aes192_wrap,
    NID_id_aes256_wrap, NID_id_smime_alg_CMS3DESwrap, OSSL_ALG_PARAM_CIPHER, OSSL_ALG_PARAM_DIGEST,
    OSSL_ALG_PARAM_ENGINE, OSSL_ALG_PARAM_MAC, OSSL_ALG_PARAM_PROPERTIES, OSSL_ALGORITHM,
    OSSL_FUNC_KDF_DERIVE, OSSL_FUNC_KDF_DUPCTX, OSSL_FUNC_KDF_FREECTX,
    OSSL_FUNC_KDF_GET_CTX_PARAMS, OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS, OSSL_FUNC_KDF_NEWCTX,
    OSSL_FUNC_KDF_RESET, OSSL_FUNC_KDF_SET_CTX_PARAMS, OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
    OSSL_KDF_PARAM_CEK_ALG, OSSL_KDF_PARAM_CIPHER, OSSL_KDF_PARAM_DATA, OSSL_KDF_PARAM_DIGEST,
    OSSL_KDF_PARAM_INFO, OSSL_KDF_PARAM_ITER, OSSL_KDF_PARAM_KBKDF_R, OSSL_KDF_PARAM_KBKDF_USE_L,
    OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, OSSL_KDF_PARAM_KEY, OSSL_KDF_PARAM_LABEL,
    OSSL_KDF_PARAM_MAC, OSSL_KDF_PARAM_MAC_SIZE, OSSL_KDF_PARAM_MODE, OSSL_KDF_PARAM_PASSWORD,
    OSSL_KDF_PARAM_PKCS5, OSSL_KDF_PARAM_PREFIX, OSSL_KDF_PARAM_PROPERTIES, OSSL_KDF_PARAM_SALT,
    OSSL_KDF_PARAM_SCRYPT_MAXMEM, OSSL_KDF_PARAM_SCRYPT_N, OSSL_KDF_PARAM_SCRYPT_P,
    OSSL_KDF_PARAM_SCRYPT_R, OSSL_KDF_PARAM_SECRET, OSSL_KDF_PARAM_SEED, OSSL_KDF_PARAM_SIZE,
    OSSL_KDF_PARAM_SSHKDF_SESSION_ID, OSSL_KDF_PARAM_SSHKDF_TYPE, OSSL_KDF_PARAM_SSHKDF_XCGHASH,
    OSSL_KDF_PARAM_UKM, OSSL_KDF_PARAM_X942_ACVPINFO, OSSL_KDF_PARAM_X942_PARTYUINFO,
    OSSL_KDF_PARAM_X942_PARTYVINFO, OSSL_KDF_PARAM_X942_SUPP_PRIVINFO,
    OSSL_KDF_PARAM_X942_SUPP_PUBINFO, OSSL_KDF_PARAM_X942_USE_KEYBITS, OSSL_LIB_CTX,
    OSSL_MAC_PARAM_CIPHER, OSSL_MAC_PARAM_CUSTOM, OSSL_MAC_PARAM_DIGEST, OSSL_MAC_PARAM_PROPERTIES,
    OSSL_MAC_PARAM_SIZE, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, PKCS5_DEFAULT_ITER, PROV_R_BAD_ENCODING,
    PROV_R_BAD_LENGTH, PROV_R_INVALID_DATA, PROV_R_INVALID_ITERATION_COUNT,
    PROV_R_INVALID_KEY_LENGTH, PROV_R_INVALID_MAC, PROV_R_INVALID_MODE, PROV_R_INVALID_PUBINFO,
    PROV_R_INVALID_SALT_LENGTH, PROV_R_INVALID_SEED_LENGTH, PROV_R_INVALID_UKM_LENGTH,
    PROV_R_KEY_SIZE_TOO_SMALL, PROV_R_MISSING_CEK_ALG, PROV_R_MISSING_KEY, PROV_R_MISSING_MAC,
    PROV_R_MISSING_MESSAGE_DIGEST, PROV_R_MISSING_PASS, PROV_R_MISSING_SALT, PROV_R_MISSING_SECRET,
    PROV_R_MISSING_SEED, PROV_R_MISSING_SESSION_ID, PROV_R_MISSING_TYPE, PROV_R_MISSING_XCGHASH,
    PROV_R_NO_KEY_SET, PROV_R_NOT_SUPPORTED, PROV_R_UNABLE_TO_LOAD_SHA256,
    PROV_R_UNSUPPORTED_CEK_ALG, PROV_R_UNSUPPORTED_MAC_TYPE, PROV_R_VALUE_ERROR,
    PROV_R_WRONG_OUTPUT_BUFFER_SIZE, PROV_R_XOF_DIGESTS_NOT_ALLOWED,
};

use super::builtin::libctx_of;
use super::kdfs_more;
use super::macs::{Prov, SIZE_T, boxed, context, is_empty, locate, unbox, wipe};
use super::tables::{ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, alg, defn, entry};
use crate::err;
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_is_a};
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_MD_get0_name, EVP_MD_up_ref,
};
use crate::evp::mac::{
    EVP_MAC_CTX_dup, EVP_MAC_CTX_free, EVP_MAC_CTX_get_mac_size, EVP_MAC_CTX_get0_mac,
    EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch, EVP_MAC_final, EVP_MAC_free,
    EVP_MAC_init, EVP_MAC_is_a, EVP_MAC_update, EVP_Q_mac,
};
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy_ex,
    EVP_MD_CTX_free, EVP_MD_CTX_new, EVP_MD_xof,
};
use crate::ffi::ffi_callback;
use crate::hmac::{
    HMAC_CTX_copy, HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update,
};
use crate::mem;
use crate::objects::{OBJ_get0_data, OBJ_length, OBJ_nid2obj};
use crate::params::{
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_size_t,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_int, OSSL_PARAM_get_octet_string,
    OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint64,
    OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_locate, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_octet_string, OSSL_PARAM_set_size_t, end,
};

pub(super) type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
pub(super) type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
pub(super) type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
pub(super) type ResetFn = unsafe extern "C" fn(*mut c_void);
pub(super) type DeriveFn =
    unsafe extern "C" fn(*mut c_void, *mut c_uchar, usize, *const OSSL_PARAM) -> c_int;
pub(super) type GetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
pub(super) type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
pub(super) type CtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

pub(super) const MAX_MD: usize = EVP_MAX_MD_SIZE as usize;

// -------------------------------------------------------------------------------------------
// Shared

/// Octets a KDF keeps (a key, salt, secret, ...), wiped when dropped.
#[derive(Clone, Default)]
pub(crate) struct Secret(pub(super) Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Secret {
    pub(super) fn ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }
}

/// `ossl_prov_memdup` of a buffer: none for none, but a failure for an empty one (whose copy,
/// `OPENSSL_memdup` of no octets, is NULL there).
pub(super) fn memdup(s: &Option<Secret>) -> Option<Option<Secret>> {
    match s {
        None => Some(None),
        Some(v) if v.len() == 0 => None,
        Some(v) => Some(Some(v.clone())),
    }
}

/// The pointer the reference passes for a buffer it may not have (NULL for none).
fn ptr_of(s: Option<&Secret>) -> *const u8 {
    s.map_or(ptr::null(), Secret::ptr)
}

/// The length the reference passes alongside [`ptr_of`].
fn len_of(s: Option<&Secret>) -> usize {
    s.map_or(0, Secret::len)
}

/// `OSSL_PARAM_get_octet_string` into a buffer it allocates: the octets, or `None` (with what
/// it raised).
///
/// # Safety
/// `p` is a parameter whose data is NULL or holds `data_size` octets.
pub(super) unsafe fn get_octets(p: &OSSL_PARAM) -> Option<Secret> {
    let mut buf: *mut c_void = ptr::null_mut();
    let mut len = 0usize;
    // SAFETY: the caller's guarantee; locals for the buffer and its length.
    if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut buf, 0, &raw mut len) } == 0 {
        return None;
    }
    let out = if len == 0 || buf.is_null() {
        Vec::new()
    } else {
        // SAFETY: the buffer just allocated, of `len` octets.
        unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len) }.to_vec()
    };
    // SAFETY: the buffer allocated above, of `len` octets (one for an empty string).
    unsafe { mem::release_clean(buf, len.max(1)) };
    Some(Secret(out))
}

/// `ossl_param_get1_octet_string`: the parameter `name`'s octets into `out` (`None` for NULL
/// or empty data). -1 if there's no such parameter, 0 on an error, 1.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn get1_octets(params: *const OSSL_PARAM, name: &CStr, out: &mut Option<Secret>) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { locate(params, name) }) else {
        return -1;
    };
    let mut value = None;
    if !p.data.is_null() && p.data_size > 0 {
        // SAFETY: a parameter of the caller's array.
        match unsafe { get_octets(p) } {
            Some(v) => value = Some(v),
            None => return 0,
        }
    }
    *out = value;
    1
}

/// `ossl_param_get1_concat_octet_string`: every parameter `name`'s octets, concatenated, into
/// `out` (at most `maxsize` octets, if nonzero). -1 if there's none, 0 on an error, 1.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn concat_octets(
    params: *const OSSL_PARAM,
    name: &CStr,
    out: &mut Option<Secret>,
    maxsize: usize,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let mut p = unsafe { OSSL_PARAM_locate_const(params, name.as_ptr()) };
    if p.is_null() {
        return -1;
    }
    let mut all = Secret::default();
    // SAFETY: parameters of the caller's array, each followed by the rest of it.
    while let Some(q) = unsafe { p.as_ref() } {
        if q.data_type != OSSL_PARAM_OCTET_STRING as u32 {
            return 0;
        }
        if !q.data.is_null() && q.data_size != 0 {
            // SAFETY: the parameter's data, of `data_size` octets.
            all.0.extend_from_slice(unsafe {
                core::slice::from_raw_parts(q.data.cast::<u8>(), q.data_size)
            });
        }
        // SAFETY: the rest of the caller's array, after this parameter.
        p = unsafe { OSSL_PARAM_locate_const(p.wrapping_add(1), name.as_ptr()) };
    }
    if maxsize > 0 && all.len() > maxsize {
        return 0;
    }
    *out = Some(all);
    1
}

/// Raises `reason` in `ERR_LIB_PROV`.
pub(super) fn raise(reason: c_int, function: &str) {
    err::raise(ERR_LIB_PROV, reason, function);
}

/// The digest's size, or `None` for none (with `EVP_MD_get_size`'s error for NULL).
///
/// # Safety
/// `md` is NULL or a live digest.
pub(super) unsafe fn md_size(md: *const EVP_MD) -> Option<usize> {
    // SAFETY: the caller's guarantee.
    let sz = unsafe { EVP_MD_get_size(md) };
    usize::try_from(sz).ok().filter(|&n| n > 0)
}

/// Loads the digest the parameters name and refuses an XOF, as each KDF does when `digest`
/// is among them. False on an error.
///
/// # Safety
/// `params` is NULL or a parameter array; `provctx` is the provider's context.
pub(super) unsafe fn load_digest(
    digest: &mut Prov<EVP_MD>,
    params: *const OSSL_PARAM,
    provctx: *mut c_void,
) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { locate(params, OSSL_ALG_PARAM_DIGEST) }.is_none() {
        return true;
    }
    // SAFETY: the provider's context.
    let libctx = unsafe { libctx_of(provctx) };
    // SAFETY: the caller's array.
    if !unsafe { digest.load(params, OSSL_ALG_PARAM_DIGEST, libctx) } {
        return false;
    }
    // SAFETY: the digest just fetched.
    if unsafe { EVP_MD_xof(digest.method) } != 0 {
        raise(PROV_R_XOF_DIGESTS_NOT_ALLOWED, "load_digest");
        return false;
    }
    true
}

/// A C string parameter's text, if it's a UTF-8 string.
pub(super) fn utf8(p: &OSSL_PARAM) -> Option<*const c_char> {
    (p.data_type == OSSL_PARAM_UTF8_STRING as u32).then_some(p.data.cast_const().cast())
}

/// `ossl_prov_set_macctx` without a key: the digest (or `mdname`), cipher (or `ciphername`),
/// engine, and `properties` onto the MAC context.
///
/// # Safety
/// `macctx` is a live MAC context; `params` is NULL or a parameter array.
unsafe fn set_macctx(
    macctx: *mut EVP_MAC_CTX,
    params: *const OSSL_PARAM,
    ciphername: *const c_char,
    mdname: *const c_char,
    properties: *const c_char,
) -> bool {
    let (mut md, mut cipher, mut engine) = (mdname, ciphername, ptr::null());
    if !params.is_null() {
        for (name, slot) in [
            (OSSL_ALG_PARAM_DIGEST, &mut md),
            (OSSL_ALG_PARAM_CIPHER, &mut cipher),
            (OSSL_ALG_PARAM_ENGINE, &mut engine),
        ] {
            if !slot.is_null() {
                continue;
            }
            // SAFETY: the caller's guarantee.
            if let Some(p) = unsafe { locate(params, name) } {
                let Some(text) = utf8(p) else { return false };
                *slot = text;
            }
        }
    }
    let mut mac_params = Vec::with_capacity(5);
    for (key, value) in [
        (OSSL_MAC_PARAM_DIGEST, md),
        (OSSL_MAC_PARAM_CIPHER, cipher),
        (OSSL_MAC_PARAM_PROPERTIES, properties),
        (OSSL_ALG_PARAM_ENGINE, engine),
    ] {
        if !value.is_null() {
            // SAFETY: a static key; the caller's string, which outlives the call.
            mac_params.push(unsafe {
                OSSL_PARAM_construct_utf8_string(key.as_ptr(), value.cast_mut(), 0)
            });
        }
    }
    mac_params.push(end());
    // SAFETY: the caller's context; the array above.
    let r = unsafe { EVP_MAC_CTX_set_params(macctx, mac_params.as_ptr()) };
    r != 0
}

/// `ossl_prov_macctx_load_from_params`: a new MAC context for `macname` (or the `mac`
/// parameter), then the digest or cipher and properties set on it. False on an error, which
/// leaves no context.
///
/// # Safety
/// `macctx` is NULL or a live MAC context of the caller's; `params` is NULL or a parameter
/// array; the names are NULL or strings.
pub(super) unsafe fn macctx_load(
    macctx: &mut *mut EVP_MAC_CTX,
    params: *const OSSL_PARAM,
    macname: *const c_char,
    ciphername: *const c_char,
    mdname: *const c_char,
    libctx: *mut OSSL_LIB_CTX,
) -> bool {
    let mut macname = macname;
    let mut properties = ptr::null();
    if macname.is_null() {
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { locate(params, OSSL_ALG_PARAM_MAC) } {
            let Some(text) = utf8(p) else { return false };
            macname = text;
        }
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_ALG_PARAM_PROPERTIES) } {
        let Some(text) = utf8(p) else { return false };
        properties = text;
    }
    if !macname.is_null() {
        // SAFETY: the caller's library context, name, and query.
        let mac = unsafe { EVP_MAC_fetch(libctx, macname, properties) };
        // SAFETY: the caller's context, replaced.
        unsafe { EVP_MAC_CTX_free(*macctx) };
        *macctx = if mac.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the method just fetched.
            unsafe { EVP_MAC_CTX_new(mac) }
        };
        // SAFETY: as above; the context holds its own reference.
        unsafe { EVP_MAC_free(mac) };
        if macctx.is_null() {
            return false;
        }
    }
    if macctx.is_null() {
        return true;
    }
    // SAFETY: the live context; the caller's array and names.
    if unsafe { set_macctx(*macctx, params, ciphername, mdname, properties) } {
        return true;
    }
    // SAFETY: the context, dropped on failure.
    unsafe { EVP_MAC_CTX_free(*macctx) };
    *macctx = ptr::null_mut();
    false
}

/// Sets the `size_t` parameter `key` of `params` if it's there. False if it can't be.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn set_size(params: *mut OSSL_PARAM, key: &CStr, value: usize) -> bool {
    // SAFETY: the caller's guarantee.
    let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
    // SAFETY: a parameter of the array.
    p.is_null() || unsafe { OSSL_PARAM_set_size_t(p, value) } != 0
}

/// `HKDF_Extract`: HMAC-Hash(salt, IKM) into `prk` (exactly the digest's size).
///
/// # Safety
/// `md` is a live digest; the buffers are NULL or hold their lengths; `prk` has room for
/// `prk_len` octets.
#[expect(
    clippy::too_many_arguments,
    reason = "the reference's function, one to one"
)]
unsafe fn hkdf_extract(
    libctx: *mut OSSL_LIB_CTX,
    md: *const EVP_MD,
    salt: *const u8,
    salt_len: usize,
    ikm: *const u8,
    ikm_len: usize,
    prk: *mut u8,
    prk_len: usize,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(sz) = (unsafe { md_size(md) }) else {
        return false;
    };
    if prk_len != sz {
        raise(PROV_R_WRONG_OUTPUT_BUFFER_SIZE, "HKDF_Extract");
        return false;
    }
    // SAFETY: the caller's digest.
    let name = unsafe { EVP_MD_get0_name(md) };
    // SAFETY: the caller's library context and buffers; a static name.
    let r = unsafe {
        EVP_Q_mac(
            libctx,
            c"HMAC".as_ptr(),
            ptr::null(),
            name,
            ptr::null(),
            salt.cast(),
            salt_len,
            ikm,
            ikm_len,
            prk,
            sz,
            ptr::null_mut(),
        )
    };
    !r.is_null()
}

/// `HKDF_Expand`: T(1) || T(2) || ... into `okm`, T(i) = HMAC-Hash(PRK, T(i-1) || info || i).
///
/// # Safety
/// `md` is a live digest; `prk` and `info` are NULL or hold their lengths; `okm` is NULL or
/// has room for `okm_len` octets.
unsafe fn hkdf_expand(
    md: *const EVP_MD,
    prk: *const u8,
    prk_len: usize,
    info: *const u8,
    info_len: usize,
    okm: *mut u8,
    okm_len: usize,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(dig_len) = (unsafe { md_size(md) }) else {
        return false;
    };
    let n = okm_len.div_ceil(dig_len);
    if n > 255 || okm.is_null() {
        return false;
    }
    // SAFETY: no preconditions.
    let hmac = unsafe { HMAC_CTX_new() };
    if hmac.is_null() {
        return false;
    }
    let mut prev = [0u8; MAX_MD];
    let mut done = 0usize;
    // C's conversion of the length to `int`: the low 32 bits.
    let klen = u32::try_from(prk_len & 0xffff_ffff)
        .unwrap_or(0)
        .cast_signed();
    // SAFETY: the context made here; the caller's key and digest.
    let mut ok = unsafe { HMAC_Init_ex(hmac, prk.cast(), klen, md, ptr::null_mut()) } != 0;
    let mut i: u8 = 1;
    while ok && usize::from(i) <= n {
        if i > 1 {
            // SAFETY: as above; the previous block.
            ok = unsafe { HMAC_Init_ex(hmac, ptr::null(), 0, ptr::null(), ptr::null_mut()) } != 0
                // SAFETY: as above.
                && unsafe { HMAC_Update(hmac, prev.as_ptr(), dig_len) } != 0;
        }
        let ctr = [i];
        ok = ok
            // SAFETY: as above; the caller's info.
            && unsafe { HMAC_Update(hmac, info, info_len) } != 0
            // SAFETY: as above.
            && unsafe { HMAC_Update(hmac, ctr.as_ptr(), 1) } != 0
            // SAFETY: as above; room for any digest.
            && unsafe { HMAC_Final(hmac, prev.as_mut_ptr(), ptr::null_mut()) } != 0;
        if ok {
            let copy = dig_len.min(okm_len - done);
            // SAFETY: the caller's room, `copy` octets at `done`.
            unsafe { ptr::copy_nonoverlapping(prev.as_ptr(), okm.wrapping_add(done), copy) };
            done += copy;
        }
        i = i.wrapping_add(1);
        if i == 0 {
            break;
        }
    }
    wipe(&mut prev);
    // SAFETY: the context made here.
    unsafe { HMAC_CTX_free(hmac) };
    ok
}

/// The three KDF parameter lists' shared `size` description.
static SIZE_ONLY: Params<2> = Params([
    defn(
        OSSL_KDF_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// The gettable list of the KDFs that report only `size`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn size_only_gettable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SIZE_ONLY.0.as_ptr()
    }
}

// -------------------------------------------------------------------------------------------
// HKDF and TLS13-KDF

/// `KDF_HKDF`.
#[derive(Default)]
struct Hkdf {
    provctx: Ptr,
    mode: c_int,
    digest: Prov<EVP_MD>,
    salt: Option<Secret>,
    key: Option<Secret>,
    prefix: Option<Secret>,
    label: Option<Secret>,
    data: Option<Secret>,
    info: Option<Secret>,
}

/// A provider context pointer, defaulting to NULL.
#[derive(Clone, Copy)]
pub(super) struct Ptr(pub(super) *mut c_void);

impl Default for Ptr {
    fn default() -> Self {
        Self(ptr::null_mut())
    }
}

impl Default for Prov<EVP_MD> {
    fn default() -> Self {
        Self::NONE
    }
}

ffi_callback! {
    /// `kdf_hkdf_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn hkdf_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Hkdf { provctx: Ptr(provctx), ..Hkdf::default() })
    }
}

ffi_callback! {
    /// `kdf_hkdf_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or an HKDF context, not used afterwards.
    pub(crate) unsafe extern "C" fn hkdf_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Hkdf>(vctx) };
    }
}

ffi_callback! {
    /// `kdf_hkdf_reset`: everything gone but the provider.
    ///
    /// # Safety
    /// `vctx` is a live HKDF context.
    pub(crate) unsafe extern "C" fn hkdf_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(h) = unsafe { context::<Hkdf>(vctx) } {
            *h = Hkdf { provctx: h.provctx, ..Hkdf::default() };
        }
    }
}

ffi_callback! {
    /// `kdf_hkdf_dup`.
    ///
    /// # Safety
    /// `vctx` is a live HKDF context.
    pub(crate) unsafe extern "C" fn hkdf_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Hkdf>(vctx) }) else { return ptr::null_mut() };
        let (Some(salt), Some(key), Some(prefix), Some(label), Some(data), Some(info)) = (
            memdup(&src.salt),
            memdup(&src.key),
            memdup(&src.prefix),
            memdup(&src.label),
            memdup(&src.data),
            memdup(&src.info),
        ) else {
            return ptr::null_mut();
        };
        let Some(digest) = src.digest.copy() else { return ptr::null_mut() };
        boxed(Hkdf { provctx: src.provctx, mode: src.mode, digest, salt, key, prefix, label, data, info })
    }
}

/// `kdf_hkdf_size`: the digest's size in extract-only mode, else any.
///
/// # Safety
/// The context's digest is NULL or live.
unsafe fn hkdf_size(h: &Hkdf) -> usize {
    if h.mode != EVP_KDF_HKDF_MODE_EXTRACT_ONLY {
        return usize::MAX;
    }
    if h.digest.method.is_null() {
        raise(PROV_R_MISSING_MESSAGE_DIGEST, "kdf_hkdf_size");
        return 0;
    }
    // SAFETY: the context's digest.
    unsafe { md_size(h.digest.method) }.unwrap_or(0)
}

/// `hkdf_common_set_ctx_params`: the digest, mode, key, and salt.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn hkdf_common_set(h: &mut Hkdf, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { is_empty(params) } {
        return true;
    }
    // SAFETY: as above; the context's provider.
    if !unsafe { load_digest(&mut h.digest, params, h.provctx.0) } {
        return false;
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_MODE) } {
        let mode = if let Some(text) = utf8(p) {
            // SAFETY: a UTF-8 string parameter's data: a C string.
            let t = unsafe { CStr::from_ptr(text) }.to_bytes();
            [
                (
                    &b"EXTRACT_AND_EXPAND"[..],
                    EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND,
                ),
                (b"EXTRACT_ONLY", EVP_KDF_HKDF_MODE_EXTRACT_ONLY),
                (b"EXPAND_ONLY", EVP_KDF_HKDF_MODE_EXPAND_ONLY),
            ]
            .into_iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(t))
            .map(|(_, m)| m)
        } else {
            let mut n = 0;
            // SAFETY: a parameter of the caller's array.
            (unsafe { OSSL_PARAM_get_int(p, &raw mut n) } != 0)
                .then_some(n)
                .filter(|n| (0..=2).contains(n))
        };
        let Some(mode) = mode else {
            raise(PROV_R_INVALID_MODE, "hkdf_common_set_ctx_params");
            return false;
        };
        h.mode = mode;
    }
    for (name, slot) in [
        (OSSL_KDF_PARAM_KEY, &mut h.key),
        (OSSL_KDF_PARAM_SALT, &mut h.salt),
    ] {
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, name) } {
            *slot = None;
            // SAFETY: a parameter of the caller's array.
            let Some(v) = (unsafe { get_octets(p) }) else {
                return false;
            };
            *slot = Some(v);
        }
    }
    true
}

/// `hkdf_common_get_ctx_params`: the size and the info.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn hkdf_common_get(h: &Hkdf, params: *mut OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { is_empty(params) } {
        return true;
    }
    // SAFETY: as above.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE.as_ptr()) };
    if !p.is_null() {
        // SAFETY: the context's digest.
        let sz = unsafe { hkdf_size(h) };
        // SAFETY: a parameter of the caller's array.
        if sz == 0 || unsafe { OSSL_PARAM_set_size_t(p, sz) } == 0 {
            return false;
        }
    }
    // SAFETY: as above.
    let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_INFO.as_ptr()) };
    // SAFETY: as above.
    if let Some(q) = unsafe { p.as_mut() } {
        match h.info.as_ref().filter(|i| i.len() > 0) {
            None => q.return_size = 0,
            Some(i) => {
                // SAFETY: as above; the context's info.
                if unsafe { OSSL_PARAM_set_octet_string(q, i.ptr().cast(), i.len()) } == 0 {
                    return false;
                }
            }
        }
    }
    true
}

ffi_callback! {
    /// `kdf_hkdf_set_ctx_params`: the common parameters and the info (concatenated, at most
    /// 32 KiB).
    ///
    /// # Safety
    /// `vctx` is a live HKDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn hkdf_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(h) = (unsafe { context::<Hkdf>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if !unsafe { hkdf_common_set(h, params) } {
            return 0;
        }
        // SAFETY: as above.
        c_int::from(unsafe { concat_octets(params, OSSL_KDF_PARAM_INFO, &mut h.info, 32 * 1024) } != 0)
    }
}

ffi_callback! {
    /// `kdf_hkdf_get_ctx_params` (TLS13-KDF's too).
    ///
    /// # Safety
    /// `vctx` is a live HKDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn hkdf_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { context::<Hkdf>(vctx) }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { hkdf_common_get(h, params) })
    }
}

ffi_callback! {
    /// `kdf_hkdf_derive`: extract and expand, extract only, or expand only.
    ///
    /// # Safety
    /// `vctx` is a live HKDF context; `key` has room for `keylen` octets; `params` is NULL or
    /// a parameter array.
    pub(crate) unsafe extern "C" fn hkdf_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { hkdf_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(h) = (unsafe { context::<Hkdf>(vctx) }) else { return 0 };
        let md = h.digest.method;
        if md.is_null() {
            raise(PROV_R_MISSING_MESSAGE_DIGEST, "kdf_hkdf_derive");
            return 0;
        }
        let Some(ikm) = h.key.as_ref() else {
            raise(PROV_R_MISSING_KEY, "kdf_hkdf_derive");
            return 0;
        };
        if keylen == 0 {
            raise(PROV_R_INVALID_KEY_LENGTH, "kdf_hkdf_derive");
            return 0;
        }
        // SAFETY: the provider's context.
        let libctx = unsafe { libctx_of(h.provctx.0) };
        let (salt, salt_len) = (ptr_of(h.salt.as_ref()), len_of(h.salt.as_ref()));
        let (info, info_len) = (ptr_of(h.info.as_ref()), len_of(h.info.as_ref()));
        let ok = match h.mode {
            // SAFETY: the context's digest and buffers; the caller's room.
            EVP_KDF_HKDF_MODE_EXTRACT_ONLY => unsafe { hkdf_extract(libctx, md, salt, salt_len, ikm.ptr(), ikm.len(), key, keylen) },
            // SAFETY: as above.
            EVP_KDF_HKDF_MODE_EXPAND_ONLY => unsafe { hkdf_expand(md, ikm.ptr(), ikm.len(), info, info_len, key, keylen) },
            _ => {
                // SAFETY: as above.
                let Some(sz) = (unsafe { md_size(md) }) else { return 0 };
                let mut prk = [0u8; MAX_MD];
                // SAFETY: as above, into the local buffer of the digest's size.
                let ok = unsafe { hkdf_extract(libctx, md, salt, salt_len, ikm.ptr(), ikm.len(), prk.as_mut_ptr(), sz) }
                    // SAFETY: as above.
                    && unsafe { hkdf_expand(md, prk.as_ptr(), sz, info, info_len, key, keylen) };
                wipe(&mut prk);
                ok
            }
        };
        c_int::from(ok)
    }
}

/// `prov_tls13_hkdf_expand`: HKDF-Expand-Label.
///
/// # Safety
/// `md` is a live digest; `out` has room for `outlen` octets.
unsafe fn tls13_expand(
    md: *const EVP_MD,
    key: Option<&Secret>,
    prefix: Option<&Secret>,
    label: Option<&Secret>,
    data: Option<&[u8]>,
    out: *mut u8,
    outlen: usize,
) -> bool {
    let Ok(out16) = u16::try_from(outlen) else {
        return false;
    };
    let pl = len_of(prefix) + len_of(label);
    let Ok(pl8) = u8::try_from(pl) else {
        return false;
    };
    let data = data.unwrap_or_default();
    let Ok(dl8) = u8::try_from(data.len()) else {
        return false;
    };
    let mut hkdflabel = Vec::with_capacity(4 + pl + data.len());
    hkdflabel.extend_from_slice(&out16.to_be_bytes());
    hkdflabel.push(pl8);
    for part in [prefix, label].into_iter().flatten() {
        hkdflabel.extend_from_slice(&part.0);
    }
    hkdflabel.push(dl8);
    hkdflabel.extend_from_slice(data);
    // SAFETY: the caller's guarantee; the label above.
    unsafe {
        hkdf_expand(
            md,
            ptr_of(key),
            len_of(key),
            hkdflabel.as_ptr(),
            hkdflabel.len(),
            out,
            outlen,
        )
    }
}

ffi_callback! {
    /// `kdf_tls1_3_derive`: the extract step (with the derive-then-extract salt) or
    /// HKDF-Expand-Label.
    ///
    /// # Safety
    /// `vctx` is a live HKDF context; `key` has room for `keylen` octets; `params` is NULL or
    /// a parameter array.
    pub(crate) unsafe extern "C" fn tls13_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { tls13_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(h) = (unsafe { context::<Hkdf>(vctx) }) else { return 0 };
        let md = h.digest.method;
        if md.is_null() {
            raise(PROV_R_MISSING_MESSAGE_DIGEST, "kdf_tls1_3_derive");
            return 0;
        }
        let ok = match h.mode {
            EVP_KDF_HKDF_MODE_EXTRACT_ONLY => {
                // SAFETY: the context's digest; the caller's room.
                unsafe { tls13_generate_secret(h, md, key, keylen) }
            }
            EVP_KDF_HKDF_MODE_EXPAND_ONLY => {
                let data = h.data.as_ref().map(|d| &d.0[..]);
                // SAFETY: as above.
                unsafe { tls13_expand(md, h.key.as_ref(), h.prefix.as_ref(), h.label.as_ref(), data, key, keylen) }
            }
            _ => false,
        };
        c_int::from(ok)
    }
}

/// `prov_tls13_hkdf_generate_secret`: HKDF-Extract of the key (zeros for none) with the salt
/// derived from the previous secret (zeros for none).
///
/// # Safety
/// `md` is a live digest; `out` has room for `outlen` octets.
unsafe fn tls13_generate_secret(h: &Hkdf, md: *const EVP_MD, out: *mut u8, outlen: usize) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(mdlen) = (unsafe { md_size(md) }) else {
        return false;
    };
    let zeros = [0u8; MAX_MD];
    let (insecret, insecretlen) = match h.key.as_ref() {
        Some(k) => (k.ptr(), k.len()),
        None => (zeros.as_ptr(), mdlen),
    };
    let mut preextract = [0u8; MAX_MD];
    let (prev, prevlen) = match h.salt.as_ref() {
        None => (zeros.as_ptr(), mdlen),
        Some(prev) => {
            // The pre-extract derive step's hash of no message.
            let mut hash = [0u8; MAX_MD];
            // SAFETY: no preconditions.
            let mctx = unsafe { EVP_MD_CTX_new() };
            // SAFETY: the context made here, or NULL; the caller's digest; room for any
            // digest.
            let ok = !mctx.is_null()
                // SAFETY: as above.
                && unsafe { EVP_DigestInit_ex(mctx, md, ptr::null_mut()) } > 0
                // SAFETY: as above.
                && unsafe { EVP_DigestFinal_ex(mctx, hash.as_mut_ptr(), ptr::null_mut()) } > 0;
            // SAFETY: as above.
            unsafe { EVP_MD_CTX_free(mctx) };
            if !ok {
                return false;
            }
            let hash = hash.get(..mdlen).unwrap_or_default();
            // SAFETY: the context's octets; room for the digest's size.
            if !unsafe {
                tls13_expand(
                    md,
                    Some(prev),
                    h.prefix.as_ref(),
                    h.label.as_ref(),
                    Some(hash),
                    preextract.as_mut_ptr(),
                    mdlen,
                )
            } {
                return false;
            }
            (preextract.as_ptr(), mdlen)
        }
    };
    // SAFETY: the provider's context.
    let libctx = unsafe { libctx_of(h.provctx.0) };
    // SAFETY: the buffers above; the caller's room.
    let ok = unsafe {
        hkdf_extract(
            libctx,
            md,
            prev,
            prevlen,
            insecret,
            insecretlen,
            out,
            outlen,
        )
    };
    wipe(&mut preextract);
    ok
}

ffi_callback! {
    /// `kdf_tls1_3_set_ctx_params`: the common parameters (not in the default mode), the
    /// prefix and label, and the data (cleared by every call).
    ///
    /// # Safety
    /// `vctx` is a live HKDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn tls13_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(h) = (unsafe { context::<Hkdf>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if !unsafe { hkdf_common_set(h, params) } {
            return 0;
        }
        if h.mode == EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND {
            raise(PROV_R_INVALID_MODE, "kdf_tls1_3_set_ctx_params");
            return 0;
        }
        for (name, slot) in [(OSSL_KDF_PARAM_PREFIX, &mut h.prefix), (OSSL_KDF_PARAM_LABEL, &mut h.label)] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                *slot = None;
                // SAFETY: a parameter of the caller's array.
                let Some(v) = (unsafe { get_octets(p) }) else { return 0 };
                *slot = Some(v);
            }
        }
        h.data = None;
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_DATA) } {
            // SAFETY: a parameter of the caller's array.
            let Some(v) = (unsafe { get_octets(p) }) else { return 0 };
            h.data = Some(v);
        }
        1
    }
}

static HKDF_SETTABLE: Params<8> = Params([
    defn(OSSL_KDF_PARAM_MODE, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_MODE,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_INFO, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

static TLS13_SETTABLE: Params<10> = Params([
    defn(OSSL_KDF_PARAM_MODE, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_MODE,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_PREFIX, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_LABEL, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_DATA, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

static HKDF_GETTABLE: Params<3> = Params([
    defn(
        OSSL_KDF_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    defn(OSSL_KDF_PARAM_INFO, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `kdf_hkdf_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn hkdf_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        HKDF_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `kdf_tls1_3_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn tls13_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        TLS13_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `kdf_hkdf_gettable_ctx_params` (TLS13-KDF's too).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn hkdf_gettable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        HKDF_GETTABLE.0.as_ptr()
    }
}

static HKDF_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, hkdf_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, hkdf_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, hkdf_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, hkdf_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, hkdf_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        hkdf_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        hkdf_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        hkdf_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        hkdf_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

static TLS13_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, hkdf_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, hkdf_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, hkdf_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, hkdf_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, tls13_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        tls13_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        tls13_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        hkdf_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        hkdf_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// PBKDF2

/// `KDF_PBKDF2`.
#[derive(Default)]
struct Pbkdf2 {
    provctx: Ptr,
    pass: Option<Secret>,
    salt: Option<Secret>,
    iter: u64,
    digest: Prov<EVP_MD>,
    lower_bound_checks: bool,
}

impl Pbkdf2 {
    /// `kdf_pbkdf2_init`: SHA-1, 2048 iterations, no lower-bound checks.
    fn init(&mut self) {
        let params = [
            // SAFETY: static strings.
            unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_KDF_PARAM_DIGEST.as_ptr(),
                    c"SHA1".as_ptr().cast_mut(),
                    0,
                )
            },
            end(),
        ];
        // SAFETY: the provider's context.
        let libctx = unsafe { libctx_of(self.provctx.0) };
        // SAFETY: the array above.
        if !unsafe {
            self.digest
                .load(params.as_ptr(), OSSL_ALG_PARAM_DIGEST, libctx)
        } {
            self.digest.reset();
        }
        self.iter = u64::try_from(PKCS5_DEFAULT_ITER).unwrap_or(2048);
        self.lower_bound_checks = false;
    }
}

ffi_callback! {
    /// `kdf_pbkdf2_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn pbkdf2_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        let mut p = Pbkdf2 { provctx: Ptr(provctx), ..Pbkdf2::default() };
        p.init();
        boxed(p)
    }
}

ffi_callback! {
    /// `kdf_pbkdf2_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a PBKDF2 context, not used afterwards.
    pub(crate) unsafe extern "C" fn pbkdf2_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Pbkdf2>(vctx) };
    }
}

ffi_callback! {
    /// `kdf_pbkdf2_reset`: back to the defaults.
    ///
    /// # Safety
    /// `vctx` is a live PBKDF2 context.
    pub(crate) unsafe extern "C" fn pbkdf2_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { context::<Pbkdf2>(vctx) } {
            *p = Pbkdf2 { provctx: p.provctx, ..Pbkdf2::default() };
            p.init();
        }
    }
}

ffi_callback! {
    /// `kdf_pbkdf2_dup`.
    ///
    /// # Safety
    /// `vctx` is a live PBKDF2 context.
    pub(crate) unsafe extern "C" fn pbkdf2_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Pbkdf2>(vctx) }) else { return ptr::null_mut() };
        let (Some(salt), Some(pass)) = (memdup(&src.salt), memdup(&src.pass)) else {
            return ptr::null_mut();
        };
        let Some(digest) = src.digest.copy() else { return ptr::null_mut() };
        boxed(Pbkdf2 {
            provctx: src.provctx,
            pass,
            salt,
            iter: src.iter,
            digest,
            lower_bound_checks: src.lower_bound_checks,
        })
    }
}

/// `pbkdf2_set_membuf`: an empty buffer for no octets, the octets, or nothing for NULL ones.
///
/// # Safety
/// `p`'s data is NULL or holds `data_size` octets.
pub(super) unsafe fn set_membuf(slot: &mut Option<Secret>, p: &OSSL_PARAM) -> bool {
    *slot = None;
    if p.data_size == 0 {
        *slot = Some(Secret::default());
    } else if !p.data.is_null() {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { get_octets(p) }) else {
            return false;
        };
        *slot = Some(v);
    }
    true
}

ffi_callback! {
    /// `kdf_pbkdf2_set_ctx_params`: the digest, the PKCS#5 switch, password, salt, and
    /// iterations (with the lower bounds unless PKCS#5 mode).
    ///
    /// # Safety
    /// `vctx` is a live PBKDF2 context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn pbkdf2_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Pbkdf2>(vctx) }) else { return 0 };
        // SAFETY: as above; the context's provider.
        if !unsafe { load_digest(&mut c.digest, params, c.provctx.0) } {
            return 0;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_PKCS5) } {
            let mut pkcs5 = 0;
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_get_int(p, &raw mut pkcs5) } == 0 {
                return 0;
            }
            c.lower_bound_checks = pkcs5 == 0;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_PASSWORD) } {
            // SAFETY: a parameter of the caller's array.
            if !unsafe { set_membuf(&mut c.pass, p) } {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_SALT) } {
            if c.lower_bound_checks && p.data_size < 16 {
                raise(PROV_R_INVALID_SALT_LENGTH, "kdf_pbkdf2_set_ctx_params");
                return 0;
            }
            // SAFETY: a parameter of the caller's array.
            if !unsafe { set_membuf(&mut c.salt, p) } {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_ITER) } {
            let mut iter = 0u64;
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_get_uint64(p, &raw mut iter) } == 0 {
                return 0;
            }
            let min = if c.lower_bound_checks { 1000 } else { 1 };
            if iter < min {
                raise(PROV_R_INVALID_ITERATION_COUNT, "kdf_pbkdf2_set_ctx_params");
                return 0;
            }
            c.iter = iter;
        }
        1
    }
}

/// `pbkdf2_derive`: PBKDF2 over HMAC with the digest, into `keylen` octets of `key` (the
/// reference's `int` lengths: a key or salt past `INT_MAX` fails, where it would run past its
/// buffers).
///
/// # Safety
/// `md` is NULL or a live digest; `key` has room for `keylen` octets.
unsafe fn pbkdf2_compute(
    pass: &Secret,
    salt: &Secret,
    iter: u64,
    md: *const EVP_MD,
    key: *mut u8,
    keylen: usize,
    lower: bool,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(mdlen) = (unsafe { md_size(md) }) else {
        return false;
    };
    if keylen / mdlen >= 0xffff_ffff {
        raise(PROV_R_INVALID_KEY_LENGTH, "pbkdf2_derive");
        return false;
    }
    // C's `int` conversions of the salt's length and the key's.
    let saltlen = u32::try_from(salt.len() & 0xffff_ffff)
        .unwrap_or(0)
        .cast_signed();
    if lower {
        let reason = if keylen.saturating_mul(8) < 112 {
            Some(PROV_R_KEY_SIZE_TOO_SMALL)
        } else if saltlen < 16 {
            Some(PROV_R_INVALID_SALT_LENGTH)
        } else if iter < 1000 {
            Some(PROV_R_INVALID_ITERATION_COUNT)
        } else {
            None
        };
        if let Some(r) = reason {
            raise(r, "pbkdf2_derive");
            return false;
        }
    }
    let tkeylen = u32::try_from(keylen & 0xffff_ffff)
        .unwrap_or(0)
        .cast_signed();
    let (Ok(mut tkeylen), Ok(saltlen)) = (usize::try_from(tkeylen), usize::try_from(saltlen))
    else {
        // A negative `int`: the reference copies a length that wrapped (docs/DEVIATIONS.md).
        return false;
    };
    // SAFETY: no preconditions.
    let tpl = unsafe { HMAC_CTX_new() };
    if tpl.is_null() {
        return false;
    }
    let passlen = u32::try_from(pass.len() & 0xffff_ffff)
        .unwrap_or(0)
        .cast_signed();
    // SAFETY: no preconditions.
    let hctx = unsafe { HMAC_CTX_new() };
    let mut digtmp = [0u8; MAX_MD];
    // SAFETY: the template made here; the password; the caller's digest.
    let mut ok = unsafe { HMAC_Init_ex(tpl, pass.ptr().cast(), passlen, md, ptr::null_mut()) } != 0
        && !hctx.is_null();
    let mut out = key;
    let mut i: u32 = 1;
    while ok && tkeylen > 0 {
        let cplen = tkeylen.min(mdlen);
        let itmp = i.to_be_bytes();
        // SAFETY: the contexts made here; the salt; room for any digest.
        ok = unsafe { HMAC_CTX_copy(hctx, tpl) } != 0
            // SAFETY: as above.
            && unsafe { HMAC_Update(hctx, salt.ptr(), saltlen) } != 0
            // SAFETY: as above.
            && unsafe { HMAC_Update(hctx, itmp.as_ptr(), 4) } != 0
            // SAFETY: as above.
            && unsafe { HMAC_Final(hctx, digtmp.as_mut_ptr(), ptr::null_mut()) } != 0;
        if !ok {
            break;
        }
        // SAFETY: the caller's room: `cplen` more octets at `out`.
        let block = unsafe { core::slice::from_raw_parts_mut(out, cplen) };
        block.copy_from_slice(digtmp.get(..cplen).unwrap_or_default());
        let mut j = 1u64;
        while ok && j < iter {
            // SAFETY: as above.
            ok = unsafe { HMAC_CTX_copy(hctx, tpl) } != 0
                // SAFETY: as above.
                && unsafe { HMAC_Update(hctx, digtmp.as_ptr(), mdlen) } != 0
                // SAFETY: as above.
                && unsafe { HMAC_Final(hctx, digtmp.as_mut_ptr(), ptr::null_mut()) } != 0;
            for (b, d) in block.iter_mut().zip(digtmp.iter()) {
                *b ^= d;
            }
            j += 1;
        }
        tkeylen -= cplen;
        i = i.wrapping_add(1);
        out = out.wrapping_add(cplen);
    }
    wipe(&mut digtmp);
    // SAFETY: the contexts made here.
    unsafe { HMAC_CTX_free(hctx) };
    // SAFETY: as above.
    unsafe { HMAC_CTX_free(tpl) };
    ok
}

ffi_callback! {
    /// `kdf_pbkdf2_derive`.
    ///
    /// # Safety
    /// `vctx` is a live PBKDF2 context; `key` has room for `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn pbkdf2_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { pbkdf2_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Pbkdf2>(vctx) }) else { return 0 };
        let Some(pass) = c.pass.as_ref() else {
            raise(PROV_R_MISSING_PASS, "kdf_pbkdf2_derive");
            return 0;
        };
        let Some(salt) = c.salt.as_ref() else {
            raise(PROV_R_MISSING_SALT, "kdf_pbkdf2_derive");
            return 0;
        };
        // SAFETY: the context's digest; the caller's room.
        c_int::from(unsafe { pbkdf2_compute(pass, salt, c.iter, c.digest.method, key, keylen, c.lower_bound_checks) })
    }
}

ffi_callback! {
    /// `kdf_pbkdf2_get_ctx_params` (TLS1-PRF's too): the size, any.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn any_size_get_ctx_params(_vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { set_size(params, OSSL_KDF_PARAM_SIZE, usize::MAX) })
    }
}

static PBKDF2_SETTABLE: Params<7> = Params([
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_PASSWORD, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_ITER,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u64>(),
    ),
    defn(
        OSSL_KDF_PARAM_PKCS5,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `kdf_pbkdf2_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pbkdf2_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        PBKDF2_SETTABLE.0.as_ptr()
    }
}

static PBKDF2_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, pbkdf2_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, pbkdf2_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, pbkdf2_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, pbkdf2_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, pbkdf2_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        pbkdf2_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        pbkdf2_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        size_only_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        any_size_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// TLS1-PRF

/// `TLS1_PRF`: the HMAC contexts (two for MD5-SHA1), the secret, and the seed.
struct Tls1Prf {
    provctx: Ptr,
    p_hash: *mut EVP_MAC_CTX,
    p_sha1: *mut EVP_MAC_CTX,
    sec: Option<Secret>,
    seed: Secret,
}

impl Tls1Prf {
    fn new(provctx: Ptr) -> Self {
        Self {
            provctx,
            p_hash: ptr::null_mut(),
            p_sha1: ptr::null_mut(),
            sec: None,
            seed: Secret::default(),
        }
    }
}

impl Drop for Tls1Prf {
    fn drop(&mut self) {
        // SAFETY: the contexts this owns, or NULL.
        unsafe { EVP_MAC_CTX_free(self.p_hash) };
        // SAFETY: as above.
        unsafe { EVP_MAC_CTX_free(self.p_sha1) };
    }
}

ffi_callback! {
    /// `kdf_tls1_prf_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn tls1_prf_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Tls1Prf::new(Ptr(provctx)))
    }
}

ffi_callback! {
    /// `kdf_tls1_prf_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a TLS1-PRF context, not used afterwards.
    pub(crate) unsafe extern "C" fn tls1_prf_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Tls1Prf>(vctx) };
    }
}

ffi_callback! {
    /// `kdf_tls1_prf_reset`.
    ///
    /// # Safety
    /// `vctx` is a live TLS1-PRF context.
    pub(crate) unsafe extern "C" fn tls1_prf_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(t) = unsafe { context::<Tls1Prf>(vctx) } {
            *t = Tls1Prf::new(t.provctx);
        }
    }
}

ffi_callback! {
    /// `kdf_tls1_prf_dup`.
    ///
    /// # Safety
    /// `vctx` is a live TLS1-PRF context.
    pub(crate) unsafe extern "C" fn tls1_prf_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Tls1Prf>(vctx) }) else { return ptr::null_mut() };
        let mut dst = Tls1Prf::new(src.provctx);
        for (from, to) in [(src.p_hash, &mut dst.p_hash), (src.p_sha1, &mut dst.p_sha1)] {
            if !from.is_null() {
                // SAFETY: the source's live context.
                *to = unsafe { EVP_MAC_CTX_dup(from) };
                if to.is_null() {
                    return ptr::null_mut();
                }
            }
        }
        let Some(sec) = memdup(&src.sec) else { return ptr::null_mut() };
        dst.sec = sec;
        dst.seed = src.seed.clone();
        boxed(dst)
    }
}

ffi_callback! {
    /// `kdf_tls1_prf_set_ctx_params`: the digest (MD5-SHA1 makes two HMACs), the secret, and
    /// the seeds, appended in order.
    ///
    /// # Safety
    /// `vctx` is a live TLS1-PRF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn tls1_prf_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(t) = (unsafe { context::<Tls1Prf>(vctx) }) else { return 0 };
        // SAFETY: the provider's context.
        let libctx = unsafe { libctx_of(t.provctx.0) };
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_DIGEST) } {
            // The reference compares the data as a string, whatever its type; NULL data, which
            // it would read through, is refused (docs/DEVIATIONS.md).
            if p.data.is_null() {
                return 0;
            }
            // SAFETY: the parameter's data, read as the reference reads it: to a NUL.
            let name = unsafe { CStr::from_ptr(p.data.cast::<c_char>()) };
            let hmac = c"HMAC".as_ptr();
            let ok = if name.to_bytes().eq_ignore_ascii_case(b"MD5-SHA1") {
                // SAFETY: the context's MAC contexts; the caller's array; static names.
                let md5 = unsafe { macctx_load(&mut t.p_hash, params, hmac, ptr::null(), c"MD5".as_ptr(), libctx) };
                // SAFETY: as above.
                md5 && unsafe { macctx_load(&mut t.p_sha1, params, hmac, ptr::null(), c"SHA1".as_ptr(), libctx) }
            } else {
                // SAFETY: as above.
                unsafe { EVP_MAC_CTX_free(t.p_sha1) };
                t.p_sha1 = ptr::null_mut();
                // SAFETY: as above.
                unsafe { macctx_load(&mut t.p_hash, params, hmac, ptr::null(), ptr::null(), libctx) }
            };
            if !ok {
                return 0;
            }
            let mut digest = Prov::<EVP_MD>::NONE;
            // SAFETY: the caller's array.
            if !unsafe { digest.load(params, OSSL_ALG_PARAM_DIGEST, libctx) } {
                return 0;
            }
            // SAFETY: the digest just fetched.
            if unsafe { EVP_MD_xof(digest.method) } != 0 {
                raise(PROV_R_XOF_DIGESTS_NOT_ALLOWED, "kdf_tls1_prf_set_ctx_params");
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_SECRET) } {
            t.sec = None;
            // SAFETY: a parameter of the caller's array.
            let Some(v) = (unsafe { get_octets(p) }) else { return 0 };
            t.sec = Some(v);
        }
        // SAFETY: as above.
        let mut p = unsafe { OSSL_PARAM_locate_const(params, OSSL_KDF_PARAM_SEED.as_ptr()) };
        // SAFETY: parameters of the caller's array.
        while let Some(q) = unsafe { p.as_ref() } {
            if q.data_size != 0 && !q.data.is_null() {
                let mut val: *const c_void = ptr::null();
                let mut sz = 0usize;
                // SAFETY: a parameter of the caller's array; locals.
                if unsafe { OSSL_PARAM_get_octet_string_ptr(q, &raw mut val, &raw mut sz) } == 0 {
                    return 0;
                }
                if sz > 0 && !val.is_null() {
                    // SAFETY: the parameter's octets.
                    t.seed.0.extend_from_slice(unsafe { core::slice::from_raw_parts(val.cast::<u8>(), sz) });
                }
            }
            // SAFETY: the rest of the caller's array.
            p = unsafe { OSSL_PARAM_locate_const(p.wrapping_add(1), OSSL_KDF_PARAM_SEED.as_ptr()) };
        }
        1
    }
}

/// `tls1_prf_P_hash`: P_hash of `olen` octets into `out`.
///
/// # Safety
/// `ctx_init` is a live HMAC context; `out` has room for `olen` octets.
unsafe fn p_hash(
    ctx_init: *mut EVP_MAC_CTX,
    sec: &[u8],
    seed: &[u8],
    out: *mut u8,
    olen: usize,
) -> bool {
    let mut ai = [0u8; MAX_MD];
    let mut ai_len = 0usize;
    let mut ctx: *mut EVP_MAC_CTX = ptr::null_mut();
    let mut ctx_ai: *mut EVP_MAC_CTX = ptr::null_mut();
    let (mut out, mut olen) = (out, olen);
    let ok = 'run: {
        // SAFETY: the caller's context; the secret.
        if unsafe { EVP_MAC_init(ctx_init, sec.as_ptr(), sec.len(), ptr::null()) } == 0 {
            break 'run false;
        }
        // SAFETY: as above.
        let chunk = unsafe { EVP_MAC_CTX_get_mac_size(ctx_init) };
        if chunk == 0 {
            break 'run false;
        }
        // SAFETY: as above.
        ctx_ai = unsafe { EVP_MAC_CTX_dup(ctx_init) };
        // SAFETY: the copy, or NULL; the seed.
        if ctx_ai.is_null() || unsafe { EVP_MAC_update(ctx_ai, seed.as_ptr(), seed.len()) } == 0 {
            break 'run false;
        }
        loop {
            // SAFETY: the copy; room for any digest.
            if unsafe { EVP_MAC_final(ctx_ai, ai.as_mut_ptr(), &raw mut ai_len, ai.len()) } == 0 {
                break 'run false;
            }
            // SAFETY: the copy, done with.
            unsafe { EVP_MAC_CTX_free(ctx_ai) };
            ctx_ai = ptr::null_mut();
            // SAFETY: the caller's context.
            ctx = unsafe { EVP_MAC_CTX_dup(ctx_init) };
            // SAFETY: the copy, or NULL; A(i).
            if ctx.is_null() || unsafe { EVP_MAC_update(ctx, ai.as_ptr(), ai_len) } == 0 {
                break 'run false;
            }
            if olen > chunk {
                // SAFETY: the copy.
                ctx_ai = unsafe { EVP_MAC_CTX_dup(ctx) };
                if ctx_ai.is_null() {
                    break 'run false;
                }
            }
            // SAFETY: as above; the seed.
            if unsafe { EVP_MAC_update(ctx, seed.as_ptr(), seed.len()) } == 0 {
                break 'run false;
            }
            if olen <= chunk {
                // SAFETY: as above; room for any digest.
                if unsafe { EVP_MAC_final(ctx, ai.as_mut_ptr(), &raw mut ai_len, ai.len()) } == 0 {
                    break 'run false;
                }
                // SAFETY: the caller's room for the last `olen` octets.
                unsafe { ptr::copy_nonoverlapping(ai.as_ptr(), out, olen) };
                break 'run true;
            }
            // SAFETY: as above; the caller's room for a chunk.
            if unsafe { EVP_MAC_final(ctx, out, ptr::null_mut(), olen) } == 0 {
                break 'run false;
            }
            // SAFETY: the copy, done with.
            unsafe { EVP_MAC_CTX_free(ctx) };
            ctx = ptr::null_mut();
            out = out.wrapping_add(chunk);
            olen -= chunk;
        }
    };
    // SAFETY: the copies made here, or NULL.
    unsafe { EVP_MAC_CTX_free(ctx) };
    // SAFETY: as above.
    unsafe { EVP_MAC_CTX_free(ctx_ai) };
    wipe(&mut ai);
    ok
}

ffi_callback! {
    /// `kdf_tls1_prf_derive`: P_hash, or for MD5-SHA1 P_MD5 of the secret's first half XOR
    /// P_SHA1 of its second.
    ///
    /// # Safety
    /// `vctx` is a live TLS1-PRF context; `key` has room for `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn tls1_prf_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { tls1_prf_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(t) = (unsafe { context::<Tls1Prf>(vctx) }) else { return 0 };
        if t.p_hash.is_null() {
            raise(PROV_R_MISSING_MESSAGE_DIGEST, "kdf_tls1_prf_derive");
            return 0;
        }
        let Some(sec) = t.sec.as_ref() else {
            raise(PROV_R_MISSING_SECRET, "kdf_tls1_prf_derive");
            return 0;
        };
        if t.seed.len() == 0 {
            raise(PROV_R_MISSING_SEED, "kdf_tls1_prf_derive");
            return 0;
        }
        if keylen == 0 {
            raise(PROV_R_INVALID_KEY_LENGTH, "kdf_tls1_prf_derive");
            return 0;
        }
        let sec = &sec.0[..];
        if t.p_sha1.is_null() {
            // SAFETY: the context's HMAC; the caller's room.
            return c_int::from(unsafe { p_hash(t.p_hash, sec, &t.seed.0, key, keylen) });
        }
        let half = sec.len().div_ceil(2);
        let first = sec.get(..half).unwrap_or_default();
        let second = sec.get(sec.len() - half..).unwrap_or_default();
        // SAFETY: as above.
        if !unsafe { p_hash(t.p_hash, first, &t.seed.0, key, keylen) } {
            return 0;
        }
        let mut tmp = Secret(vec![0u8; keylen]);
        // SAFETY: the context's SHA-1 HMAC; the buffer above.
        if !unsafe { p_hash(t.p_sha1, second, &t.seed.0, tmp.0.as_mut_ptr(), keylen) } {
            return 0;
        }
        // SAFETY: the caller's room for `keylen` octets, written above.
        let out = unsafe { core::slice::from_raw_parts_mut(key, keylen) };
        for (o, x) in out.iter_mut().zip(tmp.0.iter()) {
            *o ^= x;
        }
        1
    }
}

static TLS1_PRF_SETTABLE: Params<5> = Params([
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SECRET, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SEED, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `kdf_tls1_prf_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn tls1_prf_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        TLS1_PRF_SETTABLE.0.as_ptr()
    }
}

static TLS1_PRF_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, tls1_prf_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, tls1_prf_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, tls1_prf_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, tls1_prf_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, tls1_prf_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        tls1_prf_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        tls1_prf_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        size_only_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        any_size_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// SSKDF and X963KDF

/// `SSKDF_MAX_INLEN`.
const SSKDF_MAX_INLEN: usize = 1 << 30;
/// KMAC's customization for SSKDF: "KDF".
const KMAC_CUSTOM: [u8; 3] = [0x4b, 0x44, 0x46];

/// `KDF_SSKDF`.
struct Sskdf {
    provctx: Ptr,
    macctx: *mut EVP_MAC_CTX,
    digest: Prov<EVP_MD>,
    secret: Option<Secret>,
    info: Option<Secret>,
    salt: Option<Secret>,
    out_len: usize,
    is_kmac: bool,
}

impl Sskdf {
    fn new(provctx: Ptr) -> Self {
        Self {
            provctx,
            macctx: ptr::null_mut(),
            digest: Prov::NONE,
            secret: None,
            info: None,
            salt: None,
            out_len: 0,
            is_kmac: false,
        }
    }
}

impl Drop for Sskdf {
    fn drop(&mut self) {
        // SAFETY: the context this owns, or NULL.
        unsafe { EVP_MAC_CTX_free(self.macctx) };
    }
}

ffi_callback! {
    /// `sskdf_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn sskdf_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Sskdf::new(Ptr(provctx)))
    }
}

ffi_callback! {
    /// `sskdf_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or an SSKDF context, not used afterwards.
    pub(crate) unsafe extern "C" fn sskdf_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Sskdf>(vctx) };
    }
}

ffi_callback! {
    /// `sskdf_reset`.
    ///
    /// # Safety
    /// `vctx` is a live SSKDF context.
    pub(crate) unsafe extern "C" fn sskdf_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { context::<Sskdf>(vctx) } {
            *s = Sskdf::new(s.provctx);
        }
    }
}

ffi_callback! {
    /// `sskdf_dup`.
    ///
    /// # Safety
    /// `vctx` is a live SSKDF context.
    pub(crate) unsafe extern "C" fn sskdf_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Sskdf>(vctx) }) else { return ptr::null_mut() };
        let mut dst = Sskdf::new(src.provctx);
        if !src.macctx.is_null() {
            // SAFETY: the source's live context.
            dst.macctx = unsafe { EVP_MAC_CTX_dup(src.macctx) };
            if dst.macctx.is_null() {
                return ptr::null_mut();
            }
        }
        let (Some(info), Some(salt), Some(secret)) = (memdup(&src.info), memdup(&src.salt), memdup(&src.secret)) else {
            return ptr::null_mut();
        };
        dst.info = info;
        dst.salt = salt;
        dst.secret = secret;
        let Some(digest) = src.digest.copy() else { return ptr::null_mut() };
        dst.digest = digest;
        dst.out_len = src.out_len;
        dst.is_kmac = src.is_kmac;
        boxed(dst)
    }
}

/// `sskdf_size`: any for KMAC, else the digest's size.
///
/// # Safety
/// The context's digest is NULL or live.
unsafe fn sskdf_size(s: &Sskdf) -> usize {
    if s.is_kmac {
        return usize::MAX;
    }
    if s.digest.method.is_null() {
        raise(PROV_R_MISSING_MESSAGE_DIGEST, "sskdf_size");
        return 0;
    }
    // SAFETY: the context's digest.
    unsafe { md_size(s.digest.method) }.unwrap_or(0)
}

/// `SSKDF_hash_kdm`: Hash(counter || Z || info), or for X9.63 Hash(Z || counter || info),
/// for counters from 1.
///
/// # Safety
/// `md` is a live digest; `out` has room for `len` octets.
unsafe fn hash_kdm(
    md: *const EVP_MD,
    z: &[u8],
    info: &[u8],
    append_ctr: bool,
    out: *mut u8,
    len: usize,
) -> bool {
    if z.len() > SSKDF_MAX_INLEN
        || info.len() > SSKDF_MAX_INLEN
        || len > SSKDF_MAX_INLEN
        || len == 0
    {
        return false;
    }
    // SAFETY: the caller's guarantee.
    let Some(hlen) = (unsafe { md_size(md) }) else {
        return false;
    };
    // SAFETY: no preconditions.
    let ctx = unsafe { EVP_MD_CTX_new() };
    // SAFETY: as above.
    let init = unsafe { EVP_MD_CTX_new() };
    let mut mac = [0u8; MAX_MD];
    let (mut out, mut len) = (out, len);
    // SAFETY: the contexts made here, or NULL; the caller's digest.
    let mut ok = !ctx.is_null() && !init.is_null() && unsafe { EVP_DigestInit(init, md) } != 0;
    let mut counter: u32 = 1;
    while ok {
        let c = counter.to_be_bytes();
        // SAFETY: the contexts made here; the octets above and the caller's.
        ok = unsafe { EVP_MD_CTX_copy_ex(ctx, init) } != 0
            // SAFETY: as above.
            && (append_ctr || unsafe { EVP_DigestUpdate(ctx, c.as_ptr().cast(), 4) } != 0)
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(ctx, z.as_ptr().cast(), z.len()) } != 0
            // SAFETY: as above.
            && (!append_ctr || unsafe { EVP_DigestUpdate(ctx, c.as_ptr().cast(), 4) } != 0)
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(ctx, info.as_ptr().cast(), info.len()) } != 0;
        if !ok {
            break;
        }
        if len >= hlen {
            // SAFETY: the caller's room for a block.
            ok = unsafe { EVP_DigestFinal_ex(ctx, out, ptr::null_mut()) } != 0;
            out = out.wrapping_add(hlen);
            len -= hlen;
            if len == 0 {
                break;
            }
        } else {
            // SAFETY: room for any digest; the caller's for the rest.
            ok = unsafe { EVP_DigestFinal_ex(ctx, mac.as_mut_ptr(), ptr::null_mut()) } != 0;
            if ok {
                // SAFETY: as above.
                unsafe { ptr::copy_nonoverlapping(mac.as_ptr(), out, len) };
            }
            break;
        }
        counter = counter.wrapping_add(1);
    }
    // SAFETY: the contexts made here.
    unsafe { EVP_MD_CTX_free(ctx) };
    // SAFETY: as above.
    unsafe { EVP_MD_CTX_free(init) };
    wipe(&mut mac);
    ok
}

/// `SSKDF_mac_kdm`: MAC(counter || Z || info) keyed with the salt, for counters from 1 (KMAC
/// customized "KDF" and sized first).
///
/// # Safety
/// `ctx_init` is a live MAC context; `out` has room for `len` octets.
#[expect(
    clippy::too_many_arguments,
    reason = "the reference's function, one to one"
)]
unsafe fn mac_kdm(
    ctx_init: *mut EVP_MAC_CTX,
    kmac: bool,
    kmac_out_len: usize,
    salt: &[u8],
    z: &[u8],
    info: &[u8],
    out: *mut u8,
    len: usize,
) -> bool {
    if z.len() > SSKDF_MAX_INLEN
        || info.len() > SSKDF_MAX_INLEN
        || len > SSKDF_MAX_INLEN
        || len == 0
    {
        return false;
    }
    let mut kmac_buffer: Option<Secret> = None;
    if kmac {
        let params = [
            // SAFETY: a static key and the static custom string.
            unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_MAC_PARAM_CUSTOM.as_ptr(),
                    KMAC_CUSTOM.as_ptr().cast_mut().cast(),
                    KMAC_CUSTOM.len(),
                )
            },
            end(),
        ];
        // SAFETY: the caller's context; the array above.
        if unsafe { EVP_MAC_CTX_set_params(ctx_init, params.as_ptr()) } == 0 {
            return false;
        }
        let mut size = if kmac_out_len == 0 { len } else { kmac_out_len };
        if !(size == len || [20, 28, 32, 48, 64].contains(&size)) {
            return false;
        }
        let params = [
            // SAFETY: a static key; the local size.
            unsafe { OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE.as_ptr(), &raw mut size) },
            end(),
        ];
        // SAFETY: as above.
        if unsafe { EVP_MAC_CTX_set_params(ctx_init, params.as_ptr()) } <= 0 {
            return false;
        }
        if size > MAX_MD {
            kmac_buffer = Some(Secret(vec![0u8; size]));
        }
    }
    // SAFETY: as above; the salt.
    if unsafe { EVP_MAC_init(ctx_init, salt.as_ptr(), salt.len(), ptr::null()) } == 0 {
        return false;
    }
    // SAFETY: as above.
    let out_len = unsafe { EVP_MAC_CTX_get_mac_size(ctx_init) };
    if out_len == 0 || (kmac_buffer.is_none() && out_len > MAX_MD) {
        return false;
    }
    let mut mac_buf = [0u8; MAX_MD];
    let mac: *mut u8 = match kmac_buffer.as_mut() {
        Some(b) => b.0.as_mut_ptr(),
        None => mac_buf.as_mut_ptr(),
    };
    let (mut out, mut len) = (out, len);
    let mut counter: u32 = 1;
    let ok = loop {
        let c = counter.to_be_bytes();
        // SAFETY: as above.
        let ctx = unsafe { EVP_MAC_CTX_dup(ctx_init) };
        // SAFETY: the copy, or NULL; the octets above and the caller's.
        let mut ok = !ctx.is_null()
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(ctx, c.as_ptr(), 4) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(ctx, z.as_ptr(), z.len()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(ctx, info.as_ptr(), info.len()) } != 0;
        let mut done = !ok;
        if ok {
            if len >= out_len {
                // SAFETY: the copy; the caller's room.
                ok = unsafe { EVP_MAC_final(ctx, out, ptr::null_mut(), len) } != 0;
                out = out.wrapping_add(out_len);
                len -= out_len;
                done = !ok || len == 0;
            } else {
                // SAFETY: the copy; the buffer of the MAC's size.
                ok = unsafe { EVP_MAC_final(ctx, mac, ptr::null_mut(), out_len) } != 0;
                if ok {
                    // SAFETY: the buffer; the caller's room for the rest.
                    unsafe { ptr::copy_nonoverlapping(mac, out, len) };
                }
                done = true;
            }
        }
        // SAFETY: the copy made here, or NULL.
        unsafe { EVP_MAC_CTX_free(ctx) };
        if done {
            break ok;
        }
        counter = counter.wrapping_add(1);
    };
    wipe(&mut mac_buf);
    ok
}

/// `sskdf_common_set_ctx_params`: the MAC, the digest, the secret (or key), info, salt, and
/// the KMAC output size.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn sskdf_common_set(s: &mut Sskdf, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { is_empty(params) } {
        return true;
    }
    // SAFETY: the provider's context.
    let libctx = unsafe { libctx_of(s.provctx.0) };
    // SAFETY: the context's MAC context; the caller's array.
    if !unsafe {
        macctx_load(
            &mut s.macctx,
            params,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            libctx,
        )
    } {
        return false;
    }
    if !s.macctx.is_null() {
        // SAFETY: the live MAC context.
        let mac = unsafe { EVP_MAC_CTX_get0_mac(s.macctx) };
        // SAFETY: its method; static names.
        let k128 = unsafe { EVP_MAC_is_a(mac, c"KMAC-128".as_ptr()) } != 0;
        // SAFETY: as above.
        if k128 || unsafe { EVP_MAC_is_a(mac, c"KMAC-256".as_ptr()) } != 0 {
            s.is_kmac = true;
        }
    }
    // SAFETY: as above.
    if !unsafe { load_digest(&mut s.digest, params, s.provctx.0) } {
        return false;
    }
    // SAFETY: as above.
    let mut r = unsafe { get1_octets(params, OSSL_KDF_PARAM_SECRET, &mut s.secret) };
    if r == -1 {
        // SAFETY: as above.
        r = unsafe { get1_octets(params, OSSL_KDF_PARAM_KEY, &mut s.secret) };
    }
    if r == 0 {
        return false;
    }
    // SAFETY: as above.
    if unsafe { concat_octets(params, OSSL_KDF_PARAM_INFO, &mut s.info, 0) } == 0 {
        return false;
    }
    // SAFETY: as above.
    if unsafe { get1_octets(params, OSSL_KDF_PARAM_SALT, &mut s.salt) } == 0 {
        return false;
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_MAC_SIZE) } {
        let mut sz = 0usize;
        // SAFETY: a parameter of the caller's array.
        if unsafe { OSSL_PARAM_get_size_t(p, &raw mut sz) } == 0 || sz == 0 {
            return false;
        }
        s.out_len = sz;
    }
    true
}

ffi_callback! {
    /// `sskdf_set_ctx_params` (X963KDF's too).
    ///
    /// # Safety
    /// `vctx` is a live SSKDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn sskdf_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { context::<Sskdf>(vctx) }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { sskdf_common_set(s, params) })
    }
}

ffi_callback! {
    /// `sskdf_get_ctx_params` (X963KDF's too): the size.
    ///
    /// # Safety
    /// `vctx` is a live SSKDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn sskdf_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(s) = (unsafe { context::<Sskdf>(vctx) }) else { return 0 };
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE.as_ptr()) };
        if !p.is_null() {
            // SAFETY: the context's digest.
            let sz = unsafe { sskdf_size(s) };
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_set_size_t(p, sz) } == 0 {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `sskdf_derive`: over the MAC (HMAC or KMAC, salt defaulting to zeros, which it keeps) or
    /// the digest.
    ///
    /// # Safety
    /// `vctx` is a live SSKDF context; `key` has room for `keylen` octets; `params` is NULL or
    /// a parameter array.
    pub(crate) unsafe extern "C" fn sskdf_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { sskdf_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(s) = (unsafe { context::<Sskdf>(vctx) }) else { return 0 };
        if s.secret.is_none() {
            raise(PROV_R_MISSING_SECRET, "sskdf_derive");
            return 0;
        }
        let md = s.digest.method;
        if s.macctx.is_null() {
            if md.is_null() {
                raise(PROV_R_MISSING_MESSAGE_DIGEST, "sskdf_derive");
                return 0;
            }
            let z = s.secret.as_ref().map(|x| &x.0[..]).unwrap_or_default();
            let info = s.info.as_ref().map(|x| &x.0[..]).unwrap_or_default();
            // SAFETY: the context's digest; the caller's room.
            return c_int::from(unsafe { hash_kdm(md, z, info, false, key, keylen) });
        }
        // SAFETY: the live MAC context.
        let mac = unsafe { EVP_MAC_CTX_get0_mac(s.macctx) };
        // SAFETY: its method; a static name.
        let default_salt_len = if unsafe { EVP_MAC_is_a(mac, c"HMAC".as_ptr()) } != 0 {
            if md.is_null() {
                raise(PROV_R_MISSING_MESSAGE_DIGEST, "sskdf_derive");
                return 0;
            }
            // SAFETY: the context's digest.
            let Some(n) = (unsafe { md_size(md) }) else { return 0 };
            n
        } else if s.is_kmac {
            // SAFETY: as above.
            if unsafe { EVP_MAC_is_a(mac, c"KMAC-128".as_ptr()) } != 0 { 168 - 4 } else { 136 - 4 }
        } else {
            raise(PROV_R_UNSUPPORTED_MAC_TYPE, "sskdf_derive");
            return 0;
        };
        if s.salt.as_ref().is_none_or(|x| x.len() == 0) {
            s.salt = Some(Secret(vec![0u8; default_salt_len]));
        }
        let salt = s.salt.as_ref().map(|x| &x.0[..]).unwrap_or_default();
        let z = s.secret.as_ref().map(|x| &x.0[..]).unwrap_or_default();
        let info = s.info.as_ref().map(|x| &x.0[..]).unwrap_or_default();
        // SAFETY: the context's MAC; the caller's room.
        c_int::from(unsafe { mac_kdm(s.macctx, s.is_kmac, s.out_len, salt, z, info, key, keylen) })
    }
}

ffi_callback! {
    /// `x963kdf_derive`: over the digest only.
    ///
    /// # Safety
    /// `vctx` is a live SSKDF context; `key` has room for `keylen` octets; `params` is NULL or
    /// a parameter array.
    pub(crate) unsafe extern "C" fn x963kdf_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { sskdf_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(s) = (unsafe { context::<Sskdf>(vctx) }) else { return 0 };
        let Some(z) = s.secret.as_ref() else {
            raise(PROV_R_MISSING_SECRET, "x963kdf_derive");
            return 0;
        };
        if !s.macctx.is_null() {
            raise(PROV_R_NOT_SUPPORTED, "x963kdf_derive");
            return 0;
        }
        let md = s.digest.method;
        if md.is_null() {
            raise(PROV_R_MISSING_MESSAGE_DIGEST, "x963kdf_derive");
            return 0;
        }
        let info = s.info.as_ref().map(|x| &x.0[..]).unwrap_or_default();
        // SAFETY: the context's digest; the caller's room.
        c_int::from(unsafe { hash_kdm(md, &z.0, info, true, key, keylen) })
    }
}

static SSKDF_SETTABLE: Params<9> = Params([
    defn(OSSL_KDF_PARAM_SECRET, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_INFO, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_MAC, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_MAC_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `sskdf_settable_ctx_params` (X963KDF's too).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sskdf_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SSKDF_SETTABLE.0.as_ptr()
    }
}

/// An SSKDF-family dispatch table with its `derive`.
macro_rules! sskdf_table {
    ($derive:ident) => {
        Dispatch([
            entry!(OSSL_FUNC_KDF_NEWCTX, sskdf_new, NewCtxFn),
            entry!(OSSL_FUNC_KDF_DUPCTX, sskdf_dup, DupCtxFn),
            entry!(OSSL_FUNC_KDF_FREECTX, sskdf_free, FreeCtxFn),
            entry!(OSSL_FUNC_KDF_RESET, sskdf_reset, ResetFn),
            entry!(OSSL_FUNC_KDF_DERIVE, $derive, DeriveFn),
            entry!(
                OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
                sskdf_settable,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_KDF_SET_CTX_PARAMS,
                sskdf_set_ctx_params,
                SetCtxParamsFn
            ),
            entry!(
                OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
                size_only_gettable,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_KDF_GET_CTX_PARAMS,
                sskdf_get_ctx_params,
                GetCtxParamsFn
            ),
            END,
        ])
    };
}

static SSKDF_FUNCTIONS: Dispatch<10> = sskdf_table!(sskdf_derive);
static X963KDF_FUNCTIONS: Dispatch<10> = sskdf_table!(x963kdf_derive);

// -------------------------------------------------------------------------------------------
// SSHKDF

/// `KDF_SSHKDF`.
#[derive(Default)]
struct Sshkdf {
    provctx: Ptr,
    digest: Prov<EVP_MD>,
    key: Option<Secret>,
    xcghash: Option<Secret>,
    session_id: Option<Secret>,
    kind: u8,
}

ffi_callback! {
    /// `kdf_sshkdf_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn sshkdf_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Sshkdf { provctx: Ptr(provctx), ..Sshkdf::default() })
    }
}

ffi_callback! {
    /// `kdf_sshkdf_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or an SSHKDF context, not used afterwards.
    pub(crate) unsafe extern "C" fn sshkdf_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Sshkdf>(vctx) };
    }
}

ffi_callback! {
    /// `kdf_sshkdf_reset`.
    ///
    /// # Safety
    /// `vctx` is a live SSHKDF context.
    pub(crate) unsafe extern "C" fn sshkdf_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context::<Sshkdf>(vctx) } {
            *c = Sshkdf { provctx: c.provctx, ..Sshkdf::default() };
        }
    }
}

ffi_callback! {
    /// `kdf_sshkdf_dup`.
    ///
    /// # Safety
    /// `vctx` is a live SSHKDF context.
    pub(crate) unsafe extern "C" fn sshkdf_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Sshkdf>(vctx) }) else { return ptr::null_mut() };
        let (Some(key), Some(xcghash), Some(session_id)) = (memdup(&src.key), memdup(&src.xcghash), memdup(&src.session_id)) else {
            return ptr::null_mut();
        };
        let Some(digest) = src.digest.copy() else { return ptr::null_mut() };
        boxed(Sshkdf { provctx: src.provctx, digest, key, xcghash, session_id, kind: src.kind })
    }
}

ffi_callback! {
    /// `kdf_sshkdf_set_ctx_params`: the digest, K, H, the session id, and the type (A to F).
    ///
    /// # Safety
    /// `vctx` is a live SSHKDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn sshkdf_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Sshkdf>(vctx) }) else { return 0 };
        // SAFETY: as above; the context's provider.
        if !unsafe { load_digest(&mut c.digest, params, c.provctx.0) } {
            return 0;
        }
        for (name, slot) in [
            (OSSL_KDF_PARAM_KEY, &mut c.key),
            (OSSL_KDF_PARAM_SSHKDF_XCGHASH, &mut c.xcghash),
            (OSSL_KDF_PARAM_SSHKDF_SESSION_ID, &mut c.session_id),
        ] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                *slot = None;
                // SAFETY: a parameter of the caller's array.
                let Some(v) = (unsafe { get_octets(p) }) else { return 0 };
                *slot = Some(v);
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_SSHKDF_TYPE) } {
            let mut text: *const c_char = ptr::null();
            // SAFETY: a parameter of the caller's array; a local.
            if unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &raw mut text) } == 0 || text.is_null() || p.data_size != 1 {
                return 0;
            }
            // SAFETY: the parameter's one octet.
            let t = unsafe { text.cast::<u8>().read() };
            if !(b'A'..=b'F').contains(&t) {
                raise(PROV_R_VALUE_ERROR, "kdf_sshkdf_set_ctx_params");
                return 0;
            }
            c.kind = t;
        }
        1
    }
}

/// `SSHKDF`: K1 = HASH(K || H || type || session_id), then K(n) = HASH(K || H || K1..K(n-1)).
/// Over a digest of no size the reference loops forever; it fails here (docs/DEVIATIONS.md).
///
/// # Safety
/// `md` is a live digest; `okey` has room for `okey_len` octets.
unsafe fn sshkdf_compute(
    md: *const EVP_MD,
    key: &[u8],
    xcghash: &[u8],
    kind: u8,
    session_id: &[u8],
    okey: *mut u8,
    okey_len: usize,
) -> bool {
    // SAFETY: no preconditions.
    let mctx = unsafe { EVP_MD_CTX_new() };
    if mctx.is_null() {
        return false;
    }
    let mut digest = [0u8; MAX_MD];
    let mut dsize: c_uint = 0;
    let t = [kind];
    // SAFETY: the context made here; the caller's digest and octets; room for any digest.
    let mut ok = unsafe { EVP_DigestInit_ex(mctx, md, ptr::null_mut()) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestUpdate(mctx, key.as_ptr().cast(), key.len()) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestUpdate(mctx, xcghash.as_ptr().cast(), xcghash.len()) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestUpdate(mctx, t.as_ptr().cast(), 1) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestUpdate(mctx, session_id.as_ptr().cast(), session_id.len()) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestFinal_ex(mctx, digest.as_mut_ptr(), &raw mut dsize) } != 0;
    let mut d = dsize as usize;
    if ok && okey_len > 0 && d == 0 {
        ok = false;
    }
    if ok {
        let n = okey_len.min(d);
        // SAFETY: the caller's room.
        unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), okey, n) };
        let mut cursize = n;
        while ok && cursize < okey_len {
            // SAFETY: as above; the octets written so far.
            ok = unsafe { EVP_DigestInit_ex(mctx, md, ptr::null_mut()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(mctx, key.as_ptr().cast(), key.len()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(mctx, xcghash.as_ptr().cast(), xcghash.len()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(mctx, okey.cast_const().cast(), cursize) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestFinal_ex(mctx, digest.as_mut_ptr(), &raw mut dsize) } != 0;
            d = dsize as usize;
            if ok && d == 0 {
                ok = false;
            }
            if ok {
                let n = (okey_len - cursize).min(d);
                // SAFETY: the caller's room for `n` more octets.
                unsafe { ptr::copy_nonoverlapping(digest.as_ptr(), okey.wrapping_add(cursize), n) };
                cursize += n;
            }
        }
    }
    // SAFETY: the context made here.
    unsafe { EVP_MD_CTX_free(mctx) };
    wipe(&mut digest);
    ok
}

ffi_callback! {
    /// `kdf_sshkdf_derive`.
    ///
    /// # Safety
    /// `vctx` is a live SSHKDF context; `key` has room for `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn sshkdf_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { sshkdf_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(c) = (unsafe { context::<Sshkdf>(vctx) }) else { return 0 };
        let md = c.digest.method;
        let missing = if md.is_null() {
            Some(PROV_R_MISSING_MESSAGE_DIGEST)
        } else if c.key.is_none() {
            Some(PROV_R_MISSING_KEY)
        } else if c.xcghash.is_none() {
            Some(PROV_R_MISSING_XCGHASH)
        } else if c.session_id.is_none() {
            Some(PROV_R_MISSING_SESSION_ID)
        } else if c.kind == 0 {
            Some(PROV_R_MISSING_TYPE)
        } else {
            None
        };
        if let Some(r) = missing {
            raise(r, "kdf_sshkdf_derive");
            return 0;
        }
        let bytes = |s: &Option<Secret>| s.as_ref().map(|x| x.0.clone()).unwrap_or_default();
        let (k, h, sid) = (Secret(bytes(&c.key)), Secret(bytes(&c.xcghash)), Secret(bytes(&c.session_id)));
        // SAFETY: the context's digest; the caller's room.
        c_int::from(unsafe { sshkdf_compute(md, &k.0, &h.0, c.kind, &sid.0, key, keylen) })
    }
}

static SSHKDF_SETTABLE: Params<7> = Params([
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_SSHKDF_XCGHASH,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_SSHKDF_SESSION_ID,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_SSHKDF_TYPE,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `kdf_sshkdf_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sshkdf_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SSHKDF_SETTABLE.0.as_ptr()
    }
}

static SSHKDF_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, sshkdf_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, sshkdf_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, sshkdf_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, sshkdf_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, sshkdf_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        sshkdf_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        sshkdf_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        size_only_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        any_size_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// KBKDF

/// `KBKDF`.
struct Kbkdf {
    provctx: Ptr,
    feedback: bool,
    ctx_init: *mut EVP_MAC_CTX,
    r: c_int,
    ki: Option<Secret>,
    label: Option<Secret>,
    context: Option<Secret>,
    iv: Option<Secret>,
    use_l: c_int,
    is_kmac: bool,
    use_separator: c_int,
}

impl Kbkdf {
    fn new(provctx: Ptr) -> Self {
        Self {
            provctx,
            feedback: false,
            ctx_init: ptr::null_mut(),
            r: 32,
            ki: None,
            label: None,
            context: None,
            iv: None,
            use_l: 1,
            is_kmac: false,
            use_separator: 1,
        }
    }
}

impl Drop for Kbkdf {
    fn drop(&mut self) {
        // SAFETY: the context this owns, or NULL.
        unsafe { EVP_MAC_CTX_free(self.ctx_init) };
    }
}

ffi_callback! {
    /// `kbkdf_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn kbkdf_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Kbkdf::new(Ptr(provctx)))
    }
}

ffi_callback! {
    /// `kbkdf_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a KBKDF context, not used afterwards.
    pub(crate) unsafe extern "C" fn kbkdf_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Kbkdf>(vctx) };
    }
}

ffi_callback! {
    /// `kbkdf_reset`.
    ///
    /// # Safety
    /// `vctx` is a live KBKDF context.
    pub(crate) unsafe extern "C" fn kbkdf_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { context::<Kbkdf>(vctx) } {
            *k = Kbkdf::new(k.provctx);
        }
    }
}

ffi_callback! {
    /// `kbkdf_dup`: fails for a context without a MAC, as the reference's does.
    ///
    /// # Safety
    /// `vctx` is a live KBKDF context.
    pub(crate) unsafe extern "C" fn kbkdf_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Kbkdf>(vctx) }) else { return ptr::null_mut() };
        let mut dst = Kbkdf::new(src.provctx);
        // SAFETY: the source's context, or NULL.
        dst.ctx_init = unsafe { EVP_MAC_CTX_dup(src.ctx_init) };
        if dst.ctx_init.is_null() {
            return ptr::null_mut();
        }
        let (Some(ki), Some(label), Some(context), Some(iv)) = (memdup(&src.ki), memdup(&src.label), memdup(&src.context), memdup(&src.iv)) else {
            return ptr::null_mut();
        };
        dst.ki = ki;
        dst.label = label;
        dst.context = context;
        dst.iv = iv;
        dst.feedback = src.feedback;
        dst.r = src.r;
        dst.use_l = src.use_l;
        dst.use_separator = src.use_separator;
        dst.is_kmac = src.is_kmac;
        boxed(dst)
    }
}

/// `OPENSSL_strncasecmp(word, data, n)` as the reference calls it on the `mode` parameter:
/// a match of the data's first `n` octets (to a NUL in either) against `word`.
///
/// # Safety
/// `data` is NULL (for 0) or holds `n` octets.
unsafe fn strncasecmp_eq(word: &[u8], data: *const u8, n: usize) -> bool {
    for i in 0..n {
        let a = word.get(i).copied().unwrap_or(0);
        // SAFETY: the caller's guarantee: `n` octets.
        let b = unsafe { data.wrapping_add(i).read() };
        if !a.eq_ignore_ascii_case(&b) {
            return false;
        }
        if a == 0 {
            return true;
        }
    }
    true
}

/// `kmac_init` for KBKDF: the label as KMAC's customization.
///
/// # Safety
/// `ctx` is a live MAC context.
unsafe fn kbkdf_kmac_init(ctx: *mut EVP_MAC_CTX, custom: Option<&Secret>) -> bool {
    let Some(c) = custom.filter(|c| c.len() > 0) else {
        return true;
    };
    let params = [
        // SAFETY: a static key; the octets outlive the call.
        unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_MAC_PARAM_CUSTOM.as_ptr(),
                c.ptr().cast_mut().cast(),
                c.len(),
            )
        },
        end(),
    ];
    // SAFETY: the caller's context; the array above.
    let r = unsafe { EVP_MAC_CTX_set_params(ctx, params.as_ptr()) };
    r > 0
}

ffi_callback! {
    /// `kbkdf_set_ctx_params`: the MAC (HMAC, CMAC, or KMAC), the mode, the key, label (the
    /// salt), context (the info), and IV (the seed), the switches, and r; then the MAC keyed.
    ///
    /// # Safety
    /// `vctx` is a live KBKDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn kbkdf_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(k) = (unsafe { context::<Kbkdf>(vctx) }) else { return 0 };
        // SAFETY: the provider's context.
        let libctx = unsafe { libctx_of(k.provctx.0) };
        // SAFETY: the context's MAC context; the caller's array.
        if !unsafe { macctx_load(&mut k.ctx_init, params, ptr::null(), ptr::null(), ptr::null(), libctx) } {
            return 0;
        }
        if !k.ctx_init.is_null() {
            k.is_kmac = false;
            // SAFETY: the live MAC context.
            let mac = unsafe { EVP_MAC_CTX_get0_mac(k.ctx_init) };
            // SAFETY: its method; static names, here and below.
            let is = |name: &CStr| unsafe { EVP_MAC_is_a(mac, name.as_ptr()) } != 0;
            if is(c"KMAC-128") || is(c"KMAC-256") {
                k.is_kmac = true;
            } else if !is(c"HMAC") && !is(c"CMAC") {
                raise(PROV_R_INVALID_MAC, "kbkdf_set_ctx_params");
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_MODE) } {
            let data = p.data.cast_const().cast::<u8>();
            if data.is_null() && p.data_size > 0 {
                // The reference compares through NULL (docs/DEVIATIONS.md).
                return 0;
            }
            // SAFETY: the parameter's octets.
            if unsafe { strncasecmp_eq(b"counter", data, p.data_size) } {
                k.feedback = false;
            // SAFETY: as above.
            } else if unsafe { strncasecmp_eq(b"feedback", data, p.data_size) } {
                k.feedback = true;
            } else {
                raise(PROV_R_INVALID_MODE, "kbkdf_set_ctx_params");
                return 0;
            }
        }
        // SAFETY: as above, here and below.
        if unsafe { get1_octets(params, OSSL_KDF_PARAM_KEY, &mut k.ki) } == 0
            // SAFETY: as above.
            || unsafe { get1_octets(params, OSSL_KDF_PARAM_SALT, &mut k.label) } == 0
            // SAFETY: as above.
            || unsafe { concat_octets(params, OSSL_KDF_PARAM_INFO, &mut k.context, 0) } == 0
            // SAFETY: as above.
            || unsafe { get1_octets(params, OSSL_KDF_PARAM_SEED, &mut k.iv) } == 0
        {
            return 0;
        }
        for (name, slot) in [(OSSL_KDF_PARAM_KBKDF_USE_L, &mut k.use_l), (OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, &mut k.use_separator)] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                // SAFETY: a parameter of the caller's array.
                if unsafe { OSSL_PARAM_get_int(p, slot) } == 0 {
                    return 0;
                }
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_KBKDF_R) } {
            let mut r = 0;
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_get_int(p, &raw mut r) } == 0 || ![8, 16, 24, 32].contains(&r) {
                return 0;
            }
            k.r = r;
        }
        if !k.ctx_init.is_null() && let Some(ki) = k.ki.as_ref().filter(|x| x.len() > 0) {
            // SAFETY: the live MAC context; the context's octets.
            if (k.is_kmac && !unsafe { kbkdf_kmac_init(k.ctx_init, k.label.as_ref()) })
                // SAFETY: as above.
                || unsafe { EVP_MAC_init(k.ctx_init, ki.ptr(), ki.len(), ptr::null()) } == 0
            {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `kbkdf_derive`: KMAC's own output, or counter or feedback mode over HMAC or CMAC. A
    /// failure wipes the output, as the reference does.
    ///
    /// # Safety
    /// `vctx` is a live KBKDF context; `key` has room for `keylen` octets; `params` is NULL or
    /// a parameter array.
    pub(crate) unsafe extern "C" fn kbkdf_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { kbkdf_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(k) = (unsafe { context::<Kbkdf>(vctx) }) else { return 0 };
        if k.ctx_init.is_null() {
            let reason = if k.ki.as_ref().is_none_or(|x| x.len() == 0) { PROV_R_NO_KEY_SET } else { PROV_R_MISSING_MAC };
            raise(reason, "kbkdf_derive");
            return 0;
        }
        if keylen == 0 {
            raise(PROV_R_INVALID_KEY_LENGTH, "kbkdf_derive");
            return 0;
        }
        // SAFETY: the context's MAC; the caller's room.
        let ok = unsafe { kbkdf_compute(k, key, keylen) };
        if !ok && !key.is_null() {
            // SAFETY: the caller's room for `keylen` octets.
            unsafe { mem::OPENSSL_cleanse(key.cast(), keylen) };
        }
        c_int::from(ok)
    }
}

/// The derivation behind `kbkdf_derive`.
///
/// # Safety
/// The context's MAC context is live; `key` has room for `keylen` octets.
unsafe fn kbkdf_compute(k: &Kbkdf, key: *mut u8, keylen: usize) -> bool {
    let context = k.context.as_ref().map(|c| &c.0[..]).unwrap_or_default();
    if k.is_kmac {
        let mut outlen = keylen;
        let params = [
            // SAFETY: a static key; the local length.
            unsafe { OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE.as_ptr(), &raw mut outlen) },
            end(),
        ];
        // SAFETY: the context's MAC; the array above; the caller's room.
        return unsafe { EVP_MAC_CTX_set_params(k.ctx_init, params.as_ptr()) } > 0
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(k.ctx_init, context.as_ptr(), context.len()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MAC_final(k.ctx_init, key, ptr::null_mut(), keylen) } != 0;
    }
    // SAFETY: the context's MAC.
    let h = unsafe { EVP_MAC_CTX_get_mac_size(k.ctx_init) };
    if h == 0 {
        return false;
    }
    let iv = k.iv.as_ref().map(|c| &c.0[..]).unwrap_or_default();
    if !iv.is_empty() && iv.len() != h {
        raise(PROV_R_INVALID_SEED_LENGTH, "kbkdf_derive");
        return false;
    }
    let r = u32::try_from(k.r).unwrap_or(32);
    if !k.feedback && u64::try_from(keylen / h).unwrap_or(u64::MAX) >= 1u64 << r {
        raise(PROV_R_INVALID_KEY_LENGTH, "kbkdf_derive");
        return false;
    }
    let l = if k.use_l != 0 {
        Some(
            u32::try_from((keylen.wrapping_mul(8)) & 0xffff_ffff)
                .unwrap_or(0)
                .to_be_bytes(),
        )
    } else {
        None
    };
    let label = k.label.as_ref().map(|c| &c.0[..]).unwrap_or_default();
    let mut k_i = Secret(vec![0u8; h]);
    if let Some(d) = k_i.0.get_mut(..iv.len()) {
        d.copy_from_slice(iv);
    }
    let mut k_i_len = iv.len();
    let ctr_len = usize::try_from(r / 8).unwrap_or(4);
    let mut written = 0usize;
    let mut counter: u32 = 1;
    while written < keylen {
        let i = counter.to_be_bytes();
        // SAFETY: the context's MAC.
        let ctx = unsafe { EVP_MAC_CTX_dup(k.ctx_init) };
        let zero = [0u8];
        let ok = !ctx.is_null()
            // SAFETY: the copy; the octets above.
            && (!k.feedback || unsafe { EVP_MAC_update(ctx, k_i.ptr(), k_i_len) } != 0)
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(ctx, i.as_ptr().wrapping_add(4 - ctr_len), ctr_len) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(ctx, label.as_ptr(), label.len()) } != 0
            // SAFETY: as above.
            && (k.use_separator == 0 || unsafe { EVP_MAC_update(ctx, zero.as_ptr(), 1) } != 0)
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(ctx, context.as_ptr(), context.len()) } != 0
            // SAFETY: as above.
            && l.is_none_or(|l| unsafe { EVP_MAC_update(ctx, l.as_ptr(), 4) } != 0)
            // SAFETY: as above; room for the MAC.
            && unsafe { EVP_MAC_final(ctx, k_i.0.as_mut_ptr(), ptr::null_mut(), h) } != 0;
        // SAFETY: the copy made here, or NULL.
        unsafe { EVP_MAC_CTX_free(ctx) };
        if !ok {
            return false;
        }
        let n = (keylen - written).min(h);
        // SAFETY: the caller's room for `n` more octets.
        unsafe { ptr::copy_nonoverlapping(k_i.ptr(), key.wrapping_add(written), n) };
        written = written.saturating_add(h);
        k_i_len = h;
        counter = counter.wrapping_add(1);
    }
    true
}

static KBKDF_SETTABLE: Params<13> = Params([
    defn(OSSL_KDF_PARAM_INFO, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SEED, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_MAC, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_MODE, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_KBKDF_USE_L,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_KDF_PARAM_KBKDF_R,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `kbkdf_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn kbkdf_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        KBKDF_SETTABLE.0.as_ptr()
    }
}

static KBKDF_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, kbkdf_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, kbkdf_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, kbkdf_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, kbkdf_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, kbkdf_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        kbkdf_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        kbkdf_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        size_only_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        any_size_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// X942KDF-ASN1

/// `kek_algs`: the key-wrapping algorithms X9.42's `OtherInfo` can name, with their key sizes.
const KEK_ALGS: [(&CStr, c_int, usize); 4] = [
    (c"AES-128-WRAP", NID_id_aes128_wrap, 16),
    (c"AES-192-WRAP", NID_id_aes192_wrap, 24),
    (c"AES-256-WRAP", NID_id_aes256_wrap, 32),
    (c"DES3-WRAP", NID_id_smime_alg_CMS3DESwrap, 24),
];

/// A NID's OBJECT IDENTIFIER, DER-encoded (from the object table).
fn oid_der(nid: c_int) -> Option<Vec<u8>> {
    // SAFETY: a built-in NID.
    let obj = unsafe { OBJ_nid2obj(nid) };
    if obj.is_null() {
        return None;
    }
    // SAFETY: the static object.
    let len = unsafe { OBJ_length(obj) };
    // SAFETY: as above.
    let data = unsafe { OBJ_get0_data(obj) };
    if data.is_null() || len >= 0x80 {
        return None;
    }
    let mut der = vec![0x06, u8::try_from(len).ok()?];
    // SAFETY: the object's `len` content octets.
    der.extend_from_slice(unsafe { core::slice::from_raw_parts(data, len) });
    Some(der)
}

/// `KDF_X942`.
struct X942 {
    provctx: Ptr,
    digest: Prov<EVP_MD>,
    secret: Option<Secret>,
    acvpinfo: Option<Secret>,
    partyuinfo: Option<Secret>,
    partyvinfo: Option<Secret>,
    supp_pubinfo: Option<Secret>,
    supp_privinfo: Option<Secret>,
    dkm_len: usize,
    /// The key-wrapping algorithm's index in [`KEK_ALGS`].
    cek: Option<usize>,
    use_keybits: c_int,
}

impl X942 {
    fn new(provctx: Ptr) -> Self {
        Self {
            provctx,
            digest: Prov::NONE,
            secret: None,
            acvpinfo: None,
            partyuinfo: None,
            partyvinfo: None,
            supp_pubinfo: None,
            supp_privinfo: None,
            dkm_len: 0,
            cek: None,
            use_keybits: 1,
        }
    }
}

ffi_callback! {
    /// `x942kdf_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn x942_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(X942::new(Ptr(provctx)))
    }
}

ffi_callback! {
    /// `x942kdf_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or an X942KDF context, not used afterwards.
    pub(crate) unsafe extern "C" fn x942_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<X942>(vctx) };
    }
}

ffi_callback! {
    /// `x942kdf_reset`.
    ///
    /// # Safety
    /// `vctx` is a live X942KDF context.
    pub(crate) unsafe extern "C" fn x942_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(x) = unsafe { context::<X942>(vctx) } {
            *x = X942::new(x.provctx);
        }
    }
}

ffi_callback! {
    /// `x942kdf_dup`.
    ///
    /// # Safety
    /// `vctx` is a live X942KDF context.
    pub(crate) unsafe extern "C" fn x942_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<X942>(vctx) }) else { return ptr::null_mut() };
        let mut dst = X942::new(src.provctx);
        let (Some(a), Some(b), Some(c), Some(d), Some(e), Some(f)) = (
            memdup(&src.secret),
            memdup(&src.acvpinfo),
            memdup(&src.partyuinfo),
            memdup(&src.partyvinfo),
            memdup(&src.supp_pubinfo),
            memdup(&src.supp_privinfo),
        ) else {
            return ptr::null_mut();
        };
        let Some(digest) = src.digest.copy() else { return ptr::null_mut() };
        (dst.secret, dst.acvpinfo, dst.partyuinfo, dst.partyvinfo, dst.supp_pubinfo, dst.supp_privinfo) = (a, b, c, d, e, f);
        dst.digest = digest;
        dst.cek = src.cek;
        dst.dkm_len = src.dkm_len;
        dst.use_keybits = src.use_keybits;
        boxed(dst)
    }
}

/// `x942kdf_set_buffer`: nothing for no data, else the octets.
///
/// # Safety
/// `p`'s data is NULL or holds `data_size` octets.
unsafe fn x942_set_buffer(slot: &mut Option<Secret>, p: &OSSL_PARAM) -> bool {
    if p.data_size == 0 || p.data.is_null() {
        return true;
    }
    *slot = None;
    // SAFETY: the caller's guarantee.
    match unsafe { get_octets(p) } {
        Some(v) => {
            *slot = Some(v);
            true
        }
        None => false,
    }
}

ffi_callback! {
    /// `x942kdf_set_ctx_params`.
    ///
    /// # Safety
    /// `vctx` is a live X942KDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn x942_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(x) = (unsafe { context::<X942>(vctx) }) else { return 0 };
        // SAFETY: as above; the context's provider.
        if !unsafe { load_digest(&mut x.digest, params, x.provctx.0) } {
            return 0;
        }
        // The first of each pair that's there.
        let first = |a: &CStr, b: Option<&CStr>| {
            // SAFETY: as above.
            unsafe { locate(params, a) }.or_else(|| b.and_then(|b| unsafe { locate(params, b) }))
        };
        for (p, slot) in [
            (first(OSSL_KDF_PARAM_SECRET, Some(OSSL_KDF_PARAM_KEY)), &mut x.secret),
            (first(OSSL_KDF_PARAM_X942_ACVPINFO, None), &mut x.acvpinfo),
            (first(OSSL_KDF_PARAM_X942_PARTYUINFO, Some(OSSL_KDF_PARAM_UKM)), &mut x.partyuinfo),
            (first(OSSL_KDF_PARAM_X942_PARTYVINFO, None), &mut x.partyvinfo),
        ] {
            // SAFETY: a parameter of the caller's array.
            if let Some(p) = p && !unsafe { x942_set_buffer(slot, p) } {
                return 0;
            }
        }
        if let Some(p) = first(OSSL_KDF_PARAM_X942_USE_KEYBITS, None) {
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_get_int(p, &raw mut x.use_keybits) } == 0 {
                return 0;
            }
        }
        if let Some(p) = first(OSSL_KDF_PARAM_X942_SUPP_PUBINFO, None) {
            // SAFETY: as above.
            if !unsafe { x942_set_buffer(&mut x.supp_pubinfo, p) } {
                return 0;
            }
            x.use_keybits = 0;
        }
        if let Some(p) = first(OSSL_KDF_PARAM_X942_SUPP_PRIVINFO, None) {
            // SAFETY: as above.
            if !unsafe { x942_set_buffer(&mut x.supp_privinfo, p) } {
                return 0;
            }
        }
        if let Some(p) = first(OSSL_KDF_PARAM_CEK_ALG, None) {
            let Some(name) = utf8(p) else { return 0 };
            // The reference passes the algorithm's name as the property query when there are
            // properties at all.
            let propq = if first(OSSL_ALG_PARAM_PROPERTIES, None).is_some() { name } else { ptr::null() };
            // SAFETY: the provider's context.
            let libctx = unsafe { libctx_of(x.provctx.0) };
            // SAFETY: the parameter's string; the query.
            let cipher = unsafe { EVP_CIPHER_fetch(libctx, name, propq) };
            let id = if cipher.is_null() {
                None
            } else {
                // SAFETY: the cipher just fetched; static names.
                KEK_ALGS.iter().position(|(n, _, _)| unsafe { EVP_CIPHER_is_a(cipher, n.as_ptr()) } != 0)
            };
            // SAFETY: the cipher fetched here, or NULL.
            unsafe { EVP_CIPHER_free(cipher) };
            let Some(id) = id else {
                raise(PROV_R_UNSUPPORTED_CEK_ALG, "find_alg_id");
                return 0;
            };
            x.cek = Some(id);
            x.dkm_len = KEK_ALGS.get(id).map_or(0, |a| a.2);
        }
        1
    }
}

ffi_callback! {
    /// `x942kdf_derive`: Hash(Z || OtherInfo) with the counter in `OtherInfo`.
    ///
    /// # Safety
    /// `vctx` is a live X942KDF context; `key` has room for `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn x942_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { x942_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(x) = (unsafe { context::<X942>(vctx) }) else { return 0 };
        const F: &str = "x942kdf_derive";
        if x.use_keybits != 0 && x.supp_pubinfo.is_some() {
            raise(PROV_R_INVALID_PUBINFO, F);
            return 0;
        }
        if x.acvpinfo.is_some() && (x.partyuinfo.is_some() || x.partyvinfo.is_some() || x.supp_pubinfo.is_some() || x.supp_privinfo.is_some()) {
            raise(PROV_R_INVALID_DATA, F);
            return 0;
        }
        let Some(z) = x.secret.as_ref() else {
            raise(PROV_R_MISSING_SECRET, F);
            return 0;
        };
        let md = x.digest.method;
        if md.is_null() {
            raise(PROV_R_MISSING_MESSAGE_DIGEST, F);
            return 0;
        }
        let Some(cek) = x.cek.and_then(|i| KEK_ALGS.get(i)).and_then(|a| oid_der(a.1)) else {
            raise(PROV_R_MISSING_CEK_ALG, F);
            return 0;
        };
        if x.partyuinfo.as_ref().is_some_and(|u| u.len() >= 1 << 30) {
            raise(PROV_R_INVALID_UKM_LENGTH, F);
            return 0;
        }
        fn bytes(s: &Option<Secret>) -> Option<&[u8]> {
            s.as_ref().map(|v| &v.0[..])
        }
        let info = rustyssl_crypto::kdf::X942Info {
            cek_oid: &cek,
            kek_length: if x.use_keybits != 0 { x.dkm_len } else { 0 },
            acvp: bytes(&x.acvpinfo),
            party_u: bytes(&x.partyuinfo),
            party_v: bytes(&x.partyvinfo),
            supp_pub: bytes(&x.supp_pubinfo),
            supp_priv: bytes(&x.supp_privinfo),
        };
        let Ok((mut other, at)) = rustyssl_crypto::kdf::x942_other_info(&info) else {
            raise(PROV_R_BAD_ENCODING, F);
            return 0;
        };
        // SAFETY: the context's digest; the caller's room.
        let ok = unsafe { x942_hash_kdm(md, &z.0, &mut other, at, key, keylen) };
        wipe(&mut other);
        c_int::from(ok)
    }
}

/// `x942kdf_hash_kdm`: Hash(Z || OtherInfo) for counters from 1, patched in at `at`.
///
/// # Safety
/// `md` is a live digest; `out` has room for `len` octets.
unsafe fn x942_hash_kdm(
    md: *const EVP_MD,
    z: &[u8],
    other: &mut [u8],
    at: usize,
    out: *mut u8,
    len: usize,
) -> bool {
    const MAX: usize = 1 << 30;
    if z.len() > MAX || other.len() > MAX || len > MAX || len == 0 {
        raise(PROV_R_BAD_LENGTH, "x942kdf_hash_kdm");
        return false;
    }
    // SAFETY: the caller's guarantee.
    let Some(hlen) = (unsafe { md_size(md) }) else {
        return false;
    };
    // SAFETY: no preconditions.
    let ctx = unsafe { EVP_MD_CTX_new() };
    // SAFETY: as above.
    let init = unsafe { EVP_MD_CTX_new() };
    let mut mac = [0u8; MAX_MD];
    let (mut out, mut len) = (out, len);
    // SAFETY: the contexts made here, or NULL; the caller's digest.
    let mut ok = !ctx.is_null() && !init.is_null() && unsafe { EVP_DigestInit(init, md) } != 0;
    let mut counter: u32 = 1;
    while ok {
        if let Some(c) = other.get_mut(at..at.saturating_add(4)) {
            c.copy_from_slice(&counter.to_be_bytes());
        }
        // SAFETY: the contexts made here; the octets.
        ok = unsafe { EVP_MD_CTX_copy_ex(ctx, init) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(ctx, z.as_ptr().cast(), z.len()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(ctx, other.as_ptr().cast(), other.len()) } != 0;
        if !ok {
            break;
        }
        if len >= hlen {
            // SAFETY: the caller's room for a block.
            ok = unsafe { EVP_DigestFinal_ex(ctx, out, ptr::null_mut()) } != 0;
            out = out.wrapping_add(hlen);
            len -= hlen;
            if len == 0 {
                break;
            }
        } else {
            // SAFETY: room for any digest; the caller's for the rest.
            ok = unsafe { EVP_DigestFinal_ex(ctx, mac.as_mut_ptr(), ptr::null_mut()) } != 0;
            if ok {
                // SAFETY: as above.
                unsafe { ptr::copy_nonoverlapping(mac.as_ptr(), out, len) };
            }
            break;
        }
        counter = counter.wrapping_add(1);
    }
    // SAFETY: the contexts made here.
    unsafe { EVP_MD_CTX_free(ctx) };
    // SAFETY: as above.
    unsafe { EVP_MD_CTX_free(init) };
    wipe(&mut mac);
    ok
}

ffi_callback! {
    /// `x942kdf_get_ctx_params`: the size (the digest's).
    ///
    /// # Safety
    /// `vctx` is a live X942KDF context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn x942_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { context::<X942>(vctx) }) else { return 0 };
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE.as_ptr()) };
        if p.is_null() {
            return 1;
        }
        let sz = if x.digest.method.is_null() {
            raise(PROV_R_MISSING_MESSAGE_DIGEST, "x942kdf_size");
            0
        } else {
            // SAFETY: the context's digest.
            unsafe { md_size(x.digest.method) }.unwrap_or(0)
        };
        // SAFETY: a parameter of the caller's array.
        c_int::from(unsafe { OSSL_PARAM_set_size_t(p, sz) } != 0)
    }
}

static X942_SETTABLE: Params<13> = Params([
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_KDF_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SECRET, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_UKM, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_X942_ACVPINFO,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_X942_PARTYUINFO,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_X942_PARTYVINFO,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_X942_SUPP_PUBINFO,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_X942_SUPP_PRIVINFO,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_KDF_PARAM_X942_USE_KEYBITS,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    defn(OSSL_KDF_PARAM_CEK_ALG, OSSL_PARAM_UTF8_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `x942kdf_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn x942_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        X942_SETTABLE.0.as_ptr()
    }
}

static X942_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, x942_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, x942_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, x942_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, x942_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, x942_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        x942_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        x942_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        size_only_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        x942_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// SCRYPT

/// `KDF_SCRYPT`.
struct Scrypt {
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<std::ffi::CString>,
    pass: Option<Secret>,
    salt: Option<Secret>,
    n: u64,
    r: u64,
    p: u64,
    maxmem: u64,
    /// SHA-256, fetched with the property query, with a reference (NULL until needed).
    sha256: *mut EVP_MD,
}

impl Scrypt {
    fn new(libctx: *mut OSSL_LIB_CTX) -> Self {
        let mut s = Self {
            libctx,
            propq: None,
            pass: None,
            salt: None,
            n: 0,
            r: 0,
            p: 0,
            maxmem: 0,
            sha256: ptr::null_mut(),
        };
        s.init();
        s
    }

    /// `kdf_scrypt_init`: the paper's most conservative parameters (about 1 GiB).
    fn init(&mut self) {
        self.n = 1 << 20;
        self.r = 8;
        self.p = 1;
        self.maxmem = 1025 * 1024 * 1024;
    }

    /// `set_digest`: SHA-256 fetched again with the query.
    fn set_digest(&mut self) -> bool {
        // SAFETY: the reference this holds, or NULL.
        unsafe { EVP_MD_free(self.sha256) };
        let propq = self.propq.as_ref().map_or(ptr::null(), |q| q.as_ptr());
        // SAFETY: the context's library context; a static name; the query.
        self.sha256 = unsafe { EVP_MD_fetch(self.libctx, c"sha256".as_ptr(), propq) };
        if self.sha256.is_null() {
            raise(PROV_R_UNABLE_TO_LOAD_SHA256, "set_digest");
            return false;
        }
        true
    }
}

impl Drop for Scrypt {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { EVP_MD_free(self.sha256) };
    }
}

ffi_callback! {
    /// `kdf_scrypt_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn scrypt_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        boxed(Scrypt::new(unsafe { libctx_of(provctx) }))
    }
}

ffi_callback! {
    /// `kdf_scrypt_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a scrypt context, not used afterwards.
    pub(crate) unsafe extern "C" fn scrypt_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Scrypt>(vctx) };
    }
}

ffi_callback! {
    /// `kdf_scrypt_reset`: the password and salt gone, the parameters back to the defaults
    /// (the property query and digest kept).
    ///
    /// # Safety
    /// `vctx` is a live scrypt context.
    pub(crate) unsafe extern "C" fn scrypt_reset(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if let Some(s) = unsafe { context::<Scrypt>(vctx) } {
            s.salt = None;
            s.pass = None;
            s.init();
        }
    }
}

ffi_callback! {
    /// `kdf_scrypt_dup`.
    ///
    /// # Safety
    /// `vctx` is a live scrypt context.
    pub(crate) unsafe extern "C" fn scrypt_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<Scrypt>(vctx) }) else { return ptr::null_mut() };
        let mut dst = Scrypt::new(src.libctx);
        // SAFETY: the source's digest, or NULL.
        if !src.sha256.is_null() && unsafe { EVP_MD_up_ref(src.sha256) } == 0 {
            return ptr::null_mut();
        }
        dst.sha256 = src.sha256;
        dst.propq = src.propq.clone();
        let (Some(salt), Some(pass)) = (memdup(&src.salt), memdup(&src.pass)) else { return ptr::null_mut() };
        (dst.salt, dst.pass) = (salt, pass);
        (dst.n, dst.r, dst.p, dst.maxmem) = (src.n, src.r, src.p, src.maxmem);
        boxed(dst)
    }
}

ffi_callback! {
    /// `kdf_scrypt_set_ctx_params`: the password, salt, N (a power of two from 2), r, p, the
    /// memory limit (from 1), and the property query (which fetches SHA-256 again).
    ///
    /// # Safety
    /// `vctx` is a live scrypt context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn scrypt_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(s) = (unsafe { context::<Scrypt>(vctx) }) else { return 0 };
        for (name, slot) in [(OSSL_KDF_PARAM_PASSWORD, &mut s.pass), (OSSL_KDF_PARAM_SALT, &mut s.salt)] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                // SAFETY: a parameter of the caller's array.
                if !unsafe { set_membuf(slot, p) } {
                    return 0;
                }
            }
        }
        type Check<'a> = (&'a CStr, fn(u64) -> bool, &'a mut u64);
        let checks: [Check<'_>; 4] = [
            (OSSL_KDF_PARAM_SCRYPT_N, |v| v > 1 && v.is_power_of_two(), &mut s.n),
            (OSSL_KDF_PARAM_SCRYPT_R, |v| v >= 1, &mut s.r),
            (OSSL_KDF_PARAM_SCRYPT_P, |v| v >= 1, &mut s.p),
            (OSSL_KDF_PARAM_SCRYPT_MAXMEM, |v| v >= 1, &mut s.maxmem),
        ];
        for (name, valid, slot) in checks {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, name) } {
                let mut v = 0u64;
                // SAFETY: a parameter of the caller's array.
                if unsafe { OSSL_PARAM_get_uint64(p, &raw mut v) } == 0 || !valid(v) {
                    return 0;
                }
                *slot = v;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_KDF_PARAM_PROPERTIES) } {
            let Some(text) = utf8(p) else { return 0 };
            s.propq = if text.is_null() {
                None
            } else {
                // SAFETY: a UTF-8 string parameter's data: a C string.
                Some(unsafe { CStr::from_ptr(text) }.to_owned())
            };
            if !s.set_digest() {
                return 0;
            }
        }
        1
    }
}

/// `scrypt_alg`'s checks, then (for an output) scrypt over the backend. NULL `key` checks only.
///
/// # Safety
/// `key` is NULL or has room for `keylen` octets.
unsafe fn scrypt_compute(s: &Scrypt, key: *mut u8, keylen: usize) -> bool {
    const PR_MAX: u64 = (1 << 30) - 1;
    let (n, r, p) = (s.n, s.r, s.p);
    if r == 0 || p == 0 || n < 2 || !n.is_power_of_two() {
        return false;
    }
    let limit = |why: &str| {
        err::raise(ERR_LIB_EVP, EVP_R_MEMORY_LIMIT_EXCEEDED, why);
        false
    };
    if p > PR_MAX / r {
        return limit("scrypt_alg");
    }
    let bits = r.wrapping_mul(16);
    if bits <= 63 && n >= 1u64 << bits {
        return limit("scrypt_alg");
    }
    let b_len = p.wrapping_mul(128).wrapping_mul(r);
    if b_len > i32::MAX.unsigned_abs().into() {
        return limit("scrypt_alg");
    }
    if n + 2 > (u64::MAX / 128) / r {
        return limit("scrypt_alg");
    }
    let v_len = r.wrapping_mul(128).wrapping_mul(n + 2);
    if b_len > u64::MAX - v_len {
        return limit("scrypt_alg");
    }
    let maxmem = s.maxmem.min(u64::try_from(usize::MAX).unwrap_or(u64::MAX));
    if b_len + v_len > maxmem {
        return limit("scrypt_alg");
    }
    if key.is_null() {
        return true;
    }
    let pass = s.pass.as_ref().map(|x| &x.0[..]).unwrap_or_default();
    let salt = s.salt.as_ref().map(|x| &x.0[..]).unwrap_or_default();
    let mut out = Secret(vec![0u8; keylen]);
    if rustyssl_crypto::kdf::scrypt(pass, salt, n, r, p, s.maxmem, &mut out.0).is_err() {
        err::raise(ERR_LIB_EVP, EVP_R_PBKDF2_ERROR, "scrypt_alg");
        return false;
    }
    // SAFETY: the caller's room.
    unsafe { ptr::copy_nonoverlapping(out.ptr(), key, keylen) };
    true
}

ffi_callback! {
    /// `kdf_scrypt_derive`.
    ///
    /// # Safety
    /// `vctx` is a live scrypt context; `key` is NULL (to check the parameters) or has room for
    /// `keylen` octets; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn scrypt_derive(vctx: *mut c_void, key: *mut c_uchar, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { scrypt_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(s) = (unsafe { context::<Scrypt>(vctx) }) else { return 0 };
        if s.pass.is_none() {
            raise(PROV_R_MISSING_PASS, "kdf_scrypt_derive");
            return 0;
        }
        if s.salt.is_none() {
            raise(PROV_R_MISSING_SALT, "kdf_scrypt_derive");
            return 0;
        }
        if s.sha256.is_null() && !s.set_digest() {
            return 0;
        }
        // SAFETY: the caller's room.
        c_int::from(unsafe { scrypt_compute(s, key, keylen) })
    }
}

ffi_callback! {
    /// `kdf_scrypt_get_ctx_params` (PKCS12KDF's and Argon2's too): the size, any; -2 when it
    /// isn't asked for, as the reference returns.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn size_or_unasked_get_ctx_params(_vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_KDF_PARAM_SIZE.as_ptr()) };
        if p.is_null() {
            return -2;
        }
        // SAFETY: a parameter of the caller's array.
        unsafe { OSSL_PARAM_set_size_t(p, usize::MAX) }
    }
}

static SCRYPT_SETTABLE: Params<8> = Params([
    defn(OSSL_KDF_PARAM_PASSWORD, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_KDF_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_KDF_PARAM_SCRYPT_N,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u64>(),
    ),
    defn(
        OSSL_KDF_PARAM_SCRYPT_R,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_SCRYPT_P,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u32>(),
    ),
    defn(
        OSSL_KDF_PARAM_SCRYPT_MAXMEM,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<u64>(),
    ),
    defn(
        OSSL_KDF_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `kdf_scrypt_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn scrypt_settable(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SCRYPT_SETTABLE.0.as_ptr()
    }
}

static SCRYPT_FUNCTIONS: Dispatch<10> = Dispatch([
    entry!(OSSL_FUNC_KDF_NEWCTX, scrypt_new, NewCtxFn),
    entry!(OSSL_FUNC_KDF_DUPCTX, scrypt_dup, DupCtxFn),
    entry!(OSSL_FUNC_KDF_FREECTX, scrypt_free, FreeCtxFn),
    entry!(OSSL_FUNC_KDF_RESET, scrypt_reset, ResetFn),
    entry!(OSSL_FUNC_KDF_DERIVE, scrypt_derive, DeriveFn),
    entry!(
        OSSL_FUNC_KDF_SETTABLE_CTX_PARAMS,
        scrypt_settable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_SET_CTX_PARAMS,
        scrypt_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GETTABLE_CTX_PARAMS,
        size_only_gettable,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_KDF_GET_CTX_PARAMS,
        size_or_unasked_get_ctx_params,
        GetCtxParamsFn
    ),
    END,
]);

/// `deflt_kdfs`, in the reference's order.
static DEFAULT_KDFS: Algorithms<17> = Algorithms([
    alg(c"HKDF", &HKDF_FUNCTIONS),
    alg(c"TLS13-KDF", &TLS13_FUNCTIONS),
    alg(c"SSKDF", &SSKDF_FUNCTIONS),
    alg(c"PBKDF2:1.2.840.113549.1.5.12", &PBKDF2_FUNCTIONS),
    alg(c"PKCS12KDF", &kdfs_more::PKCS12_FUNCTIONS),
    alg(c"SSHKDF", &SSHKDF_FUNCTIONS),
    alg(c"X963KDF:X942KDF-CONCAT", &X963KDF_FUNCTIONS),
    alg(c"TLS1-PRF", &TLS1_PRF_FUNCTIONS),
    alg(c"KBKDF", &KBKDF_FUNCTIONS),
    alg(c"X942KDF-ASN1:X942KDF", &X942_FUNCTIONS),
    alg(
        c"SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11",
        &SCRYPT_FUNCTIONS,
    ),
    alg(c"KRB5KDF", &kdfs_more::KRB5_FUNCTIONS),
    alg(c"HMAC-DRBG-KDF", &kdfs_more::HMAC_DRBG_FUNCTIONS),
    alg(c"ARGON2I", &kdfs_more::ARGON2I_FUNCTIONS),
    alg(c"ARGON2D", &kdfs_more::ARGON2D_FUNCTIONS),
    alg(c"ARGON2ID", &kdfs_more::ARGON2ID_FUNCTIONS),
    ALG_END,
]);

/// The default provider's KDF table.
pub(crate) fn default_kdfs() -> *const OSSL_ALGORITHM {
    DEFAULT_KDFS.0.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::kdf::{
        EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_CTX_set_params, EVP_KDF_fetch, EVP_KDF_free,
    };

    /// docs/DEVIATIONS.md: TLS1-PRF's `digest` with NULL data is refused (the reference
    /// compares through NULL).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn tls1_prf_null_digest_data_is_refused() {
        // SAFETY: a static name.
        let kdf = unsafe { EVP_KDF_fetch(ptr::null_mut(), c"TLS1-PRF".as_ptr(), ptr::null()) };
        // SAFETY: the method just fetched.
        let ctx = unsafe { EVP_KDF_CTX_new(kdf) };
        // SAFETY: as above.
        unsafe { EVP_KDF_free(kdf) };
        // SAFETY: a static key; NULL data is the case under test.
        let params = [
            unsafe {
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST.as_ptr(), ptr::null_mut(), 0)
            },
            end(),
        ];
        // SAFETY: the context; the parameters above.
        assert_eq!(unsafe { EVP_KDF_CTX_set_params(ctx, params.as_ptr()) }, 0);
        // SAFETY: the test's context.
        unsafe { EVP_KDF_CTX_free(ctx) };
    }

    /// A context of the KDF `name`.
    fn kdf_context(name: &CStr) -> *mut rustyssl_abi::EVP_KDF_CTX {
        // SAFETY: a static name.
        let kdf = unsafe { EVP_KDF_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
        // SAFETY: the method just fetched.
        let ctx = unsafe { EVP_KDF_CTX_new(kdf) };
        // SAFETY: as above.
        unsafe { EVP_KDF_free(kdf) };
        ctx
    }

    /// docs/DEVIATIONS.md: a KBKDF context without a MAC doesn't copy (the reference copies
    /// the MAC context through NULL), and its `mode` with NULL data is refused.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn kbkdf_without_a_mac() {
        let ctx = kdf_context(c"KBKDF");
        // SAFETY: the context.
        assert!(unsafe { crate::evp::kdf::EVP_KDF_CTX_dup(ctx) }.is_null());
        // SAFETY: a static key; NULL data with a length is the case under test.
        let params = [
            unsafe {
                OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_MODE.as_ptr(), ptr::null_mut(), 0)
            },
            end(),
        ];
        let mut params = params;
        params[0].data_size = 7;
        // SAFETY: the context; the parameters above.
        assert_eq!(unsafe { EVP_KDF_CTX_set_params(ctx, params.as_ptr()) }, 0);
        // SAFETY: the test's context.
        unsafe { EVP_KDF_CTX_free(ctx) };
    }

    /// docs/DEVIATIONS.md: SSHKDF over the NULL digest fails (the reference loops forever),
    /// but derives nothing as it does.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn sshkdf_over_null_fails() {
        let ctx = kdf_context(c"SSHKDF");
        let octets = [7u8; 8];
        let o = |key: &CStr| {
            // SAFETY: a static key; the octets outlive the parameters.
            unsafe {
                OSSL_PARAM_construct_octet_string(
                    key.as_ptr(),
                    octets.as_ptr().cast_mut().cast(),
                    8,
                )
            }
        };
        let u = |key: &CStr, value: &CStr| {
            // SAFETY: static keys and strings.
            unsafe { OSSL_PARAM_construct_utf8_string(key.as_ptr(), value.as_ptr().cast_mut(), 0) }
        };
        let params = [
            u(OSSL_KDF_PARAM_DIGEST, c"NULL"),
            o(OSSL_KDF_PARAM_KEY),
            o(OSSL_KDF_PARAM_SSHKDF_XCGHASH),
            o(OSSL_KDF_PARAM_SSHKDF_SESSION_ID),
            u(OSSL_KDF_PARAM_SSHKDF_TYPE, c"A"),
            end(),
        ];
        let mut out = [0u8; 16];
        // SAFETY: the context; the buffer; the parameters above.
        let r =
            unsafe { crate::evp::kdf::EVP_KDF_derive(ctx, out.as_mut_ptr(), 16, params.as_ptr()) };
        assert_eq!(r, 0);
        // SAFETY: as above, of nothing.
        let r = unsafe { crate::evp::kdf::EVP_KDF_derive(ctx, out.as_mut_ptr(), 0, ptr::null()) };
        assert_eq!(r, 1);
        // SAFETY: the test's context.
        unsafe { EVP_KDF_CTX_free(ctx) };
    }
}
