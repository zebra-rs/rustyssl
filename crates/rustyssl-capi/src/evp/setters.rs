//! The key context's typed setters and getters (`EVP_PKEY_CTX_set_hkdf_md(3)`,
//! `EVP_PKEY_CTX_set_tls1_prf_md(3)`, `EVP_PKEY_CTX_set_scrypt_N(3)`,
//! `EVP_PKEY_CTX_set_rsa_padding(3)`, `EVP_PKEY_CTX_set_dh_pad(3)`,
//! `EVP_PKEY_CTX_set_ec_paramgen_curve_nid(3)`, ...; `pmeth_lib.c`, `rsa_lib.c`, `dh_ctrl.c`,
//! `dsa_ctrl.c`, `ec_ctrl.c`, `evp_lib.c`): each sets (or gets) a parameter of the context's
//! provider operation, or sends the ctrl that does, as OpenSSL's does.
//!
//! As in OpenSSL, each checks the operation first (-2 with `EVP_R_COMMAND_NOT_SUPPORTED` where
//! it's not one the setter is for), some check the key type (-1), and the "strict" ones fail
//! with -2 for a parameter the operation doesn't list. Functions given a NULL context fail as
//! for a context without the operation, where the reference would crash
//! (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, BIGNUM, ERR_LIB_EVP, EVP_MD, EVP_PKEY_CTRL_DH_KDF_MD, EVP_PKEY_CTRL_DH_KDF_OID,
    EVP_PKEY_CTRL_DH_KDF_TYPE, EVP_PKEY_CTRL_DH_NID, EVP_PKEY_CTRL_DH_PARAMGEN_TYPE,
    EVP_PKEY_CTRL_DH_RFC5114, EVP_PKEY_CTRL_DSA_PARAMGEN_MD, EVP_PKEY_CTRL_EC_KDF_MD,
    EVP_PKEY_CTRL_EC_KDF_TYPE, EVP_PKEY_CTRL_EC_PARAM_ENC, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID,
    EVP_PKEY_CTRL_GET_DH_KDF_MD, EVP_PKEY_CTRL_GET_DH_KDF_OID, EVP_PKEY_CTRL_GET_EC_KDF_MD,
    EVP_PKEY_CTRL_GET_RSA_MGF1_MD, EVP_PKEY_CTRL_GET_RSA_OAEP_MD, EVP_PKEY_CTRL_GET_RSA_PADDING,
    EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, EVP_PKEY_CTRL_GET1_ID, EVP_PKEY_CTRL_GET1_ID_LEN,
    EVP_PKEY_CTRL_HKDF_INFO, EVP_PKEY_CTRL_HKDF_KEY, EVP_PKEY_CTRL_HKDF_MD,
    EVP_PKEY_CTRL_HKDF_MODE, EVP_PKEY_CTRL_HKDF_SALT, EVP_PKEY_CTRL_MD, EVP_PKEY_CTRL_PASS,
    EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, EVP_PKEY_CTRL_RSA_MGF1_MD, EVP_PKEY_CTRL_RSA_OAEP_MD,
    EVP_PKEY_CTRL_RSA_PADDING, EVP_PKEY_CTRL_RSA_PSS_SALTLEN, EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES,
    EVP_PKEY_CTRL_SCRYPT_N, EVP_PKEY_CTRL_SCRYPT_P, EVP_PKEY_CTRL_SCRYPT_R,
    EVP_PKEY_CTRL_SCRYPT_SALT, EVP_PKEY_CTRL_SET1_ID, EVP_PKEY_CTRL_TLS_MD,
    EVP_PKEY_CTRL_TLS_SECRET, EVP_PKEY_CTRL_TLS_SEED, EVP_PKEY_CTX, EVP_PKEY_DH, EVP_PKEY_DHX,
    EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_OP_DERIVE, EVP_PKEY_OP_KEYGEN, EVP_PKEY_OP_PARAMGEN,
    EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS, EVP_PKEY_SM2, EVP_R_COMMAND_NOT_SUPPORTED,
    EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED, EVP_R_INVALID_LENGTH, EVP_R_INVALID_VALUE,
    NID_sm2, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
    OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
    OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_EXCHANGE_PARAM_PAD,
    OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_INFO, OSSL_KDF_PARAM_KEY, OSSL_KDF_PARAM_MODE,
    OSSL_KDF_PARAM_PASSWORD, OSSL_KDF_PARAM_SALT, OSSL_KDF_PARAM_SCRYPT_MAXMEM,
    OSSL_KDF_PARAM_SCRYPT_N, OSSL_KDF_PARAM_SCRYPT_P, OSSL_KDF_PARAM_SCRYPT_R,
    OSSL_KDF_PARAM_SECRET, OSSL_KDF_PARAM_SEED, OSSL_KEM_PARAM_OPERATION, OSSL_PARAM,
    OSSL_PKEY_PARAM_ALGORITHM_ID_PARAMS, OSSL_PKEY_PARAM_DH_GENERATOR, OSSL_PKEY_PARAM_FFC_DIGEST,
    OSSL_PKEY_PARAM_FFC_DIGEST_PROPS, OSSL_PKEY_PARAM_FFC_GINDEX, OSSL_PKEY_PARAM_FFC_PBITS,
    OSSL_PKEY_PARAM_FFC_QBITS, OSSL_PKEY_PARAM_FFC_SEED, OSSL_PKEY_PARAM_FFC_TYPE,
    OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_MGF1_DIGEST, OSSL_PKEY_PARAM_MGF1_PROPERTIES,
    OSSL_PKEY_PARAM_RSA_BITS, OSSL_PKEY_PARAM_RSA_DIGEST, OSSL_PKEY_PARAM_RSA_DIGEST_PROPS,
    OSSL_PKEY_PARAM_RSA_PRIMES, OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
    OSSL_SIGNATURE_PARAM_PSS_SALTLEN, X509_ALGOR,
};

use super::ctrl::{self, get_params_strict, set_params_strict};
use super::pkey_ctx::{
    self, EVP_PKEY_CTX_get_params, EVP_PKEY_CTX_gettable_params, EVP_PKEY_CTX_is_a,
    EVP_PKEY_CTX_set_params,
};
use crate::err;
use crate::ffi::ffi_export;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_ptr, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_size_t, OSSL_PARAM_construct_uint, OSSL_PARAM_construct_uint64,
    OSSL_PARAM_construct_utf8_string, OSSL_PARAM_locate_const, OSSL_PARAM_modified, UNMODIFIED,
    end,
};
use crate::provider::Ptr;

/// The context's operation and whether its provider contexts are missing: (operation, the
/// derivation's, the generation's).
fn op_of(ctx: *mut EVP_PKEY_CTX) -> Option<(c_int, bool, bool)> {
    // SAFETY: the callers' guarantee: NULL or a live context.
    unsafe { pkey_ctx::context(ctx) }.map(|c| {
        let s = c.lock();
        (
            s.operation,
            s.kexctx.0.is_null(),
            s.is_gen_op() && s.algctx().is_null(),
        )
    })
}

/// `-2` with `EVP_R_COMMAND_NOT_SUPPORTED`, named for `function`.
fn not_supported(function: &str) -> c_int {
    err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, function);
    -2
}

/// A C `int` as the `size_t` C converts it to.
fn size_of_int(v: c_int) -> usize {
    isize::try_from(v).unwrap_or(0).cast_unsigned()
}

/// A static parameter key.
fn key(k: &'static CStr) -> *const c_char {
    k.as_ptr()
}

/// Sets one parameter (non-strictly).
///
/// # Safety
/// `ctx` is a live context; `p`'s data outlives the call.
unsafe fn set1(ctx: *mut EVP_PKEY_CTX, p: OSSL_PARAM) -> c_int {
    let params = [p, end()];
    // SAFETY: the caller's guarantee.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

/// Sets one parameter strictly.
///
/// # Safety
/// As for [`set1`].
unsafe fn set1_strict(ctx: *mut EVP_PKEY_CTX, p: OSSL_PARAM) -> c_int {
    let params = [p, end()];
    // SAFETY: the caller's guarantee.
    unsafe { set_params_strict(ctx, params.as_ptr()) }
}

/// `evp_pkey_ctx_set_md`.
///
/// # Safety
/// `ctx` is NULL or a live context; `md` is NULL or a live digest.
unsafe fn set_md(
    ctx: *mut EVP_PKEY_CTX,
    md: *const EVP_MD,
    fallback: impl Fn((c_int, bool, bool)) -> bool,
    param: &'static CStr,
    op: c_int,
    cmd: c_int,
) -> c_int {
    let Some(st) = op_of(ctx).filter(|s| s.0 & op != 0) else {
        return not_supported("evp_pkey_ctx_set_md");
    };
    if fallback(st) {
        // SAFETY: the caller's guarantee.
        return unsafe { ctrl::ctrl(ctx, -1, op, cmd, 0, md.cast_mut().cast()) };
    }
    let name = if md.is_null() {
        c"".as_ptr()
    } else {
        // SAFETY: the caller's live digest.
        unsafe { super::digest::EVP_MD_get0_name(md) }
    };
    // SAFETY: a static key; the digest's static name.
    let p = unsafe { OSSL_PARAM_construct_utf8_string(key(param), name.cast_mut(), 0) };
    // SAFETY: the caller's context; the parameter above.
    unsafe { set1(ctx, p) }
}

/// `evp_pkey_ctx_set1_octet_string`.
///
/// # Safety
/// `ctx` is NULL or a live context; `data` holds `len` octets.
unsafe fn set1_octets(
    ctx: *mut EVP_PKEY_CTX,
    fallback: bool,
    param: &'static CStr,
    op: c_int,
    cmd: c_int,
    data: *const u8,
    len: c_int,
) -> c_int {
    const F: &str = "evp_pkey_ctx_set1_octet_string";
    if op_of(ctx).is_none_or(|s| s.0 & op == 0) {
        return not_supported(F);
    }
    if fallback {
        // SAFETY: the caller's guarantee.
        return unsafe { ctrl::ctrl(ctx, -1, op, cmd, len, data.cast_mut().cast()) };
    }
    let Ok(n) = usize::try_from(len) else {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_LENGTH, F);
        return 0;
    };
    // SAFETY: a static key; the caller's octets.
    let p = unsafe { OSSL_PARAM_construct_octet_string(key(param), data.cast_mut().cast(), n) };
    // SAFETY: the caller's context; the parameter above.
    unsafe { set1(ctx, p) }
}

/// `evp_pkey_ctx_add1_octet_string`: appends to what the operation has, where it can say what
/// that is.
///
/// # Safety
/// `ctx` is NULL or a live context; `data` holds `len` octets.
unsafe fn add1_octets(
    ctx: *mut EVP_PKEY_CTX,
    fallback: bool,
    param: &'static CStr,
    op: c_int,
    cmd: c_int,
    data: *const u8,
    len: c_int,
) -> c_int {
    const F: &str = "evp_pkey_ctx_add1_octet_string";
    if op_of(ctx).is_none_or(|s| s.0 & op == 0) {
        return not_supported(F);
    }
    if fallback {
        // SAFETY: the caller's guarantee.
        return unsafe { ctrl::ctrl(ctx, -1, op, cmd, len, data.cast_mut().cast()) };
    }
    let Ok(n) = usize::try_from(len) else {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_LENGTH, F);
        return 0;
    };
    if n == 0 {
        return 1;
    }
    // SAFETY: the caller's context.
    let gettables = unsafe { EVP_PKEY_CTX_gettable_params(ctx) };
    // SAFETY: the list (or NULL); a static key.
    if gettables.is_null() || unsafe { OSSL_PARAM_locate_const(gettables, key(param)) }.is_null() {
        // SAFETY: the caller's guarantee.
        return unsafe { set1_octets(ctx, fallback, param, op, cmd, data, len) };
    }
    // SAFETY: a static key; no buffer: the length is asked.
    let mut params = [
        unsafe { OSSL_PARAM_construct_octet_string(key(param), ptr::null_mut(), 0) },
        end(),
    ];
    // SAFETY: the caller's context; the array above.
    if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
        return 0;
    }
    let have = params[0].return_size;
    if have == UNMODIFIED {
        return 0;
    }
    let Some(total) = have.checked_add(n).filter(|&t| t != 0) else {
        return 0;
    };
    let mut info = rustyssl_crypto::bn::Zeroizing::new(vec![0u8; total]);
    // SAFETY: a static key; the buffer of `total` octets.
    params[0] =
        unsafe { OSSL_PARAM_construct_octet_string(key(param), info.as_mut_ptr().cast(), total) };
    // SAFETY: as above.
    if have > 0 && unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
        return 0;
    }
    // SAFETY: the caller's octets.
    let add = unsafe { core::slice::from_raw_parts(data, n) };
    if let Some(dst) = info.get_mut(have..total) {
        dst.copy_from_slice(add);
    }
    // SAFETY: as above.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
}

ffi_export! {
    /// Sets the TLS1-PRF digest. -2 outside a derivation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is NULL or a live digest.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_tls1_prf_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_md(ctx, md, |s| s.1, OSSL_KDF_PARAM_DIGEST, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_MD) }
    }
}

ffi_export! {
    /// Sets the HKDF digest. -2 outside a derivation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is NULL or a live digest.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_hkdf_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_md(ctx, md, |s| s.1, OSSL_KDF_PARAM_DIGEST, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MD) }
    }
}

macro_rules! octets_setter {
    ($(#[$attr:meta])* pub unsafe extern "C" fn $name:ident(ctx, $arg:ident: $ty:ty, $len:ident: c_int) => $how:ident, $param:expr, $cmd:expr) => {
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `ctx` is NULL or a live context; the octets are `len` long.
            pub unsafe extern "C" fn $name(ctx: *mut EVP_PKEY_CTX, $arg: $ty, $len: c_int) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                let fallback = op_of(ctx).is_some_and(|s| s.1);
                // SAFETY: the caller's guarantee.
                unsafe { $how(ctx, fallback, $param, EVP_PKEY_OP_DERIVE, $cmd, $arg.cast(), $len) }
            }
        }
    };
}

octets_setter! {
    /// Sets the TLS1-PRF secret.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set1_tls1_prf_secret(ctx, sec: *const u8, seclen: c_int) => set1_octets, OSSL_KDF_PARAM_SECRET, EVP_PKEY_CTRL_TLS_SECRET
}

octets_setter! {
    /// Sets the TLS1-PRF seed (replacing it, as OpenSSL's does).
    pub unsafe extern "C" fn EVP_PKEY_CTX_add1_tls1_prf_seed(ctx, seed: *const u8, seedlen: c_int) => set1_octets, OSSL_KDF_PARAM_SEED, EVP_PKEY_CTRL_TLS_SEED
}

octets_setter! {
    /// Sets the HKDF salt.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt: *const u8, saltlen: c_int) => set1_octets, OSSL_KDF_PARAM_SALT, EVP_PKEY_CTRL_HKDF_SALT
}

octets_setter! {
    /// Sets the HKDF key.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set1_hkdf_key(ctx, key: *const u8, keylen: c_int) => set1_octets, OSSL_KDF_PARAM_KEY, EVP_PKEY_CTRL_HKDF_KEY
}

octets_setter! {
    /// Appends to the HKDF info.
    pub unsafe extern "C" fn EVP_PKEY_CTX_add1_hkdf_info(ctx, info: *const u8, infolen: c_int) => add1_octets, OSSL_KDF_PARAM_INFO, EVP_PKEY_CTRL_HKDF_INFO
}

octets_setter! {
    /// Sets the password of a password-based derivation (scrypt).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set1_pbe_pass(ctx, pass: *const c_char, passlen: c_int) => set1_octets, OSSL_KDF_PARAM_PASSWORD, EVP_PKEY_CTRL_PASS
}

octets_setter! {
    /// Sets the scrypt salt.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set1_scrypt_salt(ctx, salt: *const u8, saltlen: c_int) => set1_octets, OSSL_KDF_PARAM_SALT, EVP_PKEY_CTRL_SCRYPT_SALT
}

ffi_export! {
    /// Sets the HKDF mode (`EVP_KDF_HKDF_MODE_*`). -2 outside a derivation, 0 for a negative
    /// mode.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_hkdf_mode(ctx: *mut EVP_PKEY_CTX, mode: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_CTX_set_hkdf_mode";
        let Some(st) = op_of(ctx).filter(|s| s.0 & EVP_PKEY_OP_DERIVE != 0) else {
            return not_supported(F);
        };
        if st.1 {
            // SAFETY: the caller's guarantee.
            return unsafe { ctrl::ctrl(ctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_HKDF_MODE, mode, ptr::null_mut()) };
        }
        if mode < 0 {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_VALUE, F);
            return 0;
        }
        let mut mode = mode;
        // SAFETY: a static key; the local, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_int(key(OSSL_KDF_PARAM_MODE), &raw mut mode) };
        // SAFETY: the caller's context.
        unsafe { set1(ctx, p) }
    }
}

/// `evp_pkey_ctx_set_uint64`.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn set_u64(ctx: *mut EVP_PKEY_CTX, param: &'static CStr, cmd: c_int, val: u64) -> c_int {
    let Some(st) = op_of(ctx).filter(|s| s.0 & EVP_PKEY_OP_DERIVE != 0) else {
        return not_supported("evp_pkey_ctx_set_uint64");
    };
    if st.1 {
        // SAFETY: the caller's guarantee.
        return unsafe { ctrl::EVP_PKEY_CTX_ctrl_uint64(ctx, -1, EVP_PKEY_OP_DERIVE, cmd, val) };
    }
    let mut v = val;
    // SAFETY: a static key; the local, which outlives the call.
    let p = unsafe { OSSL_PARAM_construct_uint64(key(param), &raw mut v) };
    // SAFETY: the caller's context.
    unsafe { set1(ctx, p) }
}

macro_rules! u64_setter {
    ($(#[$attr:meta])* pub unsafe extern "C" fn $name:ident => $param:expr, $cmd:expr) => {
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `ctx` is NULL or a live context.
            pub unsafe extern "C" fn $name(ctx: *mut EVP_PKEY_CTX, v: u64) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { set_u64(ctx, $param, $cmd, v) }
            }
        }
    };
}

u64_setter! {
    /// Sets scrypt's N. -2 outside a derivation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_N => OSSL_KDF_PARAM_SCRYPT_N, EVP_PKEY_CTRL_SCRYPT_N
}

u64_setter! {
    /// Sets scrypt's r. -2 outside a derivation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_r => OSSL_KDF_PARAM_SCRYPT_R, EVP_PKEY_CTRL_SCRYPT_R
}

u64_setter! {
    /// Sets scrypt's p. -2 outside a derivation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_p => OSSL_KDF_PARAM_SCRYPT_P, EVP_PKEY_CTRL_SCRYPT_P
}

u64_setter! {
    /// Sets scrypt's memory limit. -2 outside a derivation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_scrypt_maxmem_bytes => OSSL_KDF_PARAM_SCRYPT_MAXMEM, EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES
}

ffi_export! {
    /// Sets the KEM operation's name (`OSSL_KEM_PARAM_OPERATION`). 0 for NULL, -2 outside a
    /// KEM operation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `op` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_kem_op(ctx: *mut EVP_PKEY_CTX, op: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_CTX_set_kem_op";
        let Some(st) = op_of(ctx).filter(|_| !op.is_null()) else {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_VALUE, F);
            return 0;
        };
        if st.0 & rustyssl_abi::EVP_PKEY_OP_TYPE_KEM == 0 {
            return not_supported(F);
        }
        // SAFETY: a static key; the caller's string.
        let p = unsafe { OSSL_PARAM_construct_utf8_string(key(OSSL_KEM_PARAM_OPERATION), op.cast_mut(), 0) };
        // SAFETY: the caller's context.
        unsafe { set1(ctx, p) }
    }
}

ffi_export! {
    /// Sets the distinguishing ID (kept for the next operation if none is set).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `id` holds `len` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set1_id(ctx: *mut EVP_PKEY_CTX, id: *const c_void, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, -1, -1, EVP_PKEY_CTRL_SET1_ID, len, id.cast_mut()) }
    }
}

ffi_export! {
    /// Gets the distinguishing ID: through the translation, a pointer to the operation's copy
    /// is written at `id` (as OpenSSL's does), and its length returned.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `id` has room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get1_id(ctx: *mut EVP_PKEY_CTX, id: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, -1, -1, EVP_PKEY_CTRL_GET1_ID, 0, id) }
    }
}

ffi_export! {
    /// Gets the distinguishing ID's length (0 through the translation, as OpenSSL's).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `id_len` is NULL or room for a size.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get1_id_len(ctx: *mut EVP_PKEY_CTX, id_len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, -1, -1, EVP_PKEY_CTRL_GET1_ID_LEN, 0, id_len.cast()) }
    }
}

// -------------------------------------------------------------------------------------------
// DH (dh_ctrl.c)

/// `dh_paramgen_check` (and `dsa_paramgen_check`): a generation operation.
fn gen_check(ctx: *mut EVP_PKEY_CTX, function: &str) -> c_int {
    if op_of(ctx).is_none_or(|s| s.0 & EVP_PKEY_OP_TYPE_GEN == 0) {
        return not_supported(function);
    }
    1
}

/// `dh_param_derive_check` (and EC's): a derivation.
fn derive_check(ctx: *mut EVP_PKEY_CTX, function: &str) -> c_int {
    if op_of(ctx).is_none_or(|s| s.0 & EVP_PKEY_OP_DERIVE == 0) {
        return not_supported(function);
    }
    1
}

ffi_export! {
    /// Sets the FIPS 186-4 generator index of DH parameter generation (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_gindex(ctx: *mut EVP_PKEY_CTX, gindex: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "dh_paramgen_check");
        if ret <= 0 {
            return ret;
        }
        let mut g = gindex;
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_int(key(OSSL_PKEY_PARAM_FFC_GINDEX), &raw mut g) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1_strict(ctx, p) }
    }
}

ffi_export! {
    /// Sets the FIPS 186-4 seed of DH parameter generation (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `seed` holds `seedlen` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_seed(ctx: *mut EVP_PKEY_CTX, seed: *const u8, seedlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "dh_paramgen_check");
        if ret <= 0 {
            return ret;
        }
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_octet_string(key(OSSL_PKEY_PARAM_FFC_SEED), seed.cast_mut().cast(), seedlen) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1_strict(ctx, p) }
    }
}

ffi_export! {
    /// Sets the DH parameter generation type (through the ctrl).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_type(ctx: *mut EVP_PKEY_CTX, typ: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, typ, ptr::null_mut()) }
    }
}

macro_rules! size_setter {
    ($(#[$attr:meta])* pub unsafe extern "C" fn $name:ident($arg:ident) => $check:expr, $param:expr) => {
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `ctx` is NULL or a live context.
            pub unsafe extern "C" fn $name(ctx: *mut EVP_PKEY_CTX, $arg: c_int) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                let ret = gen_check(ctx, $check);
                if ret <= 0 {
                    return ret;
                }
                let mut v = size_of_int($arg);
                // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
                let p = unsafe { OSSL_PARAM_construct_size_t(key($param), &raw mut v) };
                // SAFETY: the caller's context; the parameter above.
                unsafe { set1_strict(ctx, p) }
            }
        }
    };
}

size_setter! {
    /// Sets the prime length of DH parameter generation (strict).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_prime_len(pbits) => "dh_paramgen_check", OSSL_PKEY_PARAM_FFC_PBITS
}

size_setter! {
    /// Sets the subprime length of DH parameter generation (strict).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_subprime_len(qbits) => "dh_paramgen_check", OSSL_PKEY_PARAM_FFC_QBITS
}

ffi_export! {
    /// Sets the generator of DH parameter generation (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_paramgen_generator(ctx: *mut EVP_PKEY_CTX, generator: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "dh_paramgen_check");
        if ret <= 0 {
            return ret;
        }
        let mut g = generator;
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_int(key(OSSL_PKEY_PARAM_DH_GENERATOR), &raw mut g) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1_strict(ctx, p) }
    }
}

ffi_export! {
    /// Sets an RFC 5114 group (1 to 3) for DH (through the DHX ctrl).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_rfc5114(ctx: *mut EVP_PKEY_CTX, generator: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, EVP_PKEY_DHX, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DH_RFC5114, generator, ptr::null_mut()) }
    }
}

ffi_export! {
    /// `EVP_PKEY_CTX_set_dh_rfc5114`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dhx_rfc5114(ctx: *mut EVP_PKEY_CTX, generator: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_CTX_set_dh_rfc5114(ctx, generator) }
    }
}

ffi_export! {
    /// Sets a named DH group by NID (through the ctrl).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_nid(ctx: *mut EVP_PKEY_CTX, nid: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, EVP_PKEY_DH, EVP_PKEY_OP_PARAMGEN | EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_DH_NID, nid, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Sets whether DH derivation pads the secret (strict). -2 outside a derivation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_pad(ctx: *mut EVP_PKEY_CTX, pad: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, "EVP_PKEY_CTX_set_dh_pad");
        if ret <= 0 {
            return ret;
        }
        let mut upad: c_uint = pad.cast_unsigned();
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_uint(key(OSSL_EXCHANGE_PARAM_PAD), &raw mut upad) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1_strict(ctx, p) }
    }
}

macro_rules! ctrl_fn {
    ($(#[$attr:meta])* pub unsafe extern "C" fn $name:ident($($arg:ident: $ty:ty),*) => $keytype:expr, $op:expr, $cmd:expr, $p1:expr, $p2:expr) => {
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `ctx` is NULL or a live context; the pointer argument is what the ctrl takes.
            pub unsafe extern "C" fn $name(ctx: *mut EVP_PKEY_CTX $(, $arg: $ty)*) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { ctrl::ctrl(ctx, $keytype, $op, $cmd, $p1, $p2) }
            }
        }
    };
}

ctrl_fn! {
    /// Sets the X9.42 KDF type of DH derivation (`EVP_PKEY_DH_KDF_*`).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_kdf_type(kdf: c_int) => EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_DH_KDF_TYPE, kdf, ptr::null_mut()
}

ctrl_fn! {
    /// Gets the KDF type of DH derivation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_dh_kdf_type() => EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_DH_KDF_TYPE, -2, ptr::null_mut()
}

ctrl_fn! {
    /// Sets the KDF's key-wrapping algorithm (the object is not taken over).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set0_dh_kdf_oid(oid: *mut ASN1_OBJECT) => EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_DH_KDF_OID, 0, oid.cast()
}

ctrl_fn! {
    /// Gets the KDF's key-wrapping algorithm (never, through the translation).
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_dh_kdf_oid(oid: *mut *mut ASN1_OBJECT) => EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_GET_DH_KDF_OID, 0, oid.cast()
}

ctrl_fn! {
    /// Sets the KDF digest of DH derivation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_kdf_md(md: *const EVP_MD) => EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_DH_KDF_MD, 0, md.cast_mut().cast()
}

ctrl_fn! {
    /// Gets the KDF digest of DH derivation into `*pmd`.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_dh_kdf_md(pmd: *mut *const EVP_MD) => EVP_PKEY_DHX, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_GET_DH_KDF_MD, 0, pmd.cast()
}

/// The outlen setters of DH and EC: -2 for a length <= 0, else strict.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn set_kdf_outlen(ctx: *mut EVP_PKEY_CTX, outlen: c_int, function: &str) -> c_int {
    if outlen <= 0 {
        return -2;
    }
    let mut len = size_of_int(outlen);
    // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
    let p =
        unsafe { OSSL_PARAM_construct_size_t(key(OSSL_EXCHANGE_PARAM_KDF_OUTLEN), &raw mut len) };
    // SAFETY: the caller's context; the parameter above.
    let ret = unsafe { set1_strict(ctx, p) };
    if ret == -2 {
        err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, function);
    }
    ret
}

/// Gets the KDF output length (strict): the getter's result and the length.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn get_kdf_outlen(ctx: *mut EVP_PKEY_CTX, function: &str) -> (c_int, usize) {
    let mut len: usize = c_uint::MAX as usize;
    // SAFETY: a static key; the local, which outlives the call.
    let mut params = [
        unsafe { OSSL_PARAM_construct_size_t(key(OSSL_EXCHANGE_PARAM_KDF_OUTLEN), &raw mut len) },
        end(),
    ];
    // SAFETY: the caller's context; the array above.
    let ret = unsafe { get_params_strict(ctx, params.as_mut_ptr()) };
    if ret == -2 {
        err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, function);
    }
    (ret, len)
}

ffi_export! {
    /// Sets the KDF output length of DH derivation (strict). -2 for a length <= 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dh_kdf_outlen(ctx: *mut EVP_PKEY_CTX, outlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, "dh_param_derive_check");
        if ret != 1 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set_kdf_outlen(ctx, outlen, "EVP_PKEY_CTX_set_dh_kdf_outlen") }
    }
}

ffi_export! {
    /// Gets the KDF output length of DH derivation into `*plen`: 1, or -1 (-2 outside a
    /// derivation).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `plen` is room for an int.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_dh_kdf_outlen(ctx: *mut EVP_PKEY_CTX, plen: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, "dh_param_derive_check");
        if ret != 1 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        let (ret, len) = unsafe { get_kdf_outlen(ctx, "EVP_PKEY_CTX_get_dh_kdf_outlen") };
        let Ok(v) = c_int::try_from(len) else { return -1 };
        if ret != 1 {
            return -1;
        }
        if !plen.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { plen.write(v) };
        }
        1
    }
}

/// Sets the KDF's UKM (strict), freeing the caller's buffer when it's taken.
///
/// # Safety
/// `ctx` is a live context; `ukm` is NULL or `OPENSSL_malloc` memory holding `len` octets.
unsafe fn set0_ukm(ctx: *mut EVP_PKEY_CTX, ukm: *mut u8, len: usize, function: &str) -> c_int {
    // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
    let p = unsafe {
        OSSL_PARAM_construct_octet_string(key(OSSL_EXCHANGE_PARAM_KDF_UKM), ukm.cast(), len)
    };
    // SAFETY: the caller's context; the parameter above.
    let ret = unsafe { set1_strict(ctx, p) };
    if ret == -2 {
        err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, function);
    }
    if ret == 1 {
        // SAFETY: the caller's guarantee: the buffer is taken over.
        unsafe { crate::mem::free(ukm.cast(), ptr::null(), 0) };
    }
    ret
}

/// Gets a pointer to the KDF's UKM (strict): the getter's result and the UKM's length.
///
/// # Safety
/// `ctx` is a live context; `pukm` is room for a pointer.
unsafe fn get0_ukm(ctx: *mut EVP_PKEY_CTX, pukm: *mut *mut u8, function: &str) -> (c_int, usize) {
    // SAFETY: a static key; the caller's pointer to fill.
    let mut params = [
        unsafe { OSSL_PARAM_construct_octet_ptr(key(OSSL_EXCHANGE_PARAM_KDF_UKM), pukm.cast(), 0) },
        end(),
    ];
    // SAFETY: the caller's context; the array above.
    let ret = unsafe { get_params_strict(ctx, params.as_mut_ptr()) };
    if ret == -2 {
        err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, function);
    }
    (ret, params[0].return_size)
}

ffi_export! {
    /// Sets the UKM of DH derivation (taking over `ukm` on success). -1 for a negative length.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `ukm` is NULL or `OPENSSL_malloc` memory holding `len`
    /// octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set0_dh_kdf_ukm(ctx: *mut EVP_PKEY_CTX, ukm: *mut u8, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let Ok(n) = usize::try_from(len) else { return -1 };
        let ret = derive_check(ctx, "dh_param_derive_check");
        if ret != 1 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set0_ukm(ctx, ukm, n, "EVP_PKEY_CTX_set0_dh_kdf_ukm") }
    }
}

ffi_export! {
    /// Points `*pukm` at the UKM of DH derivation: its length, or -1 (-2 outside a derivation).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pukm` is room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_dh_kdf_ukm(ctx: *mut EVP_PKEY_CTX, pukm: *mut *mut u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, "dh_param_derive_check");
        if ret != 1 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        let (ret, len) = unsafe { get0_ukm(ctx, pukm, "EVP_PKEY_CTX_get0_dh_kdf_ukm") };
        if ret != 1 {
            return -1;
        }
        c_int::try_from(len).unwrap_or(-1)
    }
}

// -------------------------------------------------------------------------------------------
// DSA (dsa_ctrl.c)

ffi_export! {
    /// Sets the DSA parameter generation type's name.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_type(ctx: *mut EVP_PKEY_CTX, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "dsa_paramgen_check");
        if ret <= 0 {
            return ret;
        }
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_utf8_string(key(OSSL_PKEY_PARAM_FFC_TYPE), name.cast_mut(), 0) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1(ctx, p) }
    }
}

ffi_export! {
    /// Sets the FIPS 186-4 generator index of DSA parameter generation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_gindex(ctx: *mut EVP_PKEY_CTX, gindex: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "dsa_paramgen_check");
        if ret <= 0 {
            return ret;
        }
        let mut g = gindex;
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_int(key(OSSL_PKEY_PARAM_FFC_GINDEX), &raw mut g) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1(ctx, p) }
    }
}

ffi_export! {
    /// Sets the FIPS 186-4 seed of DSA parameter generation.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `seed` holds `seedlen` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_seed(ctx: *mut EVP_PKEY_CTX, seed: *const u8, seedlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "dsa_paramgen_check");
        if ret <= 0 {
            return ret;
        }
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_octet_string(key(OSSL_PKEY_PARAM_FFC_SEED), seed.cast_mut().cast(), seedlen) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1(ctx, p) }
    }
}

macro_rules! dsa_size_setter {
    ($(#[$attr:meta])* pub unsafe extern "C" fn $name:ident($arg:ident) => $param:expr) => {
        ffi_export! {
            $(#[$attr])*
            ///
            /// # Safety
            /// `ctx` is NULL or a live context.
            pub unsafe extern "C" fn $name(ctx: *mut EVP_PKEY_CTX, $arg: c_int) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                let ret = gen_check(ctx, "dsa_paramgen_check");
                if ret <= 0 {
                    return ret;
                }
                let mut v = size_of_int($arg);
                // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
                let p = unsafe { OSSL_PARAM_construct_size_t(key($param), &raw mut v) };
                // SAFETY: the caller's context; the parameter above.
                unsafe { set1(ctx, p) }
            }
        }
    };
}

dsa_size_setter! {
    /// Sets the prime length of DSA parameter generation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_bits(nbits) => OSSL_PKEY_PARAM_FFC_PBITS
}

dsa_size_setter! {
    /// Sets the subprime length of DSA parameter generation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_q_bits(qbits) => OSSL_PKEY_PARAM_FFC_QBITS
}

ffi_export! {
    /// Sets the digest of DSA parameter generation by name, with properties.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md_name` and `md_properties` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_md_props(ctx: *mut EVP_PKEY_CTX, md_name: *const c_char, md_properties: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "dsa_paramgen_check");
        if ret <= 0 {
            return ret;
        }
        let mut params = vec![
            // SAFETY: a static key; the caller's string.
            unsafe { OSSL_PARAM_construct_utf8_string(key(OSSL_PKEY_PARAM_FFC_DIGEST), md_name.cast_mut(), 0) },
        ];
        if !md_properties.is_null() {
            // SAFETY: as above.
            params.push(unsafe { OSSL_PARAM_construct_utf8_string(key(OSSL_PKEY_PARAM_FFC_DIGEST_PROPS), md_properties.cast_mut(), 0) });
        }
        params.push(end());
        // SAFETY: the caller's context; the array above.
        unsafe { EVP_PKEY_CTX_set_params(ctx, params.as_ptr()) }
    }
}

ctrl_fn! {
    /// Sets the digest of DSA parameter generation (through the ctrl).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_dsa_paramgen_md(md: *const EVP_MD) => EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, md.cast_mut().cast()
}

// -------------------------------------------------------------------------------------------
// EC (ec_ctrl.c)

const ECDH_CHECK: &str = "evp_pkey_ctx_getset_ecdh_param_checks";

ffi_export! {
    /// Sets the ECDH cofactor mode (-1, 0, or 1; strict). -2 for another value.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx: *mut EVP_PKEY_CTX, cofactor_mode: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, ECDH_CHECK);
        if ret != 1 {
            return ret;
        }
        if !(-1..=1).contains(&cofactor_mode) {
            return -2;
        }
        let mut m = cofactor_mode;
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_int(key(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE), &raw mut m) };
        // SAFETY: the caller's context; the parameter above.
        let ret = unsafe { set1_strict(ctx, p) };
        if ret == -2 {
            err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, "EVP_PKEY_CTX_set_ecdh_cofactor_mode");
        }
        ret
    }
}

ffi_export! {
    /// The ECDH cofactor mode (0 or 1), or -1 (-2 if unsupported).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_ecdh_cofactor_mode(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, ECDH_CHECK);
        if ret != 1 {
            return ret;
        }
        let mut mode: c_int = 0;
        // SAFETY: a static key; the local, which outlives the call.
        let mut params = [unsafe { OSSL_PARAM_construct_int(key(OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE), &raw mut mode) }, end()];
        // SAFETY: the caller's context; the array above.
        match unsafe { get_params_strict(ctx, params.as_mut_ptr()) } {
            -2 => {
                err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, "EVP_PKEY_CTX_get_ecdh_cofactor_mode");
                -2
            }
            1 if (0..=1).contains(&mode) => mode,
            _ => -1,
        }
    }
}

ctrl_fn! {
    /// Sets the KDF type of ECDH derivation (`EVP_PKEY_ECDH_KDF_*`).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_ecdh_kdf_type(kdf: c_int) => EVP_PKEY_EC, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_EC_KDF_TYPE, kdf, ptr::null_mut()
}

ctrl_fn! {
    /// Gets the KDF type of ECDH derivation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_ecdh_kdf_type() => EVP_PKEY_EC, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_EC_KDF_TYPE, -2, ptr::null_mut()
}

ctrl_fn! {
    /// Sets the KDF digest of ECDH derivation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_ecdh_kdf_md(md: *const EVP_MD) => EVP_PKEY_EC, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_EC_KDF_MD, 0, md.cast_mut().cast()
}

ctrl_fn! {
    /// Gets the KDF digest of ECDH derivation into `*pmd`.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_ecdh_kdf_md(pmd: *mut *const EVP_MD) => EVP_PKEY_EC, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_GET_EC_KDF_MD, 0, pmd.cast()
}

ffi_export! {
    /// Sets the KDF output length of ECDH derivation (strict). -2 for a length <= 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx: *mut EVP_PKEY_CTX, outlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, ECDH_CHECK);
        if ret != 1 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        unsafe { set_kdf_outlen(ctx, outlen, "EVP_PKEY_CTX_set_ecdh_kdf_outlen") }
    }
}

ffi_export! {
    /// Gets the KDF output length of ECDH derivation into `*plen`: 1, -2 if unsupported, or
    /// -1.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `plen` is room for an int.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx: *mut EVP_PKEY_CTX, plen: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, ECDH_CHECK);
        if ret != 1 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        match unsafe { get_kdf_outlen(ctx, "EVP_PKEY_CTX_get_ecdh_kdf_outlen") } {
            (-2, _) => -2,
            (1, len) => match c_int::try_from(len) {
                Ok(v) => {
                    if !plen.is_null() {
                        // SAFETY: the caller's guarantee.
                        unsafe { plen.write(v) };
                    }
                    1
                }
                Err(_) => -1,
            },
            _ => -1,
        }
    }
}

ffi_export! {
    /// Sets the UKM of ECDH derivation (taking over `ukm` on success).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `ukm` is NULL or `OPENSSL_malloc` memory holding `len`
    /// octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set0_ecdh_kdf_ukm(ctx: *mut EVP_PKEY_CTX, ukm: *mut u8, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, ECDH_CHECK);
        if ret != 1 {
            return ret;
        }
        // SAFETY: the caller's guarantee (the length as C converts it).
        unsafe { set0_ukm(ctx, ukm, size_of_int(len), "EVP_PKEY_CTX_set0_ecdh_kdf_ukm") }
    }
}

ffi_export! {
    /// Points `*pukm` at the UKM of ECDH derivation: its length, -2 if unsupported, or -1.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pukm` is room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_ecdh_kdf_ukm(ctx: *mut EVP_PKEY_CTX, pukm: *mut *mut u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = derive_check(ctx, ECDH_CHECK);
        if ret != 1 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        match unsafe { get0_ukm(ctx, pukm, "EVP_PKEY_CTX_get0_ecdh_kdf_ukm") } {
            (-2, _) => -2,
            (1, len) => c_int::try_from(len).unwrap_or(-1),
            _ => -1,
        }
    }
}

ffi_export! {
    /// Sets the curve of EC (or SM2, for its NID) generation by NID.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx: *mut EVP_PKEY_CTX, nid: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let keytype = if nid == NID_sm2 { EVP_PKEY_SM2 } else { EVP_PKEY_EC };
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, keytype, EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, nid, ptr::null_mut()) }
    }
}

ctrl_fn! {
    /// Sets the parameter encoding of EC generation (`OPENSSL_EC_*_CURVE`).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_ec_param_enc(param_enc: c_int) => EVP_PKEY_EC, EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_CTRL_EC_PARAM_ENC, param_enc, ptr::null_mut()
}

// -------------------------------------------------------------------------------------------
// RSA (rsa_lib.c)

/// `RSA_pkey_ctx_ctrl`: a ctrl of any key type (an `EVP_PKEY_METHOD`'s type would be checked).
///
/// # Safety
/// `ctx` is NULL or a live context; `p2` is what the command takes.
unsafe fn rsa_ctrl(
    ctx: *mut EVP_PKEY_CTX,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { ctrl::ctrl(ctx, -1, optype, cmd, p1, p2) }
}

/// `EVP_PKEY_CTX_is_a`.
fn is_a(ctx: *mut EVP_PKEY_CTX, name: &CStr) -> bool {
    // SAFETY: the callers' guarantee: NULL or a live context; a string.
    unsafe { EVP_PKEY_CTX_is_a(ctx, name.as_ptr()) != 0 }
}

/// The RSA key type check of `int_set_rsa_md_name` and `int_get_rsa_md_name`.
fn rsa_type_ok(ctx: *mut EVP_PKEY_CTX, keytype: c_int) -> bool {
    if keytype == -1 {
        is_a(ctx, c"RSA") || is_a(ctx, c"RSA-PSS")
    } else {
        let name = super::pkey::ameth::type2name(keytype);
        std::ffi::CString::new(name).is_ok_and(|n| is_a(ctx, &n))
    }
}

/// `int_set_rsa_md_name`.
///
/// # Safety
/// `ctx` is NULL or a live context; `mdname` and `mdprops` are NULL or strings.
unsafe fn set_rsa_md_name(
    ctx: *mut EVP_PKEY_CTX,
    keytype: c_int,
    optype: c_int,
    mdkey: &'static CStr,
    mdname: *const c_char,
    propkey: Option<&'static CStr>,
    mdprops: *const c_char,
) -> c_int {
    if mdname.is_null() || op_of(ctx).is_none_or(|s| s.0 & optype == 0) {
        return not_supported("int_set_rsa_md_name");
    }
    if !rsa_type_ok(ctx, keytype) {
        return -1;
    }
    // SAFETY: a static key; the caller's string.
    let mut params =
        vec![unsafe { OSSL_PARAM_construct_utf8_string(key(mdkey), mdname.cast_mut(), 0) }];
    if let Some(pk) = propkey
        && !mdprops.is_null()
    {
        // SAFETY: as above.
        params.push(unsafe { OSSL_PARAM_construct_utf8_string(key(pk), mdprops.cast_mut(), 0) });
    }
    params.push(end());
    // SAFETY: the caller's context; the array above.
    unsafe { set_params_strict(ctx, params.as_ptr()) }
}

/// `int_get_rsa_md_name`.
///
/// # Safety
/// `ctx` is NULL or a live context; `mdname` is NULL or has room for `size` octets.
unsafe fn get_rsa_md_name(
    ctx: *mut EVP_PKEY_CTX,
    keytype: c_int,
    optype: c_int,
    mdkey: &'static CStr,
    mdname: *mut c_char,
    size: usize,
) -> c_int {
    if mdname.is_null() || op_of(ctx).is_none_or(|s| s.0 & optype == 0) {
        return not_supported("int_get_rsa_md_name");
    }
    if !rsa_type_ok(ctx, keytype) {
        return -1;
    }
    // SAFETY: a static key; the caller's buffer.
    let mut params = [
        unsafe { OSSL_PARAM_construct_utf8_string(key(mdkey), mdname, size) },
        end(),
    ];
    // SAFETY: the caller's context; the array above.
    unsafe { get_params_strict(ctx, params.as_mut_ptr()) }
}

ffi_export! {
    /// Sets the RSA padding mode (through the ctrl).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EVP_PKEY_CTX, pad_mode: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_ctrl(ctx, -1, EVP_PKEY_CTRL_RSA_PADDING, pad_mode, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Gets the RSA padding mode into `*pad_mode` (the length of its name back, through the
    /// translation).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pad_mode` is NULL or room for an int.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_padding(ctx: *mut EVP_PKEY_CTX, pad_mode: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_ctrl(ctx, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, pad_mode.cast()) }
    }
}

ctrl_fn! {
    /// Sets the digest of RSA-PSS key generation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_md(md: *const EVP_MD) => EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_MD, 0, md.cast_mut().cast()
}

ffi_export! {
    /// Sets the digest of RSA-PSS key generation by name (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `mdname` and `mdprops` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(ctx: *mut EVP_PKEY_CTX, mdname: *const c_char, mdprops: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_rsa_md_name(ctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, OSSL_PKEY_PARAM_RSA_DIGEST, mdname, Some(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS), mdprops) }
    }
}

ffi_export! {
    /// Sets the OAEP digest. -1 for a key type other than RSA.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is NULL or a live digest.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if !is_a(ctx, c"RSA") {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_MD, 0, md.cast_mut().cast()) }
    }
}

ffi_export! {
    /// Sets the OAEP digest by name (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `mdname` and `mdprops` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx: *mut EVP_PKEY_CTX, mdname: *const c_char, mdprops: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_rsa_md_name(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, mdname, Some(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS), mdprops) }
    }
}

ffi_export! {
    /// Gets the OAEP digest's name into `name` (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` is NULL or has room for `namesize` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_oaep_md_name(ctx: *mut EVP_PKEY_CTX, name: *mut c_char, namesize: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_rsa_md_name(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, name, namesize) }
    }
}

ffi_export! {
    /// Gets the OAEP digest into `*md`. -1 for a key type other than RSA.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is NULL or room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_oaep_md(ctx: *mut EVP_PKEY_CTX, md: *mut *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if !is_a(ctx, c"RSA") {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        unsafe { ctrl::ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, md.cast()) }
    }
}

ffi_export! {
    /// Sets the MGF1 digest (through the ctrl).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is NULL or a live digest.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_MGF1_MD, 0, md.cast_mut().cast()) }
    }
}

ffi_export! {
    /// Sets the MGF1 digest by name (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `mdname` and `mdprops` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx: *mut EVP_PKEY_CTX, mdname: *const c_char, mdprops: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_rsa_md_name(ctx, -1, EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG, OSSL_PKEY_PARAM_MGF1_DIGEST, mdname, Some(OSSL_PKEY_PARAM_MGF1_PROPERTIES), mdprops) }
    }
}

ffi_export! {
    /// Gets the MGF1 digest's name into `name` (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` is NULL or has room for `namesize` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_mgf1_md_name(ctx: *mut EVP_PKEY_CTX, name: *mut c_char, namesize: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_rsa_md_name(ctx, -1, EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG, OSSL_PKEY_PARAM_MGF1_DIGEST, name, namesize) }
    }
}

ctrl_fn! {
    /// Sets the MGF1 digest of RSA-PSS key generation.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md(md: *const EVP_MD) => EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_MGF1_MD, 0, md.cast_mut().cast()
}

ffi_export! {
    /// Sets the MGF1 digest of RSA-PSS key generation by name (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `mdname` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_mgf1_md_name(ctx: *mut EVP_PKEY_CTX, mdname: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_rsa_md_name(ctx, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_KEYGEN, OSSL_PKEY_PARAM_MGF1_DIGEST, mdname, None, ptr::null()) }
    }
}

ffi_export! {
    /// Gets the MGF1 digest into `*md` (through the ctrl).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is NULL or room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_mgf1_md(ctx: *mut EVP_PKEY_CTX, md: *mut *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG | EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_GET_RSA_MGF1_MD, 0, md.cast()) }
    }
}

/// The check of the OAEP label functions: an asymmetric cipher operation (-2) on an RSA key
/// (-1).
fn oaep_label_check(ctx: *mut EVP_PKEY_CTX, function: &str) -> c_int {
    if op_of(ctx).is_none_or(|s| s.0 & EVP_PKEY_OP_TYPE_CRYPT == 0) {
        return not_supported(function);
    }
    if !is_a(ctx, c"RSA") {
        return -1;
    }
    1
}

ffi_export! {
    /// Sets the OAEP label (strict), taking over `label` (from `OPENSSL_malloc`) on success.
    /// NULL with a zero length sets an empty label.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `label` is NULL or `OPENSSL_malloc` memory holding
    /// `llen` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set0_rsa_oaep_label(ctx: *mut EVP_PKEY_CTX, label: *mut c_void, llen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = oaep_label_check(ctx, "EVP_PKEY_CTX_set0_rsa_oaep_label");
        if ret <= 0 {
            return ret;
        }
        let plabel = if label.is_null() && llen == 0 { c"".as_ptr().cast_mut().cast() } else { label };
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_octet_string(key(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL), plabel, size_of_int(llen)) };
        // SAFETY: the caller's context; the parameter above.
        let ret = unsafe { set1_strict(ctx, p) };
        if ret <= 0 {
            return ret;
        }
        // SAFETY: the caller's guarantee: the label is taken over.
        unsafe { crate::mem::free(label, ptr::null(), 0) };
        1
    }
}

ffi_export! {
    /// Points `*label` at the OAEP label: its length, or -1 (-2 outside an asymmetric cipher
    /// operation).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `label` is room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get0_rsa_oaep_label(ctx: *mut EVP_PKEY_CTX, label: *mut *mut u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = oaep_label_check(ctx, "EVP_PKEY_CTX_get0_rsa_oaep_label");
        if ret <= 0 {
            return ret;
        }
        // SAFETY: a static key; the caller's pointer to fill.
        let mut params = [unsafe { OSSL_PARAM_construct_octet_ptr(key(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL), label.cast(), 0) }, end()];
        // SAFETY: the caller's context; the array above.
        if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
            return -1;
        }
        c_int::try_from(params[0].return_size).unwrap_or(-1)
    }
}

ffi_export! {
    /// Sets the PSS salt length (through the ctrl).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut EVP_PKEY_CTX, saltlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_RSA_PSS_SALTLEN, saltlen, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Gets the PSS salt length into `*saltlen` (through the ctrl).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `saltlen` is NULL or room for an int.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx: *mut EVP_PKEY_CTX, saltlen: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_ctrl(ctx, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, 0, saltlen.cast()) }
    }
}

ffi_export! {
    /// Sets the salt length of RSA-PSS key generation (strict). -1 for another key type.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen(ctx: *mut EVP_PKEY_CTX, saltlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "EVP_PKEY_CTX_set_rsa_pss_keygen_saltlen");
        if ret <= 0 {
            return ret;
        }
        if !is_a(ctx, c"RSA-PSS") {
            return -1;
        }
        let mut s = saltlen;
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_int(key(OSSL_SIGNATURE_PARAM_PSS_SALTLEN), &raw mut s) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1_strict(ctx, p) }
    }
}

/// The RSA key generation size setters: a generation (-2) of RSA or RSA-PSS (-1), strict.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn rsa_keygen_size(
    ctx: *mut EVP_PKEY_CTX,
    v: c_int,
    param: &'static CStr,
    function: &str,
) -> c_int {
    let ret = gen_check(ctx, function);
    if ret <= 0 {
        return ret;
    }
    if !is_a(ctx, c"RSA") && !is_a(ctx, c"RSA-PSS") {
        return -1;
    }
    let mut v = size_of_int(v);
    // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
    let p = unsafe { OSSL_PARAM_construct_size_t(key(param), &raw mut v) };
    // SAFETY: the caller's context; the parameter above.
    unsafe { set1_strict(ctx, p) }
}

ffi_export! {
    /// Sets the modulus size of RSA key generation (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_keygen_bits(ctx: *mut EVP_PKEY_CTX, bits: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_keygen_size(ctx, bits, OSSL_PKEY_PARAM_RSA_BITS, "EVP_PKEY_CTX_set_rsa_keygen_bits") }
    }
}

ffi_export! {
    /// Sets the number of primes of RSA key generation (strict).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_keygen_primes(ctx: *mut EVP_PKEY_CTX, primes: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_keygen_size(ctx, primes, OSSL_PKEY_PARAM_RSA_PRIMES, "EVP_PKEY_CTX_set_rsa_keygen_primes") }
    }
}

ffi_export! {
    /// Sets the public exponent of RSA key generation, taking over `pubexp` on success.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `pubexp` is NULL or a BIGNUM the caller gives up on
    /// success.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx: *mut EVP_PKEY_CTX, pubexp: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { rsa_ctrl(ctx, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp.cast()) };
        // SAFETY: the caller's guarantee.
        if ret > 0 && let Some(c) = unsafe { pkey_ctx::context(ctx) } {
            let mut s = c.lock();
            if s.keymgmt.is_some() {
                let old = core::mem::replace(&mut s.rsa_pubexp, Ptr(pubexp));
                drop(s);
                // SAFETY: the exponent the context owned, or NULL.
                unsafe { crate::bn::BN_free(old.0) };
            }
        }
        ret
    }
}

ctrl_fn! {
    /// Sets the public exponent of RSA key generation (copied).
    pub unsafe extern "C" fn EVP_PKEY_CTX_set1_rsa_keygen_pubexp(pubexp: *mut BIGNUM) => EVP_PKEY_RSA, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, 0, pubexp.cast()
}

// -------------------------------------------------------------------------------------------
// Groups and algorithm identifiers (evp_lib.c)

ffi_export! {
    /// Sets the group of a generation by name. -2 outside a generation, -1 for NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_group_name(ctx: *mut EVP_PKEY_CTX, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "EVP_PKEY_CTX_set_group_name");
        if ret <= 0 {
            return ret;
        }
        if name.is_null() {
            return -1;
        }
        // SAFETY: a static key; the caller's (or a local) value, which outlives the call.
        let p = unsafe { OSSL_PARAM_construct_utf8_string(key(OSSL_PKEY_PARAM_GROUP_NAME), name.cast_mut(), 0) };
        // SAFETY: the caller's context; the parameter above.
        unsafe { set1(ctx, p) }
    }
}

ffi_export! {
    /// Gets the group's name into `name`: 1, or -1 (-2 outside a generation).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` is NULL or has room for `namelen` octets.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_group_name(ctx: *mut EVP_PKEY_CTX, name: *mut c_char, namelen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let ret = gen_check(ctx, "EVP_PKEY_CTX_get_group_name");
        if ret <= 0 {
            return ret;
        }
        if name.is_null() {
            return -1;
        }
        // SAFETY: a static key; the caller's buffer.
        let mut params = [unsafe { OSSL_PARAM_construct_utf8_string(key(OSSL_PKEY_PARAM_GROUP_NAME), name, namelen) }, end()];
        // SAFETY: the caller's context; the array above.
        if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
            return -1;
        }
        1
    }
}

ffi_export! {
    /// Gives the operation `alg`'s parameters (DER, as `OSSL_PKEY_PARAM_ALGORITHM_ID_PARAMS`):
    /// the setter's result, or -1. A NULL algorithm fails (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `alg` is NULL or a live algorithm identifier.
    pub unsafe extern "C" fn EVP_PKEY_CTX_set_algor_params(ctx: *mut EVP_PKEY_CTX, alg: *const X509_ALGOR) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { alg.as_ref() }) else { return -1 };
        let mut der: *mut u8 = ptr::null_mut();
        // SAFETY: the parameter (or NULL); the encoder allocates.
        let derl = unsafe { crate::asn1::tpl::items::i2d_ASN1_TYPE(a.parameter, &raw mut der) };
        let mut ret = -1;
        if let Ok(n) = usize::try_from(derl) {
            // SAFETY: a static key; the encoding.
            let p = unsafe { OSSL_PARAM_construct_octet_string(key(OSSL_PKEY_PARAM_ALGORITHM_ID_PARAMS), der.cast(), n) };
            // SAFETY: the caller's context.
            ret = unsafe { set1(ctx, p) };
        }
        // SAFETY: the encoder's allocation, or NULL.
        unsafe { crate::mem::free(der.cast(), ptr::null(), 0) };
        ret
    }
}

ffi_export! {
    /// Sets `alg`'s parameters from the operation's: 1, or -1.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `alg` is NULL or a live algorithm identifier.
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_algor_params(ctx: *mut EVP_PKEY_CTX, alg: *mut X509_ALGOR) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { alg.as_mut() }) else { return -1 };
        let k = key(OSSL_PKEY_PARAM_ALGORITHM_ID_PARAMS);
        // SAFETY: a static key; no buffer: the length is asked.
        let mut params = [unsafe { OSSL_PARAM_construct_octet_string(k, ptr::null_mut(), 0) }, end()];
        // SAFETY: the caller's context; the array above.
        if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
            return -1;
        }
        let derl = params[0].return_size;
        // SAFETY: the parameter above.
        if unsafe { OSSL_PARAM_modified(params.as_ptr()) } == 0 || derl == 0 {
            return -1;
        }
        let mut der = vec![0u8; derl];
        // SAFETY: a static key; the buffer.
        params[0] = unsafe { OSSL_PARAM_construct_octet_string(k, der.as_mut_ptr().cast(), derl) };
        // SAFETY: as above.
        if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 || unsafe { OSSL_PARAM_modified(params.as_ptr()) } == 0 {
            return -1;
        }
        let Ok(len) = core::ffi::c_long::try_from(derl) else { return -1 };
        let mut t = a.parameter;
        let mut pp: *const u8 = der.as_ptr();
        // SAFETY: the parameter to reuse (or NULL); the encoding.
        if unsafe { crate::asn1::tpl::items::d2i_ASN1_TYPE(&raw mut t, &raw mut pp, len) }.is_null() {
            return -1;
        }
        a.parameter = t;
        1
    }
}

ffi_export! {
    /// The operation's algorithm identifier into `*alg` (decoded): 1; -2 with
    /// `EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED` if it has none; -1 otherwise (also
    /// for a NULL `alg`).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `alg` is NULL or room for a pointer (NULL or a live
    /// algorithm identifier).
    pub unsafe extern "C" fn EVP_PKEY_CTX_get_algor(ctx: *mut EVP_PKEY_CTX, alg: *mut *mut X509_ALGOR) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        let k = key(OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
        // SAFETY: a static key; no buffer: the length is asked.
        let mut params = [unsafe { OSSL_PARAM_construct_octet_string(k, ptr::null_mut(), 0) }, end()];
        // SAFETY: the caller's context; the array above.
        if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } <= 0 {
            return -1;
        }
        // SAFETY: the parameter above.
        let aid_len = if unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0 { params[0].return_size } else { 0 };
        if aid_len == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_GETTING_ALGORITHMIDENTIFIER_NOT_SUPPORTED, "EVP_PKEY_CTX_get_algor");
            return -2;
        }
        if alg.is_null() {
            return -1;
        }
        let mut aid = vec![0u8; aid_len];
        // SAFETY: a static key; the buffer.
        params[0] = unsafe { OSSL_PARAM_construct_octet_string(k, aid.as_mut_ptr().cast(), aid_len) };
        let Ok(len) = core::ffi::c_long::try_from(aid_len) else { return -1 };
        let mut pp: *const u8 = aid.as_ptr();
        // SAFETY: the caller's context; the array above.
        if unsafe { EVP_PKEY_CTX_get_params(ctx, params.as_mut_ptr()) } == 0 {
            return -1;
        }
        // SAFETY: the parameter above.
        if unsafe { OSSL_PARAM_modified(params.as_ptr()) } == 0 {
            return -1;
        }
        // SAFETY: the caller's pointer; the encoding.
        if unsafe { crate::asn1::tpl::items::d2i_X509_ALGOR(alg, &raw mut pp, len) }.is_null() {
            return -1;
        }
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL context fails as one without the operation (the reference
    /// crashes reading it).
    #[test]
    fn null_contexts_are_refused() {
        let c: *mut EVP_PKEY_CTX = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_hkdf_md(c, ptr::null()) }, -2);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_CTX_set1_hkdf_salt(c, ptr::null(), 0) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_scrypt_N(c, 16) }, -2);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_dh_pad(c, 1) }, -2);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_rsa_padding(c, 1) }, -2);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_algor_params(c, ptr::null()) }, -1);
        crate::err::take_all();
    }

    #[test]
    fn sizes_convert_as_c_does() {
        assert_eq!(size_of_int(5), 5);
        assert_eq!(size_of_int(-1), usize::MAX);
    }
}
