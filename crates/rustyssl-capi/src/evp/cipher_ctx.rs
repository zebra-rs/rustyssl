//! Cipher contexts (`EVP_EncryptInit(3)`): `EVP_CIPHER_CTX` and encrypting and decrypting
//! through a fetched cipher's provider functions, ported from `crypto/evp/evp_enc.c` and the
//! accessors in `evp_lib.c`.
//!
//! The context is OpenSSL's: a zeroed allocation holding the cipher in use and the reference
//! the context owns, the direction, cached key and IV lengths (-1 until known), flags, the
//! application's data, the provider's algorithm context, and the legacy buffers some accessors
//! still return. Its behavior follows the reference's paths, including:
//! - initializing with a cipher when the context has one resets it (keeping the flags and the
//!   direction) and frees what `EVP_CIPHER_CTX_set_cipher_data` gave it; initializing without
//!   one keeps the algorithm context, so the key can be set apart from the IV;
//! - a static cipher (`EVP_aes_128_cbc()`) is replaced by the provider's, fetched by its short
//!   name; `EVP_CIPH_NO_PADDING` carries over to the new algorithm context; key and IV lengths
//!   given as parameters are set before the key and IV (CVE-2023-5363);
//! - `update` and `final` give the provider room for the input plus a block, and a direction
//!   other than the context's fails with `EVP_R_INVALID_OPERATION`;
//! - `EVP_Cipher` returns the length written, or -1, through a provider's `cipher`;
//! - `EVP_CIPHER_CTX_ctrl` turns each command into the provider parameter it stands for, and
//!   an unknown command or a parameter nothing handles into
//!   `EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED`.
//!
//! What OpenSSL dereferences without checking (a NULL context in most of these, a NULL cipher
//! for `EVP_CIPHER_CTX_set_key_length`) is refused here instead (docs/DEVIATIONS.md). There
//! are no engines, so an `ENGINE` argument fails initialization. Random keys come from the
//! operating system until the private generator of 3.7. The `EVP_CIPHER_meth_*` ciphers come
//! with 3.11, the pipeline functions and the AlgorithmIdentifier ones later.
//! `EVP_CipherInit_SKEY` keys a cipher with an opaque key of its provider's: its data for a
//! cipher that takes key objects, else its raw octets.

use core::ffi::{CStr, c_int, c_uint, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    ENGINE, ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, EVP_CIPH_FLAG_LENGTH_BITS,
    EVP_CIPH_NO_PADDING, EVP_CIPH_RAND_KEY, EVP_CIPHER, EVP_CIPHER_CTX, EVP_CTRL_AEAD_GET_TAG,
    EVP_CTRL_AEAD_SET_IV_FIXED, EVP_CTRL_AEAD_SET_IVLEN, EVP_CTRL_AEAD_SET_MAC_KEY,
    EVP_CTRL_AEAD_SET_TAG, EVP_CTRL_AEAD_TLS1_AAD, EVP_CTRL_CCM_SET_L, EVP_CTRL_GCM_IV_GEN,
    EVP_CTRL_GCM_SET_IV_INV, EVP_CTRL_GET_RC2_KEY_BITS, EVP_CTRL_GET_RC5_ROUNDS, EVP_CTRL_INIT,
    EVP_CTRL_RAND_KEY, EVP_CTRL_SET_KEY_LENGTH, EVP_CTRL_SET_RC2_KEY_BITS, EVP_CTRL_SET_RC5_ROUNDS,
    EVP_CTRL_SET_SPEED, EVP_CTRL_TLS1_1_MULTIBLOCK_AAD, EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT,
    EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE, EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM, EVP_MAX_BLOCK_LENGTH,
    EVP_MAX_IV_LENGTH, EVP_R_CANNOT_GET_PARAMETERS, EVP_R_CANNOT_SET_PARAMETERS,
    EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED, EVP_R_FINAL_ERROR, EVP_R_INITIALIZATION_ERROR,
    EVP_R_INPUT_NOT_INITIALIZED, EVP_R_INVALID_KEY_LENGTH, EVP_R_INVALID_LENGTH,
    EVP_R_INVALID_OPERATION, EVP_R_NO_CIPHER_SET, EVP_R_NOT_ABLE_TO_COPY_CTX, EVP_R_UPDATE_ERROR,
    NID_undef, OSSL_CIPHER_PARAM_AEAD_MAC_KEY, OSSL_CIPHER_PARAM_AEAD_TAG,
    OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
    OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN,
    OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV,
    OSSL_CIPHER_PARAM_IV, OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_KEYLEN, OSSL_CIPHER_PARAM_NUM,
    OSSL_CIPHER_PARAM_PADDING, OSSL_CIPHER_PARAM_RANDOM_KEY, OSSL_CIPHER_PARAM_RC2_KEYBITS,
    OSSL_CIPHER_PARAM_ROUNDS, OSSL_CIPHER_PARAM_SPEED, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, OSSL_CIPHER_PARAM_UPDATED_IV,
    OSSL_CIPHER_PARAM_USE_BITS, OSSL_PARAM,
};
use rustyssl_crypto::params::{OCTET_PTR, OCTET_STRING, UNSIGNED_INTEGER};

use super::cipher::{Cipher, EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_up_ref, method};
use crate::err;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::OBJ_nid2sn;
mod legacy;

pub(crate) use legacy::asn1_fn as legacy_asn1_fn;

use crate::params::{
    OSSL_PARAM_get_int, OSSL_PARAM_locate_const, OSSL_PARAM_modified, OSSL_PARAM_set_int,
    construct, end,
};

/// `EVP_CTRL_RET_UNSUPPORTED`: what the parameter helpers return for a cipher without a
/// provider.
const UNSUPPORTED: c_int = -1;

/// `EVP_MAX_IV_LENGTH` and `EVP_MAX_BLOCK_LENGTH` as array lengths.
const MAX_IV: usize = EVP_MAX_IV_LENGTH.cast_unsigned() as usize;
const MAX_BLOCK: usize = EVP_MAX_BLOCK_LENGTH.cast_unsigned() as usize;

/// What an `EVP_CIPHER_CTX *` points to (`struct evp_cipher_ctx_st`): every field is valid
/// zeroed.
#[repr(C)]
struct CipherCtx {
    /// The cipher in use.
    cipher: *const EVP_CIPHER,
    /// Always NULL: there are no engines.
    engine: *mut ENGINE,
    /// 1 when encrypting.
    encrypt: c_int,
    /// The legacy ciphers' partial block's length; unused.
    buf_len: c_int,
    /// The legacy buffers, which the IV accessors fall back to and `EVP_CIPHER_CTX_buf_noconst`
    /// returns.
    oiv: [u8; MAX_IV],
    iv: [u8; MAX_IV],
    buf: [u8; MAX_BLOCK],
    num: c_int,
    app_data: *mut c_void,
    /// The key length, or -1 (or 0) until asked.
    key_len: c_int,
    /// The IV length, or -1 until asked.
    iv_len: c_int,
    flags: c_ulong,
    /// What `EVP_CIPHER_CTX_set_cipher_data` set (the legacy ciphers' state).
    cipher_data: *mut c_void,
    final_used: c_int,
    block_mask: c_int,
    final_: [u8; MAX_BLOCK],
    /// The provider's algorithm context.
    algctx: *mut c_void,
    /// The context's reference to the cipher in use.
    fetched_cipher: *mut EVP_CIPHER,
}

impl CipherCtx {
    /// A cleared context (`memset` and `iv_len = -1`).
    fn cleared() -> Self {
        Self {
            cipher: ptr::null(),
            engine: ptr::null_mut(),
            encrypt: 0,
            buf_len: 0,
            oiv: [0; MAX_IV],
            iv: [0; MAX_IV],
            buf: [0; MAX_BLOCK],
            num: 0,
            app_data: ptr::null_mut(),
            key_len: 0,
            iv_len: -1,
            flags: 0,
            cipher_data: ptr::null_mut(),
            final_used: 0,
            block_mask: 0,
            final_: [0; MAX_BLOCK],
            algctx: ptr::null_mut(),
            fetched_cipher: ptr::null_mut(),
        }
    }

    /// The cipher in use, if any.
    fn cipher<'a>(&self) -> Option<&'a Cipher> {
        // SAFETY: the context holds a reference to its cipher (or it's a static one).
        unsafe { method(self.cipher) }
    }

    /// Whether the cipher in use is a provider's.
    fn provided(&self) -> bool {
        self.cipher().is_some_and(|c| !c.prov.0.is_null())
    }
}

/// The context behind `ctx`, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live context from `EVP_CIPHER_CTX_new`, not used elsewhere meanwhile.
unsafe fn context<'a>(ctx: *const EVP_CIPHER_CTX) -> Option<&'a mut CipherCtx> {
    // SAFETY: the caller's guarantee: an allocation of a `CipherCtx`, any bit pattern of
    // which is valid.
    unsafe { ctx.cast::<CipherCtx>().cast_mut().as_mut() }
}

/// An `EVP_CIPH_*` flag as the flags' type.
const fn flag(f: c_int) -> c_ulong {
    f.cast_unsigned() as c_ulong
}

/// An `int` of flags as C widens it to `unsigned long` (sign-extending).
#[allow(clippy::cast_sign_loss)]
fn widen(f: c_int) -> c_ulong {
    i64::from(f) as c_ulong
}

/// An `unsigned long` as C narrows it to `int`.
#[allow(clippy::cast_possible_truncation)]
fn narrow(f: c_ulong) -> c_int {
    f as c_int
}

/// An `int` as C converts it to `size_t`.
#[allow(clippy::cast_sign_loss)]
fn to_size(n: c_int) -> usize {
    isize::try_from(n).unwrap_or(0) as usize
}

/// A `size_t` as C converts it to `int`.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn to_int(n: usize) -> c_int {
    n as c_int
}

/// A parameter of `data_type` at `data`, `size` octets.
fn param(key: &'static CStr, data_type: u32, data: *mut c_void, size: usize) -> OSSL_PARAM {
    construct(key.as_ptr(), data_type, data, size)
}

/// `evp_do_ciph_ctx_setparams`: 0 for no cipher, -1 for a cipher without a provider, 0 with
/// `EVP_R_CANNOT_SET_PARAMETERS` without the function, else the provider's result.
///
/// # Safety
/// `algctx` is the cipher's algorithm context; `params` is a parameter array.
unsafe fn set_ctx_params(
    cipher: Option<&Cipher>,
    algctx: *mut c_void,
    params: *const OSSL_PARAM,
) -> c_int {
    let Some(c) = cipher else { return 0 };
    if c.prov.0.is_null() {
        return UNSUPPORTED;
    }
    let Some(set) = c.funcs.set_ctx_params else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_CANNOT_SET_PARAMETERS,
            "evp_do_ciph_ctx_setparams",
        );
        return 0;
    };
    // SAFETY: the caller's guarantee.
    unsafe { set(algctx, params) }
}

/// `evp_do_ciph_ctx_getparams`, likewise.
///
/// # Safety
/// As for [`set_ctx_params`].
unsafe fn get_ctx_params(
    cipher: Option<&Cipher>,
    algctx: *mut c_void,
    params: *mut OSSL_PARAM,
) -> c_int {
    let Some(c) = cipher else { return 0 };
    if c.prov.0.is_null() {
        return UNSUPPORTED;
    }
    let Some(get) = c.funcs.get_ctx_params else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_CANNOT_GET_PARAMETERS,
            "evp_do_ciph_ctx_getparams",
        );
        return 0;
    };
    // SAFETY: the caller's guarantee.
    unsafe { get(algctx, params) }
}

/// The context's parameter setter on its own cipher and algorithm context.
fn set_params_of(c: &CipherCtx, params: &[OSSL_PARAM]) -> c_int {
    // SAFETY: the context's cipher and algorithm context; an ended array.
    unsafe { set_ctx_params(c.cipher(), c.algctx, params.as_ptr()) }
}

/// The context's parameter getter likewise.
fn get_params_of(c: &CipherCtx, params: &mut [OSSL_PARAM]) -> c_int {
    // SAFETY: the context's cipher and algorithm context; an ended array.
    unsafe { get_ctx_params(c.cipher(), c.algctx, params.as_mut_ptr()) }
}

/// `EVP_CIPHER_CTX_reset` on a live context.
fn reset(c: &mut CipherCtx) {
    if c.provided() {
        if !c.algctx.is_null() {
            if let Some(free) = c.cipher().and_then(|m| m.funcs.freectx) {
                // SAFETY: the context's algorithm context, freed once.
                unsafe { free(c.algctx) };
            }
            c.algctx = ptr::null_mut();
        }
        // SAFETY: the context's own reference.
        unsafe { EVP_CIPHER_free(c.fetched_cipher) };
    } else {
        // The legacy path, for a context without a provided cipher: it owns its cipher data.
        // SAFETY: memory the application gave the context to free.
        unsafe { mem::release(c.cipher_data) };
    }
    *c = CipherCtx::cleared();
}

ffi_export! {
    /// A new, empty cipher context.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_new() -> *mut EVP_CIPHER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        let ctx = mem::alloc_zeroed(size_of::<CipherCtx>()).cast::<EVP_CIPHER_CTX>();
        // SAFETY: a new zeroed context, or NULL.
        if let Some(c) = unsafe { context(ctx) } {
            c.iv_len = -1;
        }
        ctx
    }
}

ffi_export! {
    /// Frees what the context holds and empties it. Returns 1 (NULL too).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_reset(ctx: *mut EVP_CIPHER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // An application's cipher's `cleanup` first; its failure fails the reset.
        // SAFETY: the caller's guarantee.
        if !unsafe { legacy::release(ctx) } {
            return 0;
        }
        // SAFETY: as above.
        if let Some(c) = unsafe { context(ctx) } {
            reset(c);
        }
        1
    }
}

ffi_export! {
    /// Resets and frees the context; NULL does nothing.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context, not used afterwards.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_free(ctx: *mut EVP_CIPHER_CTX)
    where failure = (), library = ERR_LIB_EVP
    {
        if ctx.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CIPHER_CTX_reset(ctx) };
        // SAFETY: an allocation from `EVP_CIPHER_CTX_new`.
        unsafe { mem::release(ctx.cast()) };
    }
}

/// `EVP_CIPHER_CTX_get_key_length` on a live context.
fn key_length(c: &mut CipherCtx) -> c_int {
    if c.cipher.is_null() {
        return 0;
    }
    if c.key_len <= 0 && c.provided() {
        let mut len: usize = 0;
        let mut params = [
            param(
                OSSL_CIPHER_PARAM_KEYLEN,
                UNSIGNED_INTEGER,
                (&raw mut len).cast(),
                size_of::<usize>(),
            ),
            end(),
        ];
        if get_params_of(c, &mut params) <= 0 {
            return UNSUPPORTED;
        }
        let Ok(n) = c_int::try_from(len) else {
            return -1;
        };
        c.key_len = n;
    }
    c.key_len
}

/// `EVP_CIPHER_CTX_get_iv_length` on a live context.
fn iv_length(c: &mut CipherCtx) -> c_int {
    let Some(cipher) = c.cipher() else { return 0 };
    if c.iv_len < 0 {
        let mut len = cipher.iv_len();
        if cipher.funcs.get_ctx_params.is_some() {
            let mut v: usize = to_size(len);
            let mut params = [
                param(
                    OSSL_CIPHER_PARAM_IVLEN,
                    UNSIGNED_INTEGER,
                    (&raw mut v).cast(),
                    size_of::<usize>(),
                ),
                end(),
            ];
            let rv = get_params_of(c, &mut params);
            if rv > 0 {
                // SAFETY: the array's first parameter.
                let modified = unsafe { OSSL_PARAM_modified(params.as_ptr()) } != 0;
                // SAFETY: as above, with a local.
                if modified && unsafe { OSSL_PARAM_get_int(params.as_ptr(), &raw mut len) } == 0 {
                    return -1;
                }
            } else if rv != UNSUPPORTED {
                return -1;
            }
        }
        c.iv_len = len;
    }
    c.iv_len
}

/// `EVP_CIPHER_CTX_set_params` on a live context: the provider's result, the key and IV
/// lengths cached from what was set.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn set_params(c: &mut CipherCtx, params: *const OSSL_PARAM) -> c_int {
    let Some(set) = c.cipher().and_then(|m| m.funcs.set_ctx_params) else {
        return 0;
    };
    // SAFETY: the context's algorithm context and the caller's array.
    let mut r = unsafe { set(c.algctx, params) };
    if r > 0 {
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_KEYLEN.as_ptr()) };
        // SAFETY: a parameter of the array, and the context's field.
        if !p.is_null() && unsafe { OSSL_PARAM_get_int(p, &raw mut c.key_len) } == 0 {
            r = 0;
            c.key_len = -1;
        }
    }
    if r > 0 {
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_IVLEN.as_ptr()) };
        // SAFETY: as above.
        if !p.is_null() && unsafe { OSSL_PARAM_get_int(p, &raw mut c.iv_len) } == 0 {
            r = 0;
            c.iv_len = -1;
        }
    }
    r
}

/// `EVP_CIPHER_CTX_set_padding` on a live context.
fn set_padding(c: &mut CipherCtx, pad: c_int) -> c_int {
    if pad != 0 {
        c.flags &= !flag(EVP_CIPH_NO_PADDING);
    } else {
        c.flags |= flag(EVP_CIPH_NO_PADDING);
    }
    if c.cipher().is_some_and(|m| m.prov.0.is_null()) {
        return 1;
    }
    let mut pd: c_uint = pad.cast_unsigned();
    let params = [
        param(
            OSSL_CIPHER_PARAM_PADDING,
            UNSIGNED_INTEGER,
            (&raw mut pd).cast(),
            size_of::<c_uint>(),
        ),
        end(),
    ];
    c_int::from(set_params_of(c, &params) != 0)
}

/// A length the provider takes, from the context's: `(size_t)` of the `int`.
fn provider_len(n: c_int) -> usize {
    to_size(n)
}

/// Clears a context for a new cipher, keeping its direction (`enc`) and flags: as
/// `EVP_CIPHER_CTX_reset`, which also frees what `EVP_CIPHER_CTX_set_cipher_data` set. An
/// application's cipher whose `cleanup` fails leaves the context as it is, as in OpenSSL.
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn clear_for(ctx: *mut EVP_CIPHER_CTX, enc: c_int) {
    // SAFETY: the caller's guarantee.
    let released = unsafe { legacy::release(ctx) };
    // SAFETY: as above (the cipher's `cleanup` may have used the context).
    let Some(c) = (unsafe { context(ctx) }) else {
        return;
    };
    let flags = c.flags;
    if released {
        // SAFETY: memory the application gave the context to free.
        unsafe { mem::release(c.cipher_data) };
        c.cipher_data = ptr::null_mut();
        reset(c);
    }
    c.encrypt = enc;
    c.flags = flags;
}

/// `evp_cipher_init_internal`.
///
/// # Safety
/// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
/// are NULL or hold the cipher's key and IV lengths; `params` is NULL or a parameter array.
unsafe fn init_internal(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    engine: *mut ENGINE,
    (key, iv): (*const u8, *const u8),
    enc: c_int,
    params: *const OSSL_PARAM,
) -> c_int {
    const F: &str = "evp_cipher_init_internal";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    };
    let enc = if enc == -1 {
        c.encrypt
    } else {
        let e = c_int::from(enc != 0);
        c.encrypt = e;
        e
    };
    if cipher.is_null() && c.cipher.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET, F);
        return 0;
    }
    // There are no engines (their API can't make one), so an engine argument can't be valid.
    if !engine.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    }
    if !cipher.is_null() && !c.cipher.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { clear_for(ctx, enc) };
    }
    // SAFETY: as above (an application's `cleanup` may have used the context).
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    if unsafe { legacy::is_application(ctx, cipher) } {
        if c.cipher == c.fetched_cipher.cast_const() {
            c.cipher = ptr::null();
        }
        // SAFETY: the context's own reference.
        unsafe { EVP_CIPHER_free(c.fetched_cipher) };
        c.fetched_cipher = ptr::null_mut();
        // SAFETY: the caller's guarantee.
        return unsafe { legacy::init(ctx, cipher, key, iv, enc) };
    }
    let mut cipher = if cipher.is_null() { c.cipher } else { cipher };
    // SAFETY: the caller's live method, or the context's.
    let Some(requested) = (unsafe { method(cipher) }) else {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    };
    if requested.prov.0.is_null() {
        // A static cipher: fetch the provider's by its short name ("NULL" for the NULL
        // cipher), from the default context with no query.
        let name = if requested.nid == NID_undef {
            c"NULL".as_ptr()
        } else {
            // SAFETY: no preconditions.
            unsafe { OBJ_nid2sn(requested.nid) }
        };
        // SAFETY: the default context, a static name, and an empty query.
        let provciph = unsafe { EVP_CIPHER_fetch(ptr::null_mut(), name, c"".as_ptr()) };
        if provciph.is_null() {
            return 0;
        }
        cipher = provciph;
        // SAFETY: the context's own reference, replaced by the fetched one.
        unsafe { EVP_CIPHER_free(c.fetched_cipher) };
        c.fetched_cipher = provciph;
    }
    if cipher != c.fetched_cipher.cast_const() {
        // SAFETY: a live method; the context takes the reference.
        unsafe { EVP_CIPHER_up_ref(cipher.cast_mut()) };
        // SAFETY: the context's own reference.
        unsafe { EVP_CIPHER_free(c.fetched_cipher) };
        c.fetched_cipher = cipher.cast_mut();
    }
    c.cipher = cipher;
    let Some(m) = c.cipher() else {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    };
    if c.algctx.is_null() {
        let Some(newctx) = m.funcs.newctx else {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        };
        // SAFETY: the provider's function with its context.
        c.algctx = unsafe { newctx(m.provider_ctx()) };
        if c.algctx.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        }
    }
    if c.flags & flag(EVP_CIPH_NO_PADDING) != 0 && set_padding(c, 0) == 0 {
        return 0;
    }
    if !params.is_null() {
        // The lengths first (CVE-2023-5363).
        let mut lens = [end(), end(), end()];
        let mut n = 0;
        for key in [OSSL_CIPHER_PARAM_KEYLEN, OSSL_CIPHER_PARAM_IVLEN] {
            // SAFETY: the caller's array.
            let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
            // SAFETY: a parameter of the array, or NULL.
            if let (Some(p), Some(slot)) = (unsafe { p.as_ref() }, lens.get_mut(n)) {
                *slot = *p;
                n += 1;
            }
        }
        // SAFETY: an ended local array.
        if n > 0 && unsafe { set_params(c, lens.as_ptr()) } == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_LENGTH, F);
            return 0;
        }
    }
    let ivlen = if iv.is_null() {
        0
    } else {
        provider_len(iv_length(c))
    };
    let f = &m.funcs;
    let (init, skey) = if enc != 0 {
        (f.einit, f.einit_skey)
    } else {
        (f.dinit, f.dinit_skey)
    };
    let Some(init) = init else {
        if let (true, Some(skey)) = (key.is_null(), skey) {
            // SAFETY: the provider's function with its context and the caller's IV.
            return unsafe { skey(c.algctx, ptr::null_mut(), iv, ivlen, params) };
        }
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    };
    let keylen = if key.is_null() {
        0
    } else {
        provider_len(key_length(c))
    };
    // SAFETY: the provider's function with its context and the caller's key, IV, and array.
    unsafe { init(c.algctx, key, keylen, iv, ivlen, params) }
}

/// `evp_cipher_init_skey_internal`: as [`init_internal`] without engines, the key an opaque
/// key of the cipher's provider (or none). A cipher that takes key objects gets the key's data
/// (or NULL); one that doesn't gets its raw octets.
///
/// # Safety
/// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `skey` is NULL or
/// a live key; `iv` is NULL or holds `iv_len` octets; `params` is NULL or a parameter array.
unsafe fn init_skey_internal(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    skey: *const rustyssl_abi::EVP_SKEY,
    (iv, iv_len): (*const u8, usize),
    enc: c_int,
    params: *const OSSL_PARAM,
) -> c_int {
    const F: &str = "evp_cipher_init_skey_internal";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    };
    let enc = if enc == -1 {
        c.encrypt
    } else {
        let e = c_int::from(enc != 0);
        c.encrypt = e;
        e
    };
    if cipher.is_null() && c.cipher.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET, F);
        return 0;
    }
    if !cipher.is_null() && !c.cipher.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { clear_for(ctx, enc) };
    }
    // SAFETY: as above (an application's `cleanup` may have used the context).
    let Some(c) = (unsafe { context(ctx) }) else {
        return 0;
    };
    let cipher = if cipher.is_null() { c.cipher } else { cipher };
    // SAFETY: the caller's live method, or the context's.
    let from_provider = unsafe { method(cipher) }.is_some_and(|m| !m.prov.0.is_null());
    if !from_provider {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    }
    if cipher != c.fetched_cipher.cast_const() {
        // SAFETY: a live method; the context takes the reference.
        if unsafe { EVP_CIPHER_up_ref(cipher.cast_mut()) } == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        }
        // SAFETY: the context's own reference.
        unsafe { EVP_CIPHER_free(c.fetched_cipher) };
        c.fetched_cipher = cipher.cast_mut();
    }
    c.cipher = cipher;
    let Some(m) = c.cipher() else {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    };
    if c.algctx.is_null() {
        let Some(newctx) = m.funcs.newctx else {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        };
        // SAFETY: the provider's function with its context.
        c.algctx = unsafe { newctx(m.provider_ctx()) };
        if c.algctx.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        }
    }
    // SAFETY: the caller's guarantee.
    let key = unsafe { super::skey::key(skey) };
    if key.is_some_and(|k| k.skeymgmt.get().prov.0 != m.prov.0) {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    }
    if c.flags & flag(EVP_CIPH_NO_PADDING) != 0 && set_padding(c, 0) == 0 {
        return 0;
    }
    let iv_len = if iv.is_null() { 0 } else { iv_len };
    let f = &m.funcs;
    let (init, init_skey) = if enc != 0 {
        (f.einit, f.einit_skey)
    } else {
        (f.dinit, f.dinit_skey)
    };
    if let Some(init_skey) = init_skey {
        let keydata = key.map_or(ptr::null_mut(), |k| k.keydata.0);
        // SAFETY: the provider's function with its context, the key's data (its own
        // provider's), and the caller's IV and array.
        return unsafe { init_skey(c.algctx, keydata, iv, iv_len, params) };
    }
    // A provider that doesn't take key objects gets the raw key.
    let (mut keydata, mut keylen): (*const u8, usize) = (ptr::null(), 0);
    if key.is_some() {
        // SAFETY: the caller's live key; places for its address and length.
        let got =
            unsafe { super::skey::EVP_SKEY_get0_raw_key(skey, &raw mut keydata, &raw mut keylen) };
        if got == 0 {
            err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
            return 0;
        }
    }
    let Some(init) = init else {
        // OpenSSL calls the missing function and crashes.
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return 0;
    };
    // SAFETY: the provider's function with its context, the key's octets (valid while it
    // lives), and the caller's IV and array.
    unsafe { init(c.algctx, keydata, keylen, iv, iv_len, params) }
}

ffi_export! {
    /// Sets the cipher (keeping the context's for NULL), the opaque key `skey` (which must be
    /// the cipher's provider's; NULL keeps the key, to set the IV alone), and the `iv_len`
    /// octets of IV for the direction `enc` (1 to encrypt, 0 to decrypt, -1 for the
    /// context's), then `params`. Returns 1, or 0 with an error.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `skey` is
    /// NULL or a live key; `iv` is NULL or holds `iv_len` octets; `params` is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_CipherInit_SKEY(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, skey: *mut rustyssl_abi::EVP_SKEY, iv: *const u8, iv_len: usize, enc: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { init_skey_internal(ctx, cipher, skey, (iv, iv_len), enc, params) }
    }
}

ffi_export! {
    /// Sets the cipher (keeping the context's for NULL), key, and IV for the direction `enc`
    /// (1 to encrypt, 0 to decrypt, -1 for the context's), then `params`.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_CipherInit_ex2(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, key: *const u8, iv: *const u8, enc: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { init_internal(ctx, cipher, ptr::null_mut(), (key, iv), enc, params) }
    }
}

ffi_export! {
    /// As [`EVP_CipherInit_ex2`] without parameters; `impl_` (an `ENGINE`) must be NULL.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_CipherInit_ex(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, impl_: *mut ENGINE, key: *const u8, iv: *const u8, enc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { init_internal(ctx, cipher, impl_, (key, iv), enc, ptr::null()) }
    }
}

ffi_export! {
    /// As [`EVP_CipherInit_ex`], resetting the context first when given a cipher.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_CipherInit(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, key: *const u8, iv: *const u8, enc: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if !cipher.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { EVP_CIPHER_CTX_reset(ctx) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { init_internal(ctx, cipher, ptr::null_mut(), (key, iv), enc, ptr::null()) }
    }
}

ffi_export! {
    /// [`EVP_CipherInit_ex2`] to encrypt.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_EncryptInit_ex2(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, key: *const u8, iv: *const u8, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CipherInit_ex2(ctx, cipher, key, iv, 1, params) }
    }
}

ffi_export! {
    /// [`EVP_CipherInit_ex`] to encrypt.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_EncryptInit_ex(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, impl_: *mut ENGINE, key: *const u8, iv: *const u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CipherInit_ex(ctx, cipher, impl_, key, iv, 1) }
    }
}

ffi_export! {
    /// [`EVP_CipherInit`] to encrypt.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_EncryptInit(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, key: *const u8, iv: *const u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CipherInit(ctx, cipher, key, iv, 1) }
    }
}

ffi_export! {
    /// [`EVP_CipherInit_ex2`] to decrypt.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_DecryptInit_ex2(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, key: *const u8, iv: *const u8, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CipherInit_ex2(ctx, cipher, key, iv, 0, params) }
    }
}

ffi_export! {
    /// [`EVP_CipherInit_ex`] to decrypt.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_DecryptInit_ex(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, impl_: *mut ENGINE, key: *const u8, iv: *const u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CipherInit_ex(ctx, cipher, impl_, key, iv, 0) }
    }
}

ffi_export! {
    /// [`EVP_CipherInit`] to decrypt.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `cipher` is NULL or a live cipher method; `key` and `iv`
    /// are NULL or hold the cipher's key and IV lengths; `params` (where taken) is NULL or a
    /// parameter array.
    pub unsafe extern "C" fn EVP_DecryptInit(ctx: *mut EVP_CIPHER_CTX, cipher: *const EVP_CIPHER, key: *const u8, iv: *const u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CipherInit(ctx, cipher, key, iv, 0) }
    }
}

/// `EVP_EncryptUpdate` and `EVP_DecryptUpdate` (`encrypting` says which).
///
/// # Safety
/// `ctx` is NULL or a live cipher context; `out` has room for `inl` plus a block; `outl` is
/// NULL or valid for a write; `in_` holds `inl` octets.
unsafe fn update(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    outl: *mut c_int,
    in_: *const u8,
    inl: c_int,
    encrypting: bool,
) -> c_int {
    let f = if encrypting {
        "EVP_EncryptUpdate"
    } else {
        "EVP_DecryptUpdate"
    };
    let Ok(n) = usize::try_from(inl) else {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_LENGTH, f);
        return 0;
    };
    if outl.is_null() {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, f);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { outl.write(0) };
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, f);
        return 0;
    };
    if (c.encrypt != 0) != encrypting {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION, f);
        return 0;
    }
    let Some(m) = c.cipher() else {
        err::raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET, f);
        return 0;
    };
    if m.prov.0.is_null() {
        // SAFETY: the caller's guarantee (an application's cipher).
        return unsafe { legacy::update(ctx, out, outl, in_, inl, encrypting) };
    }
    let bs = m.block_size();
    let (Some(cupdate), Ok(b)) = (m.funcs.cupdate, usize::try_from(bs)) else {
        err::raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR, f);
        return 0;
    };
    if bs < 1 || m.prov.0.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR, f);
        return 0;
    }
    let room = n.saturating_add(if b == 1 { 0 } else { b });
    let mut soutl: usize = 0;
    // SAFETY: the provider's function with its context and the caller's buffers.
    let ret = unsafe { cupdate(c.algctx, out, &raw mut soutl, room, in_, n) };
    if ret != 0 {
        let Ok(o) = c_int::try_from(soutl) else {
            err::raise(ERR_LIB_EVP, EVP_R_UPDATE_ERROR, f);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(o) };
    }
    ret
}

/// `EVP_EncryptFinal_ex` and `EVP_DecryptFinal_ex`.
///
/// # Safety
/// `ctx` is NULL or a live cipher context; `out` has room for a block; `outl` is NULL or
/// valid for a write.
unsafe fn finalize(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    outl: *mut c_int,
    encrypting: bool,
) -> c_int {
    let f = if encrypting {
        "EVP_EncryptFinal_ex"
    } else {
        "EVP_DecryptFinal_ex"
    };
    if outl.is_null() {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, f);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { outl.write(0) };
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { context(ctx) }) else {
        err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, f);
        return 0;
    };
    if (c.encrypt != 0) != encrypting {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION, f);
        return 0;
    }
    let Some(m) = c.cipher() else {
        err::raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET, f);
        return 0;
    };
    if m.prov.0.is_null() {
        // SAFETY: the caller's guarantee (an application's cipher).
        return unsafe { legacy::finalize(ctx, out, outl, encrypting) };
    }
    let (Some(cfinal), Ok(b)) = (m.funcs.cfinal, usize::try_from(m.block_size())) else {
        err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, f);
        return 0;
    };
    if b < 1 || m.prov.0.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, f);
        return 0;
    }
    let mut soutl: usize = 0;
    let room = if b == 1 { 0 } else { b };
    // SAFETY: the provider's function with its context and the caller's buffer.
    let ret = unsafe { cfinal(c.algctx, out, &raw mut soutl, room) };
    if ret != 0 {
        let Ok(o) = c_int::try_from(soutl) else {
            err::raise(ERR_LIB_EVP, EVP_R_FINAL_ERROR, f);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(o) };
    }
    ret
}

/// The direction of a live context, or `None` for NULL.
///
/// # Safety
/// `ctx` is NULL or a live cipher context.
unsafe fn encrypting(ctx: *mut EVP_CIPHER_CTX) -> Option<bool> {
    // SAFETY: the caller's guarantee.
    unsafe { context(ctx) }.map(|c| c.encrypt != 0)
}

ffi_export! {
    /// Encrypts `inl` octets, writing what's complete through `out` and its length through
    /// `outl`.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for `inl` octets plus a block (less
    /// one); `outl` is valid for a write; `in_` holds `inl` octets.
    pub unsafe extern "C" fn EVP_EncryptUpdate(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, in_: *const u8, inl: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let enc = true;
        // SAFETY: the caller's guarantee.
        unsafe { update(ctx, out, outl, in_, inl, enc) }
    }
}
ffi_export! {
    /// Decrypts `inl` octets likewise (holding back a last block while padding is on).
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for `inl` octets plus a block (less
    /// one); `outl` is valid for a write; `in_` holds `inl` octets.
    pub unsafe extern "C" fn EVP_DecryptUpdate(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, in_: *const u8, inl: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let enc = false;
        // SAFETY: the caller's guarantee.
        unsafe { update(ctx, out, outl, in_, inl, enc) }
    }
}
ffi_export! {
    /// [`EVP_EncryptUpdate`] or [`EVP_DecryptUpdate`] by the context's direction.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for `inl` octets plus a block (less
    /// one); `outl` is valid for a write; `in_` holds `inl` octets.
    pub unsafe extern "C" fn EVP_CipherUpdate(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, in_: *const u8, inl: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(enc) = (unsafe { encrypting(ctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { update(ctx, out, outl, in_, inl, enc) }
    }
}

ffi_export! {
    /// Finishes encrypting: the padded last block, or what's left.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for a block; `outl` is valid for a
    /// write.
    pub unsafe extern "C" fn EVP_EncryptFinal_ex(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let enc = true;
        // SAFETY: the caller's guarantee.
        unsafe { finalize(ctx, out, outl, enc) }
    }
}
ffi_export! {
    /// As [`EVP_EncryptFinal_ex`].
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for a block; `outl` is valid for a
    /// write.
    pub unsafe extern "C" fn EVP_EncryptFinal(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let enc = true;
        // SAFETY: the caller's guarantee.
        unsafe { finalize(ctx, out, outl, enc) }
    }
}
ffi_export! {
    /// Finishes decrypting: the last block without its padding, checked.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for a block; `outl` is valid for a
    /// write.
    pub unsafe extern "C" fn EVP_DecryptFinal_ex(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let enc = false;
        // SAFETY: the caller's guarantee.
        unsafe { finalize(ctx, out, outl, enc) }
    }
}
ffi_export! {
    /// As [`EVP_DecryptFinal_ex`].
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for a block; `outl` is valid for a
    /// write.
    pub unsafe extern "C" fn EVP_DecryptFinal(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let enc = false;
        // SAFETY: the caller's guarantee.
        unsafe { finalize(ctx, out, outl, enc) }
    }
}
ffi_export! {
    /// [`EVP_EncryptFinal_ex`] or [`EVP_DecryptFinal_ex`] by the context's direction.
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for a block; `outl` is valid for a
    /// write.
    pub unsafe extern "C" fn EVP_CipherFinal_ex(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(enc) = (unsafe { encrypting(ctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { finalize(ctx, out, outl, enc) }
    }
}
ffi_export! {
    /// As [`EVP_CipherFinal_ex`].
    ///
    /// # Safety
    /// `ctx` is a live cipher context; `out` has room for a block; `outl` is valid for a
    /// write.
    pub unsafe extern "C" fn EVP_CipherFinal(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(enc) = (unsafe { encrypting(ctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { finalize(ctx, out, outl, enc) }
    }
}

ffi_export! {
    /// The provider's `cipher`, without buffering or padding: the length written, or -1. A
    /// cipher without one updates (or, for NULL input, finalizes) and returns that's result.
    /// 0 without a context or cipher.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `out` has room for `inl` octets plus a block;
    /// `in_` is NULL or holds `inl` octets.
    pub unsafe extern "C" fn EVP_Cipher(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, in_: *const u8, inl: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(m) = c.cipher() else { return 0 };
        if m.prov.0.is_null() {
            let Ok(n) = usize::try_from(inl) else { return 0 };
            // SAFETY: the caller's guarantee (an application's cipher).
            return unsafe { legacy::cipher(ctx, out, in_, n) };
        }
        let Ok(bs) = usize::try_from(m.block_size()) else { return 0 };
        if bs == 0 {
            return 0;
        }
        let Ok(n) = usize::try_from(inl) else { return 0 };
        let extra = if bs == 1 { 0 } else { bs };
        let mut outl: usize = 0;
        if let Some(ccipher) = m.funcs.ccipher {
            // SAFETY: the provider's function with its context and the caller's buffers.
            let ok = unsafe { ccipher(c.algctx, out, &raw mut outl, n.saturating_add(extra), in_, n) };
            return if ok != 0 { to_int(outl) } else { -1 };
        }
        if !in_.is_null() {
            let Some(cupdate) = m.funcs.cupdate else { return -1 };
            // SAFETY: as above.
            return unsafe { cupdate(c.algctx, out, &raw mut outl, n.saturating_add(extra), in_, n) };
        }
        let Some(cfinal) = m.funcs.cfinal else { return -1 };
        // SAFETY: as above.
        unsafe { cfinal(c.algctx, out, &raw mut outl, extra) }
    }
}

ffi_export! {
    /// Sets the key length, where the cipher takes one (`keylen` among its settable
    /// parameters; `EVP_R_INVALID_KEY_LENGTH` if not). 1 if it's already that.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_set_key_length(ctx: *mut EVP_CIPHER_CTX, keylen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(m) = c.cipher() else { return 0 };
        if m.prov.0.is_null() {
            // SAFETY: the caller's guarantee (an application's cipher).
            return unsafe { legacy::set_key_length(ctx, keylen) };
        }
        if key_length(c) == keylen {
            return 1;
        }
        let settable = match m.funcs.settable_ctx_params {
            // SAFETY: the provider's function with no context and its own.
            Some(list) => unsafe { list(ptr::null_mut(), m.provider_ctx()) },
            None => ptr::null(),
        };
        // SAFETY: the provider's list, or NULL.
        if unsafe { OSSL_PARAM_locate_const(settable, OSSL_CIPHER_PARAM_KEYLEN.as_ptr()) }.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH, "EVP_CIPHER_CTX_set_key_length");
            return 0;
        }
        let mut len: usize = 0;
        let mut params = [
            param(OSSL_CIPHER_PARAM_KEYLEN, UNSIGNED_INTEGER, (&raw mut len).cast(), size_of::<usize>()),
            end(),
        ];
        // SAFETY: the local array's first parameter.
        if unsafe { OSSL_PARAM_set_int(params.as_mut_ptr(), keylen) } == 0 {
            return 0;
        }
        if set_params_of(c, &params) <= 0 {
            return 0;
        }
        c.key_len = keylen;
        1
    }
}

ffi_export! {
    /// Turns padding on (`pad` nonzero) or off: the `EVP_CIPH_NO_PADDING` flag, then the
    /// provider's `padding`. Returns whether that was set (1 for a static cipher).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_set_padding(ctx: *mut EVP_CIPHER_CTX, pad: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(0, |c| set_padding(c, pad))
    }
}

/// An octet-string parameter over the caller's `ptr`, `sz` octets.
fn octets(key: &'static CStr, ptr: *mut c_void, sz: usize) -> OSSL_PARAM {
    param(key, OCTET_STRING, ptr, sz)
}

/// A `size_t` parameter at `v`.
fn size_param(key: &'static CStr, v: &mut usize) -> OSSL_PARAM {
    param(
        key,
        UNSIGNED_INTEGER,
        (&raw mut *v).cast(),
        size_of::<usize>(),
    )
}

/// An `unsigned int` parameter at `v`.
fn uint_param(key: &'static CStr, v: *mut c_uint) -> OSSL_PARAM {
    param(key, UNSIGNED_INTEGER, v.cast(), size_of::<c_uint>())
}

ffi_export! {
    /// The legacy control interface: each command as the provider parameter it stands for (set,
    /// or got for the `GET` commands), its result, or 0 with
    /// `EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED` where nothing handles it.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `ptr` is what the command takes (for the octet
    /// commands, `arg` octets).
    pub unsafe extern "C" fn EVP_CIPHER_CTX_ctrl(ctx: *mut EVP_CIPHER_CTX, type_: c_int, arg: c_int, ptr: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_CIPHER_CTX_ctrl";
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else {
            err::raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET, F);
            return 0;
        };
        let Some(m) = c.cipher() else {
            err::raise(ERR_LIB_EVP, EVP_R_NO_CIPHER_SET, F);
            return 0;
        };
        if m.prov.0.is_null() {
            // SAFETY: the caller's guarantee (an application's cipher).
            return unsafe { legacy::ctrl(ctx, type_, arg, ptr) };
        }
        let mut sz: usize = to_size(arg);
        let mut i: c_uint = arg.cast_unsigned();
        let mut set = true;
        let mut params = [end(), end(), end(), end()];
        let ret = 'end: {
            let p0 = match type_ {
                EVP_CTRL_SET_KEY_LENGTH => {
                    if arg < 0 {
                        return 0;
                    }
                    if c.key_len == arg {
                        return 1;
                    }
                    c.key_len = -1;
                    size_param(OSSL_CIPHER_PARAM_KEYLEN, &mut sz)
                }
                EVP_CTRL_RAND_KEY => {
                    set = false;
                    octets(OSSL_CIPHER_PARAM_RANDOM_KEY, ptr, sz)
                }
                EVP_CTRL_INIT => return 1,
                EVP_CTRL_AEAD_SET_IVLEN => {
                    if arg < 0 {
                        return 0;
                    }
                    if c.iv_len == arg {
                        return 1;
                    }
                    c.iv_len = -1;
                    size_param(OSSL_CIPHER_PARAM_IVLEN, &mut sz)
                }
                EVP_CTRL_CCM_SET_L => {
                    if !(2..=8).contains(&arg) {
                        return 0;
                    }
                    sz = to_size(15 - arg);
                    c.iv_len = -1;
                    size_param(OSSL_CIPHER_PARAM_IVLEN, &mut sz)
                }
                EVP_CTRL_AEAD_SET_IV_FIXED => octets(OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, ptr, sz),
                EVP_CTRL_GCM_IV_GEN => {
                    set = false;
                    if arg < 0 {
                        // The IV's length.
                        sz = 0;
                    }
                    octets(OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN, ptr, sz)
                }
                EVP_CTRL_GCM_SET_IV_INV => {
                    if arg < 0 {
                        return 0;
                    }
                    octets(OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV, ptr, sz)
                }
                EVP_CTRL_GET_RC5_ROUNDS | EVP_CTRL_SET_RC5_ROUNDS => {
                    set = type_ == EVP_CTRL_SET_RC5_ROUNDS;
                    if arg < 0 {
                        return 0;
                    }
                    uint_param(OSSL_CIPHER_PARAM_ROUNDS, &raw mut i)
                }
                EVP_CTRL_SET_SPEED => {
                    if arg < 0 {
                        return 0;
                    }
                    uint_param(OSSL_CIPHER_PARAM_SPEED, &raw mut i)
                }
                EVP_CTRL_AEAD_GET_TAG | EVP_CTRL_AEAD_SET_TAG => {
                    set = type_ == EVP_CTRL_AEAD_SET_TAG;
                    octets(OSSL_CIPHER_PARAM_AEAD_TAG, ptr, sz)
                }
                EVP_CTRL_AEAD_TLS1_AAD => {
                    // A set and then a get, since it returns a length.
                    params[0] = octets(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, ptr, sz);
                    let r = set_params_of(c, &params);
                    if r <= 0 {
                        break 'end r;
                    }
                    params[0] = size_param(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, &mut sz);
                    let r = get_params_of(c, &mut params);
                    if r <= 0 {
                        break 'end r;
                    }
                    return to_int(sz);
                }
                EVP_CTRL_GET_RC2_KEY_BITS | EVP_CTRL_SET_RC2_KEY_BITS => {
                    set = type_ == EVP_CTRL_SET_RC2_KEY_BITS;
                    size_param(OSSL_CIPHER_PARAM_RC2_KEYBITS, &mut sz)
                }
                EVP_CTRL_TLS1_1_MULTIBLOCK_MAX_BUFSIZE => {
                    params[0] = size_param(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, &mut sz);
                    if set_params_of(c, &params) <= 0 {
                        return 0;
                    }
                    params[0] = size_param(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE, &mut sz);
                    if get_params_of(c, &mut params) <= 0 {
                        return 0;
                    }
                    return to_int(sz);
                }
                EVP_CTRL_TLS1_1_MULTIBLOCK_AAD | EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT => {
                    let aad = type_ == EVP_CTRL_TLS1_1_MULTIBLOCK_AAD;
                    if aad && to_size(arg) < size_of::<EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM>() {
                        return 0;
                    }
                    let p = ptr.cast::<EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM>();
                    // SAFETY: the caller's guarantee: the command's parameter block, or NULL
                    // (where OpenSSL would crash).
                    let Some(mb) = (unsafe { p.as_mut() }) else { return 0 };
                    let interleave = &raw mut mb.interleave;
                    if aad {
                        params[0] = octets(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD, mb.inp.cast_mut().cast(), mb.len);
                        params[1] = uint_param(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, interleave);
                    } else {
                        params[0] = octets(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC, mb.out.cast(), mb.len);
                        params[1] = octets(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN, mb.inp.cast_mut().cast(), mb.len);
                        params[2] = uint_param(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, interleave);
                    }
                    let r = set_params_of(c, &params);
                    if r <= 0 {
                        return r;
                    }
                    params = [end(), end(), end(), end()];
                    if aad {
                        params[0] = size_param(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN, &mut sz);
                        params[1] = uint_param(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, interleave);
                    } else {
                        params[0] = size_param(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN, &mut sz);
                    }
                    if get_params_of(c, &mut params) <= 0 {
                        return 0;
                    }
                    return to_int(sz);
                }
                EVP_CTRL_AEAD_SET_MAC_KEY => {
                    if arg < 0 {
                        return -1;
                    }
                    octets(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, ptr, sz)
                }
                _ => break 'end UNSUPPORTED,
            };
            params[0] = p0;
            if set {
                set_params_of(c, &params)
            } else {
                get_params_of(c, &mut params)
            }
        };
        if ret == UNSUPPORTED {
            err::raise(ERR_LIB_EVP, EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED, F);
            return 0;
        }
        ret
    }
}

ffi_export! {
    /// Sets the algorithm context's parameters: the provider's result (0 without a cipher or
    /// function), caching the key and IV lengths set.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `params` is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_set_params(ctx: *mut EVP_CIPHER_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { set_params(c, params) }
    }
}

ffi_export! {
    /// Asks the algorithm context for `params`: the provider's result (0 without a cipher or
    /// function).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `params` is an array the provider may fill.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_params(ctx: *mut EVP_CIPHER_CTX, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(get) = c.cipher().and_then(|m| m.funcs.get_ctx_params) else { return 0 };
        // SAFETY: the provider's function with its context and the caller's array.
        unsafe { get(c.algctx, params) }
    }
}

ffi_export! {
    /// The parameters the algorithm context can set, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_settable_params(ctx: *mut EVP_CIPHER_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let Some(m) = c.cipher() else { return ptr::null() };
        let Some(list) = m.funcs.settable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function with its contexts.
        unsafe { list(c.algctx, m.provider_ctx()) }
    }
}

ffi_export! {
    /// The parameters the algorithm context can report, or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_gettable_params(ctx: *mut EVP_CIPHER_CTX) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        let Some(m) = c.cipher() else { return ptr::null() };
        let Some(list) = m.funcs.gettable_ctx_params else { return ptr::null() };
        // SAFETY: the provider's function with its contexts.
        unsafe { list(c.algctx, m.provider_ctx()) }
    }
}

ffi_export! {
    /// A random key for the cipher into `key` (the key length's worth): the cipher's own
    /// (triple DES sets the parity), or else random octets.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context; `key` has room for the key length.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_rand_key(ctx: *mut EVP_CIPHER_CTX, key: *mut u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let Some(m) = c.cipher() else { return 0 };
        if m.flags() & flag(EVP_CIPH_RAND_KEY) != 0 {
            // SAFETY: the caller's guarantee.
            return unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_RAND_KEY, 0, key.cast()) };
        }
        let Ok(kl) = usize::try_from(key_length(c)) else { return 0 };
        if kl == 0 || key.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let k = unsafe { core::slice::from_raw_parts_mut(key, kl) };
        // `RAND_priv_bytes_ex` of the cipher's provider's context, as the reference's.
        let libctx = m.prov.0.is_null().then(ptr::null_mut).unwrap_or_else(|| {
            // SAFETY: the method holds a reference to its live provider.
            unsafe { crate::provider::libctx_of(m.prov.0) }
        });
        c_int::from(crate::rand_lib::random_source(libctx, true)(k))
    }
}

/// `EVP_CIPHER_CTX_copy` on two contexts.
///
/// # Safety
/// `out` and `in_` are NULL or live cipher contexts.
unsafe fn copy(out: *mut EVP_CIPHER_CTX, in_: *const EVP_CIPHER_CTX) -> c_int {
    const F: &str = "EVP_CIPHER_CTX_copy";
    // SAFETY: the caller's guarantee.
    let Some(i) = (unsafe { context(in_) }) else {
        err::raise(ERR_LIB_EVP, EVP_R_INPUT_NOT_INITIALIZED, F);
        return 0;
    };
    let Some(m) = i.cipher() else {
        err::raise(ERR_LIB_EVP, EVP_R_INPUT_NOT_INITIALIZED, F);
        return 0;
    };
    if m.prov.0.is_null() {
        if out.cast_const() == in_ {
            // The reference resets the context and then copies its freed state.
            err::raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX, F);
            return 0;
        }
        // SAFETY: the caller's guarantee (an application's cipher), two contexts.
        return unsafe { legacy::copy(out, in_) };
    }
    let (Some(dup), false) = (m.funcs.dupctx, m.prov.0.is_null()) else {
        err::raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX, F);
        return 0;
    };
    if out.cast_const() == in_ {
        // The reference resets the context and then copies its freed state.
        err::raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let Some(o) = (unsafe { context(out) }) else {
        return 0;
    };
    reset(o);
    *o = CipherCtx {
        algctx: ptr::null_mut(),
        ..*i
    };
    if !i.fetched_cipher.is_null() {
        // SAFETY: the reference the copy takes.
        unsafe { EVP_CIPHER_up_ref(i.fetched_cipher) };
    }
    // SAFETY: the provider's function with the source's algorithm context.
    o.algctx = unsafe { dup(i.algctx) };
    if o.algctx.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_NOT_ABLE_TO_COPY_CTX, F);
        return 0;
    }
    1
}

ffi_export! {
    /// Makes `out` a copy of `in_`: the cipher (another reference), the cached state, and a
    /// copy of the algorithm context.
    ///
    /// # Safety
    /// `out` and `in_` are NULL or live cipher contexts.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_copy(out: *mut EVP_CIPHER_CTX, in_: *const EVP_CIPHER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { copy(out, in_) }
    }
}

ffi_export! {
    /// A new copy of `in_`, or NULL.
    ///
    /// # Safety
    /// `in_` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_dup(in_: *const EVP_CIPHER_CTX) -> *mut EVP_CIPHER_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: no preconditions.
        let out = unsafe { EVP_CIPHER_CTX_new() };
        // SAFETY: a new context and the caller's.
        if !out.is_null() && unsafe { copy(out, in_) } == 0 {
            // SAFETY: the new context.
            unsafe { EVP_CIPHER_CTX_free(out) };
            return ptr::null_mut();
        }
        out
    }
}

ffi_export! {
    /// The cipher in use (NULL for none).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_cipher(ctx: *const EVP_CIPHER_CTX) -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null(), |c| c.cipher)
    }
}

ffi_export! {
    /// The cipher in use (NULL for none).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get0_cipher(ctx: *const EVP_CIPHER_CTX) -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(ctx) }.map_or(ptr::null(), |c| c.cipher)
    }
}

ffi_export! {
    /// The cipher in use with a reference for the caller (NULL for none).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get1_cipher(ctx: *mut EVP_CIPHER_CTX) -> *mut EVP_CIPHER
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null_mut() };
        if c.cipher.is_null() {
            return ptr::null_mut();
        }
        let cipher = c.cipher.cast_mut();
        // SAFETY: the context's live method.
        unsafe { EVP_CIPHER_up_ref(cipher) };
        cipher
    }
}

ffi_export! {
    /// 1 if the context encrypts, 0 if it decrypts (0 for NULL).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_is_encrypting(ctx: *const EVP_CIPHER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.encrypt
    }
}
ffi_export! {
    /// The application's data.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_app_data(ctx: *const EVP_CIPHER_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null_mut() };
        c.app_data
    }
}
ffi_export! {
    /// Sets the application's data.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_set_app_data(ctx: *mut EVP_CIPHER_CTX, data: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if let Some(c) = unsafe { context(ctx) } {
            c.app_data = data;
        }
    }
}
ffi_export! {
    /// The legacy cipher data (NULL for provided ciphers unless set).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_cipher_data(ctx: *const EVP_CIPHER_CTX) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null_mut() };
        c.cipher_data
    }
}
ffi_export! {
    /// Sets the legacy cipher data, returning what it was.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_set_cipher_data(ctx: *mut EVP_CIPHER_CTX, data: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null_mut() };
        {
        core::mem::replace(&mut c.cipher_data, data)
    }
    }
}
ffi_export! {
    /// The key length: the cached one, or the provider's (-1 if it won't say); 0 without a
    /// cipher.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_key_length(ctx: *const EVP_CIPHER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        key_length(c)
    }
}
ffi_export! {
    /// The IV length: the cached one, or the provider's, or the cipher's; 0 without a cipher.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_iv_length(ctx: *const EVP_CIPHER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        if c.cipher().is_some_and(|m| m.prov.0.is_null()) {
            // SAFETY: the caller's guarantee (an application's cipher, whose `ctrl` may give
            // the length).
            return unsafe { legacy::iv_length(ctx.cast_mut()) };
        }
        iv_length(c)
    }
}
ffi_export! {
    /// The AEAD tag length the provider reports, else 0.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_tag_length(ctx: *const EVP_CIPHER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        {
        let mut v: usize = 0;
        let mut params = [size_param(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &mut v), end()];
        if get_params_of(c, &mut params) == 1 { to_int(v) } else { 0 }
    }
    }
}
ffi_export! {
    /// The cipher's NID (`NID_undef` for none).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_nid(ctx: *const EVP_CIPHER_CTX) -> c_int
    where failure = NID_undef, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return NID_undef };
        c.cipher().map_or(NID_undef, |m| m.nid)
    }
}
ffi_export! {
    /// The cipher's block size (0 for none).
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_block_size(ctx: *const EVP_CIPHER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        c.cipher().map_or(0, |m| m.block_size())
    }
}
ffi_export! {
    /// The flags among `flags` the context has.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_test_flags(ctx: *const EVP_CIPHER_CTX, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        narrow(c.flags & widen(flags))
    }
}
ffi_export! {
    /// The partial-block position the provider reports (`num`), or -1.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_num(ctx: *const EVP_CIPHER_CTX) -> c_int
    where failure = UNSUPPORTED, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return UNSUPPORTED };
        {
        let mut v: c_uint = c.num.cast_unsigned();
        let mut params = [uint_param(OSSL_CIPHER_PARAM_NUM, &raw mut v), end()];
        if get_params_of(c, &mut params) != 0 { v.cast_signed() } else { UNSUPPORTED }
    }
    }
}

ffi_export! {
    /// Sets the partial-block position (`num`); whether the provider took it.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_set_num(ctx: *mut EVP_CIPHER_CTX, num: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        let mut n: c_uint = num.cast_unsigned();
        let params = [uint_param(OSSL_CIPHER_PARAM_NUM, &raw mut n), end()];
        let ok = set_params_of(c, &params);
        if ok != 0 {
            c.num = n.cast_signed();
        }
        c_int::from(ok != 0)
    }
}

/// `use-bits` on or off, as the flag `EVP_CIPH_FLAG_LENGTH_BITS` changes.
fn enable_use_bits(c: &mut CipherCtx, on: c_uint) {
    let mut v = on;
    let params = [uint_param(OSSL_CIPHER_PARAM_USE_BITS, &raw mut v), end()];
    // SAFETY: an ended local array.
    unsafe { set_params(c, params.as_ptr()) };
}

ffi_export! {
    /// Sets `flags`; turning `EVP_CIPH_FLAG_LENGTH_BITS` on sets the provider's `use-bits`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_set_flags(ctx: *mut EVP_CIPHER_CTX, flags: c_int)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return };
        let old = c.flags;
        c.flags |= widen(flags);
        if (old ^ c.flags) & flag(EVP_CIPH_FLAG_LENGTH_BITS) != 0 {
            enable_use_bits(c, 1);
        }
    }
}

ffi_export! {
    /// Clears `flags`; turning `EVP_CIPH_FLAG_LENGTH_BITS` off clears `use-bits`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_clear_flags(ctx: *mut EVP_CIPHER_CTX, flags: c_int)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return };
        let old = c.flags;
        c.flags &= !widen(flags);
        if (old ^ c.flags) & flag(EVP_CIPH_FLAG_LENGTH_BITS) != 0 {
            enable_use_bits(c, 0);
        }
    }
}

/// The IV the provider points to for `key` (`iv` or `updated-iv`), else `fallback`, the
/// context's own buffer; NULL if the provider fails.
fn iv_pointer(c: &CipherCtx, key: &'static CStr, fallback: *mut u8) -> *mut u8 {
    let mut v: *mut c_void = fallback.cast();
    let mut params = [param(key, OCTET_PTR, (&raw mut v).cast(), MAX_IV), end()];
    if get_params_of(c, &mut params) != 0 {
        v.cast()
    } else {
        ptr::null_mut()
    }
}

ffi_export! {
    /// The IV as set, in the provider's context (`iv`), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_original_iv(ctx: *const EVP_CIPHER_CTX) -> *const u8
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        {
        let own = c.oiv.as_mut_ptr();
        iv_pointer(c, OSSL_CIPHER_PARAM_IV, own).cast_const()
    }
    }
}
ffi_export! {
    /// The running IV, in the provider's context (`updated-iv`), or NULL.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_iv(ctx: *const EVP_CIPHER_CTX) -> *const u8
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null() };
        {
        let own = c.iv.as_mut_ptr();
        iv_pointer(c, OSSL_CIPHER_PARAM_UPDATED_IV, own).cast_const()
    }
    }
}
ffi_export! {
    /// As [`EVP_CIPHER_CTX_iv`], writable.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_iv_noconst(ctx: *mut EVP_CIPHER_CTX) -> *mut u8
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null_mut() };
        {
        let own = c.iv.as_mut_ptr();
        iv_pointer(c, OSSL_CIPHER_PARAM_UPDATED_IV, own)
    }
    }
}
ffi_export! {
    /// The legacy partial-block buffer.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_buf_noconst(ctx: *mut EVP_CIPHER_CTX) -> *mut u8
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return ptr::null_mut() };
        c.buf.as_mut_ptr()
    }
}

/// Copies the provider's IV for `key` into `buf` (`len` octets of room).
fn iv_copy(c: &CipherCtx, key: &'static CStr, buf: *mut c_void, len: usize) -> c_int {
    let mut params = [octets(key, buf, len), end()];
    c_int::from(get_params_of(c, &mut params) > 0)
}

ffi_export! {
    /// Copies the running IV into `buf` (room for `len`); whether the provider did.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_updated_iv(ctx: *mut EVP_CIPHER_CTX, buf: *mut c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        {
        iv_copy(c, OSSL_CIPHER_PARAM_UPDATED_IV, buf, len)
    }
    }
}
ffi_export! {
    /// Copies the IV as set into `buf` likewise.
    ///
    /// # Safety
    /// `ctx` is NULL or a live cipher context.
    pub unsafe extern "C" fn EVP_CIPHER_CTX_get_original_iv(ctx: *mut EVP_CIPHER_CTX, buf: *mut c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { context(ctx) }) else { return 0 };
        {
        iv_copy(c, OSSL_CIPHER_PARAM_IV, buf, len)
    }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: what OpenSSL dereferences without checking is refused.
    #[test]
    fn null_contexts_are_refused() {
        let mut outl = 7;
        let null = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        let r = unsafe { EVP_CipherUpdate(null, null.cast(), &raw mut outl, ptr::null(), 0) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_EncryptUpdate(null, null.cast(), &raw mut outl, ptr::null(), 0) };
        assert_eq!(r, 0);
        assert_eq!(outl, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_CIPHER_CTX_set_key_length(null, 16) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_CIPHER_CTX_is_encrypting(ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_CIPHER_CTX_get_key_length(ptr::null()) }, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_CIPHER_CTX_ctrl(ptr::null_mut(), EVP_CTRL_INIT, 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: a new context, then NULL as a cipher.
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        // SAFETY: a live context.
        assert_eq!(unsafe { EVP_CIPHER_CTX_set_key_length(ctx, 16) }, 0);
        // SAFETY: a live context without a cipher.
        assert!(unsafe { EVP_CIPHER_CTX_gettable_params(ctx) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_CIPHER_CTX_settable_params(ctx) }.is_null());
        // SAFETY: the test's context.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: GCM keyed again after use without a new IV goes on as OpenSSL's
    /// generic and ARMv8 code does (the counter and hash from zero); the vector is the macOS
    /// reference's.
    #[test]
    #[cfg_attr(miri, ignore = "fetches the cipher, which loads the configuration")]
    fn gcm_keyed_again_without_an_iv() {
        let octet = |i: usize| u8::try_from(i % 256).unwrap_or(0);
        let key: [u8; 16] = core::array::from_fn(octet);
        let iv: [u8; 12] = core::array::from_fn(|i| 0xa0 + octet(i));
        let input: [u8; 64] = core::array::from_fn(|i| octet(i * 3));
        let mut out = [0u8; 64];
        let mut tag = [0u8; 16];
        let mut l = 0;
        // SAFETY: no preconditions.
        let c = unsafe { EVP_CIPHER_CTX_new() };
        // SAFETY: a static cipher.
        let gcm = unsafe { crate::evp::legacy_cipher::EVP_aes_128_gcm() };
        // SAFETY: the context; the buffers above, of the lengths given, here and below.
        let r = unsafe { EVP_DecryptInit_ex(c, gcm, ptr::null_mut(), key.as_ptr(), iv.as_ptr()) };
        assert_eq!(r, 1);
        // SAFETY: as above.
        let r = unsafe { EVP_DecryptUpdate(c, out.as_mut_ptr(), &raw mut l, input.as_ptr(), 20) };
        assert_eq!(r, 1);
        // SAFETY: as above.
        let r = unsafe {
            EVP_EncryptInit_ex(c, ptr::null(), ptr::null_mut(), key.as_ptr(), ptr::null())
        };
        assert_eq!(r, 1);
        // SAFETY: as above.
        let r = unsafe { EVP_EncryptUpdate(c, ptr::null_mut(), &raw mut l, input.as_ptr(), 5) };
        assert_eq!(r, 1);
        // SAFETY: as above.
        let r = unsafe { EVP_EncryptUpdate(c, out.as_mut_ptr(), &raw mut l, input.as_ptr(), 40) };
        assert_eq!(r, 1);
        assert_eq!(
            out[..40],
            [
                0xc6, 0xa2, 0x3d, 0x3e, 0x8b, 0x80, 0x49, 0x97, 0x77, 0x54, 0x9f, 0x43, 0x85, 0xef,
                0xf2, 0x54, 0x43, 0x75, 0x25, 0xac, 0xa9, 0xff, 0xf6, 0x5b, 0x01, 0x30, 0xf3, 0xb2,
                0x31, 0xa3, 0x77, 0x57, 0x29, 0xb5, 0xe1, 0x3a, 0xf5, 0xf4, 0xd4, 0xf9,
            ]
        );
        // SAFETY: as above.
        let r = unsafe { EVP_EncryptFinal_ex(c, out.as_mut_ptr(), &raw mut l) };
        assert_eq!(r, 1);
        // SAFETY: as above; room for the tag.
        let r = unsafe {
            EVP_CIPHER_CTX_ctrl(
                c,
                EVP_CTRL_AEAD_GET_TAG as c_int,
                16,
                tag.as_mut_ptr().cast(),
            )
        };
        assert_eq!(r, 1);
        assert_eq!(
            tag,
            [
                0x1c, 0x4a, 0x6f, 0x89, 0x3c, 0xe4, 0x4c, 0x60, 0xec, 0x70, 0xa9, 0x5d, 0xf6, 0x4a,
                0x95, 0x97,
            ]
        );
        // SAFETY: the test's context.
        unsafe { EVP_CIPHER_CTX_free(c) };
    }
}
