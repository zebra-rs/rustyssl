//! The default provider's ciphers (`deflt_ciphers` in `providers/defltprov.c`): the algorithm
//! table `query_operation` offers for `OSSL_OP_CIPHER`, and each algorithm's dispatch table
//! over `rustyssl_crypto::provided::cipher`, which has the provider functions' semantics.
//!
//! The tables have the reference's functions and parameter lists per family, since the EVP
//! layer's behavior follows from them: the generic block and stream modes
//! (`ciphercommon.c`), triple DES (`cipher_tdes_common.c`: no `use-bits` or `tls-mac` in its
//! lists, a random key to get, and `decrypt-only`), ChaCha20 (only the key and IV lengths), and
//! the NULL cipher (a TLS MAC length). An algorithm context is a boxed [`AlgCtx`], freed by
//! `freectx`.
//!
//! What the reference would crash on (an input pointer of NULL with a length, an output of
//! NULL where it writes) fails here instead, without an error (docs/DEVIATIONS.md). The SKEY
//! init functions come with `EVP_SKEY` (3.10); the AEADs and the other modes with 3.4b and
//! 3.4c.

use core::ffi::{c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, OSSL_ALGORITHM, OSSL_CIPHER_PARAM_AEAD,
    OSSL_CIPHER_PARAM_BLOCK_SIZE, OSSL_CIPHER_PARAM_CTS, OSSL_CIPHER_PARAM_CUSTOM_IV,
    OSSL_CIPHER_PARAM_DECRYPT_ONLY, OSSL_CIPHER_PARAM_HAS_RAND_KEY, OSSL_CIPHER_PARAM_IV,
    OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_KEYLEN, OSSL_CIPHER_PARAM_MODE,
    OSSL_CIPHER_PARAM_NUM, OSSL_CIPHER_PARAM_PADDING, OSSL_CIPHER_PARAM_RANDOM_KEY,
    OSSL_CIPHER_PARAM_TLS_MAC, OSSL_CIPHER_PARAM_TLS_MAC_SIZE, OSSL_CIPHER_PARAM_TLS_VERSION,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_CIPHER_PARAM_USE_BITS,
    OSSL_FUNC_CIPHER_CIPHER, OSSL_FUNC_CIPHER_DECRYPT_INIT, OSSL_FUNC_CIPHER_DUPCTX,
    OSSL_FUNC_CIPHER_ENCRYPT_INIT, OSSL_FUNC_CIPHER_FINAL, OSSL_FUNC_CIPHER_FREECTX,
    OSSL_FUNC_CIPHER_GET_CTX_PARAMS, OSSL_FUNC_CIPHER_GET_PARAMS,
    OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
    OSSL_FUNC_CIPHER_NEWCTX, OSSL_FUNC_CIPHER_SET_CTX_PARAMS, OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_CIPHER_UPDATE, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER, PROV_R_BAD_DECRYPT,
    PROV_R_CIPHER_OPERATION_FAILED, PROV_R_FAILED_TO_GENERATE_KEY, PROV_R_FAILED_TO_GET_PARAMETER,
    PROV_R_FAILED_TO_SET_PARAMETER, PROV_R_INVALID_IV_LENGTH, PROV_R_INVALID_KEY_LENGTH,
    PROV_R_NO_KEY_SET, PROV_R_OUTPUT_BUFFER_TOO_SMALL, PROV_R_WRONG_FINAL_BLOCK_LENGTH,
};
use rustyssl_crypto::provided::cipher::{Ctx, Error, Kind, Mode, Output};
use rustyssl_crypto::sym::BlockAlgorithm;

use super::tables::{ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, alg, defn, entry};
use crate::err;
use crate::ffi::ffi_callback;
use crate::params::{
    OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint, OSSL_PARAM_locate, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_int, OSSL_PARAM_set_octet_ptr, OSSL_PARAM_set_octet_string,
    OSSL_PARAM_set_size_t, OSSL_PARAM_set_uint,
};

/// An algorithm context: the cipher's, and where the NULL cipher found the TLS MAC (in the
/// caller's input, which the reference points into).
pub(crate) struct AlgCtx {
    core: Ctx,
    tlsmac: *const u8,
}

/// The algorithm context behind `vctx`, or `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a context `newctx` made and `freectx` hasn't freed.
unsafe fn context<'a>(vctx: *mut c_void) -> Option<&'a mut AlgCtx> {
    // SAFETY: the caller's guarantee: a box from `newctx`, used by one caller at a time as an
    // algorithm context is.
    unsafe { vctx.cast::<AlgCtx>().as_mut() }
}

/// `ossl_param_is_empty`.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn is_empty(params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { params.as_ref() }.is_none_or(|p| p.key.is_null())
}

/// `newctx` for `kind`.
fn new_context(kind: Kind) -> *mut c_void {
    Box::into_raw(Box::new(AlgCtx {
        core: Ctx::new(kind),
        tlsmac: ptr::null(),
    }))
    .cast()
}

/// Raises the error for a core failure from `function`.
#[track_caller]
fn raise(e: Error, function: &str) {
    let reason = match e {
        Error::Silent => return,
        Error::NoKeySet => PROV_R_NO_KEY_SET,
        Error::OutputBufferTooSmall => PROV_R_OUTPUT_BUFFER_TOO_SMALL,
        Error::CipherOperationFailed => PROV_R_CIPHER_OPERATION_FAILED,
        Error::WrongFinalBlockLength => PROV_R_WRONG_FINAL_BLOCK_LENGTH,
        Error::BadDecrypt => PROV_R_BAD_DECRYPT,
        Error::InvalidKeyLength => PROV_R_INVALID_KEY_LENGTH,
        Error::InvalidIvLength => PROV_R_INVALID_IV_LENGTH,
        Error::FailedToGetParameter => PROV_R_FAILED_TO_GET_PARAMETER,
        Error::FailedToGenerateKey => PROV_R_FAILED_TO_GENERATE_KEY,
        Error::Internal => ERR_R_INTERNAL_ERROR,
    };
    err::raise(ERR_LIB_PROV, reason, function);
}

/// `len` octets at `p` (none for a length of 0), or `None` for NULL with a length.
///
/// # Safety
/// `p` is NULL or holds `len` octets.
unsafe fn input<'a>(p: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if p.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts(p, len) })
}

/// Writes `o` at `out`: false if there's something to write and `out` is NULL.
///
/// # Safety
/// `out` is NULL or has room for `o.data.len()` octets.
unsafe fn write(out: *mut u8, o: &Output) -> bool {
    let n = o.data.len();
    if n == 0 {
        return true;
    }
    if out.is_null() {
        return false;
    }
    let mut data = o.data.clone();
    if o.last_mask != 0xff {
        // The bits of the last octet that aren't written keep the output's.
        let at = out.wrapping_add(n.wrapping_sub(1));
        // SAFETY: the caller's guarantee: the last octet of the room.
        let old = unsafe { at.read() };
        if let Some(last) = data.last_mut() {
            *last = (*last & o.last_mask) | (old & !o.last_mask);
        }
    }
    // SAFETY: the caller's guarantee; `data` is ours, so the two don't overlap.
    unsafe { ptr::copy_nonoverlapping(data.as_ptr(), out, n) };
    true
}

/// Runs `op` (`update`, `final`, or `cipher`) and writes its output and length.
///
/// # Safety
/// `out` is NULL or has room for what the operation writes; `outl` is NULL or valid for a
/// write.
unsafe fn finish(
    result: Result<Output, Error>,
    out: *mut u8,
    outl: *mut usize,
    function: &str,
) -> c_int {
    match result {
        Ok(o) => {
            // SAFETY: the caller's guarantee.
            if !unsafe { write(out, &o) } || outl.is_null() {
                return 0;
            }
            // SAFETY: the caller's guarantee.
            unsafe { outl.write(o.len) };
            1
        }
        Err(e) => {
            raise(e, function);
            0
        }
    }
}

ffi_callback! {
    /// `freectx`: wipes and frees the context; NULL does nothing.
    ///
    /// # Safety
    /// `vctx` is NULL or a context from `newctx`, not used afterwards.
    pub(crate) unsafe extern "C" fn freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee: a box from `newctx`.
            drop(unsafe { Box::from_raw(vctx.cast::<AlgCtx>()) });
        }
    }
}

ffi_callback! {
    /// `dupctx`: a copy of the context (ChaCha20's of NULL is NULL, as everyone's here).
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context.
    pub(crate) unsafe extern "C" fn dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return ptr::null_mut() };
        Box::into_raw(Box::new(AlgCtx { core: ctx.core.clone(), tlsmac: ctx.tlsmac })).cast()
    }
}

ffi_callback! {
    /// `null_dupctx`: the NULL cipher's "copy" is a new context, as the reference's
    /// `dupctx` is its `newctx`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn null_dupctx(_vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        new_context(Kind::Null)
    }
}

/// The parameters' family, for what an init sets after the key and IV.
#[derive(Clone, Copy)]
enum Family {
    Generic,
    ChaCha20,
    Null,
}

/// `einit`/`dinit`: the key and IV, then the parameters.
///
/// # Safety
/// `vctx` is a live algorithm context; `key` and `iv` are NULL or hold `keylen` and `ivlen`
/// octets; `params` is NULL or a parameter array.
unsafe fn init(
    vctx: *mut c_void,
    key: *const u8,
    keylen: usize,
    iv: *const u8,
    ivlen: usize,
    params: *const OSSL_PARAM,
    (enc, family): (bool, Family),
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(ctx) = (unsafe { context(vctx) }) else {
        return 0;
    };
    let key = if key.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { core::slice::from_raw_parts(key, keylen) })
    };
    let iv = if iv.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { core::slice::from_raw_parts(iv, ivlen) })
    };
    if let Err(e) = ctx.core.init(enc, key, iv) {
        raise(e, "cipher_generic_init_internal");
        return 0;
    }
    match family {
        // SAFETY: the caller's guarantee.
        Family::Generic => unsafe { generic_set_ctx_params(vctx, params) },
        // SAFETY: the caller's guarantee.
        Family::ChaCha20 => unsafe { chacha20_set_ctx_params(vctx, params) },
        Family::Null => 1,
    }
}

macro_rules! inits {
    ($family:expr, $einit:ident, $dinit:ident) => {
        ffi_callback! {
            /// `einit`: encrypting with the key and IV given, then the parameters.
            ///
            /// # Safety
            /// As for `init`.
            pub(crate) unsafe extern "C" fn $einit(vctx: *mut c_void, key: *const u8, keylen: usize, iv: *const u8, ivlen: usize, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { init(vctx, key, keylen, iv, ivlen, params, (true, $family)) }
            }
        }

        ffi_callback! {
            /// `dinit`: decrypting with the key and IV given, then the parameters.
            ///
            /// # Safety
            /// As for `init`.
            pub(crate) unsafe extern "C" fn $dinit(vctx: *mut c_void, key: *const u8, keylen: usize, iv: *const u8, ivlen: usize, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { init(vctx, key, keylen, iv, ivlen, params, (false, $family)) }
            }
        }
    };
}

inits!(Family::Generic, generic_einit, generic_dinit);
inits!(Family::ChaCha20, chacha20_einit, chacha20_dinit);
inits!(Family::Null, null_einit, null_dinit);

ffi_callback! {
    /// `update`: `inl` octets (bits for CFB1 counting bits) through the mode, the output's
    /// length through `outl`.
    ///
    /// # Safety
    /// `vctx` is a live algorithm context; `in_` holds the input; `out` has room for `outsize`
    /// octets; `outl` is valid for a write.
    pub(crate) unsafe extern "C" fn update(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize, in_: *const u8, inl: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { process(vctx, out, outl, outsize, in_, inl, false) }
    }
}

ffi_callback! {
    /// `cipher` (`EVP_Cipher`): the mode without buffering or padding.
    ///
    /// # Safety
    /// As for [`update`].
    pub(crate) unsafe extern "C" fn cipher(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize, in_: *const u8, inl: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { process(vctx, out, outl, outsize, in_, inl, true) }
    }
}

/// `update` and `cipher`.
///
/// # Safety
/// As for [`update`].
unsafe fn process(
    vctx: *mut c_void,
    out: *mut u8,
    outl: *mut usize,
    outsize: usize,
    in_: *const u8,
    inl: usize,
    one_shot: bool,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(ctx) = (unsafe { context(vctx) }) else {
        return 0;
    };
    let n = ctx.core.input_len(inl);
    // SAFETY: the caller's guarantee.
    let Some(data) = (unsafe { input(in_, n) }) else {
        return 0;
    };
    if ctx.core.kind() == Kind::Null {
        // `null_cipher`: the input as it is, less the TLS MAC, which it points to.
        let strips = ctx.core.null_strips_mac();
        let result = ctx.core.update(data, inl, outsize);
        let Ok(o) = result else { return 0 };
        if strips {
            ctx.tlsmac = in_.wrapping_add(o.len);
        }
        if !out.is_null() && out.cast_const() != in_ && o.len > 0 {
            // SAFETY: the caller's guarantee: room for `outsize`, at least `o.len`; the two
            // may overlap.
            unsafe { ptr::copy(in_, out, o.len) };
        }
        if outl.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(o.len) };
        return 1;
    }
    let (result, function) = if one_shot {
        (
            ctx.core.cipher(data, inl, outsize),
            "ossl_cipher_generic_cipher",
        )
    } else {
        (
            ctx.core.update(data, inl, outsize),
            "ossl_cipher_generic_update",
        )
    };
    // SAFETY: the caller's guarantee.
    unsafe { finish(result, out, outl, function) }
}

ffi_callback! {
    /// `final`: what's left, padded or with the padding checked, through `out` (room for
    /// `outsize`), its length through `outl`.
    ///
    /// # Safety
    /// `vctx` is a live algorithm context; `out` has room for `outsize` octets; `outl` is
    /// valid for a write.
    pub(crate) unsafe extern "C" fn final_(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let result = ctx.core.finalize(outsize);
        // SAFETY: the caller's guarantee.
        unsafe { finish(result, out, outl, "ossl_cipher_generic_final") }
    }
}

/// A value a provider function reports.
#[derive(Clone, Copy)]
enum Value {
    Int(c_int),
    Uint(c_uint),
    Size(usize),
    /// A pointer to the context's (or the input's) octets, as an octet pointer.
    Ptr(*const u8, usize),
    /// The context's IV: as an octet pointer, or else copied as an octet string.
    Iv(*const u8, usize),
}

/// Sets the parameter `key` of `params`, if there is one, to `value`, raising
/// `PROV_R_FAILED_TO_SET_PARAMETER` from `function` if that fails.
///
/// # Safety
/// `params` is NULL or a parameter array; a pointer value holds its length.
unsafe fn set_param(
    params: *mut OSSL_PARAM,
    key: &core::ffi::CStr,
    function: &str,
    value: Value,
) -> bool {
    // SAFETY: the caller's array.
    let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
    if p.is_null() {
        return true;
    }
    let ok = match value {
        // SAFETY: a located parameter, here and below.
        Value::Int(v) => unsafe { OSSL_PARAM_set_int(p, v) },
        // SAFETY: as above.
        Value::Uint(v) => unsafe { OSSL_PARAM_set_uint(p, v) },
        // SAFETY: as above.
        Value::Size(v) => unsafe { OSSL_PARAM_set_size_t(p, v) },
        // SAFETY: as above; the caller's pointer.
        Value::Ptr(v, n) => unsafe { OSSL_PARAM_set_octet_ptr(p, v.cast(), n) },
        Value::Iv(v, n) => {
            // SAFETY: as above.
            let r = unsafe { OSSL_PARAM_set_octet_ptr(p, v.cast(), n) };
            if r == 0 {
                // SAFETY: as above; the IV holds `n` octets.
                unsafe { OSSL_PARAM_set_octet_string(p, v.cast(), n) }
            } else {
                r
            }
        }
    };
    if ok == 0 {
        err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, function);
        return false;
    }
    true
}

/// `ossl_cipher_generic_get_params` (`ossl_tdes_get_params` adds `decrypt-only`).
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn generic_get_params(kind: Kind, params: *mut OSSL_PARAM) -> c_int {
    const F: &str = "ossl_cipher_generic_get_params";
    if kind.has_rand_key() {
        // SAFETY: the caller's array; a located parameter.
        if !unsafe { set_param(params, OSSL_CIPHER_PARAM_DECRYPT_ONLY, F, Value::Int(0)) } {
            return 0;
        }
    }
    let flags = [
        (OSSL_CIPHER_PARAM_AEAD, false),
        (OSSL_CIPHER_PARAM_CUSTOM_IV, kind.custom_iv()),
        (OSSL_CIPHER_PARAM_CTS, false),
        (OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, false),
        (OSSL_CIPHER_PARAM_HAS_RAND_KEY, kind.has_rand_key()),
    ];
    // SAFETY: the caller's array; a located parameter.
    if !unsafe { set_param(params, OSSL_CIPHER_PARAM_MODE, F, Value::Uint(kind.mode())) } {
        return 0;
    }
    for (key, on) in flags {
        // SAFETY: as above.
        if !unsafe { set_param(params, key, F, Value::Int(c_int::from(on))) } {
            return 0;
        }
    }
    for (key, value) in [
        (OSSL_CIPHER_PARAM_KEYLEN, kind.key_len()),
        (OSSL_CIPHER_PARAM_BLOCK_SIZE, kind.block_size()),
        (OSSL_CIPHER_PARAM_IVLEN, kind.iv_len()),
    ] {
        // SAFETY: as above.
        if !unsafe { set_param(params, key, F, Value::Size(value)) } {
            return 0;
        }
    }
    1
}

ffi_callback! {
    /// `ossl_cipher_generic_get_ctx_params`, and `ossl_tdes_get_ctx_params`'s random key.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array, a
    /// random key's data with room for the key.
    pub(crate) unsafe extern "C" fn generic_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "ossl_cipher_generic_get_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let tlsmac = ctx.tlsmac;
        let Some(g) = ctx.core.generic_mut() else { return 0 };
        let (ivlen, pad, num, keylen, macsize) =
            (g.iv_len(), g.padding(), g.num(), g.key_len(), g.tls_mac_size());
        // SAFETY: the caller's array; a located parameter.
        if !unsafe { set_param(params, OSSL_CIPHER_PARAM_IVLEN, F, Value::Size(ivlen)) } {
            return 0;
        }
        // SAFETY: as above.
        if !unsafe { set_param(params, OSSL_CIPHER_PARAM_PADDING, F, Value::Uint(c_uint::from(pad))) } {
            return 0;
        }
        for (key, original) in [(OSSL_CIPHER_PARAM_IV, true), (OSSL_CIPHER_PARAM_UPDATED_IV, false)] {
            let iv = if original {
                g.original_iv()
            } else {
                g.updated_iv()
            }
            .as_mut_ptr()
            .cast_const();
            // A pointer to the context's IV, which lives as long as it, or else a copy.
            // SAFETY: the caller's array; the IV holds `ivlen` octets.
            if !unsafe { set_param(params, key, F, Value::Iv(iv, ivlen)) } {
                return 0;
            }
        }
        // SAFETY: as above.
        if !unsafe { set_param(params, OSSL_CIPHER_PARAM_NUM, F, Value::Uint(num)) } {
            return 0;
        }
        // SAFETY: as above.
        if !unsafe { set_param(params, OSSL_CIPHER_PARAM_KEYLEN, F, Value::Size(keylen)) } {
            return 0;
        }
        // SAFETY: as above.
        if !unsafe { set_param(params, OSSL_CIPHER_PARAM_TLS_MAC, F, Value::Ptr(tlsmac, macsize)) } {
            return 0;
        }
        if !g.kind().has_rand_key() {
            return 1;
        }
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_RANDOM_KEY.as_ptr()) };
        // SAFETY: a located parameter, or NULL.
        let Some(p) = (unsafe { p.as_ref() }) else { return 1 };
        let n = g.key_len();
        // The reference writes the key whatever room the parameter says it has (so that
        // EVP_CIPHER_CTX_rand_key can pass none); NULL data fails here.
        let result = if p.data.is_null() {
            Err(Error::FailedToGenerateKey)
        } else {
            // SAFETY: the caller's guarantee: room for the key.
            let key = unsafe { core::slice::from_raw_parts_mut(p.data.cast::<u8>(), n) };
            // From the operating system until the private generator of 3.7.
            g.random_key(key, |k| rustyssl_crypto::rand::os_entropy(k).is_ok())
        };
        if result.is_err() {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY, "ossl_tdes_get_ctx_params");
            return 0;
        }
        1
    }
}

/// Gets a located parameter with `get`, raising `PROV_R_FAILED_TO_GET_PARAMETER` if that fails.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn get_param<T: Default>(
    params: *const OSSL_PARAM,
    key: &core::ffi::CStr,
    function: &str,
    get: impl FnOnce(*const OSSL_PARAM, *mut T) -> c_int,
) -> Result<Option<T>, ()> {
    // SAFETY: the caller's array.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    if p.is_null() {
        return Ok(None);
    }
    let mut v = T::default();
    if get(p, &raw mut v) == 0 {
        err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, function);
        return Err(());
    }
    Ok(Some(v))
}

/// Gets an unsigned int parameter.
fn get_uint(p: *const OSSL_PARAM, v: *mut c_uint) -> c_int {
    // SAFETY: a located parameter and a local.
    unsafe { OSSL_PARAM_get_uint(p, v) }
}

/// Gets a size_t parameter.
fn get_size(p: *const OSSL_PARAM, v: *mut usize) -> c_int {
    // SAFETY: a located parameter and a local.
    unsafe { OSSL_PARAM_get_size_t(p, v) }
}

ffi_callback! {
    /// `ossl_cipher_generic_set_ctx_params` (and `ossl_tdes_set_ctx_params`): `padding`,
    /// `use-bits`, `tls-version` (only 0 until the TLS step), `tls-mac-size`, and `num`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn generic_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "ossl_cipher_generic_set_ctx_params";
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let Some(g) = ctx.core.generic_mut() else { return 0 };
        // SAFETY: the caller's array, here and below.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_PADDING, F, get_uint) } {
            Err(()) => return 0,
            Ok(Some(pad)) => g.set_padding(pad != 0),
            Ok(None) => {}
        }
        // SAFETY: as above.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_USE_BITS, F, get_uint) } {
            Err(()) => return 0,
            Ok(Some(bits)) => g.set_use_bits(bits != 0),
            Ok(None) => {}
        }
        // SAFETY: as above.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_TLS_VERSION, F, get_uint) } {
            Err(()) => return 0,
            Ok(Some(v)) => {
                if g.set_tls_version(v).is_err() {
                    err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
                    return 0;
                }
            }
            Ok(None) => {}
        }
        // SAFETY: as above.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE, F, get_size) } {
            Err(()) => return 0,
            Ok(Some(n)) => g.set_tls_mac_size(n),
            Ok(None) => {}
        }
        // SAFETY: as above.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_NUM, F, get_uint) } {
            Err(()) => return 0,
            Ok(Some(num)) => {
                if let Err(e) = g.set_num(num) {
                    raise(e, F);
                    return 0;
                }
            }
            Ok(None) => {}
        }
        1
    }
}

ffi_callback! {
    /// `chacha20_get_ctx_params`: the IV and key lengths.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn chacha20_get_ctx_params(_vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "chacha20_get_ctx_params";
        for (key, value) in [
            (OSSL_CIPHER_PARAM_IVLEN, Kind::ChaCha20.iv_len()),
            (OSSL_CIPHER_PARAM_KEYLEN, Kind::ChaCha20.key_len()),
        ] {
            // SAFETY: the caller's array; a located parameter.
            if !unsafe { set_param(params, key, F, Value::Size(value)) } {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `chacha20_set_ctx_params`: the key and IV lengths may only be set to what they are.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn chacha20_set_ctx_params(_vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "chacha20_set_ctx_params";
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        for (key, value, reason) in [
            (OSSL_CIPHER_PARAM_KEYLEN, Kind::ChaCha20.key_len(), PROV_R_INVALID_KEY_LENGTH),
            (OSSL_CIPHER_PARAM_IVLEN, Kind::ChaCha20.iv_len(), PROV_R_INVALID_IV_LENGTH),
        ] {
            // SAFETY: the caller's array.
            match unsafe { get_param(params, key, F, get_size) } {
                Err(()) => return 0,
                Ok(Some(n)) if n != value => {
                    err::raise(ERR_LIB_PROV, reason, F);
                    return 0;
                }
                Ok(_) => {}
            }
        }
        1
    }
}

ffi_callback! {
    /// `null_get_ctx_params`: lengths of 0 and the TLS MAC.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn null_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "null_get_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        for key in [OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_KEYLEN] {
            // SAFETY: the caller's array; a located parameter.
            if !unsafe { set_param(params, key, F, Value::Size(0)) } {
                return 0;
            }
        }
        let (mac, size) = (ctx.tlsmac, ctx.core.null_mac_size().unwrap_or(0));
        // SAFETY: as above.
        if !unsafe { set_param(params, OSSL_CIPHER_PARAM_TLS_MAC, F, Value::Ptr(mac, size)) } {
            return 0;
        }
        1
    }
}

ffi_callback! {
    /// `null_set_ctx_params`: `tls-mac-size`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn null_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        // SAFETY: the caller's array.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE, "null_set_ctx_params", get_size) } {
            Err(()) => 0,
            Ok(Some(n)) => {
                ctx.core.set_null_mac_size(n);
                1
            }
            Ok(None) => 1,
        }
    }
}

const SIZE_T: usize = size_of::<usize>();
const INT: usize = size_of::<c_int>();
const UINT: usize = size_of::<c_uint>();

static GENERIC_GETTABLE: Params<10> = Params([
    defn(OSSL_CIPHER_PARAM_MODE, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(
        OSSL_CIPHER_PARAM_BLOCK_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_AEAD, OSSL_PARAM_INTEGER, INT),
    defn(OSSL_CIPHER_PARAM_CUSTOM_IV, OSSL_PARAM_INTEGER, INT),
    defn(OSSL_CIPHER_PARAM_CTS, OSSL_PARAM_INTEGER, INT),
    defn(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, OSSL_PARAM_INTEGER, INT),
    defn(OSSL_CIPHER_PARAM_HAS_RAND_KEY, OSSL_PARAM_INTEGER, INT),
    PARAM_END,
]);

/// `CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START`'s six, then `$extra`, then the end.
macro_rules! default_gettable_ctx {
    ($($extra:expr),*) => {
        [
            defn(OSSL_CIPHER_PARAM_KEYLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
            defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
            defn(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
            defn(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
            defn(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING, 0),
            defn(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING, 0),
            $($extra,)*
            PARAM_END,
        ]
    };
}

static GENERIC_GETTABLE_CTX: Params<8> = Params(default_gettable_ctx!(defn(
    OSSL_CIPHER_PARAM_TLS_MAC,
    OSSL_PARAM_OCTET_PTR,
    0
)));
static GENERIC_SETTABLE_CTX: Params<6> = Params([
    defn(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(
        OSSL_CIPHER_PARAM_USE_BITS,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS_VERSION,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    PARAM_END,
]);
static TDES_GETTABLE_CTX: Params<8> = Params(default_gettable_ctx!(defn(
    OSSL_CIPHER_PARAM_RANDOM_KEY,
    OSSL_PARAM_OCTET_STRING,
    0
)));
// `ossl_tdes_settable_ctx_params` lists `padding` and `num` twice, as the reference's does.
static TDES_SETTABLE_CTX: Params<5> = Params([
    defn(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    PARAM_END,
]);
static CHACHA20_CTX: Params<3> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    PARAM_END,
]);
static NULL_GETTABLE_CTX: Params<4> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR, 0),
    PARAM_END,
]);
static NULL_SETTABLE_CTX: Params<2> = Params([
    defn(
        OSSL_CIPHER_PARAM_TLS_MAC_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    PARAM_END,
]);

macro_rules! list {
    ($name:ident, $list:ident) => {
        ffi_callback! {
            /// A context parameter list.
            ///
            /// # Safety
            /// No preconditions.
            pub(crate) unsafe extern "C" fn $name(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
            where failure = ptr::null(), library = ERR_LIB_PROV
            {
                $list.0.as_ptr()
            }
        }
    };
}

list!(generic_gettable_ctx_params, GENERIC_GETTABLE_CTX);
list!(generic_settable_ctx_params, GENERIC_SETTABLE_CTX);
list!(tdes_gettable_ctx_params, TDES_GETTABLE_CTX);
list!(tdes_settable_ctx_params, TDES_SETTABLE_CTX);
list!(chacha20_ctx_params, CHACHA20_CTX);
list!(null_gettable_ctx_params, NULL_GETTABLE_CTX);
list!(null_settable_ctx_params, NULL_SETTABLE_CTX);

ffi_callback! {
    /// `ossl_cipher_generic_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn generic_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GENERIC_GETTABLE.0.as_ptr()
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type DupFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(
    *mut c_void,
    *const u8,
    usize,
    *const u8,
    usize,
    *const OSSL_PARAM,
) -> c_int;
type UpdateFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;
type FinalFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
type GettableFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type GetCtxFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetCtxFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type CtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// One cipher: its `newctx` and `get_params`, and its family's table.
macro_rules! cipher {
    ($name:ident, $kind:expr, $family:ident) => {
        pub(crate) mod $name {
            use super::*;

            ffi_callback! {
                /// `newctx`.
                ///
                /// # Safety
                /// No preconditions.
                pub(crate) unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void
                where failure = ptr::null_mut(), library = ERR_LIB_PROV
                {
                    new_context($kind)
                }
            }

            ffi_callback! {
                /// `get_params`: the mode, flags, and lengths.
                ///
                /// # Safety
                /// `params` is NULL or a parameter array.
                pub(crate) unsafe extern "C" fn get_params(params: *mut OSSL_PARAM) -> c_int
                where failure = 0, library = ERR_LIB_PROV
                {
                    // SAFETY: the caller's guarantee.
                    unsafe { generic_get_params($kind, params) }
                }
            }

            $family!();
        }
    };
}

/// `IMPLEMENT_generic_cipher`'s table.
macro_rules! generic {
    () => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, generic_einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, generic_dinit, InitFn),
            entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
            entry!(OSSL_FUNC_CIPHER_CIPHER, cipher, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_GET_PARAMS, get_params, GetParamsFn),
            entry!(
                OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                generic_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                generic_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                generic_gettable_params,
                GettableFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                generic_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                generic_settable_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

/// `IMPLEMENT_tdes_cipher`'s table.
macro_rules! tdes {
    () => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, generic_einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, generic_dinit, InitFn),
            entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
            entry!(OSSL_FUNC_CIPHER_CIPHER, cipher, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_GET_PARAMS, get_params, GetParamsFn),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                generic_gettable_params,
                GettableFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                generic_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                tdes_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                generic_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                tdes_settable_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

/// `ossl_chacha20_functions`.
macro_rules! chacha20 {
    () => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, chacha20_einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, chacha20_dinit, InitFn),
            entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
            entry!(OSSL_FUNC_CIPHER_CIPHER, cipher, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_GET_PARAMS, get_params, GetParamsFn),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                generic_gettable_params,
                GettableFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                chacha20_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                chacha20_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                chacha20_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                chacha20_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

/// `ossl_null_functions`: `update` and `cipher` are both `null_cipher`.
macro_rules! null {
    () => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, null_dupctx, DupFn),
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, null_einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, null_dinit, InitFn),
            entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
            entry!(OSSL_FUNC_CIPHER_CIPHER, cipher, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_GET_PARAMS, get_params, GetParamsFn),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
                generic_gettable_params,
                GettableFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
                null_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                null_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                null_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                null_settable_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

/// A block cipher's kind.
const fn block(algorithm: BlockAlgorithm, key_len: usize, mode: Mode) -> Kind {
    Kind::Block {
        algorithm,
        key_len,
        mode,
    }
}

use BlockAlgorithm::{Aes, Aria, Camellia, Sm4, TripleDes};
use Mode::{Cbc, Cfb, Cfb1, Cfb8, Ctr, Ecb, Ofb};

cipher!(null, Kind::Null, null);
cipher!(aes256ecb, block(Aes, 32, Ecb), generic);
cipher!(aes192ecb, block(Aes, 24, Ecb), generic);
cipher!(aes128ecb, block(Aes, 16, Ecb), generic);
cipher!(aes256cbc, block(Aes, 32, Cbc), generic);
cipher!(aes192cbc, block(Aes, 24, Cbc), generic);
cipher!(aes128cbc, block(Aes, 16, Cbc), generic);
cipher!(aes256ofb, block(Aes, 32, Ofb), generic);
cipher!(aes192ofb, block(Aes, 24, Ofb), generic);
cipher!(aes128ofb, block(Aes, 16, Ofb), generic);
cipher!(aes256cfb, block(Aes, 32, Cfb), generic);
cipher!(aes192cfb, block(Aes, 24, Cfb), generic);
cipher!(aes128cfb, block(Aes, 16, Cfb), generic);
cipher!(aes256cfb1, block(Aes, 32, Cfb1), generic);
cipher!(aes192cfb1, block(Aes, 24, Cfb1), generic);
cipher!(aes128cfb1, block(Aes, 16, Cfb1), generic);
cipher!(aes256cfb8, block(Aes, 32, Cfb8), generic);
cipher!(aes192cfb8, block(Aes, 24, Cfb8), generic);
cipher!(aes128cfb8, block(Aes, 16, Cfb8), generic);
cipher!(aes256ctr, block(Aes, 32, Ctr), generic);
cipher!(aes192ctr, block(Aes, 24, Ctr), generic);
cipher!(aes128ctr, block(Aes, 16, Ctr), generic);
cipher!(aria256ecb, block(Aria, 32, Ecb), generic);
cipher!(aria192ecb, block(Aria, 24, Ecb), generic);
cipher!(aria128ecb, block(Aria, 16, Ecb), generic);
cipher!(aria256cbc, block(Aria, 32, Cbc), generic);
cipher!(aria192cbc, block(Aria, 24, Cbc), generic);
cipher!(aria128cbc, block(Aria, 16, Cbc), generic);
cipher!(aria256ofb, block(Aria, 32, Ofb), generic);
cipher!(aria192ofb, block(Aria, 24, Ofb), generic);
cipher!(aria128ofb, block(Aria, 16, Ofb), generic);
cipher!(aria256cfb, block(Aria, 32, Cfb), generic);
cipher!(aria192cfb, block(Aria, 24, Cfb), generic);
cipher!(aria128cfb, block(Aria, 16, Cfb), generic);
cipher!(aria256cfb1, block(Aria, 32, Cfb1), generic);
cipher!(aria192cfb1, block(Aria, 24, Cfb1), generic);
cipher!(aria128cfb1, block(Aria, 16, Cfb1), generic);
cipher!(aria256cfb8, block(Aria, 32, Cfb8), generic);
cipher!(aria192cfb8, block(Aria, 24, Cfb8), generic);
cipher!(aria128cfb8, block(Aria, 16, Cfb8), generic);
cipher!(aria256ctr, block(Aria, 32, Ctr), generic);
cipher!(aria192ctr, block(Aria, 24, Ctr), generic);
cipher!(aria128ctr, block(Aria, 16, Ctr), generic);
cipher!(camellia256ecb, block(Camellia, 32, Ecb), generic);
cipher!(camellia192ecb, block(Camellia, 24, Ecb), generic);
cipher!(camellia128ecb, block(Camellia, 16, Ecb), generic);
cipher!(camellia256cbc, block(Camellia, 32, Cbc), generic);
cipher!(camellia192cbc, block(Camellia, 24, Cbc), generic);
cipher!(camellia128cbc, block(Camellia, 16, Cbc), generic);
cipher!(camellia256ofb, block(Camellia, 32, Ofb), generic);
cipher!(camellia192ofb, block(Camellia, 24, Ofb), generic);
cipher!(camellia128ofb, block(Camellia, 16, Ofb), generic);
cipher!(camellia256cfb, block(Camellia, 32, Cfb), generic);
cipher!(camellia192cfb, block(Camellia, 24, Cfb), generic);
cipher!(camellia128cfb, block(Camellia, 16, Cfb), generic);
cipher!(camellia256cfb1, block(Camellia, 32, Cfb1), generic);
cipher!(camellia192cfb1, block(Camellia, 24, Cfb1), generic);
cipher!(camellia128cfb1, block(Camellia, 16, Cfb1), generic);
cipher!(camellia256cfb8, block(Camellia, 32, Cfb8), generic);
cipher!(camellia192cfb8, block(Camellia, 24, Cfb8), generic);
cipher!(camellia128cfb8, block(Camellia, 16, Cfb8), generic);
cipher!(camellia256ctr, block(Camellia, 32, Ctr), generic);
cipher!(camellia192ctr, block(Camellia, 24, Ctr), generic);
cipher!(camellia128ctr, block(Camellia, 16, Ctr), generic);
cipher!(tdes_ede3_ecb, block(TripleDes, 24, Ecb), tdes);
cipher!(tdes_ede3_cbc, block(TripleDes, 24, Cbc), tdes);
cipher!(tdes_ede3_ofb, block(TripleDes, 24, Ofb), tdes);
cipher!(tdes_ede3_cfb, block(TripleDes, 24, Cfb), tdes);
cipher!(tdes_ede3_cfb8, block(TripleDes, 24, Cfb8), tdes);
cipher!(tdes_ede3_cfb1, block(TripleDes, 24, Cfb1), tdes);
cipher!(tdes_ede2_ecb, block(TripleDes, 16, Ecb), tdes);
cipher!(tdes_ede2_cbc, block(TripleDes, 16, Cbc), tdes);
cipher!(tdes_ede2_ofb, block(TripleDes, 16, Ofb), tdes);
cipher!(tdes_ede2_cfb, block(TripleDes, 16, Cfb), tdes);
cipher!(sm4128ecb, block(Sm4, 16, Ecb), generic);
cipher!(sm4128cbc, block(Sm4, 16, Cbc), generic);
cipher!(sm4128ctr, block(Sm4, 16, Ctr), generic);
cipher!(sm4128ofb128, block(Sm4, 16, Ofb), generic);
cipher!(sm4128cfb128, block(Sm4, 16, Cfb), generic);
cipher!(chacha20, Kind::ChaCha20, chacha20);

/// `deflt_ciphers`, with the reference's names (`PROV_NAMES_*`) in its order: those of this
/// step (the AEADs, XTS, SIV, the key wraps, CTS, and the composites come with 3.4b and 3.4c).
pub(crate) static DEFAULT_CIPHERS: Algorithms<81> = Algorithms([
    alg(c"NULL", &null::TABLE),
    alg(c"AES-256-ECB:2.16.840.1.101.3.4.1.41", &aes256ecb::TABLE),
    alg(c"AES-192-ECB:2.16.840.1.101.3.4.1.21", &aes192ecb::TABLE),
    alg(c"AES-128-ECB:2.16.840.1.101.3.4.1.1", &aes128ecb::TABLE),
    alg(
        c"AES-256-CBC:AES256:2.16.840.1.101.3.4.1.42",
        &aes256cbc::TABLE,
    ),
    alg(
        c"AES-192-CBC:AES192:2.16.840.1.101.3.4.1.22",
        &aes192cbc::TABLE,
    ),
    alg(
        c"AES-128-CBC:AES128:2.16.840.1.101.3.4.1.2",
        &aes128cbc::TABLE,
    ),
    alg(c"AES-256-OFB:2.16.840.1.101.3.4.1.43", &aes256ofb::TABLE),
    alg(c"AES-192-OFB:2.16.840.1.101.3.4.1.23", &aes192ofb::TABLE),
    alg(c"AES-128-OFB:2.16.840.1.101.3.4.1.3", &aes128ofb::TABLE),
    alg(c"AES-256-CFB:2.16.840.1.101.3.4.1.44", &aes256cfb::TABLE),
    alg(c"AES-192-CFB:2.16.840.1.101.3.4.1.24", &aes192cfb::TABLE),
    alg(c"AES-128-CFB:2.16.840.1.101.3.4.1.4", &aes128cfb::TABLE),
    alg(c"AES-256-CFB1", &aes256cfb1::TABLE),
    alg(c"AES-192-CFB1", &aes192cfb1::TABLE),
    alg(c"AES-128-CFB1", &aes128cfb1::TABLE),
    alg(c"AES-256-CFB8", &aes256cfb8::TABLE),
    alg(c"AES-192-CFB8", &aes192cfb8::TABLE),
    alg(c"AES-128-CFB8", &aes128cfb8::TABLE),
    alg(c"AES-256-CTR", &aes256ctr::TABLE),
    alg(c"AES-192-CTR", &aes192ctr::TABLE),
    alg(c"AES-128-CTR", &aes128ctr::TABLE),
    alg(c"ARIA-256-ECB:1.2.410.200046.1.1.11", &aria256ecb::TABLE),
    alg(c"ARIA-192-ECB:1.2.410.200046.1.1.6", &aria192ecb::TABLE),
    alg(c"ARIA-128-ECB:1.2.410.200046.1.1.1", &aria128ecb::TABLE),
    alg(
        c"ARIA-256-CBC:ARIA256:1.2.410.200046.1.1.12",
        &aria256cbc::TABLE,
    ),
    alg(
        c"ARIA-192-CBC:ARIA192:1.2.410.200046.1.1.7",
        &aria192cbc::TABLE,
    ),
    alg(
        c"ARIA-128-CBC:ARIA128:1.2.410.200046.1.1.2",
        &aria128cbc::TABLE,
    ),
    alg(c"ARIA-256-OFB:1.2.410.200046.1.1.14", &aria256ofb::TABLE),
    alg(c"ARIA-192-OFB:1.2.410.200046.1.1.9", &aria192ofb::TABLE),
    alg(c"ARIA-128-OFB:1.2.410.200046.1.1.4", &aria128ofb::TABLE),
    alg(c"ARIA-256-CFB:1.2.410.200046.1.1.13", &aria256cfb::TABLE),
    alg(c"ARIA-192-CFB:1.2.410.200046.1.1.8", &aria192cfb::TABLE),
    alg(c"ARIA-128-CFB:1.2.410.200046.1.1.3", &aria128cfb::TABLE),
    alg(c"ARIA-256-CFB1", &aria256cfb1::TABLE),
    alg(c"ARIA-192-CFB1", &aria192cfb1::TABLE),
    alg(c"ARIA-128-CFB1", &aria128cfb1::TABLE),
    alg(c"ARIA-256-CFB8", &aria256cfb8::TABLE),
    alg(c"ARIA-192-CFB8", &aria192cfb8::TABLE),
    alg(c"ARIA-128-CFB8", &aria128cfb8::TABLE),
    alg(c"ARIA-256-CTR:1.2.410.200046.1.1.15", &aria256ctr::TABLE),
    alg(c"ARIA-192-CTR:1.2.410.200046.1.1.10", &aria192ctr::TABLE),
    alg(c"ARIA-128-CTR:1.2.410.200046.1.1.5", &aria128ctr::TABLE),
    alg(
        c"CAMELLIA-256-ECB:0.3.4401.5.3.1.9.41",
        &camellia256ecb::TABLE,
    ),
    alg(
        c"CAMELLIA-192-ECB:0.3.4401.5.3.1.9.21",
        &camellia192ecb::TABLE,
    ),
    alg(
        c"CAMELLIA-128-ECB:0.3.4401.5.3.1.9.1",
        &camellia128ecb::TABLE,
    ),
    alg(
        c"CAMELLIA-256-CBC:CAMELLIA256:1.2.392.200011.61.1.1.1.4",
        &camellia256cbc::TABLE,
    ),
    alg(
        c"CAMELLIA-192-CBC:CAMELLIA192:1.2.392.200011.61.1.1.1.3",
        &camellia192cbc::TABLE,
    ),
    alg(
        c"CAMELLIA-128-CBC:CAMELLIA128:1.2.392.200011.61.1.1.1.2",
        &camellia128cbc::TABLE,
    ),
    alg(
        c"CAMELLIA-256-OFB:0.3.4401.5.3.1.9.43",
        &camellia256ofb::TABLE,
    ),
    alg(
        c"CAMELLIA-192-OFB:0.3.4401.5.3.1.9.23",
        &camellia192ofb::TABLE,
    ),
    alg(
        c"CAMELLIA-128-OFB:0.3.4401.5.3.1.9.3",
        &camellia128ofb::TABLE,
    ),
    alg(
        c"CAMELLIA-256-CFB:0.3.4401.5.3.1.9.44",
        &camellia256cfb::TABLE,
    ),
    alg(
        c"CAMELLIA-192-CFB:0.3.4401.5.3.1.9.24",
        &camellia192cfb::TABLE,
    ),
    alg(
        c"CAMELLIA-128-CFB:0.3.4401.5.3.1.9.4",
        &camellia128cfb::TABLE,
    ),
    alg(c"CAMELLIA-256-CFB1", &camellia256cfb1::TABLE),
    alg(c"CAMELLIA-192-CFB1", &camellia192cfb1::TABLE),
    alg(c"CAMELLIA-128-CFB1", &camellia128cfb1::TABLE),
    alg(c"CAMELLIA-256-CFB8", &camellia256cfb8::TABLE),
    alg(c"CAMELLIA-192-CFB8", &camellia192cfb8::TABLE),
    alg(c"CAMELLIA-128-CFB8", &camellia128cfb8::TABLE),
    alg(
        c"CAMELLIA-256-CTR:0.3.4401.5.3.1.9.49",
        &camellia256ctr::TABLE,
    ),
    alg(
        c"CAMELLIA-192-CTR:0.3.4401.5.3.1.9.29",
        &camellia192ctr::TABLE,
    ),
    alg(
        c"CAMELLIA-128-CTR:0.3.4401.5.3.1.9.9",
        &camellia128ctr::TABLE,
    ),
    alg(c"DES-EDE3-ECB:DES-EDE3", &tdes_ede3_ecb::TABLE),
    alg(
        c"DES-EDE3-CBC:DES3:1.2.840.113549.3.7",
        &tdes_ede3_cbc::TABLE,
    ),
    alg(c"DES-EDE3-OFB", &tdes_ede3_ofb::TABLE),
    alg(c"DES-EDE3-CFB", &tdes_ede3_cfb::TABLE),
    alg(c"DES-EDE3-CFB8", &tdes_ede3_cfb8::TABLE),
    alg(c"DES-EDE3-CFB1", &tdes_ede3_cfb1::TABLE),
    alg(c"DES-EDE-ECB:DES-EDE:1.3.14.3.2.17", &tdes_ede2_ecb::TABLE),
    alg(c"DES-EDE-CBC", &tdes_ede2_cbc::TABLE),
    alg(c"DES-EDE-OFB", &tdes_ede2_ofb::TABLE),
    alg(c"DES-EDE-CFB", &tdes_ede2_cfb::TABLE),
    alg(c"SM4-ECB:1.2.156.10197.1.104.1", &sm4128ecb::TABLE),
    alg(c"SM4-CBC:SM4:1.2.156.10197.1.104.2", &sm4128cbc::TABLE),
    alg(c"SM4-CTR:1.2.156.10197.1.104.7", &sm4128ctr::TABLE),
    alg(
        c"SM4-OFB:SM4-OFB128:1.2.156.10197.1.104.3",
        &sm4128ofb128::TABLE,
    ),
    alg(
        c"SM4-CFB:SM4-CFB128:1.2.156.10197.1.104.4",
        &sm4128cfb128::TABLE,
    ),
    alg(c"ChaCha20", &chacha20::TABLE),
    ALG_END,
]);

/// The default provider's cipher table.
pub(crate) fn default_ciphers() -> *const OSSL_ALGORITHM {
    DEFAULT_CIPHERS.0.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL input with a length, or a NULL output where there's output,
    /// fails instead of crashing.
    #[test]
    fn null_buffers_are_refused() {
        // SAFETY: no preconditions.
        let ctx = unsafe { aes128cbc::newctx(ptr::null_mut()) };
        let key = [1u8; 16];
        let iv = [2u8; 16];
        // SAFETY: a live context, a key and IV of their lengths, and no parameters.
        let r = unsafe { generic_einit(ctx, key.as_ptr(), 16, iv.as_ptr(), 16, ptr::null()) };
        assert_eq!(r, 1);
        let mut outl = 0usize;
        // SAFETY: NULL input with a length, the case under test.
        let r = unsafe { update(ctx, ptr::null_mut(), &raw mut outl, 32, ptr::null(), 16) };
        assert_eq!(r, 0);
        let data = [0u8; 16];
        // SAFETY: NULL output for a whole block, the case under test.
        let r = unsafe { update(ctx, ptr::null_mut(), &raw mut outl, 32, data.as_ptr(), 16) };
        assert_eq!(r, 0);
        // SAFETY: the context from `newctx`.
        unsafe { freectx(ctx) };
    }
}
