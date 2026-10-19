//! The legacy provider's RC4-HMAC-MD5 (`ossl_rc4_hmac_ossl_md5_functions`): the dispatch table
//! over `rustyssl_crypto::provided::rc4_hmac_md5`, with the reference's parameters (`keylen`
//! and `ivlen`, which can't change; `tls1-aad`, written back with a decrypted record's payload
//! length; `mackey`; `tls-version`; `tls-aad-pad`) and its generic stream functions.

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, OSSL_CIPHER_PARAM_AEAD_MAC_KEY, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
    OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_KEYLEN,
    OSSL_CIPHER_PARAM_TLS_VERSION, OSSL_FUNC_CIPHER_CIPHER, OSSL_FUNC_CIPHER_DECRYPT_INIT,
    OSSL_FUNC_CIPHER_DUPCTX, OSSL_FUNC_CIPHER_ENCRYPT_INIT, OSSL_FUNC_CIPHER_FINAL,
    OSSL_FUNC_CIPHER_FREECTX, OSSL_FUNC_CIPHER_GET_CTX_PARAMS, OSSL_FUNC_CIPHER_GET_PARAMS,
    OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
    OSSL_FUNC_CIPHER_NEWCTX, OSSL_FUNC_CIPHER_SET_CTX_PARAMS, OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_CIPHER_UPDATE, OSSL_PARAM, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    PROV_R_CIPHER_OPERATION_FAILED, PROV_R_FAILED_TO_GET_PARAMETER, PROV_R_INVALID_DATA,
    PROV_R_INVALID_IV_LENGTH, PROV_R_INVALID_KEY_LENGTH, PROV_R_NO_KEY_SET,
    PROV_R_OUTPUT_BUFFER_TOO_SMALL,
};
use rustyssl_crypto::provided::rc4_hmac_md5::Ctx;

use super::ciphers::{
    CtxParamsFn, DupFn, FinalFn, FreeFn, GetCtxFn, GetParamsFn, GettableFn, Info, InitFn, NewCtxFn,
    SIZE_T, SetCtxFn, UpdateFn, Value, generic_gettable_params, get_param, get_params_of, get_size,
    get_uint, set_param,
};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::ffi::ffi_callback;
use crate::params::OSSL_PARAM_locate_const;

/// The algorithm context behind `vctx`, or `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a context `newctx` made and `freectx` hasn't freed.
unsafe fn context<'a>(vctx: *mut c_void) -> Option<&'a mut Ctx> {
    // SAFETY: the caller's guarantee: a box from `newctx`, used by one caller at a time.
    unsafe { vctx.cast::<Ctx>().as_mut() }
}

fn raise(reason: c_int, function: &str) {
    err::raise(ERR_LIB_PROV, reason, function);
}

/// `rc4_hmac_md5_get_params`: a stream AEAD with a 16-octet key and no IV.
const INFO: Info = Info {
    mode: 0,
    aead: true,
    custom_iv: false,
    cts: false,
    multiblock: false,
    rand_key: false,
    key_len: 16,
    block_size: 1,
    iv_len: 0,
};

ffi_callback! {
    /// `rc4_hmac_md5_newctx`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn newctx(_provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        Box::into_raw(Box::new(Ctx::new())).cast()
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context `newctx` made, not used afterwards.
    pub(crate) unsafe extern "C" fn freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee: a box from `newctx`.
            drop(unsafe { Box::from_raw(vctx.cast::<Ctx>()) });
        }
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_dupctx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { context(vctx) }.map_or(ptr::null_mut(), |c| Box::into_raw(Box::new(c.clone())).cast())
    }
}

/// `ossl_cipher_generic_einit`/`dinit` with no parameters, then `rc4_hmac_md5_set_ctx_params`.
///
/// # Safety
/// `vctx` is a live context; `key` and `iv` are NULL or hold `keylen` and `ivlen` octets;
/// `params` is NULL or a parameter array.
unsafe fn init(
    vctx: *mut c_void,
    (key, keylen): (*const u8, usize),
    (iv, ivlen): (*const u8, usize),
    params: *const OSSL_PARAM,
    enc: bool,
) -> c_int {
    const F: &str = "cipher_generic_init_internal";
    // SAFETY: the caller's guarantee.
    let Some(ctx) = (unsafe { context(vctx) }) else {
        return 0;
    };
    // `ossl_cipher_generic_initiv`: the IV must have the cipher's length, none.
    if !iv.is_null() && ivlen != 0 {
        raise(PROV_R_INVALID_IV_LENGTH, F);
        return 0;
    }
    let key = if key.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { core::slice::from_raw_parts(key, keylen) })
    };
    if ctx.init(enc, key).is_err() {
        raise(PROV_R_INVALID_KEY_LENGTH, F);
        return 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { set_ctx_params(vctx, params) }
}

ffi_callback! {
    /// `rc4_hmac_md5_einit`.
    ///
    /// # Safety
    /// As for `init`.
    pub(crate) unsafe extern "C" fn einit(vctx: *mut c_void, key: *const u8, keylen: usize, iv: *const u8, ivlen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, (key, keylen), (iv, ivlen), params, true) }
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_dinit`.
    ///
    /// # Safety
    /// As for `init`.
    pub(crate) unsafe extern "C" fn dinit(vctx: *mut c_void, key: *const u8, keylen: usize, iv: *const u8, ivlen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { init(vctx, (key, keylen), (iv, ivlen), params, false) }
    }
}

/// `ossl_cipher_generic_stream_update` (with `tls`) and `ossl_cipher_generic_cipher`: the
/// cipher over `inl` octets, a decrypted record's length less its MAC under a TLS version.
///
/// # Safety
/// `vctx` is a live context; `in_` holds `inl` octets; `out` has room for `outsize`; `outl`
/// is valid for a write.
unsafe fn process(
    vctx: *mut c_void,
    out: *mut u8,
    outl: *mut usize,
    outsize: usize,
    in_: *const u8,
    inl: usize,
    tls: bool,
) -> c_int {
    const F: &str = "ossl_cipher_generic_stream_update";
    // SAFETY: the caller's guarantee.
    let Some(ctx) = (unsafe { context(vctx) }) else {
        return 0;
    };
    if !ctx.key_set() {
        raise(PROV_R_NO_KEY_SET, F);
        return 0;
    }
    if inl == 0 && tls {
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(0) };
        return 1;
    }
    if outsize < inl {
        raise(PROV_R_OUTPUT_BUFFER_TOO_SMALL, F);
        return 0;
    }
    let mut data = if inl == 0 {
        Vec::new()
    } else {
        // SAFETY: the caller's guarantee: `inl` octets of input (which may be the output).
        unsafe { core::slice::from_raw_parts(in_, inl) }.to_vec()
    };
    if ctx.cipher(&mut data).is_err() {
        raise(PROV_R_CIPHER_OPERATION_FAILED, F);
        return 0;
    }
    if inl > 0 {
        // SAFETY: the caller's room for `outsize` octets, at least `inl`.
        unsafe { ptr::copy(data.as_ptr(), out, inl) };
    }
    let mut n = inl;
    if tls && !ctx.encrypting() && ctx.tls_version > 0 {
        // `removetlsfixed`: the MAC (MD5's length), which the cipher checked.
        let Some(m) = n.checked_sub(16) else { return 0 };
        n = m;
    }
    // SAFETY: the caller's guarantee.
    unsafe { outl.write(n) };
    1
}

ffi_callback! {
    /// `rc4_hmac_md5_update` (`ossl_cipher_generic_stream_update`).
    ///
    /// # Safety
    /// As for `process`.
    pub(crate) unsafe extern "C" fn update(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize, in_: *const u8, inl: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { process(vctx, out, outl, outsize, in_, inl, true) }
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_cipher` (`ossl_cipher_generic_cipher`).
    ///
    /// # Safety
    /// As for `process`.
    pub(crate) unsafe extern "C" fn cipher(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize, in_: *const u8, inl: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { process(vctx, out, outl, outsize, in_, inl, false) }
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_final` (`ossl_cipher_generic_stream_final`): nothing more.
    ///
    /// # Safety
    /// `vctx` is a live context; `outl` is valid for a write.
    pub(crate) unsafe extern "C" fn final_(vctx: *mut c_void, _out: *mut u8, outl: *mut usize, _outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        if !ctx.key_set() {
            raise(PROV_R_NO_KEY_SET, "ossl_cipher_generic_stream_final");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(0) };
        1
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_get_params`.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn get_params(params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { get_params_of(INFO, params) }
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_get_ctx_params`: the key and IV lengths, and `tls-aad-pad`.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "rc4_hmac_md5_get_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        for (key, value) in [
            (OSSL_CIPHER_PARAM_KEYLEN, ctx.key_len()),
            (OSSL_CIPHER_PARAM_IVLEN, 0),
            (OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, ctx.tls_aad_pad),
        ] {
            // SAFETY: the caller's array.
            if !unsafe { set_param(params, key, F, Value::Size(value)) } {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_set_ctx_params`: `keylen` and `ivlen` (which must stay), `tls1-aad`,
    /// `mackey`, `tls-version`.
    ///
    /// # Safety
    /// `vctx` is a live context; `params` is NULL or a parameter array whose `tls1-aad` data
    /// may be written.
    pub(crate) unsafe extern "C" fn set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "rc4_hmac_md5_set_ctx_params";
        // SAFETY: the caller's array.
        if unsafe { params.as_ref() }.is_none_or(|p| p.key.is_null()) {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        for (key, want, reason) in [
            (OSSL_CIPHER_PARAM_KEYLEN, ctx.key_len(), PROV_R_INVALID_KEY_LENGTH),
            (OSSL_CIPHER_PARAM_IVLEN, 0, PROV_R_INVALID_IV_LENGTH),
        ] {
            // SAFETY: the caller's array.
            match unsafe { get_param(params, key, F, get_size) } {
                Err(()) => return 0,
                Ok(Some(n)) if n != want => {
                    raise(reason, F);
                    return 0;
                }
                _ => {}
            }
        }
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD.as_ptr()) };
        // SAFETY: a located parameter, or NULL.
        if let Some(p) = unsafe { p.as_ref() } {
            if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
                raise(PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
            let aad: &mut [u8] = if p.data.is_null() {
                &mut []
            } else {
                // SAFETY: the parameter's octets, `data_size` of them; the reference writes
                // the payload length back into them.
                unsafe { core::slice::from_raw_parts_mut(p.data.cast::<u8>(), p.data_size) }
            };
            let Some(pad) = ctx.tls_init(aad) else {
                raise(PROV_R_INVALID_DATA, F);
                return 0;
            };
            ctx.tls_aad_pad = pad;
        }
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_MAC_KEY.as_ptr()) };
        // SAFETY: as above.
        if let Some(p) = unsafe { p.as_ref() } {
            if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
                raise(PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
            let key: &[u8] = if p.data.is_null() {
                &[]
            } else {
                // SAFETY: as above.
                unsafe { core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) }
            };
            ctx.set_mac_key(key);
        }
        // SAFETY: as above.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_TLS_VERSION, F, get_uint) } {
            Err(()) => return 0,
            Ok(Some(v)) => ctx.tls_version = v,
            Ok(None) => {}
        }
        1
    }
}

static GETTABLE_CTX: Params<4> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    PARAM_END,
]);

static SETTABLE_CTX: Params<4> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `rc4_hmac_md5_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn gettable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `rc4_hmac_md5_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE_CTX.0.as_ptr()
    }
}

/// `ossl_rc4_hmac_ossl_md5_functions`.
pub(crate) static TABLE: Dispatch<15> = Dispatch([
    entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
    entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
    entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
    entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, einit, InitFn),
    entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, dinit, InitFn),
    entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
    entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
    entry!(OSSL_FUNC_CIPHER_CIPHER, cipher, UpdateFn),
    entry!(OSSL_FUNC_CIPHER_GET_PARAMS, get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        generic_gettable_params,
        GettableFn
    ),
    entry!(OSSL_FUNC_CIPHER_GET_CTX_PARAMS, get_ctx_params, GetCtxFn),
    entry!(
        OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        gettable_ctx_params,
        CtxParamsFn
    ),
    entry!(OSSL_FUNC_CIPHER_SET_CTX_PARAMS, set_ctx_params, SetCtxFn),
    entry!(
        OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        settable_ctx_params,
        CtxParamsFn
    ),
    END,
]);
