//! The default provider's SM2 encryption (`sm2_enc.c`): encrypting and decrypting with an SM2
//! key (`crate::ec::sm2_crypt`), with the digest the context is given (SM3 unless another is
//! named, fetched on first use and then reported), and the size queries.
//!
//! As in OpenSSL, the operations take the caller's room from the output length, not from the
//! output size the EVP layer passes.

use core::ffi::{CStr, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    EC_KEY, ERR_LIB_PROV, EVP_MD, OSSL_ASYM_CIPHER_PARAM_DIGEST, OSSL_ASYM_CIPHER_PARAM_ENGINE,
    OSSL_ASYM_CIPHER_PARAM_PROPERTIES, OSSL_FUNC_ASYM_CIPHER_DECRYPT,
    OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, OSSL_FUNC_ASYM_CIPHER_DUPCTX,
    OSSL_FUNC_ASYM_CIPHER_ENCRYPT, OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT,
    OSSL_FUNC_ASYM_CIPHER_FREECTX, OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
    OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_ASYM_CIPHER_NEWCTX,
    OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, OSSL_LIB_CTX,
    OSSL_PARAM, OSSL_PARAM_UTF8_STRING, PROV_R_INVALID_KEY,
};

use super::builtin::libctx_of;
use super::macs::{Prov, boxed, context, is_empty, unbox};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ec::key::{EC_KEY_free, EC_KEY_up_ref};
use crate::ec::sm2_crypt::{ciphertext_size, decrypt, encrypt, plaintext_size};
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_get0_name};
use crate::ffi::{bytes, ffi_callback};
use crate::params::{OSSL_PARAM_locate, OSSL_PARAM_set_utf8_string};

/// `PROV_SM2_CTX` (encryption).
struct Sm2EncCtx {
    libctx: *mut OSSL_LIB_CTX,
    /// The key, with a reference this holds, or NULL.
    key: *mut EC_KEY,
    md: Prov<EVP_MD>,
}

impl Drop for Sm2EncCtx {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { EC_KEY_free(self.key) };
    }
}

/// The context behind `vctx`.
///
/// # Safety
/// `vctx` is NULL or a live context from `sm2_newctx`.
unsafe fn ctx<'a>(vctx: *mut c_void) -> Option<&'a mut Sm2EncCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { context::<Sm2EncCtx>(vctx) }
}

impl Sm2EncCtx {
    /// `sm2_get_md`: the digest given, or SM3, fetched and kept.
    fn md(&mut self) -> *const EVP_MD {
        if self.md.method.is_null() {
            // SAFETY: the context's library context; a static name.
            self.md.method = unsafe { EVP_MD_fetch(self.libctx, c"SM3".as_ptr(), ptr::null()) };
        }
        self.md.method
    }
}

ffi_callback! {
    /// `sm2_newctx`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn sm2_enc_newctx(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Sm2EncCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            key: ptr::null_mut(),
            md: Prov::NONE,
        })
    }
}

ffi_callback! {
    /// `sm2_init`: the key, then the parameters.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `vkey` is NULL or a live EC key; `params` is NULL or
    /// an array.
    pub(crate) unsafe extern "C" fn sm2_enc_init(vctx: *mut c_void, vkey: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's key, if any.
        if vkey.is_null() || unsafe { EC_KEY_up_ref(vkey.cast()) } == 0 {
            return 0;
        }
        // SAFETY: the reference the context held, or NULL.
        unsafe { EC_KEY_free(c.key) };
        c.key = vkey.cast();
        // SAFETY: the caller's guarantee.
        unsafe { sm2_enc_set_ctx_params(vctx, params) }
    }
}

ffi_callback! {
    /// `sm2_asym_encrypt`: the ciphertext, or its largest size for NULL `out`.
    ///
    /// # Safety
    /// `vctx` is a live context; `out` is NULL or has room for `*outlen` octets; `outlen` is
    /// readable and writable; `in_` holds `inlen` octets.
    pub(crate) unsafe extern "C" fn sm2_asym_encrypt(vctx: *mut c_void, out: *mut c_uchar, outlen: *mut usize, _outsize: usize, in_: *const c_uchar, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let md = c.md();
        if md.is_null() {
            return 0;
        }
        if out.is_null() {
            // SAFETY: the context's key; the digest.
            let Some(n) = (unsafe { ciphertext_size(c.key, md, inlen) }) else {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, "sm2_asym_encrypt");
                return 0;
            };
            // SAFETY: the caller's guarantee.
            unsafe { outlen.write(n) };
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(msg) = (unsafe { bytes(in_, inlen) }) else { return 0 };
        // SAFETY: the context's key; the digest; the caller's room and length.
        c_int::from(unsafe { encrypt(c.key, md, msg, out, outlen) })
    }
}

ffi_callback! {
    /// `sm2_asym_decrypt`: the message, or its size for NULL `out`.
    ///
    /// # Safety
    /// As for `sm2_asym_encrypt`.
    pub(crate) unsafe extern "C" fn sm2_asym_decrypt(vctx: *mut c_void, out: *mut c_uchar, outlen: *mut usize, _outsize: usize, in_: *const c_uchar, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        let md = c.md();
        if md.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(ct) = (unsafe { bytes(in_, inlen) }) else { return 0 };
        if out.is_null() {
            let Some(n) = plaintext_size(ct) else { return 0 };
            // SAFETY: the caller's guarantee.
            unsafe { outlen.write(n) };
            return 1;
        }
        // SAFETY: the context's key; the digest; the caller's room and length.
        c_int::from(unsafe { decrypt(c.key, md, ct, out, outlen) })
    }
}

ffi_callback! {
    /// `sm2_freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context the caller gives up.
    pub(crate) unsafe extern "C" fn sm2_enc_freectx(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Sm2EncCtx>(vctx) };
    }
}

ffi_callback! {
    /// `sm2_dupctx`: a reference to the key and the digest.
    ///
    /// # Safety
    /// `vctx` is NULL or a live context.
    pub(crate) unsafe extern "C" fn sm2_enc_dupctx(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return ptr::null_mut() };
        // SAFETY: the context's key, or NULL.
        if !c.key.is_null() && unsafe { EC_KEY_up_ref(c.key) } == 0 {
            return ptr::null_mut();
        }
        let copy = Sm2EncCtx { libctx: c.libctx, key: c.key, md: Prov::NONE };
        let Some(md) = c.md.copy() else {
            drop(copy);
            return ptr::null_mut();
        };
        boxed(Sm2EncCtx { md, ..copy })
    }
}

ffi_callback! {
    /// `sm2_get_ctx_params`: the digest's name ("" before one is given or used).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2_enc_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_DIGEST.as_ptr()) };
        if !p.is_null() {
            let name = if c.md.method.is_null() {
                c"".as_ptr()
            } else {
                // SAFETY: the context's digest.
                unsafe { EVP_MD_get0_name(c.md.method) }
            };
            // SAFETY: a parameter of the array; a string.
            if unsafe { OSSL_PARAM_set_utf8_string(p, name) } != 1 {
                return 0;
            }
        }
        1
    }
}

/// `known_gettable_ctx_params`.
static GETTABLE: Params<2> = Params([
    defn(OSSL_ASYM_CIPHER_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `sm2_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sm2_enc_gettable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `sm2_set_ctx_params`: the digest, with its properties (`ossl_prov_digest_load_from_params`).
    ///
    /// # Safety
    /// `vctx` is NULL or a live context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn sm2_enc_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { ctx(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let key: &CStr = OSSL_ASYM_CIPHER_PARAM_DIGEST;
        // SAFETY: the caller's array; the provider's library context.
        c_int::from(unsafe { c.md.load(params, key, c.libctx) })
    }
}

/// `known_settable_ctx_params`.
static SETTABLE: Params<4> = Params([
    defn(OSSL_ASYM_CIPHER_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_ASYM_CIPHER_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_ASYM_CIPHER_PARAM_ENGINE, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `sm2_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn sm2_enc_settable_ctx_params(_vctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type CryptFn = unsafe extern "C" fn(
    *mut c_void,
    *mut c_uchar,
    *mut usize,
    usize,
    *const c_uchar,
    usize,
) -> c_int;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

/// `ossl_sm2_asym_cipher_functions`.
pub(crate) static SM2_ASYM_CIPHER: Dispatch<12> = Dispatch([
    entry!(OSSL_FUNC_ASYM_CIPHER_NEWCTX, sm2_enc_newctx, NewCtxFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, sm2_enc_init, InitFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_ENCRYPT, sm2_asym_encrypt, CryptFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, sm2_enc_init, InitFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_DECRYPT, sm2_asym_decrypt, CryptFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_FREECTX, sm2_enc_freectx, FreeCtxFn),
    entry!(OSSL_FUNC_ASYM_CIPHER_DUPCTX, sm2_enc_dupctx, DupCtxFn),
    entry!(
        OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
        sm2_enc_get_ctx_params,
        GetParamsFn
    ),
    entry!(
        OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
        sm2_enc_gettable_ctx_params,
        ListFn
    ),
    entry!(
        OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
        sm2_enc_set_ctx_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
        sm2_enc_settable_ctx_params,
        ListFn
    ),
    END,
]);
