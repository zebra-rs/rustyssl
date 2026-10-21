//! The default provider's other modes on the generic cipher context: CBC with ciphertext
//! stealing (`cipher_cts.c`, AES and Camellia), XTS (`cipher_aes_xts.c`, `cipher_sm4_xts.c`),
//! the AES key wraps and their inverses (`cipher_aes_wrp.c`), triple DES's key wrap
//! (`cipher_tdes_wrap.c`), and the AES-CBC-HMAC composites (`cipher_aes_cbc_hmac_sha.c`),
//! each with the reference's dispatch table and parameter lists, over
//! `rustyssl_crypto::provided::cipher`.
//!
//! What the reference would crash on (a NULL string or octet parameter it reads) fails here
//! instead (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PROV, OSSL_CIPHER_CTS_MODE_CS1, OSSL_CIPHER_CTS_MODE_CS2, OSSL_CIPHER_CTS_MODE_CS3,
    OSSL_CIPHER_HMAC_PARAM_MAC, OSSL_CIPHER_PARAM_AEAD_MAC_KEY, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
    OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, OSSL_CIPHER_PARAM_CTS_MODE, OSSL_CIPHER_PARAM_IV,
    OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_KEYLEN, OSSL_CIPHER_PARAM_NUM,
    OSSL_CIPHER_PARAM_PADDING, OSSL_CIPHER_PARAM_TLS_VERSION,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, OSSL_CIPHER_PARAM_UPDATED_IV,
    OSSL_CIPHER_PARAM_XTS_STANDARD, OSSL_FUNC_CIPHER_CIPHER, OSSL_FUNC_CIPHER_DECRYPT_INIT,
    OSSL_FUNC_CIPHER_DUPCTX, OSSL_FUNC_CIPHER_ENCRYPT_INIT, OSSL_FUNC_CIPHER_FINAL,
    OSSL_FUNC_CIPHER_FREECTX, OSSL_FUNC_CIPHER_GET_CTX_PARAMS, OSSL_FUNC_CIPHER_GET_PARAMS,
    OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
    OSSL_FUNC_CIPHER_NEWCTX, OSSL_FUNC_CIPHER_SET_CTX_PARAMS, OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_CIPHER_UPDATE, OSSL_PARAM, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER,
    OSSL_PARAM_UTF8_STRING, PROV_R_FAILED_TO_GET_PARAMETER, PROV_R_FAILED_TO_SET_PARAMETER,
    PROV_R_INVALID_KEY_LENGTH,
};
use rustyssl_crypto::provided::cipher::{ETM_MAX_TAG, Kind, Mode, TLS1_AAD_LEN};
use rustyssl_crypto::sym::BlockAlgorithm::{self, Aes, Camellia, Sm4, TripleDes};

use super::ciphers::{
    CtxParamsFn, DupFn, FinalFn, FreeFn, GetCtxFn, GetParamsFn, GettableFn, InitFn, NewCtxFn,
    SIZE_T, SetCtxFn, UINT, UpdateFn, Value, cipher, context, dupctx, final_, freectx,
    generic_get_ctx_params, generic_get_params, generic_gettable_params, generic_set_ctx_params,
    get_param, get_size, get_uint, init_core, is_empty, new_context, raise, set_param, update,
};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::ffi::ffi_callback;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_locate,
    OSSL_PARAM_locate_const,
};
use crate::string::OPENSSL_strcasecmp;

/// A block mode of `algorithm` with `key_len` octets of key.
const fn block(algorithm: BlockAlgorithm, key_len: usize, mode: Mode) -> Kind {
    Kind::Block {
        algorithm,
        key_len,
        mode,
    }
}

/// The parameter `key` of `params`, if there is one.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn locate<'a>(params: *const OSSL_PARAM, key: &CStr) -> Option<&'a OSSL_PARAM> {
    // SAFETY: the caller's array.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    // SAFETY: a parameter of the array, or NULL.
    unsafe { p.as_ref() }
}

/// A parameter's octets (`data_size` of them), `None` for NULL data with a size.
///
/// # Safety
/// The parameter's data holds `data_size` octets.
unsafe fn octets<'a>(p: &OSSL_PARAM) -> Option<&'a [u8]> {
    if p.data_size == 0 {
        return Some(&[]);
    }
    if p.data.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) })
}

/// Whether the parameter's type is `t`.
fn typed(p: &OSSL_PARAM, t: c_int) -> bool {
    p.data_type == t.cast_unsigned()
}

/// `keylen` may only be set to what it is: a failure to read it raises, a different value
/// fails `silently` or with `PROV_R_INVALID_KEY_LENGTH`.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn same_keylen(params: *const OSSL_PARAM, keylen: usize, silently: bool, f: &str) -> bool {
    // SAFETY: the caller's array.
    match unsafe { get_param(params, OSSL_CIPHER_PARAM_KEYLEN, f, get_size) } {
        Err(()) => false,
        Ok(Some(n)) if n != keylen => {
            if !silently {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, f);
            }
            false
        }
        Ok(_) => true,
    }
}

macro_rules! inits {
    ($einit:ident, $dinit:ident, $set:ident) => {
        ffi_callback! {
            /// `einit`: the key and IV, then the mode's parameters.
            ///
            /// # Safety
            /// `vctx` is a live algorithm context; `key` and `iv` are NULL or hold `keylen`
            /// and `ivlen` octets; `params` is NULL or a parameter array.
            pub(crate) unsafe extern "C" fn $einit(vctx: *mut c_void, key: *const u8, keylen: usize, iv: *const u8, ivlen: usize, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                if unsafe { init_core(vctx, (key, keylen), (iv, ivlen), true) } == 0 {
                    return 0;
                }
                // SAFETY: the caller's guarantee.
                unsafe { $set(vctx, params) }
            }
        }

        ffi_callback! {
            /// `dinit`: likewise, decrypting.
            ///
            /// # Safety
            /// As for the `einit`.
            pub(crate) unsafe extern "C" fn $dinit(vctx: *mut c_void, key: *const u8, keylen: usize, iv: *const u8, ivlen: usize, params: *const OSSL_PARAM) -> c_int
            where failure = 0, library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                if unsafe { init_core(vctx, (key, keylen), (iv, ivlen), false) } == 0 {
                    return 0;
                }
                // SAFETY: the caller's guarantee.
                unsafe { $set(vctx, params) }
            }
        }
    };
}

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

/// `newctx` and `get_params` for a cipher of `$kind`, with `$table` the rest.
macro_rules! cipher_mod {
    ($name:ident, $kind:expr, $table:ident) => {
        pub(crate) mod $name {
            use super::*;

            ffi_callback! {
                /// `newctx`.
                ///
                /// # Safety
                /// No preconditions.
                pub(crate) unsafe extern "C" fn newctx(provctx: *mut c_void) -> *mut c_void
                where failure = ptr::null_mut(), library = ERR_LIB_PROV
                {
                    // SAFETY: the provider's context.
                    unsafe { new_context($kind, provctx) }
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

            $table!();
        }
    };
}

// -------------------------------------------------------------------------------------------
// CTS

/// `cts_modes`: the variants' names by their numbers.
const CTS_MODES: [&CStr; 3] = [
    OSSL_CIPHER_CTS_MODE_CS1,
    OSSL_CIPHER_CTS_MODE_CS2,
    OSSL_CIPHER_CTS_MODE_CS3,
];

ffi_callback! {
    /// `aes_cbc_cts_get_ctx_params` (Camellia's likewise): `cts_mode`, then the generic ones.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn cts_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "aes_cbc_cts_get_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let Some(g) = ctx.core.generic() else { return 0 };
        let name = CTS_MODES.get(usize::from(g.cts_mode())).copied();
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS_MODE.as_ptr()) };
        if !p.is_null() {
            // SAFETY: a parameter of the array and a static string.
            let ok = name.is_some_and(|n| (unsafe { crate::params::OSSL_PARAM_set_utf8_string(p, n.as_ptr()) }) != 0);
            if !ok {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, F);
                return 0;
            }
        }
        // SAFETY: the caller's guarantee.
        unsafe { generic_get_ctx_params(vctx, params) }
    }
}

ffi_callback! {
    /// `aes_cbc_cts_set_ctx_params`: `cts_mode` (CS1, CS2, or CS3, without regard to case),
    /// then the generic ones.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array, a
    /// string parameter's data a string.
    pub(crate) unsafe extern "C" fn cts_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "aes_cbc_cts_set_ctx_params";
        // SAFETY: the caller's guarantee.
        if let Some(p) = unsafe { locate(params, OSSL_CIPHER_PARAM_CTS_MODE) } {
            let id = if typed(p, OSSL_PARAM_UTF8_STRING) && !p.data.is_null() {
                CTS_MODES.iter().position(|n| {
                    // SAFETY: the caller's guarantee: a string; a static one.
                    (unsafe { OPENSSL_strcasecmp(p.data.cast::<c_char>(), n.as_ptr()) }) == 0
                })
            } else {
                None
            };
            // SAFETY: the caller's guarantee.
            let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
            match (id.and_then(|i| u8::try_from(i).ok()), ctx.core.generic_mut()) {
                (Some(id), Some(g)) => g.set_cts_mode(id),
                _ => {
                    err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, F);
                    return 0;
                }
            }
        }
        // SAFETY: the caller's guarantee.
        unsafe { generic_set_ctx_params(vctx, params) }
    }
}

inits!(cts_einit, cts_dinit, cts_set_ctx_params);

static CTS_GETTABLE: Params<8> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_CTS_MODE, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);
static CTS_SETTABLE: Params<4> = Params([
    defn(OSSL_CIPHER_PARAM_PADDING, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_NUM, OSSL_PARAM_UNSIGNED_INTEGER, UINT),
    defn(OSSL_CIPHER_PARAM_CTS_MODE, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);
list!(cts_gettable_ctx_params, CTS_GETTABLE);
list!(cts_settable_ctx_params, CTS_SETTABLE);

/// `IMPLEMENT_cts_cipher`'s table.
macro_rules! cts {
    () => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, cts_einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, cts_dinit, InitFn),
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
                cts_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                cts_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                cts_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                cts_settable_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

cipher_mod!(aes256cbc_cts, block(Aes, 32, Mode::CbcCts), cts);
cipher_mod!(aes192cbc_cts, block(Aes, 24, Mode::CbcCts), cts);
cipher_mod!(aes128cbc_cts, block(Aes, 16, Mode::CbcCts), cts);
cipher_mod!(camellia256cbc_cts, block(Camellia, 32, Mode::CbcCts), cts);
cipher_mod!(camellia192cbc_cts, block(Camellia, 24, Mode::CbcCts), cts);
cipher_mod!(camellia128cbc_cts, block(Camellia, 16, Mode::CbcCts), cts);

// -------------------------------------------------------------------------------------------
// XTS

ffi_callback! {
    /// `aes_xts_set_ctx_params`: `keylen` may only be set to what it is.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn xts_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let keylen = ctx.core.generic().map_or(0, |g| g.key_len());
        // SAFETY: the caller's array.
        c_int::from(unsafe { same_keylen(params, keylen, true, "aes_xts_set_ctx_params") })
    }
}

ffi_callback! {
    /// `sm4_xts_set_ctx_params`: `xts_standard`, "GB" (GB/T 17964-2021) or "IEEE" (IEEE
    /// 1619), without regard to case.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array, a
    /// string parameter's data a string.
    pub(crate) unsafe extern "C" fn sm4_xts_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "sm4_xts_set_ctx_params";
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { locate(params, OSSL_CIPHER_PARAM_XTS_STANDARD) }) else {
            return 1;
        };
        if !typed(p, OSSL_PARAM_UTF8_STRING) {
            return 0;
        }
        let mut s: *const c_char = ptr::null();
        // SAFETY: a parameter of the array and a local.
        if unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &raw mut s) } == 0 || s.is_null() {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            return 0;
        }
        // SAFETY: the parameter's string; static strings.
        let ieee = if unsafe { OPENSSL_strcasecmp(s, c"GB".as_ptr()) } == 0 {
            false
        // SAFETY: as above.
        } else if unsafe { OPENSSL_strcasecmp(s, c"IEEE".as_ptr()) } == 0 {
            true
        } else {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, F);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        if let Some(g) = ctx.core.generic_mut() {
            g.set_xts_ieee(ieee);
        }
        1
    }
}

inits!(xts_einit, xts_dinit, xts_set_ctx_params);
inits!(sm4_xts_einit, sm4_xts_dinit, sm4_xts_set_ctx_params);

static XTS_SETTABLE: Params<2> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    PARAM_END,
]);
static SM4_XTS_SETTABLE: Params<2> = Params([
    defn(OSSL_CIPHER_PARAM_XTS_STANDARD, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);
list!(xts_settable_ctx_params, XTS_SETTABLE);
list!(sm4_xts_settable_ctx_params, SM4_XTS_SETTABLE);

/// The XTS tables (`IMPLEMENT_cipher` in `cipher_aes_xts.c` and `cipher_sm4_xts.c`).
macro_rules! xts_table {
    ($einit:ident, $dinit:ident, $set:ident, $settable:ident) => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, $einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, $dinit, InitFn),
            entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
            entry!(OSSL_FUNC_CIPHER_CIPHER, cipher, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
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
                super::super::ciphers::generic_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(OSSL_FUNC_CIPHER_SET_CTX_PARAMS, $set, SetCtxFn),
            entry!(OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, $settable, CtxParamsFn),
            END,
        ]);
    };
}

macro_rules! aes_xts {
    () => {
        xts_table!(
            xts_einit,
            xts_dinit,
            xts_set_ctx_params,
            xts_settable_ctx_params
        );
    };
}

macro_rules! sm4_xts {
    () => {
        xts_table!(
            sm4_xts_einit,
            sm4_xts_dinit,
            sm4_xts_set_ctx_params,
            sm4_xts_settable_ctx_params
        );
    };
}

cipher_mod!(aes256xts, block(Aes, 64, Mode::Xts), aes_xts);
cipher_mod!(aes128xts, block(Aes, 32, Mode::Xts), aes_xts);
cipher_mod!(sm4128xts, block(Sm4, 32, Mode::Xts), sm4_xts);

// -------------------------------------------------------------------------------------------
// The key wraps

ffi_callback! {
    /// `aes_wrap_set_ctx_params`: `keylen` may only be set to what it is.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn wrap_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let keylen = ctx.core.generic().map_or(0, |g| g.key_len());
        // SAFETY: the caller's array.
        c_int::from(unsafe { same_keylen(params, keylen, false, "aes_wrap_set_ctx_params") })
    }
}

inits!(wrap_einit, wrap_dinit, wrap_set_ctx_params);

/// `IMPLEMENT_cipher` in `cipher_aes_wrp.c`: no `cipher`.
macro_rules! wrap {
    () => {
        pub(crate) static TABLE: Dispatch<14> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, wrap_einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, wrap_dinit, InitFn),
            entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
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
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                wrap_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                super::super::ciphers::generic_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                super::super::ciphers::generic_settable_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

cipher_mod!(aes256wrap, block(Aes, 32, Mode::Wrap), wrap);
cipher_mod!(aes192wrap, block(Aes, 24, Mode::Wrap), wrap);
cipher_mod!(aes128wrap, block(Aes, 16, Mode::Wrap), wrap);
cipher_mod!(aes256wrappad, block(Aes, 32, Mode::WrapPad), wrap);
cipher_mod!(aes192wrappad, block(Aes, 24, Mode::WrapPad), wrap);
cipher_mod!(aes128wrappad, block(Aes, 16, Mode::WrapPad), wrap);
cipher_mod!(aes256wrapinv, block(Aes, 32, Mode::WrapInv), wrap);
cipher_mod!(aes192wrapinv, block(Aes, 24, Mode::WrapInv), wrap);
cipher_mod!(aes128wrapinv, block(Aes, 16, Mode::WrapInv), wrap);
cipher_mod!(aes256wrappadinv, block(Aes, 32, Mode::WrapPadInv), wrap);
cipher_mod!(aes192wrappadinv, block(Aes, 24, Mode::WrapPadInv), wrap);
cipher_mod!(aes128wrappadinv, block(Aes, 16, Mode::WrapPadInv), wrap);

/// `ossl_tdes_wrap_cbc_functions`: triple DES's inits and context parameters, no `dupctx`.
macro_rules! tdes_wrap {
    () => {
        pub(crate) static TABLE: Dispatch<14> = Dispatch([
            entry!(
                OSSL_FUNC_CIPHER_ENCRYPT_INIT,
                super::super::ciphers::generic_einit,
                InitFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_DECRYPT_INIT,
                super::super::ciphers::generic_dinit,
                InitFn
            ),
            entry!(OSSL_FUNC_CIPHER_CIPHER, cipher, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_UPDATE, update, UpdateFn),
            entry!(OSSL_FUNC_CIPHER_FINAL, final_, FinalFn),
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
                super::super::ciphers::tdes_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                generic_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                super::super::ciphers::generic_settable_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

cipher_mod!(tdes_wrap_cbc, block(TripleDes, 24, Mode::Wrap), tdes_wrap);

// -------------------------------------------------------------------------------------------
// The AES-CBC-HMAC composites

ffi_callback! {
    /// `aes_get_ctx_params` (`cipher_aes_cbc_hmac_sha.c`): the multi-block sizes, the TLS
    /// padding, the lengths, and the IVs.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn composite_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "aes_get_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let Some(g) = ctx.core.generic_mut() else { return 0 };
        // SAFETY: the caller's array.
        if !unsafe { OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE.as_ptr()) }.is_null() {
            let Ok(n) = g.multiblock_max_bufsize() else {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER, F);
                return 0;
            };
            // SAFETY: as above.
            if !unsafe { set_param(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE, F, Value::Size(n)) } {
                return 0;
            }
        }
        let mb = g.multiblock();
        let values = [
            (OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, Value::Uint(mb.interleave)),
            (OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN, Value::Uint(mb.aad_packlen)),
            (OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN, Value::Size(mb.encrypt_len)),
            (OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, Value::Size(g.composite_tls_aad_pad())),
            (OSSL_CIPHER_PARAM_KEYLEN, Value::Size(g.key_len())),
            (OSSL_CIPHER_PARAM_IVLEN, Value::Size(g.iv_len())),
        ];
        for (key, value) in values {
            // SAFETY: as above.
            if !unsafe { set_param(params, key, F, value) } {
                return 0;
            }
        }
        let ivlen = g.iv_len();
        for (key, original) in [(OSSL_CIPHER_PARAM_IV, true), (OSSL_CIPHER_PARAM_UPDATED_IV, false)] {
            let iv = if original { g.original_iv() } else { g.updated_iv() }.as_mut_ptr().cast_const();
            // A copy, or else a pointer to the context's IV, which lives as long as it.
            // SAFETY: as above; the IV holds `ivlen` octets.
            if !unsafe { set_param(params, key, F, Value::IvCopyFirst(iv, ivlen)) } {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `aes_set_ctx_params` (`cipher_aes_cbc_hmac_sha.c`): the MAC key, the multi-block
    /// parameters, the TLS AAD (written back as the reference does), `keylen`, and
    /// `tls-version`.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array whose
    /// octet strings hold their sizes (the TLS AAD's writable).
    pub(crate) unsafe extern "C" fn composite_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "aes_set_ctx_params";
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let Some(g) = ctx.core.generic_mut() else { return 0 };
        let get_failed = || {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
            0
        };
        // SAFETY: the caller's array, here and below.
        if let Some(p) = unsafe { locate(params, OSSL_CIPHER_PARAM_AEAD_MAC_KEY) } {
            // SAFETY: the caller's guarantee.
            let key = if typed(p, OSSL_PARAM_OCTET_STRING) { unsafe { octets(p) } } else { None };
            let Some(key) = key else { return get_failed() };
            if g.set_mac_key(key).is_err() {
                return 0;
            }
        }
        // SAFETY: as above.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, F, get_size) } {
            Err(()) => return 0,
            Ok(Some(n)) => {
                if g.set_max_send_fragment(n).is_err() {
                    return 0;
                }
            }
            Ok(None) => {}
        }
        // The interleave the multi-block parameters come with: 4 or 8.
        let interleave = || -> u32 {
            // SAFETY: as above.
            let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE.as_ptr()) };
            if p.is_null() {
                return 0;
            }
            let mut v: c_uint = 0;
            if get_uint(p, &raw mut v) == 0 { 0 } else { v }
        };
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD) } {
            // SAFETY: the caller's guarantee.
            let aad = if typed(p, OSSL_PARAM_OCTET_STRING) && !p.data.is_null() { unsafe { octets(p) } } else { None };
            let Some(aad) = aad else { return get_failed() };
            let avx2 = avx2();
            match g.set_multiblock_aad(aad, interleave(), avx2) {
                Ok(()) => {}
                Err(rustyssl_crypto::provided::cipher::Error::FailedToGetParameter) => return get_failed(),
                Err(_) => return 0,
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC) } {
            // SAFETY: as above.
            let pin = unsafe { locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN) };
            let n = interleave();
            let valid = typed(p, OSSL_PARAM_OCTET_STRING)
                && !p.data.is_null()
                && pin.is_some_and(|q| {
                    typed(q, OSSL_PARAM_OCTET_STRING)
                        && !q.data.is_null()
                        && q.data_size != 0
                        && q.data_size == p.data_size
                        && q.data_size <= 16384usize.saturating_mul(usize::try_from(n).unwrap_or(0))
                })
                && matches!(n, 4 | 8);
            if !valid {
                return get_failed();
            }
            // Multi-block encryption writes more than its output parameter's size, which can't
            // be checked (docs/DEVIATIONS.md).
            return 0;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD) } {
            if !typed(p, OSSL_PARAM_OCTET_STRING) {
                return get_failed();
            }
            if p.data_size != TLS1_AAD_LEN || p.data.is_null() {
                return 0;
            }
            // The reference writes the record's length back into the caller's AAD.
            // SAFETY: the caller's guarantee: the AAD's 13 octets, writable.
            let aad = unsafe { core::slice::from_raw_parts_mut(p.data.cast::<u8>(), TLS1_AAD_LEN) };
            if g.set_composite_tls_aad(aad).is_err() {
                return 0;
            }
        }
        // SAFETY: as above.
        if !unsafe { same_keylen(params, g.key_len(), false, F) } {
            return 0;
        }
        // SAFETY: as above.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_TLS_VERSION, F, get_uint) } {
            Err(()) => return 0,
            Ok(Some(v)) => {
                if let Err(e) = g.set_composite_tls_version(v) {
                    raise(e, F);
                    return 0;
                }
            }
            Ok(None) => {}
        }
        1
    }
}

/// Whether the CPU has AVX2, which the reference interleaves 8 records with.
fn avx2() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("avx2")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

inits!(composite_einit, composite_dinit, composite_set_ctx_params);

static COMPOSITE_GETTABLE: Params<10> = Params([
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(
        OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);
static COMPOSITE_SETTABLE: Params<9> = Params([
    defn(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, OSSL_PARAM_OCTET_STRING, 0),
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE,
        OSSL_PARAM_UNSIGNED_INTEGER,
        UINT,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    PARAM_END,
]);
list!(composite_gettable_ctx_params, COMPOSITE_GETTABLE);
list!(composite_settable_ctx_params, COMPOSITE_SETTABLE);

/// `IMPLEMENT_CIPHER` in `cipher_aes_cbc_hmac_sha.c`.
macro_rules! composite {
    () => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, composite_einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, composite_dinit, InitFn),
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
                composite_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                composite_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                composite_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                composite_settable_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

cipher_mod!(
    aes128cbc_hmac_sha1,
    block(Aes, 16, Mode::CbcHmacSha1),
    composite
);
cipher_mod!(
    aes256cbc_hmac_sha1,
    block(Aes, 32, Mode::CbcHmacSha1),
    composite
);
cipher_mod!(
    aes128cbc_hmac_sha256,
    block(Aes, 16, Mode::CbcHmacSha256),
    composite
);
cipher_mod!(
    aes256cbc_hmac_sha256,
    block(Aes, 32, Mode::CbcHmacSha256),
    composite
);

// -------------------------------------------------------------------------------------------
// The AES-CBC-HMAC-SHA*-ETM ciphers (OpenSSL 3.6)

ffi_callback! {
    /// `aes_get_ctx_params` (`cipher_aes_cbc_hmac_sha_etm.c`): the lengths, the IVs (as an
    /// octet string, else a pointer, leaving the first try's error), and an encryption's tag.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn etm_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "aes_get_ctx_params";
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let Some(g) = ctx.core.generic_mut() else { return 0 };
        for (key, value) in [
            (OSSL_CIPHER_PARAM_KEYLEN, Value::Size(g.key_len())),
            (OSSL_CIPHER_PARAM_IVLEN, Value::Size(g.iv_len())),
        ] {
            // SAFETY: the caller's array.
            if !unsafe { set_param(params, key, F, value) } {
                return 0;
            }
        }
        let ivlen = g.iv_len();
        for (key, original) in [(OSSL_CIPHER_PARAM_IV, true), (OSSL_CIPHER_PARAM_UPDATED_IV, false)] {
            let iv = if original { g.original_iv() } else { g.updated_iv() }.as_mut_ptr().cast_const();
            // SAFETY: as above; the IV holds `ivlen` octets and lives as long as the context.
            if !unsafe { set_param(params, key, F, Value::StringThenPtr(iv, ivlen)) } {
                return 0;
            }
        }
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_CIPHER_HMAC_PARAM_MAC.as_ptr()) };
        if !p.is_null() {
            // SAFETY: a located parameter.
            let size = unsafe { (*p).data_size };
            let tag = match g.etm_tag(size) {
                Ok(tag) => tag,
                Err(e) => {
                    raise(e, F);
                    return 0;
                }
            };
            // SAFETY: as above; the tag's octets.
            if !unsafe { set_param(params, OSSL_CIPHER_HMAC_PARAM_MAC, F, Value::Octets(tag.as_ptr(), tag.len())) } {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `aes_set_ctx_params` (`cipher_aes_cbc_hmac_sha_etm.c`): the MAC key, `keylen` (only the
    /// cipher's), and the expected tag.
    ///
    /// # Safety
    /// `vctx` is NULL or a live algorithm context; `params` is NULL or a parameter array whose
    /// octet strings hold their sizes.
    pub(crate) unsafe extern "C" fn etm_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        const F: &str = "aes_set_ctx_params";
        if params.is_null() {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { context(vctx) }) else { return 0 };
        let Some(g) = ctx.core.generic_mut() else { return 0 };
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_AEAD_MAC_KEY.as_ptr()) };
        if !p.is_null() {
            // SAFETY: a located parameter.
            let p = unsafe { &*p };
            if p.data_type != OSSL_PARAM_OCTET_STRING.cast_unsigned() {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
            // SAFETY: an octet string holds its size.
            let Some(key) = (unsafe { super::ciphers::input(p.data.cast_const().cast(), p.data_size) }) else {
                return 0;
            };
            g.etm_set_mac_key(key);
        }
        // SAFETY: the caller's array.
        match unsafe { get_param(params, OSSL_CIPHER_PARAM_KEYLEN, F, get_size) } {
            Err(()) => return 0,
            Ok(Some(n)) if n != g.key_len() => {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, F);
                return 0;
            }
            Ok(_) => {}
        }
        // SAFETY: the caller's array.
        let p = unsafe { OSSL_PARAM_locate_const(params, OSSL_CIPHER_HMAC_PARAM_MAC.as_ptr()) };
        if !p.is_null() {
            let mut tag = [0u8; ETM_MAX_TAG];
            let mut dst = tag.as_mut_ptr().cast::<c_void>();
            let mut size = 0;
            // SAFETY: a located parameter; room for `ETM_MAX_TAG` octets.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut dst, ETM_MAX_TAG, &raw mut size) } == 0 {
                err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GET_PARAMETER, F);
                return 0;
            }
            if let Err(e) = g.etm_set_expected_tag(tag.get(..size).unwrap_or_default()) {
                raise(e, F);
                return 0;
            }
        }
        1
    }
}

inits!(etm_einit, etm_dinit, etm_set_ctx_params);

static ETM_GETTABLE: Params<5> = Params([
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    defn(OSSL_CIPHER_PARAM_IVLEN, OSSL_PARAM_UNSIGNED_INTEGER, SIZE_T),
    defn(OSSL_CIPHER_PARAM_IV, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);
// The reference lists the TLS AAD, which it doesn't take.
static ETM_SETTABLE: Params<4> = Params([
    defn(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, OSSL_PARAM_OCTET_STRING, 0),
    defn(
        OSSL_CIPHER_PARAM_KEYLEN,
        OSSL_PARAM_UNSIGNED_INTEGER,
        SIZE_T,
    ),
    PARAM_END,
]);
list!(etm_gettable_ctx_params, ETM_GETTABLE);
list!(etm_settable_ctx_params, ETM_SETTABLE);

/// `IMPLEMENT_CIPHER` in `cipher_aes_cbc_hmac_sha_etm.c`.
macro_rules! etm {
    () => {
        pub(crate) static TABLE: Dispatch<15> = Dispatch([
            entry!(OSSL_FUNC_CIPHER_NEWCTX, newctx, NewCtxFn),
            entry!(OSSL_FUNC_CIPHER_FREECTX, freectx, FreeFn),
            entry!(OSSL_FUNC_CIPHER_DUPCTX, dupctx, DupFn),
            entry!(OSSL_FUNC_CIPHER_ENCRYPT_INIT, etm_einit, InitFn),
            entry!(OSSL_FUNC_CIPHER_DECRYPT_INIT, etm_dinit, InitFn),
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
                etm_get_ctx_params,
                GetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
                etm_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
                etm_set_ctx_params,
                SetCtxFn
            ),
            entry!(
                OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
                etm_settable_ctx_params,
                CtxParamsFn
            ),
            END,
        ]);
    };
}

cipher_mod!(
    aes128cbc_hmac_sha1_etm,
    block(Aes, 16, Mode::CbcHmacSha1Etm),
    etm
);
cipher_mod!(
    aes192cbc_hmac_sha1_etm,
    block(Aes, 24, Mode::CbcHmacSha1Etm),
    etm
);
cipher_mod!(
    aes256cbc_hmac_sha1_etm,
    block(Aes, 32, Mode::CbcHmacSha1Etm),
    etm
);
cipher_mod!(
    aes128cbc_hmac_sha256_etm,
    block(Aes, 16, Mode::CbcHmacSha256Etm),
    etm
);
cipher_mod!(
    aes192cbc_hmac_sha256_etm,
    block(Aes, 24, Mode::CbcHmacSha256Etm),
    etm
);
cipher_mod!(
    aes256cbc_hmac_sha256_etm,
    block(Aes, 32, Mode::CbcHmacSha256Etm),
    etm
);
cipher_mod!(
    aes128cbc_hmac_sha512_etm,
    block(Aes, 16, Mode::CbcHmacSha512Etm),
    etm
);
cipher_mod!(
    aes192cbc_hmac_sha512_etm,
    block(Aes, 24, Mode::CbcHmacSha512Etm),
    etm
);
cipher_mod!(
    aes256cbc_hmac_sha512_etm,
    block(Aes, 32, Mode::CbcHmacSha512Etm),
    etm
);

/// Whether the CPU has what the reference's ETM ciphers need (`HWAES_CBC_HMAC_SHA*_ETM_CAPABLE`):
/// aarch64's AES instructions and those of the hash, SHA-1 and SHA-256 (`sha2`) or SHA-512
/// (`sha3`, which includes them). Elsewhere the reference has none of them.
pub(crate) fn etm_capable(mode: Mode) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let aes = std::arch::is_aarch64_feature_detected!("aes");
        aes && match mode {
            Mode::CbcHmacSha1Etm | Mode::CbcHmacSha256Etm => {
                std::arch::is_aarch64_feature_detected!("sha2")
            }
            Mode::CbcHmacSha512Etm => std::arch::is_aarch64_feature_detected!("sha3"),
            _ => false,
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        let _ = mode;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{construct, end};
    use rustyssl_abi::{OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER};

    /// docs/DEVIATIONS.md: CTS, the AES key wraps, and triple DES's key wrap fail without a
    /// key (the reference crashes, or wraps under a key schedule never set).
    #[test]
    fn no_key_is_refused() {
        let data = [7u8; 48];
        let mut out = [0u8; 64];
        for newctx in [
            aes128cbc_cts::newctx,
            aes128wrap::newctx,
            aes256wrappad::newctx,
            tdes_wrap_cbc::newctx,
        ] {
            // SAFETY: no preconditions.
            let ctx = unsafe { newctx(ptr::null_mut()) };
            let mut outl = 0usize;
            // SAFETY: a live context, no key or IV, no parameters.
            let r = unsafe {
                super::super::ciphers::generic_einit(
                    ctx,
                    ptr::null(),
                    0,
                    ptr::null(),
                    0,
                    ptr::null(),
                )
            };
            assert_eq!(r, 1);
            // SAFETY: room for the output; the input.
            let r = unsafe { update(ctx, out.as_mut_ptr(), &raw mut outl, 64, data.as_ptr(), 24) };
            // The AES key wraps report a failure as SIZE_MAX octets, which EVP refuses.
            assert!(r == 0 || outl == usize::MAX);
            // SAFETY: the context from `newctx`.
            unsafe { freectx(ctx) };
        }
    }

    /// docs/DEVIATIONS.md: `cts_mode` with NULL data fails (the reference compares a string at
    /// NULL).
    #[test]
    fn null_cts_mode_is_refused() {
        // SAFETY: no preconditions.
        let ctx = unsafe { aes128cbc_cts::newctx(ptr::null_mut()) };
        let params = [
            construct(
                OSSL_CIPHER_PARAM_CTS_MODE.as_ptr(),
                OSSL_PARAM_UTF8_STRING.cast_unsigned(),
                ptr::null_mut(),
                3,
            ),
            end(),
        ];
        // SAFETY: a live context and a parameter array, NULL data the case under test.
        assert_eq!(unsafe { cts_set_ctx_params(ctx, params.as_ptr()) }, 0);
        // SAFETY: the context from `newctx`.
        unsafe { freectx(ctx) };
    }

    /// docs/DEVIATIONS.md: multi-block encryption fails (it would write past its output's
    /// size), and its buffer size needs a fragment size first (the reference asserts).
    #[test]
    fn multiblock_encryption_is_refused() {
        // SAFETY: no preconditions.
        let ctx = unsafe { aes128cbc_hmac_sha1::newctx(ptr::null_mut()) };
        let key = [1u8; 16];
        let iv = [2u8; 16];
        // SAFETY: a live context, a key and IV of their lengths.
        let r = unsafe { composite_einit(ctx, key.as_ptr(), 16, iv.as_ptr(), 16, ptr::null()) };
        assert_eq!(r, 1);
        let mut size = 0usize;
        let mut get = [
            construct(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE.as_ptr(),
                OSSL_PARAM_UNSIGNED_INTEGER.cast_unsigned(),
                (&raw mut size).cast(),
                SIZE_T,
            ),
            end(),
        ];
        // SAFETY: a live context and a parameter array.
        let r = unsafe { composite_get_ctx_params(ctx, get.as_mut_ptr()) };
        assert_eq!(r, 0);
        let mut input = [3u8; 64];
        let mut output = [0u8; 64];
        let mut interleave: c_uint = 4;
        let set = [
            construct(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC.as_ptr(),
                OSSL_PARAM_OCTET_STRING.cast_unsigned(),
                output.as_mut_ptr().cast(),
                64,
            ),
            construct(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN.as_ptr(),
                OSSL_PARAM_OCTET_STRING.cast_unsigned(),
                input.as_mut_ptr().cast(),
                64,
            ),
            construct(
                OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE.as_ptr(),
                OSSL_PARAM_UNSIGNED_INTEGER.cast_unsigned(),
                (&raw mut interleave).cast(),
                UINT,
            ),
            end(),
        ];
        // SAFETY: a live context and a parameter array.
        assert_eq!(unsafe { composite_set_ctx_params(ctx, set.as_ptr()) }, 0);
        assert_eq!(output, [0u8; 64]);
        // SAFETY: the context from `newctx`.
        unsafe { freectx(ctx) };
    }
}
