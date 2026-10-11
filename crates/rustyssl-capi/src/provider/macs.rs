//! The default provider's MACs (`deflt_macs` in `providers/defltprov.c`): the algorithm table
//! `query_operation` offers for `OSSL_OP_MAC`, and the dispatch tables of HMAC
//! (`hmac_prov.c`, over the legacy `HMAC_CTX`), CMAC (`cmac_prov.c`, over `CMAC_CTX`), and
//! GMAC (`gmac_prov.c`, over a GCM `EVP_CIPHER_CTX`), with the reference's parameters.
//!
//! The digest or cipher a MAC uses is fetched by name (`digest`/`cipher`, with `properties`)
//! from the provider's library context, as `ossl_prov_*_load_from_params` does. Engines don't
//! exist here, so an `engine` parameter fails (docs/DEVIATIONS.md). HMAC's TLS record mode
//! (`tls-data-size`) arrives with step 3.5b; until then a nonzero size is refused.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    CMAC_CTX, ERR_LIB_PROV, ERR_R_UNSUPPORTED, EVP_CIPH_CBC_MODE, EVP_CIPH_GCM_MODE, EVP_CIPHER,
    EVP_CIPHER_CTX, EVP_CTRL_AEAD_SET_IVLEN, EVP_GCM_TLS_TAG_LEN, EVP_MD, HMAC_CTX,
    OSSL_ALG_PARAM_CIPHER, OSSL_ALG_PARAM_DIGEST, OSSL_ALG_PARAM_ENGINE, OSSL_ALG_PARAM_PROPERTIES,
    OSSL_ALGORITHM, OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_FUNC_MAC_DUPCTX, OSSL_FUNC_MAC_FINAL,
    OSSL_FUNC_MAC_FREECTX, OSSL_FUNC_MAC_GET_CTX_PARAMS, OSSL_FUNC_MAC_GET_PARAMS,
    OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, OSSL_FUNC_MAC_GETTABLE_PARAMS, OSSL_FUNC_MAC_INIT,
    OSSL_FUNC_MAC_NEWCTX, OSSL_FUNC_MAC_SET_CTX_PARAMS, OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_MAC_UPDATE, OSSL_LIB_CTX, OSSL_MAC_PARAM_BLOCK_SIZE, OSSL_MAC_PARAM_CIPHER,
    OSSL_MAC_PARAM_DIGEST, OSSL_MAC_PARAM_DIGEST_NOINIT, OSSL_MAC_PARAM_DIGEST_ONESHOT,
    OSSL_MAC_PARAM_IV, OSSL_MAC_PARAM_KEY, OSSL_MAC_PARAM_PROPERTIES, OSSL_MAC_PARAM_SIZE,
    OSSL_MAC_PARAM_TLS_DATA_SIZE, OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING, PROV_R_INVALID_KEY_LENGTH,
    PROV_R_INVALID_MODE,
};

use super::builtin::libctx_of;
use super::tables::{ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, alg, defn, entry};
use crate::cmac::{
    CMAC_CTX_copy, CMAC_CTX_free, CMAC_CTX_get0_cipher_ctx, CMAC_CTX_new, CMAC_Final, CMAC_Update,
    cmac_init,
};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_mode, EVP_CIPHER_up_ref,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_copy, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_block_size,
    EVP_CIPHER_CTX_get_key_length, EVP_CIPHER_CTX_get_params, EVP_CIPHER_CTX_get0_cipher,
    EVP_CIPHER_CTX_new, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_block_size, EVP_MD_up_ref};
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::ffi::ffi_callback;
use crate::hmac::{
    HMAC_CTX_copy, HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_size,
};
use crate::mem::OPENSSL_cleanse;
use crate::params::{
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_locate,
    OSSL_PARAM_locate_const, OSSL_PARAM_set_int, OSSL_PARAM_set_size_t, end,
};

type NewCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type DupCtxFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeCtxFn = unsafe extern "C" fn(*mut c_void);
type InitFn = unsafe extern "C" fn(*mut c_void, *const u8, usize, *const OSSL_PARAM) -> c_int;
type UpdateFn = unsafe extern "C" fn(*mut c_void, *const u8, usize) -> c_int;
type FinalFn = unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut OSSL_PARAM) -> c_int;
type GettableFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type GetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetCtxParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type CtxParamsFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;

const SIZE_T: usize = size_of::<usize>();
const INT: usize = size_of::<c_int>();

/// `ossl_param_is_empty`.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn is_empty(params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { params.as_ref() }.is_none_or(|p| p.key.is_null())
}

/// The parameter `key` of `params`, or `None`.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn locate<'a>(params: *const OSSL_PARAM, key: &core::ffi::CStr) -> Option<&'a OSSL_PARAM> {
    // SAFETY: the caller's guarantee.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    // SAFETY: a parameter of the array.
    unsafe { p.as_ref() }
}

/// `load_common`: the property query (`properties`), or `None` if a parameter is malformed or
/// names an engine.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn load_common(params: *const OSSL_PARAM) -> Option<*const c_char> {
    let mut propquery = ptr::null();
    // SAFETY: the caller's guarantee.
    if let Some(p) = unsafe { locate(params, OSSL_ALG_PARAM_PROPERTIES) } {
        if p.data_type != OSSL_PARAM_UTF8_STRING as u32 {
            return None;
        }
        propquery = p.data.cast_const().cast();
    }
    // No engines (docs/DEVIATIONS.md).
    // SAFETY: as above.
    if unsafe { locate(params, OSSL_ALG_PARAM_ENGINE) }.is_some() {
        return None;
    }
    Some(propquery)
}

/// `PROV_DIGEST`/`PROV_CIPHER`: the method a MAC was given, with a reference (NULL for none).
struct Prov<T: Method> {
    method: *mut T,
}

/// What a fetched method of either kind offers [`Prov`].
trait Method {
    /// `EVP_*_up_ref`.
    unsafe fn up_ref(m: *mut Self) -> c_int;
    /// `EVP_*_free`.
    unsafe fn free(m: *mut Self);
    /// `EVP_*_fetch`.
    unsafe fn fetch(ctx: *mut OSSL_LIB_CTX, name: *const c_char, props: *const c_char)
    -> *mut Self;
    /// `EVP_get_*byname`, where OpenSSL looks for an application's (not a global) method of
    /// the name. None can exist before step 3.11, so what it finds isn't used.
    unsafe fn lookup_legacy(name: *const c_char);
}

impl Method for EVP_MD {
    unsafe fn up_ref(m: *mut Self) -> c_int {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_MD_up_ref(m) }
    }
    unsafe fn free(m: *mut Self) {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_MD_free(m) }
    }
    unsafe fn fetch(
        ctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        props: *const c_char,
    ) -> *mut Self {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_MD_fetch(ctx, name, props) }
    }
    unsafe fn lookup_legacy(name: *const c_char) {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_get_digestbyname(name) };
    }
}

impl Method for EVP_CIPHER {
    unsafe fn up_ref(m: *mut Self) -> c_int {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CIPHER_up_ref(m) }
    }
    unsafe fn free(m: *mut Self) {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CIPHER_free(m) }
    }
    unsafe fn fetch(
        ctx: *mut OSSL_LIB_CTX,
        name: *const c_char,
        props: *const c_char,
    ) -> *mut Self {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CIPHER_fetch(ctx, name, props) }
    }
    unsafe fn lookup_legacy(name: *const c_char) {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_get_cipherbyname(name) };
    }
}

impl<T: Method> Prov<T> {
    const NONE: Self = Self {
        method: ptr::null_mut(),
    };

    /// `ossl_prov_*_reset`.
    fn reset(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { T::free(self.method) };
        self.method = ptr::null_mut();
    }

    /// `ossl_prov_*_copy`.
    fn copy(&self) -> Option<Self> {
        // SAFETY: the method this holds a reference to.
        if !self.method.is_null() && unsafe { T::up_ref(self.method) } == 0 {
            return None;
        }
        Some(Self {
            method: self.method,
        })
    }

    /// `ossl_prov_*_load_from_params`: the method parameter `key` names (with the properties),
    /// fetched from `libctx`. True if there's none to load, or it was fetched.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    unsafe fn load(
        &mut self,
        params: *const OSSL_PARAM,
        key: &core::ffi::CStr,
        libctx: *mut OSSL_LIB_CTX,
    ) -> bool {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return true;
        }
        // SAFETY: as above.
        let Some(propquery) = (unsafe { load_common(params) }) else {
            return false;
        };
        // SAFETY: as above.
        let Some(p) = (unsafe { locate(params, key) }) else {
            return true;
        };
        if p.data_type != OSSL_PARAM_UTF8_STRING as u32 {
            return false;
        }
        self.reset();
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the provider's library context; the parameter's string; the query.
        self.method = unsafe { T::fetch(libctx, p.data.cast_const().cast(), propquery) };
        if self.method.is_null() {
            // The lookup is made, as it touches the error queue's slots as OpenSSL's does.
            // SAFETY: the parameter's string.
            unsafe { T::lookup_legacy(p.data.cast_const().cast()) };
            // SAFETY: the mark set above.
            unsafe { ERR_clear_last_mark() };
            false
        } else {
            // SAFETY: as above.
            unsafe { ERR_pop_to_mark() };
            true
        }
    }
}

impl<T: Method> Drop for Prov<T> {
    fn drop(&mut self) {
        self.reset();
    }
}

/// The octets of an octet-string parameter, if it is one.
fn octets(p: &OSSL_PARAM) -> Option<(*const u8, usize)> {
    (p.data_type == OSSL_PARAM_OCTET_STRING as u32)
        .then_some((p.data.cast_const().cast(), p.data_size))
}

/// Zeroes `b` (`OPENSSL_cleanse`).
fn wipe(b: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) };
}

/// The algorithm context `vctx` as a `T`, or `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a box of a `T` from its `newctx`, used by one caller at a time.
unsafe fn context<'a, T>(vctx: *mut c_void) -> Option<&'a mut T> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<T>().as_mut() }
}

/// Sets the `size_t` parameter `key` of `params`, if there. False if it's there and can't be.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn set_size(params: *mut OSSL_PARAM, key: &core::ffi::CStr, value: usize) -> bool {
    // SAFETY: the caller's guarantee.
    let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
    // SAFETY: a parameter of the array.
    p.is_null() || unsafe { OSSL_PARAM_set_size_t(p, value) } != 0
}

// -------------------------------------------------------------------------------------------
// HMAC

/// `struct hmac_data_st`.
struct HmacData {
    provctx: *mut c_void,
    ctx: *mut HMAC_CTX,
    digest: Prov<EVP_MD>,
    /// A copy of the key, for TLS mode.
    key: Option<Vec<u8>>,
    tls_data_size: usize,
}

impl HmacData {
    fn set_key_copy(&mut self, key: Option<Vec<u8>>) {
        if let Some(old) = self.key.as_mut() {
            wipe(old);
        }
        self.key = key;
    }
}

impl Drop for HmacData {
    fn drop(&mut self) {
        // SAFETY: the context's own HMAC context.
        unsafe { HMAC_CTX_free(self.ctx) };
        self.digest.reset();
        self.set_key_copy(None);
    }
}

ffi_callback! {
    /// `hmac_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn hmac_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: no preconditions.
        let ctx = unsafe { HMAC_CTX_new() };
        if ctx.is_null() {
            return ptr::null_mut();
        }
        Box::into_raw(Box::new(HmacData { provctx, ctx, digest: Prov::NONE, key: None, tls_data_size: 0 })).cast()
    }
}

ffi_callback! {
    /// `hmac_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context `hmac_new` made, not used afterwards.
    pub(crate) unsafe extern "C" fn hmac_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee.
            drop(unsafe { Box::from_raw(vctx.cast::<HmacData>()) });
        }
    }
}

ffi_callback! {
    /// `hmac_dup`.
    ///
    /// # Safety
    /// `vsrc` is a live HMAC context.
    pub(crate) unsafe extern "C" fn hmac_dup(vsrc: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<HmacData>(vsrc) }) else { return ptr::null_mut() };
        // SAFETY: the source's provider context.
        let dst = unsafe { hmac_new(src.provctx) };
        // SAFETY: the context just made.
        let Some(d) = (unsafe { context::<HmacData>(dst) }) else { return ptr::null_mut() };
        d.tls_data_size = src.tls_data_size;
        // SAFETY: the two contexts' HMAC contexts.
        let copied = unsafe { HMAC_CTX_copy(d.ctx, src.ctx) } != 0;
        let digest = if copied { src.digest.copy() } else { None };
        let Some(digest) = digest else {
            // SAFETY: the context made here.
            unsafe { hmac_free(dst) };
            return ptr::null_mut();
        };
        d.digest = digest;
        d.key = src.key.clone();
        dst
    }
}

/// `hmac_setkey`: keeps a copy of the key and starts the HMAC with it.
///
/// # Safety
/// `key` is NULL or holds `keylen` octets.
unsafe fn hmac_setkey(m: &mut HmacData, key: *const u8, keylen: usize) -> c_int {
    let copy = if keylen == 0 {
        Vec::new()
    } else if key.is_null() {
        // The reference copies from NULL.
        return 0;
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { core::slice::from_raw_parts(key, keylen) }.to_vec()
    };
    m.set_key_copy(Some(copy));
    let digest = m.digest.method;
    // `HMAC_Init_ex` doesn't take all-absent arguments.
    if !key.is_null() || (m.tls_data_size == 0 && !digest.is_null()) {
        // C's conversion of the length to `int`: the low 32 bits.
        let len = u32::try_from(keylen & 0xffff_ffff)
            .unwrap_or(0)
            .cast_signed();
        // SAFETY: the context's HMAC context; the caller's key; the digest it holds.
        return unsafe { HMAC_Init_ex(m.ctx, key.cast(), len, digest, ptr::null_mut()) };
    }
    1
}

ffi_callback! {
    /// `hmac_init`.
    ///
    /// # Safety
    /// `vctx` is a live HMAC context; `key` is NULL or holds `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn hmac_init(vctx: *mut c_void, key: *const u8, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { hmac_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<HmacData>(vctx) }) else { return 0 };
        if !key.is_null() {
            // SAFETY: as above.
            return unsafe { hmac_setkey(m, key, keylen) };
        }
        // SAFETY: the context's HMAC context.
        unsafe { HMAC_Init_ex(m.ctx, ptr::null(), 0, ptr::null(), ptr::null_mut()) }
    }
}

ffi_callback! {
    /// `hmac_update`.
    ///
    /// # Safety
    /// `vctx` is a live HMAC context; `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn hmac_update(vctx: *mut c_void, data: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<HmacData>(vctx) }) else { return 0 };
        if m.tls_data_size > 0 {
            // Refused when set (step 3.5b).
            return 0;
        }
        // SAFETY: the context's HMAC context; the caller's data.
        unsafe { HMAC_Update(m.ctx, data, len) }
    }
}

ffi_callback! {
    /// `hmac_final`.
    ///
    /// # Safety
    /// `vctx` is a live HMAC context; `out` has room for the MAC; `outl` is valid for a write.
    pub(crate) unsafe extern "C" fn hmac_final(vctx: *mut c_void, out: *mut u8, outl: *mut usize, _outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<HmacData>(vctx) }) else { return 0 };
        if m.tls_data_size > 0 {
            return 0;
        }
        let mut hlen = 0;
        // SAFETY: the context's HMAC context; the caller's buffer.
        if unsafe { HMAC_Final(m.ctx, out, &raw mut hlen) } == 0 {
            return 0;
        }
        if !outl.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { outl.write(hlen as usize) };
        }
        1
    }
}

static HMAC_GETTABLE_CTX: Params<3> = Params([
    defn(
        OSSL_MAC_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    defn(
        OSSL_MAC_PARAM_BLOCK_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    PARAM_END,
]);

static HMAC_SETTABLE_CTX: Params<7> = Params([
    defn(OSSL_MAC_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_MAC_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_MAC_PARAM_DIGEST_NOINIT,
        OSSL_PARAM_INTEGER as c_int,
        INT,
    ),
    defn(
        OSSL_MAC_PARAM_DIGEST_ONESHOT,
        OSSL_PARAM_INTEGER as c_int,
        INT,
    ),
    defn(
        OSSL_MAC_PARAM_TLS_DATA_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `hmac_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn hmac_gettable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        HMAC_GETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `hmac_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn hmac_settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        HMAC_SETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `hmac_get_ctx_params`: the size (the digest's, 0 for none) and block size.
    ///
    /// # Safety
    /// `vctx` is a live HMAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn hmac_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<HmacData>(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE.as_ptr()) };
        if !p.is_null() {
            // SAFETY: the context's HMAC context.
            let size = unsafe { HMAC_size(m.ctx) };
            // SAFETY: a parameter of the array.
            if unsafe { OSSL_PARAM_set_size_t(p, size) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE.as_ptr()) };
        if !p.is_null() {
            let block = if m.digest.method.is_null() {
                0
            } else {
                // SAFETY: the digest the context holds.
                unsafe { EVP_MD_get_block_size(m.digest.method) }
            };
            // SAFETY: a parameter of the array.
            if unsafe { OSSL_PARAM_set_int(p, block) } == 0 {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `hmac_set_ctx_params`: the digest (with properties), the key, and the TLS data size.
    ///
    /// # Safety
    /// `vctx` is a live HMAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn hmac_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<HmacData>(vctx) }) else { return 0 };
        // SAFETY: the provider's context.
        let libctx = unsafe { libctx_of(m.provctx) };
        // SAFETY: the caller's array.
        if !unsafe { m.digest.load(params, OSSL_ALG_PARAM_DIGEST, libctx) } {
            return 0;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_KEY) } {
            let Some((key, keylen)) = octets(p) else { return 0 };
            // SAFETY: the parameter's octets.
            if unsafe { hmac_setkey(m, key, keylen) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_TLS_DATA_SIZE) } {
            let mut size = 0;
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut size) } == 0 {
                return 0;
            }
            if size > 0 {
                // TLS record mode comes with step 3.5b.
                err::raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED, "hmac_set_ctx_params");
                return 0;
            }
            m.tls_data_size = size;
        }
        1
    }
}

static HMAC_FUNCTIONS: Dispatch<11> = Dispatch([
    entry!(OSSL_FUNC_MAC_NEWCTX, hmac_new, NewCtxFn),
    entry!(OSSL_FUNC_MAC_DUPCTX, hmac_dup, DupCtxFn),
    entry!(OSSL_FUNC_MAC_FREECTX, hmac_free, FreeCtxFn),
    entry!(OSSL_FUNC_MAC_INIT, hmac_init, InitFn),
    entry!(OSSL_FUNC_MAC_UPDATE, hmac_update, UpdateFn),
    entry!(OSSL_FUNC_MAC_FINAL, hmac_final, FinalFn),
    entry!(
        OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
        hmac_gettable_ctx_params,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_GET_CTX_PARAMS,
        hmac_get_ctx_params,
        GetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        hmac_settable_ctx_params,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_SET_CTX_PARAMS,
        hmac_set_ctx_params,
        SetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// CMAC

/// `struct cmac_data_st`.
struct CmacData {
    provctx: *mut c_void,
    ctx: *mut CMAC_CTX,
    cipher: Prov<EVP_CIPHER>,
}

impl Drop for CmacData {
    fn drop(&mut self) {
        // SAFETY: the context's own CMAC context.
        unsafe { CMAC_CTX_free(self.ctx) };
        self.cipher.reset();
    }
}

ffi_callback! {
    /// `cmac_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn cmac_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: no preconditions.
        let ctx = unsafe { CMAC_CTX_new() };
        if ctx.is_null() {
            return ptr::null_mut();
        }
        Box::into_raw(Box::new(CmacData { provctx, ctx, cipher: Prov::NONE })).cast()
    }
}

ffi_callback! {
    /// `cmac_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context `cmac_new` made, not used afterwards.
    pub(crate) unsafe extern "C" fn cmac_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee.
            drop(unsafe { Box::from_raw(vctx.cast::<CmacData>()) });
        }
    }
}

ffi_callback! {
    /// `cmac_dup`: fails for a context without a key, as `CMAC_CTX_copy` does.
    ///
    /// # Safety
    /// `vsrc` is a live CMAC context.
    pub(crate) unsafe extern "C" fn cmac_dup(vsrc: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<CmacData>(vsrc) }) else { return ptr::null_mut() };
        // SAFETY: the source's provider context.
        let dst = unsafe { cmac_new(src.provctx) };
        // SAFETY: the context just made.
        let Some(d) = (unsafe { context::<CmacData>(dst) }) else { return ptr::null_mut() };
        // SAFETY: the two contexts' CMAC contexts.
        let copied = unsafe { CMAC_CTX_copy(d.ctx, src.ctx) } != 0;
        let cipher = if copied { src.cipher.copy() } else { None };
        let Some(cipher) = cipher else {
            // SAFETY: the context made here.
            unsafe { cmac_free(dst) };
            return ptr::null_mut();
        };
        d.cipher = cipher;
        dst
    }
}

/// `cmac_size`: the cipher's block size, 0 without a cipher.
fn cmac_size(m: &CmacData) -> usize {
    // SAFETY: the context's own CMAC context.
    let cctx: *const EVP_CIPHER_CTX = unsafe { CMAC_CTX_get0_cipher_ctx(m.ctx) };
    // SAFETY: its cipher context.
    if unsafe { EVP_CIPHER_CTX_get0_cipher(cctx) }.is_null() {
        return 0;
    }
    // SAFETY: as above. (A negative size converts to the huge `size_t` it is in C.)
    let bl = unsafe { EVP_CIPHER_CTX_get_block_size(cctx) };
    isize::try_from(bl).unwrap_or(0).cast_unsigned()
}

/// `cmac_setkey`: starts the CMAC with the cipher it was given (then forgets it) and the key.
///
/// # Safety
/// `key` is NULL or holds `keylen` octets.
unsafe fn cmac_setkey(m: &mut CmacData, key: *const u8, keylen: usize) -> c_int {
    // SAFETY: the context's CMAC context; the caller's key; the cipher it holds.
    let rv = unsafe {
        cmac_init(
            m.ctx,
            key.cast(),
            keylen,
            m.cipher.method,
            ptr::null_mut(),
            ptr::null(),
        )
    };
    m.cipher.reset();
    rv
}

ffi_callback! {
    /// `cmac_init`.
    ///
    /// # Safety
    /// `vctx` is a live CMAC context; `key` is NULL or holds `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn cmac_init_fn(vctx: *mut c_void, key: *const u8, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { cmac_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<CmacData>(vctx) }) else { return 0 };
        if !key.is_null() {
            // SAFETY: as above.
            return unsafe { cmac_setkey(m, key, keylen) };
        }
        // SAFETY: the context's CMAC context: restart.
        unsafe { cmac_init(m.ctx, ptr::null(), 0, ptr::null(), ptr::null_mut(), ptr::null()) }
    }
}

ffi_callback! {
    /// `cmac_update`.
    ///
    /// # Safety
    /// `vctx` is a live CMAC context; `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn cmac_update(vctx: *mut c_void, data: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<CmacData>(vctx) }) else { return 0 };
        // SAFETY: the context's CMAC context; the caller's data.
        unsafe { CMAC_Update(m.ctx, data.cast(), len) }
    }
}

ffi_callback! {
    /// `cmac_final`.
    ///
    /// # Safety
    /// `vctx` is a live CMAC context; `out` has room for a block; `outl` is NULL or valid for
    /// a write.
    pub(crate) unsafe extern "C" fn cmac_final(vctx: *mut c_void, out: *mut u8, outl: *mut usize, _outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<CmacData>(vctx) }) else { return 0 };
        // SAFETY: the context's CMAC context; the caller's buffers.
        unsafe { CMAC_Final(m.ctx, out, outl) }
    }
}

static CMAC_GETTABLE_CTX: Params<3> = Params([
    defn(
        OSSL_MAC_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    defn(
        OSSL_MAC_PARAM_BLOCK_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    PARAM_END,
]);

static CMAC_SETTABLE_CTX: Params<4> = Params([
    defn(OSSL_MAC_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_MAC_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `cmac_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn cmac_gettable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        CMAC_GETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `cmac_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn cmac_settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        CMAC_SETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `cmac_get_ctx_params`: the size and block size, both the cipher's block size.
    ///
    /// # Safety
    /// `vctx` is a live CMAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn cmac_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<CmacData>(vctx) }) else { return 0 };
        let size = cmac_size(m);
        // SAFETY: the caller's guarantee.
        let ok = unsafe { set_size(params, OSSL_MAC_PARAM_SIZE, size) }
            // SAFETY: as above.
            && unsafe { set_size(params, OSSL_MAC_PARAM_BLOCK_SIZE, size) };
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `cmac_set_ctx_params`: the cipher (CBC only, with properties) and the key.
    ///
    /// # Safety
    /// `vctx` is a live CMAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn cmac_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<CmacData>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { locate(params, OSSL_MAC_PARAM_CIPHER) }.is_some() {
            // SAFETY: the provider's context.
            let libctx = unsafe { libctx_of(m.provctx) };
            // SAFETY: the caller's array.
            if !unsafe { m.cipher.load(params, OSSL_ALG_PARAM_CIPHER, libctx) } {
                return 0;
            }
            // SAFETY: the cipher just fetched.
            if unsafe { EVP_CIPHER_get_mode(m.cipher.method) } != EVP_CIPH_CBC_MODE as c_int {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_MODE, "cmac_set_ctx_params");
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_KEY) } {
            let Some((key, keylen)) = octets(p) else { return 0 };
            // SAFETY: the parameter's octets.
            return unsafe { cmac_setkey(m, key, keylen) };
        }
        1
    }
}

static CMAC_FUNCTIONS: Dispatch<11> = Dispatch([
    entry!(OSSL_FUNC_MAC_NEWCTX, cmac_new, NewCtxFn),
    entry!(OSSL_FUNC_MAC_DUPCTX, cmac_dup, DupCtxFn),
    entry!(OSSL_FUNC_MAC_FREECTX, cmac_free, FreeCtxFn),
    entry!(OSSL_FUNC_MAC_INIT, cmac_init_fn, InitFn),
    entry!(OSSL_FUNC_MAC_UPDATE, cmac_update, UpdateFn),
    entry!(OSSL_FUNC_MAC_FINAL, cmac_final, FinalFn),
    entry!(
        OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
        cmac_gettable_ctx_params,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_GET_CTX_PARAMS,
        cmac_get_ctx_params,
        GetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        cmac_settable_ctx_params,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_SET_CTX_PARAMS,
        cmac_set_ctx_params,
        SetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// GMAC

/// `struct gmac_data_st`.
struct GmacData {
    provctx: *mut c_void,
    ctx: *mut EVP_CIPHER_CTX,
    cipher: Prov<EVP_CIPHER>,
}

impl Drop for GmacData {
    fn drop(&mut self) {
        // SAFETY: the context's own cipher context.
        unsafe { EVP_CIPHER_CTX_free(self.ctx) };
        self.cipher.reset();
    }
}

ffi_callback! {
    /// `gmac_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn gmac_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        if ctx.is_null() {
            return ptr::null_mut();
        }
        Box::into_raw(Box::new(GmacData { provctx, ctx, cipher: Prov::NONE })).cast()
    }
}

ffi_callback! {
    /// `gmac_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context `gmac_new` made, not used afterwards.
    pub(crate) unsafe extern "C" fn gmac_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !vctx.is_null() {
            // SAFETY: the caller's guarantee.
            drop(unsafe { Box::from_raw(vctx.cast::<GmacData>()) });
        }
    }
}

ffi_callback! {
    /// `gmac_dup`.
    ///
    /// # Safety
    /// `vsrc` is a live GMAC context.
    pub(crate) unsafe extern "C" fn gmac_dup(vsrc: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<GmacData>(vsrc) }) else { return ptr::null_mut() };
        // SAFETY: the source's provider context.
        let dst = unsafe { gmac_new(src.provctx) };
        // SAFETY: the context just made.
        let Some(d) = (unsafe { context::<GmacData>(dst) }) else { return ptr::null_mut() };
        // SAFETY: the two contexts' cipher contexts.
        let copied = unsafe { EVP_CIPHER_CTX_copy(d.ctx, src.ctx) } != 0;
        let cipher = if copied { src.cipher.copy() } else { None };
        let Some(cipher) = cipher else {
            // SAFETY: the context made here.
            unsafe { gmac_free(dst) };
            return ptr::null_mut();
        };
        d.cipher = cipher;
        dst
    }
}

/// `gmac_setkey`: the key, which must be the cipher's length.
///
/// # Safety
/// `key` is NULL or holds `keylen` octets.
unsafe fn gmac_setkey(m: &mut GmacData, key: *const u8, keylen: usize) -> c_int {
    // SAFETY: the context's own cipher context. (A negative length converts to the huge
    // `size_t` it is in C.)
    let want = isize::try_from(unsafe { EVP_CIPHER_CTX_get_key_length(m.ctx) })
        .unwrap_or(0)
        .cast_unsigned();
    if keylen != want {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, "gmac_setkey");
        return 0;
    }
    // SAFETY: the context's cipher context; the caller's key.
    c_int::from(
        unsafe { EVP_EncryptInit_ex(m.ctx, ptr::null(), ptr::null_mut(), key, ptr::null()) } != 0,
    )
}

ffi_callback! {
    /// `gmac_init`.
    ///
    /// # Safety
    /// `vctx` is a live GMAC context; `key` is NULL or holds `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn gmac_init(vctx: *mut c_void, key: *const u8, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { gmac_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<GmacData>(vctx) }) else { return 0 };
        if !key.is_null() {
            // SAFETY: as above.
            return unsafe { gmac_setkey(m, key, keylen) };
        }
        // SAFETY: the context's cipher context.
        unsafe { EVP_EncryptInit_ex(m.ctx, ptr::null(), ptr::null_mut(), ptr::null(), ptr::null()) }
    }
}

ffi_callback! {
    /// `gmac_update`: the data, as additional authenticated data, `INT_MAX` octets at a time.
    ///
    /// # Safety
    /// `vctx` is a live GMAC context; `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn gmac_update(vctx: *mut c_void, data: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<GmacData>(vctx) }) else { return 0 };
        if len == 0 {
            return 1;
        }
        let (mut data, mut len) = (data, len);
        let max = c_int::MAX.cast_unsigned() as usize;
        let mut outl = 0;
        while len > max {
            // SAFETY: the context's cipher context; `INT_MAX` of the caller's octets.
            if unsafe { EVP_EncryptUpdate(m.ctx, ptr::null_mut(), &raw mut outl, data, c_int::MAX) } == 0 {
                return 0;
            }
            data = data.wrapping_add(max);
            len -= max;
        }
        let Ok(n) = c_int::try_from(len) else { return 0 };
        // SAFETY: as above, the rest.
        unsafe { EVP_EncryptUpdate(m.ctx, ptr::null_mut(), &raw mut outl, data, n) }
    }
}

ffi_callback! {
    /// `gmac_final`: the tag (16 octets).
    ///
    /// # Safety
    /// `vctx` is a live GMAC context; `out` has room for 16 octets; `outl` is valid for a write.
    pub(crate) unsafe extern "C" fn gmac_final(vctx: *mut c_void, out: *mut u8, outl: *mut usize, _outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<GmacData>(vctx) }) else { return 0 };
        let mut hlen = 0;
        // SAFETY: the context's cipher context; the caller's buffer (GCM writes nothing).
        if unsafe { EVP_EncryptFinal_ex(m.ctx, out, &raw mut hlen) } == 0 {
            return 0;
        }
        let tag = EVP_GCM_TLS_TAG_LEN as usize;
        let mut params = [
            // SAFETY: the caller's buffer, of the tag's size.
            unsafe { OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG.as_ptr(), out.cast(), tag) },
            end(),
        ];
        // SAFETY: the context's cipher context; the array above.
        if unsafe { EVP_CIPHER_CTX_get_params(m.ctx, params.as_mut_ptr()) } == 0 {
            return 0;
        }
        if !outl.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { outl.write(tag) };
        }
        1
    }
}

static GMAC_GETTABLE: Params<2> = Params([
    defn(
        OSSL_MAC_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    PARAM_END,
]);

static GMAC_SETTABLE_CTX: Params<5> = Params([
    defn(OSSL_MAC_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_MAC_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0,
    ),
    defn(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_MAC_PARAM_IV, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `gmac_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn gmac_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GMAC_GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `gmac_get_params`: the size, 16.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn gmac_get_params(params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { set_size(params, OSSL_MAC_PARAM_SIZE, EVP_GCM_TLS_TAG_LEN as usize) })
    }
}

ffi_callback! {
    /// `gmac_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn gmac_settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GMAC_SETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `gmac_set_ctx_params`: the cipher (GCM only, with properties), the key, and the IV.
    ///
    /// # Safety
    /// `vctx` is a live GMAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn gmac_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<GmacData>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { locate(params, OSSL_MAC_PARAM_CIPHER) }.is_some() {
            // SAFETY: the provider's context.
            let libctx = unsafe { libctx_of(m.provctx) };
            // SAFETY: the caller's array.
            if !unsafe { m.cipher.load(params, OSSL_ALG_PARAM_CIPHER, libctx) } {
                return 0;
            }
            // SAFETY: the cipher just fetched.
            if unsafe { EVP_CIPHER_get_mode(m.cipher.method) } != EVP_CIPH_GCM_MODE as c_int {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_MODE, "gmac_set_ctx_params");
                return 0;
            }
            // SAFETY: the context's cipher context; the cipher it holds.
            if unsafe { EVP_EncryptInit_ex(m.ctx, m.cipher.method, ptr::null_mut(), ptr::null(), ptr::null()) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_KEY) } {
            let Some((key, keylen)) = octets(p) else { return 0 };
            // SAFETY: the parameter's octets.
            if unsafe { gmac_setkey(m, key, keylen) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_IV) } {
            let Some((iv, ivlen)) = octets(p) else { return 0 };
            // C's conversion of the length to `int`: the low 32 bits.
            let len = u32::try_from(ivlen & 0xffff_ffff).unwrap_or(0).cast_signed();
            // SAFETY: the context's cipher context.
            let ok = unsafe { EVP_CIPHER_CTX_ctrl(m.ctx, EVP_CTRL_AEAD_SET_IVLEN as c_int, len, ptr::null_mut()) } > 0
                // SAFETY: as above; the parameter's octets.
                && unsafe { EVP_EncryptInit_ex(m.ctx, ptr::null(), ptr::null_mut(), ptr::null(), iv) } != 0;
            if !ok {
                return 0;
            }
        }
        1
    }
}

static GMAC_FUNCTIONS: Dispatch<11> = Dispatch([
    entry!(OSSL_FUNC_MAC_NEWCTX, gmac_new, NewCtxFn),
    entry!(OSSL_FUNC_MAC_DUPCTX, gmac_dup, DupCtxFn),
    entry!(OSSL_FUNC_MAC_FREECTX, gmac_free, FreeCtxFn),
    entry!(OSSL_FUNC_MAC_INIT, gmac_init, InitFn),
    entry!(OSSL_FUNC_MAC_UPDATE, gmac_update, UpdateFn),
    entry!(OSSL_FUNC_MAC_FINAL, gmac_final, FinalFn),
    entry!(
        OSSL_FUNC_MAC_GETTABLE_PARAMS,
        gmac_gettable_params,
        GettableFn
    ),
    entry!(OSSL_FUNC_MAC_GET_PARAMS, gmac_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        gmac_settable_ctx_params,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_SET_CTX_PARAMS,
        gmac_set_ctx_params,
        SetCtxParamsFn
    ),
    END,
]);

/// `deflt_macs` so far (the rest come with step 3.5b), in the reference's order.
static DEFAULT_MACS: Algorithms<4> = Algorithms([
    alg(c"CMAC", &CMAC_FUNCTIONS),
    alg(c"GMAC:1.0.9797.3.4", &GMAC_FUNCTIONS),
    alg(c"HMAC", &HMAC_FUNCTIONS),
    ALG_END,
]);

/// The default provider's MAC table.
pub(crate) fn default_macs() -> *const OSSL_ALGORITHM {
    DEFAULT_MACS.0.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::mac::{
        EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_fetch, EVP_MAC_free, EVP_MAC_init,
    };
    use crate::params::OSSL_PARAM_construct_utf8_string;

    /// docs/DEVIATIONS.md: there are no engines, so an `engine` parameter fails.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn engines_are_refused() {
        let key = [1u8; 16];
        for (mac, param, sub) in [
            (c"HMAC", OSSL_MAC_PARAM_DIGEST, c"SHA256"),
            (c"CMAC", OSSL_MAC_PARAM_CIPHER, c"AES-128-CBC"),
        ] {
            // SAFETY: a static name.
            let m = unsafe { EVP_MAC_fetch(ptr::null_mut(), mac.as_ptr(), ptr::null()) };
            // SAFETY: the method just fetched.
            let ctx = unsafe { EVP_MAC_CTX_new(m) };
            // SAFETY: as above.
            unsafe { EVP_MAC_free(m) };
            // SAFETY: static strings, which outlive the parameters.
            let named = unsafe {
                OSSL_PARAM_construct_utf8_string(param.as_ptr(), sub.as_ptr().cast_mut(), 0)
            };
            // SAFETY: as above.
            let engine = unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_ALG_PARAM_ENGINE.as_ptr(),
                    c"dynamic".as_ptr().cast_mut(),
                    0,
                )
            };
            let with = [named, engine, end()];
            let without = [named, end()];
            // SAFETY: the context; the key and parameters above.
            let r = unsafe { EVP_MAC_init(ctx, key.as_ptr(), key.len(), with.as_ptr()) };
            assert_eq!(r, 0);
            // SAFETY: as above.
            let r = unsafe { EVP_MAC_init(ctx, key.as_ptr(), key.len(), without.as_ptr()) };
            assert_eq!(r, 1);
            // SAFETY: the test's context.
            unsafe { EVP_MAC_CTX_free(ctx) };
        }
    }
}
