//! The default provider's MACs (`deflt_macs` in `providers/defltprov.c`): the algorithm table
//! `query_operation` offers for `OSSL_OP_MAC`, and the dispatch tables of HMAC
//! (`hmac_prov.c`, over the legacy `HMAC_CTX`), CMAC (`cmac_prov.c`, over `CMAC_CTX`), and
//! GMAC (`gmac_prov.c`, over a GCM `EVP_CIPHER_CTX`), with the reference's parameters.
//!
//! The digest or cipher a MAC uses is fetched by name (`digest`/`cipher`, with `properties`)
//! from the provider's library context, as `ossl_prov_*_load_from_params` does. Engines don't
//! exist here, so an `engine` parameter fails (docs/DEVIATIONS.md). HMAC's TLS record mode
//! (`tls-data-size`) MACs a decrypted CBC record in constant time
//! (`rustyssl_crypto::provided::mac::tls_cbc_record_mac`).

use core::ffi::{c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    CMAC_CTX, ENGINE, ERR_LIB_PROV, EVP_CIPH_CBC_MODE, EVP_CIPH_GCM_MODE, EVP_CIPHER,
    EVP_CIPHER_CTX, EVP_CTRL_AEAD_SET_IVLEN, EVP_GCM_TLS_TAG_LEN, EVP_MD, EVP_MD_CTX, HMAC_CTX,
    OSSL_ALG_PARAM_CIPHER, OSSL_ALG_PARAM_DIGEST, OSSL_ALG_PARAM_ENGINE, OSSL_ALG_PARAM_PROPERTIES,
    OSSL_ALGORITHM, OSSL_CIPHER_PARAM_AEAD_TAG, OSSL_FUNC_MAC_DUPCTX, OSSL_FUNC_MAC_FINAL,
    OSSL_FUNC_MAC_FREECTX, OSSL_FUNC_MAC_GET_CTX_PARAMS, OSSL_FUNC_MAC_GET_PARAMS,
    OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS, OSSL_FUNC_MAC_GETTABLE_PARAMS, OSSL_FUNC_MAC_INIT,
    OSSL_FUNC_MAC_NEWCTX, OSSL_FUNC_MAC_SET_CTX_PARAMS, OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_MAC_UPDATE, OSSL_LIB_CTX, OSSL_MAC_PARAM_BLOCK_SIZE, OSSL_MAC_PARAM_C_ROUNDS,
    OSSL_MAC_PARAM_CIPHER, OSSL_MAC_PARAM_CUSTOM, OSSL_MAC_PARAM_D_ROUNDS, OSSL_MAC_PARAM_DIGEST,
    OSSL_MAC_PARAM_DIGEST_NOINIT, OSSL_MAC_PARAM_DIGEST_ONESHOT, OSSL_MAC_PARAM_IV,
    OSSL_MAC_PARAM_KEY, OSSL_MAC_PARAM_PROPERTIES, OSSL_MAC_PARAM_SALT, OSSL_MAC_PARAM_SIZE,
    OSSL_MAC_PARAM_TLS_DATA_SIZE, OSSL_MAC_PARAM_XOF, OSSL_PARAM, OSSL_PARAM_INTEGER,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING,
    PROV_R_INVALID_CUSTOM_LENGTH, PROV_R_INVALID_DIGEST_LENGTH, PROV_R_INVALID_KEY_LENGTH,
    PROV_R_INVALID_MODE, PROV_R_INVALID_OUTPUT_LENGTH, PROV_R_INVALID_SALT_LENGTH,
    PROV_R_LENGTH_TOO_LARGE, PROV_R_NO_KEY_SET, PROV_R_NOT_XOF_OR_INVALID_LENGTH,
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
use crate::evp::digest::{
    EVP_MD_fetch, EVP_MD_free, EVP_MD_get_block_size, EVP_MD_get_size, EVP_MD_is_a, EVP_MD_up_ref,
};
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::md_ctx::{
    EVP_DigestFinalXOF, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_copy, EVP_MD_CTX_free,
    EVP_MD_CTX_new,
};
use crate::ffi::ffi_callback;
use crate::hmac::{
    HMAC_CTX_copy, HMAC_CTX_free, HMAC_CTX_new, HMAC_Final, HMAC_Init_ex, HMAC_Update, HMAC_size,
};
use crate::mem::OPENSSL_cleanse;
use crate::params::{
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_int,
    OSSL_PARAM_get_size_t, OSSL_PARAM_get_uint, OSSL_PARAM_locate, OSSL_PARAM_locate_const,
    OSSL_PARAM_set_int, OSSL_PARAM_set_size_t, OSSL_PARAM_set_uint, end,
};
use rustyssl_crypto::mac::Blake2Algorithm;
use rustyssl_crypto::provided::mac::{
    Blake2Mac, Error as MacError, Poly1305, RecordDigest, SipHash, tls_cbc_record_mac,
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

pub(crate) const SIZE_T: usize = size_of::<usize>();
pub(crate) const INT: usize = size_of::<c_int>();
const UINT: usize = size_of::<c_uint>();

/// `ossl_param_is_empty`.
///
/// # Safety
/// `params` is NULL or a parameter array.
pub(crate) unsafe fn is_empty(params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { params.as_ref() }.is_none_or(|p| p.key.is_null())
}

/// The parameter `key` of `params`, or `None`.
///
/// # Safety
/// `params` is NULL or a parameter array.
pub(crate) unsafe fn locate<'a>(
    params: *const OSSL_PARAM,
    key: &core::ffi::CStr,
) -> Option<&'a OSSL_PARAM> {
    // SAFETY: the caller's guarantee.
    let p = unsafe { OSSL_PARAM_locate_const(params, key.as_ptr()) };
    // SAFETY: a parameter of the array.
    unsafe { p.as_ref() }
}

/// `load_common`: the property query (`properties`), or `None` if a parameter is malformed or
/// the engine it names isn't there or doesn't initialize. `engine` is let go and replaced by
/// the one the `engine` parameter names (a functional reference), or NULL.
///
/// # Safety
/// `params` is NULL or a parameter array; `engine` is NULL or a functional reference.
pub(crate) unsafe fn load_common(
    params: *const OSSL_PARAM,
    engine: &mut *mut ENGINE,
) -> Option<*const c_char> {
    let mut propquery = ptr::null();
    // SAFETY: the caller's guarantee.
    if let Some(p) = unsafe { locate(params, OSSL_ALG_PARAM_PROPERTIES) } {
        if p.data_type != OSSL_PARAM_UTF8_STRING as u32 {
            return None;
        }
        propquery = p.data.cast_const().cast();
    }
    let old = core::mem::replace(engine, ptr::null_mut());
    // SAFETY: the caller's functional reference, or NULL; the engine's `finish` may run.
    unsafe { crate::engine::ENGINE_finish(old) };
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_ALG_PARAM_ENGINE) } {
        if p.data_type != OSSL_PARAM_UTF8_STRING as u32 {
            return None;
        }
        // A structural reference, then a functional one, then the structural one let go.
        // SAFETY: the parameter's string.
        let e = unsafe { crate::engine::list::ENGINE_by_id(p.data.cast_const().cast()) };
        if e.is_null() {
            return None;
        }
        // SAFETY: the engine found; its `init` may run.
        if unsafe { crate::engine::ENGINE_init(e) } == 0 {
            // SAFETY: the structural reference.
            unsafe { crate::engine::ENGINE_free(e) };
            return None;
        }
        // SAFETY: as above.
        unsafe { crate::engine::ENGINE_free(e) };
        *engine = e;
    }
    Some(propquery)
}

/// `PROV_DIGEST`/`PROV_CIPHER`: the method a MAC was given, with a reference (NULL for none),
/// and the engine its implementation comes from (a functional reference, or NULL).
pub(crate) struct Prov<T: Method> {
    pub(crate) method: *mut T,
    pub(crate) engine: *mut ENGINE,
}

/// What a fetched method of either kind offers [`Prov`].
pub(crate) trait Method {
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
    pub(crate) const NONE: Self = Self {
        method: ptr::null_mut(),
        engine: ptr::null_mut(),
    };

    /// `ossl_prov_*_reset`: the method and the engine let go.
    pub(crate) fn reset(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { T::free(self.method) };
        self.method = ptr::null_mut();
        let e = core::mem::replace(&mut self.engine, ptr::null_mut());
        // SAFETY: the functional reference this holds, or NULL.
        unsafe { crate::engine::ENGINE_finish(e) };
    }

    /// `ossl_prov_*_copy`: another reference to the method and the engine.
    pub(crate) fn copy(&self) -> Option<Self> {
        // SAFETY: the method this holds a reference to.
        if !self.method.is_null() && unsafe { T::up_ref(self.method) } == 0 {
            return None;
        }
        // SAFETY: the engine this holds a functional reference to.
        if !self.engine.is_null() && unsafe { crate::engine::ENGINE_init(self.engine) } == 0 {
            // SAFETY: the reference taken above.
            unsafe { T::free(self.method) };
            return None;
        }
        Some(Self {
            method: self.method,
            engine: self.engine,
        })
    }

    /// `ossl_prov_*_load_from_params`: the method parameter `key` names (with the properties),
    /// fetched from `libctx`. True if there's none to load, or it was fetched.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe fn load(
        &mut self,
        params: *const OSSL_PARAM,
        key: &core::ffi::CStr,
        libctx: *mut OSSL_LIB_CTX,
    ) -> bool {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return true;
        }
        // SAFETY: as above; the engine this holds.
        let Some(propquery) = (unsafe { load_common(params, &mut self.engine) }) else {
            return false;
        };
        // SAFETY: as above.
        let Some(p) = (unsafe { locate(params, key) }) else {
            return true;
        };
        if p.data_type != OSSL_PARAM_UTF8_STRING as u32 {
            return false;
        }
        // The method is replaced; the engine just loaded stays.
        // SAFETY: the reference this holds, or NULL.
        unsafe { T::free(self.method) };
        self.method = ptr::null_mut();
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
pub(crate) fn octets(p: &OSSL_PARAM) -> Option<(*const u8, usize)> {
    (p.data_type == OSSL_PARAM_OCTET_STRING as u32)
        .then_some((p.data.cast_const().cast(), p.data_size))
}

/// Zeroes `b` (`OPENSSL_cleanse`).
pub(crate) fn wipe(b: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) };
}

/// The algorithm context `vctx` as a `T`, or `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a box of a `T` from its `newctx`, used by one caller at a time.
pub(crate) unsafe fn context<'a, T>(vctx: *mut c_void) -> Option<&'a mut T> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<T>().as_mut() }
}

/// Sets the `size_t` parameter `key` of `params`, if there. False if it's there and can't be.
///
/// # Safety
/// `params` is NULL or a parameter array.
pub(crate) unsafe fn set_size(
    params: *mut OSSL_PARAM,
    key: &core::ffi::CStr,
    value: usize,
) -> bool {
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
    /// The length of a whole TLS record (data, MAC, and padding); nonzero for TLS mode.
    tls_data_size: usize,
    tls_header: [u8; 13],
    tls_header_set: bool,
    tls_mac_out: [u8; 64],
    tls_mac_out_size: usize,
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
        wipe(&mut self.tls_mac_out);
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
        let data = HmacData {
            provctx,
            ctx,
            digest: Prov::NONE,
            key: None,
            tls_data_size: 0,
            tls_header: [0; 13],
            tls_header_set: false,
            tls_mac_out: [0; 64],
            tls_mac_out_size: 0,
        };
        Box::into_raw(Box::new(data)).cast()
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
        d.tls_header = src.tls_header;
        d.tls_header_set = src.tls_header_set;
        d.tls_mac_out = src.tls_mac_out;
        d.tls_mac_out_size = src.tls_mac_out_size;
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
        // SAFETY: the context's HMAC context; the caller's key; the digest and engine it holds.
        return unsafe { HMAC_Init_ex(m.ctx, key.cast(), len, digest, m.digest.engine) };
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

/// The digest of a TLS record MAC, as `ssl3_cbc_digest_record` tells it by name.
///
/// # Safety
/// `md` is a live digest.
unsafe fn record_digest(md: *const EVP_MD) -> Option<RecordDigest> {
    [
        (c"MD5", RecordDigest::Md5),
        (c"SHA1", RecordDigest::Sha1),
        (c"SHA2-224", RecordDigest::Sha224),
        (c"SHA2-256", RecordDigest::Sha256),
        (c"SHA2-384", RecordDigest::Sha384),
        (c"SHA2-512", RecordDigest::Sha512),
    ]
    .into_iter()
    // SAFETY: the caller's guarantee; static names.
    .find(|(name, _)| unsafe { EVP_MD_is_a(md, name.as_ptr()) } != 0)
    .map(|(_, d)| d)
}

/// `hmac_update` in TLS mode: the first update is the record's 13-octet header, each one after
/// a record whose data is `len` octets (its MAC and padding follow, to `tls_data_size`).
///
/// # Safety
/// `data` holds `len` octets for the header, and `tls_data_size` for a record.
unsafe fn hmac_tls_update(m: &mut HmacData, data: *const u8, len: usize) -> c_int {
    if !m.tls_header_set {
        if len != m.tls_header.len() || data.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee: 13 octets.
        let header = unsafe { core::slice::from_raw_parts(data, len) };
        m.tls_header.copy_from_slice(header);
        m.tls_header_set = true;
        return 1;
    }
    if m.tls_data_size < len {
        return 0;
    }
    // The reference's assertion, before anything else.
    if m.tls_data_size >= 1024 * 1024 {
        return 0;
    }
    let md = m.digest.method;
    // Without a digest the reference reads through NULL (docs/DEVIATIONS.md).
    if md.is_null() || data.is_null() {
        return 0;
    }
    // SAFETY: the digest the context holds.
    let Some(digest) = (unsafe { record_digest(md) }) else {
        m.tls_mac_out_size = 0;
        return 0;
    };
    // SAFETY: the caller's guarantee: the whole record.
    let record = unsafe { core::slice::from_raw_parts(data, m.tls_data_size) };
    let secret = m.key.as_deref().unwrap_or_default();
    let Some(mac) = tls_cbc_record_mac(digest, &m.tls_header, record, len, secret) else {
        return 0;
    };
    m.tls_mac_out.fill(0);
    if let Some(d) = m.tls_mac_out.get_mut(..mac.len()) {
        d.copy_from_slice(&mac);
    }
    m.tls_mac_out_size = mac.len();
    1
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
            // SAFETY: the caller's guarantee (in TLS mode, the whole record).
            return unsafe { hmac_tls_update(m, data, len) };
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
            if m.tls_mac_out_size == 0 {
                return 0;
            }
            let n = m.tls_mac_out_size;
            if !outl.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { outl.write(n) };
            }
            // SAFETY: the caller's guarantee: room for the MAC; the context's own MAC.
            unsafe { ptr::copy_nonoverlapping(m.tls_mac_out.as_ptr(), out, n) };
            return 1;
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
            m.cipher.engine,
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
            // SAFETY: the context's cipher context; the cipher and engine it holds.
            if unsafe { EVP_EncryptInit_ex(m.ctx, m.cipher.method, m.cipher.engine, ptr::null(), ptr::null()) } == 0 {
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

// -------------------------------------------------------------------------------------------
// Shared by the rest

/// `len` octets at `data` as a slice (empty for none): `None` for NULL with a length, which the
/// reference reads through (docs/DEVIATIONS.md).
///
/// # Safety
/// `data` is NULL or holds `len` octets that outlive `'a`.
pub(crate) unsafe fn octets_at<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if data.is_null() {
        None
    } else {
        // SAFETY: the caller's guarantee.
        Some(unsafe { core::slice::from_raw_parts(data, len) })
    }
}

/// A parameter's octets, whatever its type (as these MACs take them): `None` as for
/// [`octets_at`].
///
/// # Safety
/// The parameter's data is NULL or holds `data_size` octets that outlive `'a`.
pub(crate) unsafe fn param_octets<'a>(p: &OSSL_PARAM) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    unsafe { octets_at(p.data.cast_const().cast(), p.data_size) }
}

/// Raises `reason` (in `ERR_LIB_PROV`) for a provided MAC's error.
fn raise_mac(e: MacError, function: &str) {
    let reason = match e {
        MacError::InvalidKeyLength => PROV_R_INVALID_KEY_LENGTH,
        MacError::NoKeySet => PROV_R_NO_KEY_SET,
        MacError::InvalidLength => PROV_R_NOT_XOF_OR_INVALID_LENGTH,
        MacError::InvalidCustomLength => PROV_R_INVALID_CUSTOM_LENGTH,
        MacError::InvalidSaltLength => PROV_R_INVALID_SALT_LENGTH,
        MacError::Finished | MacError::Silent => return,
    };
    err::raise(ERR_LIB_PROV, reason, function);
}

/// Writes `n` to `outl` if it's there.
///
/// # Safety
/// `outl` is NULL or valid for a write.
pub(crate) unsafe fn set_outl(outl: *mut usize, n: usize) {
    if !outl.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { outl.write(n) };
    }
}

/// Boxes a context for `newctx`.
pub(crate) fn boxed<T>(t: T) -> *mut c_void {
    Box::into_raw(Box::new(t)).cast()
}

/// Frees a context `newctx` boxed.
///
/// # Safety
/// `vctx` is NULL or a box of a `T` from [`boxed`], not used afterwards.
pub(crate) unsafe fn unbox<T>(vctx: *mut c_void) {
    if !vctx.is_null() {
        // SAFETY: the caller's guarantee.
        drop(unsafe { Box::from_raw(vctx.cast::<T>()) });
    }
}

/// A copy of a cloneable context, for `dupctx`.
///
/// # Safety
/// `vctx` is NULL or a live box of a `T`.
pub(crate) unsafe fn dup_boxed<T: Clone>(vctx: *mut c_void) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    unsafe { context::<T>(vctx) }.map_or(ptr::null_mut(), |t| boxed(t.clone()))
}

// -------------------------------------------------------------------------------------------
// Poly1305

ffi_callback! {
    /// `poly1305_new`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn poly1305_new(_provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(Poly1305::new())
    }
}

ffi_callback! {
    /// `poly1305_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context `poly1305_new` made, not used afterwards.
    pub(crate) unsafe extern "C" fn poly1305_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Poly1305>(vctx) };
    }
}

ffi_callback! {
    /// `poly1305_dup`.
    ///
    /// # Safety
    /// `vctx` is a live Poly1305 context.
    pub(crate) unsafe extern "C" fn poly1305_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_boxed::<Poly1305>(vctx) }
    }
}

/// `poly1305_setkey`: a 32-octet key.
fn poly1305_setkey(m: &mut Poly1305, key: Option<&[u8]>) -> c_int {
    match m.set_key(key) {
        Ok(()) => 1,
        Err(e) => {
            raise_mac(e, "poly1305_setkey");
            0
        }
    }
}

ffi_callback! {
    /// `poly1305_init`: with a key, or again before the context has been used.
    ///
    /// # Safety
    /// `vctx` is a live Poly1305 context; `key` is NULL or holds `keylen` octets; `params` is
    /// NULL or a parameter array.
    pub(crate) unsafe extern "C" fn poly1305_init(vctx: *mut c_void, key: *const u8, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { poly1305_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<Poly1305>(vctx) }) else { return 0 };
        if key.is_null() {
            return c_int::from(m.restart());
        }
        // SAFETY: the caller's guarantee.
        poly1305_setkey(m, unsafe { octets_at(key, keylen) })
    }
}

ffi_callback! {
    /// `poly1305_update`.
    ///
    /// # Safety
    /// `vctx` is a live Poly1305 context; `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn poly1305_update(vctx: *mut c_void, data: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<Poly1305>(vctx) }) else { return 0 };
        // SAFETY: as above.
        let Some(input) = (unsafe { octets_at(data, len) }) else { return 0 };
        match m.update(input) {
            Ok(()) => 1,
            Err(e) => {
                raise_mac(e, "poly1305_update");
                0
            }
        }
    }
}

ffi_callback! {
    /// `poly1305_final`: the 16-octet tag.
    ///
    /// # Safety
    /// `vctx` is a live Poly1305 context; `out` has room for 16 octets; `outl` is NULL or
    /// valid for a write.
    pub(crate) unsafe extern "C" fn poly1305_final(vctx: *mut c_void, out: *mut u8, outl: *mut usize, _outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<Poly1305>(vctx) }) else { return 0 };
        match m.finalize() {
            Ok(mut tag) => {
                // SAFETY: the caller's guarantee: room for the tag.
                unsafe { ptr::copy_nonoverlapping(tag.as_ptr(), out, tag.len()) };
                wipe(&mut tag);
                // SAFETY: as above.
                unsafe { set_outl(outl, Poly1305::SIZE) };
                1
            }
            Err(e) => {
                raise_mac(e, "poly1305_final");
                0
            }
        }
    }
}

static POLY1305_GETTABLE: Params<2> = Params([
    defn(
        OSSL_MAC_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    PARAM_END,
]);

static POLY1305_SETTABLE_CTX: Params<2> = Params([
    defn(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `poly1305_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn poly1305_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        POLY1305_GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `poly1305_get_params`: the size, 16.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn poly1305_get_params(params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { set_size(params, OSSL_MAC_PARAM_SIZE, Poly1305::SIZE) })
    }
}

ffi_callback! {
    /// `poly1305_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn poly1305_settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        POLY1305_SETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `poly1305_set_ctx_params`: the key.
    ///
    /// # Safety
    /// `vctx` is a live Poly1305 context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn poly1305_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<Poly1305>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_KEY) } {
            // SAFETY: the parameter's data.
            let key = if p.data.is_null() { None } else { unsafe { param_octets(p) } };
            return poly1305_setkey(m, key);
        }
        1
    }
}

static POLY1305_FUNCTIONS: Dispatch<11> = Dispatch([
    entry!(OSSL_FUNC_MAC_NEWCTX, poly1305_new, NewCtxFn),
    entry!(OSSL_FUNC_MAC_DUPCTX, poly1305_dup, DupCtxFn),
    entry!(OSSL_FUNC_MAC_FREECTX, poly1305_free, FreeCtxFn),
    entry!(OSSL_FUNC_MAC_INIT, poly1305_init, InitFn),
    entry!(OSSL_FUNC_MAC_UPDATE, poly1305_update, UpdateFn),
    entry!(OSSL_FUNC_MAC_FINAL, poly1305_final, FinalFn),
    entry!(
        OSSL_FUNC_MAC_GETTABLE_PARAMS,
        poly1305_gettable_params,
        GettableFn
    ),
    entry!(OSSL_FUNC_MAC_GET_PARAMS, poly1305_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        poly1305_settable_ctx_params,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_SET_CTX_PARAMS,
        poly1305_set_ctx_params,
        SetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// SipHash

ffi_callback! {
    /// `siphash_new`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn siphash_new(_provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(SipHash::new())
    }
}

ffi_callback! {
    /// `siphash_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a context `siphash_new` made, not used afterwards.
    pub(crate) unsafe extern "C" fn siphash_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<SipHash>(vctx) };
    }
}

ffi_callback! {
    /// `siphash_dup`.
    ///
    /// # Safety
    /// `vctx` is a live SipHash context.
    pub(crate) unsafe extern "C" fn siphash_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_boxed::<SipHash>(vctx) }
    }
}

ffi_callback! {
    /// `siphash_init`: with a key, or back to the state after the last one.
    ///
    /// # Safety
    /// `vctx` is a live SipHash context; `key` is NULL or holds `keylen` octets; `params` is
    /// NULL or a parameter array.
    pub(crate) unsafe extern "C" fn siphash_init(vctx: *mut c_void, key: *const u8, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { siphash_set_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<SipHash>(vctx) }) else { return 0 };
        if key.is_null() {
            m.restart();
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { octets_at(key, keylen) }) else { return 0 };
        c_int::from(m.set_key(k))
    }
}

ffi_callback! {
    /// `siphash_update`.
    ///
    /// # Safety
    /// `vctx` is a live SipHash context; `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn siphash_update(vctx: *mut c_void, data: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<SipHash>(vctx) }) else { return 0 };
        // SAFETY: as above.
        let Some(input) = (unsafe { octets_at(data, len) }) else { return 0 };
        m.update(input);
        1
    }
}

ffi_callback! {
    /// `siphash_final`: the hash, 8 or 16 octets, into room for `outsize`.
    ///
    /// # Safety
    /// `vctx` is a live SipHash context; `out` has room for `outsize` octets; `outl` is NULL or
    /// valid for a write.
    pub(crate) unsafe extern "C" fn siphash_final(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<SipHash>(vctx) }) else { return 0 };
        let hlen = m.size();
        if outsize < hlen || out.is_null() {
            return 0;
        }
        // SAFETY: as above.
        unsafe { set_outl(outl, hlen) };
        // SAFETY: the caller's guarantee: room for `outsize` octets, at least `hlen`.
        let dest = unsafe { core::slice::from_raw_parts_mut(out, hlen) };
        c_int::from(m.finalize(dest))
    }
}

static SIPHASH_GETTABLE_CTX: Params<4> = Params([
    defn(
        OSSL_MAC_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    defn(
        OSSL_MAC_PARAM_C_ROUNDS,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        UINT,
    ),
    defn(
        OSSL_MAC_PARAM_D_ROUNDS,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        UINT,
    ),
    PARAM_END,
]);

static SIPHASH_SETTABLE_CTX: Params<5> = Params([
    defn(
        OSSL_MAC_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    defn(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(
        OSSL_MAC_PARAM_C_ROUNDS,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        UINT,
    ),
    defn(
        OSSL_MAC_PARAM_D_ROUNDS,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        UINT,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `siphash_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn siphash_gettable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SIPHASH_GETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `siphash_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn siphash_settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SIPHASH_SETTABLE_CTX.0.as_ptr()
    }
}

/// Sets the `unsigned int` parameter `key` of `params`, if there. False if it's there and
/// can't be.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn set_uint(params: *mut OSSL_PARAM, key: &core::ffi::CStr, value: c_uint) -> bool {
    // SAFETY: the caller's guarantee.
    let p = unsafe { OSSL_PARAM_locate(params, key.as_ptr()) };
    // SAFETY: a parameter of the array.
    p.is_null() || unsafe { OSSL_PARAM_set_uint(p, value) } != 0
}

ffi_callback! {
    /// `siphash_get_ctx_params`: the size and the rounds.
    ///
    /// # Safety
    /// `vctx` is a live SipHash context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn siphash_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<SipHash>(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee, here and below.
        let ok = unsafe { set_size(params, OSSL_MAC_PARAM_SIZE, m.size()) }
            // SAFETY: as above.
            && unsafe { set_uint(params, OSSL_MAC_PARAM_C_ROUNDS, m.c_rounds()) }
            // SAFETY: as above.
            && unsafe { set_uint(params, OSSL_MAC_PARAM_D_ROUNDS, m.d_rounds()) };
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `siphash_set_params`: the size, the rounds, and the key.
    ///
    /// # Safety
    /// `vctx` is a live SipHash context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn siphash_set_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<SipHash>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_SIZE) } {
            let mut size = 0;
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut size) } == 0 || !m.set_size(size) {
                return 0;
            }
        }
        for (key, set) in [
            (OSSL_MAC_PARAM_C_ROUNDS, SipHash::set_c_rounds as fn(&mut SipHash, u32)),
            (OSSL_MAC_PARAM_D_ROUNDS, SipHash::set_d_rounds),
        ] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, key) } {
                let mut n: c_uint = 0;
                // SAFETY: a parameter of the caller's array.
                if unsafe { OSSL_PARAM_get_uint(p, &raw mut n) } == 0 {
                    return 0;
                }
                set(m, n);
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_KEY) } {
            let Some((key, keylen)) = octets(p) else { return 0 };
            // SAFETY: the parameter's octets.
            let Some(k) = (unsafe { octets_at(key, keylen) }) else { return 0 };
            if !m.set_key(k) {
                return 0;
            }
        }
        1
    }
}

static SIPHASH_FUNCTIONS: Dispatch<11> = Dispatch([
    entry!(OSSL_FUNC_MAC_NEWCTX, siphash_new, NewCtxFn),
    entry!(OSSL_FUNC_MAC_DUPCTX, siphash_dup, DupCtxFn),
    entry!(OSSL_FUNC_MAC_FREECTX, siphash_free, FreeCtxFn),
    entry!(OSSL_FUNC_MAC_INIT, siphash_init, InitFn),
    entry!(OSSL_FUNC_MAC_UPDATE, siphash_update, UpdateFn),
    entry!(OSSL_FUNC_MAC_FINAL, siphash_final, FinalFn),
    entry!(
        OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
        siphash_gettable_ctx_params,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_GET_CTX_PARAMS,
        siphash_get_ctx_params,
        GetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
        siphash_settable_ctx_params,
        CtxParamsFn
    ),
    entry!(
        OSSL_FUNC_MAC_SET_CTX_PARAMS,
        siphash_set_params,
        SetCtxParamsFn
    ),
    END,
]);

// -------------------------------------------------------------------------------------------
// BLAKE2BMAC and BLAKE2SMAC

/// One BLAKE2 MAC's dispatch table, over [`Blake2Mac`] of `$alg`.
macro_rules! blake2_mac {
    ($module:ident, $alg:expr) => {
        mod $module {
            use super::*;

            ffi_callback! {
                /// `blake2_mac_new`.
                ///
                /// # Safety
                /// No preconditions.
                pub(crate) unsafe extern "C" fn new(_provctx: *mut c_void) -> *mut c_void
                where failure = ptr::null_mut(), library = ERR_LIB_PROV
                {
                    boxed(Blake2Mac::new($alg))
                }
            }

            pub(super) static FUNCTIONS: Dispatch<11> = Dispatch([
                entry!(OSSL_FUNC_MAC_NEWCTX, new, NewCtxFn),
                entry!(OSSL_FUNC_MAC_DUPCTX, blake2_mac_dup, DupCtxFn),
                entry!(OSSL_FUNC_MAC_FREECTX, blake2_mac_free, FreeCtxFn),
                entry!(OSSL_FUNC_MAC_INIT, blake2_mac_init, InitFn),
                entry!(OSSL_FUNC_MAC_UPDATE, blake2_mac_update, UpdateFn),
                entry!(OSSL_FUNC_MAC_FINAL, blake2_mac_final, FinalFn),
                entry!(
                    OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
                    blake2_gettable_ctx_params,
                    CtxParamsFn
                ),
                entry!(
                    OSSL_FUNC_MAC_GET_CTX_PARAMS,
                    blake2_get_ctx_params,
                    GetCtxParamsFn
                ),
                entry!(
                    OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
                    blake2_mac_settable_ctx_params,
                    CtxParamsFn
                ),
                entry!(
                    OSSL_FUNC_MAC_SET_CTX_PARAMS,
                    blake2_mac_set_ctx_params,
                    SetCtxParamsFn
                ),
                END,
            ]);
        }
    };
}

blake2_mac!(blake2bmac, Blake2Algorithm::Blake2b);
blake2_mac!(blake2smac, Blake2Algorithm::Blake2s);

ffi_callback! {
    /// `blake2_mac_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a BLAKE2 MAC context, not used afterwards.
    pub(crate) unsafe extern "C" fn blake2_mac_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<Blake2Mac>(vctx) };
    }
}

ffi_callback! {
    /// `blake2_mac_dup`.
    ///
    /// # Safety
    /// `vctx` is a live BLAKE2 MAC context.
    pub(crate) unsafe extern "C" fn blake2_mac_dup(vctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_boxed::<Blake2Mac>(vctx) }
    }
}

/// `blake2_setkey`, raising the error.
fn blake2_setkey(m: &mut Blake2Mac, key: Option<&[u8]>) -> bool {
    // A NULL key of a length the reference copies from NULL (docs/DEVIATIONS.md).
    let Some(key) = key else { return false };
    match m.set_key(key) {
        Ok(()) => true,
        Err(e) => {
            raise_mac(e, "blake2_setkey");
            false
        }
    }
}

ffi_callback! {
    /// `blake2_mac_init`: with a key, or the one set.
    ///
    /// # Safety
    /// `vctx` is a live BLAKE2 MAC context; `key` is NULL or holds `keylen` octets; `params`
    /// is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn blake2_mac_init(vctx: *mut c_void, key: *const u8, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { blake2_mac_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<Blake2Mac>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if !key.is_null() && !blake2_setkey(m, unsafe { octets_at(key, keylen) }) {
            return 0;
        }
        match m.start() {
            Ok(()) => 1,
            Err(e) => {
                raise_mac(e, "blake2_mac_init");
                0
            }
        }
    }
}

ffi_callback! {
    /// `blake2_mac_update`.
    ///
    /// # Safety
    /// `vctx` is a live BLAKE2 MAC context; `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn blake2_mac_update(vctx: *mut c_void, data: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<Blake2Mac>(vctx) }) else { return 0 };
        // SAFETY: as above.
        let Some(input) = (unsafe { octets_at(data, len) }) else { return 0 };
        m.update(input);
        1
    }
}

ffi_callback! {
    /// `blake2_mac_final`: the output of the size the MAC was started with (which the reference
    /// writes whole even where the size set since is smaller: here what fits `outsize`).
    ///
    /// # Safety
    /// `vctx` is a live BLAKE2 MAC context; `out` has room for `outsize` octets; `outl` is NULL
    /// or valid for a write.
    pub(crate) unsafe extern "C" fn blake2_mac_final(vctx: *mut c_void, out: *mut u8, outl: *mut usize, outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<Blake2Mac>(vctx) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set_outl(outl, m.size()) };
        let output = m.finalize();
        let n = output.len().min(outsize);
        if n > 0 && !out.is_null() {
            // SAFETY: the caller's guarantee: room for `outsize` octets, at least `n`.
            unsafe { ptr::copy_nonoverlapping(output.as_ptr(), out, n) };
        }
        1
    }
}

static BLAKE2_GETTABLE_CTX: Params<3> = Params([
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

static BLAKE2_SETTABLE_CTX: Params<5> = Params([
    defn(
        OSSL_MAC_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    defn(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_MAC_PARAM_CUSTOM, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_MAC_PARAM_SALT, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `blake2_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn blake2_gettable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        BLAKE2_GETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `blake2_mac_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn blake2_mac_settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        BLAKE2_SETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `blake2_get_ctx_params`: the size and the block size.
    ///
    /// # Safety
    /// `vctx` is a live BLAKE2 MAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn blake2_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { context::<Blake2Mac>(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let ok = unsafe { set_size(params, OSSL_MAC_PARAM_SIZE, m.size()) }
            // SAFETY: as above.
            && unsafe { set_size(params, OSSL_MAC_PARAM_BLOCK_SIZE, m.block_size()) };
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `blake2_mac_set_ctx_params`: the size, key, custom string, and salt.
    ///
    /// # Safety
    /// `vctx` is a live BLAKE2 MAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn blake2_mac_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(m) = (unsafe { context::<Blake2Mac>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_SIZE) } {
            let mut size = 0;
            // SAFETY: a parameter of the caller's array.
            let got = unsafe { OSSL_PARAM_get_size_t(p, &raw mut size) } != 0;
            if !got || m.set_size(size).is_err() {
                err::raise(ERR_LIB_PROV, PROV_R_NOT_XOF_OR_INVALID_LENGTH, "blake2_mac_set_ctx_params");
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_KEY) } {
            // SAFETY: the parameter's data.
            if !blake2_setkey(m, unsafe { param_octets(p) }) {
                return 0;
            }
        }
        for (key, set) in [
            (OSSL_MAC_PARAM_CUSTOM, Blake2Mac::set_custom as fn(&mut Blake2Mac, &[u8]) -> Result<(), MacError>),
            (OSSL_MAC_PARAM_SALT, Blake2Mac::set_salt),
        ] {
            // SAFETY: as above.
            if let Some(p) = unsafe { locate(params, key) } {
                // SAFETY: the parameter's data.
                let value = unsafe { param_octets(p) };
                let r = match value {
                    Some(v) => set(m, v),
                    // Longer than allowed is refused first; NULL data within it is copied from
                    // NULL by the reference (docs/DEVIATIONS.md).
                    None => {
                        let zeros = [0u8; 64];
                        let probe = zeros.get(..p.data_size).unwrap_or(&zeros);
                        set(m, probe).and(Err(MacError::Silent))
                    }
                };
                if let Err(e) = r {
                    raise_mac(e, "blake2_mac_set_ctx_params");
                    return 0;
                }
            }
        }
        1
    }
}

// -------------------------------------------------------------------------------------------
// KMAC-128 and KMAC-256

/// `KMAC_MAX_OUTPUT_LEN`.
const KMAC_MAX_OUTPUT_LEN: usize = 0x00ff_ffff / 8;
/// `KMAC_MAX_KEY`, `KMAC_MIN_KEY`, `KMAC_MAX_CUSTOM`.
const KMAC_MAX_KEY: usize = 512;
const KMAC_MIN_KEY: usize = 4;
const KMAC_MAX_CUSTOM: usize = 512;
/// `kmac_string`: "KMAC", encoded.
const KMAC_STRING: [u8; 6] = [0x01, 0x20, 0x4b, 0x4d, 0x41, 0x43];

/// `get_encode_size`: the octets `bits` takes, at least one.
fn encode_size(bits: usize) -> usize {
    let n = usize::BITS.saturating_sub(bits.leading_zeros()).div_ceil(8);
    usize::try_from(n).unwrap_or(1).max(1)
}

/// `encode_string`: SP 800-185's encoding of `input` (empty for NULL, which the reference
/// encodes as nothing at all).
fn encode_string(input: Option<&[u8]>) -> Vec<u8> {
    let Some(input) = input else {
        return Vec::new();
    };
    let bits = input.len().wrapping_mul(8);
    let n = encode_size(bits);
    let mut out = Vec::with_capacity(1 + n + input.len());
    out.push(u8::try_from(n).unwrap_or(0));
    out.extend(bits.to_be_bytes().iter().skip(size_of::<usize>() - n));
    out.extend_from_slice(input);
    out
}

/// `right_encode` of `bits`.
fn right_encode(bits: usize) -> Vec<u8> {
    let n = encode_size(bits);
    let mut out: Vec<u8> = bits
        .to_be_bytes()
        .iter()
        .skip(size_of::<usize>() - n)
        .copied()
        .collect();
    out.push(u8::try_from(n).unwrap_or(0));
    out
}

/// `bytepad(in1 || in2, w)`.
fn bytepad(in1: &[u8], in2: &[u8], w: usize) -> Vec<u8> {
    let mut out = vec![1, u8::try_from(w).unwrap_or(0)];
    out.extend_from_slice(in1);
    out.extend_from_slice(in2);
    let padded = out.len().div_ceil(w.max(1)) * w.max(1);
    out.resize(padded, 0);
    out
}

/// `struct kmac_data_st`.
struct KmacData {
    provctx: *mut c_void,
    ctx: *mut EVP_MD_CTX,
    digest: Prov<EVP_MD>,
    out_len: usize,
    xof_mode: c_int,
    /// The key, encoded and padded; empty until set.
    key: Vec<u8>,
    /// The customization string, encoded; empty until set (or set from NULL).
    custom: Vec<u8>,
}

impl Drop for KmacData {
    fn drop(&mut self) {
        // SAFETY: the context's own digest context.
        unsafe { EVP_MD_CTX_free(self.ctx) };
        wipe(&mut self.key);
        wipe(&mut self.custom);
    }
}

/// `kmac_new`: a context with its digest context and nothing else.
fn kmac_new(provctx: *mut c_void) -> Option<KmacData> {
    // SAFETY: no preconditions.
    let ctx = unsafe { EVP_MD_CTX_new() };
    (!ctx.is_null()).then_some(KmacData {
        provctx,
        ctx,
        digest: Prov::NONE,
        out_len: 0,
        xof_mode: 0,
        key: Vec::new(),
        custom: Vec::new(),
    })
}

/// `kmac_fetch_new`: a context with the KECCAK-KMAC digest `name`, its output that digest's
/// size.
///
/// # Safety
/// `provctx` is the provider's context.
unsafe fn kmac_fetch_new(provctx: *mut c_void, name: &'static core::ffi::CStr) -> *mut c_void {
    let Some(mut k) = kmac_new(provctx) else {
        return ptr::null_mut();
    };
    let params = [
        // SAFETY: static strings.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_ALG_PARAM_DIGEST.as_ptr(),
                name.as_ptr().cast_mut(),
                0,
            )
        },
        end(),
    ];
    // SAFETY: the provider's context.
    let libctx = unsafe { libctx_of(provctx) };
    // SAFETY: the array above.
    if !unsafe {
        k.digest
            .load(params.as_ptr(), OSSL_ALG_PARAM_DIGEST, libctx)
    } {
        return ptr::null_mut();
    }
    // SAFETY: the digest just fetched.
    let Ok(size) = usize::try_from(unsafe { EVP_MD_get_size(k.digest.method) }) else {
        return ptr::null_mut();
    };
    if size == 0 {
        return ptr::null_mut();
    }
    k.out_len = size;
    boxed(k)
}

ffi_callback! {
    /// `kmac128_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn kmac128_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { kmac_fetch_new(provctx, c"KECCAK-KMAC-128") }
    }
}

ffi_callback! {
    /// `kmac256_new`.
    ///
    /// # Safety
    /// `provctx` is the provider's context.
    pub(crate) unsafe extern "C" fn kmac256_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { kmac_fetch_new(provctx, c"KECCAK-KMAC-256") }
    }
}

ffi_callback! {
    /// `kmac_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a KMAC context, not used afterwards.
    pub(crate) unsafe extern "C" fn kmac_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<KmacData>(vctx) };
    }
}

ffi_callback! {
    /// `kmac_dup`.
    ///
    /// # Safety
    /// `vsrc` is a live KMAC context.
    pub(crate) unsafe extern "C" fn kmac_dup(vsrc: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { context::<KmacData>(vsrc) }) else { return ptr::null_mut() };
        let Some(mut dst) = kmac_new(src.provctx) else { return ptr::null_mut() };
        // SAFETY: the two contexts' digest contexts.
        if unsafe { EVP_MD_CTX_copy(dst.ctx, src.ctx) } == 0 {
            return ptr::null_mut();
        }
        let Some(digest) = src.digest.copy() else { return ptr::null_mut() };
        dst.digest = digest;
        dst.out_len = src.out_len;
        dst.xof_mode = src.xof_mode;
        dst.key = src.key.clone();
        dst.custom = src.custom.clone();
        boxed(dst)
    }
}

/// `kmac_setkey`: 4 to 512 octets (NULL is encoded as nothing, as the reference does).
fn kmac_setkey(k: &mut KmacData, key: Option<&[u8]>, keylen: usize) -> bool {
    // SAFETY: the digest the context holds.
    let w = unsafe { EVP_MD_get_block_size(k.digest.method) };
    if !(KMAC_MIN_KEY..=KMAC_MAX_KEY).contains(&keylen) {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, "kmac_setkey");
        return false;
    }
    let Ok(w) = usize::try_from(w) else {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH, "kmac_setkey");
        return false;
    };
    if w == 0 {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH, "kmac_setkey");
        return false;
    }
    wipe(&mut k.key);
    let mut encoded = encode_string(key);
    k.key = bytepad(&encoded, &[], w);
    wipe(&mut encoded);
    true
}

ffi_callback! {
    /// `kmac_init`: absorbs the padded "KMAC" and customization string, then the key.
    ///
    /// # Safety
    /// `vctx` is a live KMAC context; `key` is NULL or holds `keylen` octets; `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn kmac_init(vctx: *mut c_void, key: *const u8, keylen: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { kmac_set_ctx_params(vctx, params) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(k) = (unsafe { context::<KmacData>(vctx) }) else { return 0 };
        if !key.is_null() {
            // SAFETY: the caller's guarantee.
            let Some(kb) = (unsafe { octets_at(key, keylen) }) else { return 0 };
            if !kmac_setkey(k, Some(kb), keylen) {
                return 0;
            }
        } else if k.key.is_empty() {
            err::raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET, "kmac_init");
            return 0;
        }
        // SAFETY: the context's digest context; the digest it holds.
        if unsafe { EVP_DigestInit_ex(k.ctx, k.digest.method, ptr::null_mut()) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Ok(block_len) = usize::try_from(unsafe { EVP_MD_get_block_size(k.digest.method) }) else {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH, "kmac_init");
            return 0;
        };
        if block_len == 0 {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST_LENGTH, "kmac_init");
            return 0;
        }
        if k.custom.is_empty() {
            k.custom = encode_string(Some(&[]));
        }
        let pad = bytepad(&KMAC_STRING, &k.custom, block_len);
        // SAFETY: the context's digest context; the octets above.
        let ok = unsafe { EVP_DigestUpdate(k.ctx, pad.as_ptr().cast(), pad.len()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestUpdate(k.ctx, k.key.as_ptr().cast(), k.key.len()) } != 0;
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `kmac_update`.
    ///
    /// # Safety
    /// `vctx` is a live KMAC context; `data` holds `len` octets.
    pub(crate) unsafe extern "C" fn kmac_update(vctx: *mut c_void, data: *const u8, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { context::<KmacData>(vctx) }) else { return 0 };
        // SAFETY: the context's digest context; the caller's data.
        unsafe { EVP_DigestUpdate(k.ctx, data.cast(), len) }
    }
}

ffi_callback! {
    /// `kmac_final`: the output length (0 in XOF mode), encoded, then `out_len` octets.
    ///
    /// # Safety
    /// `vctx` is a live KMAC context; `out` has room for the output; `outl` is NULL or valid
    /// for a write.
    pub(crate) unsafe extern "C" fn kmac_final(vctx: *mut c_void, out: *mut u8, outl: *mut usize, _outsize: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { context::<KmacData>(vctx) }) else { return 0 };
        let lbits = if k.xof_mode != 0 { 0 } else { k.out_len.wrapping_mul(8) };
        let encoded = right_encode(lbits);
        let ok = if encoded.len() > 4 {
            err::raise(ERR_LIB_PROV, PROV_R_LENGTH_TOO_LARGE, "right_encode");
            false
        } else {
            // SAFETY: the context's digest context; the octets above; the caller's room.
            let updated = unsafe { EVP_DigestUpdate(k.ctx, encoded.as_ptr().cast(), encoded.len()) };
            // SAFETY: as above.
            updated != 0 && unsafe { EVP_DigestFinalXOF(k.ctx, out, k.out_len) } != 0
        };
        // SAFETY: the caller's guarantee.
        unsafe { set_outl(outl, k.out_len) };
        c_int::from(ok)
    }
}

static KMAC_GETTABLE_CTX: Params<3> = Params([
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

static KMAC_SETTABLE_CTX: Params<5> = Params([
    defn(OSSL_MAC_PARAM_XOF, OSSL_PARAM_INTEGER as c_int, INT),
    defn(
        OSSL_MAC_PARAM_SIZE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        SIZE_T,
    ),
    defn(OSSL_MAC_PARAM_KEY, OSSL_PARAM_OCTET_STRING as c_int, 0),
    defn(OSSL_MAC_PARAM_CUSTOM, OSSL_PARAM_OCTET_STRING as c_int, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `kmac_gettable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn kmac_gettable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        KMAC_GETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `kmac_settable_ctx_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn kmac_settable_ctx_params(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        KMAC_SETTABLE_CTX.0.as_ptr()
    }
}

ffi_callback! {
    /// `kmac_get_ctx_params`: the output size and the digest's block size (as an `int`).
    ///
    /// # Safety
    /// `vctx` is a live KMAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn kmac_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { context::<KmacData>(vctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if !unsafe { set_size(params, OSSL_MAC_PARAM_SIZE, k.out_len) } {
            return 0;
        }
        // SAFETY: as above.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_MAC_PARAM_BLOCK_SIZE.as_ptr()) };
        if !p.is_null() {
            // SAFETY: the digest the context holds.
            let sz = unsafe { EVP_MD_get_block_size(k.digest.method) };
            // SAFETY: a parameter of the array.
            if unsafe { OSSL_PARAM_set_int(p, sz) } == 0 {
                return 0;
            }
        }
        1
    }
}

ffi_callback! {
    /// `kmac_set_ctx_params`: XOF mode, the output size, the key, and the customization string.
    ///
    /// # Safety
    /// `vctx` is a live KMAC context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn kmac_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(k) = (unsafe { context::<KmacData>(vctx) }) else { return 0 };
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_XOF) } {
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_get_int(p, &raw mut k.xof_mode) } == 0 {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_SIZE) } {
            let mut sz = 0;
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_get_size_t(p, &raw mut sz) } == 0 {
                return 0;
            }
            if sz > KMAC_MAX_OUTPUT_LEN {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_OUTPUT_LENGTH, "kmac_set_ctx_params");
                return 0;
            }
            k.out_len = sz;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_KEY) } {
            let key = if p.data.is_null() {
                None
            } else {
                // SAFETY: the parameter's data.
                let Some(kb) = (unsafe { param_octets(p) }) else { return 0 };
                Some(kb)
            };
            if !kmac_setkey(k, key, p.data_size) {
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_MAC_PARAM_CUSTOM) } {
            if p.data_size > KMAC_MAX_CUSTOM {
                err::raise(ERR_LIB_PROV, PROV_R_INVALID_CUSTOM_LENGTH, "kmac_set_ctx_params");
                return 0;
            }
            let custom = if p.data.is_null() {
                None
            } else {
                // SAFETY: the parameter's data.
                let Some(c) = (unsafe { param_octets(p) }) else { return 0 };
                Some(c)
            };
            wipe(&mut k.custom);
            k.custom = encode_string(custom);
        }
        1
    }
}

/// A KMAC's dispatch table, with its `newctx`.
macro_rules! kmac_table {
    ($new:ident) => {
        Dispatch([
            entry!(OSSL_FUNC_MAC_NEWCTX, $new, NewCtxFn),
            entry!(OSSL_FUNC_MAC_DUPCTX, kmac_dup, DupCtxFn),
            entry!(OSSL_FUNC_MAC_FREECTX, kmac_free, FreeCtxFn),
            entry!(OSSL_FUNC_MAC_INIT, kmac_init, InitFn),
            entry!(OSSL_FUNC_MAC_UPDATE, kmac_update, UpdateFn),
            entry!(OSSL_FUNC_MAC_FINAL, kmac_final, FinalFn),
            entry!(
                OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
                kmac_gettable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_MAC_GET_CTX_PARAMS,
                kmac_get_ctx_params,
                GetCtxParamsFn
            ),
            entry!(
                OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
                kmac_settable_ctx_params,
                CtxParamsFn
            ),
            entry!(
                OSSL_FUNC_MAC_SET_CTX_PARAMS,
                kmac_set_ctx_params,
                SetCtxParamsFn
            ),
            END,
        ])
    };
}

static KMAC128_FUNCTIONS: Dispatch<11> = kmac_table!(kmac128_new);
static KMAC256_FUNCTIONS: Dispatch<11> = kmac_table!(kmac256_new);

/// `deflt_macs`, in the reference's order.
static DEFAULT_MACS: Algorithms<10> = Algorithms([
    alg(
        c"BLAKE2BMAC:1.3.6.1.4.1.1722.12.2.1",
        &blake2bmac::FUNCTIONS,
    ),
    alg(
        c"BLAKE2SMAC:1.3.6.1.4.1.1722.12.2.2",
        &blake2smac::FUNCTIONS,
    ),
    alg(c"CMAC", &CMAC_FUNCTIONS),
    alg(c"GMAC:1.0.9797.3.4", &GMAC_FUNCTIONS),
    alg(c"HMAC", &HMAC_FUNCTIONS),
    alg(
        c"KMAC-128:KMAC128:2.16.840.1.101.3.4.2.19",
        &KMAC128_FUNCTIONS,
    ),
    alg(
        c"KMAC-256:KMAC256:2.16.840.1.101.3.4.2.20",
        &KMAC256_FUNCTIONS,
    ),
    alg(c"SIPHASH", &SIPHASH_FUNCTIONS),
    alg(c"POLY1305", &POLY1305_FUNCTIONS),
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
        EVP_MAC_CTX_free, EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch, EVP_MAC_final,
        EVP_MAC_free, EVP_MAC_init, EVP_MAC_update,
    };
    use crate::params::OSSL_PARAM_construct_size_t;

    /// The `dynamic` engine refuses `ENGINE_init`, so naming it fails, as in the
    /// reference; a later load without the parameter has no engine.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn uninitializable_engines_are_refused() {
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

    /// A context of the MAC `name`.
    fn context_of(name: &core::ffi::CStr) -> *mut rustyssl_abi::EVP_MAC_CTX {
        // SAFETY: a static name.
        let m = unsafe { EVP_MAC_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
        // SAFETY: the method just fetched.
        let ctx = unsafe { EVP_MAC_CTX_new(m) };
        // SAFETY: as above.
        unsafe { EVP_MAC_free(m) };
        ctx
    }

    /// docs/DEVIATIONS.md: a BLAKE2 MAC whose size is set below the one it started with writes
    /// only what fits the room (the reference writes the whole output past it).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn blake2_writes_only_what_fits() {
        let ctx = context_of(c"BLAKE2BMAC");
        let key = [1u8; 16];
        // SAFETY: the context; the key above.
        let r = unsafe { EVP_MAC_init(ctx, key.as_ptr(), key.len(), ptr::null()) };
        assert_eq!(r, 1);
        let mut size = 20usize;
        // SAFETY: the size outlives the parameters.
        let params = [
            unsafe { OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_SIZE.as_ptr(), &raw mut size) },
            end(),
        ];
        // SAFETY: the context; the parameters above.
        assert_eq!(unsafe { EVP_MAC_CTX_set_params(ctx, params.as_ptr()) }, 1);
        let mut out = [0xeeu8; 64];
        let mut outl = 0;
        // SAFETY: the context; room for 20 octets of the buffer.
        let r = unsafe { EVP_MAC_final(ctx, out.as_mut_ptr(), &raw mut outl, 20) };
        assert_eq!((r, outl), (1, 20));
        assert!(out[20..].iter().all(|&b| b == 0xee));
        assert!(out[..20].iter().any(|&b| b != 0xee));
        // SAFETY: the test's context.
        unsafe { EVP_MAC_CTX_free(ctx) };
    }

    /// docs/DEVIATIONS.md: NULL data of a nonzero length (an update, or a key, custom string,
    /// or salt parameter) fails, as does HMAC's TLS mode without a digest (the reference reads
    /// through NULL).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn null_data_is_refused() {
        let key = [3u8; 32];
        for (name, keylen) in [(c"SIPHASH", 16), (c"BLAKE2SMAC", 32), (c"POLY1305", 32)] {
            let ctx = context_of(name);
            // SAFETY: the context; the key above.
            let r = unsafe { EVP_MAC_init(ctx, key.as_ptr(), keylen, ptr::null()) };
            assert_eq!(r, 1);
            // SAFETY: NULL data with a length is the case under test.
            assert_eq!(unsafe { EVP_MAC_update(ctx, ptr::null(), 5) }, 0);
            let params = [
                // SAFETY: NULL data with a length is the case under test.
                unsafe {
                    OSSL_PARAM_construct_octet_string(
                        OSSL_MAC_PARAM_KEY.as_ptr(),
                        ptr::null_mut(),
                        16,
                    )
                },
                end(),
            ];
            // SAFETY: the context; the parameters above.
            assert_eq!(unsafe { EVP_MAC_CTX_set_params(ctx, params.as_ptr()) }, 0);
            // SAFETY: the test's context.
            unsafe { EVP_MAC_CTX_free(ctx) };
        }
        let ctx = context_of(c"BLAKE2BMAC");
        for p in [OSSL_MAC_PARAM_CUSTOM, OSSL_MAC_PARAM_SALT] {
            // SAFETY: NULL data with a length is the case under test.
            let params = [
                unsafe { OSSL_PARAM_construct_octet_string(p.as_ptr(), ptr::null_mut(), 8) },
                end(),
            ];
            // SAFETY: the context; the parameters above.
            assert_eq!(unsafe { EVP_MAC_CTX_set_params(ctx, params.as_ptr()) }, 0);
        }
        // SAFETY: the test's context.
        unsafe { EVP_MAC_CTX_free(ctx) };

        let ctx = context_of(c"HMAC");
        let mut total = 64usize;
        let header = [0u8; 13];
        let record = [0u8; 64];
        // SAFETY: the size outlives the parameters.
        let params = [
            unsafe {
                OSSL_PARAM_construct_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE.as_ptr(), &raw mut total)
            },
            end(),
        ];
        // SAFETY: the context; the parameters above.
        assert_eq!(unsafe { EVP_MAC_CTX_set_params(ctx, params.as_ptr()) }, 1);
        // SAFETY: the context; the header above.
        assert_eq!(unsafe { EVP_MAC_update(ctx, header.as_ptr(), 13) }, 1);
        // SAFETY: the context; a whole record above.
        assert_eq!(unsafe { EVP_MAC_update(ctx, record.as_ptr(), 10) }, 0);
        // SAFETY: the test's context.
        unsafe { EVP_MAC_CTX_free(ctx) };
        crate::err::take_all();
    }
}
