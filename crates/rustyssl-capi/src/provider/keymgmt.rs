//! The default provider's key managers (`deflt_keymgmt` in `providers/defltprov.c`) for the key
//! types of MACs and KDFs used through `EVP_PKEY`: HMAC, SIPHASH, POLY1305, and CMAC
//! (`mac_legacy_kmgmt.c`), whose keys are a raw private key (and CMAC's cipher), and TLS1-PRF,
//! HKDF, and SCRYPT (`kdf_legacy_kmgmt.c`), whose keys hold nothing. The other key types come
//! with their steps (4.3 onwards).
//!
//! As in OpenSSL, a MAC key's octets are kept in secure memory when the secure heap is on
//! (`CRYPTO_secure_malloc`), its "generation" only takes the key it was given, and a CMAC key's
//! cipher is fetched by name with the key's properties.

use core::ffi::{CStr, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_INVALID_ARGUMENT, EVP_CIPHER,
    OSSL_ALG_PARAM_CIPHER, OSSL_ALGORITHM, OSSL_CALLBACK, OSSL_FUNC_KEYMGMT_EXPORT,
    OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN,
    OSSL_FUNC_KEYMGMT_GEN_CLEANUP, OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GET_PARAMS,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW,
    OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_CIPHER, OSSL_PKEY_PARAM_ENGINE,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PROPERTIES, PROV_R_INVALID_KEY,
};

use super::builtin::libctx_of;
use super::macs::{Prov, locate};
use super::tables::{ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, alg_desc, defn, entry};
use crate::err;
use crate::evp::cipher::{EVP_CIPHER_get0_name, EVP_CIPHER_is_a};
use crate::ffi::ffi_callback;
use crate::mem::CRYPTO_memcmp;
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_octet_string,
    OSSL_PARAM_BLD_push_utf8_string, OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{OSSL_PARAM_locate, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string};
use crate::provider::Ptr;
use crate::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};

const FILE: &CStr = c"providers/implementations/keymgmt/mac_legacy_kmgmt.c";

/// Octets in memory from `CRYPTO_secure_malloc`, cleared and freed when dropped.
struct SecureBytes {
    ptr: Ptr<u8>,
    len: usize,
}

impl SecureBytes {
    /// A copy of `len` octets at `data` in an allocation of `alloc` octets, or `None` if it
    /// can't be allocated.
    ///
    /// # Safety
    /// `data` holds `len` octets (or `len` is 0); `alloc` is at least `len`.
    unsafe fn copy(data: *const u8, len: usize, alloc: usize) -> Option<Self> {
        // SAFETY: a size; the file name is static.
        let ptr: *mut u8 = unsafe { CRYPTO_secure_malloc(alloc, FILE.as_ptr(), 0) }.cast();
        if ptr.is_null() {
            return None;
        }
        if len > 0 {
            // SAFETY: the caller's octets into the allocation of at least `len`.
            unsafe { ptr::copy_nonoverlapping(data, ptr, len) };
        }
        Some(Self { ptr: Ptr(ptr), len })
    }

    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: the allocation holds `len` initialized octets while this lives.
        unsafe { core::slice::from_raw_parts(self.ptr.0, self.len) }
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // SAFETY: the allocation this owns, of at least `len` octets.
        unsafe { CRYPTO_secure_clear_free(self.ptr.0.cast(), self.len, FILE.as_ptr(), 0) };
    }
}

/// `PROV_CIPHER` in a shared key.
struct Cipher(Prov<EVP_CIPHER>);

// SAFETY: a reference to a fetched cipher, which OpenSSL's ciphers allow sharing between threads.
unsafe impl Send for Cipher {}

impl Cipher {
    fn ptr(&self) -> *mut EVP_CIPHER {
        self.0.method
    }
}

/// A MAC key's data (`MAC_KEY`).
struct MacKeyData {
    priv_key: Option<SecureBytes>,
    cipher: Cipher,
    properties: Option<CString>,
}

/// A MAC key (`MAC_KEY`), shared by reference (`ossl_mac_key_up_ref`).
pub(crate) struct MacKey {
    libctx: Ptr<OSSL_LIB_CTX>,
    cmac: bool,
    data: Mutex<MacKeyData>,
}

impl MacKey {
    fn lock(&self) -> MutexGuard<'_, MacKeyData> {
        self.data.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `ossl_mac_key_new`: a new key with one reference.
fn mac_key_new(libctx: *mut OSSL_LIB_CTX, cmac: bool) -> *mut c_void {
    Arc::into_raw(Arc::new(MacKey {
        libctx: Ptr(libctx),
        cmac,
        data: Mutex::new(MacKeyData {
            priv_key: None,
            cipher: Cipher(Prov::NONE),
            properties: None,
        }),
    }))
    .cast_mut()
    .cast()
}

/// The key behind key data, or `None` for NULL.
///
/// # Safety
/// `keydata` is NULL or a live key from `mac_key_new`.
pub(crate) unsafe fn mac_key<'a>(keydata: *const c_void) -> Option<&'a MacKey> {
    // SAFETY: the caller's guarantee.
    unsafe { keydata.cast::<MacKey>().as_ref() }
}

/// `ossl_mac_key_up_ref`: another reference to a MAC key.
///
/// # Safety
/// `keydata` is a live key from `mac_key_new`.
pub(crate) unsafe fn mac_key_up_ref(keydata: *mut c_void) {
    // SAFETY: the caller's guarantee: a live `Arc` pointer.
    unsafe { Arc::increment_strong_count(keydata.cast::<MacKey>().cast_const()) };
}

impl MacKey {
    /// Runs `f` with the key's octets (`None` without a key), its cipher's name (NULL without
    /// one), and its properties, holding its lock: the octets stay in place for `f`.
    pub(crate) fn with<R>(
        &self,
        f: impl FnOnce(Option<&[u8]>, *const core::ffi::c_char, Option<&CStr>) -> R,
    ) -> R {
        let d = self.lock();
        let cipher = d.cipher.ptr();
        let name = if cipher.is_null() {
            ptr::null()
        } else {
            // SAFETY: the key's fetched cipher.
            unsafe { EVP_CIPHER_get0_name(cipher) }
        };
        f(
            d.priv_key.as_ref().map(SecureBytes::as_slice),
            name,
            d.properties.as_deref(),
        )
    }
}

ffi_callback! {
    /// `mac_new`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn mac_new(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        mac_key_new(unsafe { libctx_of(provctx) }, false)
    }
}

ffi_callback! {
    /// `mac_new_cmac`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn mac_new_cmac(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        mac_key_new(unsafe { libctx_of(provctx) }, true)
    }
}

ffi_callback! {
    /// `mac_free`: drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `keydata` is NULL or a key whose reference the caller gives up.
    pub(crate) unsafe extern "C" fn mac_free(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !keydata.is_null() {
            // SAFETY: the caller's reference to a live `Arc`.
            unsafe { Arc::decrement_strong_count(keydata.cast::<MacKey>().cast_const()) };
        }
    }
}

ffi_callback! {
    /// `mac_has`: a MAC key has every part but, for the private key, its key.
    ///
    /// # Safety
    /// `keydata` is NULL or a live key.
    pub(crate) unsafe extern "C" fn mac_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { mac_key(keydata) }) else { return 0 };
        if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int != 0 {
            return c_int::from(k.lock().priv_key.is_some());
        }
        1
    }
}

ffi_callback! {
    /// `mac_match`: the private keys (compared in constant time) and the ciphers' presence and
    /// names.
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are live keys.
    pub(crate) unsafe extern "C" fn mac_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let (Some(k1), Some(k2)) = (unsafe { mac_key(keydata1) }, unsafe { mac_key(keydata2) }) else {
            return 0;
        };
        if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int == 0 {
            return 1;
        }
        // Copies, so one key's lock isn't held while taking the other's.
        let (p1, c1) = {
            let d = k1.lock();
            (d.priv_key.as_ref().map(|k| k.as_slice().to_vec()), d.cipher.ptr())
        };
        let (p2, c2) = {
            let d = k2.lock();
            (d.priv_key.as_ref().map(|k| k.as_slice().to_vec()), d.cipher.ptr())
        };
        let mut ok = match (&p1, &p2) {
            (Some(a), Some(b)) if a.len() == b.len() && c1.is_null() == c2.is_null() => {
                // SAFETY: two buffers of the same length.
                unsafe { CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
            }
            (None, None) if c1.is_null() == c2.is_null() => true,
            _ => false,
        };
        if !c1.is_null() {
            // SAFETY: the second key's fetched cipher.
            let name = unsafe { EVP_CIPHER_get0_name(c2) };
            // SAFETY: the first key's; the name.
            ok = ok && unsafe { EVP_CIPHER_is_a(c1, name) } != 0;
        }
        c_int::from(ok)
    }
}

/// `mac_key_fromdata`: the key's private key, properties, and (for CMAC) cipher from `params`.
/// True if the key has a private key after.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn mac_key_fromdata(key: &MacKey, params: *const OSSL_PARAM) -> bool {
    const F: &str = "mac_key_fromdata";
    let mut d = key.lock();
    // SAFETY: the caller's guarantee.
    if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) } {
        if p.data_type != OSSL_PARAM_OCTET_STRING as u32 {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return false;
        }
        d.priv_key = None;
        // At least one octet, so an empty key differs from none.
        // SAFETY: the parameter's octets.
        let Some(k) =
            (unsafe { SecureBytes::copy(p.data.cast(), p.data_size, p.data_size.max(1)) })
        else {
            return false;
        };
        d.priv_key = Some(k);
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PROPERTIES) } {
        if p.data_type != OSSL_PARAM_UTF8_STRING as u32 {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return false;
        }
        // SAFETY: a UTF-8 string parameter's data is a string.
        d.properties = Some(unsafe { CStr::from_ptr(p.data.cast()) }.to_owned());
    }
    // SAFETY: as above; the key's library context.
    if key.cmac && !unsafe { d.cipher.0.load(params, OSSL_ALG_PARAM_CIPHER, key.libctx.0) } {
        err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, F);
        return false;
    }
    d.priv_key.is_some()
}

ffi_callback! {
    /// `mac_import`: only private keys.
    ///
    /// # Safety
    /// `keydata` is NULL or a live key; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mac_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { mac_key(keydata) }) else { return 0 };
        if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { mac_key_fromdata(k, params) })
    }
}

/// Where `key_to_params` writes: a builder, or an array to fill.
enum Target {
    Builder(*mut rustyssl_abi::OSSL_PARAM_BLD),
    Params(*mut OSSL_PARAM),
}

/// `key_to_params`: the private key and the cipher's name, to a builder or into an array. A
/// builder keeps pointers to the key's octets until it makes its array, so the caller holds the
/// key's lock until then.
fn key_to_params(d: &MacKeyData, target: &Target) -> bool {
    if let Some(k) = &d.priv_key {
        let k = k.as_slice();
        // `ossl_param_build_set_octet_string`.
        let ok = match *target {
            Target::Builder(b) => {
                // SAFETY: a live builder; a static key; the key's octets, which outlive the builder's
                // use of them (the caller's guarantee).
                (unsafe {
                    OSSL_PARAM_BLD_push_octet_string(
                        b,
                        OSSL_PKEY_PARAM_PRIV_KEY.as_ptr(),
                        k.as_ptr().cast(),
                        k.len(),
                    )
                } != 0)
            }
            Target::Params(p) => {
                // SAFETY: the caller's array.
                let p = unsafe { OSSL_PARAM_locate(p, OSSL_PKEY_PARAM_PRIV_KEY.as_ptr()) };
                // SAFETY: a parameter of it; the key's octets.
                p.is_null()
                    || unsafe { OSSL_PARAM_set_octet_string(p, k.as_ptr().cast(), k.len()) } != 0
            }
        };
        if !ok {
            return false;
        }
    }
    let cipher = d.cipher.ptr();
    if !cipher.is_null() {
        // SAFETY: the key's fetched cipher.
        let name = unsafe { EVP_CIPHER_get0_name(cipher) };
        let ok = match *target {
            Target::Builder(b) => {
                // SAFETY: a live builder; a static key; the cipher's name.
                (unsafe {
                    OSSL_PARAM_BLD_push_utf8_string(b, OSSL_PKEY_PARAM_CIPHER.as_ptr(), name, 0)
                } != 0)
            }
            Target::Params(p) => {
                // SAFETY: the caller's array.
                let p = unsafe { OSSL_PARAM_locate(p, OSSL_PKEY_PARAM_CIPHER.as_ptr()) };
                // SAFETY: a parameter of it; the name.
                p.is_null() || unsafe { OSSL_PARAM_set_utf8_string(p, name) } != 0
            }
        };
        if !ok {
            return false;
        }
    }
    true
}

ffi_callback! {
    /// `mac_export`: the private key (and cipher) to `param_cb`.
    ///
    /// # Safety
    /// `keydata` is NULL or a live key; `param_cb` takes `cbarg`.
    pub(crate) unsafe extern "C" fn mac_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { mac_key(keydata) }) else { return 0 };
        if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int == 0 {
            return 0;
        }
        // SAFETY: no preconditions.
        let tmpl = unsafe { OSSL_PARAM_BLD_new() };
        if tmpl.is_null() {
            return 0;
        }
        let mut ret = 0;
        let d = k.lock();
        let params = if key_to_params(&d, &Target::Builder(tmpl)) {
            // SAFETY: the builder made above, whose pointers into the key are still valid.
            unsafe { OSSL_PARAM_BLD_to_param(tmpl) }
        } else {
            ptr::null_mut()
        };
        // The array has its own copies; no lock is held for the callback.
        drop(d);
        {
            if !params.is_null() {
                if let Some(cb) = param_cb {
                    // SAFETY: the caller's callback with the array and its argument.
                    ret = unsafe { cb(params, cbarg) };
                }
                // SAFETY: made above.
                unsafe { OSSL_PARAM_free(params) };
            }
        }
        // SAFETY: made above.
        unsafe { OSSL_PARAM_BLD_free(tmpl) };
        ret
    }
}

static MAC_KEY_TYPES: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

static CMAC_KEY_TYPES: Params<5> = Params([
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_ENGINE, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `mac_imexport_types`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn mac_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int != 0 {
            return MAC_KEY_TYPES.0.as_ptr();
        }
        ptr::null()
    }
}

ffi_callback! {
    /// `cmac_imexport_types`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn cmac_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int != 0 {
            return CMAC_KEY_TYPES.0.as_ptr();
        }
        ptr::null()
    }
}

ffi_callback! {
    /// `mac_get_params`.
    ///
    /// # Safety
    /// `key` is NULL or a live key; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mac_get_params(key: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { mac_key(key) }) else { return 0 };
        c_int::from(key_to_params(&k.lock(), &Target::Params(params)))
    }
}

static MAC_GETTABLE: Params<2> = Params([
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

static CMAC_GETTABLE: Params<4> = Params([
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_ENGINE, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `mac_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn mac_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        MAC_GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `cmac_gettable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn cmac_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        CMAC_GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `mac_set_params`: a new private key (with the other parameters `mac_key_fromdata` takes).
    ///
    /// # Safety
    /// `keydata` is NULL or a live key; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mac_set_params(keydata: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { mac_key(keydata) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) }.is_some() {
            // SAFETY: as above.
            return c_int::from(unsafe { mac_key_fromdata(k, params) });
        }
        1
    }
}

ffi_callback! {
    /// `mac_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn mac_settable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        MAC_GETTABLE.0.as_ptr()
    }
}

/// A MAC key generation context (`struct mac_gen_ctx`).
struct MacGenCtx {
    libctx: Ptr<OSSL_LIB_CTX>,
    selection: c_int,
    priv_key: Option<SecureBytes>,
    cipher: Prov<EVP_CIPHER>,
}

/// The generation context behind `genctx`, or `None` for NULL.
///
/// # Safety
/// `genctx` is NULL or a context from `mac_gen_init`, used by one caller at a time.
unsafe fn gen_ctx<'a>(genctx: *mut c_void) -> Option<&'a mut MacGenCtx> {
    // SAFETY: the caller's guarantee.
    unsafe { genctx.cast::<MacGenCtx>().as_mut() }
}

/// `mac_gen_init_common`.
///
/// # Safety
/// `provctx` is the default provider's context.
unsafe fn gen_init_common(provctx: *mut c_void, selection: c_int) -> *mut c_void {
    Box::into_raw(Box::new(MacGenCtx {
        // SAFETY: the caller's guarantee.
        libctx: Ptr(unsafe { libctx_of(provctx) }),
        selection,
        priv_key: None,
        cipher: Prov::NONE,
    }))
    .cast()
}

/// `mac_gen_set_params`: the key to "generate".
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn gen_set_key(g: &mut MacGenCtx, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) } {
        if p.data_type != OSSL_PARAM_OCTET_STRING as u32 {
            err::raise(
                ERR_LIB_PROV,
                ERR_R_PASSED_INVALID_ARGUMENT,
                "mac_gen_set_params",
            );
            return false;
        }
        // Exactly the key's size: an empty key's allocation fails as OpenSSL's does.
        // SAFETY: the parameter's octets.
        let Some(k) = (unsafe { SecureBytes::copy(p.data.cast(), p.data_size, p.data_size) })
        else {
            return false;
        };
        g.priv_key = Some(k);
    }
    true
}

ffi_callback! {
    /// `mac_gen_set_params`.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mac_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return 0 };
        // SAFETY: as above.
        c_int::from(unsafe { gen_set_key(g, params) })
    }
}

ffi_callback! {
    /// `cmac_gen_set_params`: the key and its cipher.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn cmac_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return 0 };
        // SAFETY: as above.
        if !unsafe { gen_set_key(g, params) } {
            return 0;
        }
        let libctx = g.libctx.0;
        // SAFETY: as above.
        if !unsafe { g.cipher.load(params, OSSL_ALG_PARAM_CIPHER, libctx) } {
            err::raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT, "cmac_gen_set_params");
            return 0;
        }
        1
    }
}

ffi_callback! {
    /// `mac_gen_init`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mac_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let g = unsafe { gen_init_common(provctx, selection) };
        // SAFETY: the context just made; the caller's array.
        if unsafe { mac_gen_set_params(g, params) } == 0 {
            // SAFETY: as above.
            unsafe { mac_gen_cleanup(g) };
            return ptr::null_mut();
        }
        g
    }
}

ffi_callback! {
    /// `cmac_gen_init`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn cmac_gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let g = unsafe { gen_init_common(provctx, selection) };
        // SAFETY: the context just made; the caller's array.
        if unsafe { cmac_gen_set_params(g, params) } == 0 {
            // SAFETY: as above.
            unsafe { mac_gen_cleanup(g) };
            return ptr::null_mut();
        }
        g
    }
}

static MAC_GEN_SETTABLE: Params<2> = Params([
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

static CMAC_GEN_SETTABLE: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `mac_gen_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn mac_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        MAC_GEN_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `cmac_gen_settable_params`.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn cmac_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        CMAC_GEN_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `mac_gen`: a key with the key (and cipher) the context was given; a blank key for
    /// parameters only.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context.
    pub(crate) unsafe extern "C" fn mac_gen(genctx: *mut c_void, _cb: OSSL_CALLBACK, _cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { gen_ctx(genctx) }) else { return ptr::null_mut() };
        // OpenSSL makes a non-CMAC key here, CMAC's too.
        let kd = mac_key_new(g.libctx.0, false);
        if g.selection & OSSL_KEYMGMT_SELECT_KEYPAIR as c_int == 0 {
            return kd;
        }
        // SAFETY: just made.
        let Some(k) = (unsafe { mac_key(kd) }) else { return ptr::null_mut() };
        if g.priv_key.is_none() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, "mac_gen");
            // SAFETY: the reference made above.
            unsafe { mac_free(kd) };
            return ptr::null_mut();
        }
        let Some(cipher) = g.cipher.copy() else {
            // SAFETY: as above.
            unsafe { mac_free(kd) };
            err::raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, "mac_gen");
            return ptr::null_mut();
        };
        g.cipher.reset();
        let mut d = k.lock();
        d.cipher = Cipher(cipher);
        d.priv_key = g.priv_key.take();
        drop(d);
        kd
    }
}

ffi_callback! {
    /// `mac_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context, not used afterwards.
    pub(crate) unsafe extern "C" fn mac_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !genctx.is_null() {
            // SAFETY: the box `gen_init_common` made, freed once.
            drop(unsafe { Box::from_raw(genctx.cast::<MacGenCtx>()) });
        }
    }
}

type NewFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type HasFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;
type MatchFn = unsafe extern "C" fn(*const c_void, *const c_void, c_int) -> c_int;
type ImportFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> c_int;
type TypesFn = unsafe extern "C" fn(c_int) -> *const OSSL_PARAM;
type ExportFn = unsafe extern "C" fn(*mut c_void, c_int, OSSL_CALLBACK, *mut c_void) -> c_int;
type GenInitFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type GenListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type GenFn = unsafe extern "C" fn(*mut c_void, OSSL_CALLBACK, *mut c_void) -> *mut c_void;

/// `ossl_mac_legacy_keymgmt_functions`.
static MAC_LEGACY_KEYMGMT: Dispatch<18> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, mac_new, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, mac_free, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, mac_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        mac_gettable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, mac_set_params, SetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        mac_settable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, mac_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, mac_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, mac_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, mac_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, mac_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, mac_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, mac_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        mac_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        mac_gen_settable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, mac_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, mac_gen_cleanup, FreeFn),
    END,
]);

/// `ossl_cmac_legacy_keymgmt_functions`.
static CMAC_LEGACY_KEYMGMT: Dispatch<18> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, mac_new_cmac, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, mac_free, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, mac_get_params, GetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
        cmac_gettable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, mac_set_params, SetParamsFn),
    entry!(
        OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
        mac_settable_params,
        ListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_HAS, mac_has, HasFn),
    entry!(OSSL_FUNC_KEYMGMT_MATCH, mac_match, MatchFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT, mac_import, ImportFn),
    entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, cmac_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT, mac_export, ExportFn),
    entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, cmac_imexport_types, TypesFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, cmac_gen_init, GenInitFn),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
        cmac_gen_set_params,
        SetParamsFn
    ),
    entry!(
        OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        cmac_gen_settable_params,
        GenListFn
    ),
    entry!(OSSL_FUNC_KEYMGMT_GEN, mac_gen, GenFn),
    entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, mac_gen_cleanup, FreeFn),
    END,
]);

/// A KDF's key data (`KDF_DATA`): nothing but the context, shared by reference.
pub(crate) struct KdfData {
    #[expect(dead_code, reason = "OpenSSL's KDF_DATA keeps it; nothing reads it")]
    libctx: Ptr<OSSL_LIB_CTX>,
}

/// `ossl_kdf_data_up_ref`: adds a reference to a KDF's key data.
///
/// # Safety
/// `kdfdata` is live data from `kdf_newdata`.
pub(crate) unsafe fn kdf_data_up_ref(kdfdata: *mut c_void) {
    // SAFETY: the caller's guarantee: a live `Arc`.
    unsafe { Arc::increment_strong_count(kdfdata.cast::<KdfData>().cast_const()) };
}

ffi_callback! {
    /// `kdf_newdata`.
    ///
    /// # Safety
    /// `provctx` is the default provider's context.
    pub(crate) unsafe extern "C" fn kdf_newdata(provctx: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        Arc::into_raw(Arc::new(KdfData {
            // SAFETY: the caller's guarantee.
            libctx: Ptr(unsafe { libctx_of(provctx) }),
        }))
        .cast_mut()
        .cast()
    }
}

ffi_callback! {
    /// `kdf_freedata`: drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `kdfdata` is NULL or data whose reference the caller gives up.
    pub(crate) unsafe extern "C" fn kdf_freedata(kdfdata: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        if !kdfdata.is_null() {
            // SAFETY: the caller's reference to a live `Arc`.
            unsafe { Arc::decrement_strong_count(kdfdata.cast::<KdfData>().cast_const()) };
        }
    }
}

ffi_callback! {
    /// `kdf_has`: nothing is ever missing.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn kdf_has(_keydata: *const c_void, _selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        1
    }
}

/// `ossl_kdf_keymgmt_functions`.
static KDF_KEYMGMT: Dispatch<4> = Dispatch([
    entry!(OSSL_FUNC_KEYMGMT_NEW, kdf_newdata, NewFn),
    entry!(OSSL_FUNC_KEYMGMT_FREE, kdf_freedata, FreeFn),
    entry!(OSSL_FUNC_KEYMGMT_HAS, kdf_has, HasFn),
    END,
]);

/// The default provider's key managers, in `deflt_keymgmt`'s order.
static DEFAULT_KEYMGMT: Algorithms<41> = Algorithms([
    alg_desc(
        c"DH:dhKeyAgreement:1.2.840.113549.1.3.1",
        &super::dh_kmgmt::DH_KEYMGMT,
        c"OpenSSL PKCS#3 DH implementation",
    ),
    alg_desc(
        c"DHX:X9.42 DH:dhpublicnumber:1.2.840.10046.2.1",
        &super::dh_kmgmt::DHX_KEYMGMT,
        c"OpenSSL X9.42 DH implementation",
    ),
    alg_desc(
        c"DSA:dsaEncryption:1.2.840.10040.4.1",
        &super::dsa_kmgmt::DSA_KEYMGMT,
        c"OpenSSL DSA implementation",
    ),
    alg_desc(
        c"RSA:rsaEncryption:1.2.840.113549.1.1.1",
        &super::rsa_kmgmt::RSA_KEYMGMT,
        c"OpenSSL RSA implementation",
    ),
    alg_desc(
        c"RSA-PSS:RSASSA-PSS:1.2.840.113549.1.1.10",
        &super::rsa_kmgmt::RSAPSS_KEYMGMT,
        c"OpenSSL RSA-PSS implementation",
    ),
    alg_desc(
        c"EC:id-ecPublicKey:1.2.840.10045.2.1",
        &super::ec_kmgmt::EC_KEYMGMT,
        c"OpenSSL EC implementation",
    ),
    alg_desc(
        c"X25519:1.3.101.110",
        &super::ecx_kmgmt::X25519_KEYMGMT,
        c"OpenSSL X25519 implementation",
    ),
    alg_desc(
        c"X448:1.3.101.111",
        &super::ecx_kmgmt::X448_KEYMGMT,
        c"OpenSSL X448 implementation",
    ),
    alg_desc(
        c"ED25519:1.3.101.112",
        &super::ecx_kmgmt::ED25519_KEYMGMT,
        c"OpenSSL ED25519 implementation",
    ),
    alg_desc(
        c"ED448:1.3.101.113",
        &super::ecx_kmgmt::ED448_KEYMGMT,
        c"OpenSSL ED448 implementation",
    ),
    alg_desc(
        c"ML-DSA-44:MLDSA44:2.16.840.1.101.3.4.3.17:id-ml-dsa-44",
        &super::ml_dsa_kmgmt::ML_DSA_44_KEYMGMT,
        c"OpenSSL ML-DSA-44 implementation",
    ),
    alg_desc(
        c"ML-DSA-65:MLDSA65:2.16.840.1.101.3.4.3.18:id-ml-dsa-65",
        &super::ml_dsa_kmgmt::ML_DSA_65_KEYMGMT,
        c"OpenSSL ML-DSA-65 implementation",
    ),
    alg_desc(
        c"ML-DSA-87:MLDSA87:2.16.840.1.101.3.4.3.19:id-ml-dsa-87",
        &super::ml_dsa_kmgmt::ML_DSA_87_KEYMGMT,
        c"OpenSSL ML-DSA-87 implementation",
    ),
    alg_desc(
        c"TLS1-PRF",
        &KDF_KEYMGMT,
        c"OpenSSL TLS1_PRF via EVP_PKEY implementation",
    ),
    alg_desc(
        c"HKDF",
        &KDF_KEYMGMT,
        c"OpenSSL HKDF via EVP_PKEY implementation",
    ),
    alg_desc(
        c"SCRYPT:id-scrypt:1.3.6.1.4.1.11591.4.11",
        &KDF_KEYMGMT,
        c"OpenSSL SCRYPT via EVP_PKEY implementation",
    ),
    alg_desc(
        c"HMAC",
        &MAC_LEGACY_KEYMGMT,
        c"OpenSSL HMAC via EVP_PKEY implementation",
    ),
    alg_desc(
        c"SIPHASH",
        &MAC_LEGACY_KEYMGMT,
        c"OpenSSL SIPHASH via EVP_PKEY implementation",
    ),
    alg_desc(
        c"POLY1305",
        &MAC_LEGACY_KEYMGMT,
        c"OpenSSL POLY1305 via EVP_PKEY implementation",
    ),
    alg_desc(
        c"CMAC",
        &CMAC_LEGACY_KEYMGMT,
        c"OpenSSL CMAC via EVP_PKEY implementation",
    ),
    alg_desc(
        c"SM2:1.2.156.10197.1.301",
        &super::ec_kmgmt::SM2_KEYMGMT,
        c"OpenSSL SM2 implementation",
    ),
    alg_desc(
        c"ML-KEM-512:MLKEM512:id-alg-ml-kem-512:2.16.840.1.101.3.4.4.1",
        &super::ml_kem_kmgmt::ML_KEM_512_KEYMGMT,
        c"OpenSSL ML-KEM-512 implementation",
    ),
    alg_desc(
        c"ML-KEM-768:MLKEM768:id-alg-ml-kem-768:2.16.840.1.101.3.4.4.2",
        &super::ml_kem_kmgmt::ML_KEM_768_KEYMGMT,
        c"OpenSSL ML-KEM-768 implementation",
    ),
    alg_desc(
        c"ML-KEM-1024:MLKEM1024:id-alg-ml-kem-1024:2.16.840.1.101.3.4.4.3",
        &super::ml_kem_kmgmt::ML_KEM_1024_KEYMGMT,
        c"OpenSSL ML-KEM-1024 implementation",
    ),
    alg_desc(
        c"X25519MLKEM768",
        &super::mlx_kmgmt::X25519_KEYMGMT,
        c"X25519+ML-KEM-768 TLS hybrid implementation",
    ),
    alg_desc(
        c"X448MLKEM1024",
        &super::mlx_kmgmt::X448_KEYMGMT,
        c"X448+ML-KEM-1024 TLS hybrid implementation",
    ),
    alg_desc(
        c"SecP256r1MLKEM768",
        &super::mlx_kmgmt::P256_KEYMGMT,
        c"P-256+ML-KEM-768 TLS hybrid implementation",
    ),
    alg_desc(
        c"SecP384r1MLKEM1024",
        &super::mlx_kmgmt::P384_KEYMGMT,
        c"P-384+ML-KEM-1024 TLS hybrid implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHA2-128s:id-slh-dsa-sha2-128s:2.16.840.1.101.3.4.3.20",
        &super::slh_dsa_kmgmt::SHA2_128S_KEYMGMT,
        c"OpenSSL SLH-DSA-SHA2-128s implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHA2-128f:id-slh-dsa-sha2-128f:2.16.840.1.101.3.4.3.21",
        &super::slh_dsa_kmgmt::SHA2_128F_KEYMGMT,
        c"OpenSSL SLH-DSA-SHA2-128f implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHA2-192s:id-slh-dsa-sha2-192s:2.16.840.1.101.3.4.3.22",
        &super::slh_dsa_kmgmt::SHA2_192S_KEYMGMT,
        c"OpenSSL SLH-DSA-SHA2-192s implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHA2-192f:id-slh-dsa-sha2-192f:2.16.840.1.101.3.4.3.23",
        &super::slh_dsa_kmgmt::SHA2_192F_KEYMGMT,
        c"OpenSSL SLH-DSA-SHA2-192f implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHA2-256s:id-slh-dsa-sha2-256s:2.16.840.1.101.3.4.3.24",
        &super::slh_dsa_kmgmt::SHA2_256S_KEYMGMT,
        c"OpenSSL SLH-DSA-SHA2-256s implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHA2-256f:id-slh-dsa-sha2-256f:2.16.840.1.101.3.4.3.25",
        &super::slh_dsa_kmgmt::SHA2_256F_KEYMGMT,
        c"OpenSSL SLH-DSA-SHA2-256f implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHAKE-128s:id-slh-dsa-shake-128s:2.16.840.1.101.3.4.3.26",
        &super::slh_dsa_kmgmt::SHAKE_128S_KEYMGMT,
        c"OpenSSL SLH-DSA-SHAKE-128s implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHAKE-128f:id-slh-dsa-shake-128f:2.16.840.1.101.3.4.3.27",
        &super::slh_dsa_kmgmt::SHAKE_128F_KEYMGMT,
        c"OpenSSL SLH-DSA-SHAKE-128f implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHAKE-192s:id-slh-dsa-shake-192s:2.16.840.1.101.3.4.3.28",
        &super::slh_dsa_kmgmt::SHAKE_192S_KEYMGMT,
        c"OpenSSL SLH-DSA-SHAKE-192s implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHAKE-192f:id-slh-dsa-shake-192f:2.16.840.1.101.3.4.3.29",
        &super::slh_dsa_kmgmt::SHAKE_192F_KEYMGMT,
        c"OpenSSL SLH-DSA-SHAKE-192f implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHAKE-256s:id-slh-dsa-shake-256s:2.16.840.1.101.3.4.3.30",
        &super::slh_dsa_kmgmt::SHAKE_256S_KEYMGMT,
        c"OpenSSL SLH-DSA-SHAKE-256s implementation",
    ),
    alg_desc(
        c"SLH-DSA-SHAKE-256f:id-slh-dsa-shake-256f:2.16.840.1.101.3.4.3.31",
        &super::slh_dsa_kmgmt::SHAKE_256F_KEYMGMT,
        c"OpenSSL SLH-DSA-SHAKE-256f implementation",
    ),
    ALG_END,
]);

/// The default provider's key managers, for `OSSL_OP_KEYMGMT`.
pub(crate) fn default_keymgmt() -> *const OSSL_ALGORITHM {
    DEFAULT_KEYMGMT.0.as_ptr()
}
