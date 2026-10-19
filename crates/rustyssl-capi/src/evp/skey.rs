//! Opaque symmetric keys (`EVP_SKEY(3)`; `s_lib.c`): a key a provider's symmetric key manager
//! holds (its key data), made by importing values or generating, and read back through
//! `EVP_SKEY_export`.
//!
//! A key whose type no provider manages is given to the generic key manager
//! (`GENERIC-SECRET`), as in OpenSSL. `EVP_SKEY_to_provider` to the key's own provider gives
//! the key itself, with a reference; OpenSSL's there also drops a reference to the key's key
//! manager that it never took, which can free it under the key: here the counts stay right
//! (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_FETCH_FAILED, ERR_R_PASSED_NULL_PARAMETER, EVP_SKEY, OSSL_CALLBACK,
    OSSL_LIB_CTX, OSSL_PARAM, OSSL_PROVIDER, OSSL_SKEYMGMT_SELECT_ALL,
    OSSL_SKEYMGMT_SELECT_SECRET_KEY,
};

use super::skeymgmt::{self, Ref};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_octet_string_ptr,
    OSSL_PARAM_locate_const,
};
use crate::provider::Ptr;

/// The raw key's parameter (`OSSL_SKEY_PARAM_RAW_BYTES`).
const RAW_BYTES: &CStr = c"raw-bytes";
/// The generic key type (`OSSL_SKEY_TYPE_GENERIC`).
const GENERIC: &CStr = c"GENERIC-SECRET";

/// An opaque symmetric key (`EVP_SKEY`): its key manager and the key data it made.
pub(crate) struct Skey {
    pub(crate) skeymgmt: Ref,
    pub(crate) keydata: Ptr<c_void>,
}

handle_type!(EVP_SKEY => Skey);

impl Drop for Skey {
    fn drop(&mut self) {
        // SAFETY: the key data this key's manager made, freed once, with the key.
        unsafe { self.skeymgmt.get().freedata(self.keydata.0) };
    }
}

/// The key behind `skey`, or `None` for NULL.
///
/// # Safety
/// `skey` is NULL or a live key.
pub(crate) unsafe fn key<'a>(skey: *const EVP_SKEY) -> Option<&'a Skey> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_SKEY::get(skey) }
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a NUL-terminated string that outlives `'a`.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

/// `evp_skey_alloc_fetch`: the key manager `name`, or the generic one if no provider has it;
/// `None` with an error if neither is found.
///
/// # Safety
/// `libctx` is NULL or a live library context; `name` and `propquery` are NULL or strings.
unsafe fn alloc_fetch(
    libctx: *mut OSSL_LIB_CTX,
    name: *const c_char,
    propquery: *const c_char,
) -> Option<Ref> {
    // SAFETY: the caller's guarantee.
    let name = unsafe { text(name) };
    // SAFETY: as above.
    let props = unsafe { text(propquery) };
    // SAFETY: as above.
    if let Some(m) = unsafe { skeymgmt::fetch_by_name(libctx, name, props) } {
        return Some(m);
    }
    // SAFETY: as above.
    let generic = unsafe { skeymgmt::fetch_by_name(libctx, Some(GENERIC), props) };
    if generic.is_none() {
        err::raise(ERR_LIB_EVP, ERR_R_FETCH_FAILED, "evp_skey_alloc_fetch");
    }
    generic
}

/// A new key of `skeymgmt`'s with `keydata`, or NULL for no key data.
pub(crate) fn new_key(skeymgmt: Ref, keydata: *mut c_void) -> *mut EVP_SKEY {
    if keydata.is_null() {
        return ptr::null_mut();
    }
    EVP_SKEY::new_handle(Skey {
        skeymgmt,
        keydata: Ptr(keydata),
    })
}

ffi_export! {
    /// Passes the key's values that `selection` picks to `export_cb` (with `export_cbarg`), as
    /// its key manager gives them. Returns its result, or 0.
    ///
    /// # Safety
    /// `skey` is NULL or a live key; `export_cb` is a callback taking `export_cbarg`.
    pub unsafe extern "C" fn EVP_SKEY_export(skey: *const EVP_SKEY, selection: c_int, export_cb: OSSL_CALLBACK, export_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(skey) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_SKEY_export");
            return 0;
        };
        // SAFETY: the key's own data; the caller's callback.
        unsafe { k.skeymgmt.get().export(k.keydata.0, selection, export_cb, export_cbarg) }
    }
}

ffi_export! {
    /// A new key of the type `skeymgmtname` (or the generic type, if no provider has it) from
    /// the values in `params` that `selection` picks; NULL if the key manager refuses them.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; the strings are NULL or strings; `params`
    /// is NULL or a parameter array.
    pub unsafe extern "C" fn EVP_SKEY_import(libctx: *mut OSSL_LIB_CTX, skeymgmtname: *const c_char, propquery: *const c_char, selection: c_int, params: *const OSSL_PARAM) -> *mut EVP_SKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { alloc_fetch(libctx, skeymgmtname, propquery) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the caller's parameters.
        let keydata = unsafe { m.get().import(selection, params) };
        new_key(m, keydata)
    }
}

ffi_export! {
    /// A new key of `skeymgmt`'s (3.6) from the values in `params` that `selection` picks;
    /// NULL if it refuses them (or for no key manager).
    ///
    /// # Safety
    /// `skeymgmt` is NULL or a live symmetric key manager; `params` is NULL or a parameter
    /// array.
    pub unsafe extern "C" fn EVP_SKEY_import_SKEYMGMT(libctx: *mut OSSL_LIB_CTX, skeymgmt: *mut rustyssl_abi::EVP_SKEYMGMT, selection: c_int, params: *const OSSL_PARAM) -> *mut EVP_SKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        let _ = libctx;
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { Ref::borrow(skeymgmt) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the caller's parameters.
        let keydata = unsafe { m.get().import(selection, params) };
        new_key(m, keydata)
    }
}

/// `evp_skeymgmt_fetch_from_prov`, then `EVP_SKEYMGMT_fetch` anywhere: the key manager for
/// `key_type` that `EVP_PKEY_derive_SKEY` and `EVP_KDF_derive_SKEY` use (the caller's
/// `mgmt` if given), or `None` with `ERR_R_FETCH_FAILED`.
///
/// # Safety
/// `mgmt` is NULL or a live key manager; `prov` a live provider; the strings are strings or
/// NULL.
pub(crate) unsafe fn derive_skeymgmt(
    mgmt: *mut rustyssl_abi::EVP_SKEYMGMT,
    prov: *mut rustyssl_abi::OSSL_PROVIDER,
    libctx: *mut OSSL_LIB_CTX,
    key_type: &CStr,
    propquery: *const c_char,
) -> Option<Ref> {
    if !mgmt.is_null() {
        // SAFETY: the caller's guarantee.
        return unsafe { Ref::borrow(mgmt) };
    }
    // SAFETY: as above.
    let props = unsafe { text(propquery) };
    // SAFETY: as above.
    let m = unsafe { skeymgmt::fetch_from_prov(prov, key_type, props) }
        // SAFETY: as above.
        .or_else(|| unsafe { skeymgmt::fetch_by_name(libctx, Some(key_type), props) });
    if m.is_none() {
        err::raise(
            ERR_LIB_EVP,
            rustyssl_abi::ERR_R_FETCH_FAILED,
            "EVP_derive_SKEY",
        );
    }
    m
}

/// The fallback of the `derive_SKEY` functions: `keylen` octets that `derive` makes, imported
/// as `skeymgmt`'s raw secret (`OSSL_SKEY_PARAM_RAW_BYTES`), or NULL.
pub(crate) fn import_derived(
    skeymgmt: Ref,
    keylen: usize,
    derive: impl FnOnce(&mut [u8]) -> bool,
) -> *mut EVP_SKEY {
    let mut key = vec![0u8; keylen];
    if !derive(&mut key) {
        crate::provider::macs::wipe(&mut key);
        return ptr::null_mut();
    }
    // SAFETY: a static key; our octets, which outlive the call.
    let params = [
        unsafe {
            OSSL_PARAM_construct_octet_string(RAW_BYTES.as_ptr(), key.as_mut_ptr().cast(), keylen)
        },
        // SAFETY: no preconditions.
        unsafe { OSSL_PARAM_construct_end() },
    ];
    // SAFETY: the parameters above.
    let keydata = unsafe {
        skeymgmt.get().import(
            rustyssl_abi::OSSL_SKEYMGMT_SELECT_SECRET_KEY,
            params.as_ptr(),
        )
    };
    crate::provider::macs::wipe(&mut key);
    new_key(skeymgmt, keydata)
}

ffi_export! {
    /// A new key of the type `skeymgmtname` (or the generic type) that its key manager
    /// generates from `params`; NULL if it can't (the default provider's can't).
    ///
    /// # Safety
    /// As for `EVP_SKEY_import`.
    pub unsafe extern "C" fn EVP_SKEY_generate(libctx: *mut OSSL_LIB_CTX, skeymgmtname: *const c_char, propquery: *const c_char, params: *const OSSL_PARAM) -> *mut EVP_SKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { alloc_fetch(libctx, skeymgmtname, propquery) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the caller's parameters.
        let keydata = unsafe { m.get().generate(params) };
        new_key(m, keydata)
    }
}

/// Where `get_secret_key` puts the raw key.
struct RawKey {
    key: *mut *const u8,
    len: *mut usize,
}

/// `get_secret_key`: the raw key's address and length from an export, if it has them.
///
/// # Safety
/// `params` is the export's parameter array; `arg` is a `RawKey`.
unsafe extern "C" fn get_secret_key(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    // SAFETY: the export's parameters.
    let p = unsafe { OSSL_PARAM_locate_const(params, RAW_BYTES.as_ptr()) };
    if p.is_null() {
        return 0;
    }
    // SAFETY: `EVP_SKEY_get0_raw_key`'s `RawKey`.
    let Some(raw) = (unsafe { arg.cast::<RawKey>().as_ref() }) else {
        return 0;
    };
    // SAFETY: the parameter, and the caller's places for the address and length.
    unsafe { OSSL_PARAM_get_octet_string_ptr(p, raw.key.cast(), raw.len) }
}

ffi_export! {
    /// Sets `*key` to the key's raw octets, which its key manager keeps (valid while the key
    /// lives), and `*len` to their length. Returns 1, or 0 if the key manager won't give them.
    ///
    /// # Safety
    /// `skey` is NULL or a live key; `key` and `len` are NULL or valid for writes.
    pub unsafe extern "C" fn EVP_SKEY_get0_raw_key(skey: *const EVP_SKEY, key: *mut *const u8, len: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let k = unsafe { self::key(skey) };
        let Some(k) = k.filter(|_| !key.is_null() && !len.is_null()) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_SKEY_get0_raw_key");
            return 0;
        };
        let mut raw = RawKey { key, len };
        // SAFETY: the key's own data; a callback that takes a `RawKey`.
        unsafe {
            k.skeymgmt.get().export(k.keydata.0, OSSL_SKEYMGMT_SELECT_SECRET_KEY, Some(get_secret_key), (&raw mut raw).cast())
        }
    }
}

ffi_export! {
    /// A new key of the type `skeymgmtname` (or the generic type) holding the `keylen` octets
    /// at `key`; NULL if its key manager refuses them.
    ///
    /// # Safety
    /// As for `EVP_SKEY_import`; `key` holds `keylen` octets.
    pub unsafe extern "C" fn EVP_SKEY_import_raw_key(libctx: *mut OSSL_LIB_CTX, skeymgmtname: *const c_char, key: *mut u8, keylen: usize, propquery: *const c_char) -> *mut EVP_SKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: a parameter over the caller's octets.
        let raw = unsafe { OSSL_PARAM_construct_octet_string(RAW_BYTES.as_ptr(), key.cast(), keylen) };
        // SAFETY: no preconditions.
        let params = [raw, unsafe { OSSL_PARAM_construct_end() }];
        // SAFETY: the caller's guarantee; the parameters above.
        unsafe { EVP_SKEY_import(libctx, skeymgmtname, propquery, OSSL_SKEYMGMT_SELECT_SECRET_KEY, params.as_ptr()) }
    }
}

ffi_export! {
    /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_SKEY_up_ref(key: *mut EVP_SKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { EVP_SKEY::up_ref(key) })
    }
}

ffi_export! {
    /// Drops a reference; the key and its key data go with the last one. NULL does nothing.
    ///
    /// # Safety
    /// `key` is NULL or a key the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_SKEY_free(key: *mut EVP_SKEY)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_SKEY::free(key) };
    }
}

ffi_export! {
    /// The key's identifier from its key manager, or NULL (also for NULL).
    ///
    /// # Safety
    /// `skey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_SKEY_get0_key_id(skey: *const EVP_SKEY) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(skey) }) else { return ptr::null() };
        // SAFETY: the key's own data.
        unsafe { k.skeymgmt.get().key_id(k.keydata.0) }
    }
}

ffi_export! {
    /// The name of the key's key manager (its type), or NULL for NULL.
    ///
    /// # Safety
    /// `skey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_SKEY_get0_skeymgmt_name(skey: *const EVP_SKEY) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(skey) }.map_or(ptr::null(), |k| k.skeymgmt.get().name().as_ptr())
    }
}

ffi_export! {
    /// The name of the provider of the key's key manager, or NULL for NULL.
    ///
    /// # Safety
    /// `skey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_SKEY_get0_provider_name(skey: *const EVP_SKEY) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(skey) }) else { return ptr::null() };
        // SAFETY: the key manager's live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_name(k.skeymgmt.get().prov.0) }
    }
}

ffi_export! {
    /// Whether the key's type is `name`. 0 for NULL.
    ///
    /// # Safety
    /// `skey` is NULL or a live key; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_SKEY_is_a(skey: *const EVP_SKEY, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(skey) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        c_int::from(k.skeymgmt.get().is_a(n))
    }
}

/// `transfer_cb`'s state: the key manager to import into, and what it made.
struct Transfer<'a> {
    skeymgmt: &'a Ref,
    keydata: *mut c_void,
}

/// `transfer_cb`: imports the exported values into the other key manager.
///
/// # Safety
/// `params` is the export's parameter array; `arg` is a `Transfer`.
unsafe extern "C" fn transfer_cb(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    // SAFETY: `EVP_SKEY_to_provider`'s `Transfer`.
    let Some(t) = (unsafe { arg.cast::<Transfer<'_>>().as_mut() }) else {
        return 0;
    };
    // SAFETY: the export's parameters.
    t.keydata = unsafe { t.skeymgmt.get().import(OSSL_SKEYMGMT_SELECT_ALL, params) };
    1
}

ffi_export! {
    /// The key for use with `prov` (the providers of `libctx` that best match `propquery`, for
    /// NULL): the key itself, with a reference, if its key manager is that provider's; else a
    /// new key that provider's key manager imports from it. NULL if there is none or the key
    /// can't be exported.
    ///
    /// # Safety
    /// `skey` is NULL or a live key; `libctx` is NULL or a live library context; `prov` is NULL
    /// or a live provider; `propquery` is NULL or a string.
    pub unsafe extern "C" fn EVP_SKEY_to_provider(skey: *mut EVP_SKEY, libctx: *mut OSSL_LIB_CTX, prov: *mut OSSL_PROVIDER, propquery: *const c_char) -> *mut EVP_SKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        const F: &str = "EVP_SKEY_to_provider";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(skey) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        };
        let own = k.skeymgmt.get();
        // SAFETY: the caller's guarantee.
        let props = unsafe { text(propquery) };
        let target = if prov.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { skeymgmt::fetch_by_name(libctx, Some(own.name()), props) }
        } else if prov == own.prov.0 {
            Some(k.skeymgmt.clone())
        } else {
            // SAFETY: the caller's live provider.
            unsafe { skeymgmt::fetch_from_prov(prov, own.name(), props) }
        };
        let Some(target) = target else {
            err::raise(ERR_LIB_EVP, ERR_R_FETCH_FAILED, F);
            return ptr::null_mut();
        };
        if target.get().name_id == own.name_id && target.get().prov.0 == own.prov.0 {
            // SAFETY: the caller's live key.
            if !unsafe { EVP_SKEY::up_ref(skey) } {
                return ptr::null_mut();
            }
            return skey;
        }
        let mut t = Transfer { skeymgmt: &target, keydata: ptr::null_mut() };
        // SAFETY: the key's own data; a callback that takes a `Transfer`.
        let exported = unsafe { own.export(k.keydata.0, OSSL_SKEYMGMT_SELECT_ALL, Some(transfer_cb), (&raw mut t).cast()) };
        let keydata = t.keydata;
        if exported == 0 {
            if !keydata.is_null() {
                // SAFETY: the target's key data, not used afterwards (OpenSSL leaks it).
                unsafe { target.get().freedata(keydata) };
            }
            return ptr::null_mut();
        }
        new_key(target, keydata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
    use crate::evp::cipher_ctx::{
        EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CipherInit_SKEY, EVP_EncryptFinal_ex,
        EVP_EncryptUpdate,
    };

    /// A default-provider AES key of 16 octets.
    fn aes_key(octets: &mut [u8; 16]) -> *mut EVP_SKEY {
        // SAFETY: the default context; a static name; the caller's octets.
        let k = unsafe {
            EVP_SKEY_import_raw_key(
                ptr::null_mut(),
                c"AES".as_ptr(),
                octets.as_mut_ptr(),
                16,
                ptr::null(),
            )
        };
        assert!(!k.is_null());
        k
    }

    /// docs/DEVIATIONS.md: `EVP_SKEY_to_provider` to the key's own provider gives the key, with
    /// a reference, and leaves its key manager's count alone (OpenSSL's drops a reference it
    /// never took).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn to_own_provider_keeps_the_counts() {
        let mut octets = [7u8; 16];
        let k = aes_key(&mut octets);
        // SAFETY: a live key.
        let prov = unsafe { key(k) }.map(|x| x.skeymgmt.get().prov.0).unwrap();
        for _ in 0..8 {
            // SAFETY: a live key and its own live provider.
            let same = unsafe { EVP_SKEY_to_provider(k, ptr::null_mut(), prov, ptr::null()) };
            assert_eq!(same, k);
            // SAFETY: the reference the call gave.
            unsafe { EVP_SKEY_free(same) };
        }
        let (mut raw, mut len) = (ptr::null(), 0usize);
        // SAFETY: a live key; places for the address and length.
        let got = unsafe { EVP_SKEY_get0_raw_key(k, &raw mut raw, &raw mut len) };
        assert_eq!(got, 1);
        assert_eq!(len, 16);
        // SAFETY: the key's last reference.
        unsafe { EVP_SKEY_free(k) };
    }

    /// Encrypts 32 octets with AES-128-CBC set up by `init`.
    fn encrypt(
        init: impl FnOnce(*mut rustyssl_abi::EVP_CIPHER_CTX, *const rustyssl_abi::EVP_CIPHER) -> c_int,
    ) -> Vec<u8> {
        // SAFETY: the default context and a static name.
        let cbc =
            unsafe { EVP_CIPHER_fetch(ptr::null_mut(), c"AES-128-CBC".as_ptr(), ptr::null()) };
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        assert_eq!(init(ctx, cbc), 1);
        let input = [9u8; 32];
        let mut out = [0u8; 64];
        let (mut n, mut f) = (0, 0);
        // SAFETY: a set-up context; buffers of the right sizes.
        let updated =
            unsafe { EVP_EncryptUpdate(ctx, out.as_mut_ptr(), &raw mut n, input.as_ptr(), 32) };
        assert_eq!(updated, 1);
        let tail = out.as_mut_ptr().wrapping_add(32);
        // SAFETY: as above.
        let finished = unsafe { EVP_EncryptFinal_ex(ctx, tail, &raw mut f) };
        assert_eq!(finished, 1);
        // SAFETY: the context and the cipher made above.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_free(cbc) };
        out[..usize::try_from(n + f).unwrap()].to_vec()
    }

    /// docs/DEVIATIONS.md: `EVP_CipherInit_SKEY` with no key keeps the key and sets the IV, for
    /// AES-CBC too (OpenSSL's AES-CBC takes key objects and reads through the NULL one).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn a_null_key_sets_the_iv_alone() {
        let mut octets = [7u8; 16];
        let k = aes_key(&mut octets);
        let (iv1, iv2) = ([1u8; 16], [2u8; 16]);
        let two_steps = encrypt(|ctx, cbc| {
            // SAFETY: a new context, the fetched cipher, a live key, and an IV of 16.
            let first =
                unsafe { EVP_CipherInit_SKEY(ctx, cbc, k, iv1.as_ptr(), 16, 1, ptr::null()) };
            // SAFETY: as above, with no key.
            let second = unsafe {
                EVP_CipherInit_SKEY(
                    ctx,
                    ptr::null(),
                    ptr::null_mut(),
                    iv2.as_ptr(),
                    16,
                    -1,
                    ptr::null(),
                )
            };
            first & second
        });
        // SAFETY: as above.
        let one_step = encrypt(|ctx, cbc| unsafe {
            EVP_CipherInit_SKEY(ctx, cbc, k, iv2.as_ptr(), 16, 1, ptr::null())
        });
        assert_eq!(two_steps, one_step);
        // SAFETY: the key's last reference.
        unsafe { EVP_SKEY_free(k) };
    }
}
