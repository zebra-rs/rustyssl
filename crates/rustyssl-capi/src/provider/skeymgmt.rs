//! The default provider's symmetric key managers (`deflt_skeymgmt` in `providers/defltprov.c`):
//! the algorithm table `query_operation` offers for `OSSL_OP_SKEYMGMT`, and the dispatch tables
//! of the generic key manager (`skeymgmt/generic.c`), which holds any non-empty octets, and
//! AES's (`skeymgmt/aes_skmgmt.c`), which holds 16, 24, or 32. Neither generates keys.
//!
//! The key data (OpenSSL's `PROV_SKEY`) is the key's type and a copy of its octets, cleared
//! when freed. Exporting it passes the octets themselves (`raw-bytes`), which stay where they
//! are while the key lives: `EVP_SKEY_get0_raw_key` hands out their address.

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    OSSL_ALGORITHM, OSSL_CALLBACK, OSSL_FUNC_SKEYMGMT_EXPORT, OSSL_FUNC_SKEYMGMT_FREE,
    OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS, OSSL_FUNC_SKEYMGMT_IMPORT, OSSL_PARAM,
    OSSL_PARAM_OCTET_STRING, OSSL_SKEY_PARAM_RAW_BYTES, OSSL_SKEYMGMT_SELECT_SECRET_KEY,
};

use super::tables::{
    ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, alg_desc, defn, entry, legacy_alg,
};
use crate::ffi::ffi_callback;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_locate_const,
};

type FreeFn = unsafe extern "C" fn(*mut c_void);
type ImportFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type ExportFn = unsafe extern "C" fn(*mut c_void, c_int, OSSL_CALLBACK, *mut c_void) -> c_int;
type SettableFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;

/// `generic_skey_import_list`: the raw octets.
static IMP_SETTABLE: Params<2> = Params([
    defn(OSSL_SKEY_PARAM_RAW_BYTES, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `generic_imp_settable_params` (from 3.6): what an import takes.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn generic_imp_settable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = rustyssl_abi::ERR_LIB_PROV
    {
        IMP_SETTABLE.0.as_ptr()
    }
}

/// The key's type (`SKEY_TYPE_*`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Type {
    Generic,
    Aes,
}

/// The key data (`PROV_SKEY`).
struct ProvSkey {
    kind: Type,
    data: Vec<u8>,
}

impl Drop for ProvSkey {
    fn drop(&mut self) {
        // As OpenSSL frees it (`OPENSSL_free`), but cleared first.
        let mut d = core::mem::take(&mut self.data);
        // SAFETY: the vector's own octets.
        unsafe { crate::mem::OPENSSL_cleanse(d.as_mut_ptr().cast(), d.len()) };
        d.clear();
    }
}

/// The raw secret of the built-in key managers' key data (`PROV_SKEY`), for the KDFs' and
/// exchanges' `set_skey` (3.6); `None` for NULL.
///
/// # Safety
/// `keydata` is NULL or key data of these key managers.
pub(crate) unsafe fn raw_secret<'a>(keydata: *mut c_void) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    unsafe { keydata.cast::<ProvSkey>().as_ref() }.map(|k| k.data.as_slice())
}

/// Imports `secret` with `import` (`OSSL_SKEY_PARAM_RAW_BYTES`): the provider-side end of
/// the `derive_skey` functions (3.6). NULL without `import`.
///
/// # Safety
/// `import` is NULL or a key manager's import with its provider context `provctx`.
pub(crate) unsafe fn import_secret(
    provctx: *mut c_void,
    import: Option<crate::evp::skeymgmt::ImportFn>,
    secret: &mut [u8],
) -> *mut c_void {
    let Some(import) = import else {
        return core::ptr::null_mut();
    };
    let params = [
        // SAFETY: a static key; the caller's octets, which outlive the call.
        unsafe {
            crate::params::OSSL_PARAM_construct_octet_string(
                RAW_BYTES.as_ptr(),
                secret.as_mut_ptr().cast(),
                secret.len(),
            )
        },
        crate::params::end(),
    ];
    // SAFETY: the caller's import with its provider context; the array above.
    unsafe {
        import(
            provctx,
            rustyssl_abi::OSSL_SKEYMGMT_SELECT_SECRET_KEY,
            params.as_ptr(),
        )
    }
}

/// The raw key's parameter (`OSSL_SKEY_PARAM_RAW_BYTES`).
const RAW_BYTES: &core::ffi::CStr = c"raw-bytes";

/// `generic_import`: key data holding the `raw-bytes` octets, if `selection` takes the secret
/// and they are there and not empty.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn import(selection: c_int, params: *const OSSL_PARAM) -> Option<Box<ProvSkey>> {
    if selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY == 0 {
        return None;
    }
    // SAFETY: the caller's guarantee.
    if !unsafe {
        crate::provider::param_decoders::decode(
            params,
            &crate::provider::param_decoders::GENERIC_SKEY_IMPORT,
        )
    } {
        return None;
    }
    // SAFETY: the caller's guarantee.
    let p = unsafe { OSSL_PARAM_locate_const(params, RAW_BYTES.as_ptr()) };
    // SAFETY: a parameter of the array.
    let p = unsafe { p.as_ref() }?;
    // `OPENSSL_memdup` copies nothing from NULL, nothing empty, and nothing as long as an `int`.
    if p.data.is_null() || p.data_size == 0 || p.data_size >= c_int::MAX.unsigned_abs() as usize {
        return None;
    }
    // SAFETY: the parameter's data holds `data_size` octets.
    let octets = unsafe { core::slice::from_raw_parts(p.data.cast::<u8>(), p.data_size) };
    let mut data = Vec::new();
    data.try_reserve_exact(octets.len()).ok()?;
    data.extend_from_slice(octets);
    Some(Box::new(ProvSkey {
        kind: Type::Generic,
        data,
    }))
}

ffi_callback! {
    /// `generic_free`: frees key data; NULL does nothing.
    ///
    /// # Safety
    /// `keydata` is NULL or this provider's key data, not used afterwards.
    pub(crate) unsafe extern "C" fn generic_free(keydata: *mut c_void)
    where failure = (), library = rustyssl_abi::ERR_LIB_PROV
    {
        if !keydata.is_null() {
            // SAFETY: key data this provider boxed.
            drop(unsafe { Box::from_raw(keydata.cast::<ProvSkey>()) });
        }
    }
}

ffi_callback! {
    /// `generic_import`: key data holding the `raw-bytes` octets (any non-empty length), or
    /// NULL.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn generic_import(_provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { import(selection, params) }.map_or(ptr::null_mut(), |k| Box::into_raw(k).cast())
    }
}

/// `generic_export`: passes the octets to `cb` as `raw-bytes`, if `selection` takes the secret.
///
/// # Safety
/// `key` is this provider's key data; `cb` is a callback taking `cbarg`.
unsafe fn export(key: &ProvSkey, selection: c_int, cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int {
    if selection & OSSL_SKEYMGMT_SELECT_SECRET_KEY == 0 {
        return 0;
    }
    let Some(cb) = cb else { return 0 };
    // SAFETY: a parameter over the key's own octets, which live as long as it does.
    let raw = unsafe {
        OSSL_PARAM_construct_octet_string(
            RAW_BYTES.as_ptr(),
            key.data.as_ptr().cast_mut().cast(),
            key.data.len(),
        )
    };
    // SAFETY: no preconditions.
    let params = [raw, unsafe { OSSL_PARAM_construct_end() }];
    // SAFETY: the caller's callback with the parameters above.
    unsafe { cb(params.as_ptr(), cbarg) }
}

ffi_callback! {
    /// `generic_export`: the octets, as `raw-bytes`, for a selection with the secret.
    ///
    /// # Safety
    /// `keydata` is NULL or this provider's key data; `cb` is a callback taking `cbarg`.
    pub(crate) unsafe extern "C" fn generic_export(keydata: *mut c_void, selection: c_int, cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(key) = (unsafe { keydata.cast::<ProvSkey>().as_ref() }) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { export(key, selection, cb, cbarg) }
    }
}

ffi_callback! {
    /// `aes_import`: key data holding 16, 24, or 32 `raw-bytes` octets, or NULL.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn aes_import(_provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(mut key) = (unsafe { import(selection, params) }) else { return ptr::null_mut() };
        if !matches!(key.data.len(), 16 | 24 | 32) {
            return ptr::null_mut();
        }
        key.kind = Type::Aes;
        Box::into_raw(key).cast()
    }
}

ffi_callback! {
    /// `aes_export`: as `generic_export`, for AES key data only.
    ///
    /// # Safety
    /// `keydata` is NULL or this provider's key data; `cb` is a callback taking `cbarg`.
    pub(crate) unsafe extern "C" fn aes_export(keydata: *mut c_void, selection: c_int, cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = rustyssl_abi::ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(key) = (unsafe { keydata.cast::<ProvSkey>().as_ref() }) else { return 0 };
        if key.kind != Type::Aes {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { export(key, selection, cb, cbarg) }
    }
}

static GENERIC_FUNCTIONS: Dispatch<5> = Dispatch([
    entry!(OSSL_FUNC_SKEYMGMT_FREE, generic_free, FreeFn),
    entry!(OSSL_FUNC_SKEYMGMT_IMPORT, generic_import, ImportFn),
    entry!(OSSL_FUNC_SKEYMGMT_EXPORT, generic_export, ExportFn),
    entry!(
        OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,
        generic_imp_settable_params,
        SettableFn
    ),
    END,
]);

static AES_FUNCTIONS: Dispatch<5> = Dispatch([
    entry!(OSSL_FUNC_SKEYMGMT_FREE, generic_free, FreeFn),
    entry!(OSSL_FUNC_SKEYMGMT_IMPORT, aes_import, ImportFn),
    entry!(OSSL_FUNC_SKEYMGMT_EXPORT, aes_export, ExportFn),
    entry!(
        OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,
        generic_imp_settable_params,
        SettableFn
    ),
    END,
]);

/// `legacy_skeymgmt` (from 3.6): the generic key manager, under `provider=legacy`.
pub(crate) static LEGACY_SKEYMGMT: Algorithms<2> =
    Algorithms([legacy_alg(c"GENERIC-SECRET", &GENERIC_FUNCTIONS), ALG_END]);

/// `deflt_skeymgmt`.
static DEFAULT_SKEYMGMT: Algorithms<3> = Algorithms([
    alg_desc(
        c"AES:2.16.840.1.101.3.4.1",
        &AES_FUNCTIONS,
        c"OpenSSL AES opaque secret key",
    ),
    alg_desc(
        c"GENERIC-SECRET",
        &GENERIC_FUNCTIONS,
        c"OpenSSL generic opaque secret key",
    ),
    ALG_END,
]);

/// The default provider's symmetric key managers.
pub(crate) fn default_skeymgmt() -> *const OSSL_ALGORITHM {
    DEFAULT_SKEYMGMT.0.as_ptr()
}
