//! Symmetric key managers (`EVP_SKEYMGMT(3)`; `skeymgmt_meth.c`): an `EVP_SKEYMGMT` made from a
//! provider's symmetric key management algorithm (`skeymgmt_from_algorithm`), fetched by name
//! and properties, and the internal wrappers (`evp_skeymgmt_*`) that the key code calls the
//! provider through.
//!
//! As in OpenSSL, an algorithm must offer `free`, `import`, and `export`; `generate`,
//! `get_key_id`, and the two lists of settable parameters are optional.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, EVP_R_INVALID_PROVIDER_FUNCTIONS, EVP_SKEYMGMT, OSSL_ALGORITHM,
    OSSL_CALLBACK, OSSL_FUNC_SKEYMGMT_EXPORT, OSSL_FUNC_SKEYMGMT_FREE,
    OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS, OSSL_FUNC_SKEYMGMT_GENERATE,
    OSSL_FUNC_SKEYMGMT_GET_KEY_ID, OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS,
    OSSL_FUNC_SKEYMGMT_IMPORT, OSSL_LIB_CTX, OSSL_OP_SKEYMGMT, OSSL_PARAM, OSSL_PROVIDER,
};

use super::fetch::{self, Kind};
use crate::err;
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;

type AnyFn = unsafe extern "C" fn();
type FreeFn = unsafe extern "C" fn(*mut c_void);
pub(crate) type ImportFn =
    unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type ExportFn = unsafe extern "C" fn(*mut c_void, c_int, OSSL_CALLBACK, *mut c_void) -> c_int;
type GenerateFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> *mut c_void;
type KeyIdFn = unsafe extern "C" fn(*mut c_void) -> *const c_char;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;

/// A symmetric key management algorithm's functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
struct Funcs {
    free: Option<FreeFn>,
    import: Option<ImportFn>,
    export: Option<ExportFn>,
    generate: Option<GenerateFn>,
    get_key_id: Option<KeyIdFn>,
    imp_settable_params: Option<ListFn>,
    gen_settable_params: Option<ListFn>,
}

/// A symmetric key manager (`EVP_SKEYMGMT`).
pub(crate) struct Skeymgmt {
    pub(crate) name_id: u32,
    type_name: CString,
    /// The provider's description, a static string of its, or NULL.
    description: Ptr<c_char>,
    /// The provider, with a reference.
    pub(crate) prov: Ptr<OSSL_PROVIDER>,
    funcs: Funcs,
}

handle_type!(EVP_SKEYMGMT => Skeymgmt);

impl Drop for Skeymgmt {
    fn drop(&mut self) {
        // SAFETY: the provider reference the method holds.
        unsafe { OSSL_PROVIDER::free(self.prov.0) };
    }
}

/// A dispatch table's function as the type its id stands for.
///
/// # Safety
/// `F` is the function pointer type `f` really has.
unsafe fn cast<F: Copy>(f: AnyFn) -> F {
    // SAFETY: the caller's guarantee; function pointers all have one size.
    unsafe { core::mem::transmute_copy(&f) }
}

/// `skeymgmt_from_algorithm`: a symmetric key manager from the provider's algorithm, with one
/// reference, or NULL with an error.
///
/// # Safety
/// `algo`'s names, description, and table are the provider's, valid while it lives; `prov` is
/// a live provider.
unsafe fn from_algorithm(
    name_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void {
    const F: &str = "skeymgmt_from_algorithm";
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    };
    let mut f = Funcs::default();
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        let Some(func) = d.function else { continue };
        /// Stores `func` as the function its id stands for, the first of each id only.
        macro_rules! set {
            ($field:ident) => {
                if f.$field.is_none() {
                    // SAFETY: the provider's guarantee of the function type for this id.
                    f.$field = Some(unsafe { cast(func) });
                }
            };
        }
        match d.function_id {
            OSSL_FUNC_SKEYMGMT_FREE => set!(free),
            OSSL_FUNC_SKEYMGMT_IMPORT => set!(import),
            OSSL_FUNC_SKEYMGMT_EXPORT => set!(export),
            OSSL_FUNC_SKEYMGMT_GENERATE => set!(generate),
            OSSL_FUNC_SKEYMGMT_GET_KEY_ID => set!(get_key_id),
            OSSL_FUNC_SKEYMGMT_IMP_SETTABLE_PARAMS => set!(imp_settable_params),
            OSSL_FUNC_SKEYMGMT_GEN_SETTABLE_PARAMS => set!(gen_settable_params),
            _ => {}
        }
    }
    if f.free.is_none() || f.import.is_none() || f.export.is_none() {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS, F);
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        return ptr::null_mut();
    }
    EVP_SKEYMGMT::new_handle(Skeymgmt {
        name_id,
        type_name,
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        funcs: f,
    })
    .cast()
}

/// Adds a reference to a symmetric key manager in a store.
unsafe fn up_ref(m: *mut c_void) {
    // SAFETY: a live method.
    unsafe { EVP_SKEYMGMT::up_ref(m.cast()) };
}

/// Drops a reference to a symmetric key manager in a store.
unsafe fn free(m: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { EVP_SKEYMGMT::free(m.cast()) };
}

/// Symmetric key managers to fetching.
static SKEYMGMTS: Kind = Kind {
    operation: OSSL_OP_SKEYMGMT,
    style: crate::evp::fetch::Style::Evp,
    from_algorithm,
    up_ref,
    free,
};

/// `EVP_SKEYMGMT_fetch` for the key code: the symmetric key manager `name`, with a reference,
/// or `None` with the fetch's error.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn fetch_by_name(
    libctx: *mut OSSL_LIB_CTX,
    name: Option<&CStr>,
    properties: Option<&CStr>,
) -> Option<Ref> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { fetch::fetch(libctx, &SKEYMGMTS, name, properties) };
    // SAFETY: a new reference, given to the `Ref`.
    unsafe { Ref::adopt(m.cast()) }
}

/// `evp_skeymgmt_fetch_from_prov`: the symmetric key manager `name` from `prov` only, with a
/// reference, or `None`.
///
/// # Safety
/// `prov` is a live provider.
pub(crate) unsafe fn fetch_from_prov(
    prov: *mut OSSL_PROVIDER,
    name: &CStr,
    properties: Option<&CStr>,
) -> Option<Ref> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { fetch::fetch_from_prov(prov, &SKEYMGMTS, Some(name), properties) };
    // SAFETY: a new reference, given to the `Ref`.
    unsafe { Ref::adopt(m.cast()) }
}

/// The symmetric key manager behind `skeymgmt`, or `None` for NULL.
///
/// # Safety
/// `skeymgmt` is NULL or a live symmetric key manager.
pub(crate) unsafe fn method<'a>(skeymgmt: *const EVP_SKEYMGMT) -> Option<&'a Skeymgmt> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_SKEYMGMT::get(skeymgmt) }
}

/// A reference to a symmetric key manager, given up when dropped.
pub(crate) struct Ref(Ptr<EVP_SKEYMGMT>);

impl Ref {
    /// Takes over a reference the caller holds; `None` for NULL.
    ///
    /// # Safety
    /// `m` is NULL or a live symmetric key manager whose reference the caller gives up.
    pub(crate) unsafe fn adopt(m: *mut EVP_SKEYMGMT) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        unsafe { method(m) }.map(|_| Self(Ptr(m)))
    }

    /// A new reference to `m`; `None` for NULL.
    ///
    /// # Safety
    /// `m` is NULL or a live symmetric key manager.
    pub(crate) unsafe fn borrow(m: *mut EVP_SKEYMGMT) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        unsafe { method(m) }?;
        // SAFETY: as above.
        unsafe { EVP_SKEYMGMT::up_ref(m) };
        Some(Self(Ptr(m)))
    }

    /// The symmetric key manager.
    pub(crate) fn get(&self) -> &Skeymgmt {
        // SAFETY: this holds a reference to a live method (checked when made).
        match unsafe { method(self.0.0) } {
            Some(m) => m,
            None => crate::ffi::die("a held EVP_SKEYMGMT is live"),
        }
    }
}

impl Clone for Ref {
    fn clone(&self) -> Self {
        // SAFETY: the method is live (this holds a reference).
        unsafe { EVP_SKEYMGMT::up_ref(self.0.0) };
        Self(self.0)
    }
}

impl Drop for Ref {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, given up.
        unsafe { EVP_SKEYMGMT::free(self.0.0) };
    }
}

// The internal API (`evp_skeymgmt_*`).
impl Skeymgmt {
    /// Its `import` function (for a provider's `derive_skey`).
    pub(crate) fn import_fn(&self) -> Option<ImportFn> {
        self.funcs.import
    }

    /// The provider's context, which the provider functions take.
    pub(crate) fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }

    /// `EVP_SKEYMGMT_get0_name`.
    pub(crate) fn name(&self) -> &CStr {
        &self.type_name
    }

    /// `EVP_SKEYMGMT_is_a`.
    pub(crate) fn is_a(&self, name: &[u8]) -> bool {
        fetch::number_in(self.prov.0, name) == self.name_id
    }

    /// `evp_skeymgmt_generate`: new key data from `params`, or NULL (also without `generate`).
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe fn generate(&self, params: *const OSSL_PARAM) -> *mut c_void {
        let Some(f) = self.funcs.generate else {
            return ptr::null_mut();
        };
        // SAFETY: the provider's function with its context and the caller's parameters.
        unsafe { f(self.provider_ctx(), params) }
    }

    /// `evp_skeymgmt_import`: new key data from `params`, or NULL.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe fn import(&self, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void {
        let Some(f) = self.funcs.import else {
            return ptr::null_mut();
        };
        // SAFETY: the provider's function with its context and the caller's parameters.
        unsafe { f(self.provider_ctx(), selection, params) }
    }

    /// `evp_skeymgmt_export`: the key data's values, through `cb`.
    ///
    /// # Safety
    /// `keydata` is this method's key data; `cb` and `cbarg` are a callback and its argument.
    pub(crate) unsafe fn export(
        &self,
        keydata: *mut c_void,
        selection: c_int,
        cb: OSSL_CALLBACK,
        cbarg: *mut c_void,
    ) -> c_int {
        let Some(f) = self.funcs.export else { return 0 };
        // SAFETY: the provider's function with its key data and the caller's callback.
        unsafe { f(keydata, selection, cb, cbarg) }
    }

    /// `evp_skeymgmt_freedata`.
    ///
    /// # Safety
    /// `keydata` is NULL or this method's key data, not used afterwards.
    pub(crate) unsafe fn freedata(&self, keydata: *mut c_void) {
        if let Some(f) = self.funcs.free {
            // SAFETY: the provider's function with its key data.
            unsafe { f(keydata) };
        }
    }

    /// The key data's identifier, or NULL.
    ///
    /// # Safety
    /// `keydata` is this method's key data.
    pub(crate) unsafe fn key_id(&self, keydata: *mut c_void) -> *const c_char {
        let Some(f) = self.funcs.get_key_id else {
            return ptr::null();
        };
        // SAFETY: the provider's function with its key data.
        unsafe { f(keydata) }
    }
}

/// A C string argument, or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a NUL-terminated string that outlives `'a`.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

ffi_export! {
    /// The symmetric key manager `algorithm` from the providers of `ctx` (the default context
    /// for NULL) that best matches `properties`, with a reference; NULL with an error if none
    /// does.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
    /// strings.
    pub unsafe extern "C" fn EVP_SKEYMGMT_fetch(ctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut EVP_SKEYMGMT
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { text(algorithm) };
        // SAFETY: as above.
        let props = unsafe { text(properties) };
        // SAFETY: the caller's guarantee.
        unsafe { fetch::fetch(ctx, &SKEYMGMTS, name, props) }.cast()
    }
}

ffi_export! {
    /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live symmetric key manager.
    pub unsafe extern "C" fn EVP_SKEYMGMT_up_ref(keymgmt: *mut EVP_SKEYMGMT) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { EVP_SKEYMGMT::up_ref(keymgmt) })
    }
}

ffi_export! {
    /// Drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a symmetric key manager the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_SKEYMGMT_free(keymgmt: *mut EVP_SKEYMGMT)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_SKEYMGMT::free(keymgmt) };
    }
}

ffi_export! {
    /// The provider the symmetric key manager came from (NULL for NULL).
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live symmetric key manager.
    pub unsafe extern "C" fn EVP_SKEYMGMT_get0_provider(keymgmt: *const EVP_SKEYMGMT) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(keymgmt) }.map_or(ptr::null(), |m| m.prov.0.cast_const())
    }
}

ffi_export! {
    /// The algorithm's first name, as its provider gave it; NULL for NULL.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live symmetric key manager.
    pub unsafe extern "C" fn EVP_SKEYMGMT_get0_name(keymgmt: *const EVP_SKEYMGMT) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(keymgmt) }.map_or(ptr::null(), |m| m.type_name.as_ptr())
    }
}

ffi_export! {
    /// The provider's description of the algorithm, or NULL.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live symmetric key manager.
    pub unsafe extern "C" fn EVP_SKEYMGMT_get0_description(keymgmt: *const EVP_SKEYMGMT) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(keymgmt) }.map_or(ptr::null(), |m| m.description.0.cast_const())
    }
}

ffi_export! {
    /// Whether `name` is one of the algorithm's names. 0 for NULL.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live symmetric key manager; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_SKEYMGMT_is_a(keymgmt: *const EVP_SKEYMGMT, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(keymgmt) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        c_int::from(m.is_a(n))
    }
}

/// A names callback.
type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each of the algorithm's names. Returns 1 if it has any (0 for NULL).
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live symmetric key manager; `fn_` is a function of the
    /// documented type.
    pub unsafe extern "C" fn EVP_SKEYMGMT_names_do_all(keymgmt: *const EVP_SKEYMGMT, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(keymgmt) }) else { return 0 };
        let names = fetch::c_names_of(m.prov.0, m.name_id);
        for &n in &names {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a string the context keeps, and its data.
                unsafe { f(n, data) };
            }
        }
        // OpenSSL returns 1 whenever the method has a provider.
        1
    }
}

/// `EVP_SKEYMGMT_do_all_provided`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut EVP_SKEYMGMT, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each symmetric key manager the active providers of `libctx` offer.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_SKEYMGMT_do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let all = unsafe { fetch::all(libctx, &SKEYMGMTS) };
        for m in &all {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a method held for the call.
                unsafe { f(m.as_ptr().cast(), arg) };
            }
        }
    }
}

ffi_export! {
    /// The parameters generating a key takes, or NULL.
    ///
    /// # Safety
    /// `skeymgmt` is NULL or a live symmetric key manager.
    pub unsafe extern "C" fn EVP_SKEYMGMT_get0_gen_settable_params(skeymgmt: *const EVP_SKEYMGMT) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(skeymgmt) }) else { return ptr::null() };
        let Some(f) = m.funcs.gen_settable_params else { return ptr::null() };
        // SAFETY: the provider's function with its context.
        unsafe { f(m.provider_ctx()) }
    }
}

ffi_export! {
    /// The parameters importing a key takes, or NULL.
    ///
    /// # Safety
    /// `skeymgmt` is NULL or a live symmetric key manager.
    pub unsafe extern "C" fn EVP_SKEYMGMT_get0_imp_settable_params(skeymgmt: *const EVP_SKEYMGMT) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(skeymgmt) }) else { return ptr::null() };
        let Some(f) = m.funcs.imp_settable_params else { return ptr::null() };
        // SAFETY: the provider's function with its context.
        unsafe { f(m.provider_ctx()) }
    }
}
