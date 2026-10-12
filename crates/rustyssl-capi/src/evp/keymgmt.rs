//! Key managers (`EVP_KEYMGMT(3)`; `keymgmt_meth.c`): an `EVP_KEYMGMT` made from a provider's
//! key management algorithm (`keymgmt_from_algorithm`), fetched by name and properties, and the
//! internal wrappers (`evp_keymgmt_*`) that the key and context code calls the provider through,
//! with OpenSSL's defaults for the functions an algorithm leaves out.
//!
//! As in OpenSSL, an algorithm must offer `free`, `has`, and one of `new`, `gen`, and `load`;
//! the parameter functions come in pairs (getter and its list, setter and its list), import and
//! export each with a list of their types, and `gen` with `gen_init` and `gen_cleanup`. The
//! functions given a NULL method fail here where the reference would crash
//! (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    ERR_LIB_EVP, ERR_R_EVP_LIB, EVP_KEYMGMT, EVP_R_INVALID_PROVIDER_FUNCTIONS,
    EVP_R_PROVIDER_KEYMGMT_FAILURE, EVP_R_PROVIDER_KEYMGMT_NOT_SUPPORTED, NID_undef,
    OSSL_ALGORITHM, OSSL_CALLBACK, OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT,
    OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX, OSSL_FUNC_KEYMGMT_FREE,
    OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP, OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GEN_INIT,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE,
    OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GET_PARAMS,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX, OSSL_FUNC_KEYMGMT_LOAD,
    OSSL_FUNC_KEYMGMT_MATCH, OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
    OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_VALIDATE,
    OSSL_LIB_CTX, OSSL_OP_KEYMGMT, OSSL_PARAM, OSSL_PROVIDER,
};

use super::fetch::{self, Kind};
use crate::err::{self, ERR_clear_last_mark, ERR_count_to_mark, ERR_set_mark};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::provider::Ptr;

type AnyFn = unsafe extern "C" fn();
type NewFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type LoadFn = unsafe extern "C" fn(*const c_void, usize) -> *mut c_void;
type GenInitFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type GenSetTemplateFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type GenSetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type GenGetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type GenListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type GenFn = unsafe extern "C" fn(*mut c_void, OSSL_CALLBACK, *mut c_void) -> *mut c_void;
type GenCleanupFn = unsafe extern "C" fn(*mut c_void);
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type QueryNameFn = unsafe extern "C" fn(c_int) -> *const c_char;
type HasFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;
type DupFn = unsafe extern "C" fn(*const c_void, c_int) -> *mut c_void;
type ValidateFn = unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int;
type MatchFn = unsafe extern "C" fn(*const c_void, *const c_void, c_int) -> c_int;
type ImportFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> c_int;
type TypesFn = unsafe extern "C" fn(c_int) -> *const OSSL_PARAM;
type TypesExFn = unsafe extern "C" fn(*mut c_void, c_int) -> *const OSSL_PARAM;
type ExportFn = unsafe extern "C" fn(*mut c_void, c_int, OSSL_CALLBACK, *mut c_void) -> c_int;

/// A key management algorithm's functions, as its dispatch table gave them.
#[derive(Default, Clone, Copy)]
pub(crate) struct Funcs {
    new: Option<NewFn>,
    free: Option<FreeFn>,
    load: Option<LoadFn>,
    gen_init: Option<GenInitFn>,
    gen_set_template: Option<GenSetTemplateFn>,
    gen_set_params: Option<GenSetParamsFn>,
    gen_settable_params: Option<GenListFn>,
    gen_get_params: Option<GenGetParamsFn>,
    gen_gettable_params: Option<GenListFn>,
    generate: Option<GenFn>,
    gen_cleanup: Option<GenCleanupFn>,
    get_params: Option<GetParamsFn>,
    gettable_params: Option<ListFn>,
    set_params: Option<SetParamsFn>,
    settable_params: Option<ListFn>,
    query_operation_name: Option<QueryNameFn>,
    has: Option<HasFn>,
    dup: Option<DupFn>,
    validate: Option<ValidateFn>,
    match_: Option<MatchFn>,
    import: Option<ImportFn>,
    import_types: Option<TypesFn>,
    import_types_ex: Option<TypesExFn>,
    export: Option<ExportFn>,
    export_types: Option<TypesFn>,
    export_types_ex: Option<TypesExFn>,
}

/// A key manager (`EVP_KEYMGMT`).
pub(crate) struct Keymgmt {
    pub(crate) name_id: u32,
    type_name: CString,
    /// The provider's description, a static string of its, or NULL.
    description: Ptr<c_char>,
    /// The provider, with a reference.
    pub(crate) prov: Ptr<OSSL_PROVIDER>,
    /// `legacy_alg`: the key type the names stand for (`evp_pkey_name2type`), or `NID_undef`.
    pub(crate) legacy_alg: c_int,
    funcs: Funcs,
}

handle_type!(EVP_KEYMGMT => Keymgmt);

impl Drop for Keymgmt {
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

/// `keymgmt_from_algorithm`: a key manager from the provider's algorithm, with one reference,
/// or NULL with an error.
///
/// # Safety
/// `algo`'s names, description, and table are the provider's, valid while it lives; `prov` is
/// a live provider.
unsafe fn from_algorithm(
    name_id: u32,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
) -> *mut c_void {
    const F: &str = "keymgmt_from_algorithm";
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let first = names.split(|&c| c == b':').next().unwrap_or(names);
    let Ok(type_name) = CString::new(first) else {
        err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, F);
        return ptr::null_mut();
    };
    let mut f = Funcs::default();
    let (mut setparam, mut getparam, mut setgenparam, mut getgenparam) = (0, 0, 0, 0);
    let (mut import, mut export, mut import_types, mut export_types) = (0, 0, 0, 0);
    let mut at = algo.implementation;
    // SAFETY: the caller's guarantee: the table is ended by a zero id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        at = at.wrapping_add(1);
        let Some(func) = d.function else { continue };
        /// Stores `func` as the function its id stands for, the first of each id only;
        /// evaluates to whether it was stored.
        macro_rules! set {
            ($field:ident) => {{
                let fresh = f.$field.is_none();
                if fresh {
                    // SAFETY: the provider's guarantee of the function type for this id.
                    f.$field = Some(unsafe { cast(func) });
                }
                fresh
            }};
        }
        match d.function_id {
            OSSL_FUNC_KEYMGMT_NEW => _ = set!(new),
            OSSL_FUNC_KEYMGMT_GEN_INIT => _ = set!(gen_init),
            OSSL_FUNC_KEYMGMT_GEN_SET_TEMPLATE => _ = set!(gen_set_template),
            OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS => {
                if set!(gen_set_params) {
                    setgenparam += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS => {
                if set!(gen_settable_params) {
                    setgenparam += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_GEN_GET_PARAMS => {
                if set!(gen_get_params) {
                    getgenparam += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_GEN_GETTABLE_PARAMS => {
                if set!(gen_gettable_params) {
                    getgenparam += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_GEN => _ = set!(generate),
            OSSL_FUNC_KEYMGMT_GEN_CLEANUP => _ = set!(gen_cleanup),
            OSSL_FUNC_KEYMGMT_FREE => _ = set!(free),
            OSSL_FUNC_KEYMGMT_LOAD => _ = set!(load),
            OSSL_FUNC_KEYMGMT_GET_PARAMS => {
                if set!(get_params) {
                    getparam += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS => {
                if set!(gettable_params) {
                    getparam += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_SET_PARAMS => {
                if set!(set_params) {
                    setparam += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS => {
                if set!(settable_params) {
                    setparam += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME => _ = set!(query_operation_name),
            OSSL_FUNC_KEYMGMT_HAS => _ = set!(has),
            OSSL_FUNC_KEYMGMT_DUP => _ = set!(dup),
            OSSL_FUNC_KEYMGMT_VALIDATE => _ = set!(validate),
            OSSL_FUNC_KEYMGMT_MATCH => _ = set!(match_),
            OSSL_FUNC_KEYMGMT_IMPORT => {
                if set!(import) {
                    import += 1;
                }
            }
            // Either list of the types counts once toward import (and export).
            OSSL_FUNC_KEYMGMT_IMPORT_TYPES if f.import_types.is_none() => {
                if import_types == 0 {
                    import += 1;
                }
                import_types += 1;
                _ = set!(import_types);
            }
            OSSL_FUNC_KEYMGMT_IMPORT_TYPES_EX if f.import_types_ex.is_none() => {
                if import_types == 0 {
                    import += 1;
                }
                import_types += 1;
                _ = set!(import_types_ex);
            }
            OSSL_FUNC_KEYMGMT_EXPORT => {
                if set!(export) {
                    export += 1;
                }
            }
            OSSL_FUNC_KEYMGMT_EXPORT_TYPES if f.export_types.is_none() => {
                if export_types == 0 {
                    export += 1;
                }
                export_types += 1;
                _ = set!(export_types);
            }
            OSSL_FUNC_KEYMGMT_EXPORT_TYPES_EX if f.export_types_ex.is_none() => {
                if export_types == 0 {
                    export += 1;
                }
                export_types += 1;
                _ = set!(export_types_ex);
            }
            _ => {}
        }
    }
    let pair = |n: i32| n == 0 || n == 2;
    if f.free.is_none()
        || (f.new.is_none() && f.generate.is_none() && f.load.is_none())
        || f.has.is_none()
        || !pair(getparam)
        || !pair(setparam)
        || !pair(setgenparam)
        || !pair(getgenparam)
        || !pair(import)
        || !pair(export)
        || (f.generate.is_some() && (f.gen_init.is_none() || f.gen_cleanup.is_none()))
    {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_PROVIDER_FUNCTIONS, F);
        return ptr::null_mut();
    }
    // SAFETY: the caller's live provider; the method holds the reference.
    if !unsafe { OSSL_PROVIDER::up_ref(prov) } {
        return ptr::null_mut();
    }
    // `get_legacy_alg_type_from_keymgmt`: the first of the names that is a key type.
    let legacy_alg = fetch::names_of(prov, name_id)
        .iter()
        .map(|n| super::pkey::ameth::name2type(n))
        .find(|&t| t != NID_undef)
        .unwrap_or(NID_undef);
    EVP_KEYMGMT::new_handle(Keymgmt {
        name_id,
        type_name,
        description: Ptr(algo.algorithm_description.cast_mut()),
        prov: Ptr(prov),
        legacy_alg,
        funcs: f,
    })
    .cast()
}

/// Adds a reference to a key manager in a store.
unsafe fn up_ref(m: *mut c_void) {
    // SAFETY: a live method.
    unsafe { EVP_KEYMGMT::up_ref(m.cast()) };
}

/// Drops a reference to a key manager in a store.
unsafe fn free(m: *mut c_void) {
    // SAFETY: a reference the store held.
    unsafe { EVP_KEYMGMT::free(m.cast()) };
}

/// Key managers to fetching.
static KEYMGMTS: Kind = Kind {
    operation: OSSL_OP_KEYMGMT,
    from_algorithm,
    up_ref,
    free,
};

/// `EVP_KEYMGMT_fetch` for the key and context code: the key manager `name`, with a reference,
/// or NULL with the fetch's error.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn fetch_by_name(
    libctx: *mut OSSL_LIB_CTX,
    name: &CStr,
    properties: Option<&CStr>,
) -> Option<Ref> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { fetch::fetch(libctx, &KEYMGMTS, Some(name), properties) };
    // SAFETY: a new reference, given to the `Ref`.
    unsafe { Ref::adopt(m.cast()) }
}

/// `evp_keymgmt_fetch_from_prov`: the key manager `name` from `prov` only, with a reference,
/// or `None`.
///
/// # Safety
/// `prov` is a live provider.
pub(crate) unsafe fn fetch_from_prov(
    prov: *mut OSSL_PROVIDER,
    name: &CStr,
    properties: Option<&CStr>,
) -> Option<Ref> {
    // SAFETY: the caller's guarantee.
    let m = unsafe { fetch::fetch_from_prov(prov, &KEYMGMTS, Some(name), properties) };
    // SAFETY: a new reference, given to the `Ref`.
    unsafe { Ref::adopt(m.cast()) }
}

/// The key manager behind `keymgmt`, or `None` for NULL.
///
/// # Safety
/// `keymgmt` is NULL or a live key manager.
pub(crate) unsafe fn method<'a>(keymgmt: *const EVP_KEYMGMT) -> Option<&'a Keymgmt> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_KEYMGMT::get(keymgmt) }
}

/// A reference to a key manager, given up when dropped.
pub(crate) struct Ref(Ptr<EVP_KEYMGMT>);

impl Ref {
    /// Takes over a reference the caller holds; `None` for NULL.
    ///
    /// # Safety
    /// `m` is NULL or a live key manager whose reference the caller gives up.
    pub(crate) unsafe fn adopt(m: *mut EVP_KEYMGMT) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        unsafe { method(m) }.map(|_| Self(Ptr(m)))
    }

    /// A new reference to a live key manager.
    ///
    /// # Safety
    /// `m` is NULL or a live key manager.
    pub(crate) unsafe fn new(m: *mut EVP_KEYMGMT) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_KEYMGMT::up_ref(m) }.then_some(Self(Ptr(m)))
    }

    /// The key manager.
    pub(crate) fn get(&self) -> &Keymgmt {
        // SAFETY: this holds a reference to a live key manager (checked when made).
        match unsafe { method(self.0.0) } {
            Some(m) => m,
            None => crate::ffi::die("a held EVP_KEYMGMT is live"),
        }
    }

    /// Whether two references are to the same key manager.
    pub(crate) fn same(&self, other: &Self) -> bool {
        self.0.0 == other.0.0
    }
}

impl Clone for Ref {
    fn clone(&self) -> Self {
        // SAFETY: the method is live (this holds a reference).
        unsafe { EVP_KEYMGMT::up_ref(self.0.0) };
        Self(self.0)
    }
}

impl Drop for Ref {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, given up.
        unsafe { EVP_KEYMGMT::free(self.0.0) };
    }
}

// The internal API (`evp_keymgmt_*`), with OpenSSL's defaults for missing functions.
impl Keymgmt {
    /// The provider's context, which the provider functions take.
    pub(crate) fn provider_ctx(&self) -> *mut c_void {
        // SAFETY: the method holds a reference to its live provider.
        unsafe { crate::provider::OSSL_PROVIDER_get0_provider_ctx(self.prov.0) }
    }

    /// `EVP_KEYMGMT_get0_name`.
    pub(crate) fn name(&self) -> &CStr {
        &self.type_name
    }

    /// `EVP_KEYMGMT_is_a`.
    pub(crate) fn is_a(&self, name: &[u8]) -> bool {
        fetch::number_in(self.prov.0, name) == self.name_id
    }

    /// `match_type`: whether `other`'s first name is one of this one's.
    pub(crate) fn match_type(&self, other: &Self) -> bool {
        self.is_a(other.type_name.to_bytes())
    }

    /// The names, in the order they were added.
    pub(crate) fn names(&self) -> Vec<Vec<u8>> {
        fetch::names_of(self.prov.0, self.name_id)
    }

    /// The description, or NULL.
    pub(crate) fn description(&self) -> *const c_char {
        self.description.0.cast_const()
    }

    /// Whether it can generate keys (`gen_init`).
    pub(crate) fn has_gen_init(&self) -> bool {
        self.funcs.gen_init.is_some()
    }

    /// Whether it has `gen_set_params`.
    pub(crate) fn has_gen_set_params(&self) -> bool {
        self.funcs.gen_set_params.is_some()
    }

    /// Whether it has `gen_get_params`.
    pub(crate) fn has_gen_get_params(&self) -> bool {
        self.funcs.gen_get_params.is_some()
    }

    /// Whether it has `match`.
    pub(crate) fn has_match(&self) -> bool {
        self.funcs.match_.is_some()
    }

    /// Whether it has `export`.
    pub(crate) fn has_export(&self) -> bool {
        self.funcs.export.is_some()
    }

    /// Whether it has `dup`.
    pub(crate) fn has_dup(&self) -> bool {
        self.funcs.dup.is_some()
    }

    /// `evp_keymgmt_newdata`: new key data, or NULL.
    pub(crate) fn newdata(&self) -> *mut c_void {
        match self.funcs.new {
            // SAFETY: the provider's function with its context.
            Some(new) => unsafe { new(self.provider_ctx()) },
            None => ptr::null_mut(),
        }
    }

    /// `evp_keymgmt_freedata`.
    ///
    /// # Safety
    /// `keydata` is NULL or key data of this key manager, not used afterwards.
    pub(crate) unsafe fn freedata(&self, keydata: *mut c_void) {
        if let Some(free) = self.funcs.free {
            // SAFETY: the caller's guarantee.
            unsafe { free(keydata) };
        }
    }

    /// `evp_keymgmt_gen_init`: a generation context, or NULL.
    ///
    /// # Safety
    /// `params` is NULL or a parameter array.
    pub(crate) unsafe fn gen_init(
        &self,
        selection: c_int,
        params: *const OSSL_PARAM,
    ) -> *mut c_void {
        match self.funcs.gen_init {
            // SAFETY: the provider's function with its context and the caller's array.
            Some(f) => unsafe { f(self.provider_ctx(), selection, params) },
            None => ptr::null_mut(),
        }
    }

    /// `evp_keymgmt_gen_set_template`: 1 without the function, as OpenSSL's legacy methods.
    ///
    /// # Safety
    /// `genctx` is a generation context of this key manager; `templ` key data of it.
    pub(crate) unsafe fn gen_set_template(&self, genctx: *mut c_void, templ: *mut c_void) -> c_int {
        match self.funcs.gen_set_template {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(genctx, templ) },
            None => 1,
        }
    }

    /// `evp_keymgmt_gen_set_params`: 0 without the function.
    ///
    /// # Safety
    /// `genctx` is a generation context of this key manager; `params` NULL or an array.
    pub(crate) unsafe fn gen_set_params(
        &self,
        genctx: *mut c_void,
        params: *const OSSL_PARAM,
    ) -> c_int {
        match self.funcs.gen_set_params {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(genctx, params) },
            None => 0,
        }
    }

    /// `evp_keymgmt_gen_get_params`: 0 without the function.
    ///
    /// # Safety
    /// `genctx` is a generation context of this key manager; `params` NULL or an array.
    pub(crate) unsafe fn gen_get_params(
        &self,
        genctx: *mut c_void,
        params: *mut OSSL_PARAM,
    ) -> c_int {
        match self.funcs.gen_get_params {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(genctx, params) },
            None => 0,
        }
    }

    /// The generation parameters it can be given for `genctx` (NULL for the method's), or NULL.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context of this key manager.
    pub(crate) unsafe fn gen_settable_params(&self, genctx: *mut c_void) -> *const OSSL_PARAM {
        match self.funcs.gen_settable_params {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(genctx, self.provider_ctx()) },
            None => ptr::null(),
        }
    }

    /// The generation parameters it can report for `genctx` (NULL for the method's), or NULL.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context of this key manager.
    pub(crate) unsafe fn gen_gettable_params(&self, genctx: *mut c_void) -> *const OSSL_PARAM {
        match self.funcs.gen_gettable_params {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(genctx, self.provider_ctx()) },
            None => ptr::null(),
        }
    }

    /// `evp_keymgmt_gen`: new key data, or NULL; a failure that raised nothing raises
    /// `EVP_R_PROVIDER_KEYMGMT_FAILURE`.
    ///
    /// # Safety
    /// `genctx` is a generation context of this key manager; `cb` takes `cbarg`.
    pub(crate) unsafe fn generate(
        &self,
        genctx: *mut c_void,
        cb: OSSL_CALLBACK,
        cbarg: *mut c_void,
    ) -> *mut c_void {
        const F: &str = "evp_keymgmt_gen";
        let desc = if self.description.0.is_null() {
            String::new()
        } else {
            // SAFETY: the provider's static string.
            unsafe { CStr::from_ptr(self.description.0) }
                .to_string_lossy()
                .into_owned()
        };
        let text = format!("{} key generation:{desc}", self.type_name.to_string_lossy());
        let Some(generate) = self.funcs.generate else {
            err::raise_with_text(ERR_LIB_EVP, EVP_R_PROVIDER_KEYMGMT_NOT_SUPPORTED, F, &text);
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the caller's guarantee.
        let ret = unsafe { generate(genctx, cb, cbarg) };
        // SAFETY: the mark set above.
        if ret.is_null() && unsafe { ERR_count_to_mark() } == 0 {
            err::raise_with_text(ERR_LIB_EVP, EVP_R_PROVIDER_KEYMGMT_FAILURE, F, &text);
        }
        // SAFETY: as above.
        unsafe { ERR_clear_last_mark() };
        ret
    }

    /// `evp_keymgmt_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is a generation context of this key manager, not used afterwards.
    pub(crate) unsafe fn gen_cleanup(&self, genctx: *mut c_void) {
        if let Some(f) = self.funcs.gen_cleanup {
            // SAFETY: the caller's guarantee.
            unsafe { f(genctx) };
        }
    }

    /// `evp_keymgmt_get_params`: 1 without the function.
    ///
    /// # Safety
    /// `keydata` is key data of this key manager; `params` NULL or an array.
    pub(crate) unsafe fn get_params(&self, keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int {
        match self.funcs.get_params {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(keydata, params) },
            None => 1,
        }
    }

    /// `evp_keymgmt_set_params`: 1 without the function.
    ///
    /// # Safety
    /// `keydata` is key data of this key manager; `params` NULL or an array.
    pub(crate) unsafe fn set_params(
        &self,
        keydata: *mut c_void,
        params: *const OSSL_PARAM,
    ) -> c_int {
        match self.funcs.set_params {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(keydata, params) },
            None => 1,
        }
    }

    /// `EVP_KEYMGMT_gettable_params`.
    pub(crate) fn gettable_params(&self) -> *const OSSL_PARAM {
        match self.funcs.gettable_params {
            // SAFETY: the provider's function with its context.
            Some(f) => unsafe { f(self.provider_ctx()) },
            None => ptr::null(),
        }
    }

    /// `EVP_KEYMGMT_settable_params`.
    pub(crate) fn settable_params(&self) -> *const OSSL_PARAM {
        match self.funcs.settable_params {
            // SAFETY: the provider's function with its context.
            Some(f) => unsafe { f(self.provider_ctx()) },
            None => ptr::null(),
        }
    }

    /// `evp_keymgmt_util_query_operation_name`: the algorithm name for the operation, the key
    /// manager's own name if the provider gives none.
    pub(crate) fn query_operation_name(&self, op: c_int) -> CString {
        if let Some(f) = self.funcs.query_operation_name {
            // SAFETY: the provider's function.
            let name = unsafe { f(op) };
            if !name.is_null() {
                // SAFETY: the provider's string.
                return unsafe { CStr::from_ptr(name) }.to_owned();
            }
        }
        self.type_name.clone()
    }

    /// `evp_keymgmt_has` (the function is mandatory).
    ///
    /// # Safety
    /// `keydata` is NULL or key data of this key manager.
    pub(crate) unsafe fn has(&self, keydata: *mut c_void, selection: c_int) -> c_int {
        match self.funcs.has {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(keydata, selection) },
            None => 0,
        }
    }

    /// `evp_keymgmt_validate`: valid (1) without the function.
    ///
    /// # Safety
    /// `keydata` is key data of this key manager.
    pub(crate) unsafe fn validate(
        &self,
        keydata: *mut c_void,
        selection: c_int,
        checktype: c_int,
    ) -> c_int {
        match self.funcs.validate {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(keydata, selection, checktype) },
            None => 1,
        }
    }

    /// `evp_keymgmt_match`: no match (0) without the function.
    ///
    /// # Safety
    /// `a` and `b` are key data of this key manager.
    pub(crate) unsafe fn match_(&self, a: *mut c_void, b: *mut c_void, selection: c_int) -> c_int {
        match self.funcs.match_ {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(a, b, selection) },
            None => 0,
        }
    }

    /// `evp_keymgmt_import`: 0 without the function.
    ///
    /// # Safety
    /// `keydata` is key data of this key manager; `params` NULL or an array.
    pub(crate) unsafe fn import(
        &self,
        keydata: *mut c_void,
        selection: c_int,
        params: *const OSSL_PARAM,
    ) -> c_int {
        match self.funcs.import {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(keydata, selection, params) },
            None => 0,
        }
    }

    /// `evp_keymgmt_import_types`.
    pub(crate) fn import_types(&self, selection: c_int) -> *const OSSL_PARAM {
        if let Some(f) = self.funcs.import_types_ex {
            // SAFETY: the provider's function with its context.
            return unsafe { f(self.provider_ctx(), selection) };
        }
        match self.funcs.import_types {
            // SAFETY: the provider's function.
            Some(f) => unsafe { f(selection) },
            None => ptr::null(),
        }
    }

    /// `evp_keymgmt_export`: 0 without the function.
    ///
    /// # Safety
    /// `keydata` is key data of this key manager; `cb` takes `cbarg`.
    pub(crate) unsafe fn export(
        &self,
        keydata: *mut c_void,
        selection: c_int,
        cb: OSSL_CALLBACK,
        cbarg: *mut c_void,
    ) -> c_int {
        match self.funcs.export {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(keydata, selection, cb, cbarg) },
            None => 0,
        }
    }

    /// `evp_keymgmt_dup`: NULL without the function.
    ///
    /// # Safety
    /// `keydata` is key data of this key manager.
    pub(crate) unsafe fn dup(&self, keydata: *mut c_void, selection: c_int) -> *mut c_void {
        match self.funcs.dup {
            // SAFETY: the caller's guarantee.
            Some(f) => unsafe { f(keydata, selection) },
            None => ptr::null_mut(),
        }
    }
}

/// A C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

ffi_export! {
    /// The key manager `algorithm` from the providers of `ctx` (the default context for NULL)
    /// that best matches `properties`, with a reference; NULL with an error if none does.
    ///
    /// # Safety
    /// `ctx` is NULL or a live library context; `algorithm` and `properties` are NULL or
    /// strings.
    pub unsafe extern "C" fn EVP_KEYMGMT_fetch(ctx: *mut OSSL_LIB_CTX, algorithm: *const c_char, properties: *const c_char) -> *mut EVP_KEYMGMT
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let name = unsafe { text(algorithm) };
        // SAFETY: as above.
        let props = unsafe { text(properties) };
        // SAFETY: the caller's guarantee.
        unsafe { fetch::fetch(ctx, &KEYMGMTS, name, props) }.cast()
    }
}

ffi_export! {
    /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_KEYMGMT_up_ref(keymgmt: *mut EVP_KEYMGMT) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { EVP_KEYMGMT::up_ref(keymgmt) })
    }
}

ffi_export! {
    /// Drops a reference; NULL does nothing.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a key manager the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_KEYMGMT_free(keymgmt: *mut EVP_KEYMGMT)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_KEYMGMT::free(keymgmt) };
    }
}

ffi_export! {
    /// The provider the key manager came from (NULL for NULL).
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_KEYMGMT_get0_provider(keymgmt: *const EVP_KEYMGMT) -> *const OSSL_PROVIDER
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
    /// `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_KEYMGMT_get0_name(keymgmt: *const EVP_KEYMGMT) -> *const c_char
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
    /// `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_KEYMGMT_get0_description(keymgmt: *const EVP_KEYMGMT) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(keymgmt) }.map_or(ptr::null(), Keymgmt::description)
    }
}

ffi_export! {
    /// Whether `name` is one of the algorithm's names. 0 for NULL.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live key manager; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_KEYMGMT_is_a(keymgmt: *const EVP_KEYMGMT, name: *const c_char) -> c_int
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
    /// `keymgmt` is NULL or a live key manager; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_KEYMGMT_names_do_all(keymgmt: *const EVP_KEYMGMT, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(keymgmt) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { names_do_all(m, fn_, data) }
    }
}

/// `evp_names_do_all` for a key manager: 1 if it has names.
///
/// # Safety
/// `fn_` is a function of the documented type.
pub(crate) unsafe fn names_do_all(m: &Keymgmt, fn_: Option<NameFn>, data: *mut c_void) -> c_int {
    let names = m.names();
    for n in &names {
        let Ok(c) = CString::new(n.clone()) else {
            continue;
        };
        if let Some(f) = fn_ {
            // SAFETY: the caller's callback with a string and its data.
            unsafe { f(c.as_ptr(), data) };
        }
    }
    c_int::from(!names.is_empty())
}

/// `EVP_KEYMGMT_do_all_provided`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut EVP_KEYMGMT, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each key manager the active providers of `libctx` offer.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_KEYMGMT_do_all_provided(libctx: *mut OSSL_LIB_CTX, fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let all = unsafe { fetch::all(libctx, &KEYMGMTS) };
        for m in &all {
            if let Some(f) = fn_ {
                // SAFETY: the caller's callback with a method held for the call.
                unsafe { f(m.as_ptr().cast(), arg) };
            }
        }
    }
}

ffi_export! {
    /// The key parameters the algorithm can report, or NULL.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_KEYMGMT_gettable_params(keymgmt: *const EVP_KEYMGMT) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(keymgmt) }.map_or(ptr::null(), Keymgmt::gettable_params)
    }
}

ffi_export! {
    /// The key parameters the algorithm can be given, or NULL.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_KEYMGMT_settable_params(keymgmt: *const EVP_KEYMGMT) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { method(keymgmt) }.map_or(ptr::null(), Keymgmt::settable_params)
    }
}

ffi_export! {
    /// The generation parameters the algorithm can be given (asked without a context), or
    /// NULL.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_KEYMGMT_gen_settable_params(keymgmt: *const EVP_KEYMGMT) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(keymgmt) }) else { return ptr::null() };
        // SAFETY: no context.
        unsafe { m.gen_settable_params(ptr::null_mut()) }
    }
}

ffi_export! {
    /// The generation parameters the algorithm can report (asked without a context), or NULL.
    ///
    /// # Safety
    /// `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_KEYMGMT_gen_gettable_params(keymgmt: *const EVP_KEYMGMT) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(keymgmt) }) else { return ptr::null() };
        // SAFETY: no context.
        unsafe { m.gen_gettable_params(ptr::null_mut()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL key manager is refused (the reference crashes).
    #[test]
    fn null_methods_are_refused() {
        let km: *mut EVP_KEYMGMT = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        assert_eq!(unsafe { EVP_KEYMGMT_up_ref(km) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYMGMT_get0_name(km) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYMGMT_get0_description(km) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYMGMT_get0_provider(km) }.is_null());
        // SAFETY: as above.
        let got = unsafe { EVP_KEYMGMT_names_do_all(km, None, ptr::null_mut()) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYMGMT_gettable_params(km) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYMGMT_settable_params(km) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYMGMT_gen_settable_params(km) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_KEYMGMT_gen_gettable_params(km) }.is_null());
        // SAFETY: as above.
        unsafe { EVP_KEYMGMT_free(km) };
    }

    /// The default provider's MAC key managers come with their names and descriptions.
    #[test]
    fn fetches_the_mac_key_managers() {
        // A context of its own: fetching from it loads no configuration, which Miri can't run.
        // SAFETY: no preconditions.
        let lib = unsafe { crate::libctx::OSSL_LIB_CTX_new() };
        for name in [
            c"HMAC",
            c"SIPHASH",
            c"POLY1305",
            c"CMAC",
            c"HKDF",
            c"id-scrypt",
        ] {
            // SAFETY: the context; a static name.
            let km = unsafe { EVP_KEYMGMT_fetch(lib, name.as_ptr(), ptr::null()) };
            // SAFETY: the method fetched above, or NULL.
            let m = unsafe { method(km) };
            assert!(m.is_some_and(|m| !m.description().is_null()), "{name:?}");
            // SAFETY: the reference fetched above.
            unsafe { EVP_KEYMGMT_free(km) };
        }
        // SAFETY: made above.
        unsafe { crate::libctx::OSSL_LIB_CTX_free(lib) };
    }
}
