//! Providers (`provider(7)`, `OSSL_PROVIDER(3)`): each library context's store of providers,
//! loading (`OSSL_PROVIDER_load`, `_try_load`, and their `_ex` forms), unloading, the fallback
//! that activates the default provider when nothing was loaded, `OSSL_PROVIDER_available`,
//! `OSSL_PROVIDER_do_all`, and a provider's name, parameters, self-test, context, and dispatch
//! table.
//!
//! A port of `crypto/provider_core.c`'s behavior:
//! - A provider has references (`OSSL_PROVIDER *`s, one held by its store) and activations.
//!   Loading makes it if its store has none of that name, initializes it once (its init
//!   function gets the core's dispatch table and returns its own), and activates it.
//!   Unloading deactivates it and drops a reference. A deactivated provider stays in the store
//!   and is reactivated, not initialized again, by a later load; it's torn down when its last
//!   reference goes, normally with its library context.
//! - Every provider made takes a number from `ERR_get_next_error_library`, as OpenSSL's do.
//! - Loading disables the fallback; otherwise the first `OSSL_PROVIDER_available` or
//!   `OSSL_PROVIDER_do_all` (and, later, fetch) activates the default provider.
//! - The store keeps OpenSSL's order: providers are sorted by name when one is looked up, and
//!   one added after that goes last, so `OSSL_PROVIDER_do_all` sees them in OpenSSL's order.
//! - The built-in providers (`default`, `base`, `null`) are in [`builtin`], behind the same
//!   init function and dispatch tables external providers use. Any other name is a module,
//!   looked up as OpenSSL's DSO loader does ([`module`]); running external providers comes
//!   later, so one that's found isn't initialized.
//!
//! No lock is held while a provider's functions (init, teardown, parameters, self-test) or a
//! `do_all` callback run.

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_CRYPTO, ERR_R_INIT_FAIL, ERR_R_PASSED_NULL_PARAMETER, OPENSSL_INIT_LOAD_CONFIG,
    OSSL_ALGORITHM, OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
    OSSL_FUNC_PROVIDER_GET_PARAMS, OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
    OSSL_FUNC_PROVIDER_QUERY_OPERATION, OSSL_FUNC_PROVIDER_RANDOM_BYTES,
    OSSL_FUNC_PROVIDER_SELF_TEST, OSSL_FUNC_PROVIDER_TEARDOWN,
    OSSL_FUNC_PROVIDER_UNQUERY_OPERATION, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PROVIDER,
    OSSL_provider_init_fn,
};
use rustyssl_crypto::params::UTF8_STRING;

use crate::err::strings::ERR_get_next_error_library;
use crate::ffi::ffi_export;
use crate::handle::{Handle, Held, handle_type};
use crate::{err, init, libctx};

pub(crate) mod aeads;
mod blob2key;
pub(crate) mod builtin;
pub(crate) mod capabilities;
pub(crate) mod child;
pub(crate) mod ciphers;
pub(crate) mod conf;
mod decoders;
mod der2key;
mod dh_exch;
pub(crate) mod dh_kmgmt;
mod dhkem;
pub(crate) mod digests;
pub(crate) mod dsa_kmgmt;
pub(crate) mod dsa_sig;
pub(crate) mod ec_kmgmt;
mod ecdh_exch;
mod ecdsa_sig;
mod ecx_exch;
mod ecx_kmgmt;
mod eddsa_sig;
mod encoders;
pub(crate) mod exchanges;
mod file_store;
pub(crate) mod kdfs;
mod kdfs_more;
mod key2ms;
mod key2text;
pub(crate) mod keymgmt;
pub(crate) mod macs;
mod ml_codecs;
pub(crate) mod ml_dsa_kmgmt;
pub(crate) mod ml_dsa_sig;
mod ml_kem_kem;
pub(crate) mod ml_kem_kmgmt;
mod mlx_kem;
pub(crate) mod mlx_kmgmt;
pub(crate) mod modes;
mod module;
pub(crate) mod param_decoders;
pub(crate) mod rands;
mod rc4_hmac_md5;
pub(crate) mod rsa_enc;
pub(crate) mod rsa_kem;
pub(crate) mod rsa_kmgmt;
pub(crate) mod rsa_sig;
pub(crate) mod signatures;
pub(crate) mod skeymgmt;
pub(crate) mod slh_dsa_kmgmt;
pub(crate) mod slh_dsa_sig;
mod sm2_enc;
mod sm2_sig;
pub(crate) mod tables;
pub(crate) mod upcalls;

/// A raw pointer kept in a provider or store, never dereferenced without its owner's guarantee.
#[derive(PartialEq, Eq)]
pub(crate) struct Ptr<T>(pub(crate) *mut T);

impl<T> Clone for Ptr<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Ptr<T> {}

impl<T> Default for Ptr<T> {
    /// NULL.
    fn default() -> Self {
        Ptr(core::ptr::null_mut())
    }
}

// SAFETY: the pointers are the application's or the provider's, used as OpenSSL uses them: passed
// back to the provider's functions (which OpenSSL may call from any thread) or compared.
unsafe impl<T> Send for Ptr<T> {}
// SAFETY: as above.
unsafe impl<T> Sync for Ptr<T> {}

/// A library context a key keeps, which a provider's decoder can set afterwards
/// (`ossl_*_set0_libctx`).
#[derive(Default)]
pub(crate) struct KeyLibctx(core::sync::atomic::AtomicPtr<rustyssl_abi::OSSL_LIB_CTX>);

impl KeyLibctx {
    pub(crate) fn new(libctx: *mut rustyssl_abi::OSSL_LIB_CTX) -> Self {
        Self(core::sync::atomic::AtomicPtr::new(libctx))
    }

    /// The library context (NULL for the default one).
    pub(crate) fn get(&self) -> *mut rustyssl_abi::OSSL_LIB_CTX {
        self.0.load(core::sync::atomic::Ordering::Acquire)
    }

    pub(crate) fn set(&self, libctx: *mut rustyssl_abi::OSSL_LIB_CTX) {
        self.0.store(libctx, core::sync::atomic::Ordering::Release);
    }
}

type TeardownFn = unsafe extern "C" fn(*mut c_void);
type GettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SelfTestFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type QueryFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const OSSL_ALGORITHM;
type UnqueryFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_ALGORITHM);
type RandomBytesFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize, c_uint) -> c_int;
type GetCapabilitiesFn = unsafe extern "C" fn(
    *mut c_void,
    *const core::ffi::c_char,
    rustyssl_abi::OSSL_CALLBACK,
    *mut c_void,
) -> c_int;

/// The provider functions the core calls, from its dispatch table.
#[derive(Default, Clone, Copy)]
struct Functions {
    teardown: Option<TeardownFn>,
    gettable_params: Option<GettableParamsFn>,
    get_params: Option<GetParamsFn>,
    self_test: Option<SelfTestFn>,
    query_operation: Option<QueryFn>,
    unquery_operation: Option<UnqueryFn>,
    random_bytes: Option<RandomBytesFn>,
    get_capabilities: Option<GetCapabilitiesFn>,
}

/// What changes as a provider is initialized and activated.
#[derive(Default)]
struct State {
    /// `provider_init` succeeded.
    initialized: bool,
    /// In its store (`prov->store`).
    in_store: bool,
    /// Activations; negative after more deactivations than activations, as in OpenSSL.
    activations: i32,
    /// `flag_activated`.
    activated: bool,
    provctx: Option<Ptr<c_void>>,
    dispatch: Option<Ptr<OSSL_DISPATCH>>,
    functions: Functions,
    /// The operations whose algorithms are in the context's method store
    /// (`operation_bits`), bit `n` for operation `n`.
    operations: u64,
}

/// A provider (`OSSL_PROVIDER`).
pub(crate) struct Provider {
    name: CString,
    /// The library context it was loaded into, as given (NULL for the default).
    libctx: Ptr<OSSL_LIB_CTX>,
    /// The init function: a built-in's, or none for a module.
    init: OSSL_provider_init_fn,
    /// The module's path, from configuration (set once, before the provider is shared).
    path: std::sync::OnceLock<CString>,
    /// The configuration parameters (`OSSL_PROVIDER_load_ex`'s UTF-8 strings and
    /// `OSSL_PROVIDER_add_conf_parameter`'s), in order. Never removed, so pointers to the values
    /// stay valid while the provider lives.
    parameters: Mutex<Vec<(CString, CString)>>,
    /// The error library number taken for it: its own reasons' library.
    error_lib: c_int,
    state: Mutex<State>,
    /// Its module, once opened (`prov->module`): closed after the teardown, with the provider.
    module: Mutex<Option<module::Module>>,
    /// The reason strings it gave (`get_reason_strings`), loaded under `error_lib` until it goes.
    reasons: Mutex<Option<Reasons>>,
    /// A child provider's parent in the parent context (`ossl_provider_set_child`).
    parent: std::sync::OnceLock<Ptr<OSSL_CORE_HANDLE>>,
}

handle_type!(OSSL_PROVIDER => Provider, teardown = Provider::teardown);

/// A provider's reason strings as `ERR_load_strings` takes them: the library's name, then the
/// reasons, then the end. The strings are the provider's (static in its module) and its name.
struct Reasons(Vec<rustyssl_abi::ERR_STRING_DATA>);

// SAFETY: the table is only handed to the error-string functions, under the provider's lock; its
// strings are never written.
unsafe impl Send for Reasons {}

/// The most entries a provider's table (dispatch, reason strings) is read for: past it, the
/// table is taken as unterminated.
pub(crate) const TABLE_LIMIT: usize = 1 << 16;

impl Provider {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The provider's context and functions, copied out of the lock.
    fn functions(&self) -> (*mut c_void, Functions) {
        let s = self.state();
        (s.provctx.map_or(ptr::null_mut(), |p| p.0), s.functions)
    }

    /// The module's path, for the core's `module-filename` parameter.
    pub(crate) fn module_path(&self) -> Option<&CStr> {
        self.path.get().map(CString::as_c_str)
    }

    /// The name.
    pub(crate) fn name(&self) -> &CStr {
        &self.name
    }

    /// The library context it was loaded into, as given.
    pub(crate) fn libctx(&self) -> *mut OSSL_LIB_CTX {
        self.libctx.0
    }

    /// The error library its own reasons are raised in.
    pub(crate) fn error_lib(&self) -> c_int {
        self.error_lib
    }

    /// `ossl_provider_module_path`: the file its module was opened from (`DSO_get_filename`,
    /// which raises `ERR_R_PASSED_NULL_PARAMETER` for a provider without one, NULL). The string
    /// stays valid while the provider lives: a module, once open, is never replaced.
    pub(crate) fn module_filename(&self) -> *const c_char {
        let module = self.module.lock().unwrap_or_else(PoisonError::into_inner);
        let name = module.as_ref().map(|m| m.filename.as_ptr());
        if name.is_none() {
            err::raise(
                rustyssl_abi::ERR_LIB_DSO,
                ERR_R_PASSED_NULL_PARAMETER,
                "DSO_get_filename",
            );
        }
        name.unwrap_or(ptr::null())
    }

    /// Whether it's a child provider (`ossl_provider_is_child`).
    pub(crate) fn is_child(&self) -> bool {
        self.parent.get().is_some()
    }

    /// A child provider's parent (`ossl_provider_get_parent`).
    pub(crate) fn parent(&self) -> *const OSSL_CORE_HANDLE {
        self.parent.get().map_or(ptr::null(), |p| p.0.cast_const())
    }

    /// `ossl_provider_set_child`: marks it as the child of `parent`.
    pub(crate) fn set_child(&self, parent: *const OSSL_CORE_HANDLE) {
        let _ = self.parent.set(Ptr(parent.cast_mut()));
    }
}

impl Provider {
    /// `ossl_provider_free` at the last reference ([`Handle::teardown`]): an initialized
    /// provider is torn down, its reason strings unloaded, its thread-stop handlers dropped;
    /// its module is closed when it drops (the field drops last). The teardown makes upcalls
    /// with the provider's handle, which still reaches it.
    fn teardown(&self) {
        let is_child = self.parent.get().is_some();
        let (initialized, teardown, provctx) = {
            let state = self.state();
            let provctx = state.provctx.map_or(ptr::null_mut(), |p| p.0);
            (state.initialized, state.functions.teardown, provctx)
        };
        if initialized {
            // `ossl_provider_teardown`: a child provider's context is its parent's, torn down
            // with the parent.
            if let Some(teardown) = teardown.filter(|_| !is_child) {
                // SAFETY: the provider's own teardown, given its own context, once, with no
                // lock held.
                unsafe { teardown(provctx) };
            }
            let reasons = self
                .reasons
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take();
            if let Some(Reasons(mut table)) = reasons {
                // SAFETY: the table loaded at init, ended by a zero entry.
                unsafe {
                    crate::err::strings::ERR_unload_strings(self.error_lib, table.as_mut_ptr())
                };
            }
        }
        crate::threads::deregister_stop_handlers(core::ptr::from_ref(self).addr());
    }
}

/// A reference to a provider, held by its store.
struct Stored(Ptr<OSSL_PROVIDER>);

impl Stored {
    fn get(&self) -> Option<&Provider> {
        // SAFETY: the store holds a reference, so the provider is live.
        unsafe { OSSL_PROVIDER::get(self.0.0) }
    }
}

/// A library context's providers.
pub(crate) struct StoreState {
    /// The providers, each with a reference, in OpenSSL's order (see the module docs).
    providers: Vec<Stored>,
    /// Sorted by name since the last addition.
    sorted: bool,
    /// The default provider is still to be activated if nothing is loaded.
    use_fallbacks: bool,
    /// `OSSL_PROVIDER_set_default_search_path`'s directory.
    default_path: Option<CString>,
    /// Earlier search paths, kept so a pointer `OSSL_PROVIDER_get0_default_search_path`
    /// returned stays valid (OpenSSL frees it).
    old_paths: Vec<CString>,
    /// The providers' information (`OSSL_PROVIDER_INFO`): the application's built-ins
    /// (`OSSL_PROVIDER_add_builtin`) and the configuration's providers it didn't activate, in
    /// order.
    infos: Vec<Info>,
    /// The providers the configuration activated, each with a reference (OpenSSL's
    /// `PROVIDER_CONF_GLOBAL`).
    conf_activated: Vec<Stored>,
    /// The child contexts' callbacks (`child_cbs`), in registration order.
    child_cbs: Vec<ChildCb>,
}

/// What `ossl_provider_new` takes for a name that isn't predefined (`OSSL_PROVIDER_INFO`).
pub(crate) struct Info {
    name: CString,
    init: OSSL_provider_init_fn,
    path: Option<CString>,
    parameters: Option<Vec<(CString, CString)>>,
}

impl Default for StoreState {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            sorted: true,
            use_fallbacks: true,
            default_path: None,
            old_paths: Vec::new(),
            infos: Vec::new(),
            conf_activated: Vec::new(),
            child_cbs: Vec::new(),
        }
    }
}

impl StoreState {
    /// `sk_OSSL_PROVIDER_find` on the store: sorts it by name, then the first of that name.
    fn find(&mut self, name: &CStr) -> Option<*mut OSSL_PROVIDER> {
        if !self.sorted {
            self.providers.sort_by(|a, b| {
                a.get()
                    .map(Provider::name)
                    .cmp(&b.get().map(Provider::name))
            });
            self.sorted = true;
        }
        self.providers
            .iter()
            .find(|p| p.get().is_some_and(|p| p.name() == name))
            .map(|p| p.0.0)
    }

    /// `sk_OSSL_PROVIDER_push`: the store takes the caller's reference.
    fn push(&mut self, prov: *mut OSSL_PROVIDER) {
        self.providers.push(Stored(Ptr(prov)));
        self.sorted = self.providers.len() < 2;
    }
}

impl StoreState {
    /// `provider_deactivate_free` for each provider, as the context goes.
    fn release(conf_activated: Vec<Stored>, providers: Vec<Stored>) {
        // `ossl_prov_conf_ctx_free`: the configuration's references.
        for p in conf_activated {
            // SAFETY: the configuration's reference, given up.
            unsafe { OSSL_PROVIDER::free(p.0.0) };
        }
        for p in providers {
            // The context is going, its method store with it: only the count changes.
            if let Some(prov) = p.get().filter(|p| p.state().activated) {
                count_deactivation(prov);
            }
            // SAFETY: the store's reference, given up.
            unsafe { OSSL_PROVIDER::free(p.0.0) };
        }
    }
}

impl Drop for StoreState {
    fn drop(&mut self) {
        Self::release(
            core::mem::take(&mut self.conf_activated),
            core::mem::take(&mut self.providers),
        );
    }
}

/// A library context's provider store, behind its lock.
#[derive(Default)]
pub(crate) struct Store(Mutex<StoreState>);

impl Store {
    /// Gives up the store's providers as its context goes ([`Handle::teardown`]): their
    /// teardowns run with the context still there and the store unlocked.
    pub(crate) fn release(&self) {
        let (conf_activated, providers) = {
            let mut s = self.lock();
            s.sorted = true;
            (
                core::mem::take(&mut s.conf_activated),
                core::mem::take(&mut s.providers),
            )
        };
        StoreState::release(conf_activated, providers);
    }

    fn lock(&self) -> MutexGuard<'_, StoreState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The context `libctx` stands for.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn context(libctx: *mut OSSL_LIB_CTX) -> Option<Held<OSSL_LIB_CTX>> {
    // SAFETY: the caller's guarantee.
    unsafe { libctx::resolve(libctx) }
}

/// Runs `f` with the context's provider store.
fn with_store<R>(ctx: Option<Held<OSSL_LIB_CTX>>, f: impl FnOnce(&Store) -> R) -> Option<R> {
    ctx.map(|c| f(&c.providers))
}

/// Loads the configuration when `libctx` is the thread's default context, as provider lookups
/// do.
fn load_config_for(libctx: *mut OSSL_LIB_CTX) {
    if libctx.is_null() || libctx == libctx::current() {
        let opts = u64::try_from(OPENSSL_INIT_LOAD_CONFIG).unwrap_or(0);
        // SAFETY: no settings.
        unsafe { init::OPENSSL_init_crypto(opts, ptr::null()) };
    }
}

/// `ossl_provider_find`: the provider `name` in the store, with a reference for the caller.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn find(libctx: *mut OSSL_LIB_CTX, name: &CStr) -> Option<*mut OSSL_PROVIDER> {
    load_config_for(libctx);
    // SAFETY: the caller's guarantee.
    let found = with_store(unsafe { context(libctx) }, |s| s.lock().find(name))??;
    // SAFETY: in the store, so live; the reference is the caller's.
    unsafe { OSSL_PROVIDER::up_ref(found) }.then_some(found)
}

/// `ossl_provider_find(libctx, name, 0)`, with a reference for the caller, or NULL.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn find_held(libctx: *mut OSSL_LIB_CTX, name: &CStr) -> *mut OSSL_PROVIDER {
    // SAFETY: the caller's guarantee.
    unsafe { find(libctx, name) }.unwrap_or(ptr::null_mut())
}

/// The built-in providers OpenSSL predefines, and whether each is a fallback.
fn predefined(name: &CStr) -> Option<(OSSL_provider_init_fn, bool)> {
    builtin::PREDEFINED
        .iter()
        .find(|(n, _, _)| *n == name)
        .map(|&(_, init, fallback)| (init, fallback))
}

/// `provider_new`: a provider with one reference, not yet initialized.
fn provider_new(
    libctx: *mut OSSL_LIB_CTX,
    name: &CStr,
    init: OSSL_provider_init_fn,
    parameters: Vec<(CString, CString)>,
) -> *mut OSSL_PROVIDER {
    // SAFETY: no preconditions.
    let error_lib = unsafe { ERR_get_next_error_library() };
    OSSL_PROVIDER::new_handle(Provider {
        name: name.to_owned(),
        libctx: Ptr(libctx),
        init,
        path: std::sync::OnceLock::new(),
        parameters: Mutex::new(parameters),
        error_lib,
        state: Mutex::new(State::default()),
        module: Mutex::new(None),
        reasons: Mutex::new(None),
        parent: std::sync::OnceLock::new(),
    })
}

/// `ossl_provider_new`: a provider `name`, from the predefined built-ins or else a module, with
/// the UTF-8 string parameters of `params`.
///
/// # Safety
/// `params` is NULL or an array ended by a NULL key whose UTF-8 strings are strings.
unsafe fn new(
    libctx: *mut OSSL_LIB_CTX,
    name: &CStr,
    params: *const OSSL_PARAM,
) -> *mut OSSL_PROVIDER {
    // A predefined built-in, else the first information under the name (an application's
    // built-in, or the configuration's), whose parameters come too unless `params` are given.
    let predefined = predefined(name).map(|(init, _)| init);
    // SAFETY: the caller's guarantee.
    let info = with_store(unsafe { context(libctx) }, |s| {
        s.lock()
            .infos
            .iter()
            .find(|i| i.name.as_c_str() == name)
            .map(|i| (i.init, i.path.clone(), i.parameters.clone()))
    })
    .flatten();
    let (init, path, mut parameters) = match (predefined, info) {
        (Some(init), Some((_, _, params))) => (init, None, params),
        (Some(init), None) => (init, None, None),
        (None, Some((init, path, params))) => (init, path, params),
        (None, None) => (None, None, None),
    };
    if !params.is_null() {
        parameters = None;
    }
    let mut parameters = parameters.unwrap_or_default();
    let mut at = params;
    // SAFETY: the caller's guarantee: the array goes on to its end.
    while let Some(p) = unsafe { at.as_ref() } {
        if p.key.is_null() {
            break;
        }
        if p.data_type == UTF8_STRING && !p.data.is_null() {
            // SAFETY: the caller's guarantee for the key.
            let key = unsafe { CStr::from_ptr(p.key) };
            // SAFETY: the caller's guarantee for the string.
            let value = unsafe { CStr::from_ptr(p.data.cast()) };
            parameters.push((key.to_owned(), value.to_owned()));
        }
        at = at.wrapping_add(1);
    }
    let handle = provider_new(libctx, name, init, parameters);
    if let Some(path) = path {
        // SAFETY: just made.
        unsafe { set_module_path(handle, path) };
    }
    handle
}

/// `ossl_provider_set_module_path`.
///
/// # Safety
/// `handle` is a live provider.
unsafe fn set_module_path(handle: *mut OSSL_PROVIDER, path: CString) {
    // SAFETY: the caller's guarantee.
    if let Some(p) = unsafe { OSSL_PROVIDER::get(handle) } {
        let _ = p.path.set(path);
    }
}

/// `provider_init`: runs the init function (a module's, for one without, if it can be found),
/// keeping the provider's context and dispatch table.
fn provider_init(handle: *mut OSSL_PROVIDER, prov: &Provider) -> bool {
    let name = prov.name.to_string_lossy();
    let init = match prov.init {
        Some(init) => Some(init),
        None => {
            // A module: opened once (it stays open while the provider lives, even if its init
            // fails, as OpenSSL keeps `prov->module`).
            let mut module = prov.module.lock().unwrap_or_else(PoisonError::into_inner);
            if module.is_none() {
                // SAFETY: the store of a live provider's context.
                let path = with_store(unsafe { context(prov.libctx.0) }, |s| {
                    s.lock().default_path.clone()
                })
                .flatten();
                *module = module::open(prov, path.as_deref());
            }
            let Some(m) = module.as_ref() else {
                return false;
            };
            m.init
        }
    };
    let Some(init) = init else {
        err::raise_with_text(
            ERR_LIB_CRYPTO,
            rustyssl_abi::ERR_R_UNSUPPORTED,
            "provider_init",
            &format!("name={name}, provider has no provider init function"),
        );
        return false;
    };
    let mut out: *const OSSL_DISPATCH = ptr::null();
    let mut provctx: *mut c_void = ptr::null_mut();
    // SAFETY: the provider's own init function, with the core's table and this provider as its
    // handle.
    let ok = unsafe {
        init(
            handle.cast::<OSSL_CORE_HANDLE>(),
            upcalls::DISPATCH.as_ptr(),
            &raw mut out,
            &raw mut provctx,
        )
    };
    if ok == 0 {
        err::raise_with_text(
            ERR_LIB_CRYPTO,
            ERR_R_INIT_FAIL,
            "provider_init",
            &format!("name={name}"),
        );
        return false;
    }
    let mut functions = Functions::default();
    let mut reason_strings: Option<ReasonStringsFn> = None;
    let mut at = out;
    // SAFETY: the provider's table, ended by a zero function id (read up to a limit).
    for _ in 0..TABLE_LIMIT {
        // SAFETY: as above.
        let Some(d) = (unsafe { at.as_ref() }) else {
            break;
        };
        if d.function_id == 0 {
            break;
        }
        if d.function_id == rustyssl_abi::OSSL_FUNC_PROVIDER_GET_REASON_STRINGS
            && let Some(f) = d.function
        {
            // SAFETY: the provider's guarantee of the function's type.
            reason_strings = Some(unsafe { cast(f) });
        }
        // SAFETY: each function has the type its id says (the provider's guarantee).
        unsafe { functions.set(d) };
        at = at.wrapping_add(1);
    }
    {
        let mut s = prov.state();
        s.provctx = Some(Ptr(provctx));
        s.dispatch = Some(Ptr(out.cast_mut()));
    }
    if let Some(get) = reason_strings {
        // SAFETY: the provider's function with its context.
        let items = unsafe { get(provctx) };
        // SAFETY: the provider's table of reasons, ended by a zero id.
        let Some(table) = (unsafe { reason_table(prov, items) }) else {
            // A reason with a library: OpenSSL gives up on the provider, with no error.
            return false;
        };
        let mut reasons = prov.reasons.lock().unwrap_or_else(PoisonError::into_inner);
        let table = reasons.insert(Reasons(table));
        // SAFETY: a table ended by a zero entry, whose strings stay valid while the provider
        // (its name) and its module (the reasons) are there; unloaded when it goes.
        unsafe { crate::err::strings::ERR_load_strings(prov.error_lib, table.0.as_mut_ptr()) };
    }
    let mut s = prov.state();
    s.initialized = true;
    s.functions = functions;
    true
}

/// `OSSL_FUNC_provider_get_reason_strings`.
type ReasonStringsFn = unsafe extern "C" fn(*mut c_void) -> *const rustyssl_abi::OSSL_ITEM;

/// The provider's reasons as `ERR_load_strings` takes them: the library's name (the provider's)
/// first, then each reason, then the end. `None` if a reason carries a library number, which
/// `provider_init` refuses.
///
/// # Safety
/// `items` is NULL or a table of reasons ended by a zero id (read up to a limit), whose strings
/// stay valid while the provider is loaded.
unsafe fn reason_table(
    prov: &Provider,
    items: *const rustyssl_abi::OSSL_ITEM,
) -> Option<Vec<rustyssl_abi::ERR_STRING_DATA>> {
    use rustyssl_abi::ERR_STRING_DATA;
    let mut table = vec![ERR_STRING_DATA {
        error: crate::err::pack(prov.error_lib, 0),
        string: prov.name.as_ptr(),
    }];
    let mut at = items;
    for _ in 0..TABLE_LIMIT {
        // SAFETY: the caller's guarantee.
        let Some(item) = (unsafe { at.as_ref() }) else {
            break;
        };
        if item.id == 0 {
            break;
        }
        let id = core::ffi::c_ulong::from(item.id);
        if crate::err::library_of(id) != 0 {
            return None;
        }
        table.push(ERR_STRING_DATA {
            error: id,
            string: item.ptr.cast_const().cast(),
        });
        at = at.wrapping_add(1);
    }
    table.push(ERR_STRING_DATA {
        error: 0,
        string: ptr::null(),
    });
    Some(table)
}

/// A dispatch table's function as the type its id stands for.
///
/// # Safety
/// `F` is a function pointer type, the one `f` really has.
unsafe fn cast<F: Copy>(f: unsafe extern "C" fn()) -> F {
    // SAFETY: the caller's guarantee; function pointers all have one size.
    unsafe { core::mem::transmute_copy(&f) }
}

impl Functions {
    /// Keeps the function `d` names, if the core uses it.
    ///
    /// # Safety
    /// `d.function` has the type `d.function_id` stands for.
    unsafe fn set(&mut self, d: &OSSL_DISPATCH) {
        let Some(f) = d.function else { return };
        match d.function_id {
            // SAFETY: the caller's guarantee of the type.
            OSSL_FUNC_PROVIDER_TEARDOWN => self.teardown = Some(unsafe { cast(f) }),
            // SAFETY: as above.
            OSSL_FUNC_PROVIDER_GETTABLE_PARAMS => self.gettable_params = Some(unsafe { cast(f) }),
            // SAFETY: as above.
            OSSL_FUNC_PROVIDER_GET_PARAMS => self.get_params = Some(unsafe { cast(f) }),
            // SAFETY: as above.
            OSSL_FUNC_PROVIDER_SELF_TEST => self.self_test = Some(unsafe { cast(f) }),
            // SAFETY: as above.
            OSSL_FUNC_PROVIDER_QUERY_OPERATION => self.query_operation = Some(unsafe { cast(f) }),
            OSSL_FUNC_PROVIDER_UNQUERY_OPERATION => {
                // SAFETY: as above.
                self.unquery_operation = Some(unsafe { cast(f) });
            }
            // SAFETY: as above.
            OSSL_FUNC_PROVIDER_RANDOM_BYTES => self.random_bytes = Some(unsafe { cast(f) }),
            OSSL_FUNC_PROVIDER_GET_CAPABILITIES => {
                // SAFETY: as above.
                self.get_capabilities = Some(unsafe { cast(f) });
            }
            _ => {}
        }
    }
}

/// `ossl_provider_activate(prov, 1, 0)`: [`activate_with`] with upcalls.
///
/// # Safety
/// `handle` is a live provider.
unsafe fn activate(handle: *mut OSSL_PROVIDER) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { activate_with(handle, true) }
}

/// `ossl_provider_activate(prov, upcalls, 0)`: initializes a provider not yet in its store,
/// gives a child provider's parent an activation (with `upcalls`), then counts an activation;
/// the first, for a provider in its store, makes its children in the child contexts. False if
/// any of it failed.
///
/// # Safety
/// `handle` is a live provider.
pub(crate) unsafe fn activate_with(handle: *mut OSSL_PROVIDER, upcalls: bool) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(prov) = (unsafe { OSSL_PROVIDER::get(handle) }) else {
        return false;
    };
    let needs_init = {
        let s = prov.state();
        !s.in_store && !s.initialized
    };
    if needs_init && !provider_init(handle, prov) {
        return false;
    }
    if prov.functions().1.random_bytes.is_some()
        && !crate::rand_lib::check_random_provider_on_load(prov.libctx(), handle)
    {
        return false;
    }
    if prov.is_child() && upcalls && !child::up_ref_parent(prov, true) {
        return false;
    }
    let (first, in_store) = {
        let mut s = prov.state();
        s.activations = s.activations.saturating_add(1);
        s.activated = true;
        (s.activations == 1, s.in_store)
    };
    // As in OpenSSL, a failure here leaves the activation counted.
    // SAFETY: the caller's guarantee.
    if first && in_store && !unsafe { create_children(handle) } {
        return false;
    }
    if first {
        // `provider_flush_store_cache`: choices made without this provider are stale.
        crate::evp::fetch::flush_cache(prov.libctx());
    }
    true
}

/// `ossl_provider_activate(prov, 0, 1)`, for a provider that a child context finds of a parent
/// provider's name: activated if it's a child provider; one the child context loaded itself is
/// left alone (true).
///
/// # Safety
/// `handle` is a live provider.
pub(crate) unsafe fn activate_as_child(handle: *mut OSSL_PROVIDER) -> bool {
    // SAFETY: the caller's guarantee.
    if !unsafe { OSSL_PROVIDER::get(handle) }.is_some_and(Provider::is_child) {
        return true;
    }
    // SAFETY: the caller's guarantee.
    unsafe { activate_with(handle, false) }
}

/// `ossl_provider_deactivate(prov, 1)`: [`deactivate_with`] with upcalls, removing children.
///
/// # Safety
/// `handle` is NULL or a live provider.
unsafe fn deactivate(handle: *mut OSSL_PROVIDER) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { deactivate_with(handle, true, true) }
}

/// `ossl_provider_deactivate` (`provider_deactivate(prov, upcalls, removechildren)`): counts a
/// deactivation. The last takes its children from the child contexts (if `removechildren`) and
/// its algorithms from the method store; one that isn't the last gives back a child provider's
/// activation of its parent (with `upcalls`). False for NULL or after more deactivations than
/// activations.
///
/// # Safety
/// `handle` is NULL or a live provider.
pub(crate) unsafe fn deactivate_with(
    handle: *mut OSSL_PROVIDER,
    upcalls: bool,
    removechildren: bool,
) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(prov) = (unsafe { OSSL_PROVIDER::get(handle) }) else {
        return false;
    };
    if prov.functions().1.random_bytes.is_some() {
        crate::rand_lib::check_random_provider_on_unload(prov.libctx(), handle);
    }
    let count = count_deactivation(prov);
    let free_parent = count >= 1 && prov.is_child() && upcalls;
    if count < 1 && removechildren {
        // SAFETY: the caller's guarantee.
        unsafe { remove_children(handle) };
    }
    if free_parent {
        child::free_parent(prov, true);
    }
    if count == 0 {
        // `provider_remove_store_methods`: its algorithms go from the method store.
        prov.state().operations = 0;
        crate::evp::fetch::remove_provider(prov.libctx(), handle);
    }
    count >= 0
}

/// A child context's callbacks, registered with its parent's store through a provider
/// (`OSSL_PROVIDER_CHILD_CB`).
#[derive(Clone, Copy)]
struct ChildCb {
    /// The provider that registered them.
    prov: Ptr<OSSL_PROVIDER>,
    create: upcalls::ChildFn,
    remove: upcalls::ChildFn,
    props: upcalls::PropsFn,
    cbdata: Ptr<c_void>,
}

/// The child callbacks registered with `libctx`'s store, copied out of its lock.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn child_cbs(libctx: *mut OSSL_LIB_CTX) -> Vec<ChildCb> {
    // SAFETY: the caller's guarantee.
    with_store(unsafe { context(libctx) }, |s| s.lock().child_cbs.clone()).unwrap_or_default()
}

/// `create_provider_children`: each child context hears that `handle` was activated. True if
/// every one made its child.
///
/// # Safety
/// `handle` is a live provider.
unsafe fn create_children(handle: *mut OSSL_PROVIDER) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(prov) = (unsafe { OSSL_PROVIDER::get(handle) }) else {
        return false;
    };
    let mut ok = true;
    // SAFETY: a live provider's context.
    for cb in unsafe { child_cbs(prov.libctx()) } {
        // SAFETY: the registrant's callback with its own data; no lock is held.
        ok &= unsafe { (cb.create)(handle.cast(), cb.cbdata.0) } != 0;
    }
    ok
}

/// `provider_deactivate`'s removal: each child context hears that `handle` was deactivated.
///
/// # Safety
/// `handle` is a live provider.
unsafe fn remove_children(handle: *mut OSSL_PROVIDER) {
    // SAFETY: the caller's guarantee.
    let Some(prov) = (unsafe { OSSL_PROVIDER::get(handle) }) else {
        return;
    };
    // SAFETY: a live provider's context.
    for cb in unsafe { child_cbs(prov.libctx()) } {
        // SAFETY: as above.
        unsafe { (cb.remove)(handle.cast(), cb.cbdata.0) };
    }
}

/// `ossl_provider_default_props_update`: the child contexts registered with `ctx`'s store hear
/// of its new default properties.
pub(crate) fn default_props_update(ctx: &libctx::LibCtx, props: &[u8]) {
    let cbs = ctx.providers.lock().child_cbs.clone();
    if cbs.is_empty() {
        return;
    }
    let Ok(text) = CString::new(props) else {
        return;
    };
    for cb in cbs {
        // SAFETY: the registrant's callback with a string and its own data; no lock is held.
        unsafe { (cb.props)(text.as_ptr(), cb.cbdata.0) };
    }
}

/// `ossl_provider_register_child_cb`: the provider `handle`'s child context hears of the
/// global properties and of each provider active in `handle`'s context now, then of those
/// activated and deactivated later. 1, or 0 if a creation failed (each provider up to it given
/// to `remove`).
///
/// # Safety
/// `handle` is a live provider; the callbacks take `cbdata`.
pub(crate) unsafe fn register_child_cb(
    handle: *const OSSL_PROVIDER,
    create: upcalls::ChildFn,
    remove: upcalls::ChildFn,
    props: upcalls::PropsFn,
    cbdata: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(this) = (unsafe { OSSL_PROVIDER::get(handle) }) else {
        return 0;
    };
    // SAFETY: a live provider's context.
    let Some(ctx) = (unsafe { context(this.libctx()) }) else {
        return 0;
    };
    let text = crate::property::global_text(&ctx);
    // The store's providers, held, and whether each is active.
    let providers: Vec<(*mut OSSL_PROVIDER, bool)> = {
        let store = ctx.providers.lock();
        store
            .providers
            .iter()
            .filter_map(|p| {
                let activated = p.get()?.state().activated;
                // SAFETY: in the store, so live.
                unsafe { OSSL_PROVIDER::up_ref(p.0.0) }.then_some((p.0.0, activated))
            })
            .collect()
    };
    if let Some(t) = text.and_then(|t| CString::new(t).ok()) {
        // SAFETY: the caller's callback with a string and its data; no lock is held.
        unsafe { props(t.as_ptr(), cbdata) };
    }
    let failed = providers.iter().position(|&(p, activated)| {
        // SAFETY: as above, with a held provider.
        activated && unsafe { create(p.cast(), cbdata) } == 0
    });
    let ret = match failed {
        None => {
            ctx.providers.lock().child_cbs.push(ChildCb {
                prov: Ptr(handle.cast_mut()),
                create,
                remove,
                props,
                cbdata: Ptr(cbdata),
            });
            1
        }
        Some(i) => {
            for &(p, _) in providers.iter().take(i.saturating_add(1)).rev() {
                // SAFETY: as above.
                unsafe { remove(p.cast(), cbdata) };
            }
            0
        }
    };
    for (p, _) in providers {
        // SAFETY: the references taken above.
        unsafe { OSSL_PROVIDER::free(p) };
    }
    ret
}

/// `ossl_provider_deregister_child_cb`: the callbacks `handle` registered go.
///
/// # Safety
/// `handle` is a live provider.
pub(crate) unsafe fn deregister_child_cb(handle: *const OSSL_PROVIDER) {
    // SAFETY: the caller's guarantee.
    let Some(this) = (unsafe { OSSL_PROVIDER::get(handle) }) else {
        return;
    };
    // SAFETY: a live provider's context.
    with_store(unsafe { context(this.libctx()) }, |s| {
        let mut store = s.lock();
        if let Some(i) = store
            .child_cbs
            .iter()
            .position(|c| c.prov.0.cast_const() == handle)
        {
            store.child_cbs.remove(i);
        }
    });
}

/// `core_provider_up_ref_intern`: an activation (1, or 0 if it failed) or a reference (the
/// count afterwards).
///
/// # Safety
/// `prov` is NULL or a live provider.
pub(crate) unsafe fn up_ref_intern(prov: *mut OSSL_PROVIDER, activate: bool) -> c_int {
    if activate {
        // SAFETY: the caller's guarantee.
        return c_int::from(!prov.is_null() && unsafe { activate_with(prov, true) });
    }
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_PROVIDER::up_ref_count(prov) }
        .map_or(0, |n| c_int::try_from(n).unwrap_or(c_int::MAX))
}

/// `core_provider_free_intern`: a deactivation (1, or 0 after more than there were
/// activations) or a reference given up (1).
///
/// # Safety
/// `prov` is NULL or a live provider; without `deactivate`, the caller gives up a reference.
pub(crate) unsafe fn free_intern(prov: *mut OSSL_PROVIDER, deactivate: bool) -> c_int {
    if deactivate {
        // SAFETY: the caller's guarantee.
        return c_int::from(unsafe { deactivate_with(prov, true, true) });
    }
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_PROVIDER::free(prov) };
    1
}

/// `provider_deactivate`'s count: one activation fewer. Returns the new count.
fn count_deactivation(prov: &Provider) -> i32 {
    let mut s = prov.state();
    s.activations = s.activations.saturating_sub(1);
    if s.activations < 1 {
        s.activated = false;
    }
    s.activations
}

/// `ossl_provider_add_to_store`: adds a new provider to its store, or finds that another of
/// its name got there first. Returns the provider in the store, with a reference for the
/// caller; the new one, if not added, is deactivated and freed.
///
/// # Safety
/// `handle` is a live provider with a reference the store takes.
unsafe fn add_to_store(
    handle: *mut OSSL_PROVIDER,
    retain_fallbacks: bool,
) -> Option<*mut OSSL_PROVIDER> {
    // SAFETY: the caller's guarantee.
    let prov = unsafe { OSSL_PROVIDER::get(handle) }?;
    let name = prov.name.clone();
    let libctx = prov.libctx.0;
    let (actual, added) = {
        // SAFETY: a live provider's context.
        with_store(unsafe { context(libctx) }, |s| {
            let mut store = s.lock();
            match store.find(&name) {
                Some(existing) => (existing, false),
                None => {
                    store.push(handle);
                    prov.state().in_store = true;
                    (handle, true)
                }
            }
        })
    }?;
    if added {
        // `create_provider_children` (OpenSSL holds the store's lock; this doesn't, rule 7).
        // SAFETY: the caller's guarantee.
        if !unsafe { create_children(handle) } {
            // SAFETY: as above.
            with_store(unsafe { context(libctx) }, |s| {
                let mut store = s.lock();
                if let Some(i) = store.providers.iter().position(|p| p.0.0 == handle) {
                    // The store's reference goes back to the caller (a `Stored` frees nothing).
                    store.providers.remove(i);
                }
            });
            prov.state().in_store = false;
            return None;
        }
        if !retain_fallbacks {
            // SAFETY: as above.
            with_store(unsafe { context(libctx) }, |s| {
                s.lock().use_fallbacks = false
            });
        }
    }
    // SAFETY: in the store, so live.
    if !unsafe { OSSL_PROVIDER::up_ref(actual) } {
        return None;
    }
    if actual != handle {
        // SAFETY: the new provider, which the store didn't take.
        unsafe { deactivate(handle) };
        // SAFETY: as above, its reference given up.
        unsafe { OSSL_PROVIDER::free(handle) };
    }
    Some(actual)
}

/// `provider_activate_fallbacks`: activates the default provider if the store still uses
/// fallbacks. False if it couldn't be.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn activate_fallbacks(libctx: *mut OSSL_LIB_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(use_fallbacks) = with_store(unsafe { context(libctx) }, |s| s.lock().use_fallbacks)
    else {
        return false;
    };
    if !use_fallbacks {
        return true;
    }
    let mut made = Vec::new();
    for &(name, init, fallback) in builtin::PREDEFINED {
        if !fallback {
            continue;
        }
        // The parameters of the first information under the name (the configuration's, for a
        // provider it names without activating).
        // SAFETY: the caller's guarantee.
        let params = with_store(unsafe { context(libctx) }, |s| {
            s.lock()
                .infos
                .iter()
                .find(|i| i.name.as_c_str() == name)
                .and_then(|i| i.parameters.clone())
        })
        .flatten()
        .unwrap_or_default();
        let handle = provider_new(libctx, name, init, params);
        // SAFETY: just made.
        if !unsafe { activate(handle) } {
            // SAFETY: as above, freed.
            unsafe { OSSL_PROVIDER::free(handle) };
            for h in made {
                // SAFETY: made above, not stored.
                unsafe { OSSL_PROVIDER::free(h) };
            }
            return false;
        }
        made.push(handle);
    }
    let leftover = {
        // SAFETY: the caller's guarantee.
        with_store(unsafe { context(libctx) }, |s| {
            let mut store = s.lock();
            if !store.use_fallbacks {
                // Another thread activated them meanwhile.
                return made;
            }
            for &h in &made {
                // SAFETY: made above.
                if let Some(p) = unsafe { OSSL_PROVIDER::get(h) } {
                    p.state().in_store = true;
                }
                store.push(h);
            }
            store.use_fallbacks = made.is_empty();
            Vec::new()
        })
    };
    for h in leftover.unwrap_or_default() {
        // SAFETY: made above, not stored.
        unsafe { OSSL_PROVIDER::free(h) };
    }
    true
}

/// The name argument as a C string, or `None` (with an error) for NULL, where OpenSSL would
/// crash.
///
/// # Safety
/// `name` is NULL or a string.
#[track_caller]
unsafe fn name_arg<'a>(name: *const c_char, function: &str) -> Option<&'a CStr> {
    if name.is_null() {
        err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, function);
        return None;
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { CStr::from_ptr(name) })
}

/// `OSSL_PROVIDER_try_load_ex`.
///
/// # Safety
/// `libctx` is NULL or a live library context; `params` as for [`new`].
unsafe fn try_load(
    libctx: *mut OSSL_LIB_CTX,
    name: &CStr,
    params: *const OSSL_PARAM,
    retain_fallbacks: bool,
) -> *mut OSSL_PROVIDER {
    // SAFETY: the caller's guarantee.
    let (prov, is_new) = match unsafe { find(libctx, name) } {
        Some(p) => (p, false),
        // SAFETY: the caller's guarantee.
        None => (unsafe { new(libctx, name, params) }, true),
    };
    // SAFETY: found or made, so live.
    if !unsafe { activate(prov) } {
        // SAFETY: as above, our reference given up.
        unsafe { OSSL_PROVIDER::free(prov) };
        return ptr::null_mut();
    }
    if !is_new {
        return prov;
    }
    // SAFETY: made above, its reference for the store.
    let Some(actual) = (unsafe { add_to_store(prov, retain_fallbacks) }) else {
        // SAFETY: as above.
        unsafe { deactivate(prov) };
        // SAFETY: as above.
        unsafe { OSSL_PROVIDER::free(prov) };
        return ptr::null_mut();
    };
    // SAFETY: in the store, with the caller's reference.
    if actual != prov && !unsafe { activate(actual) } {
        // SAFETY: as above.
        unsafe { OSSL_PROVIDER::free(actual) };
        return ptr::null_mut();
    }
    actual
}

ffi_export! {
    /// Loads (or finds) and activates the provider `name` in `libctx` (the thread's default
    /// context for NULL), with the UTF-8 strings of `params` as its configuration; the
    /// fallback to the default provider stays if `retain_fallbacks`. NULL on failure.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` is a string; `params` is NULL or an
    /// array ended by a NULL key.
    pub unsafe extern "C" fn OSSL_PROVIDER_try_load_ex(libctx: *mut OSSL_LIB_CTX, name: *const c_char, params: *mut OSSL_PARAM, retain_fallbacks: c_int) -> *mut OSSL_PROVIDER
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(name) = (unsafe { name_arg(name, "OSSL_PROVIDER_try_load_ex") }) else { return ptr::null_mut() };
        // SAFETY: the caller's guarantee.
        unsafe { try_load(libctx, name, params, retain_fallbacks != 0) }
    }
}

ffi_export! {
    /// As `OSSL_PROVIDER_try_load_ex`, without parameters.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` is a string.
    pub unsafe extern "C" fn OSSL_PROVIDER_try_load(libctx: *mut OSSL_LIB_CTX, name: *const c_char, retain_fallbacks: c_int) -> *mut OSSL_PROVIDER
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(name) = (unsafe { name_arg(name, "OSSL_PROVIDER_try_load") }) else { return ptr::null_mut() };
        // SAFETY: the caller's guarantee.
        unsafe { try_load(libctx, name, ptr::null(), retain_fallbacks != 0) }
    }
}

/// `OSSL_PROVIDER_load_ex`: any load disables the fallback, even one that fails.
///
/// # Safety
/// As for [`try_load`].
unsafe fn load(
    libctx: *mut OSSL_LIB_CTX,
    name: &CStr,
    params: *const OSSL_PARAM,
) -> *mut OSSL_PROVIDER {
    // SAFETY: the caller's guarantee.
    let disabled = with_store(unsafe { context(libctx) }, |s| {
        s.lock().use_fallbacks = false
    });
    if disabled.is_none() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    unsafe { try_load(libctx, name, params, false) }
}

ffi_export! {
    /// Loads (or finds) and activates the provider `name`, with the UTF-8 strings of `params`
    /// as its configuration, and stops the fallback to the default provider. NULL on failure.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` is a string; `params` is NULL or an
    /// array ended by a NULL key.
    pub unsafe extern "C" fn OSSL_PROVIDER_load_ex(libctx: *mut OSSL_LIB_CTX, name: *const c_char, params: *mut OSSL_PARAM) -> *mut OSSL_PROVIDER
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(name) = (unsafe { name_arg(name, "OSSL_PROVIDER_load_ex") }) else { return ptr::null_mut() };
        // SAFETY: the caller's guarantee.
        unsafe { load(libctx, name, params) }
    }
}

ffi_export! {
    /// As `OSSL_PROVIDER_load_ex`, without parameters.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` is a string.
    pub unsafe extern "C" fn OSSL_PROVIDER_load(libctx: *mut OSSL_LIB_CTX, name: *const c_char) -> *mut OSSL_PROVIDER
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(name) = (unsafe { name_arg(name, "OSSL_PROVIDER_load") }) else { return ptr::null_mut() };
        // SAFETY: the caller's guarantee.
        unsafe { load(libctx, name, ptr::null()) }
    }
}

ffi_export! {
    /// Deactivates a provider and drops the caller's reference. Returns 1, or 0 for NULL or a
    /// provider unloaded more times than loaded.
    ///
    /// # Safety
    /// `prov` is NULL or a provider the caller holds, not used afterwards.
    pub unsafe extern "C" fn OSSL_PROVIDER_unload(prov: *mut OSSL_PROVIDER) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { deactivate(prov) } {
            return 0;
        }
        // SAFETY: as above, the caller's reference.
        unsafe { OSSL_PROVIDER::free(prov) };
        1
    }
}

ffi_export! {
    /// Whether the provider `name` is loaded and active in `libctx` (the thread's default
    /// context for NULL), after activating the fallback if nothing was loaded.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` is a string.
    pub unsafe extern "C" fn OSSL_PROVIDER_available(libctx: *mut OSSL_LIB_CTX, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(name) = (unsafe { name_arg(name, "OSSL_PROVIDER_available") }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if !unsafe { activate_fallbacks(libctx) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(found) = (unsafe { find(libctx, name) }) else { return 0 };
        // SAFETY: found, with our reference.
        let available = unsafe { OSSL_PROVIDER::get(found) }.is_some_and(|p| p.state().activated);
        // SAFETY: our reference, given up.
        unsafe { OSSL_PROVIDER::free(found) };
        c_int::from(available)
    }
}

/// `OSSL_PROVIDER_do_all`'s callback.
type DoAllFn = unsafe extern "C" fn(*mut OSSL_PROVIDER, *mut c_void) -> c_int;

ffi_export! {
    /// Calls `cb` with each active provider of `libctx` (the thread's default context for
    /// NULL), in OpenSSL's order, after activating the fallback if nothing was loaded; stops
    /// when `cb` returns 0. Each provider stays loaded during its call. Returns 1, or 0 if a
    /// callback failed.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `cb` is a function of the documented type.
    pub unsafe extern "C" fn OSSL_PROVIDER_do_all(ctx: *mut OSSL_LIB_CTX, cb: Option<DoAllFn>, cbdata: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        load_config_for(ctx);
        // SAFETY: the caller's guarantee.
        if !unsafe { activate_fallbacks(ctx) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let held = unsafe { hold_activated(ctx) };
        let mut ret = 1;
        if let Some(cb) = cb {
            for &prov in &held {
                // SAFETY: the caller's guarantee about the callback; the provider is held.
                if unsafe { cb(prov, cbdata) } == 0 {
                    ret = 0;
                    break;
                }
            }
        }
        release_activated(held);
        ret
    }
}

/// The active providers of `libctx`'s store, in its order, each held with a reference and one
/// more activation while the caller works with it (`ossl_provider_doall_activated`).
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn hold_activated(libctx: *mut OSSL_LIB_CTX) -> Vec<*mut OSSL_PROVIDER> {
    // SAFETY: the caller's guarantee.
    with_store(unsafe { context(libctx) }, |s| {
        let store = s.lock();
        let mut held = Vec::new();
        for p in &store.providers {
            let Some(prov) = p.get() else { continue };
            let mut st = prov.state();
            if !st.activated {
                continue;
            }
            st.activations = st.activations.saturating_add(1);
            drop(st);
            // SAFETY: in the store, so live.
            if unsafe { OSSL_PROVIDER::up_ref(p.0.0) } {
                held.push(p.0.0);
            }
        }
        held
    })
    .unwrap_or_default()
}

/// Gives back what [`hold_activated`] took. A provider unloaded meanwhile (its extra
/// activation the last) is left inactive, without its algorithms going from the method store,
/// as OpenSSL does.
fn release_activated(held: Vec<*mut OSSL_PROVIDER>) {
    for prov in held {
        // SAFETY: held, so live.
        if let Some(p) = unsafe { OSSL_PROVIDER::get(prov) } {
            count_deactivation(p);
        }
        // SAFETY: the reference taken by `hold_activated`.
        unsafe { OSSL_PROVIDER::free(prov) };
    }
}

/// The providers a fetch looks through (`ossl_provider_doall_activated`): the configuration
/// loaded for the default context, the fallback activated, then the active providers, held.
/// Give them back with [`release_activated`].
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn activated(libctx: *mut OSSL_LIB_CTX) -> Vec<*mut OSSL_PROVIDER> {
    load_config_for(libctx);
    // SAFETY: the caller's guarantee.
    if !unsafe { activate_fallbacks(libctx) } {
        return Vec::new();
    }
    // SAFETY: the caller's guarantee.
    unsafe { hold_activated(libctx) }
}

/// Gives back the providers [`activated`] held.
pub(crate) fn release(held: Vec<*mut OSSL_PROVIDER>) {
    release_activated(held);
}

/// `ossl_provider_query_operation`: the provider's algorithms for `operation` (NULL if it has
/// none or no `query_operation`), and whether they mustn't be stored.
///
/// # Safety
/// `prov` is a live provider.
/// `ossl_provider_random_bytes`: `n` random octets into `buf` from the provider's
/// `random_bytes` (public or private ones, at `strength`); 0 if it has none.
///
/// # Safety
/// `prov` is NULL or a live provider; `buf` has room for `n` octets.
pub(crate) unsafe fn random_bytes(
    prov: *const OSSL_PROVIDER,
    which: c_int,
    buf: *mut c_void,
    n: usize,
    strength: c_uint,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { provider(prov) }) else {
        return 0;
    };
    let (provctx, f) = p.functions();
    match f.random_bytes {
        // SAFETY: the provider's function with its context and the caller's buffer.
        Some(random) => unsafe { random(provctx, which, buf, n, strength) },
        None => 0,
    }
}

pub(crate) unsafe fn query_operation(
    prov: *const OSSL_PROVIDER,
    operation: c_int,
) -> (*const OSSL_ALGORITHM, bool) {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { provider(prov) }) else {
        return (ptr::null(), false);
    };
    let (provctx, f) = p.functions();
    let Some(query) = f.query_operation else {
        return (ptr::null(), false);
    };
    let mut no_store: c_int = 0;
    // SAFETY: the provider's function with its context.
    let algs = unsafe { query(provctx, operation, &raw mut no_store) };
    (algs, no_store != 0)
}

/// `ossl_provider_unquery_operation`: gives the provider back the algorithms it returned.
///
/// # Safety
/// `prov` is a live provider; `algs` is what its `query_operation` returned for `operation`.
pub(crate) unsafe fn unquery_operation(
    prov: *const OSSL_PROVIDER,
    operation: c_int,
    algs: *const OSSL_ALGORITHM,
) {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { provider(prov) }) else {
        return;
    };
    let (provctx, f) = p.functions();
    if let Some(unquery) = f.unquery_operation {
        // SAFETY: the provider's function with its context and its own algorithms.
        unsafe { unquery(provctx, operation, algs) };
    }
}

/// The bit standing for `operation` (`ossl_provider_test_operation_bit` and `_set_`).
fn operation_bit(operation: c_int) -> u64 {
    u32::try_from(operation)
        .ok()
        .and_then(|n| 1u64.checked_shl(n))
        .unwrap_or(0)
}

/// Whether the provider's algorithms for `operation` are in the method store.
///
/// # Safety
/// `prov` is a live provider.
pub(crate) unsafe fn operation_stored(prov: *const OSSL_PROVIDER, operation: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { provider(prov) }.is_some_and(|p| p.state().operations & operation_bit(operation) != 0)
}

/// Records that the provider's algorithms for `operation` are in the method store.
///
/// # Safety
/// `prov` is a live provider.
pub(crate) unsafe fn set_operation_stored(prov: *const OSSL_PROVIDER, operation: c_int) {
    // SAFETY: the caller's guarantee.
    if let Some(p) = unsafe { provider(prov) } {
        p.state().operations |= operation_bit(operation);
    }
}

ffi_export! {
    /// The provider's algorithms for `operation_id`, and through `no_cache` whether they may be
    /// kept. NULL if it has none.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider; `no_cache` is NULL or valid for a write.
    pub unsafe extern "C" fn OSSL_PROVIDER_query_operation(prov: *const OSSL_PROVIDER, operation_id: c_int, no_cache: *mut c_int) -> *const OSSL_ALGORITHM
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provider(prov) }) else { return ptr::null() };
        let (provctx, f) = p.functions();
        let Some(query) = f.query_operation else { return ptr::null() };
        // SAFETY: the provider's function with its context and the caller's flag.
        unsafe { query(provctx, operation_id, no_cache) }
    }
}

ffi_export! {
    /// Gives the provider back algorithms `OSSL_PROVIDER_query_operation` returned.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider; `algs` came from its `query_operation`.
    pub unsafe extern "C" fn OSSL_PROVIDER_unquery_operation(prov: *const OSSL_PROVIDER, operation_id: c_int, algs: *const OSSL_ALGORITHM)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { unquery_operation(prov, operation_id, algs) };
    }
}

ffi_export! {
    /// Registers an application's built-in provider `name` with its init function in `libctx`
    /// (the thread's default context for NULL), for a later load. Returns 1, or 0 for a NULL
    /// name or function.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `name` is NULL or a string; `init_fn` is
    /// NULL or a provider init function.
    pub unsafe extern "C" fn OSSL_PROVIDER_add_builtin(libctx: *mut OSSL_LIB_CTX, name: *const c_char, init_fn: OSSL_provider_init_fn) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if name.is_null() || init_fn.is_none() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, "OSSL_PROVIDER_add_builtin");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        // SAFETY: the caller's guarantee.
        let added = with_store(unsafe { context(libctx) }, |s| {
            s.lock().infos.push(Info { name, init: init_fn, path: None, parameters: None });
        });
        c_int::from(added.is_some())
    }
}

/// Whether `prov` is one of rustyssl's own predefined providers, whose functions are Rust (an
/// application's or a module's are C).
///
/// # Safety
/// `prov` is NULL or a live provider.
pub(crate) unsafe fn is_predefined(prov: *const OSSL_PROVIDER) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_PROVIDER::get(prov) }.is_some_and(|p| {
        builtin::PREDEFINED
            .iter()
            .any(|&(_, init, _)| match (init, p.init) {
                (Some(a), Some(b)) => core::ptr::fn_addr_eq(a, b),
                _ => false,
            })
    })
}

/// The library context a provider was loaded into, as given (NULL for the default).
///
/// # Safety
/// `prov` is NULL or a live provider.
pub(crate) unsafe fn libctx_of(prov: *const OSSL_PROVIDER) -> *mut OSSL_LIB_CTX {
    // SAFETY: the caller's guarantee.
    unsafe { provider(prov) }.map_or(ptr::null_mut(), Provider::libctx)
}

/// The provider behind `prov`, or `None` for NULL.
///
/// # Safety
/// `prov` is NULL or a live provider.
unsafe fn provider<'a>(prov: *const OSSL_PROVIDER) -> Option<&'a Provider> {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_PROVIDER::get(prov) }
}

ffi_export! {
    /// The provider's name, or NULL for NULL (OpenSSL would crash, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `prov` is NULL or a live provider.
    pub unsafe extern "C" fn OSSL_PROVIDER_get0_name(prov: *const OSSL_PROVIDER) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { provider(prov) }.map_or(ptr::null(), |p| p.name.as_ptr())
    }
}

ffi_export! {
    /// The provider's own context, or NULL.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider.
    pub unsafe extern "C" fn OSSL_PROVIDER_get0_provider_ctx(prov: *const OSSL_PROVIDER) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { provider(prov) }.map_or(ptr::null_mut(), |p| p.functions().0)
    }
}

ffi_export! {
    /// The dispatch table the provider's init function returned, or NULL.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider.
    pub unsafe extern "C" fn OSSL_PROVIDER_get0_dispatch(prov: *const OSSL_PROVIDER) -> *const OSSL_DISPATCH
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { provider(prov) }.and_then(|p| p.state().dispatch).map_or(ptr::null(), |d| d.0.cast_const())
    }
}

ffi_export! {
    /// The parameters the provider can report, or NULL if it has no `gettable_params`.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider.
    pub unsafe extern "C" fn OSSL_PROVIDER_gettable_params(prov: *const OSSL_PROVIDER) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provider(prov) }) else { return ptr::null() };
        let (provctx, f) = p.functions();
        match f.gettable_params {
            // SAFETY: the provider's function with its context.
            Some(gettable) => unsafe { gettable(provctx) },
            None => ptr::null(),
        }
    }
}

ffi_export! {
    /// Asks the provider for `params`. Returns its result, or 0 if it has no `get_params`.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider; `params` is an array the provider may fill.
    pub unsafe extern "C" fn OSSL_PROVIDER_get_params(prov: *const OSSL_PROVIDER, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provider(prov) }) else { return 0 };
        let (provctx, f) = p.functions();
        match f.get_params {
            // SAFETY: the provider's function with its context and the caller's array.
            Some(get) => unsafe { get(provctx, params) },
            None => 0,
        }
    }
}

ffi_export! {
    /// Gives each parameter set of the provider's `capability` (`TLS-GROUP`, `TLS-SIGALG`) to
    /// `cb`. The provider's result, or 1 if it has no `get_capabilities`.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider; `capability` NULL or a NUL-terminated string; `cb`
    /// takes `arg`.
    pub unsafe extern "C" fn OSSL_PROVIDER_get_capabilities(prov: *const OSSL_PROVIDER, capability: *const core::ffi::c_char, cb: rustyssl_abi::OSSL_CALLBACK, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provider(prov) }) else { return 0 };
        let (provctx, f) = p.functions();
        match f.get_capabilities {
            // SAFETY: the provider's function with its context and the caller's arguments; no
            // lock is held.
            Some(get) => unsafe { get(provctx, capability, cb, arg) },
            None => 1,
        }
    }
}

ffi_export! {
    /// Runs the provider's self-test: its result, or 1 if it has none.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider.
    pub unsafe extern "C" fn OSSL_PROVIDER_self_test(prov: *const OSSL_PROVIDER) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provider(prov) }) else { return 0 };
        let (provctx, f) = p.functions();
        match f.self_test {
            // SAFETY: the provider's function with its context.
            Some(test) => unsafe { test(provctx) },
            None => 1,
        }
    }
}

ffi_export! {
    /// Sets the directory modules are loaded from in `libctx` (the thread's default context
    /// for NULL); NULL goes back to `OPENSSL_MODULES` or the built-in directory. Returns 1.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `path` is NULL or a string.
    pub unsafe extern "C" fn OSSL_PROVIDER_set_default_search_path(libctx: *mut OSSL_LIB_CTX, path: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let path = if path.is_null() {
            None
        } else {
            // SAFETY: the caller's guarantee.
            Some(unsafe { CStr::from_ptr(path) }.to_owned())
        };
        let set = {
            // SAFETY: the caller's guarantee.
            with_store(unsafe { context(libctx) }, |s| {
                let mut store = s.lock();
                let old = core::mem::replace(&mut store.default_path, path);
                store.old_paths.extend(old);
            })
        };
        c_int::from(set.is_some())
    }
}

ffi_export! {
    /// The directory set with `OSSL_PROVIDER_set_default_search_path`, or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context.
    pub unsafe extern "C" fn OSSL_PROVIDER_get0_default_search_path(libctx: *mut OSSL_LIB_CTX) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let path = with_store(unsafe { context(libctx) }, |s| s.lock().default_path.as_ref().map(|p| p.as_ptr()));
        path.flatten().unwrap_or(ptr::null())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    unsafe extern "C" fn count(_prov: *mut OSSL_PROVIDER, data: *mut c_void) -> c_int {
        // SAFETY: the test passes a counter.
        unsafe { *data.cast::<i32>() += 1 };
        1
    }

    #[test]
    fn lifecycle_in_a_context() {
        // SAFETY: no preconditions.
        let ctx = unsafe { libctx::OSSL_LIB_CTX_new() };
        // SAFETY: a live context and a string.
        let base = unsafe { OSSL_PROVIDER_load(ctx, c"base".as_ptr()) };
        // SAFETY: as above.
        let null = unsafe { OSSL_PROVIDER_try_load(ctx, c"null".as_ptr(), 1) };
        assert!(!base.is_null() && !null.is_null());
        // SAFETY: as above.
        let again = unsafe { OSSL_PROVIDER_load(ctx, c"base".as_ptr()) };
        assert_eq!(again, base);
        let mut n = 0i32;
        // SAFETY: a live context and a counting callback.
        let r = unsafe { OSSL_PROVIDER_do_all(ctx, Some(count), (&raw mut n).cast()) };
        assert_eq!((r, n), (1, 2));
        // SAFETY: a provider held by the test.
        let status = unsafe { OSSL_PROVIDER_self_test(base) };
        assert_eq!(status, 1);
        // docs/DEVIATIONS.md: the build information names rustyssl, as the version text does.
        let mut info: *const c_char = ptr::null();
        let mut params = [
            crate::params::construct(
                c"buildinfo".as_ptr(),
                rustyssl_crypto::params::UTF8_PTR,
                (&raw mut info).cast(),
                0,
            ),
            crate::params::end(),
        ];
        // SAFETY: a provider held by the test, and a parameter array.
        let r = unsafe { OSSL_PROVIDER_get_params(base, params.as_mut_ptr()) };
        assert_eq!(r, 1);
        // SAFETY: set to a static string.
        let info = unsafe { CStr::from_ptr(info) }.to_str().unwrap_or_default();
        let version = rustyssl_abi::OPENSSL_VERSION_STR
            .to_str()
            .unwrap_or_default();
        assert!(info.starts_with(&format!("{version}+rustyssl.")), "{info}");
        // SAFETY: null's context is its handle.
        let provctx = unsafe { OSSL_PROVIDER_get0_provider_ctx(null) };
        assert_eq!(provctx, null.cast());
        for p in [again, base, null] {
            // SAFETY: each reference the test holds, once.
            let r = unsafe { OSSL_PROVIDER_unload(p) };
            assert_eq!(r, 1);
        }
        // SAFETY: a live context.
        let available = unsafe { OSSL_PROVIDER_available(ctx, c"base".as_ptr()) };
        assert_eq!(available, 0);
        // SAFETY: the context and the providers it still holds go.
        unsafe { libctx::OSSL_LIB_CTX_free(ctx) };
    }

    /// docs/DEVIATIONS.md: NULL names, providers, and callbacks.
    #[test]
    fn null_arguments_fail() {
        // SAFETY: NULL is the case under test, here and below.
        assert!(unsafe { OSSL_PROVIDER_load(ptr::null_mut(), ptr::null()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { OSSL_PROVIDER_try_load(ptr::null_mut(), ptr::null(), 0) }.is_null());
        // SAFETY: as above.
        let r = unsafe { OSSL_PROVIDER_available(ptr::null_mut(), ptr::null()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert!(unsafe { OSSL_PROVIDER_get0_name(ptr::null()) }.is_null());
        // SAFETY: as above.
        let r = unsafe { OSSL_PROVIDER_get_params(ptr::null(), ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { OSSL_PROVIDER_self_test(ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { OSSL_PROVIDER_unload(ptr::null_mut()) }, 0);
        // SAFETY: a new context, and no callback.
        let ctx = unsafe { libctx::OSSL_LIB_CTX_new() };
        // SAFETY: as above.
        let r = unsafe { OSSL_PROVIDER_do_all(ctx, None, ptr::null_mut()) };
        assert_eq!(r, 1);
        // SAFETY: made above.
        unsafe { libctx::OSSL_LIB_CTX_free(ctx) };
        err::take_all();
    }
}

ffi_export! {
    /// Adds a configuration parameter to a provider. Returns 1, or 0 for a NULL argument (as
    /// OpenSSL does for a NULL name or value; for a NULL provider it would crash,
    /// docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `prov` is NULL or a live provider; `name` and `value` are NULL or strings.
    pub unsafe extern "C" fn OSSL_PROVIDER_add_conf_parameter(prov: *mut OSSL_PROVIDER, name: *const c_char, value: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provider(prov) }) else { return 0 };
        if name.is_null() || value.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        // SAFETY: as above.
        let value = unsafe { CStr::from_ptr(value) }.to_owned();
        p.parameters.lock().unwrap_or_else(PoisonError::into_inner).push((name, value));
        1
    }
}

/// The provider's configuration parameter `name`, as the core's `core_get_params` gives it to
/// the provider (the last of that name winning).
pub(crate) fn conf_value(p: &Provider, name: &CStr) -> Option<CString> {
    let parameters = p.parameters.lock().unwrap_or_else(PoisonError::into_inner);
    parameters
        .iter()
        .rev()
        .find(|(n, _)| n.as_c_str() == name)
        .map(|(_, v)| v.clone())
}

/// `OSSL_PROVIDER_get_conf_parameters`: points each parameter of `params` named like one of
/// the provider's at its value (a later one of the same name winning).
///
/// # Safety
/// `params` is an array ended by a NULL key whose entries may be written.
unsafe fn conf_parameters(p: &Provider, params: *mut OSSL_PARAM) -> c_int {
    let parameters = p.parameters.lock().unwrap_or_else(PoisonError::into_inner);
    for (name, value) in parameters.iter() {
        // SAFETY: the caller's guarantee.
        let q = unsafe { crate::params::OSSL_PARAM_locate(params, name.as_ptr()) };
        // SAFETY: as above; the value lives as long as the provider.
        if !q.is_null() && unsafe { crate::params::OSSL_PARAM_set_utf8_ptr(q, value.as_ptr()) } == 0
        {
            return 0;
        }
    }
    1
}

ffi_export! {
    /// Points each of `params` named like one of the provider's configuration parameters at its
    /// value. Returns 1, or 0 if one isn't a UTF-8 pointer parameter (or for NULL).
    ///
    /// # Safety
    /// `prov` is NULL or a live provider; `params` is an array ended by a NULL key whose
    /// entries may be written.
    pub unsafe extern "C" fn OSSL_PROVIDER_get_conf_parameters(prov: *const OSSL_PROVIDER, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provider(prov) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        unsafe { conf_parameters(p, params) }
    }
}

ffi_export! {
    /// The configuration parameter `name` as a Boolean: 1 for `1`, `yes`, `true`, or `on`, 0 for
    /// `0`, `no`, `false`, or `off` (without case), and `defval` otherwise or if it isn't set.
    ///
    /// # Safety
    /// `prov` is NULL or a live provider; `name` is NULL or a string.
    pub unsafe extern "C" fn OSSL_PROVIDER_conf_get_bool(prov: *const OSSL_PROVIDER, name: *const c_char, defval: c_int) -> c_int
    where failure = defval, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { provider(prov) }) else { return defval };
        if name.is_null() {
            return defval;
        }
        let mut val: *mut c_char = ptr::null_mut();
        let mut param = [
            crate::params::construct(name, rustyssl_crypto::params::UTF8_PTR, (&raw mut val).cast(), size_of::<*mut c_char>()),
            crate::params::end(),
        ];
        // SAFETY: an array of one UTF-8 pointer parameter and its end.
        let ok = unsafe { conf_parameters(p, param.as_mut_ptr()) };
        let [first, _] = &param;
        if ok == 0 || first.return_size == crate::params::unmodified() || val.is_null() {
            return defval;
        }
        // SAFETY: set to one of the provider's values, a string.
        let v = unsafe { CStr::from_ptr(val) }.to_bytes();
        let is = |words: &[&[u8]]| words.iter().any(|w| w.eq_ignore_ascii_case(v));
        if v == b"1" || is(&[b"yes", b"true", b"on"]) {
            1
        } else if v == b"0" || is(&[b"no", b"false", b"off"]) {
            0
        } else {
            defval
        }
    }
}
