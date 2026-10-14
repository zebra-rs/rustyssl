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
pub(crate) mod builtin;
pub(crate) mod ciphers;
pub(crate) mod digests;
pub(crate) mod exchanges;
pub(crate) mod kdfs;
mod kdfs_more;
pub(crate) mod keymgmt;
pub(crate) mod macs;
pub(crate) mod modes;
mod module;
pub(crate) mod rands;
pub(crate) mod signatures;
pub(crate) mod skeymgmt;
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

// SAFETY: the pointers are the application's or the provider's, used as OpenSSL uses them: passed
// back to the provider's functions (which OpenSSL may call from any thread) or compared.
unsafe impl<T> Send for Ptr<T> {}
// SAFETY: as above.
unsafe impl<T> Sync for Ptr<T> {}

type TeardownFn = unsafe extern "C" fn(*mut c_void);
type GettableParamsFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SelfTestFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type QueryFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_int) -> *const OSSL_ALGORITHM;
type UnqueryFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_ALGORITHM);
type RandomBytesFn = unsafe extern "C" fn(*mut c_void, c_int, *mut c_void, usize, c_uint) -> c_int;

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
    /// The module's path, from configuration (none yet).
    path: Option<CString>,
    /// The configuration parameters (`OSSL_PROVIDER_load_ex`'s UTF-8 strings and
    /// `OSSL_PROVIDER_add_conf_parameter`'s), in order. Never removed, so pointers to the values
    /// stay valid while the provider lives.
    parameters: Mutex<Vec<(CString, CString)>>,
    /// The error library number taken for it.
    #[expect(
        dead_code,
        reason = "used once providers load their error strings (3.1d-b)"
    )]
    error_lib: c_int,
    state: Mutex<State>,
}

handle_type!(OSSL_PROVIDER => Provider);

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
        self.path.as_deref()
    }

    /// The name.
    pub(crate) fn name(&self) -> &CStr {
        &self.name
    }

    /// The library context it was loaded into, as given.
    pub(crate) fn libctx(&self) -> *mut OSSL_LIB_CTX {
        self.libctx.0
    }
}

impl Drop for Provider {
    /// `ossl_provider_free` at the last reference: an initialized provider is torn down.
    fn drop(&mut self) {
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        if !state.initialized {
            return;
        }
        if let Some(teardown) = state.functions.teardown {
            let provctx = state.provctx.map_or(ptr::null_mut(), |p| p.0);
            // SAFETY: the provider's own teardown, given its own context, once.
            unsafe { teardown(provctx) };
        }
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
    /// The application's built-in providers (`OSSL_PROVIDER_add_builtin`), in order.
    infos: Vec<(CString, OSSL_provider_init_fn)>,
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

impl Drop for StoreState {
    /// `provider_deactivate_free` for each provider, as the context goes.
    fn drop(&mut self) {
        for p in self.providers.drain(..) {
            // The context is going, its method store with it: only the count changes.
            if let Some(prov) = p.get().filter(|p| p.state().activated) {
                count_deactivation(prov);
            }
            // SAFETY: the store's reference, given up.
            unsafe { OSSL_PROVIDER::free(p.0.0) };
        }
    }
}

/// A library context's provider store, behind its lock.
#[derive(Default)]
pub(crate) struct Store(Mutex<StoreState>);

impl Store {
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
        path: None,
        parameters: Mutex::new(parameters),
        error_lib,
        state: Mutex::new(State::default()),
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
    // A predefined built-in, else the first the application registered under the name.
    // SAFETY: the caller's guarantee.
    let registered = with_store(unsafe { context(libctx) }, |s| {
        s.lock()
            .infos
            .iter()
            .find(|(n, _)| n.as_c_str() == name)
            .and_then(|(_, init)| *init)
    })
    .flatten();
    let init = predefined(name).and_then(|(init, _)| init).or(registered);
    let mut parameters = Vec::new();
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
    provider_new(libctx, name, init, parameters)
}

/// `provider_init`: runs the init function (a module's, for one without, if it can be found),
/// keeping the provider's context and dispatch table.
fn provider_init(handle: *mut OSSL_PROVIDER, prov: &Provider) -> bool {
    let name = prov.name.to_string_lossy();
    let init = match prov.init {
        Some(init) => init,
        None => {
            // SAFETY: the store of a live provider's context.
            let path = with_store(unsafe { context(prov.libctx.0) }, |s| {
                s.lock().default_path.clone()
            })
            .flatten();
            module::load(prov, path.as_deref());
            return false;
        }
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
    let mut at = out;
    // SAFETY: the provider's table, ended by a zero function id.
    while let Some(d) = unsafe { at.as_ref() } {
        if d.function_id == 0 {
            break;
        }
        // SAFETY: each function has the type its id says (the provider's guarantee).
        unsafe { functions.set(d) };
        at = at.wrapping_add(1);
    }
    let mut s = prov.state();
    s.initialized = true;
    s.provctx = Some(Ptr(provctx));
    s.dispatch = Some(Ptr(out.cast_mut()));
    s.functions = functions;
    true
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
            // Capabilities come with the TLS groups and signature algorithms they describe.
            OSSL_FUNC_PROVIDER_GET_CAPABILITIES => {}
            _ => {}
        }
    }
}

/// `ossl_provider_activate`: initializes a provider not yet in its store, then counts an
/// activation. False if it couldn't be initialized.
///
/// # Safety
/// `handle` is a live provider.
unsafe fn activate(handle: *mut OSSL_PROVIDER) -> bool {
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
    let first = {
        let mut s = prov.state();
        s.activations = s.activations.saturating_add(1);
        s.activated = true;
        s.activations == 1
    };
    if first {
        // `provider_flush_store_cache`: choices made without this provider are stale.
        crate::evp::fetch::flush_cache(prov.libctx());
    }
    true
}

/// `ossl_provider_deactivate`: counts a deactivation; false for NULL or after more
/// deactivations than activations.
///
/// # Safety
/// `handle` is NULL or a live provider.
unsafe fn deactivate(handle: *mut OSSL_PROVIDER) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(prov) = (unsafe { OSSL_PROVIDER::get(handle) }) else {
        return false;
    };
    if prov.functions().1.random_bytes.is_some() {
        crate::rand_lib::check_random_provider_on_unload(prov.libctx(), handle);
    }
    let count = count_deactivation(prov);
    if count == 0 {
        // `provider_remove_store_methods`: its algorithms go from the method store.
        prov.state().operations = 0;
        crate::evp::fetch::remove_provider(prov.libctx(), handle);
    }
    count >= 0
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
    let actual = {
        // SAFETY: a live provider's context.
        with_store(unsafe { context(libctx) }, |s| {
            let mut store = s.lock();
            match store.find(&name) {
                Some(existing) => existing,
                None => {
                    store.push(handle);
                    prov.state().in_store = true;
                    if !retain_fallbacks {
                        store.use_fallbacks = false;
                    }
                    handle
                }
            }
        })
    }?;
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
        let handle = provider_new(libctx, name, init, Vec::new());
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
        let added = with_store(unsafe { context(libctx) }, |s| s.lock().infos.push((name, init_fn)));
        c_int::from(added.is_some())
    }
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
        assert!(info.starts_with("3.5.9+rustyssl."), "{info}");
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
