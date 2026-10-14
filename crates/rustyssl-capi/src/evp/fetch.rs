//! Fetching algorithms from providers (`crypto/evp/evp_fetch.c`, `crypto/core_fetch.c`,
//! `crypto/core_algorithm.c`): each library context's names ([`Namemap`]) and method store,
//! filled from its active providers' algorithms an operation at a time, and the choice of an
//! implementation for a name and property query.
//!
//! As in OpenSSL:
//! - A fetch looks in the cache, then has every active provider (the fallback activated, the
//!   configuration loaded for the default context) offer its algorithms for the operation,
//!   once per provider while it stays active (`operation_bits`). Each algorithm's names are
//!   numbered, its method made, and stored under its first name with its property
//!   definition; a provider that says not to store them puts them in a store for this fetch
//!   only.
//! - The choice parses the query in the context (unknown values stay unknown), adds the
//!   context's default properties, and takes the best match. It's cached under the query text.
//! - A failure raises `ERR_R_UNSUPPORTED` (or `ERR_R_FETCH_FAILED` if a method couldn't be made)
//!   with OpenSSL's text naming the context, the algorithm, its number, and the properties.
//!
//! Providers' functions and method constructors run without a lock held.

use core::ffi::{CStr, c_int, c_void};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    CRYPTO_R_BAD_ALGORITHM_NAME, CRYPTO_R_CONFLICTING_NAMES, ERR_LIB_CRYPTO, ERR_LIB_EVP,
    ERR_R_FETCH_FAILED, ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_UNSUPPORTED, OPENSSL_INIT_LOAD_CONFIG,
    OSSL_ALGORITHM, OSSL_LIB_CTX, OSSL_PROVIDER,
};
use rustyssl_crypto::method_store::MethodStore;
use rustyssl_crypto::namemap::{self, Namemap};
use rustyssl_crypto::property::{self, List};

use crate::provider::{self, Ptr};
use crate::{err, init, libctx};

/// What a kind of method (`EVP_MD`, `EVP_CIPHER`, ...) brings to fetching.
pub(crate) struct Kind {
    /// The operation (`OSSL_OP_DIGEST`, ...).
    pub(crate) operation: c_int,
    /// `method_from_algorithm`: a method with one reference, or NULL (with an error).
    pub(crate) from_algorithm: unsafe fn(u32, &OSSL_ALGORITHM, *mut OSSL_PROVIDER) -> *mut c_void,
    /// Adds a reference.
    pub(crate) up_ref: unsafe fn(*mut c_void),
    /// Drops a reference.
    pub(crate) free: unsafe fn(*mut c_void),
}

/// A method in a store or cache, holding a reference.
pub(crate) struct Method {
    ptr: Ptr<c_void>,
    kind: &'static Kind,
}

impl Method {
    /// The method, with a new reference for the caller.
    pub(crate) fn into_raw(self) -> *mut c_void {
        let p = self.ptr.0;
        core::mem::forget(self);
        p
    }

    /// The method (no reference is taken).
    pub(crate) fn as_ptr(&self) -> *mut c_void {
        self.ptr.0
    }
}

impl Clone for Method {
    fn clone(&self) -> Self {
        // SAFETY: the method is live (this holds a reference).
        unsafe { (self.kind.up_ref)(self.ptr.0) };
        Self {
            ptr: self.ptr,
            kind: self.kind,
        }
    }
}

impl Drop for Method {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, given up.
        unsafe { (self.kind.free)(self.ptr.0) };
    }
}

/// A provider in a store, by address.
type ProvKey = usize;

/// A store of methods.
type Methods = MethodStore<Method, ProvKey>;

/// What construction yields: the choice and its provider, the temporary store, and whether a
/// method couldn't be made.
type Constructed = (Option<(Method, *mut OSSL_PROVIDER)>, Option<Methods>, bool);

fn key(prov: *const OSSL_PROVIDER) -> ProvKey {
    prov.addr()
}

/// A context's names and EVP method store.
#[derive(Default)]
pub(crate) struct State {
    pub(crate) names: Namemap,
    store: MethodStore<Method, ProvKey>,
    /// The providers of the stored methods, by key, for the choice's provider.
    providers: Vec<(ProvKey, Ptr<OSSL_PROVIDER>)>,
    /// The names as C strings the `*_names_do_all` callbacks get, kept as long as the context
    /// (as OpenSSL's name map keeps its strings), so a callback may keep the pointers.
    c_names: std::collections::HashMap<Vec<u8>, Box<core::ffi::CStr>>,
}

/// A context's names and EVP method store, behind their lock.
#[derive(Default)]
pub(crate) struct Store(Mutex<State>);

impl Store {
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Forgets the cached choices.
    pub(crate) fn flush(&self) {
        self.lock().store.flush_all();
    }
}

/// `evp_method_id`: the store's number for a name's method of an operation.
fn method_id(name_id: u32, operation: c_int) -> u32 {
    let Ok(op) = u32::try_from(operation) else {
        return 0;
    };
    if name_id == 0 || name_id > (1 << 23) - 1 || op == 0 || op > 255 {
        return 0;
    }
    (name_id << 8) | op
}

/// The first name of a list (`"SHA2-256:SHA-256"`).
fn first_name(names: &[u8]) -> &[u8] {
    names.split(|&c| c == b':').next().unwrap_or(names)
}

/// `provider_flush_store_cache` and `evp_method_store_cache_flush`: forgets the cached choices
/// of `libctx`'s store.
pub(crate) fn flush_cache(libctx: *mut OSSL_LIB_CTX) {
    // SAFETY: a provider's or the caller's context, NULL or live.
    if let Some(ctx) = unsafe { libctx::resolve(libctx) } {
        ctx.evp.lock().store.flush_all();
    }
}

/// `evp_method_store_remove_all_provided`: drops the provider's methods from `libctx`'s store.
pub(crate) fn remove_provider(libctx: *mut OSSL_LIB_CTX, prov: *const OSSL_PROVIDER) {
    // SAFETY: a provider's context, NULL or live.
    if let Some(ctx) = unsafe { libctx::resolve(libctx) } {
        let mut state = ctx.evp.lock();
        state.store.remove_provider(key(prov));
        state.providers.retain(|(k, _)| *k != key(prov));
    }
}

/// `ossl_lib_ctx_get_descriptor`: how errors name the context.
fn descriptor(libctx: *mut OSSL_LIB_CTX, ctx: &libctx::LibCtx) -> &'static str {
    if libctx::is_global(ctx) {
        "Global default library context"
    } else if libctx.is_null() || libctx == libctx::current() {
        "Thread-local default library context"
    } else {
        "Non-default library context"
    }
}

/// `ossl_method_store_fetch`'s query: the query parsed in the context (raising its errors;
/// one that fails counts as none) with the context's default properties added.
fn query(ctx: &libctx::LibCtx, propq: &[u8]) -> Option<List> {
    let mut properties = ctx.properties.lock();
    let parsed = property::parse_query(&mut properties.strings, propq, false);
    drop(properties);
    crate::property::raise_parse_errors(&parsed.errors, "ossl_method_store_fetch");
    let properties = ctx.properties.lock();
    match (parsed.list, properties.global.as_ref()) {
        (Some(q), Some(g)) => Some(property::merge(&q, g)),
        (Some(q), None) => Some(q),
        (None, g) => g.cloned(),
    }
}

/// The parsed property definition `text`, cached per context (`ossl_prop_defn_get`/`_set`).
fn definition(ctx: &libctx::LibCtx, text: &[u8]) -> Option<List> {
    let mut properties = ctx.properties.lock();
    if let Some(l) = properties.definitions.get(text) {
        return Some(l.clone());
    }
    let parsed = property::parse_definition(&mut properties.strings, text);
    if let Some(l) = &parsed.list {
        properties.definitions.insert(text.to_vec(), l.clone());
    }
    drop(properties);
    crate::property::raise_parse_errors(&parsed.errors, "ossl_method_store_add");
    parsed.list
}

/// What a fetch asks for.
struct Request<'a> {
    kind: &'static Kind,
    name: Option<&'a CStr>,
    name_id: u32,
    propq: &'a [u8],
}

/// `get_evp_method_from_store` on the global store or a temporary one: the choice for the
/// request, with its provider.
fn choose(
    ctx: &libctx::LibCtx,
    libctx: *mut OSSL_LIB_CTX,
    store: Option<&MethodStore<Method, ProvKey>>,
    req: &Request<'_>,
    prov: Option<*mut OSSL_PROVIDER>,
) -> Option<(Method, *mut OSSL_PROVIDER)> {
    let state = ctx.evp.lock();
    let name_id = match (req.name_id, req.name) {
        (0, Some(n)) => state.names.number(first_name(n.to_bytes())),
        (id, _) => id,
    };
    let id = method_id(name_id, req.kind.operation);
    drop(state);
    if id == 0 {
        return None;
    }
    if libctx.is_null() || libctx == libctx::current() {
        let opts = u64::try_from(OPENSSL_INIT_LOAD_CONFIG).unwrap_or(0);
        // SAFETY: no settings.
        if unsafe { init::OPENSSL_init_crypto(opts, core::ptr::null()) } != 1 {
            return None;
        }
    }
    // OpenSSL looks the algorithm up before it parses the query: a store without it raises
    // nothing.
    {
        let state = ctx.evp.lock();
        if !store.unwrap_or(&state.store).contains(id) {
            return None;
        }
    }
    let q = query(ctx, req.propq);
    let state = ctx.evp.lock();
    let store = store.unwrap_or(&state.store);
    let (method, k) = store.fetch(id, q.as_ref(), prov.map(|p| key(p)))?;
    let found = state
        .providers
        .iter()
        .find(|(pk, _)| *pk == k)
        .map_or(core::ptr::null_mut(), |(_, p)| p.0);
    Some((method, found))
}

/// `ossl_method_construct`: has the providers offer their algorithms for the operation, storing
/// the methods, then chooses. Returns the choice, the temporary store (for `do_all`), and
/// whether a method couldn't be made.
fn construct(
    ctx: &libctx::LibCtx,
    libctx: *mut OSSL_LIB_CTX,
    req: &Request<'_>,
    prov: Option<*mut OSSL_PROVIDER>,
) -> Constructed {
    let op = req.kind.operation;
    let held = match prov {
        Some(p) => {
            // SAFETY: the caller's live provider; held for the work below.
            if !unsafe { <OSSL_PROVIDER as crate::handle::Handle>::up_ref(p) } {
                return (None, None, false);
            }
            vec![p]
        }
        // SAFETY: the caller's context.
        None => unsafe { provider::activated(libctx) },
    };
    let mut tmp: Option<MethodStore<Method, ProvKey>> = None;
    let mut construct_error = false;
    for &p in &held {
        // SAFETY: held, so live.
        let (map, no_store) = unsafe { provider::query_operation(p, op) };
        // SAFETY: as above.
        let skip = !no_store && unsafe { provider::operation_stored(p, op) };
        if !skip {
            let mut at = map;
            // SAFETY: the provider's table, ended by an algorithm without names.
            while let Some(algo) = unsafe { at.as_ref() } {
                if algo.algorithm_names.is_null() {
                    break;
                }
                // SAFETY: the provider's guarantee for its table.
                if !unsafe {
                    add_algorithm(
                        ctx,
                        req.kind,
                        algo,
                        p,
                        no_store.then(|| tmp.get_or_insert_with(MethodStore::default)),
                    )
                } {
                    construct_error = true;
                }
                at = at.wrapping_add(1);
            }
            if !no_store {
                // SAFETY: as above.
                unsafe { provider::set_operation_stored(p, op) };
            }
        }
        // SAFETY: as above, the provider's own table back.
        unsafe { provider::unquery_operation(p, op, map) };
    }
    match prov {
        Some(p) => {
            // SAFETY: held above.
            unsafe { <OSSL_PROVIDER as crate::handle::Handle>::free(p) };
        }
        None => provider::release(held),
    }
    let found = tmp
        .as_ref()
        .and_then(|t| choose(ctx, libctx, Some(t), req, prov))
        .or_else(|| choose(ctx, libctx, None, req, prov));
    (found, tmp, construct_error)
}

/// `construct_evp_method` and `put_evp_method_in_store` for one algorithm. False if its method
/// couldn't be made (names that don't fit aren't such a failure).
///
/// # Safety
/// `algo`'s strings and table are the provider's, valid; `prov` is a live provider.
unsafe fn add_algorithm(
    ctx: &libctx::LibCtx,
    kind: &'static Kind,
    algo: &OSSL_ALGORITHM,
    prov: *mut OSSL_PROVIDER,
    tmp: Option<&mut MethodStore<Method, ProvKey>>,
) -> bool {
    // SAFETY: the caller's guarantee.
    let names = unsafe { CStr::from_ptr(algo.algorithm_names) }.to_bytes();
    let added = ctx.evp.lock().names.add_names(0, names, b':');
    let name_id = match added {
        Ok(0) => return true,
        Ok(n) => n,
        Err(namemap::Error::BadAlgorithmName) => {
            err::raise(
                ERR_LIB_CRYPTO,
                CRYPTO_R_BAD_ALGORITHM_NAME,
                "ossl_namemap_add_names",
            );
            return true;
        }
        Err(namemap::Error::ConflictingNames(data)) => {
            err::raise_with_bytes(
                ERR_LIB_CRYPTO,
                CRYPTO_R_CONFLICTING_NAMES,
                "ossl_namemap_add_names",
                &data,
            );
            return true;
        }
    };
    // An algorithm of the default provider's that comes with a later step: its names are
    // registered, as above, but there's no method to make.
    if provider::tables::is_pending(algo.implementation) {
        return true;
    }
    // SAFETY: the caller's guarantee.
    let made = unsafe { (kind.from_algorithm)(name_id, algo, prov) };
    if made.is_null() {
        return false;
    }
    let method = Method {
        ptr: Ptr(made),
        kind,
    };
    let definition_text = if algo.property_definition.is_null() {
        &b""[..]
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { CStr::from_ptr(algo.property_definition) }.to_bytes()
    };
    let Some(properties) = definition(ctx, definition_text) else {
        return true;
    };
    let mut state = ctx.evp.lock();
    let id = method_id(state.names.number(first_name(names)), kind.operation);
    if !state.providers.iter().any(|(k, _)| *k == key(prov)) {
        state.providers.push((key(prov), Ptr(prov)));
    }
    let store = match tmp {
        Some(t) => t,
        None => &mut state.store,
    };
    store.add(key(prov), id, definition_text, properties, method);
    true
}

/// `inner_evp_generic_fetch`: the method `name` of the kind, for the properties, from `prov` if
/// given, with a reference for the caller; or, with no name, every method of the kind (the
/// temporary store's then the context's), for `do_all`.
///
/// # Safety
/// `libctx` is NULL or a live library context; `prov` is NULL or a live provider.
unsafe fn inner_fetch(
    libctx: *mut OSSL_LIB_CTX,
    kind: &'static Kind,
    name: Option<&CStr>,
    properties: Option<&CStr>,
    prov: Option<*mut OSSL_PROVIDER>,
) -> (Option<Method>, Option<MethodStore<Method, ProvKey>>) {
    // SAFETY: the caller's guarantee.
    let Some(ctx) = (unsafe { libctx::resolve(libctx) }) else {
        err::raise(
            ERR_LIB_EVP,
            ERR_R_PASSED_INVALID_ARGUMENT,
            "inner_evp_generic_fetch",
        );
        return (None, None);
    };
    let propq = properties.map_or(&b""[..], CStr::to_bytes);
    prefill(&ctx);
    let mut name_id = name.map_or(0, |n| ctx.evp.lock().names.number(n.to_bytes()));
    let id = method_id(name_id, kind.operation);
    let mut unsupported = name_id == 0;
    let cached = if id == 0 {
        None
    } else {
        ctx.evp
            .lock()
            .store
            .cache_get(id, propq, prov.map(|p| key(p)))
    };
    let mut tmp = None;
    let method = match cached {
        Some(m) => Some(m),
        None => {
            let req = Request {
                kind,
                name,
                name_id,
                propq,
            };
            let (found, t, construct_error) = construct(&ctx, libctx, &req, prov);
            tmp = t;
            unsupported = !construct_error;
            match found {
                None => None,
                Some((m, found_prov)) => {
                    let mut state = ctx.evp.lock();
                    let id_now = if name_id == 0 {
                        name.map_or(0, |n| state.names.number(n.to_bytes()))
                    } else {
                        name_id
                    };
                    if id_now == 0 {
                        drop(state);
                        let text = name.map_or_else(
                            || "<NULL>".to_owned(),
                            |n| n.to_string_lossy().into_owned(),
                        );
                        err::raise_with_text(
                            ERR_LIB_EVP,
                            ERR_R_FETCH_FAILED,
                            "inner_evp_generic_fetch",
                            &format!("Algorithm {text} cannot be found"),
                        );
                        drop(m);
                        None
                    } else {
                        name_id = id_now;
                        let id = method_id(name_id, kind.operation);
                        if id != 0 {
                            state
                                .store
                                .cache_set(id, propq, key(found_prov), Some(m.clone()));
                        }
                        Some(m)
                    }
                }
            }
        }
    };
    if (name_id != 0 || name.is_some()) && method.is_none() {
        let code = if unsupported {
            ERR_R_UNSUPPORTED
        } else {
            ERR_R_FETCH_FAILED
        };
        let shown = match name {
            Some(n) => n.to_string_lossy().into_owned(),
            None => ctx.evp.lock().names.name(name_id, 0).map_or_else(
                || "<null>".to_owned(),
                |n| String::from_utf8_lossy(n).into_owned(),
            ),
        };
        let props =
            properties.map_or_else(|| "<null>".to_owned(), |p| p.to_string_lossy().into_owned());
        let text = format!(
            "{}, Algorithm ({shown} : {name_id}), Properties ({props})",
            descriptor(libctx, &ctx)
        );
        err::raise_with_text(ERR_LIB_EVP, code, "inner_evp_generic_fetch", &text);
    }
    (method, tmp)
}

/// `evp_generic_fetch`: the method `name` of the kind, with a reference, or NULL.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn fetch(
    libctx: *mut OSSL_LIB_CTX,
    kind: &'static Kind,
    name: Option<&CStr>,
    properties: Option<&CStr>,
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let (method, _) = unsafe { inner_fetch(libctx, kind, name, properties, None) };
    method.map_or(core::ptr::null_mut(), Method::into_raw)
}

/// `evp_generic_fetch_from_prov`: the method `name` of the kind from `prov` only (in its
/// library context), with a reference, or NULL.
///
/// # Safety
/// `prov` is a live provider.
pub(crate) unsafe fn fetch_from_prov(
    prov: *mut OSSL_PROVIDER,
    kind: &'static Kind,
    name: Option<&CStr>,
    properties: Option<&CStr>,
) -> *mut c_void {
    // SAFETY: the caller's live provider.
    let libctx = unsafe { provider::libctx_of(prov) };
    // SAFETY: the provider's context.
    let (method, _) = unsafe { inner_fetch(libctx, kind, name, properties, Some(prov)) };
    method.map_or(core::ptr::null_mut(), Method::into_raw)
}

/// `evp_generic_do_all`: every method of the kind the active providers offer (the temporary
/// store's first), each with a reference while the caller has it.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn all(libctx: *mut OSSL_LIB_CTX, kind: &'static Kind) -> Vec<Method> {
    // SAFETY: the caller's guarantee.
    let (_, tmp) = unsafe { inner_fetch(libctx, kind, None, None, None) };
    let mut out = Vec::new();
    let mut take = |all: Vec<(u32, Method)>| {
        out.extend(
            all.into_iter()
                .filter(|(id, _)| i64::from(id & 0xff) == i64::from(kind.operation))
                .map(|(_, m)| m),
        );
    };
    if let Some(t) = &tmp {
        take(t.all());
    }
    // SAFETY: the caller's guarantee.
    if let Some(ctx) = unsafe { libctx::resolve(libctx) } {
        let all = ctx.evp.lock().store.all();
        take(all);
    }
    out
}

/// `ossl_namemap_stored`'s pre-filling: an empty name map starts with the legacy ciphers' and
/// then digests' names (each type's short and long names and its OID), as OpenSSL's does after
/// `OPENSSL_INIT_ADD_ALL_CIPHERS` and `_DIGESTS`, then the key types' of the built-in ASN.1
/// methods (an alias's base type's names first, and the PEM name last).
pub(crate) fn prefill(ctx: &libctx::LibCtx) {
    if !ctx.evp.lock().names.is_empty() {
        return;
    }
    // Gathered without the lock: adding the ciphers and digests runs the library's
    // initialization. Both are added before either is walked, as `ossl_namemap_stored` does
    // (the walk's order depends on everything in the name table); the ciphers' names come
    // first.
    let opts = u64::try_from(
        rustyssl_abi::OPENSSL_INIT_ADD_ALL_CIPHERS | rustyssl_abi::OPENSSL_INIT_ADD_ALL_DIGESTS,
    )
    .unwrap_or(0);
    // SAFETY: no settings.
    unsafe { init::OPENSSL_init_crypto(opts, core::ptr::null()) };
    let mut nids = super::legacy_cipher::cipher_types();
    nids.extend(super::legacy_md::md_nids());
    let mut state = ctx.evp.lock();
    if !state.names.is_empty() {
        return;
    }
    for nid in nids {
        add_legacy_names(&mut state.names, 0, 0, nid, None);
    }
    for (base, nid, pem) in super::pkey::ameth::prefill_entries() {
        add_legacy_names(&mut state.names, 0, base, nid, pem);
    }
}

/// `get_legacy_evp_names`: adds the names of `base` (short and long) and of `nid` (short, long,
/// and its OID), then `pem`, as one algorithm starting from number `num`. Returns the number.
fn add_legacy_names(
    names: &mut Namemap,
    mut num: u32,
    base: c_int,
    nid: c_int,
    pem: Option<&[u8]>,
) -> u32 {
    if let Some(obj) = rustyssl_asn1::objects::object(base).filter(|_| base != 0) {
        num = names.add_name(num, obj.short_name.as_bytes());
        num = names.add_name(num, obj.long_name.as_bytes());
    }
    if let Some(obj) = rustyssl_asn1::objects::object(nid).filter(|_| nid != 0) {
        num = names.add_name(num, obj.short_name.as_bytes());
        num = names.add_name(num, obj.long_name.as_bytes());
        if !obj.der.is_empty() {
            let text = rustyssl_asn1::oid::decode_text(obj.der);
            if text.complete && !text.text.is_empty() {
                num = names.add_name(num, &text.text);
            }
        }
    }
    if let Some(p) = pem {
        num = names.add_name(num, p);
    }
    num
}

/// The names of `name_id` in `prov`'s context, in the order they were added.
pub(crate) fn names_of(prov: *const OSSL_PROVIDER, name_id: u32) -> Vec<Vec<u8>> {
    // SAFETY: a live provider's context.
    let libctx = unsafe { provider::libctx_of(prov) };
    // SAFETY: as above.
    unsafe { libctx::resolve(libctx) }.map_or_else(Vec::new, |ctx| {
        prefill(&ctx);
        ctx.evp.lock().names.names(name_id).to_vec()
    })
}

/// The names of `name_id` in `prov`'s context as C strings that stay valid while the context
/// lives (`ossl_namemap_doall_names`'s strings).
pub(crate) fn c_names_of(
    prov: *const OSSL_PROVIDER,
    name_id: u32,
) -> Vec<*const core::ffi::c_char> {
    // SAFETY: a live provider's context.
    let libctx = unsafe { provider::libctx_of(prov) };
    // SAFETY: as above.
    unsafe { libctx::resolve(libctx) }.map_or_else(Vec::new, |ctx| {
        prefill(&ctx);
        let mut state = ctx.evp.lock();
        let names = state.names.names(name_id).to_vec();
        names
            .into_iter()
            .filter_map(|n| {
                if let Some(c) = state.c_names.get(&n) {
                    return Some(c.as_ptr());
                }
                let c = std::ffi::CString::new(n.clone()).ok()?.into_boxed_c_str();
                let p = c.as_ptr();
                state.c_names.insert(n, c);
                Some(p)
            })
            .collect()
    })
}

/// The number of `name` in `prov`'s context (`ossl_namemap_name2num`).
pub(crate) fn number_in(prov: *const OSSL_PROVIDER, name: &[u8]) -> u32 {
    // SAFETY: a live provider's context.
    let libctx = unsafe { provider::libctx_of(prov) };
    // SAFETY: as above.
    unsafe { libctx::resolve(libctx) }.map_or(0, |ctx| {
        prefill(&ctx);
        ctx.evp.lock().names.number(name)
    })
}

/// The number of `name` in `libctx` (the default for NULL), or 0.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn number_in_libctx(libctx: *mut OSSL_LIB_CTX, name: &[u8]) -> u32 {
    // SAFETY: the caller's guarantee.
    unsafe { libctx::resolve(libctx) }.map_or(0, |ctx| {
        prefill(&ctx);
        ctx.evp.lock().names.number(name)
    })
}

/// The names of `name_id` in `libctx` (the default for NULL), in the order they were added.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn names_in_libctx(libctx: *mut OSSL_LIB_CTX, name_id: u32) -> Vec<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    unsafe { libctx::resolve(libctx) }.map_or_else(Vec::new, |ctx| {
        prefill(&ctx);
        ctx.evp.lock().names.names(name_id).to_vec()
    })
}
