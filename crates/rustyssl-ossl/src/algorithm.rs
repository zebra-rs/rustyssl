//! What the libraries implement, for `openssl list`: the algorithms each provider offers
//! (`EVP_*_do_all_provided`), the legacy name tables, key methods, objects, engines, TLS
//! groups and signature algorithms, and sorting the way `sk_*_sort` does.

use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;

use crate::abi::{OSSL_PARAM, OSSL_PROVIDER};
use crate::ffi;
use crate::params::ParamsRef;
use crate::provider::LibCtx;
use crate::util::{cstring, string_at, take_string};

fn ctx_ptr(libctx: Option<&LibCtx>) -> *mut crate::abi::OSSL_LIB_CTX {
    libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr)
}

/// `OSSL_PROVIDER_get0_name(prov)` (empty for NULL).
fn provider_name(prov: *const OSSL_PROVIDER) -> String {
    if prov.is_null() {
        return String::new();
    }
    // SAFETY: prov is a live provider; the name is owned by it and copied.
    string_at(unsafe { ffi::OSSL_PROVIDER_get0_name(prov) }).unwrap_or_default()
}

unsafe extern "C" fn collect_name(name: *const c_char, data: *mut c_void) {
    // SAFETY: data is the Vec that names() passed, live for the call.
    let names = unsafe { &mut *data.cast::<Vec<String>>() };
    if let Some(n) = string_at(name) {
        names.push(n);
    }
}

/// An algorithm a provider implements, as `EVP_*_do_all_provided` and the `list` command see
/// it. Each holds its own reference.
pub trait Algorithm: Sized {
    /// `*_do_all_provided(libctx, ...)`: every algorithm of the kind, in the order given, each
    /// up-referenced.
    fn provided(libctx: Option<&LibCtx>) -> Vec<Self>;
    /// `*_get0_name`.
    fn name(&self) -> Option<String>;
    /// Whether `*_fetch(libctx, name, propq)` finds it, with no error left behind.
    fn fetchable(&self, libctx: Option<&LibCtx>, propq: Option<&str>) -> bool;
    /// `OSSL_PROVIDER_get0_name(*_get0_provider(alg))`.
    fn provider_name(&self) -> String;
    /// `*_is_a(alg, name)`.
    fn is_a(&self, name: &str) -> bool;
    /// `*_names_do_all(alg, collect_names, names)`: the names, if it succeeded.
    fn names(&self) -> Option<Vec<String>>;
    /// `*_get0_description`.
    fn description(&self) -> Option<String>;
}

macro_rules! algorithm {
    (
        $(#[$m:meta])* $name:ident, $ty:ident,
        do_all = $do_all:ident, get0_name = $get0_name:ident, fetch = $fetch:ident,
        free = $free:ident, up_ref = $up_ref:ident, provider = $provider:ident,
        is_a = $is_a:ident, names = $names:ident, description = $desc:ident,
        tables { $($(#[$tm:meta])* $table:ident = $tfn:ident),* }
        $(, properties = $props:ident)?
    ) => {
        $(#[$m])*
        pub struct $name(core::ptr::NonNull<crate::abi::$ty>);

        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: self holds one reference, released once, here.
                unsafe { ffi::$free(self.0.as_ptr()) };
            }
        }

        impl $name {
            $(
                $(#[$tm])*
                pub fn $table(&self) -> ParamsRef<'_> {
                    // SAFETY: the algorithm is live; the table is owned by it.
                    ParamsRef::from_raw(unsafe { ffi::$tfn(self.0.as_ptr()) })
                }
            )*
            $(
                /// `*_get0_properties`.
                pub fn properties(&self) -> Option<String> {
                    // SAFETY: the algorithm is live; the string is owned by it and copied.
                    string_at(unsafe { ffi::$props(self.0.as_ptr()) })
                }
            )?
        }

        impl Algorithm for $name {
            fn provided(libctx: Option<&LibCtx>) -> Vec<Self> {
                unsafe extern "C" fn collect(alg: *mut crate::abi::$ty, arg: *mut c_void) {
                    // SAFETY: arg is the Vec that provided() passed, live for the call.
                    let out = unsafe { &mut *arg.cast::<Vec<$name>>() };
                    // SAFETY: alg is live for the callback; the new reference is ours.
                    if unsafe { ffi::$up_ref(alg) } == 1
                        && let Some(p) = core::ptr::NonNull::new(alg)
                    {
                        out.push($name(p));
                    }
                }
                let mut out: Vec<Self> = Vec::new();
                // SAFETY: collect gets the Vec back, which outlives the call.
                unsafe { ffi::$do_all(ctx_ptr(libctx), Some(collect), (&raw mut out).cast()) };
                out
            }

            fn name(&self) -> Option<String> {
                // SAFETY: the algorithm is live; the name is owned by it and copied.
                string_at(unsafe { ffi::$get0_name(self.0.as_ptr()) })
            }

            fn fetchable(&self, libctx: Option<&LibCtx>, propq: Option<&str>) -> bool {
                // SAFETY: the algorithm is live; the name is owned by it.
                let name = unsafe { ffi::$get0_name(self.0.as_ptr()) };
                let pq = match propq {
                    Some(p) => match cstring(p) {
                        Some(c) => Some(c),
                        None => return false,
                    },
                    None => None,
                };
                crate::err::set_mark();
                // SAFETY: the context is NULL or live; the strings are valid or NULL.
                let impl_ = unsafe {
                    ffi::$fetch(
                        ctx_ptr(libctx),
                        name,
                        pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
                    )
                };
                crate::err::pop_to_mark();
                if impl_.is_null() {
                    return false;
                }
                // SAFETY: the fetched algorithm is ours, released once.
                unsafe { ffi::$free(impl_) };
                true
            }

            fn provider_name(&self) -> String {
                // SAFETY: the algorithm is live.
                provider_name(unsafe { ffi::$provider(self.0.as_ptr()) })
            }

            fn is_a(&self, name: &str) -> bool {
                let Some(n) = cstring(name) else {
                    return false;
                };
                // SAFETY: the algorithm is live; n is a valid C string.
                unsafe { ffi::$is_a(self.0.as_ptr(), n.as_ptr()) == 1 }
            }

            fn names(&self) -> Option<Vec<String>> {
                let mut names: Vec<String> = Vec::new();
                // SAFETY: the algorithm is live; collect_name gets the Vec back.
                let ok = unsafe {
                    ffi::$names(self.0.as_ptr(), Some(collect_name), (&raw mut names).cast())
                };
                (ok == 1).then_some(names)
            }

            fn description(&self) -> Option<String> {
                // SAFETY: the algorithm is live; the string is owned by it and copied.
                string_at(unsafe { ffi::$desc(self.0.as_ptr()) })
            }
        }
    };
}

algorithm! {
    /// A provided cipher.
    CipherAlg, EVP_CIPHER,
    do_all = EVP_CIPHER_do_all_provided, get0_name = EVP_CIPHER_get0_name,
    fetch = EVP_CIPHER_fetch, free = EVP_CIPHER_free, up_ref = EVP_CIPHER_up_ref,
    provider = EVP_CIPHER_get0_provider, is_a = EVP_CIPHER_is_a,
    names = EVP_CIPHER_names_do_all, description = EVP_CIPHER_get0_description,
    tables {
        gettable_params = EVP_CIPHER_gettable_params,
        gettable_ctx_params = EVP_CIPHER_gettable_ctx_params,
        settable_ctx_params = EVP_CIPHER_settable_ctx_params
    }
}

algorithm! {
    /// A provided digest.
    MdAlg, EVP_MD,
    do_all = EVP_MD_do_all_provided, get0_name = EVP_MD_get0_name,
    fetch = EVP_MD_fetch, free = EVP_MD_free, up_ref = EVP_MD_up_ref,
    provider = EVP_MD_get0_provider, is_a = EVP_MD_is_a,
    names = EVP_MD_names_do_all, description = EVP_MD_get0_description,
    tables {
        gettable_params = EVP_MD_gettable_params,
        gettable_ctx_params = EVP_MD_gettable_ctx_params,
        settable_ctx_params = EVP_MD_settable_ctx_params
    }
}

algorithm! {
    /// A provided MAC.
    MacAlg, EVP_MAC,
    do_all = EVP_MAC_do_all_provided, get0_name = EVP_MAC_get0_name,
    fetch = EVP_MAC_fetch, free = EVP_MAC_free, up_ref = EVP_MAC_up_ref,
    provider = EVP_MAC_get0_provider, is_a = EVP_MAC_is_a,
    names = EVP_MAC_names_do_all, description = EVP_MAC_get0_description,
    tables {
        gettable_params = EVP_MAC_gettable_params,
        gettable_ctx_params = EVP_MAC_gettable_ctx_params,
        settable_ctx_params = EVP_MAC_settable_ctx_params
    }
}

algorithm! {
    /// A provided KDF.
    KdfAlg, EVP_KDF,
    do_all = EVP_KDF_do_all_provided, get0_name = EVP_KDF_get0_name,
    fetch = EVP_KDF_fetch, free = EVP_KDF_free, up_ref = EVP_KDF_up_ref,
    provider = EVP_KDF_get0_provider, is_a = EVP_KDF_is_a,
    names = EVP_KDF_names_do_all, description = EVP_KDF_get0_description,
    tables {
        gettable_params = EVP_KDF_gettable_params,
        gettable_ctx_params = EVP_KDF_gettable_ctx_params,
        settable_ctx_params = EVP_KDF_settable_ctx_params
    }
}

algorithm! {
    /// A provided random generator or seed source.
    RandAlg, EVP_RAND,
    do_all = EVP_RAND_do_all_provided, get0_name = EVP_RAND_get0_name,
    fetch = EVP_RAND_fetch, free = EVP_RAND_free, up_ref = EVP_RAND_up_ref,
    provider = EVP_RAND_get0_provider, is_a = EVP_RAND_is_a,
    names = EVP_RAND_names_do_all, description = EVP_RAND_get0_description,
    tables {
        gettable_params = EVP_RAND_gettable_params,
        gettable_ctx_params = EVP_RAND_gettable_ctx_params,
        settable_ctx_params = EVP_RAND_settable_ctx_params
    }
}

algorithm! {
    /// A provided key manager.
    KeymgmtAlg, EVP_KEYMGMT,
    do_all = EVP_KEYMGMT_do_all_provided, get0_name = EVP_KEYMGMT_get0_name,
    fetch = EVP_KEYMGMT_fetch, free = EVP_KEYMGMT_free, up_ref = EVP_KEYMGMT_up_ref,
    provider = EVP_KEYMGMT_get0_provider, is_a = EVP_KEYMGMT_is_a,
    names = EVP_KEYMGMT_names_do_all, description = EVP_KEYMGMT_get0_description,
    tables {
        gen_settable_params = EVP_KEYMGMT_gen_settable_params,
        settable_params = EVP_KEYMGMT_settable_params,
        gettable_params = EVP_KEYMGMT_gettable_params
    }
}

algorithm! {
    /// A provided symmetric key manager.
    SkeymgmtAlg, EVP_SKEYMGMT,
    do_all = EVP_SKEYMGMT_do_all_provided, get0_name = EVP_SKEYMGMT_get0_name,
    fetch = EVP_SKEYMGMT_fetch, free = EVP_SKEYMGMT_free, up_ref = EVP_SKEYMGMT_up_ref,
    provider = EVP_SKEYMGMT_get0_provider, is_a = EVP_SKEYMGMT_is_a,
    names = EVP_SKEYMGMT_names_do_all, description = EVP_SKEYMGMT_get0_description,
    tables {}
}

algorithm! {
    /// A provided signature algorithm.
    SignatureAlg, EVP_SIGNATURE,
    do_all = EVP_SIGNATURE_do_all_provided, get0_name = EVP_SIGNATURE_get0_name,
    fetch = EVP_SIGNATURE_fetch, free = EVP_SIGNATURE_free, up_ref = EVP_SIGNATURE_up_ref,
    provider = EVP_SIGNATURE_get0_provider, is_a = EVP_SIGNATURE_is_a,
    names = EVP_SIGNATURE_names_do_all, description = EVP_SIGNATURE_get0_description,
    tables {
        settable_ctx_params = EVP_SIGNATURE_settable_ctx_params,
        gettable_ctx_params = EVP_SIGNATURE_gettable_ctx_params
    }
}

algorithm! {
    /// A provided key encapsulation mechanism.
    KemAlg, EVP_KEM,
    do_all = EVP_KEM_do_all_provided, get0_name = EVP_KEM_get0_name,
    fetch = EVP_KEM_fetch, free = EVP_KEM_free, up_ref = EVP_KEM_up_ref,
    provider = EVP_KEM_get0_provider, is_a = EVP_KEM_is_a,
    names = EVP_KEM_names_do_all, description = EVP_KEM_get0_description,
    tables {
        settable_ctx_params = EVP_KEM_settable_ctx_params,
        gettable_ctx_params = EVP_KEM_gettable_ctx_params
    }
}

algorithm! {
    /// A provided asymmetric cipher.
    AsymCipherAlg, EVP_ASYM_CIPHER,
    do_all = EVP_ASYM_CIPHER_do_all_provided, get0_name = EVP_ASYM_CIPHER_get0_name,
    fetch = EVP_ASYM_CIPHER_fetch, free = EVP_ASYM_CIPHER_free, up_ref = EVP_ASYM_CIPHER_up_ref,
    provider = EVP_ASYM_CIPHER_get0_provider, is_a = EVP_ASYM_CIPHER_is_a,
    names = EVP_ASYM_CIPHER_names_do_all, description = EVP_ASYM_CIPHER_get0_description,
    tables {
        settable_ctx_params = EVP_ASYM_CIPHER_settable_ctx_params,
        gettable_ctx_params = EVP_ASYM_CIPHER_gettable_ctx_params
    }
}

algorithm! {
    /// A provided key exchange.
    KeyexchAlg, EVP_KEYEXCH,
    do_all = EVP_KEYEXCH_do_all_provided, get0_name = EVP_KEYEXCH_get0_name,
    fetch = EVP_KEYEXCH_fetch, free = EVP_KEYEXCH_free, up_ref = EVP_KEYEXCH_up_ref,
    provider = EVP_KEYEXCH_get0_provider, is_a = EVP_KEYEXCH_is_a,
    names = EVP_KEYEXCH_names_do_all, description = EVP_KEYEXCH_get0_description,
    tables {
        settable_ctx_params = EVP_KEYEXCH_settable_ctx_params,
        gettable_ctx_params = EVP_KEYEXCH_gettable_ctx_params
    }
}

algorithm! {
    /// A provided encoder.
    EncoderAlg, OSSL_ENCODER,
    do_all = OSSL_ENCODER_do_all_provided, get0_name = OSSL_ENCODER_get0_name,
    fetch = OSSL_ENCODER_fetch, free = OSSL_ENCODER_free, up_ref = OSSL_ENCODER_up_ref,
    provider = OSSL_ENCODER_get0_provider, is_a = OSSL_ENCODER_is_a,
    names = OSSL_ENCODER_names_do_all, description = OSSL_ENCODER_get0_description,
    tables { settable_ctx_params = OSSL_ENCODER_settable_ctx_params },
    properties = OSSL_ENCODER_get0_properties
}

algorithm! {
    /// A provided decoder.
    DecoderAlg, OSSL_DECODER,
    do_all = OSSL_DECODER_do_all_provided, get0_name = OSSL_DECODER_get0_name,
    fetch = OSSL_DECODER_fetch, free = OSSL_DECODER_free, up_ref = OSSL_DECODER_up_ref,
    provider = OSSL_DECODER_get0_provider, is_a = OSSL_DECODER_is_a,
    names = OSSL_DECODER_names_do_all, description = OSSL_DECODER_get0_description,
    tables { settable_ctx_params = OSSL_DECODER_settable_ctx_params },
    properties = OSSL_DECODER_get0_properties
}

/// A provided store loader (which has no single name, so never "fetchable" by it: `list`
/// shows every one).
pub struct StoreLoaderAlg(core::ptr::NonNull<crate::abi::OSSL_STORE_LOADER>);

impl Drop for StoreLoaderAlg {
    fn drop(&mut self) {
        // SAFETY: self holds one reference, released once, here.
        unsafe { ffi::OSSL_STORE_LOADER_free(self.0.as_ptr()) };
    }
}

impl StoreLoaderAlg {
    /// `OSSL_STORE_LOADER_settable_ctx_params`.
    pub fn settable_ctx_params(&self) -> ParamsRef<'_> {
        // SAFETY: the loader is live; the table is owned by it.
        ParamsRef::from_raw(unsafe { ffi::OSSL_STORE_LOADER_settable_ctx_params(self.0.as_ptr()) })
    }
}

impl Algorithm for StoreLoaderAlg {
    fn provided(libctx: Option<&LibCtx>) -> Vec<Self> {
        unsafe extern "C" fn collect(alg: *mut crate::abi::OSSL_STORE_LOADER, arg: *mut c_void) {
            // SAFETY: arg is the Vec that provided() passed, live for the call.
            let out = unsafe { &mut *arg.cast::<Vec<StoreLoaderAlg>>() };
            // SAFETY: alg is live for the callback; the new reference is ours.
            if unsafe { ffi::OSSL_STORE_LOADER_up_ref(alg) } == 1
                && let Some(p) = core::ptr::NonNull::new(alg)
            {
                out.push(StoreLoaderAlg(p));
            }
        }
        let mut out: Vec<Self> = Vec::new();
        // SAFETY: collect gets the Vec back, which outlives the call.
        unsafe {
            ffi::OSSL_STORE_LOADER_do_all_provided(
                ctx_ptr(libctx),
                Some(collect),
                (&raw mut out).cast(),
            )
        };
        out
    }

    fn name(&self) -> Option<String> {
        None
    }

    fn fetchable(&self, _libctx: Option<&LibCtx>, _propq: Option<&str>) -> bool {
        true
    }

    fn provider_name(&self) -> String {
        // SAFETY: the loader is live.
        provider_name(unsafe { ffi::OSSL_STORE_LOADER_get0_provider(self.0.as_ptr()) })
    }

    fn is_a(&self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: the loader is live; n is a valid C string.
        unsafe { ffi::OSSL_STORE_LOADER_is_a(self.0.as_ptr(), n.as_ptr()) == 1 }
    }

    fn names(&self) -> Option<Vec<String>> {
        let mut names: Vec<String> = Vec::new();
        // SAFETY: the loader is live; collect_name gets the Vec back.
        let ok = unsafe {
            ffi::OSSL_STORE_LOADER_names_do_all(
                self.0.as_ptr(),
                Some(collect_name),
                (&raw mut names).cast(),
            )
        };
        (ok == 1).then_some(names)
    }

    fn description(&self) -> Option<String> {
        // SAFETY: the loader is live; the string is owned by it and copied.
        string_at(unsafe { ffi::OSSL_STORE_LOADER_get0_description(self.0.as_ptr()) })
    }
}

// Sorting as `sk_*_sort` does: through the library's own `OPENSSL_sk_sort`, so the order of
// equal keys is the library's.

/// How [`sk_sorted`] compares two keys.
#[derive(Clone, Copy)]
pub enum Order {
    /// `strcmp` of the first key.
    Strcmp,
    /// `OPENSSL_strcasecmp` of the first key.
    Casecmp,
    /// `OPENSSL_strcasecmp` of the first key, then `strcmp` of the second.
    CasecmpThenStrcmp,
}

struct SortNode {
    k1: CString,
    k2: CString,
    index: usize,
}

/// The node behind a comparator's argument (a pointer to the stack's element).
///
/// # Safety
/// `p` points to a stack element that is a live `SortNode` pointer.
unsafe fn node<'a>(p: *const c_void) -> &'a SortNode {
    // SAFETY: the caller's guarantee: p points to a SortNode pointer.
    let n = unsafe { *p.cast::<*const SortNode>() };
    // SAFETY: as above, that pointer is a live SortNode.
    unsafe { &*n }
}

fn strcmp(a: &CString, b: &CString) -> c_int {
    match a.as_bytes().cmp(b.as_bytes()) {
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Greater => 1,
    }
}

fn casecmp(a: &CString, b: &CString) -> c_int {
    // SAFETY: both are valid C strings.
    unsafe { ffi::OPENSSL_strcasecmp(a.as_ptr(), b.as_ptr()) }
}

unsafe extern "C" fn cmp_strcmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack holds SortNode pointers (sk_sorted).
    let a = unsafe { node(a) };
    // SAFETY: as above.
    let b = unsafe { node(b) };
    strcmp(&a.k1, &b.k1)
}

unsafe extern "C" fn cmp_casecmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack holds SortNode pointers (sk_sorted).
    let a = unsafe { node(a) };
    // SAFETY: as above.
    let b = unsafe { node(b) };
    casecmp(&a.k1, &b.k1)
}

unsafe extern "C" fn cmp_casecmp_strcmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: the stack holds SortNode pointers (sk_sorted).
    let a = unsafe { node(a) };
    // SAFETY: as above.
    let b = unsafe { node(b) };
    match casecmp(&a.k1, &b.k1) {
        0 => strcmp(&a.k2, &b.k2),
        r => r,
    }
}

/// `items` in the order `OPENSSL_sk_sort` puts them with the comparator `order` over the
/// keys `key` gives each.
pub fn sk_sorted<T>(items: Vec<T>, order: Order, key: impl Fn(&T) -> (String, String)) -> Vec<T> {
    let nodes: Vec<SortNode> = items
        .iter()
        .enumerate()
        .map(|(index, t)| {
            let (k1, k2) = key(t);
            SortNode {
                k1: CString::new(k1).unwrap_or_default(),
                k2: CString::new(k2).unwrap_or_default(),
                index,
            }
        })
        .collect();
    let cmp: unsafe extern "C" fn(*const c_void, *const c_void) -> c_int = match order {
        Order::Strcmp => cmp_strcmp,
        Order::Casecmp => cmp_casecmp,
        Order::CasecmpThenStrcmp => cmp_casecmp_strcmp,
    };
    // SAFETY: cmp is a valid comparator for the elements pushed below.
    let sk = unsafe { ffi::OPENSSL_sk_new(Some(cmp)) };
    if sk.is_null() {
        return items;
    }
    let mut pushed = true;
    for n in &nodes {
        // SAFETY: the stack is live; each node outlives it (nodes is dropped after it).
        if unsafe { ffi::OPENSSL_sk_push(sk, core::ptr::from_ref(n).cast()) } <= 0 {
            pushed = false;
        }
    }
    let mut order_out: Vec<usize> = Vec::with_capacity(nodes.len());
    if pushed {
        // SAFETY: the stack is live; the comparator reads only the nodes.
        unsafe { ffi::OPENSSL_sk_sort(sk) };
        for i in 0..nodes.len() {
            let Ok(i) = c_int::try_from(i) else {
                break;
            };
            // SAFETY: the stack is live and holds nodes.len() SortNode pointers.
            let p = unsafe { ffi::OPENSSL_sk_value(sk, i) }.cast::<SortNode>();
            if p.is_null() {
                break;
            }
            // SAFETY: p is one of the nodes, still live.
            order_out.push(unsafe { (*p).index });
        }
    }
    // SAFETY: the stack is ours; its elements (the nodes) aren't freed with it.
    unsafe { ffi::OPENSSL_sk_free(sk) };
    if order_out.len() != items.len() {
        return items;
    }
    let mut slots: Vec<Option<T>> = items.into_iter().map(Some).collect();
    order_out
        .into_iter()
        .filter_map(|i| slots.get_mut(i).and_then(Option::take))
        .collect()
}

// The legacy name tables (`EVP_CIPHER_do_all_sorted`, `EVP_MD_do_all_sorted`).

/// One entry of a legacy name table: an algorithm's name, or an alias (`from => to`).
#[derive(Debug)]
pub enum Legacy {
    Algorithm(String),
    Alias(Option<String>, Option<String>),
}

unsafe extern "C" fn legacy_cipher(
    c: *const crate::abi::EVP_CIPHER,
    from: *const c_char,
    to: *const c_char,
    arg: *mut c_void,
) {
    // SAFETY: arg is the Vec that legacy_ciphers passed, live for the call.
    let out = unsafe { &mut *arg.cast::<Vec<Legacy>>() };
    out.push(if c.is_null() {
        Legacy::Alias(string_at(from), string_at(to))
    } else {
        // SAFETY: c is a live cipher for the callback.
        Legacy::Algorithm(string_at(unsafe { ffi::EVP_CIPHER_get0_name(c) }).unwrap_or_default())
    });
}

unsafe extern "C" fn legacy_md(
    m: *const crate::abi::EVP_MD,
    from: *const c_char,
    to: *const c_char,
    arg: *mut c_void,
) {
    // SAFETY: arg is the Vec that legacy_digests passed, live for the call.
    let out = unsafe { &mut *arg.cast::<Vec<Legacy>>() };
    out.push(if m.is_null() {
        Legacy::Alias(string_at(from), string_at(to))
    } else {
        // SAFETY: m is a live digest for the callback.
        Legacy::Algorithm(string_at(unsafe { ffi::EVP_MD_get0_name(m) }).unwrap_or_default())
    });
}

/// `EVP_CIPHER_do_all_sorted`.
pub fn legacy_ciphers() -> Vec<Legacy> {
    let mut out: Vec<Legacy> = Vec::new();
    // SAFETY: the callback gets the Vec back, which outlives the call.
    unsafe { ffi::EVP_CIPHER_do_all_sorted(Some(legacy_cipher), (&raw mut out).cast()) };
    out
}

/// `EVP_MD_do_all_sorted`.
pub fn legacy_digests() -> Vec<Legacy> {
    let mut out: Vec<Legacy> = Vec::new();
    // SAFETY: as above.
    unsafe { ffi::EVP_MD_do_all_sorted(Some(legacy_md), (&raw mut out).cast()) };
    out
}

/// Whether an engine implements digest `name` (`get_digest_from_engine` of `apps/lib/engine.c`
/// finding one).
pub fn digest_from_engine(name: &str) -> bool {
    let Some(n) = cstring(name) else {
        return false;
    };
    // SAFETY: n is a valid C string.
    let nid = unsafe { ffi::OBJ_sn2nid(n.as_ptr()) };
    // SAFETY: any NID is allowed; the result is a functional reference or NULL.
    let e = unsafe { ffi::ENGINE_get_digest_engine(nid) };
    if e.is_null() {
        return false;
    }
    // SAFETY: e is ours to release.
    unsafe { ffi::ENGINE_finish(e) };
    // SAFETY: n is a valid C string.
    !unsafe { ffi::EVP_get_digestbyname(n.as_ptr()) }.is_null()
}

/// Whether an engine implements cipher `name` (`get_cipher_from_engine`).
pub fn cipher_from_engine(name: &str) -> bool {
    let Some(n) = cstring(name) else {
        return false;
    };
    // SAFETY: n is a valid C string.
    let nid = unsafe { ffi::OBJ_sn2nid(n.as_ptr()) };
    // SAFETY: any NID is allowed; the result is a functional reference or NULL.
    let e = unsafe { ffi::ENGINE_get_cipher_engine(nid) };
    if e.is_null() {
        return false;
    }
    // SAFETY: e is ours to release.
    unsafe { ffi::ENGINE_finish(e) };
    // SAFETY: n is a valid C string.
    !unsafe { ffi::EVP_get_cipherbyname(n.as_ptr()) }.is_null()
}

// The legacy key methods (`list -public-key-algorithms`, `-public-key-methods`).

/// One `EVP_PKEY_ASN1_METHOD` (`EVP_PKEY_asn1_get0_info`).
pub struct Asn1Method {
    pub id: c_int,
    pub base_id: c_int,
    pub flags: c_int,
    pub info: Option<String>,
    pub pem_str: Option<String>,
}

/// Every `EVP_PKEY_asn1_get0(i)`, in order.
pub fn asn1_methods() -> Vec<Asn1Method> {
    // SAFETY: no arguments.
    let n = unsafe { ffi::EVP_PKEY_asn1_get_count() };
    let mut out = Vec::new();
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the method is static.
        let ameth = unsafe { ffi::EVP_PKEY_asn1_get0(i) };
        if ameth.is_null() {
            continue;
        }
        let (mut id, mut base_id, mut flags) = (0, 0, 0);
        let (mut info, mut pem): (*const c_char, *const c_char) =
            (core::ptr::null(), core::ptr::null());
        // SAFETY: ameth is a live method; every out-pointer is a valid local.
        unsafe {
            ffi::EVP_PKEY_asn1_get0_info(
                &mut id,
                &mut base_id,
                &mut flags,
                &mut info,
                &mut pem,
                ameth,
            )
        };
        out.push(Asn1Method {
            id,
            base_id,
            flags,
            info: string_at(info),
            pem_str: string_at(pem),
        });
    }
    out
}

/// Every `EVP_PKEY_meth_get0(i)`'s `(id, flags)`, in order.
pub fn pkey_methods() -> Vec<(c_int, c_int)> {
    // SAFETY: no arguments.
    let n = unsafe { ffi::EVP_PKEY_meth_get_count() };
    let mut out = Vec::new();
    for i in 0..n {
        // SAFETY: i is in range; the method is static.
        let pmeth = unsafe { ffi::EVP_PKEY_meth_get0(i) };
        if pmeth.is_null() {
            continue;
        }
        let (mut id, mut flags) = (0, 0);
        // SAFETY: pmeth is a live method; the out-pointers are valid locals.
        unsafe { ffi::EVP_PKEY_meth_get0_info(&mut id, &mut flags, pmeth) };
        out.push((id, flags));
    }
    out
}

/// `OBJ_nid2ln(nid)`.
pub fn nid2ln(nid: c_int) -> Option<String> {
    // SAFETY: any NID is allowed; the result is static or NULL.
    string_at(unsafe { ffi::OBJ_nid2ln(nid) })
}

/// One object of `list -objects`.
pub enum Object {
    /// No such NID (or an error looking it up): skipped.
    Undefined,
    /// An object without an OID.
    NoOid(Option<String>, Option<String>),
    /// Its short name, long name, and OID.
    Oid(Option<String>, Option<String>, String),
    /// `OBJ_obj2txt` failed: the listing stops.
    Error,
}

/// `OBJ_new_nid(0)`: the next NID to be assigned.
pub fn max_nid() -> c_int {
    // SAFETY: 0 only reads the counter.
    unsafe { ffi::OBJ_new_nid(0) }
}

/// What `list_objects` makes of NID `nid` (the error queue cleared first, as it does).
/// `oid_size` is its OID buffer's size, kept from one NID to the next: it grows only when an
/// OID is longer than it, so an OID exactly its size loses its last character, as upstream's
/// does.
pub fn object(nid: c_int, oid_size: &mut usize) -> Object {
    // SAFETY: any NID is allowed; the results are static or NULL.
    let obj = unsafe { ffi::OBJ_nid2obj(nid) };
    // SAFETY: as above.
    let sn = string_at(unsafe { ffi::OBJ_nid2sn(nid) });
    let ln = nid2ln(nid);
    crate::err::clear();
    // SAFETY: obj is NULL or a live object; OBJ_obj2nid accepts NULL.
    if unsafe { ffi::OBJ_obj2nid(obj) } == crate::abi::NID_undef {
        return Object::Undefined;
    }
    // SAFETY: NULL buffer and 0 length ask for the length; obj is live.
    let n = unsafe { ffi::OBJ_obj2txt(core::ptr::null_mut(), 0, obj, 1) };
    if n == 0 {
        return Object::NoOid(sn, ln);
    }
    let Ok(len) = usize::try_from(n) else {
        return Object::Error;
    };
    if len > *oid_size {
        *oid_size = len + 1;
    }
    let mut buf = vec![0u8; *oid_size];
    let size = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
    // SAFETY: buf holds size bytes; obj is live.
    if unsafe { ffi::OBJ_obj2txt(buf.as_mut_ptr().cast(), size, obj, 1) } < 0 {
        return Object::Error;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf.truncate(end);
    Object::Oid(sn, ln, String::from_utf8_lossy(&buf).into_owned())
}

/// The ids of the engines loaded (`ENGINE_get_first`, `ENGINE_get_next`).
pub fn engine_ids() -> Vec<String> {
    let mut out = Vec::new();
    // SAFETY: no arguments; the result is a structural reference or NULL.
    let mut e = unsafe { ffi::ENGINE_get_first() };
    while !e.is_null() {
        // SAFETY: e is live; its id is a static string.
        out.push(string_at(unsafe { ffi::ENGINE_get_id(e) }).unwrap_or_default());
        // SAFETY: e is ours; ENGINE_get_next releases it and returns the next one.
        e = unsafe { ffi::ENGINE_get_next(e) };
    }
    out
}

/// Why [`tls_groups`] failed, as `list_tls_groups` reports it.
#[derive(Debug, PartialEq)]
pub enum GroupsError {
    Memory,
    Version,
    List,
}

/// `list_tls_groups`: the TLS groups implemented for `version` (with every alias when `all`),
/// from a new `SSL_CTX` of `TLS_method()`.
pub fn tls_groups(version: c_int, all: bool) -> Result<Vec<String>, GroupsError> {
    use crate::abi::{
        SSL_CTRL_GET0_IMPLEMENTED_GROUPS, SSL_CTRL_SET_MAX_PROTO_VERSION,
        SSL_CTRL_SET_MIN_PROTO_VERSION,
    };
    // SAFETY: no arguments.
    let groups = unsafe { ffi::OPENSSL_sk_new_null() };
    if groups.is_null() {
        return Err(GroupsError::Memory);
    }
    // SAFETY: no arguments; the method is static.
    let method = unsafe { ffi::TLS_method() };
    // SAFETY: method is a valid method.
    let ctx = unsafe { ffi::SSL_CTX_new(method) };
    let result = (|| {
        if ctx.is_null() {
            return Err(GroupsError::Memory);
        }
        let v = core::ffi::c_long::from(version);
        // SAFETY: the context is live; these commands take no pointer.
        let min = unsafe {
            ffi::SSL_CTX_ctrl(
                ctx,
                SSL_CTRL_SET_MIN_PROTO_VERSION,
                v,
                core::ptr::null_mut(),
            )
        };
        // SAFETY: as above.
        let max = (min != 0)
            && unsafe {
                ffi::SSL_CTX_ctrl(
                    ctx,
                    SSL_CTRL_SET_MAX_PROTO_VERSION,
                    v,
                    core::ptr::null_mut(),
                )
            } != 0;
        if !max {
            return Err(GroupsError::Version);
        }
        // SAFETY: the context and stack are live; the names pushed are static strings.
        let ok = unsafe {
            ffi::SSL_CTX_ctrl(
                ctx,
                SSL_CTRL_GET0_IMPLEMENTED_GROUPS,
                core::ffi::c_long::from(all),
                groups.cast(),
            )
        };
        if ok == 0 {
            return Err(GroupsError::List);
        }
        // SAFETY: the stack is live.
        let n = unsafe { ffi::OPENSSL_sk_num(groups) };
        let mut out = Vec::new();
        for i in 0..n.max(0) {
            // SAFETY: i is in range; each element is a C string.
            out.push(
                string_at(unsafe { ffi::OPENSSL_sk_value(groups, i) }.cast()).unwrap_or_default(),
            );
        }
        Ok(out)
    })();
    // SAFETY: the context is NULL or ours.
    unsafe { ffi::SSL_CTX_free(ctx) };
    // SAFETY: the stack is ours; its strings aren't.
    unsafe { ffi::OPENSSL_sk_free(groups) };
    result
}

/// `SSL_get1_builtin_sigalgs(libctx)`.
pub fn builtin_sigalgs(libctx: Option<&LibCtx>) -> Option<String> {
    // SAFETY: the context is NULL or live; the string is ours to free, which take_string does.
    take_string(unsafe { ffi::SSL_get1_builtin_sigalgs(ctx_ptr(libctx)) })
}

unsafe extern "C" fn sigalg_cap(params: *const OSSL_PARAM, data: *mut c_void) -> c_int {
    // SAFETY: data is the Vec that provider_tls_sigalgs passed, live for the call.
    let out = unsafe { &mut *data.cast::<Vec<String>>() };
    let p = ParamsRef::from_raw(params).locate(
        crate::abi::OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME
            .to_str()
            .unwrap_or_default(),
    );
    if let Some(p) = p
        && c_int::try_from(p.data_type()).ok() == Some(crate::abi::OSSL_PARAM_UTF8_STRING)
    {
        out.push(p.data_string().unwrap_or_default());
    }
    // The built-in providers don't have this capability: never an error.
    1
}

unsafe extern "C" fn sigalg_provider(provider: *mut OSSL_PROVIDER, data: *mut c_void) -> c_int {
    let cap = c"TLS-SIGALG";
    // SAFETY: the provider is live for the callback; data passes through.
    unsafe { ffi::OSSL_PROVIDER_get_capabilities(provider, cap.as_ptr(), Some(sigalg_cap), data) };
    1
}

/// The IANA names of the TLS signature algorithms the loaded providers register (their
/// `TLS-SIGALG` capabilities), and whether `OSSL_PROVIDER_do_all` succeeded.
pub fn provider_tls_sigalgs() -> (bool, Vec<String>) {
    let mut out: Vec<String> = Vec::new();
    // SAFETY: NULL is the default context; the callback gets the Vec back.
    let ok = unsafe {
        ffi::OSSL_PROVIDER_do_all(
            core::ptr::null_mut(),
            Some(sigalg_provider),
            (&raw mut out).cast(),
        )
    } == 1;
    (ok, out)
}

/// A built-in random generator instance (`RAND_get0_primary(NULL)`, ...), borrowed.
pub struct RandInstance(*mut crate::abi::EVP_RAND_CTX);

/// Which instance.
#[derive(Clone, Copy)]
pub enum Instance {
    Primary,
    Public,
    Private,
}

impl RandInstance {
    /// `RAND_get0_primary(NULL)` and the others (`None` when there is none).
    pub fn get(which: Instance) -> Option<Self> {
        let none = core::ptr::null_mut();
        let p = match which {
            // SAFETY: NULL is the default context; the instance stays owned by it.
            Instance::Primary => unsafe { ffi::RAND_get0_primary(none) },
            // SAFETY: as above.
            Instance::Public => unsafe { ffi::RAND_get0_public(none) },
            // SAFETY: as above.
            Instance::Private => unsafe { ffi::RAND_get0_private(none) },
        };
        (!p.is_null()).then_some(RandInstance(p))
    }

    fn rand(&self) -> *mut crate::abi::EVP_RAND {
        // SAFETY: the instance is live.
        unsafe { ffi::EVP_RAND_CTX_get0_rand(self.0) }
    }

    /// `EVP_RAND_get0_name(EVP_RAND_CTX_get0_rand(ctx))`.
    pub fn name(&self) -> String {
        // SAFETY: the generator is live; its name is owned by it and copied.
        string_at(unsafe { ffi::EVP_RAND_get0_name(self.rand()) }).unwrap_or_default()
    }

    /// The generator's provider's name.
    pub fn provider_name(&self) -> String {
        // SAFETY: the generator is live.
        provider_name(unsafe { ffi::EVP_RAND_get0_provider(self.rand()) })
    }

    /// `EVP_RAND_get_state`.
    pub fn state(&self) -> c_int {
        // SAFETY: the instance is live.
        unsafe { ffi::EVP_RAND_get_state(self.0) }
    }

    /// `EVP_RAND_gettable_ctx_params(EVP_RAND_CTX_get0_rand(ctx))`.
    pub fn gettable_ctx_params(&self) -> ParamsRef<'_> {
        // SAFETY: the generator is live; the table is owned by it.
        ParamsRef::from_raw(unsafe { ffi::EVP_RAND_gettable_ctx_params(self.rand()) })
    }

    /// `EVP_RAND_CTX_get_params(ctx, params)`.
    pub fn get_params(&self, params: &mut crate::params::Query) -> bool {
        // SAFETY: the instance is live; the array is terminated with its own storage.
        unsafe { ffi::EVP_RAND_CTX_get_params(self.0, params.as_mut_ptr()) == 1 }
    }
}
