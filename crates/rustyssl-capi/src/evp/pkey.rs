//! Keys (`EVP_PKEY(3)`, `EVP_PKEY_new(3)`, `EVP_PKEY_is_a(3)`, ...; `p_lib.c`, `keymgmt_lib.c`):
//! an `EVP_PKEY` holding a provider's key data through its key manager, or typed by an ASN.1
//! method (`EVP_PKEY_set_type`) and holding the method's legacy data (`EVP_PKEY_assign`).
//!
//! As in OpenSSL:
//! - A provided key's type is the ASN.1 method's that one of its key manager's names is the PEM
//!   name of, else `EVP_PKEY_KEYMGMT`; key generation gives its key the context's legacy type.
//! - Its bits, security bits, and maximum size are asked of the key manager when the data is
//!   assigned, and cached.
//! - Using a key with another provider's key manager exports it to that one, and the copy is
//!   kept in the key's operation cache until the key's parameters are set.
//! - Comparisons give 1 (equal), 0 (different), -1 (different types), or -2 (can't compare).
//!
//! - A key typed by an ASN.1 method asks the method (an application's, `EVP_PKEY_asn1_new(3)`)
//!   for its sizes, comparisons, parameters, raw keys, and default digest, and the method's
//!   `pkey_free` frees its data, whenever the key is cleared, retyped, or freed.
//!
//! The built-in key types' legacy data comes with the key types: RSA and RSA-PSS have it (an
//! `RSA`), EC and SM2 (an `EC_KEY`), and X25519, X448, ED25519, and ED448 (an ECX key); until
//! the others do a key can't be given theirs, and their built-in methods' functions abort
//! (AGENTS.md rule 10).
//! Functions given a NULL key fail here where the reference would crash (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;
use core::sync::atomic::{AtomicI32, Ordering};
use std::cell::UnsafeCell;
use std::ffi::CString;
use std::sync::atomic::AtomicPtr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ASN1_PKEY_CTRL_DEFAULT_MD_NID, CRYPTO_EX_DATA, CRYPTO_EX_INDEX_EVP_PKEY, ENGINE, ERR_LIB_EVP,
    ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER, EVP_KEYMGMT, EVP_PKEY,
    EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_KEYMGMT, EVP_PKEY_NONE, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS,
    EVP_R_DIFFERENT_KEY_TYPES, EVP_R_DIFFERENT_PARAMETERS, EVP_R_EXPECTING_A_POLY1305_KEY,
    EVP_R_EXPECTING_A_SIPHASH_KEY, EVP_R_EXPECTING_AN_HMAC_KEY, EVP_R_MISSING_PARAMETERS,
    EVP_R_UNKNOWN_BITS, EVP_R_UNKNOWN_MAX_SIZE, EVP_R_UNKNOWN_SECURITY_BITS,
    EVP_R_UNSUPPORTED_ALGORITHM, EVP_R_UNSUPPORTED_KEY_TYPE, NID_undef, OSSL_CALLBACK,
    OSSL_KEYMGMT_SELECT_ALL, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PKEY_PARAM_BITS,
    OSSL_PKEY_PARAM_DEFAULT_DIGEST, OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PKEY_PARAM_MAX_SIZE,
    OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PROVIDER, SN_undef,
};

use super::keymgmt::{self, Keymgmt};
use crate::err;
use crate::ex_data::{
    CRYPTO_dup_ex_data, CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data,
    CRYPTO_set_ex_data,
};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};
use crate::objects::OBJ_nid2sn;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_modified, end,
};
use crate::provider::Ptr;

pub(crate) mod ameth;
pub(crate) mod attrs;
pub(crate) mod d2i;
pub(crate) mod dh;
pub(crate) mod dsa;
pub(crate) mod ec;
pub(crate) mod ecx;
pub(crate) mod i2d;
pub(crate) mod params;
pub(crate) mod print;
pub(crate) mod raw;
pub(crate) mod rsa;

/// `OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS`, which `p_lib.c` calls `SELECT_PARAMETERS`.
const SELECT_PARAMETERS: c_int = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS as c_int;

/// A key manager's key data, freed by it when the last holder lets go.
pub(crate) struct KeyData {
    keymgmt: keymgmt::Ref,
    ptr: Ptr<c_void>,
}

impl KeyData {
    /// Takes over `ptr`, key data of `keymgmt`; `None` for NULL.
    pub(crate) fn adopt(keymgmt: keymgmt::Ref, ptr: *mut c_void) -> Option<Arc<Self>> {
        (!ptr.is_null()).then(|| {
            Arc::new(Self {
                keymgmt,
                ptr: Ptr(ptr),
            })
        })
    }

    /// The provider's pointer.
    pub(crate) fn ptr(&self) -> *mut c_void {
        self.ptr.0
    }
}

impl Drop for KeyData {
    fn drop(&mut self) {
        // SAFETY: the key manager's own data, freed once.
        unsafe { self.keymgmt.get().freedata(self.ptr.0) };
    }
}

/// An export of the key to another key manager (`OP_CACHE_ELEM`).
struct OpCache {
    keymgmt: keymgmt::Ref,
    keydata: Arc<KeyData>,
    selection: c_int,
}

/// What `EVP_PKEY` handles point to.
pub(crate) struct Pkey {
    references: AtomicI32,
    state: Mutex<State>,
    ex_data: ExData,
    /// The key's own handle, which the ASN.1 method's functions are given.
    this: AtomicPtr<EVP_PKEY>,
    /// The key's attributes (`EVP_PKEY_add1_attr` ...), as PKCS#8 and PKCS#12 carry them.
    attributes: AtomicPtr<rustyssl_abi::stack_st_X509_ATTRIBUTE>,
    /// `pmeth_engine`: the engine whose `EVP_PKEY_METHOD` the key's contexts use
    /// (`EVP_PKEY_set1_engine`), with a functional reference, or NULL. Outside the lock, as
    /// letting it go runs the engine's `finish`.
    pmeth_engine: AtomicPtr<ENGINE>,
}

/// The key's application data, at a fixed address for the `CRYPTO_*_ex_data` functions.
struct ExData(UnsafeCell<CRYPTO_EX_DATA>);

// SAFETY: the ex_data functions are the only users, and OpenSSL leaves serializing them to the
// application.
unsafe impl Send for ExData {}
// SAFETY: as above.
unsafe impl Sync for ExData {}

/// A key's state.
pub(crate) struct State {
    pub(crate) type_: c_int,
    save_type: c_int,
    /// The ASN.1 method of a key typed without a key manager.
    pub(crate) ameth: Option<ameth::Ref>,
    /// The method's data (`pkey.ptr`), which its `pkey_free` frees.
    legacy: Ptr<c_void>,
    /// `legacy_cache_pkey`: a provided key's data as its type's legacy data, made when asked for
    /// (`EVP_PKEY_get0_RSA` ...) and freed with the key's data.
    legacy_cache: Ptr<c_void>,
    /// `foreign`: legacy data whose operations aren't OpenSSL's (an application's method), which
    /// contexts then run through the type's built-in `EVP_PKEY_METHOD`.
    pub(crate) foreign: bool,
    pub(crate) keymgmt: Option<keymgmt::Ref>,
    pub(crate) keydata: Option<Arc<KeyData>>,
    /// `cache`: bits, security bits, and maximum size.
    bits: c_int,
    security_bits: c_int,
    size: c_int,
    dirty_cnt: u64,
    dirty_cnt_copy: u64,
    operation_cache: Vec<OpCache>,
    save_parameters: c_int,
}

handle_type!(EVP_PKEY => Pkey);

/// What a cleared key drops: freed after its lock is released, as freeing calls providers.
#[derive(Default)]
struct Dropped {
    _keymgmt: Option<keymgmt::Ref>,
    _keydata: Option<Arc<KeyData>>,
    _cache: Vec<OpCache>,
}

impl Pkey {
    /// The state, locked.
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.0.get()
    }

    /// The slot of the key's attributes, as the `X509at_*` functions take it.
    pub(crate) fn attributes_slot(&self) -> *mut *mut rustyssl_abi::stack_st_X509_ATTRIBUTE {
        self.attributes.as_ptr()
    }

    /// The engine set with `EVP_PKEY_set1_engine` (no reference is taken), or NULL.
    pub(crate) fn pmeth_engine(&self) -> *mut ENGINE {
        self.pmeth_engine.load(Ordering::Acquire)
    }

    /// Replaces the `EVP_PKEY_set1_engine` engine with `e` (whose functional reference the
    /// key takes), letting the old one go.
    fn replace_pmeth_engine(&self, e: *mut ENGINE) {
        let old = self.pmeth_engine.swap(e, Ordering::AcqRel);
        // SAFETY: the key's functional reference, or NULL; no lock is held.
        unsafe { crate::engine::ENGINE_finish(old) };
    }

    /// The key manager and data (each with a reference), as they are now.
    pub(crate) fn provided(&self) -> (Option<keymgmt::Ref>, Option<Arc<KeyData>>) {
        let s = self.lock();
        (s.keymgmt.clone(), s.keydata.clone())
    }

    /// `evp_pkey_is_provided`.
    pub(crate) fn is_provided(&self) -> bool {
        self.lock().keymgmt.is_some()
    }

    /// The key type (`EVP_PKEY_get_id`).
    pub(crate) fn type_(&self) -> c_int {
        self.lock().type_
    }

    /// The key's handle.
    pub(crate) fn handle(&self) -> *mut EVP_PKEY {
        self.this.load(Ordering::Relaxed)
    }

    /// `save_parameters`: whether a DSA or EC key's public key is encoded with its parameters.
    pub(crate) fn save_parameters(&self) -> c_int {
        self.lock().save_parameters
    }

    /// The PEM name of the key's ASN.1 method (`ameth->pem_str`), if it has one.
    pub(crate) fn ameth_pem_str(&self) -> Option<CString> {
        let m = self.lock().ameth.clone();
        m.and_then(|m| m.get().pem_str.clone())
    }

    /// Whether the key has data (`evp_pkey_is_assigned`).
    pub(crate) fn assigned(&self) -> bool {
        self.lock().is_assigned()
    }

    /// The functions of the key's ASN.1 method, if it has one.
    pub(crate) fn ameth_funcs(&self) -> Option<ameth::Funcs> {
        let m = self.lock().ameth.clone();
        m.map(|m| m.get().funcs())
    }
}

/// `evp_pkey_free_legacy`: has the key's ASN.1 method free its data (the method's `pkey_free`
/// runs whenever the key has a method, data or not, without the key's lock).
fn free_legacy(k: &Pkey) {
    // A provided key has no ASN.1 method; its legacy copy is freed by its type's.
    let (cache, type_) = {
        let s = k.lock();
        (s.legacy_cache, s.type_)
    };
    let funcs = k.ameth_funcs().or_else(|| {
        (!cache.0.is_null())
            .then(|| ameth::find(type_).map(|m| m.get().funcs()))
            .flatten()
    });
    let Some(f) = funcs else {
        return;
    };
    if !cache.0.is_null() {
        // The cache freed as if it were the key's own legacy data.
        let mut s = k.lock();
        s.legacy = cache;
        s.legacy_cache = Ptr(ptr::null_mut());
    }
    if let Some(free) = f.pkey_free {
        // SAFETY: the method's function with the key's handle.
        unsafe { free(k.handle()) };
    }
    let mut s = k.lock();
    s.legacy = Ptr(ptr::null_mut());
    s.foreign = false;
}

/// The key's legacy data as the method's functions see it (`pkey->pkey.ptr`, even for a
/// provided key whose cache is being freed), or NULL.
///
/// # Safety
/// `p` is NULL or a live key.
pub(crate) unsafe fn legacy_data(p: *const EVP_PKEY) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    unsafe { pkey(p) }.map_or(ptr::null_mut(), |k| k.lock().legacy.0)
}

/// The library context of the key's key manager's provider, or NULL without one (as the
/// built-in ASN.1 methods take it).
///
/// # Safety
/// `p` is NULL or a live key.
pub(crate) unsafe fn keymgmt_libctx(p: *const EVP_PKEY) -> *mut OSSL_LIB_CTX {
    // SAFETY: the caller's guarantee.
    let km = unsafe { pkey(p) }.and_then(|k| k.lock().keymgmt.clone());
    km.map_or(ptr::null_mut(), |km| {
        // SAFETY: the key manager's live provider.
        unsafe { crate::provider::libctx_of(km.get().prov.0) }
    })
}

/// `evp_pkey_get_legacy`: the key's legacy data; for a provided key, a copy made by its type's
/// ASN.1 method's `import_from` and kept with the key. NULL for an unassigned key.
pub(crate) fn get_legacy(k: &Pkey) -> *mut c_void {
    let (assigned, provided, legacy, cache) = {
        let s = k.lock();
        (
            s.is_assigned(),
            s.keymgmt.is_some(),
            s.legacy.0,
            s.legacy_cache.0,
        )
    };
    if !assigned {
        return ptr::null_mut();
    }
    if !provided {
        return legacy;
    }
    if !cache.is_null() {
        return cache;
    }
    let Some(copy) = copy_downgraded(k) else {
        return ptr::null_mut();
    };
    let mut s = k.lock();
    if s.legacy_cache.0.is_null() {
        // Steal the copy's legacy data.
        let mut c = copy.get().lock();
        s.legacy_cache = c.legacy;
        c.legacy = Ptr(ptr::null_mut());
    }
    s.legacy_cache.0
}

/// `evp_pkey_free_it`: frees the key's data (legacy and provided) and untypes it.
fn clear(k: &Pkey) {
    free_legacy(k);
    // `evp_pkey_free_legacy` lets the key's engine go, legacy data or not.
    k.replace_pmeth_engine(ptr::null_mut());
    let dropped = k.lock().free_it();
    drop(dropped);
}

impl State {
    /// `evp_pkey_is_assigned`.
    pub(crate) fn is_assigned(&self) -> bool {
        self.keydata.is_some() || !self.legacy.0.is_null()
    }

    /// `evp_pkey_is_blank`.
    fn is_blank(&self) -> bool {
        self.type_ == EVP_PKEY_NONE && self.keymgmt.is_none()
    }

    /// `evp_pkey_is_typed`.
    fn is_typed(&self) -> bool {
        self.type_ != EVP_PKEY_NONE || self.keymgmt.is_some()
    }

    /// `evp_pkey_is_legacy`.
    pub(crate) fn is_legacy(&self) -> bool {
        self.type_ != EVP_PKEY_NONE && self.keymgmt.is_none()
    }

    /// `evp_pkey_free_it`: clears the data, the key manager, and the type.
    fn free_it(&mut self) -> Dropped {
        let d = Dropped {
            _keymgmt: self.keymgmt.take(),
            _keydata: self.keydata.take(),
            _cache: core::mem::take(&mut self.operation_cache),
        };
        self.type_ = EVP_PKEY_NONE;
        d
    }
}

/// The key behind `pkey`, or `None` for NULL.
///
/// # Safety
/// `pkey` is NULL or a live key.
pub(crate) unsafe fn pkey<'a>(pkey: *const EVP_PKEY) -> Option<&'a Pkey> {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_PKEY::get(pkey) }
}

/// A C string argument, `None` for NULL.
///
/// # Safety
/// `s` is NULL or a string.
pub(crate) unsafe fn text<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

/// `EVP_PKEY_new`: a blank key, or NULL.
pub(crate) fn new() -> *mut EVP_PKEY {
    let p = EVP_PKEY::new_handle(Pkey {
        references: AtomicI32::new(1),
        state: Mutex::new(State {
            type_: EVP_PKEY_NONE,
            save_type: EVP_PKEY_NONE,
            ameth: None,
            legacy: Ptr(ptr::null_mut()),
            legacy_cache: Ptr(ptr::null_mut()),
            foreign: false,
            keymgmt: None,
            keydata: None,
            bits: 0,
            security_bits: 0,
            size: 0,
            dirty_cnt: 0,
            dirty_cnt_copy: 0,
            operation_cache: Vec::new(),
            save_parameters: 1,
        }),
        ex_data: ExData(UnsafeCell::new(CRYPTO_EX_DATA {
            ctx: ptr::null_mut(),
            sk: ptr::null_mut(),
        })),
        this: AtomicPtr::new(ptr::null_mut()),
        attributes: AtomicPtr::new(ptr::null_mut()),
        pmeth_engine: AtomicPtr::new(ptr::null_mut()),
    });
    // SAFETY: just made.
    let Some(k) = (unsafe { pkey(p) }) else {
        return ptr::null_mut();
    };
    k.this.store(p, Ordering::Relaxed);
    // SAFETY: the key's own ex_data.
    if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_EVP_PKEY, p.cast(), k.ex_data()) } == 0 {
        err::raise(ERR_LIB_EVP, rustyssl_abi::ERR_R_CRYPTO_LIB, "EVP_PKEY_new");
        // SAFETY: nothing else has the new handle.
        unsafe { EVP_PKEY::free(p) };
        return ptr::null_mut();
    }
    p
}

/// `EVP_PKEY_free`.
///
/// # Safety
/// `p` is NULL or a live key whose reference the caller gives up.
pub(crate) unsafe fn free(p: *mut EVP_PKEY) {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { EVP_PKEY::hold(p) }) else {
        return;
    };
    if held.references.fetch_sub(1, Ordering::AcqRel) > 1 {
        return;
    }
    clear(&held);
    // SAFETY: the key's own ex_data; its last reference.
    unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_EVP_PKEY, p.cast(), held.ex_data()) };
    let attrs = held.attributes.swap(ptr::null_mut(), Ordering::AcqRel);
    // SAFETY: the key's own attributes, or NULL.
    unsafe { crate::stack::OPENSSL_sk_pop_free(attrs.cast(), Some(attrs::attribute_free)) };
    // SAFETY: the last reference; the hold keeps the object until this returns.
    unsafe { EVP_PKEY::free(p) };
}

/// A key handle with a reference, given up when dropped.
pub(crate) struct PkeyRef(Ptr<EVP_PKEY>);

impl PkeyRef {
    /// A new reference to `p`; `None` for NULL.
    ///
    /// # Safety
    /// `p` is NULL or a live key.
    pub(crate) unsafe fn new(p: *mut EVP_PKEY) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        let k = unsafe { pkey(p) }?;
        k.references.fetch_add(1, Ordering::AcqRel);
        Some(Self(Ptr(p)))
    }

    /// Takes over the caller's reference to `p`; `None` for NULL.
    ///
    /// # Safety
    /// `p` is NULL or a live key whose reference the caller gives up.
    pub(crate) unsafe fn adopt(p: *mut EVP_PKEY) -> Option<Self> {
        // SAFETY: the caller's guarantee.
        unsafe { pkey(p) }.map(|_| Self(Ptr(p)))
    }

    /// The handle (no reference is taken).
    pub(crate) fn as_ptr(&self) -> *mut EVP_PKEY {
        self.0.0
    }

    /// The handle, with this reference for the caller.
    pub(crate) fn into_raw(self) -> *mut EVP_PKEY {
        let p = self.0.0;
        core::mem::forget(self);
        p
    }

    /// The key.
    pub(crate) fn get(&self) -> &Pkey {
        // SAFETY: this holds a reference to a live key.
        match unsafe { pkey(self.0.0) } {
            Some(k) => k,
            None => crate::ffi::die("a held EVP_PKEY is live"),
        }
    }
}

impl Clone for PkeyRef {
    fn clone(&self) -> Self {
        self.get().references.fetch_add(1, Ordering::AcqRel);
        Self(self.0)
    }
}

impl Drop for PkeyRef {
    fn drop(&mut self) {
        // SAFETY: the reference this holds.
        unsafe { free(self.0.0) };
    }
}

/// `pkey_set_type`: types `pkey` (or, without one, only checks the type exists) by the key type
/// `type_`, the PEM name `name`, or the key manager. False with an error if there's no such
/// type.
pub(crate) fn set_type(
    pkey: Option<&Pkey>,
    type_: c_int,
    name: Option<&[u8]>,
    keymgmt: Option<&keymgmt::Ref>,
) -> bool {
    if let Some(k) = pkey {
        let assigned = k.lock().is_assigned();
        if assigned {
            clear(k);
        }
        // Retyping to the type it was given keeps a key as it is.
        let s = k.lock();
        if s.type_ != EVP_PKEY_NONE && type_ == s.save_type && s.ameth.is_some() {
            return true;
        }
        drop(s);
        // Otherwise the engine its contexts used is let go.
        k.replace_pmeth_engine(ptr::null_mut());
    }
    let found = match name {
        Some(n) => ameth::find_str(n),
        None if type_ != EVP_PKEY_NONE => {
            let m = ameth::find(type_);
            ameth::engine_lookup();
            m
        }
        None => None,
    };
    if found.is_none() && keymgmt.is_none() {
        err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM, "pkey_set_type");
        return false;
    }
    if let Some(k) = pkey {
        let mut s = k.lock();
        let old = core::mem::replace(&mut s.keymgmt, keymgmt.cloned());
        s.save_type = type_;
        s.type_ = type_;
        match &found {
            Some(m) if type_ == EVP_PKEY_NONE => s.type_ = m.get().pkey_id,
            Some(_) => {}
            None => s.type_ = EVP_PKEY_KEYMGMT,
        }
        let old_ameth = if keymgmt.is_none() {
            core::mem::replace(&mut s.ameth, found)
        } else {
            None
        };
        drop(s);
        drop(old);
        drop(old_ameth);
    }
    true
}

/// `EVP_PKEY_set_type_by_keymgmt`: types the key by the ASN.1 method whose PEM name is one of the
/// key manager's names (or as `EVP_PKEY_KEYMGMT`).
pub(crate) fn set_type_by_keymgmt(k: &Pkey, keymgmt: &keymgmt::Ref) -> bool {
    let mut found: Vec<Vec<u8>> = Vec::new();
    for n in keymgmt.get().names() {
        // `find_ameth`: whether the name is a PEM name, raising nothing.
        // SAFETY: no preconditions.
        unsafe { err::ERR_set_mark() };
        if set_type(None, EVP_PKEY_NONE, Some(&n), None) && found.len() < 2 {
            found.push(n);
        }
        // SAFETY: the mark set above.
        unsafe { err::ERR_pop_to_mark() };
    }
    if found.len() > 1 {
        err::raise(
            ERR_LIB_EVP,
            ERR_R_INTERNAL_ERROR,
            "EVP_PKEY_set_type_by_keymgmt",
        );
        return false;
    }
    set_type(
        Some(k),
        EVP_PKEY_NONE,
        found.first().map(Vec::as_slice),
        Some(keymgmt),
    )
}

/// Gives a key typed by its key manager that key manager's new data (`pkey->keydata =
/// evp_keymgmt_newdata(...)`, as `EVP_PKEY_derive_init` does for key types without keys).
pub(crate) fn set_keydata(k: &Pkey, keydata: Arc<KeyData>) {
    let old = k.lock().keydata.replace(keydata);
    drop(old);
}

/// `evp_keymgmt_util_cache_keyinfo`: asks the key manager for the key's bits, security bits,
/// and maximum size, and caches them.
pub(crate) fn cache_keyinfo(k: &Pkey) {
    let (Some(km), Some(kd)) = k.provided() else {
        return;
    };
    let (mut bits, mut security_bits, mut size): (c_int, c_int, c_int) = (0, 0, 0);
    // SAFETY: a static key; a local that outlives the array, here and below.
    let p0 = unsafe { OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS.as_ptr(), &raw mut bits) };
    // SAFETY: as above.
    let p1 = unsafe {
        OSSL_PARAM_construct_int(
            OSSL_PKEY_PARAM_SECURITY_BITS.as_ptr(),
            &raw mut security_bits,
        )
    };
    // SAFETY: as above.
    let p2 = unsafe { OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_MAX_SIZE.as_ptr(), &raw mut size) };
    let mut params = [p0, p1, p2, end()];
    // SAFETY: the key manager's data; the array above.
    if unsafe { km.get().get_params(kd.ptr(), params.as_mut_ptr()) } != 0 {
        let mut s = k.lock();
        s.size = size;
        s.bits = bits;
        s.security_bits = security_bits;
    }
}

/// `evp_keymgmt_util_assign_pkey`: gives the key the key manager's data.
pub(crate) fn assign(k: &Pkey, keydata: Arc<KeyData>) -> bool {
    // A key typed by name keeps its type when typed again, so it gets no key manager; OpenSSL
    // then reaches the missing key manager (docs/DEVIATIONS.md).
    let typed = set_type_by_keymgmt(k, &keydata.keymgmt)
        && k.lock()
            .keymgmt
            .as_ref()
            .is_some_and(|m| m.same(&keydata.keymgmt));
    if !typed {
        err::raise(
            ERR_LIB_EVP,
            ERR_R_INTERNAL_ERROR,
            "evp_keymgmt_util_assign_pkey",
        );
        return false;
    }
    k.lock().keydata = Some(keydata);
    cache_keyinfo(k);
    true
}

/// `evp_keymgmt_util_has`.
pub(crate) fn has(k: &Pkey, selection: c_int) -> bool {
    let (Some(km), kd) = k.provided() else {
        return false;
    };
    let ptr = kd.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
    // SAFETY: the key manager's data, or NULL.
    unsafe { km.get().has(ptr, selection) != 0 }
}

/// `evp_keymgmt_util_export`: has the key manager export the selection to `cb`.
///
/// # Safety
/// `cb` takes `cbarg`.
pub(crate) unsafe fn export(
    k: &Pkey,
    selection: c_int,
    cb: OSSL_CALLBACK,
    cbarg: *mut c_void,
) -> c_int {
    if cb.is_none() {
        return 0;
    }
    let (Some(km), kd) = k.provided() else {
        // OpenSSL calls through a NULL key manager here.
        crate::stub::unimplemented("evp_keymgmt_util_export of a key without a key manager");
    };
    let ptr = kd.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
    // SAFETY: the key manager's data; the caller's guarantee.
    unsafe { km.get().export(ptr, selection, cb, cbarg) }
}

/// What `evp_keymgmt_util_try_import` fills.
pub(crate) struct TryImport {
    pub(crate) keymgmt: keymgmt::Ref,
    pub(crate) keydata: *mut c_void,
    pub(crate) selection: c_int,
    /// Whether `keydata` was made here.
    pub(crate) allocated: bool,
}

/// `evp_keymgmt_util_try_import`: imports the parameters into the key data (made first if
/// there's none).
///
/// # Safety
/// `params` is a parameter array; `arg` is a `TryImport`.
pub(crate) unsafe extern "C" fn try_import(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(data) = (unsafe { arg.cast::<TryImport>().as_mut() }) else {
        return 0;
    };
    let mut delete_on_error = false;
    if data.keydata.is_null() {
        data.keydata = data.keymgmt.get().newdata();
        if data.keydata.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_EVP_LIB, "evp_keymgmt_util_try_import");
            return 0;
        }
        data.allocated = true;
        delete_on_error = true;
    }
    // An empty export is fine.
    // SAFETY: the caller's guarantee.
    if unsafe { params.as_ref() }.is_none_or(|p| p.key.is_null()) {
        return 1;
    }
    // SAFETY: the key manager's data; the caller's array.
    if unsafe {
        data.keymgmt
            .get()
            .import(data.keydata, data.selection, params)
    } != 0
    {
        return 1;
    }
    if delete_on_error {
        // SAFETY: made above.
        unsafe { data.keymgmt.get().freedata(data.keydata) };
        data.keydata = ptr::null_mut();
        data.allocated = false;
    }
    0
}

/// `evp_keymgmt_util_find_operation_cache`.
fn find_cache<'a>(
    s: &'a State,
    keymgmt: &Keymgmt,
    km: &keymgmt::Ref,
    selection: c_int,
) -> Option<&'a OpCache> {
    s.operation_cache.iter().find(|p| {
        (p.selection & selection) == selection
            && (p.keymgmt.same(km)
                || (keymgmt.name_id == p.keymgmt.get().name_id
                    && keymgmt.prov.0 == p.keymgmt.get().prov.0))
    })
}

/// `evp_keymgmt_util_export_to_provider`: the key's data for `keymgmt`: its own if that's its key
/// manager (or the same algorithm of the same provider), else a cached or new export.
pub(crate) fn export_to_provider(
    k: &Pkey,
    km: &keymgmt::Ref,
    selection: c_int,
) -> Option<Arc<KeyData>> {
    let legacy = {
        let s = k.lock();
        s.keymgmt.is_none() && !s.legacy.0.is_null()
    };
    if legacy {
        return export_legacy(k, km, selection);
    }
    let (Some(own), Some(kd)) = k.provided() else {
        return None;
    };
    let m = km.get();
    if own.same(km) || (own.get().name_id == m.name_id && own.get().prov.0 == m.prov.0) {
        return Some(kd);
    }
    {
        let s = k.lock();
        if s.dirty_cnt == s.dirty_cnt_copy
            && let Some(op) = find_cache(&s, m, km, selection)
        {
            return Some(op.keydata.clone());
        }
    }
    if !own.get().has_export() {
        return None;
    }
    // The key managers must be of the same key type (OpenSSL asserts).
    if !own.get().match_type(m) {
        return None;
    }
    let mut data = TryImport {
        keymgmt: km.clone(),
        keydata: ptr::null_mut(),
        selection,
        allocated: false,
    };
    // SAFETY: the callback takes the `TryImport`, which outlives the call.
    if unsafe { export(k, selection, Some(try_import), (&raw mut data).cast()) } == 0 {
        if data.allocated {
            // SAFETY: made by `try_import`.
            unsafe { m.freedata(data.keydata) };
        }
        return None;
    }
    let new = KeyData::adopt(km.clone(), data.keydata)?;
    let mut s = k.lock();
    if let Some(op) = find_cache(&s, m, km, selection) {
        // Another thread got there first.
        return Some(op.keydata.clone());
    }
    if s.dirty_cnt != s.dirty_cnt_copy {
        let old = core::mem::take(&mut s.operation_cache);
        s.operation_cache.push(OpCache {
            keymgmt: km.clone(),
            keydata: new.clone(),
            selection,
        });
        s.dirty_cnt_copy = s.dirty_cnt;
        drop(s);
        drop(old);
        return Some(new);
    }
    s.operation_cache.push(OpCache {
        keymgmt: km.clone(),
        keydata: new.clone(),
        selection,
    });
    s.dirty_cnt_copy = s.dirty_cnt;
    Some(new)
}

/// `evp_pkey_export_to_provider` of a key with legacy data: a provider copy made through its
/// ASN.1 method's `export_to`, cached until the data changes (its `dirty_cnt`).
fn export_legacy(k: &Pkey, km: &keymgmt::Ref, selection: c_int) -> Option<Arc<KeyData>> {
    let f = k.ameth_funcs()?;
    let (dirty_cnt, export_to) = (f.dirty_cnt?, f.export_to?);
    let h = k.handle();
    // SAFETY: the method's function with the key's handle.
    let cnt = u64::try_from(unsafe { dirty_cnt(h) }).unwrap_or(0);
    let m = km.get();
    {
        let s = k.lock();
        if cnt == s.dirty_cnt_copy
            && let Some(op) = find_cache(&s, m, km, selection)
        {
            return Some(op.keydata.clone());
        }
    }
    // The key manager must be for the legacy type.
    // SAFETY: a type number.
    let sn = unsafe { OBJ_nid2sn(k.type_()) };
    // SAFETY: NULL or the table's string.
    let sn = unsafe { text(sn) };
    if !sn.is_some_and(|n| m.is_a(n.to_bytes())) {
        return None;
    }
    let keydata = m.newdata();
    if keydata.is_null() {
        return None;
    }
    let mut importer = |sel: c_int, params: *const OSSL_PARAM| {
        // SAFETY: the new key data; the method's parameters.
        unsafe { m.import(keydata, sel, params) }
    };
    // SAFETY: the method's function with the key's handle; the importer.
    if unsafe { export_to(h, &mut importer) } == 0 {
        // SAFETY: made above.
        unsafe { m.freedata(keydata) };
        return None;
    }
    let new = KeyData::adopt(km.clone(), keydata)?;
    // Read before the key's lock: the method's function takes it.
    // SAFETY: as above.
    let now = u64::try_from(unsafe { dirty_cnt(h) }).unwrap_or(0);
    let mut s = k.lock();
    let old = if now != s.dirty_cnt_copy {
        core::mem::take(&mut s.operation_cache)
    } else {
        Vec::new()
    };
    if let Some(op) = find_cache(&s, m, km, selection) {
        // Another thread got there first.
        return Some(op.keydata.clone());
    }
    s.operation_cache.push(OpCache {
        keymgmt: km.clone(),
        keydata: new.clone(),
        selection,
    });
    s.dirty_cnt_copy = now;
    drop(s);
    drop(old);
    Some(new)
}

/// `evp_pkey_export_to_provider`: the key's data for `keymgmt` (if given), else for the key
/// manager a context for the key would fetch from `libctx` with `propq`. The key manager used
/// and the data, or `None`.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn export_to_any(
    k: &PkeyRef,
    libctx: *mut OSSL_LIB_CTX,
    keymgmt: Option<keymgmt::Ref>,
    propq: Option<&CStr>,
) -> Option<(keymgmt::Ref, Arc<KeyData>)> {
    if !k.get().lock().is_assigned() {
        return None;
    }
    let km = match keymgmt {
        Some(km) => km,
        // SAFETY: the caller's guarantee.
        None => unsafe { super::pkey_ctx::keymgmt_for(libctx, k, propq) }?,
    };
    let kd = export_to_provider(k.get(), &km, OSSL_KEYMGMT_SELECT_ALL as c_int)?;
    Some((km, kd))
}

/// `evp_keymgmt_util_match`: compares two keys' selections, exporting one to the other's key
/// manager if they differ.
fn keymgmt_match(a: &Pkey, b: &Pkey, selection: c_int) -> c_int {
    let (km1, kd1) = a.provided();
    let (km2, kd2) = b.provided();
    let (mut km1, mut kd1, mut km2, mut kd2) = (km1, kd1, km2, kd2);
    let differ = match (&km1, &km2) {
        (Some(x), Some(y)) => !x.same(y),
        (None, None) => false,
        _ => true,
    };
    if differ {
        if let (Some(x), Some(y)) = (&km1, &km2)
            && !x.get().match_type(y.get())
        {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_DIFFERENT_KEY_TYPES,
                "evp_keymgmt_util_match",
            );
            return -1;
        }
        let mut ok = false;
        if let Some(y) = km2.clone().filter(|y| y.get().has_match()) {
            ok = true;
            let mut tmp = None;
            if kd1.is_some() {
                tmp = export_to_provider(a, &y, selection);
                ok = tmp.is_some();
            }
            if ok {
                km1 = Some(y);
                kd1 = tmp;
            }
        }
        if !ok && let Some(x) = km1.clone().filter(|x| x.get().has_match()) {
            ok = true;
            let mut tmp = None;
            if kd2.is_some() {
                tmp = export_to_provider(b, &x, selection);
                ok = tmp.is_some();
            }
            if ok {
                km2 = Some(x);
                kd2 = tmp;
            }
        }
    }
    let same = match (&km1, &km2) {
        (Some(x), Some(y)) => x.same(y),
        (None, None) => true,
        _ => false,
    };
    if !same {
        return -2;
    }
    match (km1, kd1, kd2) {
        (_, None, None) => 1,
        (_, None, _) | (_, _, None) => 0,
        // SAFETY: both data are the key manager's.
        (Some(m), Some(x), Some(y)) => unsafe { m.get().match_(x.ptr(), y.ptr(), selection) },
        // Neither key has a key manager, yet there's data (can't happen).
        (None, Some(_), Some(_)) => -2,
    }
}

/// `evp_pkey_cmp_any`.
fn cmp_any(a: &Pkey, b: &Pkey, selection: c_int) -> c_int {
    let (pa, pb) = (a.is_provided(), b.is_provided());
    if !pa && !pb {
        return -2;
    }
    if pa && pb {
        return keymgmt_match(a, b, selection);
    }
    // One is legacy: its type must be one of the other's key manager's names.
    let (legacy, provided) = if pa { (b, a) } else { (a, b) };
    let t = legacy.type_();
    if t == EVP_PKEY_NONE {
        // A blank key has nothing to export.
        return -2;
    }
    // SAFETY: a type number.
    let sn = unsafe { OBJ_nid2sn(t) };
    // SAFETY: NULL or a static string.
    let name = unsafe { text(sn) }.map_or(&b""[..], CStr::to_bytes);
    let Some(km) = provided.provided().0 else {
        return -2;
    };
    if !km.get().is_a(name) {
        return -1;
    }
    // Cross export: `a` to `b`'s key manager, else `b` to `a`'s, then compare there.
    let all = OSSL_KEYMGMT_SELECT_ALL as c_int;
    let ((mut km1, mut kd1), (mut km2, mut kd2)) = (a.provided(), b.provided());
    let mut exported = false;
    if let Some(y) = km2.clone().filter(|y| y.get().has_match())
        && let Some(d) = export_to_provider(a, &y, all)
    {
        km1 = Some(y);
        kd1 = Some(d);
        exported = true;
    }
    if !exported
        && let Some(x) = km1.clone().filter(|x| x.get().has_match())
        && let Some(d) = export_to_provider(b, &x, all)
    {
        km2 = Some(x);
        kd2 = Some(d);
    }
    match (km1, km2, kd1, kd2) {
        (Some(x), Some(y), d1, d2) if x.same(&y) => {
            let p1 = d1.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
            let p2 = d2.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
            // SAFETY: the key manager's data (or NULL).
            unsafe { x.get().match_(p1, p2, selection) }
        }
        _ => -2,
    }
}

/// `copy`'s helper `evp_keymgmt_util_copy`: copies the selection of `from`'s data into `to`.
fn keymgmt_copy(to: &Pkey, from: &Pkey, selection: c_int) -> bool {
    let (from_km, from_kd) = from.provided();
    let (Some(from_km), Some(from_kd)) = (from_km, from_kd) else {
        return false;
    };
    let (to_km, to_kd) = to.provided();
    let to_km = to_km.unwrap_or_else(|| from_km.clone());
    let mut to_ptr = to_kd.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
    let mut allocated = None;
    if to_km.same(&from_km) && to_km.get().has_dup() && to_kd.is_none() {
        // SAFETY: `from`'s data, of this key manager.
        let d = unsafe { to_km.get().dup(from_kd.ptr(), selection) };
        let Some(d) = KeyData::adopt(to_km.clone(), d) else {
            return false;
        };
        to_ptr = d.ptr();
        allocated = Some(d);
    } else if to_km.get().match_type(from_km.get()) {
        let mut data = TryImport {
            keymgmt: to_km.clone(),
            keydata: to_ptr,
            selection,
            allocated: false,
        };
        // SAFETY: the callback takes the `TryImport`, which outlives the call.
        if unsafe { export(from, selection, Some(try_import), (&raw mut data).cast()) } == 0 {
            if data.allocated {
                // SAFETY: made by `try_import`.
                unsafe { to_km.get().freedata(data.keydata) };
            }
            return false;
        }
        if to_kd.is_none() {
            allocated = KeyData::adopt(to_km.clone(), data.keydata);
            to_ptr = data.keydata;
        }
    } else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_DIFFERENT_KEY_TYPES,
            "evp_keymgmt_util_copy",
        );
        return false;
    }
    let _ = to_ptr;
    if !to.is_provided() && !set_type_by_keymgmt(to, &to_km) {
        return false;
    }
    if let Some(d) = allocated {
        to.lock().keydata = Some(d);
    }
    cache_keyinfo(to);
    true
}

/// `evp_keymgmt_util_has`: whether a provided key's data has the selected parts (false for a
/// key without a key manager).
pub(crate) fn util_has(k: &Pkey, selection: c_int) -> bool {
    let (Some(km), kd) = k.provided() else {
        return false;
    };
    let ptr = kd.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
    // SAFETY: the key manager's own data.
    unsafe { km.get().has(ptr, selection) != 0 }
}

/// The legacy data of a downgraded copy of a provided key (`evp_pkey_copy_downgraded`), taken
/// from the copy; `None` with OpenSSL's errors.
pub(crate) fn downgraded_legacy(k: &Pkey) -> Option<*mut c_void> {
    let copy = copy_downgraded(k)?;
    let mut c = copy.get().lock();
    let legacy = c.legacy.0;
    c.legacy = Ptr(ptr::null_mut());
    Some(legacy)
}

/// `evp_pkey_copy_downgraded` of a provided key: a new key of its type whose legacy data the
/// type's ASN.1 method's `import_from` made from the provider's export (in the key manager's
/// library context). `None` with OpenSSL's errors.
pub(crate) fn copy_downgraded(src: &Pkey) -> Option<PkeyRef> {
    const F: &str = "evp_pkey_copy_downgraded";
    let (type_, assigned, keymgmt, keydata) = {
        let s = src.lock();
        (
            s.type_,
            s.is_assigned(),
            s.keymgmt.clone(),
            s.keydata.clone(),
        )
    };
    let km = keymgmt.filter(|_| assigned)?;
    let keytype = if type_ == EVP_PKEY_KEYMGMT {
        String::from_utf8_lossy(km.get().name().to_bytes()).into_owned()
    } else {
        // SAFETY: a type number.
        let sn = unsafe { OBJ_nid2sn(type_) };
        // SAFETY: NULL or the table's string.
        unsafe { text(sn) }.map_or_else(String::new, |t| t.to_string_lossy().into_owned())
    };
    // SAFETY: just made, with its reference.
    let dest = unsafe { PkeyRef::adopt(new()) }?;
    if !set_type(Some(dest.get()), type_, None, None) {
        return None;
    }
    let Some(kd) = keydata else { return Some(dest) };
    let Some(import_from) = dest.get().ameth_funcs().and_then(|f| f.import_from) else {
        err::raise_with_text(
            ERR_LIB_EVP,
            rustyssl_abi::EVP_R_NO_IMPORT_FUNCTION,
            F,
            &format!("key type = {keytype}"),
        );
        return None;
    };
    // SAFETY: the key manager's live provider.
    let libctx = unsafe { crate::provider::libctx_of(km.get().prov.0) };
    struct Importing {
        f: ameth::ImportFrom,
        dest: *mut EVP_PKEY,
        libctx: *mut OSSL_LIB_CTX,
    }
    unsafe extern "C" fn importing(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
        // SAFETY: `copy_downgraded`'s `Importing`, live for the call.
        let Some(i) = (unsafe { arg.cast::<Importing>().as_ref() }) else {
            return 0;
        };
        // SAFETY: the method's function; the new key; the context.
        unsafe { (i.f)(params, i.dest, i.libctx) }
    }
    let mut imp = Importing {
        f: import_from,
        dest: dest.get().handle(),
        libctx,
    };
    // SAFETY: the key manager's data; the callback takes `imp`, which outlives the call.
    let ok = unsafe {
        km.get().export(
            kd.ptr(),
            OSSL_KEYMGMT_SELECT_ALL as c_int,
            Some(importing),
            (&raw mut imp).cast(),
        )
    } != 0;
    if ok {
        // Synchronize the dirty count.
        if let Some(dc) = dest.get().ameth_funcs().and_then(|f| f.dirty_cnt) {
            // SAFETY: the method's function with the new key.
            let n = unsafe { dc(dest.get().handle()) };
            dest.get().lock().dirty_cnt_copy = u64::try_from(n).unwrap_or(0);
        }
        return Some(dest);
    }
    err::raise_with_text(
        ERR_LIB_EVP,
        rustyssl_abi::EVP_R_KEYMGMT_EXPORT_FAILURE,
        F,
        &format!("key type = {keytype}"),
    );
    None
}

ffi_export! {
    /// A new blank key with one reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_new() -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        new()
    }
}

ffi_export! {
    /// Adds a reference. Returns 1 (0 for NULL, where OpenSSL would crash).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_up_ref(pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        c_int::from(k.references.fetch_add(1, Ordering::AcqRel) >= 1)
    }
}

ffi_export! {
    /// Drops a reference; with the last, frees the key's data and runs the ex_data callbacks.
    ///
    /// # Safety
    /// `x` is NULL or a key the caller holds, not used afterwards.
    pub unsafe extern "C" fn EVP_PKEY_free(x: *mut EVP_PKEY)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(x) };
    }
}

ffi_export! {
    /// The key type (`EVP_PKEY_NONE` for a blank key, `EVP_PKEY_KEYMGMT` for a provided key of
    /// a type without an ASN.1 method); 0 for NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_id(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::pkey(pkey) }.map_or(0, Pkey::type_)
    }
}

ffi_export! {
    /// The type the key's type stands for (`EVP_PKEY_type`); 0 for NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_base_id(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::pkey(pkey) }.map_or(0, |k| ameth::pkey_type(k.type_()))
    }
}

ffi_export! {
    /// The key type `type_` stands for (an alias's base type), `NID_undef` if none.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_PKEY_type(type_: c_int) -> c_int
    where failure = NID_undef, library = ERR_LIB_EVP
    {
        ameth::pkey_type(type_)
    }
}

ffi_export! {
    /// The key manager's name, or the ASN.1 method's PEM name; NULL for a blank key.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_type_name(key: *const EVP_PKEY) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(key) }) else { return ptr::null() };
        let s = k.lock();
        if let Some(km) = &s.keymgmt {
            // The key manager outlives the key's reference to it.
            return km.get().name().as_ptr();
        }
        // The method outlives the key's reference to it.
        s.ameth.as_ref().and_then(|m| m.get().pem_str.as_deref()).map_or(ptr::null(), CStr::as_ptr)
    }
}

ffi_export! {
    /// The key manager's description, or the ASN.1 method's; NULL for a key without data.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_description(pkey: *const EVP_PKEY) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return ptr::null() };
        let s = k.lock();
        if !s.is_assigned() {
            return ptr::null();
        }
        if let Some(km) = &s.keymgmt {
            let d = km.get().description();
            if !d.is_null() {
                return d;
            }
        }
        // The method outlives the key's reference to it.
        s.ameth.as_ref().and_then(|m| m.get().info.as_deref()).map_or(ptr::null(), CStr::as_ptr)
    }
}

ffi_export! {
    /// The provider of a provided key's key manager, else NULL.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_provider(key: *const EVP_PKEY) -> *const OSSL_PROVIDER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(key) }) else { return ptr::null() };
        k.lock().keymgmt.as_ref().map_or(ptr::null(), |m| m.get().prov.0.cast_const())
    }
}

ffi_export! {
    /// Whether the key is of the type `name` (one of its key manager's names, or the type
    /// `evp_pkey_name2type` gives). 0 for NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_is_a(pkey: *const EVP_PKEY, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let n = unsafe { text(name) }.map_or(&b""[..], CStr::to_bytes);
        let (km, type_) = {
            let s = k.lock();
            (s.keymgmt.clone(), s.type_)
        };
        match km {
            Some(m) => c_int::from(m.get().is_a(n)),
            None => c_int::from(type_ == ameth::name2type(n)),
        }
    }
}

/// A names callback.
type NameFn = unsafe extern "C" fn(*const c_char, *mut c_void);

ffi_export! {
    /// Calls `fn_` with each name of the key's type (its key manager's, or the type's short
    /// name). 0 for a blank key.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `fn_` is a function of the documented type.
    pub unsafe extern "C" fn EVP_PKEY_type_names_do_all(pkey: *const EVP_PKEY, fn_: Option<NameFn>, data: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        let (typed, km, type_) = {
            let s = k.lock();
            (s.is_typed(), s.keymgmt.clone(), s.type_)
        };
        if !typed {
            return 0;
        }
        match km {
            // SAFETY: the caller's guarantee.
            Some(m) => unsafe { keymgmt::names_do_all(m.get(), fn_, data) },
            None => {
                // SAFETY: a type number.
                let sn = unsafe { OBJ_nid2sn(type_) };
                if let Some(f) = fn_ {
                    // SAFETY: the caller's callback with the static name and its data.
                    unsafe { f(sn, data) };
                }
                1
            }
        }
    }
}

/// What `EVP_PKEY_get_bits` and its kin read.
#[derive(Clone, Copy)]
enum Info {
    Bits,
    SecurityBits,
    Size,
}

/// The cached information, or 0 with `reason`.
///
/// # Safety
/// `pkey` is NULL or a live key.
unsafe fn info(pkey: *const EVP_PKEY, which: Info, reason: c_int, function: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let size = unsafe { self::pkey(pkey) }.map_or(0, |k| {
        let cached = {
            let s = k.lock();
            match which {
                Info::Bits => s.bits,
                Info::SecurityBits => s.security_bits,
                Info::Size => s.size,
            }
        };
        let f = k.ameth_funcs().and_then(|f| match which {
            Info::Bits => f.pkey_bits,
            Info::SecurityBits => f.pkey_security_bits,
            Info::Size => f.pkey_size,
        });
        match f {
            // SAFETY: the method's function with the key's handle.
            Some(f) => unsafe { f(k.handle()) },
            None => cached,
        }
    });
    if size <= 0 {
        err::raise(ERR_LIB_EVP, reason, function);
        return 0;
    }
    size
}

ffi_export! {
    /// The key's size in bits, or 0 with `EVP_R_UNKNOWN_BITS`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_bits(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { info(pkey, Info::Bits, EVP_R_UNKNOWN_BITS, "EVP_PKEY_get_bits") }
    }
}

ffi_export! {
    /// The key's security bits, or 0 with `EVP_R_UNKNOWN_SECURITY_BITS`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_security_bits(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { info(pkey, Info::SecurityBits, EVP_R_UNKNOWN_SECURITY_BITS, "EVP_PKEY_get_security_bits") }
    }
}

ffi_export! {
    /// The maximum size of the key's output (a signature, ...), or 0 with
    /// `EVP_R_UNKNOWN_MAX_SIZE`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_size(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { info(pkey, Info::Size, EVP_R_UNKNOWN_MAX_SIZE, "EVP_PKEY_get_size") }
    }
}

ffi_export! {
    /// For a DSA or EC key: whether its parameters are saved with it, set to `mode` unless that's
    /// negative; the setting before. 0 for other keys.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_save_parameters(pkey: *mut EVP_PKEY, mode: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        let mut s = k.lock();
        if s.type_ != EVP_PKEY_DSA && s.type_ != EVP_PKEY_EC {
            return 0;
        }
        let ret = s.save_parameters;
        if mode >= 0 {
            s.save_parameters = mode;
        }
        ret
    }
}

ffi_export! {
    /// Sets the application data at `idx`. 0 for NULL.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_set_ex_data(key: *mut EVP_PKEY, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(key) }) else { return 0 };
        // SAFETY: the key's own ex_data.
        unsafe { CRYPTO_set_ex_data(k.ex_data(), idx, arg) }
    }
}

ffi_export! {
    /// The application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `key` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get_ex_data(key: *const EVP_PKEY, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(key) }) else { return ptr::null_mut() };
        // SAFETY: the key's own ex_data.
        unsafe { CRYPTO_get_ex_data(k.ex_data(), idx) }
    }
}

ffi_export! {
    /// Types the key by `type_` (an ASN.1 method's key type), freeing its data. 0 with
    /// `EVP_R_UNSUPPORTED_ALGORITHM` for a type without one.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_set_type(pkey: *mut EVP_PKEY, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let k = unsafe { self::pkey(pkey) };
        c_int::from(set_type(k, type_, None, None))
    }
}

ffi_export! {
    /// Types the key by the ASN.1 method whose PEM name is the `len` characters of `str_` (all
    /// of it for -1), ignoring case.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `str_` is a string of at least `len` characters.
    pub unsafe extern "C" fn EVP_PKEY_set_type_str(pkey: *mut EVP_PKEY, str_: *const c_char, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let k = unsafe { self::pkey(pkey) };
        // SAFETY: as above.
        let Some(s) = (unsafe { text(str_) }) else { return 0 };
        let all = s.to_bytes();
        let name = if len == -1 {
            all
        } else {
            let Ok(n) = usize::try_from(len) else { return 0 };
            // OpenSSL compares `len` characters of a longer name, and none of a shorter one.
            let Some(n) = all.get(..n) else {
                return c_int::from(set_type(k, EVP_PKEY_NONE, Some(b"\0"), None));
            };
            n
        };
        c_int::from(set_type(k, EVP_PKEY_NONE, Some(name), None))
    }
}

ffi_export! {
    /// Types the key by the key manager (keeping a reference).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `keymgmt` is NULL or a live key manager.
    pub unsafe extern "C" fn EVP_PKEY_set_type_by_keymgmt(pkey: *mut EVP_PKEY, keymgmt: *mut EVP_KEYMGMT) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        // SAFETY: as above.
        let Some(km) = (unsafe { keymgmt::Ref::new(keymgmt) }) else { return 0 };
        c_int::from(set_type_by_keymgmt(k, &km))
    }
}

ffi_export! {
    /// The key's engine: always NULL, as there are no engines.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_engine(pkey: *const EVP_PKEY) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        let _ = pkey;
        ptr::null_mut()
    }
}

ffi_export! {
    /// Sets the engine whose `EVP_PKEY_METHOD` for the key's type the key's contexts use
    /// (initialized, and kept until replaced or the key is retyped or freed); NULL for none.
    /// 0 if the engine doesn't initialize (`ERR_R_ENGINE_LIB`) or has no method for the type
    /// (`EVP_R_UNSUPPORTED_ALGORITHM`).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `e` is NULL or a live engine.
    pub unsafe extern "C" fn EVP_PKEY_set1_engine(pkey: *mut EVP_PKEY, e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_set1_engine";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else {
            // OpenSSL dereferences the key.
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        if !e.is_null() {
            // SAFETY: the caller's live engine; its `init` may run (no lock is held).
            if unsafe { crate::engine::ENGINE_init(e) } == 0 {
                err::raise(ERR_LIB_EVP, rustyssl_abi::ERR_R_ENGINE_LIB, F);
                return 0;
            }
            // SAFETY: an initialized engine; its method callback may run.
            if unsafe { crate::engine::table::ENGINE_get_pkey_meth(e, k.type_()) }.is_null() {
                // SAFETY: the functional reference taken above.
                unsafe { crate::engine::ENGINE_finish(e) };
                err::raise(ERR_LIB_EVP, rustyssl_abi::EVP_R_UNSUPPORTED_ALGORITHM, F);
                return 0;
            }
        }
        k.replace_pmeth_engine(e);
        1
    }
}

ffi_export! {
    /// Whether the key lacks parameters it needs (its key manager doesn't have them).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_missing_parameters(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        c_int::from(missing_parameters(k))
    }
}

/// `EVP_PKEY_missing_parameters`.
pub(crate) fn missing_parameters(k: &Pkey) -> bool {
    if k.is_provided() {
        return !has(k, SELECT_PARAMETERS);
    }
    match k.ameth_funcs().and_then(|f| f.param_missing) {
        // SAFETY: the method's function with the key's handle.
        Some(f) => (unsafe { f(k.handle()) }) != 0,
        None => false,
    }
}

/// `EVP_PKEY_parameters_eq`.
pub(crate) fn parameters_eq(a: &Pkey, b: &Pkey) -> c_int {
    if a.is_provided() || b.is_provided() {
        return cmp_any(a, b, SELECT_PARAMETERS);
    }
    let (ta, tb) = (a.type_(), b.type_());
    if ta != tb {
        return -1;
    }
    match a.ameth_funcs().and_then(|f| f.param_cmp) {
        // SAFETY: the method's function with the keys' handles.
        Some(f) => unsafe { f(a.handle(), b.handle()) },
        None => -2,
    }
}

ffi_export! {
    /// Compares the keys' parameters: 1 equal, 0 different, -1 different types, -2 can't.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live keys.
    pub unsafe extern "C" fn EVP_PKEY_parameters_eq(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { pkey(a) }, unsafe { pkey(b) }) else { return 0 };
        parameters_eq(x, y)
    }
}

ffi_export! {
    /// `EVP_PKEY_parameters_eq`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_parameters_eq`.
    pub unsafe extern "C" fn EVP_PKEY_cmp_parameters(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_parameters_eq(a, b) }
    }
}

ffi_export! {
    /// Compares the keys (their parameters and public keys, or their key pairs when either has
    /// no public key): 1 equal, 0 different, -1 different types, -2 can't compare.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live keys.
    pub unsafe extern "C" fn EVP_PKEY_eq(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if a == b {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { pkey(a) }, unsafe { pkey(b) }) else { return 0 };
        if x.is_provided() || y.is_provided() {
            let pubkey = OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int;
            let mut selection = SELECT_PARAMETERS;
            if has(x, pubkey) && has(y, pubkey) {
                selection |= pubkey;
            } else {
                selection |= OSSL_KEYMGMT_SELECT_KEYPAIR as c_int;
            }
            return cmp_any(x, y, selection);
        }
        if x.type_() != y.type_() {
            return -1;
        }
        let Some(f) = x.ameth_funcs() else { return -2 };
        if let Some(cmp) = f.param_cmp {
            // SAFETY: the method's function with the keys' handles.
            let ret = unsafe { cmp(x.handle(), y.handle()) };
            if ret <= 0 {
                return ret;
            }
        }
        match f.pub_cmp {
            // SAFETY: as above.
            Some(cmp) => unsafe { cmp(x.handle(), y.handle()) },
            None => -2,
        }
    }
}

ffi_export! {
    /// `EVP_PKEY_eq`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_eq`.
    pub unsafe extern "C" fn EVP_PKEY_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_eq(a, b) }
    }
}

ffi_export! {
    /// Copies `from`'s parameters into `to` (typing a blank `to` like `from`): 1 if `to` has
    /// them after (also when they were already equal), else 0 with an error.
    ///
    /// # Safety
    /// `to` and `from` are NULL or live keys.
    pub unsafe extern "C" fn EVP_PKEY_copy_parameters(to: *mut EVP_PKEY, from: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_copy_parameters";
        // SAFETY: the caller's guarantee.
        let (Some(t), Some(f)) = (unsafe { pkey(to) }, unsafe { pkey(from) }) else { return 0 };
        let (to_legacy, to_blank) = {
            let s = t.lock();
            (s.is_legacy(), s.is_blank())
        };
        let from_provided = f.is_provided();
        if to_legacy && from_provided {
            // The parameters would be copied from `from`'s legacy form.
            if copy_downgraded(f).is_none() {
                return 0;
            }
        }
        if to_blank {
            let (km, from_type, from_legacy) = {
                let s = f.lock();
                (s.keymgmt.clone(), s.type_, s.is_legacy())
            };
            let ok = if from_legacy {
                set_type(Some(t), from_type, None, None)
            } else {
                match km {
                    Some(km) => set_type_by_keymgmt(t, &km),
                    // `from` is blank too: OpenSSL calls through a NULL key manager.
                    None => crate::stub::unimplemented("EVP_PKEY_copy_parameters from a blank key"),
                }
            };
            if !ok {
                return 0;
            }
        } else if to_legacy && t.type_() != f.type_() {
            err::raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES, F);
            return 0;
        }
        if missing_parameters(f) {
            err::raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS, F);
            return 0;
        }
        if !missing_parameters(t) {
            if parameters_eq(t, f) == 1 {
                return 1;
            }
            err::raise(ERR_LIB_EVP, EVP_R_DIFFERENT_PARAMETERS, F);
            return 0;
        }
        if t.is_provided() && f.is_provided() {
            return c_int::from(keymgmt_copy(t, f, SELECT_PARAMETERS));
        }
        let (to_km, to_has_data) = {
            let s = t.lock();
            (s.keymgmt.clone(), s.keydata.is_some())
        };
        if let Some(km) = to_km.filter(|_| !to_has_data) {
            // `from` is a typed key without data: there's nothing to export.
            let _ = km;
            err::raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES, F);
            return 0;
        }
        match f.ameth_funcs().and_then(|m| m.param_copy) {
            // SAFETY: the method's function with the keys' handles.
            Some(copy) => unsafe { copy(t.handle(), f.handle()) },
            None => 0,
        }
    }
}

ffi_export! {
    /// A new key with a copy of `pkey`'s data and application data; NULL with an error if it
    /// can't be copied.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_dup(pkey: *mut EVP_PKEY) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_PKEY_dup");
            return ptr::null_mut();
        };
        // SAFETY: just made, with its reference.
        let Some(dup) = (unsafe { PkeyRef::adopt(new()) }) else { return ptr::null_mut() };
        let (blank, provided) = {
            let s = k.lock();
            (s.is_blank(), s.keymgmt.is_some())
        };
        if !blank {
            if provided {
                if !keymgmt_copy(dup.get(), k, OSSL_KEYMGMT_SELECT_ALL as c_int) {
                    return ptr::null_mut();
                }
            } else {
                let (type_, empty) = {
                    let s = k.lock();
                    (s.type_, s.legacy.0.is_null())
                };
                match k.ameth_funcs().and_then(|f| f.copy) {
                    Some(copy) => {
                        // SAFETY: the method's function with the keys' handles.
                        if unsafe { copy(dup.as_ptr(), k.handle()) } == 0 {
                            return ptr::null_mut();
                        }
                    }
                    // A key without data, without a copy function: typed alike.
                    None if empty && set_type(Some(dup.get()), type_, None, None) => {}
                    None => {
                        err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_TYPE, "EVP_PKEY_dup");
                        return ptr::null_mut();
                    }
                }
            }
        }
        // SAFETY: both keys' own ex_data.
        if unsafe { CRYPTO_dup_ex_data(CRYPTO_EX_INDEX_EVP_PKEY, dup.get().ex_data(), k.ex_data()) } == 0 {
            return ptr::null_mut();
        }
        let attrs = k.attributes.load(Ordering::Acquire);
        if !attrs.is_null() {
            // SAFETY: the key's attributes.
            let copy = unsafe { attrs::deep_copy(attrs) };
            if copy.is_null() {
                return ptr::null_mut();
            }
            dup.get().attributes.store(copy, Ordering::Release);
        }
        dup.into_raw()
    }
}

ffi_export! {
    /// Has the key manager pass the selected parts of the key to `export_cb` as parameters.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `export_cb` takes `export_cbarg`.
    pub unsafe extern "C" fn EVP_PKEY_export(pkey: *const EVP_PKEY, selection: c_int, export_cb: OSSL_CALLBACK, export_cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "EVP_PKEY_export");
            return 0;
        };
        if k.lock().is_legacy() {
            let builtin = k.lock().ameth.as_ref().is_some_and(|m| !m.get().is_dynamic());
            if !builtin {
                // An application's method has no `export_to` (the reference calls through NULL;
                // docs/DEVIATIONS.md).
                return 0;
            }
            let Some(export_to) = k.ameth_funcs().and_then(|f| f.export_to) else {
                // The built-in key types of later steps export with them.
                crate::stub::unimplemented("EVP_PKEY_export of a key typed by an ASN.1 method");
            };
            // `pkey_fake_import`: the parameters go straight to the callback, whatever the
            // selection. Without a callback there's nothing to give them to.
            let Some(cb) = export_cb else { return 0 };
            // SAFETY: the caller's callback, which takes its argument.
            let mut importer = |_, params| unsafe { cb(params, export_cbarg) };
            // SAFETY: the method's key.
            return unsafe { export_to(pkey, &mut importer) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { export(k, selection, export_cb, export_cbarg) }
    }
}

/// `ossl_pkey_todata_cb`: keeps a copy of the parameters.
///
/// # Safety
/// `params` is a parameter array; `arg` is a `*mut *mut OSSL_PARAM`.
unsafe extern "C" fn todata_cb(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    let ret = arg.cast::<*mut OSSL_PARAM>();
    // SAFETY: the caller's guarantee.
    let dup = unsafe { crate::params::dup::OSSL_PARAM_dup(params) };
    // SAFETY: as above.
    unsafe { ret.write(dup) };
    1
}

ffi_export! {
    /// The selected parts of the key as a new parameter array (freed with `OSSL_PARAM_free`).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `params` is NULL or room for a pointer.
    pub unsafe extern "C" fn EVP_PKEY_todata(pkey: *const EVP_PKEY, selection: c_int, params: *mut *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if params.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee; the callback writes the caller's pointer.
        unsafe { EVP_PKEY_export(pkey, selection, Some(todata_cb), params.cast()) }
    }
}

/// `evp_keymgmt_util_get_deflt_digest_name`: 2 for a mandatory digest, 1 for a default one (its
/// name, or `UNDEF` for an empty one, in `mdname`), -2 for none, 0 if the key manager fails.
///
/// # Safety
/// `mdname` has room for `mdname_sz` characters.
pub(crate) unsafe fn default_digest_name(
    km: &Keymgmt,
    keydata: *mut c_void,
    mdname: *mut c_char,
    mdname_sz: usize,
) -> c_int {
    let mut mddefault = [0u8; 100];
    let mut mdmandatory = [0u8; 100];
    // SAFETY: a static key; a local buffer that outlives the array, here and below.
    let p0 = unsafe {
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_DEFAULT_DIGEST.as_ptr(),
            mddefault.as_mut_ptr().cast(),
            mddefault.len(),
        )
    };
    // SAFETY: as above.
    let p1 = unsafe {
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_MANDATORY_DIGEST.as_ptr(),
            mdmandatory.as_mut_ptr().cast(),
            mdmandatory.len(),
        )
    };
    let mut params = [p0, p1, end()];
    // SAFETY: the key manager's data; the array above.
    if unsafe { km.get_params(keydata, params.as_mut_ptr()) } == 0 {
        return 0;
    }
    let [default, mandatory, _] = &params;
    let pick = |p: &OSSL_PARAM, buf: &[u8]| -> Vec<u8> {
        if p.return_size <= 1 {
            SN_undef.to_bytes().to_vec()
        } else {
            buf.split(|&c| c == 0).next().unwrap_or(&[]).to_vec()
        }
    };
    // SAFETY: parameters of the array.
    let (result, rv) = if unsafe { OSSL_PARAM_modified(mandatory) } != 0 {
        (pick(mandatory, &mdmandatory), 2)
    // SAFETY: as above.
    } else if unsafe { OSSL_PARAM_modified(default) } != 0 {
        (pick(default, &mddefault), 1)
    } else {
        return -2;
    };
    // SAFETY: the caller's guarantee.
    unsafe { strlcpy(mdname, mdname_sz, &result) };
    rv
}

/// `OPENSSL_strlcpy` of `src` into `dst`, which has room for `size` characters (nothing for
/// NULL).
///
/// # Safety
/// `dst` is NULL or has room for `size` characters.
unsafe fn strlcpy(dst: *mut c_char, size: usize, src: &[u8]) {
    if size > 0 && !dst.is_null() {
        let n = src.len().min(size - 1);
        // SAFETY: the caller's buffer has room for `size` characters.
        unsafe { ptr::copy_nonoverlapping(src.as_ptr().cast(), dst, n) };
        // SAFETY: as above: `n` is below `size`.
        unsafe { dst.wrapping_add(n).write(0) };
    }
}

/// `evp_pkey_asn1_ctrl` of a key with an ASN.1 method: its ctrl's answer, -2 without one;
/// `None` for a key without a method.
///
/// # Safety
/// `arg2` is what the command needs.
pub(crate) unsafe fn asn1_ctrl(
    k: &Pkey,
    op: c_int,
    arg1: c_long,
    arg2: *mut c_void,
) -> Option<c_int> {
    let f = k.ameth_funcs()?;
    Some(match f.pkey_ctrl {
        // SAFETY: the method's function with the key's handle; the caller's guarantee.
        Some(ctrl) => unsafe { ctrl(k.handle(), op, arg1, arg2) },
        None => -2,
    })
}

/// [`asn1_ctrl`] of the key behind a pointer: `None` for NULL or a key without an ASN.1
/// method.
///
/// # Safety
/// `pkey` is NULL or a live key; `arg2` is what the command needs.
pub(crate) unsafe fn asn1_ctrl_of(
    pkey: *mut EVP_PKEY,
    op: c_int,
    arg1: c_long,
    arg2: *mut c_void,
) -> Option<c_int> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { self::pkey(pkey) }?;
    // SAFETY: as above.
    unsafe { asn1_ctrl(k, op, arg1, arg2) }
}

ffi_export! {
    /// The name of the digest the key signs with by default into `mdname`: 2 if it's
    /// mandatory, 1 if it's a default, -2 if there's none, 0 on failure.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `mdname` has room for `mdname_sz` characters.
    pub unsafe extern "C" fn EVP_PKEY_get_default_digest_name(pkey: *mut EVP_PKEY, mdname: *mut c_char, mdname_sz: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        let mut nid = NID_undef;
        // SAFETY: room for the NID.
        if let Some(rv) = unsafe { asn1_ctrl(k, ASN1_PKEY_CTRL_DEFAULT_MD_NID, 0, (&raw mut nid).cast()) } {
            if rv > 0 {
                // SAFETY: a number.
                let sn = unsafe { OBJ_nid2sn(nid) };
                // SAFETY: NULL or a static name.
                let name = unsafe { text(sn) }.map_or(&b""[..], CStr::to_bytes);
                // SAFETY: the caller's buffer.
                unsafe { strlcpy(mdname, mdname_sz, name) };
            }
            return rv;
        }
        let (Some(km), kd) = k.provided() else {
            // OpenSSL calls through a NULL key manager.
            crate::stub::unimplemented("EVP_PKEY_get_default_digest_name of a blank key");
        };
        let ptr = kd.as_ref().map_or(ptr::null_mut(), |d| d.ptr());
        // SAFETY: the key manager's data; the caller's buffer.
        unsafe { default_digest_name(km.get(), ptr, mdname, mdname_sz) }
    }
}

ffi_export! {
    /// The digest the key signs with by default, as a NID in `pnid`: as
    /// `EVP_PKEY_get_default_digest_name`.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `pnid` is room for an int.
    pub unsafe extern "C" fn EVP_PKEY_get_default_digest_nid(pkey: *mut EVP_PKEY, pnid: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        // SAFETY: the caller's guarantee: room for the NID.
        if let Some(rv) = unsafe { asn1_ctrl(k, ASN1_PKEY_CTRL_DEFAULT_MD_NID, 0, pnid.cast()) } {
            return rv;
        }
        if !k.is_provided() {
            return 0;
        }
        let mut name = [0 as c_char; 80];
        // SAFETY: the caller's key; the buffer above.
        let rv = unsafe { EVP_PKEY_get_default_digest_name(pkey, name.as_mut_ptr(), name.len()) };
        if rv > 0 {
            // SAFETY: a NUL-terminated name.
            let n = unsafe { CStr::from_ptr(name.as_ptr()) };
            let (Some(km), _) = k.provided() else { return 0 };
            let Some(nid) = digest_nid(km.get(), n) else { return 0 };
            if !pnid.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { pnid.write(nid) };
            }
        }
        rv
    }
}

ffi_export! {
    /// Whether the key can sign: for a provided key, whether a signature algorithm of its key
    /// manager's signing name can be fetched (its errors left if not); for a typed key, by its
    /// base type.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_can_sign(pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        let Some(km) = k.provided().0 else {
            return match ameth::pkey_type(k.type_()) {
                rustyssl_abi::EVP_PKEY_RSA
                | rustyssl_abi::EVP_PKEY_RSA_PSS
                | EVP_PKEY_DSA
                | rustyssl_abi::EVP_PKEY_ED25519
                | rustyssl_abi::EVP_PKEY_ED448 => 1,
                EVP_PKEY_EC => {
                    // SAFETY: the caller's key.
                    let ec = unsafe { super::pkey::ec::EVP_PKEY_get0_EC_KEY(pkey) };
                    // SAFETY: its EC key, or NULL.
                    unsafe { crate::ec::key::EC_KEY_can_sign(ec) }
                }
                _ => 0,
            };
        };
        let name = km.get().query_operation_name(rustyssl_abi::OSSL_OP_SIGNATURE);
        // SAFETY: the key manager's live provider.
        let libctx = unsafe { crate::provider::libctx_of(km.get().prov.0) };
        // SAFETY: the provider's context; the name.
        let sig = unsafe { super::signature::fetch_by_name(libctx, &name, None) };
        c_int::from(sig.is_some())
    }
}

ffi_export! {
    /// The key's legacy data (what `EVP_PKEY_assign` gave it); NULL for a provided key.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0(pkey: *const EVP_PKEY) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return ptr::null_mut() };
        let s = k.lock();
        if s.keymgmt.is_some() {
            return ptr::null_mut();
        }
        s.legacy.0
    }
}

ffi_export! {
    /// Types the key by `type_` (freeing its data) and gives it `key`, the legacy data of the
    /// type's ASN.1 method, which then owns it. 1, or 0 if there's no method for the type or
    /// `key` is NULL (the key is typed all the same).
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key` is NULL or the data the type's method expects.
    pub unsafe extern "C" fn EVP_PKEY_assign(pkey: *mut EVP_PKEY, type_: c_int, key: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::pkey(pkey) }) else { return 0 };
        let base = ameth::find(type_).map(|m| (m.get().base_id, m.get().is_dynamic()));
        let rsa = matches!(base, Some((EVP_PKEY_RSA | EVP_PKEY_RSA_PSS, false)));
        let ec = matches!(base, Some((rustyssl_abi::EVP_PKEY_EC, false)));
        let dh = matches!(base, Some((rustyssl_abi::EVP_PKEY_DH | rustyssl_abi::EVP_PKEY_DHX, false)));
        let dsa = matches!(base, Some((EVP_PKEY_DSA, false)));
        let ecx = matches!(
            base,
            Some((
                rustyssl_abi::EVP_PKEY_X25519
                    | rustyssl_abi::EVP_PKEY_X448
                    | rustyssl_abi::EVP_PKEY_ED25519
                    | rustyssl_abi::EVP_PKEY_ED448,
                false
            ))
        );
        if !key.is_null() && base.is_some_and(|(_, dynamic)| !dynamic) && !rsa && !ec && !ecx && !dh && !dsa {
            // The other built-in key types' data come with them.
            crate::stub::unimplemented("EVP_PKEY_assign of a built-in key type's data");
        }
        let mut type_ = type_;
        if ec && !key.is_null() {
            // Whatever is asked, SM2's curve is SM2's type and any other curve EC's.
            // SAFETY: the caller's guarantee: an `EC_KEY`.
            let g = unsafe { crate::ec::key::EC_KEY_get0_group(key.cast()) };
            if !g.is_null() {
                // SAFETY: its group.
                let curve = unsafe { crate::ec::group::EC_GROUP_get_curve_name(g) };
                // SAFETY: no preconditions.
                let pktype = unsafe { EVP_PKEY_type(type_) };
                if curve == rustyssl_abi::NID_sm2 && pktype == rustyssl_abi::EVP_PKEY_EC {
                    type_ = rustyssl_abi::EVP_PKEY_SM2;
                } else if curve != rustyssl_abi::NID_sm2 && pktype == rustyssl_abi::EVP_PKEY_SM2 {
                    type_ = rustyssl_abi::EVP_PKEY_EC;
                }
            }
        }
        if !set_type(Some(k), type_, None, None) {
            return 0;
        }
        // `detect_foreign_key`: an `RSA`, (EC's type, not SM2's) an `EC_KEY`, a `DSA`, or (DH's
        // type, not DHX's) a `DH` whose method isn't OpenSSL's.
        let foreign = if rsa {
            // SAFETY: the caller's guarantee: an `RSA`.
            let meth = unsafe { crate::rsa::rsa(key.cast()) }.map(crate::rsa::Rsa::meth);
            // SAFETY: no preconditions.
            meth.is_some_and(|m| m != unsafe { crate::rsa_meth::RSA_PKCS1_OpenSSL() })
        } else if ec && type_ == rustyssl_abi::EVP_PKEY_EC && !key.is_null() {
            // SAFETY: the caller's guarantee: an `EC_KEY`.
            let m = unsafe { crate::ec::key::EC_KEY_get_method(key.cast()) };
            // SAFETY: no preconditions.
            m != unsafe { crate::ec::key::EC_KEY_OpenSSL() }
        } else if dsa && type_ == EVP_PKEY_DSA {
            // SAFETY: the caller's guarantee: a `DSA`, or NULL.
            unsafe { super::pkey::dsa::is_foreign(key.cast()) }
        } else if dh && type_ == rustyssl_abi::EVP_PKEY_DH {
            // SAFETY: the caller's guarantee: a `DH`, or NULL.
            unsafe { super::pkey::dh::is_foreign(key.cast()) }
        } else {
            false
        };
        let mut s = k.lock();
        s.legacy = Ptr(key);
        s.foreign = foreign;
        c_int::from(!key.is_null())
    }
}

/// `EVP_PKEY_get0_hmac` and its kin: the raw key of a legacy MAC key of `type_`.
///
/// # Safety
/// `pkey` is NULL or a live key.
unsafe fn get0_mac(
    pkey: *const EVP_PKEY,
    type_: c_int,
    reason: c_int,
    function: &str,
) -> *const u8 {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { self::pkey(pkey) }) else {
        return ptr::null();
    };
    if k.type_() != type_ {
        err::raise(ERR_LIB_EVP, reason, function);
        return ptr::null();
    }
    // `evp_pkey_get_legacy`: a provided key's legacy form, which a MAC key can't have.
    if copy_downgraded(k).is_none() {
        return ptr::null();
    }
    ptr::null()
}

ffi_export! {
    /// The raw key of an HMAC key with legacy data, or NULL (always, as the MAC key types have
    /// no legacy form) with `EVP_R_EXPECTING_AN_HMAC_KEY` for another type.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `len` is room for a size.
    pub unsafe extern "C" fn EVP_PKEY_get0_hmac(pkey: *const EVP_PKEY, len: *mut usize) -> *const u8
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        let _ = len;
        // SAFETY: the caller's guarantee.
        unsafe { get0_mac(pkey, rustyssl_abi::EVP_PKEY_HMAC, EVP_R_EXPECTING_AN_HMAC_KEY, "EVP_PKEY_get0_hmac") }
    }
}

ffi_export! {
    /// As `EVP_PKEY_get0_hmac` for a Poly1305 key.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `len` is room for a size.
    pub unsafe extern "C" fn EVP_PKEY_get0_poly1305(pkey: *const EVP_PKEY, len: *mut usize) -> *const u8
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        let _ = len;
        // SAFETY: the caller's guarantee.
        unsafe { get0_mac(pkey, rustyssl_abi::EVP_PKEY_POLY1305, EVP_R_EXPECTING_A_POLY1305_KEY, "EVP_PKEY_get0_poly1305") }
    }
}

ffi_export! {
    /// As `EVP_PKEY_get0_hmac` for a SipHash key.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `len` is room for a size.
    pub unsafe extern "C" fn EVP_PKEY_get0_siphash(pkey: *const EVP_PKEY, len: *mut usize) -> *const u8
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        let _ = len;
        // SAFETY: the caller's guarantee.
        unsafe { get0_mac(pkey, rustyssl_abi::EVP_PKEY_SIPHASH, EVP_R_EXPECTING_A_SIPHASH_KEY, "EVP_PKEY_get0_siphash") }
    }
}

/// `legacy_asn1_ctrl_to_param`'s digest lookup: the NID of the first of the digest's names
/// (in the key manager's context) that is an object's short or long name, or `NID_undef`;
/// `None` if the name isn't known there.
fn digest_nid(km: &Keymgmt, name: &CStr) -> Option<c_int> {
    let libctx = {
        // SAFETY: the key manager's live provider.
        unsafe { crate::provider::libctx_of(km.prov.0) }
    };
    // Fetched only so the digest's names are in the name map.
    // SAFETY: no preconditions.
    unsafe { err::ERR_set_mark() };
    // SAFETY: the provider's context; a string.
    let md = unsafe { super::digest::EVP_MD_fetch(libctx, name.as_ptr(), ptr::null()) };
    // SAFETY: the mark set above.
    unsafe { err::ERR_pop_to_mark() };
    // SAFETY: the reference fetched above, or NULL.
    unsafe { super::digest::EVP_MD_free(md) };
    let num = super::fetch::number_in(km.prov.0, name.to_bytes());
    if num == 0 {
        return None;
    }
    let mut nid = NID_undef;
    for n in super::fetch::names_of(km.prov.0, num) {
        if nid != NID_undef {
            break;
        }
        let Ok(c) = CString::new(n) else { continue };
        // SAFETY: a string.
        nid = unsafe { crate::objects::OBJ_sn2nid(c.as_ptr()) };
        if nid == NID_undef {
            // SAFETY: as above.
            nid = unsafe { crate::objects::OBJ_ln2nid(c.as_ptr()) };
        }
    }
    Some(nid)
}

#[cfg(test)]
mod tests {
    use super::params::{EVP_PKEY_get_params, EVP_PKEY_set_params};
    use super::raw::{
        EVP_PKEY_get_raw_private_key, EVP_PKEY_new_CMAC_key, EVP_PKEY_new_raw_private_key,
    };
    use super::*;
    use crate::evp::pkey_ctx::{
        EVP_PKEY_CTX_free, EVP_PKEY_CTX_get_keygen_info, EVP_PKEY_CTX_new,
        EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_new_id, EVP_PKEY_CTX_set_mac_key,
        EVP_PKEY_CTX_set0_keygen_info, EVP_PKEY_keygen, EVP_PKEY_keygen_init,
    };

    /// A library context of its own: fetching from it loads no configuration, which Miri
    /// can't run.
    fn libctx() -> *mut OSSL_LIB_CTX {
        // SAFETY: no preconditions.
        unsafe { crate::libctx::OSSL_LIB_CTX_new() }
    }

    /// The raw private key of `k`.
    fn raw(k: *const EVP_PKEY) -> Option<Vec<u8>> {
        let mut buf = [0u8; 64];
        let mut len = buf.len();
        // SAFETY: a live key; the buffer above.
        let r = unsafe { EVP_PKEY_get_raw_private_key(k, buf.as_mut_ptr(), &raw mut len) };
        (r == 1).then(|| buf.get(..len).unwrap_or_default().to_vec())
    }

    /// docs/DEVIATIONS.md: NULL keys are refused (the reference crashes).
    #[test]
    fn null_keys_are_refused() {
        let k: *mut EVP_PKEY = ptr::null_mut();
        let mut len = 0usize;
        // SAFETY: NULL is the case under test, here and below.
        assert_eq!(unsafe { EVP_PKEY_up_ref(k) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_get_id(k) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_get_base_id(k) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_get0_type_name(k) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_get0_description(k) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_save_parameters(k, 1) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_set_ex_data(k, 1, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_get_ex_data(k, 1) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_set_type(k, EVP_PKEY_DSA) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_set_type_str(k, c"RSA".as_ptr(), -1) }, 1);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_set_type_by_keymgmt(k, ptr::null_mut()) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_set1_engine(k, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_copy_parameters(k, k) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_parameters_eq(k, k) }, 0);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_get_raw_private_key(k, ptr::null_mut(), &raw mut len) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_get_default_digest_name(k, ptr::null_mut(), 0) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_get0_hmac(k, &raw mut len) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_get_params(k, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_set_params(k, ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_dup(k) }.is_null());
        crate::err::take_all();
    }

    /// An engine without a key method for the type gives neither a key nor a context.
    #[test]
    fn engines_without_key_methods_are_refused() {
        // SAFETY: no preconditions.
        let e = unsafe { crate::engine::ENGINE_new() };
        assert!(!e.is_null());
        let key = [7u8; 16];
        // SAFETY: a live engine; the key's octets.
        let k = unsafe {
            EVP_PKEY_new_raw_private_key(rustyssl_abi::EVP_PKEY_HMAC, e, key.as_ptr(), 16)
        };
        assert!(k.is_null());
        // SAFETY: a live engine.
        assert!(unsafe { EVP_PKEY_CTX_new_id(rustyssl_abi::EVP_PKEY_HMAC, e) }.is_null());
        // SAFETY: no preconditions.
        let cipher = unsafe { crate::evp::legacy_cipher::EVP_aes_128_cbc() };
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_new_CMAC_key(e, key.as_ptr(), 16, cipher) }.is_null());
        let p = new();
        // SAFETY: a live key and engine.
        assert_eq!(unsafe { EVP_PKEY_set1_engine(p, e) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_PKEY_CTX_new(p, e) }.is_null());
        // SAFETY: made above.
        unsafe { EVP_PKEY_free(p) };
        // SAFETY: the engine made above, its last reference.
        unsafe { crate::engine::ENGINE_free(e) };
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: `EVP_PKEY_CTX_get_keygen_info` past the end, or without an array,
    /// gives 0 (the reference reads past the array, or through NULL).
    #[test]
    fn keygen_info_past_the_end_is_zero() {
        let lib = libctx();
        // SAFETY: the context; a static name.
        let c = unsafe { EVP_PKEY_CTX_new_from_name(lib, c"HMAC".as_ptr(), ptr::null()) };
        assert!(!c.is_null());
        let mut info = [5, 6];
        // SAFETY: the context above; the array of two.
        unsafe { EVP_PKEY_CTX_set0_keygen_info(c, info.as_mut_ptr(), 2) };
        // SAFETY: the context above, here and below.
        assert_eq!(unsafe { EVP_PKEY_CTX_get_keygen_info(c, 1) }, 6);
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_get_keygen_info(c, 2) }, 0);
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_set0_keygen_info(c, ptr::null_mut(), 2) };
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_CTX_get_keygen_info(c, 0) }, 0);
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(c) };
        // SAFETY: made above, its keys freed.
        unsafe { crate::libctx::OSSL_LIB_CTX_free(lib) };
    }

    /// An HMAC key through its lifecycle: made raw, exported, copied, compared, regenerated.
    #[test]
    fn mac_keys_round_trip() {
        let key = *b"0123456789abcdef";
        let lib = libctx();
        // SAFETY: the context; a static name; the key's octets.
        let k = unsafe {
            super::raw::EVP_PKEY_new_raw_private_key_ex(
                lib,
                c"HMAC".as_ptr(),
                ptr::null(),
                key.as_ptr(),
                16,
            )
        };
        assert!(!k.is_null());
        // SAFETY: the key above, here and below.
        assert_eq!(unsafe { EVP_PKEY_get_id(k) }, EVP_PKEY_KEYMGMT);
        assert_eq!(raw(k).as_deref(), Some(&key[..]));
        // SAFETY: as above.
        let d = unsafe { EVP_PKEY_dup(k) };
        assert_eq!(raw(d).as_deref(), Some(&key[..]));
        // SAFETY: both keys.
        assert_eq!(unsafe { EVP_PKEY_eq(k, d) }, 1);
        let mut out: *mut OSSL_PARAM = ptr::null_mut();
        // SAFETY: the key; room for the array.
        let got =
            unsafe { EVP_PKEY_todata(k, rustyssl_abi::EVP_PKEY_KEYPAIR as c_int, &raw mut out) };
        assert_eq!(got, 1);
        // SAFETY: the array made by the export.
        unsafe { crate::params::dup::OSSL_PARAM_free(out) };

        // SAFETY: the key.
        let c = unsafe { EVP_PKEY_CTX_new(k, ptr::null_mut()) };
        // SAFETY: the context, here and below.
        assert_eq!(unsafe { EVP_PKEY_keygen_init(c) }, 1);
        let other = [9u8; 8];
        // SAFETY: as above; the octets.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_mac_key(c, other.as_ptr(), 8) }, 1);
        let mut g: *mut EVP_PKEY = ptr::null_mut();
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_keygen(c, &raw mut g) }, 1);
        assert_eq!(raw(g).as_deref(), Some(&other[..]));
        // SAFETY: made above.
        unsafe { EVP_PKEY_CTX_free(c) };
        for p in [k, d, g] {
            // SAFETY: made above.
            unsafe { EVP_PKEY_free(p) };
        }
        let mut params = [end()];
        // SAFETY: a blank key; the array.
        let b = new();
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_PKEY_get_params(b, params.as_mut_ptr()) }, 0);
        // SAFETY: made above.
        unsafe { EVP_PKEY_free(b) };
        // SAFETY: made above, its keys freed.
        unsafe { crate::libctx::OSSL_LIB_CTX_free(lib) };
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: key data for a key typed by name (which keeps its type, so gets no
    /// key manager) is refused (the reference uses the NULL key manager).
    #[test]
    fn keys_typed_by_name_take_no_data() {
        let lib = libctx();
        let k = new();
        // SAFETY: the key above; a static name.
        assert_eq!(unsafe { EVP_PKEY_set_type_str(k, c"DH".as_ptr(), -1) }, 1);
        // SAFETY: a static name.
        let c = unsafe { EVP_PKEY_CTX_new_from_name(lib, c"HMAC".as_ptr(), ptr::null()) };
        // SAFETY: the context, here and below.
        assert_eq!(unsafe { EVP_PKEY_keygen_init(c) }, 1);
        let key = [1u8; 4];
        // SAFETY: as above; the octets.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_mac_key(c, key.as_ptr(), 4) }, 1);
        let mut out = k;
        // SAFETY: as above; the key.
        assert_eq!(unsafe { EVP_PKEY_keygen(c, &raw mut out) }, 0);
        // SAFETY: the key.
        assert!(!unsafe { pkey(k) }.is_some_and(|p| p.lock().is_assigned()));
        // SAFETY: made above.
        unsafe { EVP_PKEY_CTX_free(c) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
        // SAFETY: made above, its keys freed.
        unsafe { crate::libctx::OSSL_LIB_CTX_free(lib) };
        crate::err::take_all();
    }

    /// The type table: aliases resolve, PEM names ignore case, and the standard names win.
    #[test]
    fn key_types() {
        assert_eq!(
            ameth::pkey_type(rustyssl_abi::EVP_PKEY_RSA2),
            rustyssl_abi::EVP_PKEY_RSA
        );
        assert_eq!(ameth::pkey_type(rustyssl_abi::EVP_PKEY_DSA3), NID_undef);
        assert_eq!(ameth::pkey_type(rustyssl_abi::EVP_PKEY_SM2), EVP_PKEY_EC);
        assert!(ameth::find_str(b"x9.42 dh").is_some());
        assert!(ameth::find_str(b"DHX").is_none());
        assert_eq!(ameth::name2type(b"dhx"), rustyssl_abi::EVP_PKEY_DHX);
        assert_eq!(
            ameth::name2type(b"rsaEncryption"),
            rustyssl_abi::EVP_PKEY_RSA
        );
        assert_eq!(ameth::name2type(b"HMAC"), NID_undef);
    }
}
