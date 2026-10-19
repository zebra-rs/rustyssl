//! The method tables (`eng_table.c`, `tb_*.c`, `eng_fat.c`): per kind of method, the engines
//! registered for each NID (the RSA, DSA, DH, EC and RAND tables use the one NID 1), and the
//! default each NID resolves to.
//!
//! A table's engine piles hold a structural reference to each engine in them, where OpenSSL's
//! hold bare pointers: an application that frees an engine it registered without unregistering
//! it leaves OpenSSL's tables pointing at freed memory, and here only delays the engine's
//! `destroy` until it's unregistered or the tables are cleaned up (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::ptr;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU32, Ordering};

use rustyssl_abi::{
    ENGINE, ENGINE_FLAGS_NO_REGISTER_ALL, ENGINE_METHOD_ALL, ENGINE_METHOD_CIPHERS,
    ENGINE_METHOD_DH, ENGINE_METHOD_DIGESTS, ENGINE_METHOD_DSA, ENGINE_METHOD_EC,
    ENGINE_METHOD_PKEY_ASN1_METHS, ENGINE_METHOD_PKEY_METHS, ENGINE_METHOD_RAND, ENGINE_METHOD_RSA,
    ENGINE_PKEY_ASN1_METHS_PTR, ENGINE_PKEY_METHS_PTR, ENGINE_R_INIT_FAILED,
    ENGINE_R_INVALID_STRING, ENGINE_R_UNIMPLEMENTED_CIPHER, ENGINE_R_UNIMPLEMENTED_DIGEST,
    ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD, ENGINE_TABLE_FLAG_NOINIT, ERR_LIB_ENGINE, EVP_CIPHER,
    EVP_MD, EVP_PKEY_ASN1_METHOD, EVP_PKEY_METHOD, OPENSSL_INIT_LOAD_CONFIG,
};

use super::{
    EnginePtr, Fields, Guard, engine, fields, finish_locked, free_util, free_util_locked, global,
    init_locked, up_struct,
};
use crate::err;
use crate::ffi::ffi_export;

/// The kinds of method an engine can implement, one table each.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Rsa,
    Dsa,
    Dh,
    Ec,
    Rand,
    Ciphers,
    Digests,
    PkeyMeths,
    PkeyAsn1Meths,
}

const CLASSES: usize = 9;

impl Class {
    fn index(self) -> usize {
        self as usize
    }
}

/// The engines registered for one NID (`ENGINE_PILE`).
struct Pile {
    /// In registration order, each once; the pile holds a structural reference to each.
    engines: Vec<EnginePtr>,
    /// The default, with a functional reference.
    funct: Option<EnginePtr>,
    /// Whether `funct` is what a lookup would pick now.
    uptodate: bool,
}

/// One kind's table, made at its first registration.
struct Table {
    piles: BTreeMap<c_int, Pile>,
}

/// The tables, and the order they were made in (OpenSSL cleans them up newest first).
pub(super) struct Tables {
    tables: [Option<Table>; CLASSES],
    made: Vec<usize>,
}

impl Tables {
    pub(super) const fn new() -> Self {
        const NONE: Option<Table> = None;
        Self {
            tables: [NONE; CLASSES],
            made: Vec::new(),
        }
    }

    fn table(&mut self, class: Class) -> Option<&mut Table> {
        self.tables.get_mut(class.index())?.as_mut()
    }

    fn pile(&mut self, class: Class, nid: c_int) -> Option<&mut Pile> {
        self.table(class)?.piles.get_mut(&nid)
    }
}

/// `ENGINE_set_table_flags`' flags.
static TABLE_FLAGS: AtomicU32 = AtomicU32::new(0);

/// The NID the single-method tables use (`dummy_nid`).
const DUMMY_NID: c_int = 1;

/// `engine_unlocked_init` on an engine the caller found in a table, kept alive across the
/// unlocked `init`.
///
/// # Safety
/// `e` is a live engine.
unsafe fn init_held(g: Guard, e: *mut ENGINE) -> (Guard, c_int) {
    // SAFETY: the caller's guarantee; this reference is dropped below.
    unsafe { up_struct(e) };
    // SAFETY: as above.
    let (g, r) = unsafe { init_locked(g, e) };
    // SAFETY: the reference taken above.
    (unsafe { free_util_locked(g, e) }, r)
}

/// `engine_table_register`: adds `e` to (the end of) the piles of `nids`, making it their
/// default if `setdefault`. 1, or 0 if it was to be the default and its `init` failed.
///
/// # Safety
/// `e` is a live engine.
unsafe fn register(class: Class, e: *mut ENGINE, nids: &[c_int], setdefault: bool) -> c_int {
    let mut g = global();
    if g.tables.table(class).is_none() {
        if let Some(slot) = g.tables.tables.get_mut(class.index()) {
            *slot = Some(Table {
                piles: BTreeMap::new(),
            });
        }
        g.tables.made.push(class.index());
    }
    for &nid in nids {
        let Some(t) = g.tables.table(class) else {
            return 0;
        };
        let pile = t.piles.entry(nid).or_insert_with(|| Pile {
            engines: Vec::new(),
            funct: None,
            uptodate: true,
        });
        if let Some(i) = pile.engines.iter().position(|&p| p == EnginePtr(e)) {
            pile.engines.remove(i);
        } else {
            // SAFETY: the caller's guarantee; the pile's reference.
            unsafe { up_struct(e) };
        }
        pile.engines.push(EnginePtr(e));
        pile.uptodate = false;
        if setdefault {
            let r;
            // SAFETY: as above.
            (g, r) = unsafe { init_held(g, e) };
            if r == 0 {
                err::raise(
                    ERR_LIB_ENGINE,
                    ENGINE_R_INIT_FAILED,
                    "engine_table_register",
                );
                return 0;
            }
            let old = match g.tables.pile(class, nid) {
                Some(p) => {
                    p.uptodate = true;
                    p.funct.replace(EnginePtr(e))
                }
                // The table went while `init` ran: the reference goes back.
                None => Some(EnginePtr(e)),
            };
            if let Some(old) = old {
                // SAFETY: the pile's functional reference to the engine it replaces.
                (g, _) = unsafe { finish_locked(g, old.0) };
            }
        }
    }
    1
}

/// `engine_table_unregister`: takes `e` out of every pile of the kind.
///
/// # Safety
/// `e` is a live engine.
unsafe fn unregister(class: Class, e: *mut ENGINE) {
    let mut g = global();
    let nids: Vec<c_int> = match g.tables.table(class) {
        Some(t) => t.piles.keys().copied().collect(),
        None => return,
    };
    for nid in nids {
        let (listed, funct) = match g.tables.pile(class, nid) {
            Some(p) => {
                let listed = match p.engines.iter().position(|&q| q == EnginePtr(e)) {
                    Some(i) => {
                        p.engines.remove(i);
                        p.uptodate = false;
                        true
                    }
                    None => false,
                };
                let funct = p.funct == Some(EnginePtr(e));
                if funct {
                    p.funct = None;
                }
                (listed, funct)
            }
            None => (false, false),
        };
        if funct {
            // SAFETY: the pile's functional reference.
            (g, _) = unsafe { finish_locked(g, e) };
        }
        if listed {
            // SAFETY: the pile's structural reference.
            g = unsafe { free_util_locked(g, e) };
        }
    }
}

/// `ossl_engine_table_select`: the engine a NID resolves to in the kind's table, with a
/// functional reference, or NULL. The default if it initializes; else, unless the pile is
/// up to date, the first registered engine that initializes, which becomes the default.
fn select(class: Class, nid: c_int) -> *mut ENGINE {
    let flag = u64::try_from(OPENSSL_INIT_LOAD_CONFIG).unwrap_or(0);
    // SAFETY: no settings.
    unsafe { crate::init::OPENSSL_init_crypto(flag, ptr::null()) };
    let mut g = global();
    if g.tables.table(class).is_none() {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    unsafe { crate::err::ERR_set_mark() };
    let mut ret = ptr::null_mut();
    'end: {
        let Some(p) = g.tables.pile(class, nid) else {
            break 'end;
        };
        if let Some(f) = p.funct {
            let r;
            // SAFETY: the pile's default is live.
            (g, r) = unsafe { init_held(g, f.0) };
            if r != 0 {
                ret = f.0;
                break 'end;
            }
        }
        match g.tables.pile(class, nid) {
            Some(p) if p.uptodate => {
                ret = p.funct.map_or(ptr::null_mut(), |f| f.0);
                break 'end;
            }
            Some(_) => {}
            None => break 'end,
        }
        let mut i = 0usize;
        loop {
            let Some(e) = g
                .tables
                .pile(class, nid)
                .and_then(|p| p.engines.get(i).copied())
            else {
                break 'end;
            };
            i = i.saturating_add(1);
            // SAFETY: the pile's engines are live.
            let initialized =
                unsafe { engine(e.0) }.is_some_and(|en| en.funct_ref.load(Ordering::Acquire) > 0);
            let noinit = TABLE_FLAGS.load(Ordering::Relaxed) & ENGINE_TABLE_FLAG_NOINIT != 0;
            let mut initres = 0;
            if initialized || !noinit {
                // SAFETY: as above.
                (g, initres) = unsafe { init_held(g, e.0) };
            }
            if initres == 0 {
                continue;
            }
            let current = g.tables.pile(class, nid).and_then(|p| p.funct);
            if current != Some(e) {
                let r;
                // SAFETY: as above.
                (g, r) = unsafe { init_held(g, e.0) };
                if r != 0 {
                    let old = match g.tables.pile(class, nid) {
                        Some(p) => p.funct.replace(e),
                        None => Some(e),
                    };
                    if let Some(old) = old {
                        // SAFETY: the pile's functional reference.
                        (g, _) = unsafe { finish_locked(g, old.0) };
                    }
                }
            }
            ret = e.0;
            break 'end;
        }
    }
    if let Some(p) = g.tables.pile(class, nid) {
        p.uptodate = true;
    }
    drop(g);
    // SAFETY: the mark set above.
    unsafe { crate::err::ERR_pop_to_mark() };
    ret
}

/// `engine_table_cleanup` for every table, newest first: the piles' references dropped and
/// their defaults finished; then the engine list emptied (`engine_list_cleanup`). For
/// `OPENSSL_cleanup`.
pub(crate) fn cleanup() {
    let made: Vec<usize> = core::mem::take(&mut global().tables.made);
    for class in made.into_iter().rev() {
        let table = global().tables.tables.get_mut(class).and_then(Option::take);
        let Some(table) = table else { continue };
        for (_, pile) in table.piles {
            if let Some(f) = pile.funct {
                // SAFETY: the pile's functional reference.
                drop(unsafe { finish_locked(global(), f.0) });
            }
            for e in pile.engines {
                // SAFETY: the pile's structural reference.
                unsafe { free_util(e.0) };
            }
        }
    }
    loop {
        let head = global().list.first().copied();
        let Some(head) = head else { break };
        // SAFETY: the listed engine.
        unsafe { super::list::ENGINE_remove(head.0) };
    }
}

/// The NIDs an engine's NID callback lists (`cb(e, NULL, &nids, 0)`), copied.
///
/// # Safety
/// `nids` and `n` are what such a callback returned.
unsafe fn nid_list(nids: *const c_int, n: c_int) -> Vec<c_int> {
    let Ok(n) = usize::try_from(n) else {
        return Vec::new();
    };
    if n == 0 || nids.is_null() {
        return Vec::new();
    }
    // SAFETY: the callback's contract: `nids` points to `n` NIDs.
    unsafe { core::slice::from_raw_parts(nids, n) }.to_vec()
}

/// The NIDs `e` implements for the kind, from its callback (none without one).
///
/// # Safety
/// `e` is a live engine.
unsafe fn nids_of(class: Class, e: *mut ENGINE, f: &Fields) -> Vec<c_int> {
    let mut nids: *const c_int = ptr::null();
    let out = &raw mut nids;
    // The engine's own callbacks, asked for their NIDs; no lock is held.
    let n = match class {
        Class::Ciphers => match f.ciphers {
            // SAFETY: as above.
            Some(cb) => unsafe { cb(e, ptr::null_mut(), out, 0) },
            None => return Vec::new(),
        },
        Class::Digests => match f.digests {
            // SAFETY: as above.
            Some(cb) => unsafe { cb(e, ptr::null_mut(), out, 0) },
            None => return Vec::new(),
        },
        Class::PkeyMeths => match f.pkey_meths {
            // SAFETY: as above.
            Some(cb) => unsafe { cb(e, ptr::null_mut(), out, 0) },
            None => return Vec::new(),
        },
        Class::PkeyAsn1Meths => match f.pkey_asn1_meths {
            // SAFETY: as above.
            Some(cb) => unsafe { cb(e, ptr::null_mut(), out, 0) },
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    // SAFETY: what the callback returned.
    unsafe { nid_list(nids, n) }
}

/// Whether the engine has a method of the single-method kind.
fn has_method(class: Class, f: &Fields) -> bool {
    match class {
        Class::Rsa => !f.rsa.is_null(),
        Class::Dsa => !f.dsa.is_null(),
        Class::Dh => !f.dh.is_null(),
        Class::Ec => !f.ec.is_null(),
        Class::Rand => !f.rand.is_null(),
        _ => false,
    }
}

/// `ENGINE_register_*` and `ENGINE_set_default_*`: registers `e`'s methods of the kind (for
/// every NID it lists), making them the default if `setdefault`. 1 when it has none.
///
/// # Safety
/// `e` is NULL or a live engine.
unsafe fn register_class(class: Class, e: *mut ENGINE, setdefault: bool) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(f) = (unsafe { fields(e) }) else {
        return 0;
    };
    match class {
        Class::Rsa | Class::Dsa | Class::Dh | Class::Ec | Class::Rand => {
            if !has_method(class, &f) {
                return 1;
            }
            // SAFETY: as above.
            unsafe { register(class, e, &[DUMMY_NID], setdefault) }
        }
        _ => {
            // SAFETY: as above.
            let nids = unsafe { nids_of(class, e, &f) };
            if nids.is_empty() {
                return 1;
            }
            // SAFETY: as above.
            unsafe { register(class, e, &nids, setdefault) }
        }
    }
}

/// `ENGINE_register_all_*`: registers every listed engine's methods of the kind.
fn register_all(class: Class) {
    // SAFETY: no preconditions; each engine comes with a reference `ENGINE_get_next` drops.
    let mut e = unsafe { super::list::ENGINE_get_first() };
    while !e.is_null() {
        // SAFETY: a listed engine we hold.
        unsafe { register_class(class, e, false) };
        // SAFETY: as above.
        e = unsafe { super::list::ENGINE_get_next(e) };
    }
}

ffi_export! {
    /// Registers the engine's RSA method (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_RSA(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Rsa, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's RSA method out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_RSA(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::Rsa, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's RSA method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_RSA()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::Rsa);
    }
}

ffi_export! {
    /// Registers the engine's RSA method as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_RSA(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Rsa, e, true) }
    }
}

ffi_export! {
    /// Registers the engine's DSA method (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_DSA(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Dsa, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's DSA method out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_DSA(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::Dsa, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's DSA method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_DSA()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::Dsa);
    }
}

ffi_export! {
    /// Registers the engine's DSA method as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_DSA(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Dsa, e, true) }
    }
}

ffi_export! {
    /// Registers the engine's DH method (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_DH(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Dh, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's DH method out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_DH(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::Dh, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's DH method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_DH()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::Dh);
    }
}

ffi_export! {
    /// Registers the engine's DH method as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_DH(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Dh, e, true) }
    }
}

ffi_export! {
    /// Registers the engine's EC_KEY method (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_EC(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Ec, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's EC_KEY method out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_EC(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::Ec, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's EC_KEY method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_EC()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::Ec);
    }
}

ffi_export! {
    /// Registers the engine's EC_KEY method as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_EC(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Ec, e, true) }
    }
}

ffi_export! {
    /// Registers the engine's RAND method (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_RAND(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Rand, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's RAND method out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_RAND(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::Rand, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's RAND method.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_RAND()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::Rand);
    }
}

ffi_export! {
    /// Registers the engine's RAND method as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_RAND(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Rand, e, true) }
    }
}

ffi_export! {
    /// Registers the engine's ciphers (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_ciphers(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Ciphers, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's ciphers out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_ciphers(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::Ciphers, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's ciphers.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_ciphers()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::Ciphers);
    }
}

ffi_export! {
    /// Registers the engine's ciphers as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_ciphers(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Ciphers, e, true) }
    }
}

ffi_export! {
    /// Registers the engine's digests (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_digests(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Digests, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's digests out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_digests(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::Digests, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's digests.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_digests()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::Digests);
    }
}

ffi_export! {
    /// Registers the engine's digests as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_digests(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::Digests, e, true) }
    }
}

ffi_export! {
    /// Registers the engine's public-key methods (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_pkey_meths(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::PkeyMeths, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's public-key methods out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_pkey_meths(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::PkeyMeths, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's public-key methods.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_pkey_meths()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::PkeyMeths);
    }
}

ffi_export! {
    /// Registers the engine's public-key methods as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_pkey_meths(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::PkeyMeths, e, true) }
    }
}

ffi_export! {
    /// Registers the engine's public-key ASN.1 methods (1 when it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_pkey_asn1_meths(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::PkeyAsn1Meths, e, false) }
    }
}

ffi_export! {
    /// Takes the engine's public-key ASN.1 methods out of the tables.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_unregister_pkey_asn1_meths(e: *mut ENGINE)
    where failure = (), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_some() {
            // SAFETY: as above.
            unsafe { unregister(Class::PkeyAsn1Meths, e) };
        }
    }
}

ffi_export! {
    /// Registers every listed engine's public-key ASN.1 methods.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_pkey_asn1_meths()
    where failure = (), library = ERR_LIB_ENGINE
    {
        register_all(Class::PkeyAsn1Meths);
    }
}

ffi_export! {
    /// Registers the engine's public-key ASN.1 methods as the default, initializing it: 1 (when it has none
    /// too), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default_pkey_asn1_meths(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { register_class(Class::PkeyAsn1Meths, e, true) }
    }
}

ffi_export! {
    /// The default engine for the RSA method, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_default_RSA() -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::Rsa, DUMMY_NID)
    }
}

ffi_export! {
    /// The default engine for the DSA method, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_default_DSA() -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::Dsa, DUMMY_NID)
    }
}

ffi_export! {
    /// The default engine for the DH method, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_default_DH() -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::Dh, DUMMY_NID)
    }
}

ffi_export! {
    /// The default engine for the EC_KEY method, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_default_EC() -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::Ec, DUMMY_NID)
    }
}

ffi_export! {
    /// The default engine for the RAND method, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_default_RAND() -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::Rand, DUMMY_NID)
    }
}

ffi_export! {
    /// The engine the cipher `nid` resolves to, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_cipher_engine(nid: c_int) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::Ciphers, nid)
    }
}

ffi_export! {
    /// The engine the digest `nid` resolves to, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_digest_engine(nid: c_int) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::Digests, nid)
    }
}

ffi_export! {
    /// The engine the public-key method `nid` resolves to, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_pkey_meth_engine(nid: c_int) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::PkeyMeths, nid)
    }
}

ffi_export! {
    /// The engine the public-key ASN.1 method `nid` resolves to, with a functional reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_pkey_asn1_meth_engine(nid: c_int) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        select(Class::PkeyAsn1Meths, nid)
    }
}

ffi_export! {
    /// The engine's cipher for `nid`, or NULL (`ENGINE_R_UNIMPLEMENTED_CIPHER`).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_cipher(e: *mut ENGINE, nid: c_int) -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        let mut ret: *const EVP_CIPHER = ptr::null();
        // SAFETY: the caller's guarantee.
        let ok = match unsafe { fields(e) }.and_then(|f| f.ciphers) {
            // SAFETY: the engine's own callback; no lock is held.
            Some(cb) => (unsafe { cb(e, &raw mut ret, ptr::null_mut(), nid) } != 0),
            None => false,
        };
        if !ok {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_UNIMPLEMENTED_CIPHER, "ENGINE_get_cipher");
            return ptr::null();
        }
        ret
    }
}

ffi_export! {
    /// The engine's digest for `nid`, or NULL (`ENGINE_R_UNIMPLEMENTED_DIGEST`).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_digest(e: *mut ENGINE, nid: c_int) -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        let mut ret: *const EVP_MD = ptr::null();
        // SAFETY: the caller's guarantee.
        let ok = match unsafe { fields(e) }.and_then(|f| f.digests) {
            // SAFETY: the engine's own callback; no lock is held.
            Some(cb) => (unsafe { cb(e, &raw mut ret, ptr::null_mut(), nid) } != 0),
            None => false,
        };
        if !ok {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_UNIMPLEMENTED_DIGEST, "ENGINE_get_digest");
            return ptr::null();
        }
        ret
    }
}

ffi_export! {
    /// The engine's public-key method for `nid`, or NULL
    /// (`ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD`).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_pkey_meth(e: *mut ENGINE, nid: c_int) -> *const EVP_PKEY_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        let mut ret: *mut EVP_PKEY_METHOD = ptr::null_mut();
        // SAFETY: the caller's guarantee.
        let ok = match unsafe { fields(e) }.and_then(|f| f.pkey_meths) {
            // SAFETY: the engine's own callback; no lock is held.
            Some(cb) => (unsafe { cb(e, &raw mut ret, ptr::null_mut(), nid) } != 0),
            None => false,
        };
        if !ok {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD, "ENGINE_get_pkey_meth");
            return ptr::null();
        }
        ret
    }
}

ffi_export! {
    /// The engine's public-key ASN.1 method for `nid`, or NULL
    /// (`ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD`).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_pkey_asn1_meth(e: *mut ENGINE, nid: c_int) -> *const EVP_PKEY_ASN1_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        let mut ret: *mut EVP_PKEY_ASN1_METHOD = ptr::null_mut();
        // SAFETY: the caller's guarantee.
        let ok = match unsafe { fields(e) }.and_then(|f| f.pkey_asn1_meths) {
            // SAFETY: the engine's own callback; no lock is held.
            Some(cb) => (unsafe { cb(e, &raw mut ret, ptr::null_mut(), nid) } != 0),
            None => false,
        };
        if !ok {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_UNIMPLEMENTED_PUBLIC_KEY_METHOD, "ENGINE_get_pkey_asn1_meth");
            return ptr::null();
        }
        ret
    }
}

/// The PEM name of an ASN.1 method, or `None` (an alias has none).
///
/// # Safety
/// `ameth` is NULL or a live method.
unsafe fn pem_str<'a>(ameth: *const EVP_PKEY_ASN1_METHOD) -> Option<&'a CStr> {
    if ameth.is_null() {
        return None;
    }
    let mut pem: *const c_char = ptr::null();
    // SAFETY: the caller's guarantee; only the PEM name is asked for.
    let ok = unsafe {
        crate::evp::pkey::ameth::EVP_PKEY_asn1_get0_info(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut pem,
            ameth,
        )
    };
    if ok == 0 || pem.is_null() {
        return None;
    }
    // SAFETY: the method's name, which lives as long as it.
    Some(unsafe { CStr::from_ptr(pem) })
}

/// Whether the PEM name is `want` ignoring ASCII case (`strlen(pem_str) == len &&
/// OPENSSL_strncasecmp(pem_str, str, len) == 0`).
fn pem_matches(pem: &CStr, want: &[u8]) -> bool {
    pem.to_bytes().eq_ignore_ascii_case(want)
}

/// The `len` octets at `s` (`len` -1: up to its NUL), or `None` for a negative length.
///
/// # Safety
/// `s` is a C string, or has `len` octets.
unsafe fn name_octets<'a>(
    s: *const c_char,
    len: c_int,
    strlen_on_minus_one: bool,
) -> Option<&'a [u8]> {
    if s.is_null() {
        return None;
    }
    if len == -1 && strlen_on_minus_one {
        // SAFETY: the caller's guarantee.
        return Some(unsafe { CStr::from_ptr(s) }.to_bytes());
    }
    let n = usize::try_from(len).ok()?;
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts(s.cast::<u8>(), n) })
}

ffi_export! {
    /// The engine's public-key ASN.1 method whose PEM name is the `len` octets at `str`
    /// (`len` -1: the C string), ignoring case, or NULL.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `str` a C string, or `len` octets.
    pub unsafe extern "C" fn ENGINE_get_pkey_asn1_meth_str(e: *mut ENGINE, str_: *const c_char, len: c_int) -> *const EVP_PKEY_ASN1_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(f) = (unsafe { fields(e) }) else { return ptr::null() };
        let Some(cb) = f.pkey_asn1_meths else { return ptr::null() };
        // SAFETY: as above.
        let Some(want) = (unsafe { name_octets(str_, len, true) }) else { return ptr::null() };
        // SAFETY: as above.
        for nid in unsafe { nids_of(Class::PkeyAsn1Meths, e, &f) } {
            let mut ameth: *mut EVP_PKEY_ASN1_METHOD = ptr::null_mut();
            // SAFETY: the engine's own callback; no lock is held.
            unsafe { cb(e, &raw mut ameth, ptr::null_mut(), nid) };
            // SAFETY: what the callback returned.
            if unsafe { pem_str(ameth) }.is_some_and(|p| pem_matches(p, want)) {
                return ameth;
            }
        }
        ptr::null()
    }
}

ffi_export! {
    /// The registered public-key ASN.1 method whose PEM name is the `len` octets at `str`,
    /// ignoring case, with its engine in `*pe` (a structural reference; NULL if none).
    ///
    /// # Safety
    /// `pe` is a writable pointer; `str` has `len` octets.
    pub unsafe extern "C" fn ENGINE_pkey_asn1_find_str(pe: *mut *mut ENGINE, str_: *const c_char, len: c_int) -> *const EVP_PKEY_ASN1_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // The registered engines, each held (from under the lock) while its callback runs
        // with no lock held.
        let candidates: Vec<(c_int, EnginePtr)> = {
            let mut g = global();
            let all: Vec<(c_int, EnginePtr)> = match g.tables.table(Class::PkeyAsn1Meths) {
                Some(t) => t
                    .piles
                    .iter()
                    .flat_map(|(&nid, p)| p.engines.iter().map(move |&e| (nid, e)))
                    .collect(),
                None => Vec::new(),
            };
            for &(_, e) in &all {
                // SAFETY: the pile's engines are live; released below.
                unsafe { up_struct(e.0) };
            }
            all
        };
        // SAFETY: the caller's guarantee.
        let want = unsafe { name_octets(str_, len, false) };
        let mut found: Option<(usize, *mut EVP_PKEY_ASN1_METHOD)> = None;
        if let Some(w) = want {
            for (i, &(nid, e)) in candidates.iter().enumerate() {
                // SAFETY: a held engine.
                let Some(cb) = unsafe { fields(e.0) }.and_then(|f| f.pkey_asn1_meths) else { continue };
                let mut ameth: *mut EVP_PKEY_ASN1_METHOD = ptr::null_mut();
                // SAFETY: the engine's own callback; no lock is held.
                unsafe { cb(e.0, &raw mut ameth, ptr::null_mut(), nid) };
                // SAFETY: what the callback returned.
                if unsafe { pem_str(ameth) }.is_some_and(|p| pem_matches(p, w)) {
                    found = Some((i, ameth));
                    break;
                }
            }
        }
        let mut engine_found = ptr::null_mut();
        for (i, &(_, e)) in candidates.iter().enumerate() {
            if found.is_some_and(|(f, _)| f == i) {
                // This reference is the caller's.
                engine_found = e.0;
                continue;
            }
            // SAFETY: the reference taken above.
            unsafe { free_util(e.0) };
        }
        let found = found.map(|(_, m)| (EnginePtr(engine_found), m));
        if !pe.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { pe.write(found.map_or(ptr::null_mut(), |(f, _)| f.0)) };
        }
        found.map_or(ptr::null(), |(_, m)| m.cast_const())
    }
}

/// `engine_pkey_meths_free`: frees the methods the engine's callback lists, at its last
/// structural reference.
///
/// # Safety
/// `e` is a live engine; `cb` its callback.
pub(super) unsafe fn free_pkey_meths(e: *mut ENGINE, cb: ENGINE_PKEY_METHS_PTR) {
    let Some(cb) = cb else { return };
    let mut nids: *const c_int = ptr::null();
    // SAFETY: the engine's own callback; no lock is held.
    let n = unsafe { cb(e, ptr::null_mut(), &raw mut nids, 0) };
    // SAFETY: what the callback returned.
    for nid in unsafe { nid_list(nids, n) } {
        let mut m: *mut EVP_PKEY_METHOD = ptr::null_mut();
        // SAFETY: as above.
        if unsafe { cb(e, &raw mut m, ptr::null_mut(), nid) } != 0 {
            // SAFETY: the engine's method, which it gives up here, as in OpenSSL.
            unsafe { crate::evp::pmeth::EVP_PKEY_meth_free(m) };
        }
    }
}

/// `engine_pkey_asn1_meths_free`: as [`free_pkey_meths`], for the ASN.1 methods.
///
/// # Safety
/// As for [`free_pkey_meths`].
pub(super) unsafe fn free_pkey_asn1_meths(e: *mut ENGINE, cb: ENGINE_PKEY_ASN1_METHS_PTR) {
    let Some(cb) = cb else { return };
    let mut nids: *const c_int = ptr::null();
    // SAFETY: the engine's own callback; no lock is held.
    let n = unsafe { cb(e, ptr::null_mut(), &raw mut nids, 0) };
    // SAFETY: what the callback returned.
    for nid in unsafe { nid_list(nids, n) } {
        let mut m: *mut EVP_PKEY_ASN1_METHOD = ptr::null_mut();
        // SAFETY: as above.
        if unsafe { cb(e, &raw mut m, ptr::null_mut(), nid) } != 0 {
            // SAFETY: the engine's method, which it gives up here, as in OpenSSL.
            unsafe { crate::evp::pkey::ameth::EVP_PKEY_asn1_free(m) };
        }
    }
}

ffi_export! {
    /// The table flags (`ENGINE_TABLE_FLAG_*`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_table_flags() -> c_uint
    where failure = 0, library = ERR_LIB_ENGINE
    {
        TABLE_FLAGS.load(Ordering::Relaxed)
    }
}

ffi_export! {
    /// Sets the table flags (`ENGINE_TABLE_FLAG_NOINIT`: a lookup initializes no engine that
    /// isn't initialized yet).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_set_table_flags(flags: c_uint)
    where failure = (), library = ERR_LIB_ENGINE
    {
        TABLE_FLAGS.store(flags, Ordering::Relaxed);
    }
}

ffi_export! {
    /// Makes the engine the default for each kind of method in `flags` (`ENGINE_METHOD_*`): 1,
    /// or 0 at the first that fails.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_default(e: *mut ENGINE, flags: c_uint) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        let order = [
            (ENGINE_METHOD_CIPHERS, Class::Ciphers),
            (ENGINE_METHOD_DIGESTS, Class::Digests),
            (ENGINE_METHOD_RSA, Class::Rsa),
            (ENGINE_METHOD_DSA, Class::Dsa),
            (ENGINE_METHOD_DH, Class::Dh),
            (ENGINE_METHOD_EC, Class::Ec),
            (ENGINE_METHOD_RAND, Class::Rand),
            (ENGINE_METHOD_PKEY_METHS, Class::PkeyMeths),
            (ENGINE_METHOD_PKEY_ASN1_METHS, Class::PkeyAsn1Meths),
        ];
        for (bit, class) in order {
            // SAFETY: the caller's guarantee.
            if flags & bit != 0 && unsafe { register_class(class, e, true) } == 0 {
                return 0;
            }
        }
        1
    }
}

/// `int_def_cb`: one name of `ENGINE_set_default_string`'s list into its `ENGINE_METHOD_*`
/// bits (matching as OpenSSL's `strncmp(alg, name, len)` does: the list's word may be a prefix
/// of the name).
fn method_bits(word: &[u8]) -> Option<c_uint> {
    let names: [(&[u8], c_uint); 11] = [
        (b"ALL", ENGINE_METHOD_ALL),
        (b"RSA", ENGINE_METHOD_RSA),
        (b"DSA", ENGINE_METHOD_DSA),
        (b"DH", ENGINE_METHOD_DH),
        (b"EC", ENGINE_METHOD_EC),
        (b"RAND", ENGINE_METHOD_RAND),
        (b"CIPHERS", ENGINE_METHOD_CIPHERS),
        (b"DIGESTS", ENGINE_METHOD_DIGESTS),
        (
            b"PKEY",
            ENGINE_METHOD_PKEY_METHS | ENGINE_METHOD_PKEY_ASN1_METHS,
        ),
        (b"PKEY_CRYPTO", ENGINE_METHOD_PKEY_METHS),
        (b"PKEY_ASN1", ENGINE_METHOD_PKEY_ASN1_METHS),
    ];
    // `strncmp(alg, name, len)` with `alg` the word's start in the whole list: the word's
    // `len` octets against the name's first `len` (a shorter name stops at its NUL).
    names.iter().find_map(|&(name, bits)| {
        let n = word.len().min(name.len().saturating_add(1));
        let mut padded = name.to_vec();
        padded.push(0);
        (word.get(..n) == padded.get(..n)).then_some(bits)
    })
}

/// `ENGINE_set_default_string`'s list callback (`CONF_parse_list`'s): ORs a word's bits into
/// `*arg`.
unsafe extern "C" fn def_cb(alg: *const c_char, len: c_int, arg: *mut core::ffi::c_void) -> c_int {
    if alg.is_null() {
        return 0;
    }
    let Ok(n) = usize::try_from(len) else {
        return 0;
    };
    // SAFETY: `CONF_parse_list` passes `len` octets of the list.
    let word = unsafe { core::slice::from_raw_parts(alg.cast::<u8>(), n) };
    let Some(bits) = method_bits(word) else {
        return 0;
    };
    let flags = arg.cast::<c_uint>();
    // SAFETY: `ENGINE_set_default_string`'s local.
    let now = unsafe { flags.read() };
    // SAFETY: as above.
    unsafe { flags.write(now | bits) };
    1
}

ffi_export! {
    /// Makes the engine the default for the kinds of method the comma-separated list names
    /// (`ALL`, `RSA`, `DSA`, `DH`, `EC`, `RAND`, `CIPHERS`, `DIGESTS`, `PKEY`, `PKEY_CRYPTO`,
    /// `PKEY_ASN1`): 1, or 0 (`ENGINE_R_INVALID_STRING` for a name it doesn't know).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `def_list` NULL or a C string.
    pub unsafe extern "C" fn ENGINE_set_default_string(e: *mut ENGINE, def_list: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        let mut flags: c_uint = 0;
        // SAFETY: the list, our callback and its local.
        let ok = unsafe {
            crate::conf::CONF_parse_list(def_list, c_int::from(b','), 1, Some(def_cb), (&raw mut flags).cast())
        };
        if ok == 0 {
            // SAFETY: the caller's guarantee.
            let text = if def_list.is_null() { &b"<NULL>"[..] } else { unsafe { CStr::from_ptr(def_list) }.to_bytes() };
            err::raise_with_bytes(ERR_LIB_ENGINE, ENGINE_R_INVALID_STRING, "ENGINE_set_default_string", &[b"str=", text].concat());
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { ENGINE_set_default(e, flags) }
    }
}

ffi_export! {
    /// Registers every kind of method the engine has: 1.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_register_complete(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        let order = [
            Class::Ciphers,
            Class::Digests,
            Class::Rsa,
            Class::Dsa,
            Class::Dh,
            Class::Ec,
            Class::Rand,
            Class::PkeyMeths,
            Class::PkeyAsn1Meths,
        ];
        for class in order {
            // SAFETY: the caller's guarantee.
            unsafe { register_class(class, e, false) };
        }
        1
    }
}

ffi_export! {
    /// Registers every kind of method of every listed engine not flagged
    /// `ENGINE_FLAGS_NO_REGISTER_ALL`: 1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_register_all_complete() -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: no preconditions; each engine comes with a reference `ENGINE_get_next` drops.
        let mut e = unsafe { super::list::ENGINE_get_first() };
        while !e.is_null() {
            // SAFETY: a listed engine we hold.
            let skip = unsafe { fields(e) }.is_none_or(|f| f.flags & ENGINE_FLAGS_NO_REGISTER_ALL != 0);
            if !skip {
                // SAFETY: as above.
                unsafe { ENGINE_register_complete(e) };
            }
            // SAFETY: as above.
            e = unsafe { super::list::ENGINE_get_next(e) };
        }
        1
    }
}
