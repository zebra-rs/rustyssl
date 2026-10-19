//! ENGINE (`crypto/engine/`), as OpenSSL 3.5's default build has it: the engines applications
//! make with `ENGINE_new`, the built-in ones (`dynamic`, and `rdrand` on x86 cores with
//! RDRAND), and the modules the dynamic engine loads, which bind themselves through this same
//! API. An engine is a table of the application's (or the module's) C functions and methods,
//! which the library calls back.
//!
//! The global state (the engine list, the method tables, each engine's functional count) is
//! behind one lock, as OpenSSL's `global_engine_lock` is, but no C function an engine holds runs
//! with it held (security rule 7): where OpenSSL calls `init`, `finish`, `destroy` or a method
//! callback under its lock, the lock is released around the call. An engine being initialized
//! by one thread makes another wait for that `init` to return instead of running it twice.
//!
//! - [`list`]: the engine list (`eng_list.c`), the built-in engines, and `ENGINE_by_id`.
//! - [`table`]: the method tables, defaults and registration (`eng_table.c`, `tb_*.c`).
//! - [`ctrl`]: control commands (`eng_ctrl.c`).
//! - [`dynamic`]: the dynamic engine, which loads engine modules (`eng_dyn.c`), with [`dso`].
//! - [`pkey`]: loading keys through an engine (`eng_pkey.c`).

pub(crate) mod ctrl;
pub(crate) mod dso;
mod dynamic;
pub(crate) mod list;
pub(crate) mod pkey;
#[cfg(target_arch = "x86_64")]
mod rdrand;
pub(crate) mod table;

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_int, c_void};
use core::ptr;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;

use rustyssl_abi::{
    CRYPTO_EX_DATA, CRYPTO_EX_INDEX_ENGINE, DH_METHOD, DSA_METHOD, EC_KEY_METHOD, ENGINE,
    ENGINE_CIPHERS_PTR, ENGINE_CMD_DEFN, ENGINE_CTRL_FUNC_PTR, ENGINE_DIGESTS_PTR,
    ENGINE_GEN_INT_FUNC_PTR, ENGINE_LOAD_KEY_PTR, ENGINE_PKEY_ASN1_METHS_PTR,
    ENGINE_PKEY_METHS_PTR, ENGINE_R_FINISH_FAILED, ENGINE_SSL_CLIENT_CERT_PTR, ERR_LIB_ENGINE,
    ERR_R_PASSED_NULL_PARAMETER, RAND_METHOD, RSA_METHOD,
};

use crate::err;
use crate::ex_data::{
    CRYPTO_free_ex_data, CRYPTO_get_ex_data, CRYPTO_new_ex_data, CRYPTO_set_ex_data,
};
use crate::ffi::ffi_export;
use crate::handle::{Handle, handle_type};

pub(crate) use ctrl::{ENGINE_ctrl, ENGINE_ctrl_cmd_string};
pub(crate) use list::{ENGINE_by_id, load_builtins};
pub(crate) use table::{ENGINE_set_default, ENGINE_set_default_string, cleanup};

/// An engine's settings (`engine_st`'s fields but the counts and links), copied out whenever
/// they're read, so no C function runs with the engine's lock held.
#[derive(Clone, Copy)]
struct Fields {
    id: *const c_char,
    name: *const c_char,
    rsa: *const RSA_METHOD,
    dsa: *const DSA_METHOD,
    dh: *const DH_METHOD,
    ec: *const EC_KEY_METHOD,
    rand: *const RAND_METHOD,
    ciphers: ENGINE_CIPHERS_PTR,
    digests: ENGINE_DIGESTS_PTR,
    pkey_meths: ENGINE_PKEY_METHS_PTR,
    pkey_asn1_meths: ENGINE_PKEY_ASN1_METHS_PTR,
    destroy: ENGINE_GEN_INT_FUNC_PTR,
    init: ENGINE_GEN_INT_FUNC_PTR,
    finish: ENGINE_GEN_INT_FUNC_PTR,
    ctrl: ENGINE_CTRL_FUNC_PTR,
    load_privkey: ENGINE_LOAD_KEY_PTR,
    load_pubkey: ENGINE_LOAD_KEY_PTR,
    load_ssl_client_cert: ENGINE_SSL_CLIENT_CERT_PTR,
    cmd_defns: *const ENGINE_CMD_DEFN,
    flags: c_int,
    /// The `bind_engine` function of the module that bound the engine (`dynamic_id`), as an
    /// address, or 0.
    dynamic_id: usize,
}

// SAFETY: the pointers are the application's (or a module's) functions, methods and strings,
// which OpenSSL shares between threads as they are; nothing here dereferences them.
unsafe impl Send for Fields {}

impl Fields {
    const EMPTY: Self = Self {
        id: ptr::null(),
        name: ptr::null(),
        rsa: ptr::null(),
        dsa: ptr::null(),
        dh: ptr::null(),
        ec: ptr::null(),
        rand: ptr::null(),
        ciphers: None,
        digests: None,
        pkey_meths: None,
        pkey_asn1_meths: None,
        destroy: None,
        init: None,
        finish: None,
        ctrl: None,
        load_privkey: None,
        load_pubkey: None,
        load_ssl_client_cert: None,
        cmd_defns: ptr::null(),
        flags: 0,
        dynamic_id: 0,
    };

    /// `engine_set_all_null`: what the dynamic engine clears before a module binds the engine
    /// (not the EC method, the public-key method callbacks or the SSL client certificate
    /// loader, which it leaves).
    fn set_all_null(&mut self) {
        let keep = *self;
        *self = Self {
            ec: keep.ec,
            pkey_meths: keep.pkey_meths,
            pkey_asn1_meths: keep.pkey_asn1_meths,
            load_ssl_client_cert: keep.load_ssl_client_cert,
            ..Self::EMPTY
        };
    }
}

/// The engine's application data, at a fixed address for the `CRYPTO_*_ex_data` functions.
struct ExData(UnsafeCell<CRYPTO_EX_DATA>);

// SAFETY: the ex_data functions are the only users, and OpenSSL leaves serializing them to the
// application.
unsafe impl Send for ExData {}
// SAFETY: as above.
unsafe impl Sync for ExData {}

/// What an `ENGINE` points to.
pub(crate) struct Engine {
    /// The structural count (`struct_ref`): `ENGINE_free` drops one, and at the last the
    /// engine's `destroy` runs and it's freed.
    struct_ref: AtomicI32,
    /// The functional count (`funct_ref`), changed with the global lock held.
    funct_ref: AtomicI32,
    fields: Mutex<Fields>,
    ex_data: ExData,
    /// The dynamic engine's settings and the module it loaded (`dynamic_data_ctx`), made at
    /// its first control command.
    dynamic: Mutex<Option<dynamic::Ctx>>,
}

handle_type!(ENGINE => Engine);

/// An engine pointer in the global state, which holds a structural reference to it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct EnginePtr(*mut ENGINE);

// SAFETY: engines are shared between threads, as OpenSSL's are.
unsafe impl Send for EnginePtr {}

/// The state OpenSSL keeps under `global_engine_lock`.
struct Global {
    /// The engine list, in order (`engine_list_head` ... `engine_list_tail`).
    list: Vec<EnginePtr>,
    /// Engines bound by a module, in order (`engine_dyn_list_head` ...).
    dyn_list: Vec<EnginePtr>,
    tables: table::Tables,
    /// Engines whose `init` is running, and the thread running it.
    initializing: Vec<(EnginePtr, ThreadId)>,
}

static GLOBAL: Mutex<Global> = Mutex::new(Global {
    list: Vec::new(),
    dyn_list: Vec::new(),
    tables: table::Tables::new(),
    initializing: Vec::new(),
});

/// Signalled when an engine's `init` returns.
static INITIALIZED: Condvar = Condvar::new();

type Guard = MutexGuard<'static, Global>;

fn global() -> Guard {
    GLOBAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The engine behind `e`.
///
/// # Safety
/// `e` is NULL or a live engine.
unsafe fn engine<'a>(e: *const ENGINE) -> Option<&'a Engine> {
    // SAFETY: the caller's guarantee.
    unsafe { ENGINE::get(e) }
}

/// A copy of the engine's settings, or `None` for NULL.
///
/// # Safety
/// As for [`engine`].
unsafe fn fields(e: *const ENGINE) -> Option<Fields> {
    // SAFETY: the caller's guarantee.
    unsafe { engine(e) }.map(Engine::fields)
}

impl Engine {
    fn lock(&self) -> MutexGuard<'_, Fields> {
        self.fields.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn fields(&self) -> Fields {
        *self.lock()
    }

    fn ex_data(&self) -> *mut CRYPTO_EX_DATA {
        self.ex_data.0.get()
    }
}

/// `ENGINE_new`: an empty engine with one structural reference, or NULL.
fn new_engine() -> *mut ENGINE {
    let e = ENGINE::new_handle(Engine {
        struct_ref: AtomicI32::new(1),
        funct_ref: AtomicI32::new(0),
        fields: Mutex::new(Fields::EMPTY),
        ex_data: ExData(UnsafeCell::new(CRYPTO_EX_DATA {
            ctx: ptr::null_mut(),
            sk: ptr::null_mut(),
        })),
        dynamic: Mutex::new(None),
    });
    // SAFETY: just made.
    let Some(en) = (unsafe { engine(e) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the engine's own ex_data.
    if unsafe { CRYPTO_new_ex_data(CRYPTO_EX_INDEX_ENGINE, e.cast(), en.ex_data()) } == 0 {
        // SAFETY: the only reference, never seen by C.
        unsafe { ENGINE::free(e) };
        return ptr::null_mut();
    }
    e
}

/// Adds a structural reference (`CRYPTO_UP_REF(&e->struct_ref)`); false for NULL.
///
/// # Safety
/// As for [`engine`].
unsafe fn up_struct(e: *mut ENGINE) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(en) = (unsafe { engine(e) }) else {
        return false;
    };
    en.struct_ref.fetch_add(1, Ordering::AcqRel);
    true
}

/// `engine_free_util`: drops a structural reference; at the last, frees the engine's
/// public-key methods, runs its `destroy`, takes it off the dynamic list, frees its ex_data and
/// the module it loaded, and frees it. Runs with no lock held.
///
/// # Safety
/// `e` is NULL or a live engine whose reference the caller gives up.
unsafe fn free_util(e: *mut ENGINE) {
    // SAFETY: the caller's guarantee.
    if unsafe { release(e) } {
        // SAFETY: the last reference is gone.
        unsafe { teardown(e) };
    }
}

/// Drops a structural reference: whether it was the last.
///
/// # Safety
/// As for [`free_util`].
unsafe fn release(e: *mut ENGINE) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { engine(e) }.is_some_and(|en| en.struct_ref.fetch_sub(1, Ordering::AcqRel) == 1)
}

/// [`free_util`]'s work once the last structural reference is gone.
///
/// # Safety
/// `e` is a live engine with no structural reference left.
unsafe fn teardown(e: *mut ENGINE) {
    // SAFETY: the caller's guarantee.
    let Some(held) = (unsafe { ENGINE::hold(e) }) else {
        return;
    };
    let f = held.fields();
    // SAFETY: the engine's callbacks, given the engine.
    unsafe { table::free_pkey_meths(e, f.pkey_meths) };
    // SAFETY: as above.
    unsafe { table::free_pkey_asn1_meths(e, f.pkey_asn1_meths) };
    if let Some(destroy) = f.destroy {
        // SAFETY: the engine's own function, given the engine.
        unsafe { destroy(e) };
    }
    list::remove_dynamic_id(e);
    // SAFETY: the engine's own ex_data; its last reference.
    unsafe { CRYPTO_free_ex_data(CRYPTO_EX_INDEX_ENGINE, e.cast(), held.ex_data()) };
    // The module goes last: the engine's functions are in it.
    let module = held
        .dynamic
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    drop(module);
    // SAFETY: the last reference; the hold keeps the object until it drops.
    unsafe { ENGINE::free(e) };
}

/// Drops a structural reference with the global lock held: released while the engine is
/// torn down at the last.
///
/// # Safety
/// As for [`free_util`].
unsafe fn free_util_locked(g: Guard, e: *mut ENGINE) -> Guard {
    // SAFETY: the caller's guarantee.
    if !unsafe { release(e) } {
        return g;
    }
    drop(g);
    // SAFETY: the last reference is gone.
    unsafe { teardown(e) };
    global()
}

/// `engine_unlocked_init`: the engine's `init` if this is its first functional reference
/// (released around the call), then a functional and a structural reference. The `init`'s
/// result (1 when it has none), 0 when it failed.
///
/// # Safety
/// `e` is a live engine.
unsafe fn init_locked(mut g: Guard, e: *mut ENGINE) -> (Guard, c_int) {
    // SAFETY: the caller's guarantee.
    let Some(en) = (unsafe { engine(e) }) else {
        return (g, 0);
    };
    let me = std::thread::current().id();
    let mut result = 1;
    loop {
        if en.funct_ref.load(Ordering::Acquire) != 0 {
            break;
        }
        let Some(init) = en.fields().init else {
            break;
        };
        let busy = g
            .initializing
            .iter()
            .any(|&(p, t)| p == EnginePtr(e) && t != me);
        if busy {
            g = INITIALIZED.wait(g).unwrap_or_else(PoisonError::into_inner);
            continue;
        }
        g.initializing.push((EnginePtr(e), me));
        drop(g);
        // SAFETY: the engine's own function, given the engine; no lock is held.
        result = unsafe { init(e) };
        g = global();
        if let Some(i) = g
            .initializing
            .iter()
            .position(|&(p, t)| p == EnginePtr(e) && t == me)
        {
            g.initializing.remove(i);
        }
        INITIALIZED.notify_all();
        if result == 0 {
            return (g, 0);
        }
        break;
    }
    en.struct_ref.fetch_add(1, Ordering::AcqRel);
    en.funct_ref.fetch_add(1, Ordering::AcqRel);
    (g, result)
}

/// `engine_unlocked_finish`: drops a functional reference, running the engine's `finish` at
/// the last (released around the call), then the structural reference that came with it.
/// The `finish`'s result (1 when it has none), 0 when it failed.
///
/// # Safety
/// `e` is a live engine with a functional reference the caller gives up.
unsafe fn finish_locked(mut g: Guard, e: *mut ENGINE) -> (Guard, c_int) {
    // SAFETY: the caller's guarantee.
    let Some(en) = (unsafe { engine(e) }) else {
        return (g, 0);
    };
    let left = en
        .funct_ref
        .fetch_sub(1, Ordering::AcqRel)
        .saturating_sub(1);
    let mut result = 1;
    if left == 0
        && let Some(finish) = en.fields().finish
    {
        drop(g);
        // SAFETY: the engine's own function, given the engine; no lock is held.
        result = unsafe { finish(e) };
        g = global();
        if result == 0 {
            return (g, 0);
        }
    }
    // SAFETY: the structural reference the functional one came with.
    g = unsafe { free_util_locked(g, e) };
    (g, result)
}

/// Raises `ERR_R_PASSED_NULL_PARAMETER` from `function` (for the ENGINE library).
fn null_parameter(function: &str) {
    err::raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER, function);
}

/// Whether two engine ids are equal (`strcmp == 0`), NULL being equal to nothing.
///
/// # Safety
/// Each is NULL or a C string.
unsafe fn same_id(a: *const c_char, b: *const c_char) -> bool {
    if a.is_null() || b.is_null() {
        return false;
    }
    // SAFETY: the caller's guarantee.
    let a = unsafe { core::ffi::CStr::from_ptr(a) };
    // SAFETY: as above.
    let b = unsafe { core::ffi::CStr::from_ptr(b) };
    a == b
}

ffi_export! {
    /// A new engine with nothing set, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_new() -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        new_engine()
    }
}

ffi_export! {
    /// Drops a structural reference; at the last, the engine's `destroy` runs and it's freed.
    /// 1 (NULL too).
    ///
    /// # Safety
    /// `e` is NULL or a live engine whose reference the caller gives up.
    pub unsafe extern "C" fn ENGINE_free(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { free_util(e) };
        1
    }
}

ffi_export! {
    /// Adds a structural reference: 1, or 0 for NULL.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_up_ref(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { up_struct(e) } {
            null_parameter("ENGINE_up_ref");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Takes a functional reference, running the engine's `init` if it's the first: what
    /// `init` returned (1 if it has none), or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_init(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_none() {
            null_parameter("ENGINE_init");
            return 0;
        }
        // SAFETY: as above.
        unsafe { init_locked(global(), e) }.1
    }
}

ffi_export! {
    /// Drops a functional reference, running the engine's `finish` at the last: 1 (NULL too),
    /// or 0 if `finish` failed.
    ///
    /// # Safety
    /// `e` is NULL or a live engine with a functional reference the caller gives up.
    pub unsafe extern "C" fn ENGINE_finish(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_none() {
            return 1;
        }
        // SAFETY: as above.
        let (_g, r) = unsafe { finish_locked(global(), e) };
        if r == 0 {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_FINISH_FAILED, "ENGINE_finish");
            return 0;
        }
        r
    }
}

ffi_export! {
    /// Stores `arg` in the engine's application data at `idx`: 1, or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_set_ex_data(e: *mut ENGINE, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        // SAFETY: the engine's own ex_data.
        unsafe { CRYPTO_set_ex_data(en.ex_data(), idx, arg) }
    }
}

ffi_export! {
    /// The engine's application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_ex_data(e: *const ENGINE, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return ptr::null_mut() };
        // SAFETY: the engine's own ex_data.
        unsafe { CRYPTO_get_ex_data(en.ex_data(), idx) }
    }
}

/// A setter of a string field: `ERR_R_PASSED_NULL_PARAMETER` for a NULL string, as OpenSSL's.
///
/// # Safety
/// `e` is NULL or a live engine.
unsafe fn set_string(
    e: *mut ENGINE,
    s: *const c_char,
    function: &str,
    field: impl FnOnce(&mut Fields) -> &mut *const c_char,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(en) = (unsafe { engine(e) }) else {
        return 0;
    };
    if s.is_null() {
        null_parameter(function);
        return 0;
    }
    *field(&mut en.lock()) = s;
    1
}

ffi_export! {
    /// Sets the engine's id (kept, not copied): 1, or 0 for NULL.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `id` is NULL or a C string that outlives the engine.
    pub unsafe extern "C" fn ENGINE_set_id(e: *mut ENGINE, id: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_string(e, id, "ENGINE_set_id", |f| &mut f.id) }
    }
}

ffi_export! {
    /// Sets the engine's name (kept, not copied): 1, or 0 for NULL.
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `name` is NULL or a C string that outlives the engine.
    pub unsafe extern "C" fn ENGINE_set_name(e: *mut ENGINE, name: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { set_string(e, name, "ENGINE_set_name", |f| &mut f.name) }
    }
}

ffi_export! {
    /// Sets the engine's destroy function: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_destroy_function(e: *mut ENGINE, value: ENGINE_GEN_INT_FUNC_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().destroy = value;
        1
    }
}

ffi_export! {
    /// The engine's destroy function (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_destroy_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.destroy)
    }
}

ffi_export! {
    /// Sets the engine's init function: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_init_function(e: *mut ENGINE, value: ENGINE_GEN_INT_FUNC_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().init = value;
        1
    }
}

ffi_export! {
    /// The engine's init function (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_init_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.init)
    }
}

ffi_export! {
    /// Sets the engine's finish function: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_finish_function(e: *mut ENGINE, value: ENGINE_GEN_INT_FUNC_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().finish = value;
        1
    }
}

ffi_export! {
    /// The engine's finish function (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_finish_function(e: *const ENGINE) -> ENGINE_GEN_INT_FUNC_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.finish)
    }
}

ffi_export! {
    /// Sets the engine's control function: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_ctrl_function(e: *mut ENGINE, value: ENGINE_CTRL_FUNC_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().ctrl = value;
        1
    }
}

ffi_export! {
    /// The engine's control function (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_ctrl_function(e: *const ENGINE) -> ENGINE_CTRL_FUNC_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.ctrl)
    }
}

ffi_export! {
    /// Sets the engine's flags (`ENGINE_FLAGS_*`): 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_flags(e: *mut ENGINE, value: c_int) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().flags = value;
        1
    }
}

ffi_export! {
    /// The engine's flags (`ENGINE_FLAGS_*`) (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_flags(e: *const ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(0, |f| f.flags)
    }
}

ffi_export! {
    /// Sets the engine's control commands' definitions: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_cmd_defns(e: *mut ENGINE, value: *const ENGINE_CMD_DEFN) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().cmd_defns = value;
        1
    }
}

ffi_export! {
    /// The engine's control commands' definitions (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_cmd_defns(e: *const ENGINE) -> *const ENGINE_CMD_DEFN
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(ptr::null(), |f| f.cmd_defns)
    }
}

ffi_export! {
    /// Sets the engine's RSA method: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_RSA(e: *mut ENGINE, value: *const RSA_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().rsa = value;
        1
    }
}

ffi_export! {
    /// The engine's RSA method (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_RSA(e: *const ENGINE) -> *const RSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(ptr::null(), |f| f.rsa)
    }
}

ffi_export! {
    /// Sets the engine's DSA method: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_DSA(e: *mut ENGINE, value: *const DSA_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().dsa = value;
        1
    }
}

ffi_export! {
    /// The engine's DSA method (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_DSA(e: *const ENGINE) -> *const DSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(ptr::null(), |f| f.dsa)
    }
}

ffi_export! {
    /// Sets the engine's DH method: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_DH(e: *mut ENGINE, value: *const DH_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().dh = value;
        1
    }
}

ffi_export! {
    /// The engine's DH method (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_DH(e: *const ENGINE) -> *const DH_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(ptr::null(), |f| f.dh)
    }
}

ffi_export! {
    /// Sets the engine's EC_KEY method: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_EC(e: *mut ENGINE, value: *const EC_KEY_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().ec = value;
        1
    }
}

ffi_export! {
    /// The engine's EC_KEY method (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_EC(e: *const ENGINE) -> *const EC_KEY_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(ptr::null(), |f| f.ec)
    }
}

ffi_export! {
    /// Sets the engine's RAND method: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_RAND(e: *mut ENGINE, value: *const RAND_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().rand = value;
        1
    }
}

ffi_export! {
    /// The engine's RAND method (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_RAND(e: *const ENGINE) -> *const RAND_METHOD
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(ptr::null(), |f| f.rand)
    }
}

ffi_export! {
    /// Sets the engine's cipher callback: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_ciphers(e: *mut ENGINE, value: ENGINE_CIPHERS_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().ciphers = value;
        1
    }
}

ffi_export! {
    /// The engine's cipher callback (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_ciphers(e: *const ENGINE) -> ENGINE_CIPHERS_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.ciphers)
    }
}

ffi_export! {
    /// Sets the engine's digest callback: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_digests(e: *mut ENGINE, value: ENGINE_DIGESTS_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().digests = value;
        1
    }
}

ffi_export! {
    /// The engine's digest callback (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_digests(e: *const ENGINE) -> ENGINE_DIGESTS_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.digests)
    }
}

ffi_export! {
    /// Sets the engine's public-key method callback: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_pkey_meths(e: *mut ENGINE, value: ENGINE_PKEY_METHS_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().pkey_meths = value;
        1
    }
}

ffi_export! {
    /// The engine's public-key method callback (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_pkey_meths(e: *const ENGINE) -> ENGINE_PKEY_METHS_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.pkey_meths)
    }
}

ffi_export! {
    /// Sets the engine's public-key ASN.1 method callback: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_pkey_asn1_meths(e: *mut ENGINE, value: ENGINE_PKEY_ASN1_METHS_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().pkey_asn1_meths = value;
        1
    }
}

ffi_export! {
    /// The engine's public-key ASN.1 method callback (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_pkey_asn1_meths(e: *const ENGINE) -> ENGINE_PKEY_ASN1_METHS_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.pkey_asn1_meths)
    }
}

ffi_export! {
    /// Sets the engine's private-key loader: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_load_privkey_function(e: *mut ENGINE, value: ENGINE_LOAD_KEY_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().load_privkey = value;
        1
    }
}

ffi_export! {
    /// The engine's private-key loader (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_load_privkey_function(e: *const ENGINE) -> ENGINE_LOAD_KEY_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.load_privkey)
    }
}

ffi_export! {
    /// Sets the engine's public-key loader: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_load_pubkey_function(e: *mut ENGINE, value: ENGINE_LOAD_KEY_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().load_pubkey = value;
        1
    }
}

ffi_export! {
    /// The engine's public-key loader (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_load_pubkey_function(e: *const ENGINE) -> ENGINE_LOAD_KEY_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.load_pubkey)
    }
}

ffi_export! {
    /// Sets the engine's SSL client certificate loader: 1 (0 for NULL, which OpenSSL's would dereference).
    ///
    /// # Safety
    /// `e` is NULL or a live engine; `value` is what the header's type describes, and stays
    /// valid while the engine holds it.
    pub unsafe extern "C" fn ENGINE_set_load_ssl_client_cert_function(e: *mut ENGINE, value: ENGINE_SSL_CLIENT_CERT_PTR) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(en) = (unsafe { engine(e) }) else { return 0 };
        en.lock().load_ssl_client_cert = value;
        1
    }
}

ffi_export! {
    /// The engine's SSL client certificate loader (none for NULL).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_ssl_client_cert_function(e: *const ENGINE) -> ENGINE_SSL_CLIENT_CERT_PTR
    where failure = None, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.and_then(|f| f.load_ssl_client_cert)
    }
}

ffi_export! {
    /// The engine's id (NULL if unset).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_id(e: *const ENGINE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(ptr::null(), |f| f.id)
    }
}

ffi_export! {
    /// The engine's name (NULL if unset).
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_get_name(e: *const ENGINE) -> *const c_char
    where failure = ptr::null(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { fields(e) }.map_or(ptr::null(), |f| f.name)
    }
}

/// What `ENGINE_get_static_state` points to: a module bound to this library compares it with
/// the one in the `dynamic_fns` it's given, to see whether it shares the library's state.
static STATIC_STATE: u8 = 0;

ffi_export! {
    /// The library's static-state marker (`ENGINE_get_static_state`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_static_state() -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        (&raw const STATIC_STATE).cast_mut().cast()
    }
}

#[cfg(test)]
mod tests;
