//! The engine list (`eng_list.c`), the built-in engines (`eng_all.c`, the
//! `OPENSSL_INIT_ENGINE_*` flags), and `ENGINE_by_id`.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ENGINE, ENGINE_FLAGS_BY_ID_COPY, ENGINE_R_CONFLICTING_ENGINE_ID,
    ENGINE_R_ENGINE_IS_NOT_IN_LIST, ENGINE_R_ID_OR_NAME_MISSING, ENGINE_R_INTERNAL_LIST_ERROR,
    ENGINE_R_NO_SUCH_ENGINE, ERR_LIB_ENGINE, OPENSSL_INIT_ENGINE_AFALG,
    OPENSSL_INIT_ENGINE_ALL_BUILTIN, OPENSSL_INIT_ENGINE_DYNAMIC, OPENSSL_INIT_ENGINE_OPENSSL,
    OPENSSL_INIT_ENGINE_RDRAND,
};

use super::{
    EnginePtr, Fields, Guard, engine, free_util, free_util_locked, global, new_engine,
    null_parameter, same_id, up_struct,
};
use crate::err;
use crate::ffi::ffi_export;

/// `engine_list_add`: puts `e` at the end of the list with a structural reference, unless an
/// engine with its id is there.
///
/// # Safety
/// `e` is a live engine.
unsafe fn list_add(g: &mut Guard, e: *mut ENGINE) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(en) = (unsafe { engine(e) }) else {
        null_parameter("engine_list_add");
        return false;
    };
    let id = en.fields().id;
    // SAFETY: the listed engines are live (the list holds them); ids are C strings.
    let conflict = g
        .list
        .iter()
        .any(|&p| unsafe { super::fields(p.0) }.is_some_and(|f| unsafe { same_id(f.id, id) }));
    if conflict {
        err::raise(
            ERR_LIB_ENGINE,
            ENGINE_R_CONFLICTING_ENGINE_ID,
            "engine_list_add",
        );
        return false;
    }
    // SAFETY: the caller's guarantee.
    unsafe { up_struct(e) };
    g.list.push(EnginePtr(e));
    true
}

/// `engine_list_remove`: takes `e` off the list and drops the list's reference.
///
/// # Safety
/// `e` is NULL or a live engine.
unsafe fn list_remove(g: Guard, e: *mut ENGINE) -> (Guard, bool) {
    let Some(i) = g.list.iter().position(|&p| p == EnginePtr(e)) else {
        err::raise(
            ERR_LIB_ENGINE,
            ENGINE_R_ENGINE_IS_NOT_IN_LIST,
            "engine_list_remove",
        );
        return (g, false);
    };
    let mut g = g;
    g.list.remove(i);
    // SAFETY: the list's reference.
    (unsafe { free_util_locked(g, e) }, true)
}

/// `engine_add_dynamic_id`: records that the module whose `bind_engine` is `id` bound `e`,
/// and puts `e` on the dynamic list. With `id` 0, `e` keeps the id it has (a copy's). False if
/// the id is already taken or `e` has neither.
///
/// OpenSSL walks the dynamic list's first engine and then the engines after it *on the engine
/// list* (it follows `next`, not `next_dyn`) looking for the id; so does this.
pub(super) fn add_dynamic_id(g: &mut Guard, e: *mut ENGINE, id: usize) -> bool {
    // SAFETY: the callers pass live engines.
    let Some(en) = (unsafe { engine(e) }) else {
        return false;
    };
    let own = en.fields().dynamic_id;
    if own == 0 && id == 0 {
        return false;
    }
    if id != 0 {
        let mut it = g.dyn_list.first().copied();
        while let Some(p) = it {
            // SAFETY: listed engines are live.
            if unsafe { super::fields(p.0) }.is_some_and(|pf| pf.dynamic_id == id) {
                return false;
            }
            it = g
                .list
                .iter()
                .position(|&q| q == p)
                .and_then(|i| g.list.get(i.saturating_add(1)))
                .copied();
        }
        if own != 0 {
            return false;
        }
        en.lock().dynamic_id = id;
    }
    g.dyn_list.push(EnginePtr(e));
    true
}

/// `engine_remove_dynamic_id`: takes `e` off the dynamic list.
pub(super) fn remove_dynamic_id(e: *mut ENGINE) {
    // SAFETY: the callers pass live engines.
    let Some(en) = (unsafe { engine(e) }) else {
        return;
    };
    if en.lock().dynamic_id == 0 {
        return;
    }
    let mut g = global();
    en.lock().dynamic_id = 0;
    g.dyn_list.retain(|&p| p != EnginePtr(e));
}

ffi_export! {
    /// Adds the engine to the list (which takes a structural reference): 1, or 0 if it has
    /// no id or name, or another listed engine has its id.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_add(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        let Some(f) = (unsafe { super::fields(e) }) else {
            null_parameter("ENGINE_add");
            return 0;
        };
        if f.id.is_null() || f.name.is_null() {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_ID_OR_NAME_MISSING, "ENGINE_add");
            return 0;
        }
        let mut g = global();
        // SAFETY: the caller's guarantee.
        if !unsafe { list_add(&mut g, e) } {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR, "ENGINE_add");
            return 0;
        }
        1
    }
}

ffi_export! {
    /// Takes the engine off the list (dropping the list's reference): 1, or 0.
    ///
    /// # Safety
    /// `e` is NULL or a live engine.
    pub unsafe extern "C" fn ENGINE_remove(e: *mut ENGINE) -> c_int
    where failure = 0, library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        if unsafe { engine(e) }.is_none() {
            null_parameter("ENGINE_remove");
            return 0;
        }
        // SAFETY: as above.
        let (_g, ok) = unsafe { list_remove(global(), e) };
        if !ok {
            err::raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR, "ENGINE_remove");
            return 0;
        }
        1
    }
}

/// The listed engine `pick` chooses, with a structural reference for the caller.
fn listed(pick: impl FnOnce(&[EnginePtr]) -> Option<EnginePtr>) -> *mut ENGINE {
    let g = global();
    match pick(&g.list) {
        Some(p) => {
            // SAFETY: listed engines are live.
            unsafe { up_struct(p.0) };
            p.0
        }
        None => ptr::null_mut(),
    }
}

ffi_export! {
    /// The first engine on the list, with a structural reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_first() -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        listed(|l| l.first().copied())
    }
}

ffi_export! {
    /// The last engine on the list, with a structural reference, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_get_last() -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        listed(|l| l.last().copied())
    }
}

/// `ENGINE_get_next`/`_prev`: the neighbour `step` picks of `e` on the list (none if `e` isn't
/// listed), with a structural reference; drops the caller's reference to `e`.
///
/// # Safety
/// `e` is NULL or a live engine whose reference the caller gives up.
unsafe fn neighbour(
    e: *mut ENGINE,
    function: &str,
    step: fn(usize) -> Option<usize>,
) -> *mut ENGINE {
    // SAFETY: the caller's guarantee.
    if unsafe { engine(e) }.is_none() {
        null_parameter(function);
        return ptr::null_mut();
    }
    let ret = listed(|l| {
        let i = l.iter().position(|&p| p == EnginePtr(e))?;
        l.get(step(i)?).copied()
    });
    // SAFETY: the caller's reference.
    unsafe { free_util(e) };
    ret
}

ffi_export! {
    /// The engine after `e` on the list, with a structural reference, or NULL; `e`'s
    /// reference is dropped.
    ///
    /// # Safety
    /// `e` is NULL or a live engine whose reference the caller gives up.
    pub unsafe extern "C" fn ENGINE_get_next(e: *mut ENGINE) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { neighbour(e, "ENGINE_get_next", |i| i.checked_add(1)) }
    }
}

ffi_export! {
    /// The engine before `e` on the list, with a structural reference, or NULL; `e`'s
    /// reference is dropped.
    ///
    /// # Safety
    /// `e` is NULL or a live engine whose reference the caller gives up.
    pub unsafe extern "C" fn ENGINE_get_prev(e: *mut ENGINE) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        // SAFETY: the caller's guarantee.
        unsafe { neighbour(e, "ENGINE_get_prev", |i| i.checked_sub(1)) }
    }
}

/// `engine_cpy`: a new engine with `src`'s settings (not its public-key ASN.1 methods or its
/// SSL client certificate loader, which OpenSSL doesn't copy), on the dynamic list if `src`
/// was bound by a module.
fn copy(g: &mut Guard, src: Fields) -> *mut ENGINE {
    let cp = new_engine();
    // SAFETY: just made.
    let Some(en) = (unsafe { engine(cp) }) else {
        return ptr::null_mut();
    };
    *en.lock() = Fields {
        pkey_asn1_meths: None,
        load_ssl_client_cert: None,
        ..src
    };
    add_dynamic_id(g, cp, 0);
    cp
}

/// `ENGINE_by_id`'s search of the list: the engine with `id` (a copy, for one flagged
/// `ENGINE_FLAGS_BY_ID_COPY`), with a structural reference, or NULL.
///
/// # Safety
/// `id` is a C string.
unsafe fn find(id: *const c_char) -> *mut ENGINE {
    let mut g = global();
    let found = g.list.iter().find_map(|&p| {
        // SAFETY: listed engines are live; ids are C strings.
        let f = unsafe { super::fields(p.0) }?;
        // SAFETY: as above.
        unsafe { same_id(id, f.id) }.then_some((p, f))
    });
    match found {
        Some((_, f)) if f.flags & ENGINE_FLAGS_BY_ID_COPY != 0 => copy(&mut g, f),
        Some((p, _)) => {
            // SAFETY: listed engines are live.
            unsafe { up_struct(p.0) };
            p.0
        }
        None => ptr::null_mut(),
    }
}

/// Runs one of the dynamic engine's commands by name.
///
/// # Safety
/// `e` is a live engine; `arg` NULL or a C string.
unsafe fn command(e: *mut ENGINE, name: &CStr, arg: *const c_char) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { super::ctrl::ENGINE_ctrl_cmd_string(e, name.as_ptr(), arg, 0) } != 0)
}

ffi_export! {
    /// The engine with the id `id`, with a structural reference: a listed one (a copy of one
    /// flagged `ENGINE_FLAGS_BY_ID_COPY`), else one the dynamic engine loads from the engines
    /// directory (`$OPENSSL_ENGINES`, else `ENGINESDIR`) and lists. NULL, with
    /// `ENGINE_R_NO_SUCH_ENGINE`, if there's none. The built-in engines are loaded first.
    ///
    /// # Safety
    /// `id` is NULL or a C string.
    pub unsafe extern "C" fn ENGINE_by_id(id: *const c_char) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_ENGINE
    {
        if id.is_null() {
            null_parameter("ENGINE_by_id");
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        unsafe { ENGINE_load_builtin_engines() };
        // SAFETY: the caller's guarantee.
        let found = unsafe { find(id) };
        if !found.is_null() {
            return found;
        }
        // SAFETY: as above.
        let ids = unsafe { CStr::from_ptr(id) };
        let mut it = ptr::null_mut();
        if ids != c"dynamic" {
            let dir = crate::init::safe_getenv(c"OPENSSL_ENGINES")
                .unwrap_or_else(|| crate::version::enginesdir().to_owned());
            // SAFETY: a C string.
            it = unsafe { ENGINE_by_id(c"dynamic".as_ptr()) };
            // SAFETY: the dynamic engine, and C strings.
            let loaded = !it.is_null()
                && unsafe { command(it, c"ID", id) }
                && unsafe { command(it, c"DIR_LOAD", c"2".as_ptr()) }
                && unsafe { command(it, c"DIR_ADD", dir.as_ptr()) }
                && unsafe { command(it, c"LIST_ADD", c"1".as_ptr()) }
                && unsafe { command(it, c"LOAD", ptr::null()) };
            if loaded {
                return it;
            }
        }
        // SAFETY: our reference, or NULL.
        unsafe { free_util(it) };
        err::raise_with_bytes(
            ERR_LIB_ENGINE,
            ENGINE_R_NO_SUCH_ENGINE,
            "ENGINE_by_id",
            &[b"id=", ids.to_bytes()].concat(),
        );
        ptr::null_mut()
    }
}

ffi_export! {
    /// Loads the built-in engines (`OPENSSL_INIT_ENGINE_ALL_BUILTIN`).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ENGINE_load_builtin_engines()
    where failure = (), library = ERR_LIB_ENGINE
    {
        let flags = u64::try_from(OPENSSL_INIT_ENGINE_ALL_BUILTIN).unwrap_or(0);
        // SAFETY: no settings.
        unsafe { crate::init::OPENSSL_init_crypto(flags, ptr::null()) };
    }
}

/// Lists `e` (made by a built-in engine's constructor) as `engine_load_*_int` do: an `add` that
/// fails (an engine with its id is there) leaves no error. Drops the constructor's reference.
fn add_builtin(e: *mut ENGINE) {
    if e.is_null() {
        return;
    }
    // SAFETY: no preconditions.
    unsafe { crate::err::ERR_set_mark() };
    // SAFETY: a live engine.
    unsafe { ENGINE_add(e) };
    // SAFETY: the constructor's reference.
    unsafe { free_util(e) };
    // SAFETY: the mark set above.
    unsafe { crate::err::ERR_pop_to_mark() };
}

/// The `OPENSSL_INIT_ENGINE_*` part of `OPENSSL_init_crypto`, for the flags not yet done: lists
/// the built-in engines asked for (each once), then registers every listed engine's methods
/// (`ENGINE_register_all_complete`) when the built-in set, the `openssl` engine or `afalg` was
/// asked for. The `openssl` test engine isn't built, and asking for it aborts.
pub(crate) fn load_builtins(opts: u64) {
    use std::sync::Once;
    static RDRAND: Once = Once::new();
    static DYNAMIC: Once = Once::new();
    let flag = |f: core::ffi::c_long| u64::try_from(f).unwrap_or(0);
    if opts & flag(OPENSSL_INIT_ENGINE_OPENSSL) != 0 {
        // The `openssl` test engine (`eng_openssl.c`), which `ENGINE_load_openssl` asks for:
        // not built (security rule 10, fail closed).
        crate::stub::unimplemented("the `openssl` test engine (ENGINE_load_openssl)");
    }
    if opts & flag(OPENSSL_INIT_ENGINE_RDRAND) != 0 {
        RDRAND.call_once(|| {
            #[cfg(target_arch = "x86_64")]
            add_builtin(super::rdrand::new());
        });
    }
    if opts & flag(OPENSSL_INIT_ENGINE_DYNAMIC) != 0 {
        DYNAMIC.call_once(|| add_builtin(super::dynamic::new()));
    }
    // The default build has no static engines (`OPENSSL_NO_STATIC_ENGINE`): devcrypto,
    // padlock, capi and afalg are modules the dynamic engine loads, if at all.
    let all = flag(OPENSSL_INIT_ENGINE_ALL_BUILTIN)
        | flag(OPENSSL_INIT_ENGINE_OPENSSL)
        | flag(OPENSSL_INIT_ENGINE_AFALG);
    if opts & all != 0 {
        // SAFETY: no preconditions.
        unsafe { super::table::ENGINE_register_all_complete() };
    }
}
