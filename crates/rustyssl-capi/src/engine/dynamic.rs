//! The dynamic engine (`eng_dyn.c`): its control commands set up a module to load (`SO_PATH`,
//! or `ID` looked for in the `DIR_ADD` directories), and `LOAD` loads it, checks its version
//! (`v_check`), and has its `bind_engine` bind the engine it's called on, which then becomes
//! that module's engine (and is listed, with `LIST_ADD`).
//!
//! A module is a shared library built against OpenSSL's ENGINE API; it links this library (as
//! `libcrypto`), so the engine it binds is one of ours, set up through the same exports an
//! application uses. It's unloaded with the engine's last structural reference.
//!
//! The library is loaded, and the module's functions run, with no lock held.

use core::ffi::{CStr, c_char, c_int, c_long, c_ulong, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Once, PoisonError};

use rustyssl_abi::{
    CRYPTO_EX_INDEX_ENGINE, DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, ENGINE, ENGINE_CMD_BASE,
    ENGINE_CMD_DEFN, ENGINE_CMD_FLAG_NO_INPUT, ENGINE_CMD_FLAG_NUMERIC, ENGINE_CMD_FLAG_STRING,
    ENGINE_FLAGS_BY_ID_COPY, ENGINE_R_ALREADY_LOADED, ENGINE_R_CONFLICTING_ENGINE_ID,
    ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED, ENGINE_R_DSO_FAILURE, ENGINE_R_DSO_NOT_FOUND,
    ENGINE_R_INIT_FAILED, ENGINE_R_INVALID_ARGUMENT, ENGINE_R_NO_INDEX,
    ENGINE_R_VERSION_INCOMPATIBILITY, ERR_LIB_ENGINE, OSSL_DYNAMIC_OLDEST, OSSL_DYNAMIC_VERSION,
    dynamic_bind_engine, dynamic_fns, dynamic_v_check_fn,
};

use super::dso::{Dso, c_str};
use super::{engine, global, new_engine};
use crate::err;

/// The dynamic engine's commands' numbers (`DYNAMIC_CMD_*`).
const SO_PATH: c_int = ENGINE_CMD_BASE;
const NO_VCHECK: c_int = ENGINE_CMD_BASE + 1;
const ID: c_int = ENGINE_CMD_BASE + 2;
const LIST_ADD: c_int = ENGINE_CMD_BASE + 3;
const DIR_LOAD: c_int = ENGINE_CMD_BASE + 4;
const DIR_ADD: c_int = ENGINE_CMD_BASE + 5;
const LOAD: c_int = ENGINE_CMD_BASE + 6;

/// The command definitions, in a table C reads.
struct Defns([ENGINE_CMD_DEFN; 8]);

// SAFETY: the table and its strings are immutable statics.
unsafe impl Sync for Defns {}

const fn defn(num: c_int, name: &'static CStr, desc: &'static CStr, flags: u32) -> ENGINE_CMD_DEFN {
    ENGINE_CMD_DEFN {
        cmd_num: num.cast_unsigned(),
        cmd_name: name.as_ptr(),
        cmd_desc: desc.as_ptr(),
        cmd_flags: flags,
    }
}

static DEFNS: Defns = Defns([
    defn(
        SO_PATH,
        c"SO_PATH",
        c"Specifies the path to the new ENGINE shared library",
        ENGINE_CMD_FLAG_STRING,
    ),
    defn(
        NO_VCHECK,
        c"NO_VCHECK",
        c"Specifies to continue even if version checking fails (boolean)",
        ENGINE_CMD_FLAG_NUMERIC,
    ),
    defn(
        ID,
        c"ID",
        c"Specifies an ENGINE id name for loading",
        ENGINE_CMD_FLAG_STRING,
    ),
    defn(
        LIST_ADD,
        c"LIST_ADD",
        c"Whether to add a loaded ENGINE to the internal list (0=no,1=yes,2=mandatory)",
        ENGINE_CMD_FLAG_NUMERIC,
    ),
    defn(
        DIR_LOAD,
        c"DIR_LOAD",
        c"Specifies whether to load from 'DIR_ADD' directories (0=no,1=yes,2=mandatory)",
        ENGINE_CMD_FLAG_NUMERIC,
    ),
    defn(
        DIR_ADD,
        c"DIR_ADD",
        c"Adds a directory from which ENGINEs can be loaded",
        ENGINE_CMD_FLAG_STRING,
    ),
    defn(
        LOAD,
        c"LOAD",
        c"Load up the ENGINE specified by other settings",
        ENGINE_CMD_FLAG_NO_INPUT,
    ),
    ENGINE_CMD_DEFN {
        cmd_num: 0,
        cmd_name: ptr::null(),
        cmd_desc: ptr::null(),
        cmd_flags: 0,
    },
]);

/// The dynamic engine's settings and the module it loaded (`dynamic_data_ctx`).
pub(super) struct Ctx {
    dso: Option<Dso>,
    libname: Option<CString>,
    no_vcheck: bool,
    engine_id: Option<CString>,
    list_add: c_long,
    /// 0: don't look in the directories; 1: look there if the name alone fails; 2: only there.
    dir_load: c_long,
    dirs: Vec<CString>,
}

impl Default for Ctx {
    fn default() -> Self {
        Self {
            dso: None,
            libname: None,
            no_vcheck: false,
            engine_id: None,
            list_add: 0,
            dir_load: 1,
            dirs: Vec::new(),
        }
    }
}

/// The ENGINE ex_data index OpenSSL's dynamic engine reserves at its first control command,
/// for its per-engine data; reserved here at the same point, so applications' indexes match.
static EX_INDEX: Once = Once::new();

/// Reserves [`EX_INDEX`] (once): false if no index could be had.
pub(crate) fn reserve_ex_index() -> bool {
    let mut ok = true;
    EX_INDEX.call_once(|| {
        // SAFETY: no functions for the index.
        let idx = unsafe {
            crate::ex_data::CRYPTO_get_ex_new_index(
                CRYPTO_EX_INDEX_ENGINE,
                0,
                ptr::null_mut(),
                None,
                None,
                None,
            )
        };
        ok = idx >= 0;
    });
    ok
}

/// The dynamic engine (`engine_dynamic`), with one structural reference, or NULL.
pub(super) fn new() -> *mut ENGINE {
    let e = new_engine();
    // SAFETY: just made.
    let Some(en) = (unsafe { super::engine(e) }) else {
        return ptr::null_mut();
    };
    {
        let mut f = en.lock();
        f.id = c"dynamic".as_ptr();
        f.name = c"Dynamic engine loading support".as_ptr();
        f.init = Some(dynamic_init);
        f.finish = Some(dynamic_finish);
        f.ctrl = Some(dynamic_ctrl);
        f.flags = ENGINE_FLAGS_BY_ID_COPY;
        f.cmd_defns = DEFNS.0.as_ptr();
    }
    e
}

/// `dynamic_init`: the dynamic engine itself can't be initialized (only what it loads).
unsafe extern "C" fn dynamic_init(_e: *mut ENGINE) -> c_int {
    0
}

/// `dynamic_finish`.
unsafe extern "C" fn dynamic_finish(_e: *mut ENGINE) -> c_int {
    0
}

/// `dynamic_ctrl`: the dynamic engine's commands, until it has loaded a module.
unsafe extern "C" fn dynamic_ctrl(
    e: *mut ENGINE,
    cmd: c_int,
    i: c_long,
    p: *mut c_void,
    _f: Option<unsafe extern "C" fn()>,
) -> c_int {
    crate::ffi::guard(
        ERR_LIB_ENGINE,
        "dynamic_ctrl",
        || 0,
        || {
            // SAFETY: the library calls this with a live engine.
            let Some(en) = (unsafe { engine(e) }) else {
                return 0;
            };
            if !reserve_ex_index() {
                err::raise(ERR_LIB_ENGINE, ENGINE_R_NO_INDEX, "dynamic_get_data_ctx");
                err::raise(
                    ERR_LIB_ENGINE,
                    rustyssl_abi::ENGINE_R_NOT_LOADED,
                    "dynamic_ctrl",
                );
                return 0;
            }
            let mut slot = en.dynamic.lock().unwrap_or_else(PoisonError::into_inner);
            let ctx = slot.get_or_insert_with(Ctx::default);
            // OpenSSL's test: whether the DSO object exists. A `LOAD` with nothing to load makes
            // one and keeps it, so every command after it fails this way, as in OpenSSL.
            if ctx.dso.is_some() {
                err::raise(ERR_LIB_ENGINE, ENGINE_R_ALREADY_LOADED, "dynamic_ctrl");
                return 0;
            }
            // SAFETY: a string command's argument is NULL or a C string.
            let text = || unsafe { c_str(p.cast::<c_char>()) }.filter(|s| !s.is_empty());
            match cmd {
                SO_PATH => {
                    ctx.libname = text().map(CStr::to_owned);
                    c_int::from(ctx.libname.is_some())
                }
                NO_VCHECK => {
                    ctx.no_vcheck = i != 0;
                    1
                }
                ID => {
                    ctx.engine_id = text().map(CStr::to_owned);
                    c_int::from(ctx.engine_id.is_some())
                }
                LIST_ADD | DIR_LOAD => {
                    if !(0..=2).contains(&i) {
                        err::raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_ARGUMENT, "dynamic_ctrl");
                        return 0;
                    }
                    if cmd == LIST_ADD {
                        ctx.list_add = i;
                    } else {
                        ctx.dir_load = i;
                    }
                    1
                }
                DIR_ADD => match text() {
                    Some(d) => {
                        ctx.dirs.push(d.to_owned());
                        1
                    }
                    None => {
                        err::raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_ARGUMENT, "dynamic_ctrl");
                        0
                    }
                },
                LOAD => {
                    // The work runs with no lock held: the module's code runs.
                    let settings = core::mem::take(ctx);
                    drop(slot);
                    // SAFETY: the engine is live.
                    let (settings, r) = unsafe { load(e, settings) };
                    *en.dynamic.lock().unwrap_or_else(PoisonError::into_inner) = Some(settings);
                    r
                }
                _ => {
                    err::raise(
                        ERR_LIB_ENGINE,
                        ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED,
                        "dynamic_ctrl",
                    );
                    0
                }
            }
        },
    )
}

/// `int_load`: the library by its name (unless `DIR_LOAD` is 2), else in each directory.
fn int_load(ctx: &Ctx, dso: &mut Dso) -> bool {
    let Some(name) = ctx.libname.as_deref() else {
        return false;
    };
    if ctx.dir_load != 2 && dso.load(name) {
        return true;
    }
    if ctx.dir_load == 0 || ctx.dirs.is_empty() {
        return false;
    }
    for dir in &ctx.dirs {
        let Some(merged) = dso.merge(name, dir) else {
            return false;
        };
        if dso.load(&merged) {
            return true;
        }
    }
    false
}

/// `using_libcrypto_11`: whether the module was built against OpenSSL 1.1 (whose libcrypto
/// has `EVP_PKEY_base_id`, which this one doesn't export).
fn using_libcrypto_11(dso: &Dso) -> bool {
    // SAFETY: no preconditions.
    unsafe { crate::err::ERR_set_mark() };
    let r = dso.bind_func(c"EVP_PKEY_base_id").is_some();
    // SAFETY: the mark set above.
    unsafe { crate::err::ERR_pop_to_mark() };
    r
}

/// `dynamic_load`: loads the module, checks it, and has it bind `e`. The settings come back
/// with the module when it's loaded.
///
/// # Safety
/// `e` is a live engine.
unsafe fn load(e: *mut ENGINE, mut ctx: Ctx) -> (Ctx, c_int) {
    let mut dso = ctx.dso.take().unwrap_or_default();
    if ctx.libname.is_none() {
        let Some(id) = ctx.engine_id.as_deref() else {
            // The DSO object stays (`ctx->dynamic_dso` isn't freed on this path).
            ctx.dso = Some(dso);
            return (ctx, 0);
        };
        dso.set_flags(DSO_FLAG_NAME_TRANSLATION_EXT_ONLY);
        ctx.libname = dso.convert_filename(Some(id));
    }
    if !int_load(&ctx, &mut dso) {
        err::raise(ERR_LIB_ENGINE, ENGINE_R_DSO_NOT_FOUND, "dynamic_load");
        return (ctx, 0);
    }
    let Some(bind) = dso.bind_func(c"bind_engine") else {
        err::raise(ERR_LIB_ENGINE, ENGINE_R_DSO_FAILURE, "dynamic_load");
        return (ctx, 0);
    };
    // SAFETY: the module's `bind_engine`, whose type OpenSSL's ENGINE ABI fixes.
    let bind: dynamic_bind_engine =
        unsafe { core::mem::transmute::<*mut c_void, dynamic_bind_engine>(bind) };
    if !ctx.no_vcheck {
        let mut vcheck: c_ulong = 0;
        if let Some(v) = dso.bind_func(c"v_check") {
            // SAFETY: the module's `v_check`, whose type OpenSSL's ENGINE ABI fixes.
            let v: dynamic_v_check_fn =
                unsafe { core::mem::transmute::<*mut c_void, dynamic_v_check_fn>(v) };
            if let Some(v) = v {
                // SAFETY: the module's function; no lock is held.
                vcheck = unsafe { v(OSSL_DYNAMIC_VERSION) };
            }
        }
        if vcheck < OSSL_DYNAMIC_OLDEST || using_libcrypto_11(&dso) {
            err::raise(
                ERR_LIB_ENGINE,
                ENGINE_R_VERSION_INCOMPATIBILITY,
                "dynamic_load",
            );
            return (ctx, 0);
        }
    }
    let Some(bind) = bind else {
        err::raise(ERR_LIB_ENGINE, ENGINE_R_DSO_FAILURE, "dynamic_load");
        return (ctx, 0);
    };
    // SAFETY: the caller's guarantee.
    let Some(en) = (unsafe { engine(e) }) else {
        return (ctx, 0);
    };
    let saved = {
        let mut f = en.lock();
        let saved = *f;
        f.set_all_null();
        saved
    };
    let mut fns = dynamic_fns {
        // SAFETY: no preconditions.
        static_state: unsafe { super::ENGINE_get_static_state() },
        mem_fns: rustyssl_abi::dynamic_MEM_fns {
            malloc_fn: None,
            realloc_fn: None,
            free_fn: None,
        },
    };
    // SAFETY: locals to fill.
    unsafe {
        crate::mem::CRYPTO_get_mem_functions(
            &raw mut fns.mem_fns.malloc_fn,
            &raw mut fns.mem_fns.realloc_fn,
            &raw mut fns.mem_fns.free_fn,
        )
    };
    let id = ctx.engine_id.as_deref().map_or(ptr::null(), CStr::as_ptr);
    let added = super::list::add_dynamic_id(&mut global(), e, bind as usize);
    // SAFETY: the module's function, given the engine to bind, the id and the library's state;
    // no lock is held.
    let bound = added && unsafe { bind(e, id, &raw const fns) } != 0;
    if !bound {
        super::list::remove_dynamic_id(e);
        err::raise(ERR_LIB_ENGINE, ENGINE_R_INIT_FAILED, "dynamic_load");
        *en.lock() = saved;
        return (ctx, 0);
    }
    ctx.dso = Some(dso);
    if ctx.list_add > 0 {
        // SAFETY: a live engine.
        if unsafe { super::list::ENGINE_add(e) } == 0 {
            if ctx.list_add > 1 {
                err::raise(
                    ERR_LIB_ENGINE,
                    ENGINE_R_CONFLICTING_ENGINE_ID,
                    "dynamic_load",
                );
                return (ctx, 0);
            }
            // SAFETY: no preconditions.
            unsafe { crate::err::ERR_clear_error() };
        }
    }
    (ctx, 1)
}
