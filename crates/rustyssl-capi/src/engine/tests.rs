use core::ffi::{c_int, c_long, c_void};
use core::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

use rustyssl_abi::{
    ENGINE, ENGINE_CMD_DEFN, ENGINE_CMD_FLAG_NUMERIC, ENGINE_CMD_FLAG_STRING,
    ENGINE_CTRL_GET_CMD_FROM_NAME, ENGINE_CTRL_GET_FIRST_CMD_TYPE, ENGINE_CTRL_GET_NEXT_CMD_TYPE,
    ENGINE_CTRL_HAS_CTRL_FUNCTION,
};

use super::ctrl::{ENGINE_ctrl, ENGINE_ctrl_cmd_string};
use super::list::{ENGINE_add, ENGINE_by_id, ENGINE_remove};
use super::table::{ENGINE_get_default_RSA, ENGINE_set_default_RSA, ENGINE_unregister_RSA};
use super::*;

static DESTROYED: AtomicI32 = AtomicI32::new(0);
static INITS: AtomicI32 = AtomicI32::new(0);
static FINISHES: AtomicI32 = AtomicI32::new(0);
static LAST_CTRL: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" fn destroy(_e: *mut ENGINE) -> c_int {
    DESTROYED.fetch_add(1, Ordering::SeqCst);
    1
}

unsafe extern "C" fn init(_e: *mut ENGINE) -> c_int {
    INITS.fetch_add(1, Ordering::SeqCst);
    1
}

unsafe extern "C" fn finish(_e: *mut ENGINE) -> c_int {
    FINISHES.fetch_add(1, Ordering::SeqCst);
    1
}

unsafe extern "C" fn ctrl(
    _e: *mut ENGINE,
    cmd: c_int,
    i: c_long,
    _p: *mut c_void,
    _f: Option<unsafe extern "C" fn()>,
) -> c_int {
    let i = c_int::try_from(i).unwrap_or(-1);
    LAST_CTRL.store(cmd.saturating_mul(1000).saturating_add(i), Ordering::SeqCst);
    1
}

struct Defns([ENGINE_CMD_DEFN; 3]);
// SAFETY: immutable statics.
unsafe impl Sync for Defns {}

static DEFNS: Defns = Defns([
    ENGINE_CMD_DEFN {
        cmd_num: 200,
        cmd_name: c"COUNT".as_ptr(),
        cmd_desc: c"a number".as_ptr(),
        cmd_flags: ENGINE_CMD_FLAG_NUMERIC,
    },
    ENGINE_CMD_DEFN {
        cmd_num: 201,
        cmd_name: c"NAME".as_ptr(),
        cmd_desc: ptr::null(),
        cmd_flags: ENGINE_CMD_FLAG_STRING,
    },
    ENGINE_CMD_DEFN {
        cmd_num: 0,
        cmd_name: ptr::null(),
        cmd_desc: ptr::null(),
        cmd_flags: 0,
    },
]);

/// A new engine with `id` and a name.
fn made(id: &'static core::ffi::CStr) -> *mut ENGINE {
    // SAFETY: no preconditions.
    let e = unsafe { ENGINE_new() };
    // SAFETY: a live engine and a static string.
    assert_eq!(unsafe { ENGINE_set_id(e, id.as_ptr()) }, 1);
    // SAFETY: as above.
    assert_eq!(unsafe { ENGINE_set_name(e, c"test engine".as_ptr()) }, 1);
    e
}

/// `ENGINE_free`, checked.
fn free(e: *mut ENGINE) {
    // SAFETY: the tests' engines, each reference given back once.
    assert_eq!(unsafe { ENGINE_free(e) }, 1);
}

fn clear_errors() {
    // SAFETY: no preconditions.
    unsafe { crate::err::ERR_clear_error() };
}

#[test]
fn an_engine_is_destroyed_at_its_last_structural_reference() {
    let before = DESTROYED.load(Ordering::SeqCst);
    let e = made(c"rustyssl-unit-destroy");
    // SAFETY: a live engine.
    assert_eq!(unsafe { ENGINE_set_destroy_function(e, Some(destroy)) }, 1);
    // SAFETY: as above.
    assert_eq!(unsafe { ENGINE_up_ref(e) }, 1);
    free(e);
    assert_eq!(DESTROYED.load(Ordering::SeqCst), before);
    free(e);
    assert_eq!(DESTROYED.load(Ordering::SeqCst), before + 1);
}

/// docs/DEVIATIONS.md: a table's reference keeps a registered engine alive.
#[test]
fn a_registered_engine_outlives_its_last_reference() {
    let e = made(c"rustyssl-unit-registered");
    static GONE: AtomicI32 = AtomicI32::new(0);
    unsafe extern "C" fn gone(_e: *mut ENGINE) -> c_int {
        GONE.fetch_add(1, Ordering::SeqCst);
        1
    }
    // SAFETY: a live engine.
    assert_eq!(unsafe { ENGINE_set_destroy_function(e, Some(gone)) }, 1);
    // SAFETY: no preconditions.
    let meth = unsafe { crate::rsa_meth::RSA_get_default_method() };
    // SAFETY: a live engine and the library's method.
    assert_eq!(unsafe { ENGINE_set_RSA(e, meth) }, 1);
    // SAFETY: a live engine.
    assert_eq!(unsafe { super::table::ENGINE_register_RSA(e) }, 1);
    free(e);
    assert_eq!(GONE.load(Ordering::SeqCst), 0);
    // SAFETY: the table still holds it.
    unsafe { ENGINE_unregister_RSA(e) };
    assert_eq!(GONE.load(Ordering::SeqCst), 1);
}

/// docs/DEVIATIONS.md: the accessors refuse a NULL engine.
#[test]
fn null_engines_are_refused() {
    // SAFETY: NULL.
    assert!(unsafe { ENGINE_get_id(ptr::null()) }.is_null());
    // SAFETY: as above.
    assert_eq!(unsafe { ENGINE_set_flags(ptr::null_mut(), 1) }, 0);
    // SAFETY: as above.
    assert_eq!(unsafe { ENGINE_get_flags(ptr::null()) }, 0);
    // SAFETY: as above.
    assert!(unsafe { ENGINE_get_RSA(ptr::null()) }.is_null());
}

#[test]
#[cfg_attr(
    miri,
    ignore = "ENGINE_by_id loads the configuration, reading the environment"
)]
fn a_listed_engine_is_found_by_its_id() {
    let e = made(c"rustyssl-unit-listed");
    // SAFETY: a live engine.
    assert_eq!(unsafe { ENGINE_add(e) }, 1);
    // SAFETY: a C string.
    let found = unsafe { ENGINE_by_id(c"rustyssl-unit-listed".as_ptr()) };
    assert_eq!(found, e);
    free(found);
    // A second engine with the same id isn't listed.
    let twin = made(c"rustyssl-unit-listed");
    // SAFETY: a live engine.
    assert_eq!(unsafe { ENGINE_add(twin) }, 0);
    clear_errors();
    free(twin);
    // SAFETY: the listed engine.
    assert_eq!(unsafe { ENGINE_remove(e) }, 1);
    free(e);
}

#[test]
fn control_commands_are_answered_from_the_definitions() {
    let e = made(c"rustyssl-unit-ctrl");
    let ctl = |cmd: c_int, i: c_long, p: *mut c_void| {
        // SAFETY: a live engine; `p` is NULL or a C string, as the commands take.
        unsafe { ENGINE_ctrl(e, cmd, i, p, None) }
    };
    let cmd = |name: &core::ffi::CStr, arg: &core::ffi::CStr, optional: c_int| {
        // SAFETY: a live engine and C strings.
        unsafe { ENGINE_ctrl_cmd_string(e, name.as_ptr(), arg.as_ptr(), optional) }
    };
    assert_eq!(ctl(ENGINE_CTRL_HAS_CTRL_FUNCTION, 0, ptr::null_mut()), 0);
    // SAFETY: a live engine.
    assert_eq!(unsafe { ENGINE_set_ctrl_function(e, Some(ctrl)) }, 1);
    // SAFETY: a live engine and a static table.
    assert_eq!(unsafe { ENGINE_set_cmd_defns(e, DEFNS.0.as_ptr()) }, 1);
    assert_eq!(ctl(ENGINE_CTRL_GET_FIRST_CMD_TYPE, 0, ptr::null_mut()), 200);
    assert_eq!(
        ctl(ENGINE_CTRL_GET_NEXT_CMD_TYPE, 200, ptr::null_mut()),
        201
    );
    assert_eq!(ctl(ENGINE_CTRL_GET_NEXT_CMD_TYPE, 201, ptr::null_mut()), 0);
    let name = c"NAME".as_ptr().cast_mut().cast::<c_void>();
    assert_eq!(ctl(ENGINE_CTRL_GET_CMD_FROM_NAME, 0, name), 201);
    assert_eq!(cmd(c"COUNT", c"42", 0), 1);
    assert_eq!(LAST_CTRL.load(Ordering::SeqCst), 200_042);
    assert_eq!(cmd(c"COUNT", c"4x", 0), 0);
    assert_eq!(cmd(c"MISSING", c"", 1), 1);
    clear_errors();
    free(e);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "a table lookup loads the configuration, reading the environment"
)]
fn a_default_engine_is_initialized_and_finished() {
    let e = made(c"rustyssl-unit-default");
    let (i0, f0) = (
        INITS.load(Ordering::SeqCst),
        FINISHES.load(Ordering::SeqCst),
    );
    // SAFETY: a live engine.
    assert_eq!(unsafe { ENGINE_set_init_function(e, Some(init)) }, 1);
    // SAFETY: as above.
    assert_eq!(unsafe { ENGINE_set_finish_function(e, Some(finish)) }, 1);
    // SAFETY: no preconditions.
    let meth = unsafe { crate::rsa_meth::RSA_get_default_method() };
    // SAFETY: a live engine and the library's method.
    assert_eq!(unsafe { ENGINE_set_RSA(e, meth) }, 1);
    // SAFETY: a live engine.
    assert_eq!(unsafe { ENGINE_set_default_RSA(e) }, 1);
    assert_eq!(INITS.load(Ordering::SeqCst), i0 + 1);
    // SAFETY: no preconditions.
    let d = unsafe { ENGINE_get_default_RSA() };
    assert_eq!(d, e);
    // SAFETY: the functional reference the lookup gave.
    assert_eq!(unsafe { ENGINE_finish(d) }, 1);
    // SAFETY: a live engine.
    unsafe { ENGINE_unregister_RSA(e) };
    assert_eq!(FINISHES.load(Ordering::SeqCst), f0 + 1);
    // SAFETY: no preconditions.
    assert!(unsafe { ENGINE_get_default_RSA() }.is_null());
    free(e);
}
