//! Engines (`apps/lib/engine.c`'s needs). The API is deprecated but in the default build.

use core::ffi::{c_int, c_uint};

use crate::abi::{ENGINE, ENGINE_CTRL_SET_LOGSTREAM};
use crate::bio::Bio;
use crate::ffi;
use crate::util::{cstring, string_at};

/// An engine's structural reference, released (`ENGINE_free`) when dropped.
pub struct Engine(core::ptr::NonNull<ENGINE>);

impl Drop for Engine {
    fn drop(&mut self) {
        // SAFETY: the reference is owned here and released once.
        unsafe { ffi::ENGINE_free(self.0.as_ptr()) };
    }
}

impl Engine {
    /// `ENGINE_by_id`.
    pub fn by_id(id: &str) -> Option<Self> {
        let i = cstring(id)?;
        // SAFETY: a valid C string; the result is a new structural reference.
        core::ptr::NonNull::new(unsafe { ffi::ENGINE_by_id(i.as_ptr()) }).map(Self)
    }

    pub fn as_ptr(&self) -> *mut ENGINE {
        self.0.as_ptr()
    }

    /// `ENGINE_ctrl_cmd_string(e, cmd, arg, 0)`.
    pub fn ctrl_cmd_string(&self, cmd: &str, arg: Option<&str>) -> bool {
        let Some(c) = cstring(cmd) else {
            return false;
        };
        let a = match arg {
            Some(a) => match cstring(a) {
                Some(a) => Some(a),
                None => return false,
            },
            None => None,
        };
        // SAFETY: the engine is live; the strings are valid or NULL.
        unsafe {
            ffi::ENGINE_ctrl_cmd_string(
                self.as_ptr(),
                c.as_ptr(),
                a.as_ref().map_or(core::ptr::null(), |a| a.as_ptr()),
                0,
            ) == 1
        }
    }

    /// `ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio, 0)`.
    pub fn set_logstream(&self, bio: &Bio) {
        // SAFETY: the engine and BIO are live; the BIO outlives the engine's use of it.
        unsafe {
            ffi::ENGINE_ctrl(
                self.as_ptr(),
                ENGINE_CTRL_SET_LOGSTREAM,
                0,
                bio.as_ptr().cast(),
                None,
            )
        };
    }

    /// `ENGINE_ctrl_cmd(e, "SET_USER_INTERFACE", 0, get_ui_method(), 0, 1)`.
    pub fn set_user_interface(&self) -> bool {
        // SAFETY: the engine is live; the method is static for the program's life.
        unsafe {
            ffi::ENGINE_ctrl_cmd(
                self.as_ptr(),
                c"SET_USER_INTERFACE".as_ptr(),
                0,
                crate::ui::method().cast_mut().cast(),
                None,
                1,
            ) == 1
        }
    }

    /// `ENGINE_set_default(e, methods)`.
    pub fn set_default(&self, methods: c_uint) -> bool {
        // SAFETY: the engine is live.
        unsafe { ffi::ENGINE_set_default(self.as_ptr(), methods) == 1 }
    }

    /// `ENGINE_get_id`.
    pub fn id(&self) -> String {
        // SAFETY: the engine is live; the id is owned by it.
        string_at(unsafe { ffi::ENGINE_get_id(self.as_ptr()) }).unwrap_or_default()
    }

    /// `ENGINE_init`: what it returns.
    pub fn init(&self) -> c_int {
        // SAFETY: the engine is live.
        unsafe { ffi::ENGINE_init(self.as_ptr()) }
    }

    /// `ENGINE_finish`: what it returns.
    pub fn finish(&self) -> c_int {
        // SAFETY: the engine is live (with a functional reference from init).
        unsafe { ffi::ENGINE_finish(self.as_ptr()) }
    }
}

/// `ENGINE_register_all_complete()`.
pub fn register_all_complete() {
    // SAFETY: no arguments.
    unsafe { ffi::ENGINE_register_all_complete() };
}

use crate::abi::{
    OSSL_STORE_INFO, OSSL_STORE_INFO_PKEY, OSSL_STORE_INFO_PUBKEY, OSSL_STORE_LOADER,
    OSSL_STORE_LOADER_CTX, UI_METHOD,
};

/// `ENGINE_SCHEME` of `engine_loader.h`.
pub const ENGINE_SCHEME: &str = "org.openssl.engine";

/// `struct ossl_store_loader_ctx_st` of `engine_loader.c`.
struct LoaderCtx {
    engine: Engine,
    keyid: std::ffi::CString,
    expected: c_int,
    loaded: bool,
}

unsafe extern "C" fn engine_open(
    _loader: *const OSSL_STORE_LOADER,
    uri: *const core::ffi::c_char,
    _ui_method: *const UI_METHOD,
    _ui_data: *mut core::ffi::c_void,
) -> *mut OSSL_STORE_LOADER_CTX {
    let Some(uri) = string_at(uri) else {
        return core::ptr::null_mut();
    };
    let prefix = format!("{ENGINE_SCHEME}:");
    let Some(rest) = uri
        .get(..prefix.len())
        .filter(|p| p.eq_ignore_ascii_case(&prefix))
        .and_then(|_| uri.get(prefix.len()..))
    else {
        return core::ptr::null_mut();
    };
    // `<engine id>:<key id>`, both at least one character; the id at most 255.
    let Some((id, keyid)) = rest.split_once(':') else {
        return core::ptr::null_mut();
    };
    if id.is_empty() || keyid.is_empty() {
        return core::ptr::null_mut();
    }
    let id = id.get(..id.len().min(255)).unwrap_or(id);
    let (Some(engine), Some(keyid)) = (Engine::by_id(id), cstring(keyid)) else {
        return core::ptr::null_mut();
    };
    let ctx = Box::new(LoaderCtx {
        engine,
        keyid,
        expected: 0,
        loaded: false,
    });
    Box::into_raw(ctx).cast()
}

/// The context `engine_open` made.
///
/// # Safety
/// `ctx` came from `engine_open` and isn't closed.
unsafe fn ctx_of<'a>(ctx: *mut OSSL_STORE_LOADER_CTX) -> &'a mut LoaderCtx {
    // SAFETY: the caller's contract; the store calls one callback at a time.
    unsafe { &mut *ctx.cast::<LoaderCtx>() }
}

unsafe extern "C" fn engine_expect(ctx: *mut OSSL_STORE_LOADER_CTX, expected: c_int) -> c_int {
    if expected == 0 || expected == OSSL_STORE_INFO_PUBKEY || expected == OSSL_STORE_INFO_PKEY {
        // SAFETY: the store passes back the context engine_open made.
        unsafe { ctx_of(ctx) }.expected = expected;
        return 1;
    }
    0
}

unsafe extern "C" fn engine_load(
    ctx: *mut OSSL_STORE_LOADER_CTX,
    ui_method: *const UI_METHOD,
    ui_data: *mut core::ffi::c_void,
) -> *mut OSSL_STORE_INFO {
    // SAFETY: as above.
    let c = unsafe { ctx_of(ctx) };
    let e = c.engine.as_ptr();
    let mut pkey = core::ptr::null_mut();
    let mut pubkey = core::ptr::null_mut();
    // SAFETY: e is live; the UI method and data are the store's, passed on.
    if !c.loaded && unsafe { ffi::ENGINE_init(e) } == 1 {
        if c.expected == 0 || c.expected == OSSL_STORE_INFO_PKEY {
            // SAFETY: as above; the key id is a valid C string.
            pkey = unsafe {
                ffi::ENGINE_load_private_key(e, c.keyid.as_ptr(), ui_method.cast_mut(), ui_data)
            };
        }
        if (pkey.is_null() && c.expected == 0) || c.expected == OSSL_STORE_INFO_PUBKEY {
            // SAFETY: as above.
            pubkey = unsafe {
                ffi::ENGINE_load_public_key(e, c.keyid.as_ptr(), ui_method.cast_mut(), ui_data)
            };
        }
        // SAFETY: the functional reference from ENGINE_init.
        unsafe { ffi::ENGINE_finish(e) };
    }
    c.loaded = true;
    let info = if !pubkey.is_null() {
        // SAFETY: on success the info owns pubkey.
        unsafe { ffi::OSSL_STORE_INFO_new_PUBKEY(pubkey) }
    } else if !pkey.is_null() {
        // SAFETY: on success the info owns pkey.
        unsafe { ffi::OSSL_STORE_INFO_new_PKEY(pkey) }
    } else {
        core::ptr::null_mut()
    };
    if info.is_null() {
        // SAFETY: neither key was taken; EVP_PKEY_free(NULL) is a no-op.
        unsafe { ffi::EVP_PKEY_free(pkey) };
        // SAFETY: as above.
        unsafe { ffi::EVP_PKEY_free(pubkey) };
    }
    info
}

unsafe extern "C" fn engine_eof(ctx: *mut OSSL_STORE_LOADER_CTX) -> c_int {
    // SAFETY: as above.
    c_int::from(unsafe { ctx_of(ctx) }.loaded)
}

unsafe extern "C" fn engine_error(_ctx: *mut OSSL_STORE_LOADER_CTX) -> c_int {
    0
}

unsafe extern "C" fn engine_close(ctx: *mut OSSL_STORE_LOADER_CTX) -> c_int {
    // SAFETY: the context engine_open made, closed once: its Box is reclaimed.
    drop(unsafe { Box::from_raw(ctx.cast::<LoaderCtx>()) });
    1
}

/// `setup_engine_loader`: registers the `org.openssl.engine:<id>:<key id>` store loader.
pub fn setup_loader() -> bool {
    let Some(scheme) = cstring(ENGINE_SCHEME) else {
        return false;
    };
    // SAFETY: NULL engine; the scheme is copied.
    let l = unsafe { ffi::OSSL_STORE_LOADER_new(core::ptr::null_mut(), scheme.as_ptr()) };
    if l.is_null() {
        return false;
    }
    // SAFETY: l is a fresh loader; each callback has the setter's type.
    let ok = unsafe { ffi::OSSL_STORE_LOADER_set_open(l, Some(engine_open)) } == 1
        // SAFETY: as above.
        && unsafe { ffi::OSSL_STORE_LOADER_set_expect(l, Some(engine_expect)) } == 1
        // SAFETY: as above.
        && unsafe { ffi::OSSL_STORE_LOADER_set_load(l, Some(engine_load)) } == 1
        // SAFETY: as above.
        && unsafe { ffi::OSSL_STORE_LOADER_set_eof(l, Some(engine_eof)) } == 1
        // SAFETY: as above.
        && unsafe { ffi::OSSL_STORE_LOADER_set_error(l, Some(engine_error)) } == 1
        // SAFETY: as above.
        && unsafe { ffi::OSSL_STORE_LOADER_set_close(l, Some(engine_close)) } == 1
        // SAFETY: on success the library keeps the loader until it is unregistered.
        && unsafe { ffi::OSSL_STORE_register_loader(l) } == 1;
    if !ok {
        // SAFETY: l is still owned here.
        unsafe { ffi::OSSL_STORE_LOADER_free(l) };
    }
    ok
}

/// `destroy_engine_loader`.
pub fn destroy_loader() {
    let Some(scheme) = cstring(ENGINE_SCHEME) else {
        return;
    };
    // SAFETY: a valid C string; the loader returned is now owned here.
    let l = unsafe { ffi::OSSL_STORE_unregister_loader(scheme.as_ptr()) };
    // SAFETY: NULL or the loader setup_loader registered.
    unsafe { ffi::OSSL_STORE_LOADER_free(l) };
}
