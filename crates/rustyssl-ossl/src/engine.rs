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
    // OSSL_STORE_LOADER_new keeps the pointer (it doesn't copy the scheme), so it is static.
    const SCHEME: &core::ffi::CStr = c"org.openssl.engine";
    debug_assert_eq!(SCHEME.to_str(), Ok(ENGINE_SCHEME));
    // SAFETY: NULL engine; the scheme is a static C string, which outlives the loader.
    let l = unsafe { ffi::OSSL_STORE_LOADER_new(core::ptr::null_mut(), SCHEME.as_ptr()) };
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

/// `get_legacy_pkey_id` of `apps/lib/engine.c`: the NID of an engine's key type named
/// `algname`, or `NID_undef`.
pub fn legacy_pkey_id(algname: &str, e: Option<&Engine>) -> c_int {
    let Some(n) = cstring(algname) else {
        return 0;
    };
    let mut tmpeng: *mut ENGINE = core::ptr::null_mut();
    // SAFETY: no arguments.
    unsafe { ffi::ERR_set_mark() };
    // SAFETY: tmpeng is a valid out-pointer; n a valid C string.
    let mut ameth = unsafe { ffi::EVP_PKEY_asn1_find_str(&mut tmpeng, n.as_ptr(), -1) };
    // SAFETY: tmpeng is NULL or a functional reference to finish.
    unsafe { ffi::ENGINE_finish(tmpeng) };
    if ameth.is_null()
        && let Some(e) = e
    {
        // SAFETY: the engine is live; n a valid C string.
        ameth = unsafe { ffi::ENGINE_get_pkey_asn1_meth_str(e.as_ptr(), n.as_ptr(), -1) };
    } else if tmpeng.is_null() {
        // Only one from an engine counts.
        ameth = core::ptr::null();
    }
    // SAFETY: no arguments.
    unsafe { ffi::ERR_pop_to_mark() };
    if ameth.is_null() {
        return 0;
    }
    let mut id: c_int = 0;
    // SAFETY: ameth is live; the out-pointers are valid or NULL.
    unsafe {
        ffi::EVP_PKEY_asn1_get0_info(
            &mut id,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            ameth,
        )
    };
    id
}

/// The ids of every engine in the list (`ENGINE_get_first` ... `ENGINE_get_next`).
pub fn ids() -> Vec<String> {
    let mut out = Vec::new();
    // SAFETY: no arguments; the result is a structural reference (or NULL).
    let mut e = unsafe { ffi::ENGINE_get_first() };
    while !e.is_null() {
        // SAFETY: e is live; its id is owned by it and copied at once.
        out.push(string_at(unsafe { ffi::ENGINE_get_id(e) }).unwrap_or_default());
        // SAFETY: get_next releases e's reference and returns the next one (or NULL).
        e = unsafe { ffi::ENGINE_get_next(e) };
    }
    out
}

/// The schemes of the store loaders `e` provides (the `OSSL_STORE_do_all_loaders` walk).
struct LoaderWalk {
    engine: *const ENGINE,
    schemes: Vec<String>,
}

unsafe extern "C" fn visit_loader(loader: *const OSSL_STORE_LOADER, arg: *mut core::ffi::c_void) {
    // SAFETY: arg is the LoaderWalk that store_schemes passed, live for the whole walk.
    let walk = unsafe { &mut *arg.cast::<LoaderWalk>() };
    // SAFETY: the loader is live for the callback.
    if unsafe { ffi::OSSL_STORE_LOADER_get0_engine(loader) } == walk.engine {
        // SAFETY: as above; the scheme is owned by the loader and copied at once.
        let scheme = string_at(unsafe { ffi::OSSL_STORE_LOADER_get0_scheme(loader) });
        walk.schemes
            .push(scheme.unwrap_or_else(|| "(null)".to_owned()));
    }
}

/// `OBJ_nid2sn` of each of the `n` NIDs at `nids`.
///
/// # Safety
/// `nids` points to `n` ints (or `n <= 0`).
unsafe fn short_names(nids: *const c_int, n: c_int) -> Vec<String> {
    let Ok(n) = usize::try_from(n) else {
        return Vec::new();
    };
    if nids.is_null() || n == 0 {
        return Vec::new();
    }
    // SAFETY: the caller's contract.
    let nids = unsafe { core::slice::from_raw_parts(nids, n) };
    nids.iter()
        // SAFETY: OBJ_nid2sn takes any NID; the name is static.
        .map(|&nid| string_at(unsafe { ffi::OBJ_nid2sn(nid) }).unwrap_or_else(|| "(null)".into()))
        .collect()
}

impl Engine {
    /// `ENGINE_get_name`.
    pub fn name(&self) -> String {
        // SAFETY: the engine is live; the name is owned by it.
        string_at(unsafe { ffi::ENGINE_get_name(self.as_ptr()) })
            .unwrap_or_else(|| "(null)".to_owned())
    }

    /// `ENGINE_ctrl(e, cmd, i, NULL, NULL)`: the commands that take and return numbers.
    pub fn ctrl_num(&self, cmd: c_int, i: core::ffi::c_long) -> c_int {
        // SAFETY: the engine is live; these commands take no pointer.
        unsafe { ffi::ENGINE_ctrl(self.as_ptr(), cmd, i, core::ptr::null_mut(), None) }
    }

    /// `ENGINE_ctrl(e, cmd, i, buf, NULL)` into a buffer of `len + 1` bytes (the
    /// `ENGINE_CTRL_GET_*_FROM_CMD` commands): what it returns, and the string.
    pub fn ctrl_text(&self, cmd: c_int, i: core::ffi::c_long, len: usize) -> (c_int, String) {
        let mut buf = vec![0u8; len.saturating_add(1)];
        // SAFETY: the engine is live; buf holds len + 1 bytes, as these commands need for
        // the length the matching *_LEN_* command gave.
        let r = unsafe { ffi::ENGINE_ctrl(self.as_ptr(), cmd, i, buf.as_mut_ptr().cast(), None) };
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        buf.truncate(end);
        (r, String::from_utf8_lossy(&buf).into_owned())
    }

    /// `ENGINE_ctrl_cmd_string(e, cmd, arg, 0)`: what it returns.
    pub fn ctrl_cmd_string_ret(&self, cmd: &[u8], arg: Option<&[u8]>) -> c_int {
        let Ok(c) = std::ffi::CString::new(cmd) else {
            return 0;
        };
        let a = match arg.map(std::ffi::CString::new) {
            Some(Ok(a)) => Some(a),
            Some(Err(_)) => return 0,
            None => None,
        };
        // SAFETY: the engine is live; the strings are valid or NULL.
        unsafe {
            ffi::ENGINE_ctrl_cmd_string(
                self.as_ptr(),
                c.as_ptr(),
                a.as_ref().map_or(core::ptr::null(), |a| a.as_ptr()),
                0,
            )
        }
    }

    /// What `openssl engine -c` lists: the methods the engine has (RSA, EC, DSA, DH, RAND),
    /// its ciphers', digests', and key methods' short names, and its store loaders.
    pub fn capabilities(&self) -> Vec<String> {
        let e = self.as_ptr();
        let mut out = Vec::new();
        // The engine is live; each getter returns its method or NULL.
        let methods = [
            // SAFETY: as above.
            ("RSA", !unsafe { ffi::ENGINE_get_RSA(e) }.is_null()),
            // SAFETY: as above.
            ("EC", !unsafe { ffi::ENGINE_get_EC(e) }.is_null()),
            // SAFETY: as above.
            ("DSA", !unsafe { ffi::ENGINE_get_DSA(e) }.is_null()),
            // SAFETY: as above.
            ("DH", !unsafe { ffi::ENGINE_get_DH(e) }.is_null()),
            // SAFETY: as above.
            ("RAND", !unsafe { ffi::ENGINE_get_RAND(e) }.is_null()),
        ];
        out.extend(methods.iter().filter(|m| m.1).map(|m| m.0.to_owned()));
        // SAFETY: the engine is live.
        if let Some(f) = unsafe { ffi::ENGINE_get_ciphers(e) } {
            let mut nids: *const c_int = core::ptr::null();
            // SAFETY: the engine's own callback, asked for its NID list (NULL cipher).
            let n = unsafe { f(e, core::ptr::null_mut(), &mut nids, 0) };
            // SAFETY: the callback returned n NIDs at nids.
            out.extend(unsafe { short_names(nids, n) });
        }
        // SAFETY: the engine is live.
        if let Some(f) = unsafe { ffi::ENGINE_get_digests(e) } {
            let mut nids: *const c_int = core::ptr::null();
            // SAFETY: as above.
            let n = unsafe { f(e, core::ptr::null_mut(), &mut nids, 0) };
            // SAFETY: as above.
            out.extend(unsafe { short_names(nids, n) });
        }
        // SAFETY: the engine is live.
        if let Some(f) = unsafe { ffi::ENGINE_get_pkey_meths(e) } {
            let mut nids: *const c_int = core::ptr::null();
            // SAFETY: as above.
            let n = unsafe { f(e, core::ptr::null_mut(), &mut nids, 0) };
            // SAFETY: as above.
            out.extend(unsafe { short_names(nids, n) });
        }
        let mut walk = LoaderWalk {
            engine: e,
            schemes: Vec::new(),
        };
        // SAFETY: visit_loader gets &mut walk back, which outlives the call, and doesn't keep
        // it.
        unsafe {
            ffi::OSSL_STORE_do_all_loaders(Some(visit_loader), (&raw mut walk).cast());
        }
        out.extend(walk.schemes.into_iter().map(|s| format!("STORE({s})")));
        out
    }
}
