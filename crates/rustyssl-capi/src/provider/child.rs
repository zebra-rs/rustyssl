//! Child library contexts (`OSSL_LIB_CTX_new_child(3)`, `crypto/provider_child.c`): a provider
//! makes one from its core's dispatch table, and every provider active in the parent context
//! appears in it as a child provider of the same name, which runs on the parent's context and
//! dispatch table (`ossl_child_provider_init`), comes when the parent's is activated and goes
//! when it's deactivated. The parent's default properties are mirrored until the child sets its
//! own.
//!
//! The parent's providers are reached only through the core's functions in the table (name,
//! context, dispatch table, references), as OpenSSL does, so the parent context may belong to
//! another core. No lock is held while those functions or the parent's callbacks run: the
//! provider being made is passed to its init function through the thread, as the init runs on
//! the thread making it.

use core::cell::Cell;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_CRYPTO, OPENSSL_CORE_CTX, OSSL_CORE_HANDLE, OSSL_DISPATCH, OSSL_FUNC_CORE_GET_LIBCTX,
    OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB, OSSL_FUNC_PROVIDER_FREE,
    OSSL_FUNC_PROVIDER_GET0_DISPATCH, OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX,
    OSSL_FUNC_PROVIDER_NAME, OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB, OSSL_FUNC_PROVIDER_UP_REF,
    OSSL_LIB_CTX, OSSL_PROVIDER,
};

use super::upcalls::{ChildFn, PropsFn};
use super::{Provider, Ptr, TABLE_LIMIT, cast};
use crate::ffi::ffi_callback;
use crate::handle::Handle;

type GetLibctxFn = unsafe extern "C" fn(*const OSSL_CORE_HANDLE) -> *mut OPENSSL_CORE_CTX;
type RegisterFn = unsafe extern "C" fn(
    *const OSSL_CORE_HANDLE,
    Option<ChildFn>,
    Option<ChildFn>,
    Option<PropsFn>,
    *mut c_void,
) -> c_int;
type DeregisterFn = unsafe extern "C" fn(*const OSSL_CORE_HANDLE);
type NameFn = unsafe extern "C" fn(*const OSSL_CORE_HANDLE) -> *const c_char;
type ProvCtxFn = unsafe extern "C" fn(*const OSSL_CORE_HANDLE) -> *mut c_void;
type DispatchFn = unsafe extern "C" fn(*const OSSL_CORE_HANDLE) -> *const OSSL_DISPATCH;
type RefFn = unsafe extern "C" fn(*const OSSL_CORE_HANDLE, c_int) -> c_int;

/// A child context's link to its parent (`child_prov_globals`).
pub(crate) struct Globals {
    /// The handle of the provider that made the child context.
    handle: Ptr<OSSL_CORE_HANDLE>,
    deregister: DeregisterFn,
    name: NameFn,
    provider_ctx: ProvCtxFn,
    dispatch: DispatchFn,
    up_ref: RefFn,
    free: RefFn,
}

thread_local! {
    /// The parent provider whose child is being made on this thread (`gbl->curr_prov`).
    static CURRENT: Cell<*const OSSL_CORE_HANDLE> = const { Cell::new(ptr::null()) };
}

/// The child context's link, `None` for a context that isn't a child.
///
/// # Safety
/// `ctx` is NULL or a live library context.
unsafe fn globals(ctx: *mut OSSL_LIB_CTX) -> Option<crate::handle::Held<OSSL_LIB_CTX>> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { crate::libctx::resolve(ctx) }?;
    c.child().is_some().then_some(c)
}

ffi_callback! {
    /// `ossl_child_provider_init`: a child provider runs on the parent's context and dispatch
    /// table (of the provider being made on this thread).
    ///
    /// # Safety
    /// The core's arguments; called while a child is made (`provider_create_child_cb`).
    pub(crate) unsafe extern "C" fn child_provider_init(handle: *const OSSL_CORE_HANDLE, in_: *const OSSL_DISPATCH, out: *mut *const OSSL_DISPATCH, provctx: *mut *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let mut get_libctx: Option<GetLibctxFn> = None;
        let mut at = in_;
        for _ in 0..TABLE_LIMIT {
            // SAFETY: the core's table, ended by a zero id.
            let Some(d) = (unsafe { at.as_ref() }) else { break };
            if d.function_id == 0 {
                break;
            }
            if d.function_id == OSSL_FUNC_CORE_GET_LIBCTX && let Some(f) = d.function {
                // SAFETY: the core's guarantee of the function's type.
                get_libctx = Some(unsafe { cast(f) });
            }
            at = at.wrapping_add(1);
        }
        let Some(get_libctx) = get_libctx else { return 0 };
        // SAFETY: the core's function with its handle: the context the child provider is in.
        let ctx = unsafe { get_libctx(handle) }.cast::<OSSL_LIB_CTX>();
        // SAFETY: a live context.
        let Some(c) = (unsafe { globals(ctx) }) else { return 0 };
        let Some(g) = c.child() else { return 0 };
        let parent = CURRENT.with(Cell::get);
        if parent.is_null() || out.is_null() || provctx.is_null() {
            return 0;
        }
        let (provider_ctx, dispatch) = (g.provider_ctx, g.dispatch);
        drop(c);
        // SAFETY: the parent's function with the parent provider being made a child of.
        let parent_ctx = unsafe { provider_ctx(parent) };
        // SAFETY: as above.
        let parent_dispatch = unsafe { dispatch(parent) };
        // SAFETY: the caller's outputs, checked above.
        unsafe { provctx.write(parent_ctx) };
        // SAFETY: as above.
        unsafe { out.write(parent_dispatch) };
        1
    }
}

/// `ossl_provider_find(ctx, name, 1)`, with the caller's reference.
///
/// # Safety
/// `ctx` is a live library context.
unsafe fn find(ctx: *mut OSSL_LIB_CTX, name: &CStr) -> Option<*mut OSSL_PROVIDER> {
    // SAFETY: the caller's guarantee.
    unsafe { super::find(ctx, name) }
}

ffi_callback! {
    /// `provider_create_child_cb`: the parent's provider `prov` was activated, so its child is
    /// made in the child context (or, if the child is there already, activated again; a
    /// provider of the name loaded into the child context itself is left alone).
    ///
    /// # Safety
    /// `prov` is a parent provider's handle; `cbdata` the child context.
    pub(crate) unsafe extern "C" fn provider_create_child_cb(prov: *const OSSL_CORE_HANDLE, cbdata: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let ctx = cbdata.cast::<OSSL_LIB_CTX>();
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { globals(ctx) }) else { return 0 };
        let Some(g) = c.child() else { return 0 };
        // SAFETY: the parent's function with its provider.
        let name = unsafe { (g.name)(prov) };
        if name.is_null() {
            return 0;
        }
        // SAFETY: the parent provider's name, a string.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        let previous = CURRENT.with(|cur| cur.replace(prov));
        // SAFETY: a live context.
        let ok = if let Some(found) = unsafe { find(ctx, &name) } {
            // The store's reference keeps it.
            // SAFETY: the reference `find` took.
            unsafe { OSSL_PROVIDER::free(found) };
            // SAFETY: in the store, so live.
            unsafe { super::activate_as_child(found) }
        } else {
            let made = super::provider_new(ctx, &name, Some(child_provider_init), Vec::new());
            // SAFETY: just made.
            if unsafe { super::activate_with(made, false) } {
                // SAFETY: as above.
                if let Some(p) = unsafe { OSSL_PROVIDER::get(made) } {
                    p.set_child(prov);
                }
                // SAFETY: as above, its reference for the store.
                match unsafe { super::add_to_store(made, false) } {
                    Some(actual) => {
                        // SAFETY: the extra reference `add_to_store` gave.
                        unsafe { OSSL_PROVIDER::free(actual) };
                        true
                    }
                    None => {
                        // SAFETY: as above.
                        unsafe { super::deactivate_with(made, true, false) };
                        // SAFETY: as above.
                        unsafe { OSSL_PROVIDER::free(made) };
                        false
                    }
                }
            } else {
                // SAFETY: as above.
                unsafe { OSSL_PROVIDER::free(made) };
                false
            }
        };
        CURRENT.with(|cur| cur.set(previous));
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `provider_remove_child_cb`: the parent's provider `prov` was deactivated, so its child
    /// is too.
    ///
    /// # Safety
    /// `prov` is a parent provider's handle; `cbdata` the child context.
    pub(crate) unsafe extern "C" fn provider_remove_child_cb(prov: *const OSSL_CORE_HANDLE, cbdata: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        let ctx = cbdata.cast::<OSSL_LIB_CTX>();
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { globals(ctx) }) else { return 0 };
        let Some(g) = c.child() else { return 0 };
        // SAFETY: the parent's function with its provider.
        let name = unsafe { (g.name)(prov) };
        if name.is_null() {
            return 0;
        }
        // SAFETY: as above, a string.
        let name = unsafe { CStr::from_ptr(name) }.to_owned();
        // SAFETY: a live context.
        let Some(found) = (unsafe { find(ctx, &name) }) else { return 0 };
        // SAFETY: the reference `find` took; the store's keeps it.
        unsafe { OSSL_PROVIDER::free(found) };
        // SAFETY: in the store, so live.
        let is_child = unsafe { OSSL_PROVIDER::get(found) }.is_some_and(Provider::is_child);
        // SAFETY: as above.
        if is_child && !unsafe { super::deactivate_with(found, true, true) } {
            return 0;
        }
        1
    }
}

ffi_callback! {
    /// `provider_global_props_cb`: the parent's default properties, mirrored.
    ///
    /// # Safety
    /// `props` is a string; `cbdata` the child context.
    pub(crate) unsafe extern "C" fn provider_global_props_cb(props: *const c_char, cbdata: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { crate::libctx::resolve(cbdata.cast()) }) else { return 0 };
        if props.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let props = unsafe { CStr::from_ptr(props) }.to_bytes();
        c_int::from(crate::property::set_mirrored(&c, props))
    }
}

/// `ossl_provider_init_as_child`: links the new context `ctx` to the parent through the
/// provider `handle`'s core table `in_`, and registers for its providers. False if the table
/// lacks a function this needs or the registration failed.
///
/// # Safety
/// `ctx` is a live library context, not yet shared; `in_` a core's dispatch table ended by a
/// zero id whose functions have the types their ids stand for.
pub(crate) unsafe fn init_as_child(
    ctx: *mut OSSL_LIB_CTX,
    handle: *const OSSL_CORE_HANDLE,
    in_: *const OSSL_DISPATCH,
) -> bool {
    let (mut get_libctx, mut register, mut deregister, mut name) = (None, None, None, None);
    let (mut provider_ctx, mut dispatch, mut up_ref, mut free) = (None, None, None, None);
    let mut at = in_;
    for _ in 0..TABLE_LIMIT {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { at.as_ref() }) else {
            break;
        };
        if d.function_id == 0 {
            break;
        }
        if let Some(f) = d.function {
            match d.function_id {
                // SAFETY: the caller's guarantee of the function's type, here and below.
                OSSL_FUNC_CORE_GET_LIBCTX => get_libctx = Some(unsafe { cast::<GetLibctxFn>(f) }),
                OSSL_FUNC_PROVIDER_REGISTER_CHILD_CB => {
                    // SAFETY: as above.
                    register = Some(unsafe { cast::<RegisterFn>(f) });
                }
                OSSL_FUNC_PROVIDER_DEREGISTER_CHILD_CB => {
                    // SAFETY: as above.
                    deregister = Some(unsafe { cast::<DeregisterFn>(f) });
                }
                // SAFETY: as above.
                OSSL_FUNC_PROVIDER_NAME => name = Some(unsafe { cast::<NameFn>(f) }),
                OSSL_FUNC_PROVIDER_GET0_PROVIDER_CTX => {
                    // SAFETY: as above.
                    provider_ctx = Some(unsafe { cast::<ProvCtxFn>(f) });
                }
                OSSL_FUNC_PROVIDER_GET0_DISPATCH => {
                    // SAFETY: as above.
                    dispatch = Some(unsafe { cast::<DispatchFn>(f) });
                }
                // SAFETY: as above.
                OSSL_FUNC_PROVIDER_UP_REF => up_ref = Some(unsafe { cast::<RefFn>(f) }),
                // SAFETY: as above.
                OSSL_FUNC_PROVIDER_FREE => free = Some(unsafe { cast::<RefFn>(f) }),
                _ => {}
            }
        }
        at = at.wrapping_add(1);
    }
    let (
        Some(_),
        Some(register),
        Some(name),
        Some(provider_ctx),
        Some(dispatch),
        Some(up_ref),
        Some(free),
    ) = (
        get_libctx,
        register,
        name,
        provider_ctx,
        dispatch,
        up_ref,
        free,
    )
    else {
        return false;
    };
    // OpenSSL calls a missing deregister function at free time and crashes; one that's missing
    // here is a no-op.
    let deregister = deregister.unwrap_or(no_deregister);
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { crate::libctx::resolve(ctx) }) else {
        return false;
    };
    if !c.set_child(Globals {
        handle: Ptr(handle.cast_mut()),
        deregister,
        name,
        provider_ctx,
        dispatch,
        up_ref,
        free,
    }) {
        return false;
    }
    drop(c);
    // SAFETY: the parent's function, with the provider's handle and our callbacks, which take
    // the context; no lock is held.
    let registered = unsafe {
        register(
            handle,
            Some(provider_create_child_cb),
            Some(provider_remove_child_cb),
            Some(provider_global_props_cb),
            ctx.cast(),
        )
    };
    registered != 0
}

ffi_callback! {
    /// A deregistration that does nothing, for a table without one.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn no_deregister(_handle: *const OSSL_CORE_HANDLE)
    where failure = (), library = ERR_LIB_CRYPTO
    {}
}

/// `ossl_provider_deinit_child`: the parent stops calling the child context `c` back.
pub(crate) fn deinit(c: &crate::libctx::LibCtx) {
    if let Some(g) = c.child() {
        // SAFETY: the parent's function with the handle the context was made with; no lock is
        // held.
        unsafe { (g.deregister)(g.handle.0) };
    }
}

/// `ossl_provider_up_ref_parent`: the child provider `prov`'s parent gets a reference (and an
/// activation, if `activate`), unless the parent is the provider the child context belongs to.
pub(crate) fn up_ref_parent(prov: &Provider, activate: bool) -> bool {
    // SAFETY: a live provider's context.
    let Some(c) = (unsafe { crate::libctx::resolve(prov.libctx()) }) else {
        return false;
    };
    let Some(g) = c.child() else { return false };
    let parent = prov.parent();
    if parent == g.handle.0.cast_const() {
        return true;
    }
    let up_ref = g.up_ref;
    drop(c);
    // SAFETY: the parent's function with the parent provider; no lock is held.
    unsafe { up_ref(parent, c_int::from(activate)) != 0 }
}

/// `ossl_provider_free_parent`: undoes [`up_ref_parent`].
pub(crate) fn free_parent(prov: &Provider, deactivate: bool) -> bool {
    // SAFETY: a live provider's context.
    let Some(c) = (unsafe { crate::libctx::resolve(prov.libctx()) }) else {
        return false;
    };
    let Some(g) = c.child() else { return false };
    let parent = prov.parent();
    if parent == g.handle.0.cast_const() {
        return true;
    }
    let free = g.free;
    drop(c);
    // SAFETY: the parent's function with the parent provider; no lock is held.
    unsafe { free(parent, c_int::from(deactivate)) != 0 }
}
