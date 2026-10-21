//! Library contexts and providers.

use core::ffi::{c_int, c_void};

use crate::abi::OSSL_PROVIDER;
use crate::ffi;
use crate::util::{cstring, string_at};

crate::handle!(
    /// An owned `OSSL_LIB_CTX`.
    LibCtx, OSSL_LIB_CTX, OSSL_LIB_CTX_free
);

impl LibCtx {
    /// `OSSL_LIB_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::OSSL_LIB_CTX_new() })
    }
}

crate::handle!(
    /// A loaded provider, unloaded (`OSSL_PROVIDER_unload`) when dropped.
    Provider, OSSL_PROVIDER, OSSL_PROVIDER_unload
);

impl Provider {
    /// `OSSL_PROVIDER_load(libctx, name)`; NULL `libctx` is the default context.
    pub fn load(libctx: Option<&LibCtx>, name: &str) -> Option<Self> {
        let n = cstring(name)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; n is a valid C string.
        Self::from_ptr(unsafe { ffi::OSSL_PROVIDER_load(ctx, n.as_ptr()) })
    }
}

/// `OSSL_PROVIDER_set_default_search_path(libctx, path)`.
pub fn set_default_search_path(libctx: Option<&LibCtx>, path: Option<&str>) -> bool {
    let p = match path {
        Some(p) => match cstring(p) {
            Some(c) => Some(c),
            None => return false,
        },
        None => None,
    };
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    let pp = p.as_ref().map_or(core::ptr::null(), |c| c.as_ptr());
    // SAFETY: ctx is NULL or live; pp is NULL or a valid C string.
    unsafe { ffi::OSSL_PROVIDER_set_default_search_path(ctx, pp) == 1 }
}

/// A provider seen by [`for_each`], borrowed for the callback.
pub struct ProviderRef(*mut OSSL_PROVIDER);

impl ProviderRef {
    /// `OSSL_PROVIDER_get0_name`.
    pub fn name(&self) -> String {
        // SAFETY: the provider is live for the callback; the name is owned by it.
        string_at(unsafe { ffi::OSSL_PROVIDER_get0_name(self.0) }).unwrap_or_default()
    }

    /// `OSSL_PROVIDER_add_conf_parameter`.
    pub fn add_conf_parameter(&self, key: &str, value: &str) -> bool {
        let (Some(k), Some(v)) = (cstring(key), cstring(value)) else {
            return false;
        };
        // SAFETY: the provider is live; both strings are valid C strings (copied by the call).
        unsafe { ffi::OSSL_PROVIDER_add_conf_parameter(self.0, k.as_ptr(), v.as_ptr()) == 1 }
    }
}

type Visitor<'a> = &'a mut dyn FnMut(&ProviderRef) -> bool;

unsafe extern "C" fn visit(provider: *mut OSSL_PROVIDER, data: *mut c_void) -> c_int {
    // SAFETY: data is the `&mut Visitor` that for_each passed, live for the whole call.
    let f = unsafe { &mut *data.cast::<Visitor<'_>>() };
    // A panic must not unwind into C.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&ProviderRef(provider)))) {
        Ok(true) => 1,
        _ => 0,
    }
}

/// `OSSL_PROVIDER_do_all(libctx, cb, data)`: `f` returns whether to go on; the result is
/// what the call returns.
pub fn for_each(libctx: Option<&LibCtx>, mut f: impl FnMut(&ProviderRef) -> bool) -> bool {
    let mut visitor: Visitor<'_> = &mut f;
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    let data: *mut Visitor<'_> = &mut visitor;
    // SAFETY: ctx is NULL or live; visit gets data back, which outlives the call, and doesn't
    // keep it.
    unsafe { ffi::OSSL_PROVIDER_do_all(ctx, Some(visit), data.cast()) == 1 }
}

impl Provider {
    /// `OSSL_PROVIDER_get_params` with a `OSSL_PARAM_construct_utf8_ptr` for each key: `None`
    /// if the call fails, else each value the provider set (`OSSL_PARAM_modified`).
    pub fn get_utf8_ptr_params(&self, keys: &[&str]) -> Option<Vec<Option<String>>> {
        let ckeys: Vec<std::ffi::CString> = keys.iter().filter_map(|k| cstring(k)).collect();
        if ckeys.len() != keys.len() {
            return None;
        }
        let mut values: Vec<*mut core::ffi::c_char> = vec![core::ptr::null_mut(); keys.len()];
        let mut params: Vec<crate::abi::OSSL_PARAM> = Vec::with_capacity(keys.len() + 1);
        for (k, v) in ckeys.iter().zip(values.iter_mut()) {
            // SAFETY: k is a valid C string and v a valid pointer slot, both outliving the
            // parameter's use below.
            params.push(unsafe {
                ffi::OSSL_PARAM_construct_utf8_ptr(
                    k.as_ptr(),
                    v,
                    size_of::<*mut core::ffi::c_char>(),
                )
            });
        }
        // SAFETY: no arguments.
        params.push(unsafe { ffi::OSSL_PARAM_construct_end() });
        // SAFETY: the provider is live; the list is END-terminated, its slots valid.
        if unsafe { ffi::OSSL_PROVIDER_get_params(self.as_ptr(), params.as_mut_ptr()) } == 0 {
            return None;
        }
        let mut out = Vec::with_capacity(keys.len());
        for (p, v) in params.iter().zip(values.iter()) {
            // SAFETY: p is one of the list's parameters.
            let modified = unsafe { ffi::OSSL_PARAM_modified(p) } == 1;
            // A modified pointer parameter points to a string the provider owns.
            out.push(if modified { string_at(*v) } else { None });
        }
        Some(out)
    }
}

/// `OSSL_PROVIDER_available(libctx, name)`.
pub fn available(libctx: Option<&LibCtx>, name: &str) -> bool {
    let Some(n) = cstring(name) else {
        return false;
    };
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    // SAFETY: ctx is NULL or live; n is a valid C string.
    unsafe { ffi::OSSL_PROVIDER_available(ctx, n.as_ptr()) == 1 }
}

/// `OSSL_LIB_CTX_load_config(libctx, file)`.
pub fn load_config(libctx: Option<&LibCtx>, file: &str) -> bool {
    let Some(f) = cstring(file) else {
        return false;
    };
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    // SAFETY: ctx is NULL or live; f is a valid C string.
    unsafe { ffi::OSSL_LIB_CTX_load_config(ctx, f.as_ptr()) == 1 }
}

/// What the self-test callback is given: (phase, description, type), and whether to go on.
type SelfTestFn = Box<dyn Fn(&str, &str, &str) -> bool + Send>;

static SELF_TEST: std::sync::Mutex<Option<SelfTestFn>> = std::sync::Mutex::new(None);

unsafe extern "C" fn self_test_event(
    params: *const crate::abi::OSSL_PARAM,
    _arg: *mut c_void,
) -> c_int {
    use crate::abi::{
        OSSL_PROV_PARAM_SELF_TEST_DESC, OSSL_PROV_PARAM_SELF_TEST_PHASE,
        OSSL_PROV_PARAM_SELF_TEST_TYPE,
    };
    // SAFETY: the library passes a live END-terminated list.
    let at = |key: &core::ffi::CStr| unsafe { crate::params::utf8_at(params, key) };
    let (Some(phase), Some(desc), Some(kind)) = (
        at(OSSL_PROV_PARAM_SELF_TEST_PHASE),
        at(OSSL_PROV_PARAM_SELF_TEST_DESC),
        at(OSSL_PROV_PARAM_SELF_TEST_TYPE),
    ) else {
        return 0;
    };
    let run = || {
        SELF_TEST
            .lock()
            .ok()
            .and_then(|f| f.as_ref().map(|f| f(&phase, &desc, &kind)))
    };
    // A panic must not unwind into C.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Some(true)) => 1,
        _ => 0,
    }
}

/// `OSSL_SELF_TEST_set_callback(NULL, cb, NULL)`: `f` sees each event's phase, description,
/// and type, and returns whether the test goes on (false corrupts it).
pub fn set_self_test_callback(f: impl Fn(&str, &str, &str) -> bool + Send + 'static) {
    if let Ok(mut g) = SELF_TEST.lock() {
        *g = Some(Box::new(f));
    }
    // SAFETY: the default context; the callback is a valid OSSL_CALLBACK that ignores its
    // argument.
    unsafe {
        ffi::OSSL_SELF_TEST_set_callback(
            core::ptr::null_mut(),
            Some(self_test_event),
            core::ptr::null_mut(),
        )
    };
}
