//! Verification parameters, purposes, and trust stores' lookups.

use core::ffi::{c_int, c_ulong};

use crate::abi::{
    X509_FILETYPE_ASN1, X509_FILETYPE_DEFAULT, X509_FILETYPE_PEM, X509_L_ADD_DIR, X509_L_ADD_STORE,
    X509_L_FILE_LOAD, X509_LOOKUP, X509_LOOKUP_METHOD, X509_VERIFY_PARAM,
};
use crate::ffi;
use crate::provider::LibCtx;
use crate::util::cstring;
use crate::x509::Store;

crate::handle!(
    /// An owned `X509_VERIFY_PARAM`.
    VerifyParam, X509_VERIFY_PARAM, X509_VERIFY_PARAM_free
);

impl VerifyParam {
    /// `X509_VERIFY_PARAM_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::X509_VERIFY_PARAM_new() })
    }
}

/// An `X509_VERIFY_PARAM` borrowed from its owner: a [`VerifyParam`], or an object's own
/// (`X509_STORE_get0_param`, ...).
#[derive(Clone, Copy)]
pub struct ParamRef<'a>(*mut X509_VERIFY_PARAM, core::marker::PhantomData<&'a ()>);

impl<'a> From<&'a VerifyParam> for ParamRef<'a> {
    fn from(p: &'a VerifyParam) -> Self {
        Self(p.as_ptr(), core::marker::PhantomData)
    }
}

impl Store {
    /// `X509_STORE_get0_param`.
    pub fn param(&self) -> ParamRef<'_> {
        // SAFETY: the store is live; the param is owned by it.
        ParamRef(
            unsafe { ffi::X509_STORE_get0_param(self.as_ptr()) },
            core::marker::PhantomData,
        )
    }
}

impl ParamRef<'_> {
    /// `OBJ_txt2obj(policy, 0)` added with `X509_VERIFY_PARAM_add0_policy`: `Err(true)` if the
    /// policy doesn't parse, `Err(false)` if it can't be added.
    pub fn add_policy(self, policy: &str) -> Result<(), bool> {
        let p = cstring(policy).ok_or(true)?;
        // SAFETY: a valid C string; the object is the caller's.
        let obj = unsafe { ffi::OBJ_txt2obj(p.as_ptr(), 0) };
        if obj.is_null() {
            return Err(true);
        }
        // SAFETY: the param is live; on success it takes obj.
        if unsafe { ffi::X509_VERIFY_PARAM_add0_policy(self.0, obj) } != 1 {
            // SAFETY: obj is still owned here.
            unsafe { ffi::ASN1_OBJECT_free(obj) };
            return Err(false);
        }
        Ok(())
    }

    /// `X509_PURPOSE_get_by_sname` .. `X509_VERIFY_PARAM_set_purpose`: `Err(true)` for an
    /// unknown purpose, `Err(false)` if setting it fails.
    pub fn set_purpose_by_sname(self, sname: &str) -> Result<(), bool> {
        let s = cstring(sname).ok_or(true)?;
        // SAFETY: a valid C string.
        let i = unsafe { ffi::X509_PURPOSE_get_by_sname(s.as_ptr()) };
        if i < 0 {
            return Err(true);
        }
        // SAFETY: i is a valid index; the purpose is owned by the library.
        let xp = unsafe { ffi::X509_PURPOSE_get0(i) };
        // SAFETY: xp is a valid purpose.
        let id = unsafe { ffi::X509_PURPOSE_get_id(xp) };
        // SAFETY: the param is live.
        if unsafe { ffi::X509_VERIFY_PARAM_set_purpose(self.0, id) } != 1 {
            return Err(false);
        }
        Ok(())
    }

    /// `X509_VERIFY_PARAM_lookup(name)` copied in with `X509_VERIFY_PARAM_set1`: false for an
    /// unknown name.
    pub fn set_by_name(self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: a valid C string; the result is owned by the library.
        let v = unsafe { ffi::X509_VERIFY_PARAM_lookup(n.as_ptr()) };
        if v.is_null() {
            return false;
        }
        // SAFETY: both are live.
        unsafe { ffi::X509_VERIFY_PARAM_set1(self.0, v) };
        true
    }

    /// `X509_VERIFY_PARAM_set_depth`.
    pub fn set_depth(self, depth: c_int) {
        // SAFETY: the param is live.
        unsafe { ffi::X509_VERIFY_PARAM_set_depth(self.0, depth) };
    }

    /// `X509_VERIFY_PARAM_set_auth_level`.
    pub fn set_auth_level(self, level: c_int) {
        // SAFETY: the param is live.
        unsafe { ffi::X509_VERIFY_PARAM_set_auth_level(self.0, level) };
    }

    /// `X509_VERIFY_PARAM_set_time`.
    pub fn set_time(self, t: libc::time_t) {
        // SAFETY: the param is live.
        unsafe { ffi::X509_VERIFY_PARAM_set_time(self.0, t) };
    }

    /// `X509_VERIFY_PARAM_set1_host(vpm, name, 0)`.
    pub fn set1_host(self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: the param is live; 0 means NUL-terminated.
        unsafe { ffi::X509_VERIFY_PARAM_set1_host(self.0, n.as_ptr(), 0) == 1 }
    }

    /// `X509_VERIFY_PARAM_set1_email(vpm, email, 0)`.
    pub fn set1_email(self, email: &str) -> bool {
        let Some(e) = cstring(email) else {
            return false;
        };
        // SAFETY: as above.
        unsafe { ffi::X509_VERIFY_PARAM_set1_email(self.0, e.as_ptr(), 0) == 1 }
    }

    /// `X509_VERIFY_PARAM_set1_ip_asc`.
    pub fn set1_ip_asc(self, ip: &str) -> bool {
        let Some(i) = cstring(ip) else {
            return false;
        };
        // SAFETY: as above.
        unsafe { ffi::X509_VERIFY_PARAM_set1_ip_asc(self.0, i.as_ptr()) == 1 }
    }

    /// `X509_VERIFY_PARAM_set_flags`.
    pub fn set_flags(self, flags: c_ulong) {
        // SAFETY: the param is live.
        unsafe { ffi::X509_VERIFY_PARAM_set_flags(self.0, flags) };
    }
}

/// A lookup of a store (owned by the store).
#[derive(Clone, Copy)]
pub struct Lookup(*mut X509_LOOKUP);

/// The kinds of lookup `setup_verify` adds.
pub enum LookupKind {
    File,
    HashDir,
    Store,
}

impl Store {
    /// `X509_STORE_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::X509_STORE_new() })
    }

    /// `X509_STORE_add_lookup(store, X509_LOOKUP_file() / _hash_dir() / _store())`.
    pub fn add_lookup(&self, kind: LookupKind) -> Option<Lookup> {
        let m: *mut X509_LOOKUP_METHOD = match kind {
            // SAFETY: no arguments; static methods.
            LookupKind::File => unsafe { ffi::X509_LOOKUP_file() },
            // SAFETY: as above.
            LookupKind::HashDir => unsafe { ffi::X509_LOOKUP_hash_dir() },
            // SAFETY: as above.
            LookupKind::Store => unsafe { ffi::X509_LOOKUP_store() },
        };
        // SAFETY: the store is live; m is a valid method; the lookup is owned by the store.
        let l = unsafe { ffi::X509_STORE_add_lookup(self.as_ptr(), m) };
        (!l.is_null()).then_some(Lookup(l))
    }
}

/// The file types of `X509_LOOKUP_load_file_ex` and `X509_LOOKUP_add_dir`.
#[derive(Clone, Copy)]
pub enum FileType {
    Pem,
    Asn1,
    Default,
}

impl FileType {
    fn value(self) -> core::ffi::c_long {
        core::ffi::c_long::from(match self {
            FileType::Pem => X509_FILETYPE_PEM,
            FileType::Asn1 => X509_FILETYPE_ASN1,
            FileType::Default => X509_FILETYPE_DEFAULT,
        })
    }
}

fn opt_c(s: Option<&str>) -> Option<Option<std::ffi::CString>> {
    match s {
        Some(s) => cstring(s).map(Some),
        None => Some(None),
    }
}

impl Lookup {
    fn ctrl_ex(
        self,
        cmd: c_int,
        arg: Option<&str>,
        argl: core::ffi::c_long,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> c_int {
        let (Some(a), Some(pq)) = (opt_c(arg), opt_c(propq)) else {
            return 0;
        };
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: the lookup is live (its store is); the strings are valid or NULL.
        unsafe {
            ffi::X509_LOOKUP_ctrl_ex(
                self.0,
                cmd,
                a.as_ref().map_or(core::ptr::null(), |a| a.as_ptr()),
                argl,
                core::ptr::null_mut(),
                ctx,
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        }
    }

    /// `X509_LOOKUP_load_file_ex(lookup, file, type, libctx, propq)`.
    pub fn load_file_ex(
        self,
        file: Option<&str>,
        kind: FileType,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> c_int {
        self.ctrl_ex(X509_L_FILE_LOAD, file, kind.value(), libctx, propq)
    }

    /// `X509_LOOKUP_add_dir(lookup, dir, type)`.
    pub fn add_dir(self, dir: Option<&str>, kind: FileType) -> c_int {
        let Some(d) = opt_c(dir) else {
            return 0;
        };
        // SAFETY: the lookup is live; the string is valid or NULL.
        unsafe {
            ffi::X509_LOOKUP_ctrl(
                self.0,
                X509_L_ADD_DIR,
                d.as_ref().map_or(core::ptr::null(), |d| d.as_ptr()),
                kind.value(),
                core::ptr::null_mut(),
            )
        }
    }

    /// `X509_LOOKUP_add_store_ex(lookup, uri, libctx, propq)`.
    pub fn add_store_ex(
        self,
        uri: Option<&str>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> c_int {
        self.ctrl_ex(X509_L_ADD_STORE, uri, 0, libctx, propq)
    }
}

crate::handle!(
    /// An owned `X509_STORE_CTX`.
    StoreCtx, X509_STORE_CTX, X509_STORE_CTX_free
);

impl StoreCtx {
    /// `X509_STORE_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::X509_STORE_CTX_new() })
    }

    /// `X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_X509, name)`.
    pub fn get_cert_by_subject(
        &self,
        name: crate::x509::NameRef<'_>,
    ) -> Option<crate::x509::Object> {
        // SAFETY: the context is live (initialized with its store); the name is live.
        crate::x509::Object::from_ptr(unsafe {
            ffi::X509_STORE_CTX_get_obj_by_subject(
                self.as_ptr(),
                crate::abi::X509_LU_X509,
                name.as_ptr(),
            )
        })
    }
}

/// An initialized `X509_STORE_CTX` using objects borrowed for `'a` (the store, the
/// certificate, the untrusted, trusted, and CRL stacks), which outlive it.
pub struct VerifyCtx<'a>(StoreCtx, core::marker::PhantomData<&'a ()>);

/// Why [`VerifyCtx::new`] failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtxError {
    /// `X509_STORE_CTX_new` failed.
    Alloc,
    /// `X509_STORE_CTX_init` failed.
    Init,
}

impl<'a> VerifyCtx<'a> {
    /// `X509_STORE_CTX_new` then `X509_STORE_CTX_init(ctx, store, cert, untrusted)`.
    pub fn new(
        store: &'a Store,
        cert: Option<&'a crate::x509::Cert>,
        untrusted: Option<&'a crate::x509::CertStack>,
    ) -> Result<Self, CtxError> {
        let ctx = StoreCtx::new().ok_or(CtxError::Alloc)?;
        // SAFETY: all are live or NULL, and borrowed for 'a, longer than the context lives.
        let ok = unsafe {
            ffi::X509_STORE_CTX_init(
                ctx.as_ptr(),
                store.as_ptr(),
                cert.map_or(core::ptr::null_mut(), crate::x509::Cert::as_ptr),
                untrusted.map_or(core::ptr::null_mut(), crate::x509::CertStack::as_ptr),
            )
        };
        if ok != 1 {
            return Err(CtxError::Init);
        }
        Ok(Self(ctx, core::marker::PhantomData))
    }

    /// The context, borrowed.
    pub fn as_ref(&self) -> StoreCtxRef<'_> {
        StoreCtxRef(self.0.as_ptr(), core::marker::PhantomData)
    }

    /// `X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_X509, name)`.
    pub fn get_cert_by_subject(
        &self,
        name: crate::x509::NameRef<'_>,
    ) -> Option<crate::x509::Object> {
        // SAFETY: the context is live and initialized; the name is live.
        crate::x509::Object::from_ptr(unsafe {
            ffi::X509_STORE_CTX_get_obj_by_subject(
                self.0.as_ptr(),
                crate::abi::X509_LU_X509,
                name.as_ptr(),
            )
        })
    }

    /// `X509_STORE_CTX_set0_trusted_stack` (the stack stays the caller's).
    pub fn set0_trusted_stack(&mut self, trusted: &'a crate::x509::CertStack) {
        // SAFETY: both are live; the stack outlives the context ('a).
        unsafe { ffi::X509_STORE_CTX_set0_trusted_stack(self.0.as_ptr(), trusted.as_ptr()) };
    }

    /// `X509_STORE_CTX_set0_crls` (the stack stays the caller's).
    pub fn set0_crls(&mut self, crls: &'a crate::x509::CrlStack) {
        // SAFETY: both are live; the stack outlives the context ('a).
        unsafe { ffi::X509_STORE_CTX_set0_crls(self.0.as_ptr(), crls.as_ptr()) };
    }

    /// `X509_STORE_CTX_set_flags`.
    pub fn set_flags(&mut self, flags: c_ulong) {
        // SAFETY: the context is live.
        unsafe { ffi::X509_STORE_CTX_set_flags(self.0.as_ptr(), flags) };
    }

    /// `X509_verify_cert`: what it returns.
    pub fn verify_cert(&mut self) -> c_int {
        // SAFETY: the context is live and initialized.
        unsafe { ffi::X509_verify_cert(self.0.as_ptr()) }
    }
}

/// An `X509_STORE_CTX` borrowed (a verification callback's, or a [`VerifyCtx`]).
#[derive(Clone, Copy)]
pub struct StoreCtxRef<'a>(
    *mut crate::abi::X509_STORE_CTX,
    core::marker::PhantomData<&'a ()>,
);

impl<'a> StoreCtxRef<'a> {
    /// `X509_STORE_CTX_get_error`.
    pub fn error(self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::X509_STORE_CTX_get_error(self.0) }
    }

    /// `X509_STORE_CTX_get_error_depth`.
    pub fn error_depth(self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::X509_STORE_CTX_get_error_depth(self.0) }
    }

    /// `X509_STORE_CTX_get_current_cert`.
    pub fn current_cert(self) -> Option<crate::x509::CertRef<'a>> {
        // SAFETY: the context is live; the certificate is owned by it.
        crate::x509::CertRef::new(unsafe { ffi::X509_STORE_CTX_get_current_cert(self.0) })
    }

    /// Whether `X509_STORE_CTX_get0_parent_ctx` is non-NULL (a CRL path's context).
    pub fn has_parent(self) -> bool {
        // SAFETY: the context is live.
        !unsafe { ffi::X509_STORE_CTX_get0_parent_ctx(self.0) }.is_null()
    }

    /// `X509_STORE_CTX_get_explicit_policy`.
    pub fn explicit_policy(self) -> bool {
        // SAFETY: the context is live.
        unsafe { ffi::X509_STORE_CTX_get_explicit_policy(self.0) != 0 }
    }

    /// The policy tree's authority (`user` false) or user policies (`nodes_print` of
    /// `apps.c`): `None`, printing nothing, for a NULL stack; else a newline, then
    /// `X509_POLICY_NODE_print(out, node, indent)` for each.
    pub fn print_policy_nodes(self, user: bool, out: &crate::Bio, indent: c_int) -> Option<()> {
        // SAFETY: the context is live; the tree is owned by it (NULL allowed below).
        let tree = unsafe { ffi::X509_STORE_CTX_get0_policy_tree(self.0) };
        let nodes = if user {
            // SAFETY: tree is NULL or live.
            unsafe { ffi::X509_policy_tree_get0_user_policies(tree) }
        } else {
            // SAFETY: as above.
            unsafe { ffi::X509_policy_tree_get0_policies(tree) }
        };
        if nodes.is_null() {
            return None;
        }
        let _ = out.write_all(b"\n");
        let st = nodes.cast::<crate::abi::OPENSSL_STACK>();
        // SAFETY: st is live.
        let n = unsafe { ffi::OPENSSL_sk_num(st) };
        for i in 0..n.max(0) {
            // SAFETY: i is in range.
            let node = unsafe { ffi::OPENSSL_sk_value(st, i) };
            // SAFETY: node is a live X509_POLICY_NODE of the tree; out is live.
            unsafe { ffi::X509_POLICY_NODE_print(out.as_ptr(), node.cast(), indent) };
        }
        Some(())
    }

    /// `X509_STORE_CTX_get1_chain`.
    pub fn chain(self) -> Option<crate::x509::CertStack> {
        // SAFETY: the context is live; the stack and its references are the caller's.
        crate::x509::CertStack::from_raw(unsafe { ffi::X509_STORE_CTX_get1_chain(self.0) })
    }

    /// `X509_STORE_CTX_get_num_untrusted`.
    pub fn num_untrusted(self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::X509_STORE_CTX_get_num_untrusted(self.0) }
    }
}

/// `X509_verify_cert_error_string`.
pub fn verify_cert_error_string(n: core::ffi::c_long) -> String {
    // SAFETY: any value; the string is static.
    crate::util::string_at(unsafe { ffi::X509_verify_cert_error_string(n) }).unwrap_or_default()
}

/// A verification callback (`X509_STORE_CTX_verify_cb`), in Rust.
pub type VerifyCb = fn(c_int, StoreCtxRef<'_>) -> c_int;

/// A CRL lookup callback (`X509_STORE_CTX_lookup_crls_fn`), in Rust: the CRLs, or `None`.
pub type LookupCrlsCb = fn(StoreCtxRef<'_>) -> Option<crate::x509::CrlStack>;

/// The program's one verification callback and one CRL lookup callback: the CLI sets each at
/// most once per command, on the main thread.
static VERIFY_CB: std::sync::Mutex<Option<VerifyCb>> = std::sync::Mutex::new(None);
static LOOKUP_CRLS_CB: std::sync::Mutex<Option<LookupCrlsCb>> = std::sync::Mutex::new(None);

unsafe extern "C" fn verify_trampoline(ok: c_int, ctx: *mut crate::abi::X509_STORE_CTX) -> c_int {
    // The lock is released before the callback runs (it may set callbacks itself).
    let cb = VERIFY_CB.lock().map(|g| *g).unwrap_or(None);
    let Some(cb) = cb else {
        return ok;
    };
    let r = std::panic::catch_unwind(|| cb(ok, StoreCtxRef(ctx, core::marker::PhantomData)));
    r.unwrap_or(0)
}

unsafe extern "C" fn lookup_crls_trampoline(
    ctx: *const crate::abi::X509_STORE_CTX,
    _nm: *const crate::abi::X509_NAME,
) -> *mut crate::abi::stack_st_X509_CRL {
    let cb = LOOKUP_CRLS_CB.lock().map(|g| *g).unwrap_or(None);
    let Some(cb) = cb else {
        return core::ptr::null_mut();
    };
    let r = std::panic::catch_unwind(|| cb(StoreCtxRef(ctx.cast_mut(), core::marker::PhantomData)));
    // The library takes the stack.
    r.ok()
        .flatten()
        .map_or(core::ptr::null_mut(), crate::x509::CrlStack::into_ptr)
}

impl Store {
    /// `X509_STORE_set_verify_cb(store, cb)`.
    pub fn set_verify_cb(&self, cb: VerifyCb) {
        if let Ok(mut g) = VERIFY_CB.lock() {
            *g = Some(cb);
        }
        // SAFETY: the store is live; the trampoline has the callback's C type.
        unsafe { ffi::X509_STORE_set_verify_cb(self.as_ptr(), Some(verify_trampoline)) };
    }

    /// `X509_STORE_set_lookup_crls_cb(store, cb)`.
    pub fn set_lookup_crls_cb(&self, cb: LookupCrlsCb) {
        if let Ok(mut g) = LOOKUP_CRLS_CB.lock() {
            *g = Some(cb);
        }
        // SAFETY: the store is live; the trampoline has the callback's C type.
        unsafe { ffi::X509_STORE_set_lookup_crls(self.as_ptr(), Some(lookup_crls_trampoline)) };
    }

    /// `X509_STORE_set1_param`.
    pub fn set1_param(&self, param: &VerifyParam) -> bool {
        // SAFETY: both are live; the store copies the param.
        unsafe { ffi::X509_STORE_set1_param(self.as_ptr(), param.as_ptr()) == 1 }
    }

    /// `X509_STORE_set_flags`.
    pub fn set_flags(&self, flags: c_ulong) {
        // SAFETY: the store is live.
        unsafe { ffi::X509_STORE_set_flags(self.as_ptr(), flags) };
    }

    /// `X509_STORE_set_default_paths_ex(store, libctx, propq)`.
    pub fn set_default_paths_ex(&self, libctx: Option<&LibCtx>, propq: Option<&str>) -> bool {
        let Some(pq) = opt_c(propq) else {
            return false;
        };
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: the store is live; ctx and pq are NULL or valid.
        unsafe {
            ffi::X509_STORE_set_default_paths_ex(
                self.as_ptr(),
                ctx,
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            ) == 1
        }
    }

    /// `X509_STORE_add_cert`.
    pub fn add_cert(&self, cert: &crate::x509::Cert) -> bool {
        // SAFETY: both are live; the store takes its own reference.
        unsafe { ffi::X509_STORE_add_cert(self.as_ptr(), cert.as_ptr()) == 1 }
    }
}

/// The purposes' short names and names (`X509_PURPOSE_get0_sname`, `_get0_name`), in order.
pub fn purposes() -> Vec<(String, String)> {
    // SAFETY: no arguments.
    let n = unsafe { ffi::X509_PURPOSE_get_count() };
    let mut out = Vec::new();
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the purpose is the library's.
        let p = unsafe { ffi::X509_PURPOSE_get0(i) };
        if p.is_null() {
            continue;
        }
        // SAFETY: p is live; the strings are owned by it.
        let sname = crate::util::string_at(unsafe { ffi::X509_PURPOSE_get0_sname(p) });
        // SAFETY: as above.
        let name = crate::util::string_at(unsafe { ffi::X509_PURPOSE_get0_name(p) });
        out.push((sname.unwrap_or_default(), name.unwrap_or_default()));
    }
    out
}

/// The built-in verification parameters' names (`X509_VERIFY_PARAM_get0_name`), in order.
pub fn param_names() -> Vec<String> {
    // SAFETY: no arguments.
    let n = unsafe { ffi::X509_VERIFY_PARAM_get_count() };
    let mut out = Vec::new();
    for i in 0..n.max(0) {
        // SAFETY: i is in range; the param is the library's.
        let p = unsafe { ffi::X509_VERIFY_PARAM_get0(i) };
        if p.is_null() {
            continue;
        }
        // SAFETY: p is live; the name is owned by it.
        out.push(
            crate::util::string_at(unsafe { ffi::X509_VERIFY_PARAM_get0_name(p) })
                .unwrap_or_default(),
        );
    }
    out
}
