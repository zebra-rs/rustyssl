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

    /// `X509_STORE_CTX_init(ctx, store, cert, untrusted)`; the context uses the objects
    /// while it lives, so the caller keeps them alive until it is dropped or re-initialized.
    pub fn init(
        &self,
        store: &Store,
        cert: Option<&crate::x509::Cert>,
        untrusted: Option<&crate::x509::CertStack>,
    ) -> bool {
        // SAFETY: all are live or NULL.
        unsafe {
            ffi::X509_STORE_CTX_init(
                self.as_ptr(),
                store.as_ptr(),
                cert.map_or(core::ptr::null_mut(), crate::x509::Cert::as_ptr),
                untrusted.map_or(core::ptr::null_mut(), crate::x509::CertStack::as_ptr),
            ) == 1
        }
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
