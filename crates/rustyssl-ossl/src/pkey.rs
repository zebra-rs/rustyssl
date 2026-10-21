//! Keys and the signing context.

use core::ffi::c_char;

use crate::abi::{EVP_PKEY, EVP_PKEY_CTX};
use crate::ffi;
use crate::provider::LibCtx;
use crate::util::{cstring, string_at};

crate::handle!(
    /// An owned `EVP_PKEY`.
    Pkey, EVP_PKEY, EVP_PKEY_free
);

impl Pkey {
    /// Takes ownership of a key the caller got from the library.
    pub fn from_raw(p: *mut EVP_PKEY) -> Option<Self> {
        Self::from_ptr(p)
    }

    /// `EVP_PKEY_is_a`.
    pub fn is_a(&self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: the key is live; n is a valid C string.
        unsafe { ffi::EVP_PKEY_is_a(self.as_ptr(), n.as_ptr()) == 1 }
    }

    /// `EVP_PKEY_get_default_digest_name`: what it returns, and the name.
    pub fn default_digest_name(&self) -> (i32, String) {
        let mut buf = [0 as c_char; 80];
        // SAFETY: the key is live; buf is writable for its length.
        let r = unsafe {
            ffi::EVP_PKEY_get_default_digest_name(self.as_ptr(), buf.as_mut_ptr(), buf.len())
        };
        let name = if r > 0 {
            string_at(buf.as_ptr()).unwrap_or_default()
        } else {
            String::new()
        };
        (r, name)
    }
}

crate::handle!(
    /// An owned `EVP_MD_CTX`.
    MdCtx, EVP_MD_CTX, EVP_MD_CTX_free
);

impl MdCtx {
    /// `EVP_MD_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::EVP_MD_CTX_new() })
    }

    /// `EVP_DigestSignInit_ex(ctx, &pctx, md, libctx, propq, pkey, NULL)`: whether it
    /// succeeded, and the key context it set up (owned by `self`).
    pub fn digest_sign_init(
        &self,
        md: Option<&str>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        pkey: &Pkey,
    ) -> (bool, PkeyCtxRef<'_>) {
        let md = md.map(cstring);
        let propq = propq.map(cstring);
        if md.as_ref().is_some_and(Option::is_none) || propq.as_ref().is_some_and(Option::is_none) {
            return (
                false,
                PkeyCtxRef(core::ptr::null_mut(), core::marker::PhantomData),
            );
        }
        let mdp = md
            .as_ref()
            .and_then(|m| m.as_ref())
            .map_or(core::ptr::null(), |m| m.as_ptr());
        let pqp = propq
            .as_ref()
            .and_then(|p| p.as_ref())
            .map_or(core::ptr::null(), |p| p.as_ptr());
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        let mut pctx: *mut EVP_PKEY_CTX = core::ptr::null_mut();
        // SAFETY: every pointer is live or NULL where the API allows it; pctx is a valid
        // out-pointer, and what it receives belongs to self.
        let r = unsafe {
            ffi::EVP_DigestSignInit_ex(
                self.as_ptr(),
                &mut pctx,
                mdp,
                ctx,
                pqp,
                pkey.as_ptr(),
                core::ptr::null(),
            )
        };
        (r == 1, PkeyCtxRef(pctx, core::marker::PhantomData))
    }
}

/// An `EVP_PKEY_CTX` borrowed from its owner (an `EVP_MD_CTX`'s, ...); it may be NULL.
#[derive(Clone, Copy)]
pub struct PkeyCtxRef<'a>(*mut EVP_PKEY_CTX, core::marker::PhantomData<&'a ()>);

impl PkeyCtxRef<'_> {
    /// `EVP_PKEY_CTX_ctrl_str(ctx, type, value)`: what it returns (-1 for NULL, as the
    /// library does for a context it can't use).
    pub fn ctrl_str(self, kind: &str, value: &str) -> i32 {
        let (Some(k), Some(v)) = (cstring(kind), cstring(value)) else {
            return -1;
        };
        if self.0.is_null() {
            return -1;
        }
        // SAFETY: the context is live (borrowed from its owner); the strings are valid.
        unsafe { ffi::EVP_PKEY_CTX_ctrl_str(self.0, k.as_ptr(), v.as_ptr()) }
    }
}

// Key contexts and raw keys (`dgst`, `mac`).

use core::ffi::c_int;

use crate::engine::Engine;

impl<'a> PkeyCtxRef<'a> {
    /// A context the caller keeps alive for `'a` (NULL allowed).
    pub(crate) fn from_raw(p: *mut EVP_PKEY_CTX) -> Self {
        Self(p, core::marker::PhantomData)
    }

    /// Whether it is NULL.
    pub fn is_null(self) -> bool {
        self.0.is_null()
    }
}

crate::handle!(
    /// An owned `EVP_PKEY_CTX`.
    PkeyCtx, EVP_PKEY_CTX, EVP_PKEY_CTX_free
);

impl PkeyCtx {
    /// `EVP_PKEY_CTX_new_id(id, e)`.
    pub fn new_id(id: c_int, e: Option<&Engine>) -> Option<Self> {
        let e = e.map_or(core::ptr::null_mut(), Engine::as_ptr);
        // SAFETY: the engine is NULL or live.
        Self::from_ptr(unsafe { ffi::EVP_PKEY_CTX_new_id(id, e) })
    }

    /// `EVP_PKEY_CTX_new_from_name(libctx, name, propq)`.
    pub fn new_from_name(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// The context, borrowed.
    pub fn borrow(&self) -> PkeyCtxRef<'_> {
        PkeyCtxRef(self.as_ptr(), core::marker::PhantomData)
    }

    /// `EVP_PKEY_keygen_init`.
    pub fn keygen_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_keygen_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_paramgen_init`.
    pub fn paramgen_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_paramgen_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_keygen(ctx, &key)`: what it returns, and the key.
    pub fn keygen(&self) -> (c_int, Option<Pkey>) {
        let mut p: *mut EVP_PKEY = core::ptr::null_mut();
        // SAFETY: the context is live; p is a valid out-pointer, and the key ours.
        let r = unsafe { ffi::EVP_PKEY_keygen(self.as_ptr(), &mut p) };
        (r, Pkey::from_ptr(p))
    }
}

impl Pkey {
    /// `EVP_PKEY_new_raw_private_key(kind, e, key, len)`.
    pub fn new_raw_private_key(kind: c_int, e: Option<&Engine>, key: &[u8]) -> Option<Self> {
        let e = e.map_or(core::ptr::null_mut(), Engine::as_ptr);
        // SAFETY: the engine is NULL or live; key is valid for its length.
        Self::from_ptr(unsafe {
            ffi::EVP_PKEY_new_raw_private_key(kind, e, key.as_ptr(), key.len())
        })
    }

    /// `EVP_PKEY_get_size`.
    pub fn size(&self) -> c_int {
        // SAFETY: the key is live.
        unsafe { ffi::EVP_PKEY_get_size(self.as_ptr()) }
    }

    /// `EVP_PKEY_get0_type_name`.
    pub fn type_name(&self) -> Option<String> {
        // SAFETY: the key is live; the name is owned by it and copied.
        string_at(unsafe { ffi::EVP_PKEY_get0_type_name(self.as_ptr()) })
    }
}

/// `get_legacy_pkey_id` of `apps/lib/engine.c`: the key type's NID when an engine implements
/// it (`algname` found through an engine, or in `e`), `NID_undef` otherwise.
pub fn legacy_pkey_id(algname: &str, e: Option<&Engine>) -> c_int {
    let Some(n) = cstring(algname) else {
        return crate::abi::NID_undef;
    };
    crate::err::set_mark();
    let mut tmpeng: *mut crate::abi::ENGINE = core::ptr::null_mut();
    // SAFETY: tmpeng is a valid out-pointer; n is a valid C string; -1 means NUL-terminated.
    let mut ameth = unsafe { ffi::EVP_PKEY_asn1_find_str(&mut tmpeng, n.as_ptr(), -1) };
    // SAFETY: tmpeng is NULL or a functional reference the lookup gave us.
    unsafe { ffi::ENGINE_finish(tmpeng) };
    if ameth.is_null()
        && let Some(e) = e
    {
        // SAFETY: the engine is live; n is valid.
        ameth = unsafe { ffi::ENGINE_get_pkey_asn1_meth_str(e.as_ptr(), n.as_ptr(), -1) };
    } else if tmpeng.is_null() {
        // Only one that comes from an engine counts.
        ameth = core::ptr::null();
    }
    crate::err::pop_to_mark();
    if ameth.is_null() {
        return crate::abi::NID_undef;
    }
    let mut id = crate::abi::NID_undef;
    // SAFETY: ameth is a live method table; NULL out-pointers are allowed.
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
