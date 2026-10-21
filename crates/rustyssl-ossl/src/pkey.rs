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

impl Pkey {
    /// `PEM_write_bio_PUBKEY`: what it returns.
    pub fn write_pubkey_pem(&self, out: &crate::Bio) -> core::ffi::c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_PUBKEY(out.as_ptr(), self.as_ptr()) }
    }
}

impl Pkey {
    /// `EVP_PKEY_print_params(out, pkey, indent, NULL)`.
    pub fn print_params(&self, out: &crate::Bio, indent: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: both are live; no print context.
        unsafe {
            ffi::EVP_PKEY_print_params(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `EVP_PKEY_print_public(out, pkey, indent, NULL)`.
    pub fn print_public(&self, out: &crate::Bio, indent: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: as above.
        unsafe {
            ffi::EVP_PKEY_print_public(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `EVP_PKEY_print_private(out, pkey, indent, NULL)`.
    pub fn print_private(&self, out: &crate::Bio, indent: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: as above.
        unsafe {
            ffi::EVP_PKEY_print_private(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `PEM_write_bio_Parameters`.
    pub fn write_params_pem(&self, out: &crate::Bio) -> core::ffi::c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_Parameters(out.as_ptr(), self.as_ptr()) }
    }

    /// `PEM_write_bio_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL)`.
    pub fn write_private_pem(&self, out: &crate::Bio) -> core::ffi::c_int {
        // SAFETY: both are live; no cipher or callback.
        unsafe {
            ffi::PEM_write_bio_PrivateKey(
                out.as_ptr(),
                self.as_ptr(),
                core::ptr::null(),
                core::ptr::null_mut(),
                0,
                None,
                core::ptr::null_mut(),
            )
        }
    }
}

crate::handle!(
    /// An owned `EVP_PKEY_CTX` for generating a key (`req -newkey`).
    KeygenCtx, EVP_PKEY_CTX, EVP_PKEY_CTX_free
);

/// The keygen progress callback (`EVP_PKEY_gen_cb`), in Rust: it gets
/// `EVP_PKEY_CTX_get_keygen_info(ctx, 0)`.
pub type ProgressCb = fn(core::ffi::c_int);

static PROGRESS_CB: std::sync::Mutex<Option<ProgressCb>> = std::sync::Mutex::new(None);

unsafe extern "C" fn progress_trampoline(ctx: *mut EVP_PKEY_CTX) -> core::ffi::c_int {
    let cb = PROGRESS_CB.lock().map(|g| *g).unwrap_or(None);
    if let Some(cb) = cb {
        // SAFETY: the library passes its live context.
        let p = unsafe { ffi::EVP_PKEY_CTX_get_keygen_info(ctx, 0) };
        let _ = std::panic::catch_unwind(|| cb(p));
    }
    1
}

impl KeygenCtx {
    /// `EVP_PKEY_CTX_new_from_name(libctx, name, propq)`.
    pub fn from_name(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
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

    /// `EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)`.
    pub fn from_pkey(libctx: Option<&LibCtx>, pkey: &Pkey, propq: Option<&str>) -> Option<Self> {
        let pq = match propq {
            Some(p) => Some(cstring(p)?),
            None => None,
        };
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: all are live or NULL.
        Self::from_ptr(unsafe {
            ffi::EVP_PKEY_CTX_new_from_pkey(
                ctx,
                pkey.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `EVP_PKEY_CTX_new(pkey, e)`.
    pub fn with_engine(pkey: &Pkey, e: &crate::engine::Engine) -> Option<Self> {
        // SAFETY: both are live.
        Self::from_ptr(unsafe { ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), e.as_ptr()) })
    }

    /// `EVP_PKEY_CTX_new_id(id, e)`.
    pub fn from_id(id: core::ffi::c_int, e: &crate::engine::Engine) -> Option<Self> {
        // SAFETY: the engine is live.
        Self::from_ptr(unsafe { ffi::EVP_PKEY_CTX_new_id(id, e.as_ptr()) })
    }

    /// The context, borrowed (for `pkey_ctrl_string`).
    pub fn as_ref(&self) -> PkeyCtxRef<'_> {
        PkeyCtxRef(self.as_ptr(), core::marker::PhantomData)
    }

    /// `EVP_PKEY_CTX_is_a`.
    pub fn is_a(&self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: the context is live; n is a valid C string.
        unsafe { ffi::EVP_PKEY_CTX_is_a(self.as_ptr(), n.as_ptr()) == 1 }
    }

    /// `EVP_PKEY_keygen_init`: what it returns.
    pub fn keygen_init(&self) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_keygen_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_CTX_set_params` with `OSSL_PKEY_PARAM_BITS` (a `size_t`): what it returns.
    pub fn set_bits(&self, bits: usize) -> core::ffi::c_int {
        let mut b = bits;
        // SAFETY: the key is a static string; b outlives the params.
        let first = unsafe {
            ffi::OSSL_PARAM_construct_size_t(crate::abi::OSSL_PKEY_PARAM_BITS.as_ptr(), &mut b)
        };
        // SAFETY: no arguments.
        let end = unsafe { ffi::OSSL_PARAM_construct_end() };
        let params = [first, end];
        // SAFETY: the context is live; params is a terminated array.
        unsafe { ffi::EVP_PKEY_CTX_set_params(self.as_ptr(), params.as_ptr()) }
    }

    /// `EVP_PKEY_CTX_set_cb(ctx, progress)`, with `cb` the Rust callback (one per program).
    pub fn set_progress_cb(&self, cb: ProgressCb) {
        if let Ok(mut g) = PROGRESS_CB.lock() {
            *g = Some(cb);
        }
        // SAFETY: the context is live; the trampoline has the callback's C type.
        unsafe { ffi::EVP_PKEY_CTX_set_cb(self.as_ptr(), Some(progress_trampoline)) };
    }

    /// `EVP_PKEY_keygen`: the key, if it worked.
    pub fn keygen(&self) -> Option<Pkey> {
        let mut k: *mut EVP_PKEY = core::ptr::null_mut();
        // SAFETY: the context is live; k is a valid out-pointer.
        let r = unsafe { ffi::EVP_PKEY_keygen(self.as_ptr(), &mut k) };
        let key = Pkey::from_raw(k);
        if r <= 0 { None } else { key }
    }
}

impl Pkey {
    /// `PEM_read_bio_Parameters(bio, NULL)`.
    pub fn read_params_pem(bio: &crate::Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::PEM_read_bio_Parameters(bio.as_ptr(), core::ptr::null_mut()) })
    }

    /// `EVP_PKEY_get0_type_name`.
    pub fn type_name(&self) -> Option<String> {
        // SAFETY: the key is live; the name is owned by it.
        string_at(unsafe { ffi::EVP_PKEY_get0_type_name(self.as_ptr()) })
    }

    /// `EVP_PKEY_get_bits`.
    pub fn bits(&self) -> core::ffi::c_int {
        // SAFETY: the key is live.
        unsafe { ffi::EVP_PKEY_get_bits(self.as_ptr()) }
    }

    /// `PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, pass)`: with no
    /// password, the library's default callback asks for one.
    pub fn write_private_pem_enc(
        &self,
        out: &crate::Bio,
        cipher: Option<&crate::evp::Cipher>,
        pass: Option<&str>,
    ) -> core::ffi::c_int {
        let p = match pass {
            Some(p) => match cstring(p) {
                Some(c) => Some(c),
                None => return 0,
            },
            None => None,
        };
        // SAFETY: all are live or NULL; the password is a C string the default callback
        // reads as its user data.
        unsafe {
            ffi::PEM_write_bio_PrivateKey(
                out.as_ptr(),
                self.as_ptr(),
                cipher.map_or(core::ptr::null(), |c| c.as_ptr().cast_const()),
                core::ptr::null_mut(),
                0,
                None,
                p.as_ref()
                    .map_or(core::ptr::null_mut(), |c| c.as_ptr().cast_mut().cast()),
            )
        }
    }
}

/// `RAND_status()`.
pub fn rand_status() -> bool {
    // SAFETY: no arguments.
    unsafe { ffi::RAND_status() == 1 }
}
