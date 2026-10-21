//! EVP lookups.

use crate::ffi;
use crate::util::cstring;

/// Whether `EVP_get_digestbyname(name)` finds a digest.
pub fn digest_exists(name: &str) -> bool {
    let Some(n) = cstring(name) else {
        return false;
    };
    // SAFETY: n is a valid C string; the result is a static (or NULL), not freed.
    !unsafe { ffi::EVP_get_digestbyname(n.as_ptr()) }.is_null()
}

/// Whether `EVP_get_cipherbyname(name)` finds a cipher.
pub fn cipher_exists(name: &str) -> bool {
    let Some(n) = cstring(name) else {
        return false;
    };
    // SAFETY: as above.
    !unsafe { ffi::EVP_get_cipherbyname(n.as_ptr()) }.is_null()
}

use crate::provider::LibCtx;

crate::handle!(
    /// A cipher: fetched (freed when dropped) or a legacy static one (`EVP_CIPHER_free`
    /// ignores those).
    Cipher, EVP_CIPHER, EVP_CIPHER_free
);
crate::handle!(
    /// A digest, fetched or legacy (as [`Cipher`]).
    Md, EVP_MD, EVP_MD_free
);

fn propq_c(propq: Option<&str>) -> Option<Option<std::ffi::CString>> {
    match propq {
        Some(p) => cstring(p).map(Some),
        None => Some(None),
    }
}

impl Cipher {
    /// `EVP_CIPHER_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe {
            ffi::EVP_CIPHER_fetch(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `EVP_get_cipherbyname(name)` (a legacy, static cipher).
    pub fn by_name(name: &str) -> Option<Self> {
        let n = cstring(name)?;
        // SAFETY: n is a valid C string; EVP_CIPHER_free ignores the static result.
        Self::from_ptr(unsafe { ffi::EVP_get_cipherbyname(n.as_ptr()) }.cast_mut())
    }

    /// `EVP_CIPHER_get_mode`.
    pub fn mode(&self) -> core::ffi::c_int {
        // SAFETY: the cipher is live.
        unsafe { ffi::EVP_CIPHER_get_mode(self.as_ptr()) }
    }

    /// `EVP_CIPHER_get_flags`.
    pub fn flags(&self) -> core::ffi::c_ulong {
        // SAFETY: the cipher is live.
        unsafe { ffi::EVP_CIPHER_get_flags(self.as_ptr()) }
    }
}

impl Md {
    /// `EVP_MD_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: as in Cipher::fetch.
        Self::from_ptr(unsafe {
            ffi::EVP_MD_fetch(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `EVP_get_digestbyname(name)` (a legacy, static digest).
    pub fn by_name(name: &str) -> Option<Self> {
        let n = cstring(name)?;
        // SAFETY: n is a valid C string; EVP_MD_free ignores the static result.
        Self::from_ptr(unsafe { ffi::EVP_get_digestbyname(n.as_ptr()) }.cast_mut())
    }
}

impl Cipher {
    /// `EVP_aes_256_cbc()` (a legacy, static cipher; dropping it is a no-op).
    pub fn aes_256_cbc() -> Option<Self> {
        // SAFETY: no arguments; EVP_CIPHER_free ignores the static result.
        Self::from_ptr(unsafe { ffi::EVP_aes_256_cbc() }.cast_mut())
    }
}

// Digest contexts (`dgst`) and the name lists (`OBJ_NAME_do_all_sorted`).

use core::ffi::c_int;

use crate::abi::{EVP_MD_CTX, EVP_PKEY_CTX, OBJ_NAME};
use crate::engine::Engine;
use crate::pkey::{MdCtx, Pkey, PkeyCtxRef};
use crate::util::string_at;

/// An `EVP_MD_CTX` borrowed from its owner (a digest `BIO`, or an [`MdCtx`]).
#[derive(Clone, Copy)]
pub struct MdCtxRef<'a>(*mut EVP_MD_CTX, core::marker::PhantomData<&'a ()>);

fn c_opt(s: Option<&str>) -> Option<Option<std::ffi::CString>> {
    match s {
        Some(s) => cstring(s).map(Some),
        None => Some(None),
    }
}

fn ptr_of(s: &Option<std::ffi::CString>) -> *const core::ffi::c_char {
    s.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

fn engine_ptr(e: Option<&Engine>) -> *mut crate::abi::ENGINE {
    e.map_or(core::ptr::null_mut(), Engine::as_ptr)
}

impl MdCtx {
    /// The context, borrowed.
    pub fn borrow(&self) -> MdCtxRef<'_> {
        MdCtxRef(self.as_ptr(), core::marker::PhantomData)
    }
}

impl<'a> MdCtxRef<'a> {
    /// A context the caller keeps alive for `'a`.
    pub(crate) fn new(p: *mut EVP_MD_CTX) -> Self {
        Self(p, core::marker::PhantomData)
    }

    /// `EVP_DigestInit_ex(ctx, md, impl)`.
    pub fn digest_init(self, md: &Md, e: Option<&Engine>) -> bool {
        // SAFETY: the context and digest are live; the engine is NULL or live.
        unsafe { ffi::EVP_DigestInit_ex(self.0, md.as_ptr(), engine_ptr(e)) == 1 }
    }

    /// `EVP_DigestSignInit_ex` (`verify` false) or `EVP_DigestVerifyInit_ex`, with the digest
    /// by name: what it returns, and the key context (owned by the digest context).
    pub fn sign_verify_init_ex(
        self,
        verify: bool,
        mdname: Option<&str>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        pkey: &Pkey,
    ) -> (c_int, PkeyCtxRef<'a>) {
        let mut pctx: *mut EVP_PKEY_CTX = core::ptr::null_mut();
        let (Some(md), Some(pq)) = (c_opt(mdname), c_opt(propq)) else {
            return (0, PkeyCtxRef::from_raw(pctx));
        };
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        let (m, q, k) = (ptr_of(&md), ptr_of(&pq), pkey.as_ptr());
        let r = if verify {
            // SAFETY: every pointer is live or NULL where the API allows it; pctx is a valid
            // out-pointer, and what it receives belongs to the digest context.
            unsafe {
                ffi::EVP_DigestVerifyInit_ex(self.0, &mut pctx, m, ctx, q, k, core::ptr::null())
            }
        } else {
            // SAFETY: as above.
            unsafe {
                ffi::EVP_DigestSignInit_ex(self.0, &mut pctx, m, ctx, q, k, core::ptr::null())
            }
        };
        (r, PkeyCtxRef::from_raw(pctx))
    }

    /// `EVP_DigestSignInit` (`verify` false) or `EVP_DigestVerifyInit`, with an engine.
    pub fn sign_verify_init(
        self,
        verify: bool,
        md: Option<&Md>,
        e: Option<&Engine>,
        pkey: &Pkey,
    ) -> (c_int, PkeyCtxRef<'a>) {
        let mut pctx: *mut EVP_PKEY_CTX = core::ptr::null_mut();
        let mdp = md.map_or(core::ptr::null(), |m| m.as_ptr().cast_const());
        let (eng, k) = (engine_ptr(e), pkey.as_ptr());
        let r = if verify {
            // SAFETY: as in sign_verify_init_ex.
            unsafe { ffi::EVP_DigestVerifyInit(self.0, &mut pctx, mdp, eng, k) }
        } else {
            // SAFETY: as in sign_verify_init_ex.
            unsafe { ffi::EVP_DigestSignInit(self.0, &mut pctx, mdp, eng, k) }
        };
        (r, PkeyCtxRef::from_raw(pctx))
    }

    /// `EVP_DigestVerifyFinal(ctx, sig, len)`.
    pub fn verify_final(self, sig: &[u8]) -> c_int {
        // SAFETY: the context is live; sig is valid for its length.
        unsafe { ffi::EVP_DigestVerifyFinal(self.0, sig.as_ptr(), sig.len()) }
    }

    /// `EVP_DigestSignFinal(ctx, NULL, &len)`: the signature's maximum length.
    pub fn sign_final_len(self) -> Option<usize> {
        let mut len = 0usize;
        // SAFETY: the context is live; NULL asks for the length only.
        (unsafe { ffi::EVP_DigestSignFinal(self.0, core::ptr::null_mut(), &mut len) } == 1)
            .then_some(len)
    }

    /// `EVP_DigestSignFinal(ctx, buf, &len)`: the signature's length.
    pub fn sign_final(self, buf: &mut [u8]) -> Option<usize> {
        let mut len = buf.len();
        // SAFETY: the context is live; buf is writable for len bytes.
        (unsafe { ffi::EVP_DigestSignFinal(self.0, buf.as_mut_ptr(), &mut len) } == 1)
            .then_some(len)
    }

    /// `EVP_DigestFinalXOF(ctx, buf, len)`.
    pub fn final_xof(self, buf: &mut [u8]) -> bool {
        // SAFETY: the context is live; buf is writable for its length.
        unsafe { ffi::EVP_DigestFinalXOF(self.0, buf.as_mut_ptr(), buf.len()) == 1 }
    }

    /// `EVP_DigestVerify(ctx, sig, siglen, data, len)`.
    pub fn verify_oneshot(self, sig: &[u8], data: &[u8]) -> c_int {
        // SAFETY: the context is live; both slices are valid for their lengths.
        unsafe { ffi::EVP_DigestVerify(self.0, sig.as_ptr(), sig.len(), data.as_ptr(), data.len()) }
    }

    /// `EVP_DigestSign(ctx, NULL, &len, data, n)`: the signature's maximum length.
    pub fn sign_oneshot_len(self, data: &[u8]) -> Option<usize> {
        let mut len = 0usize;
        // SAFETY: the context is live; NULL asks for the length only; data is valid.
        (unsafe {
            ffi::EVP_DigestSign(
                self.0,
                core::ptr::null_mut(),
                &mut len,
                data.as_ptr(),
                data.len(),
            )
        } == 1)
            .then_some(len)
    }

    /// `EVP_DigestSign(ctx, sig, &len, data, n)`: the signature's length.
    pub fn sign_oneshot(self, sig: &mut [u8], data: &[u8]) -> Option<usize> {
        let mut len = sig.len();
        // SAFETY: the context is live; sig is writable for len bytes; data is valid.
        (unsafe {
            ffi::EVP_DigestSign(
                self.0,
                sig.as_mut_ptr(),
                &mut len,
                data.as_ptr(),
                data.len(),
            )
        } == 1)
            .then_some(len)
    }

    /// `EVP_MD_CTX_get1_md`.
    pub fn get1_md(self) -> Option<Md> {
        // SAFETY: the context is live; the digest returned is a new reference.
        Md::from_ptr(unsafe { ffi::EVP_MD_CTX_get1_md(self.0) })
    }
}

impl Md {
    /// `EVP_sha256()` (static).
    pub fn sha256() -> Option<Self> {
        // SAFETY: no arguments; EVP_MD_free ignores the static result.
        Self::from_ptr(unsafe { ffi::EVP_sha256() }.cast_mut())
    }

    /// `EVP_MD_get0_name`.
    pub fn name(&self) -> Option<String> {
        // SAFETY: the digest is live; the name is owned by it and copied.
        string_at(unsafe { ffi::EVP_MD_get0_name(self.as_ptr()) })
    }

    /// `EVP_MD_xof`.
    pub fn xof(&self) -> bool {
        // SAFETY: the digest is live.
        unsafe { ffi::EVP_MD_xof(self.as_ptr()) == 1 }
    }
}

/// One `OBJ_NAME` (copied).
#[derive(Clone, Debug)]
pub struct ObjName {
    pub name: String,
    pub alias: bool,
    /// For an alias, the name it stands for.
    pub data: Option<String>,
}

unsafe extern "C" fn collect_name(name: *const OBJ_NAME, arg: *mut core::ffi::c_void) {
    // SAFETY: arg is the Vec that names_sorted passed, live for the call.
    let out = unsafe { &mut *arg.cast::<Vec<ObjName>>() };
    // SAFETY: name is a live OBJ_NAME for the callback's duration.
    let n = unsafe { &*name };
    let alias = n.alias != 0;
    out.push(ObjName {
        name: string_at(n.name).unwrap_or_default(),
        alias,
        // For an alias, data is the C string it names; otherwise it is the object.
        data: if alias { string_at(n.data) } else { None },
    });
}

/// `OBJ_NAME_do_all_sorted(kind, ...)`: the names, in its order.
pub fn names_sorted(kind: c_int) -> Vec<ObjName> {
    let mut out: Vec<ObjName> = Vec::new();
    // SAFETY: collect_name gets the Vec back, which outlives the call, and doesn't keep it.
    unsafe {
        ffi::OBJ_NAME_do_all_sorted(kind, Some(collect_name), (&raw mut out).cast());
    }
    out
}

// Cipher contexts, key derivation, and opaque symmetric keys (`enc`).

use crate::abi::EVP_CIPHER_CTX;
use crate::params::{Params, ParamsRef};
pub use crate::skey::Skey;
pub use crate::skey::SkeyMgmt;

impl Cipher {
    /// `EVP_CIPHER_get0_name`.
    pub fn name(&self) -> Option<String> {
        // SAFETY: the cipher is live; the name is owned by it and copied.
        string_at(unsafe { ffi::EVP_CIPHER_get0_name(self.as_ptr()) })
    }

    /// `EVP_CIPHER_get_key_length`.
    pub fn key_length(&self) -> c_int {
        // SAFETY: the cipher is live.
        unsafe { ffi::EVP_CIPHER_get_key_length(self.as_ptr()) }
    }

    /// `EVP_CIPHER_get_iv_length`.
    pub fn iv_length(&self) -> c_int {
        // SAFETY: the cipher is live.
        unsafe { ffi::EVP_CIPHER_get_iv_length(self.as_ptr()) }
    }

    /// `EVP_BytesToKey(cipher, md, salt, data, count, key, iv)`: the key's length, or 0. The
    /// salt is the first 8 bytes of `salt`, as the function reads.
    pub fn bytes_to_key(
        &self,
        md: &Md,
        salt: Option<&[u8; 8]>,
        data: &[u8],
        count: c_int,
        key: &mut [u8; 64],
        iv: &mut [u8; 16],
    ) -> c_int {
        let Ok(n) = c_int::try_from(data.len()) else {
            return 0;
        };
        let s = salt.map_or(core::ptr::null(), |s| s.as_ptr());
        // SAFETY: the cipher and digest are live; the salt is NULL or 8 bytes; data is valid
        // for n bytes; key and iv hold EVP_MAX_KEY_LENGTH and EVP_MAX_IV_LENGTH bytes.
        unsafe {
            ffi::EVP_BytesToKey(
                self.as_ptr(),
                md.as_ptr(),
                s,
                data.as_ptr(),
                n,
                count,
                key.as_mut_ptr(),
                iv.as_mut_ptr(),
            )
        }
    }
}

/// `PKCS5_PBKDF2_HMAC(pass, salt, iter, md, out)`.
pub fn pbkdf2_hmac(pass: &[u8], salt: Option<&[u8]>, iter: c_int, md: &Md, out: &mut [u8]) -> bool {
    let (Ok(plen), Ok(slen), Ok(olen)) = (
        c_int::try_from(pass.len()),
        c_int::try_from(salt.map_or(0, <[u8]>::len)),
        c_int::try_from(out.len()),
    ) else {
        return false;
    };
    let s = salt.map_or(core::ptr::null(), <[u8]>::as_ptr);
    // SAFETY: every buffer is valid for the length given; the digest is live.
    unsafe {
        ffi::PKCS5_PBKDF2_HMAC(
            pass.as_ptr().cast(),
            plen,
            s,
            slen,
            iter,
            md.as_ptr(),
            olen,
            out.as_mut_ptr(),
        ) == 1
    }
}

/// `EVP_read_pw_string(buf, size, prompt, verify)`: what it returns, and the password.
pub fn read_pw_string(size: usize, prompt: &str, verify: bool) -> (c_int, Vec<u8>) {
    let Some(p) = cstring(prompt) else {
        return (-1, Vec::new());
    };
    let mut buf = vec![0u8; size.max(1)];
    let n = c_int::try_from(buf.len()).unwrap_or(c_int::MAX);
    // SAFETY: buf is writable for n bytes; p is a valid C string.
    let r = unsafe {
        ffi::EVP_read_pw_string(buf.as_mut_ptr().cast(), n, p.as_ptr(), c_int::from(verify))
    };
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let pw = buf.get(..end).unwrap_or_default().to_vec();
    buf.fill(0);
    (r, pw)
}

/// An `EVP_CIPHER_CTX` borrowed from its owner (a cipher `BIO`).
#[derive(Clone, Copy)]
pub struct CipherCtxRef<'a>(*mut EVP_CIPHER_CTX, core::marker::PhantomData<&'a ()>);

impl CipherCtxRef<'_> {
    pub(crate) fn new(p: *mut EVP_CIPHER_CTX) -> Self {
        Self(p, core::marker::PhantomData)
    }

    /// `EVP_CIPHER_CTX_set_flags`.
    pub fn set_flags(self, flags: c_int) {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_CIPHER_CTX_set_flags(self.0, flags) };
    }

    /// `EVP_CIPHER_CTX_set_padding(ctx, pad)`.
    pub fn set_padding(self, pad: bool) {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_CIPHER_CTX_set_padding(self.0, c_int::from(pad)) };
    }

    /// `EVP_CipherInit_ex(ctx, cipher, e, key, iv, enc)`.
    pub fn init(
        self,
        cipher: &Cipher,
        e: Option<&Engine>,
        key: &[u8; 64],
        iv: Option<&[u8; 16]>,
        enc: bool,
    ) -> bool {
        let ivp = iv.map_or(core::ptr::null(), |v| v.as_ptr());
        // SAFETY: the context and cipher are live; the engine is NULL or live; key and iv
        // hold the most any cipher reads (EVP_MAX_KEY_LENGTH, EVP_MAX_IV_LENGTH).
        unsafe {
            ffi::EVP_CipherInit_ex(
                self.0,
                cipher.as_ptr(),
                engine_ptr(e),
                key.as_ptr(),
                ivp,
                c_int::from(enc),
            ) == 1
        }
    }

    /// `EVP_CipherInit_SKEY(ctx, cipher, skey, iv, iv_len, enc, NULL)`.
    pub fn init_skey(
        self,
        cipher: &Cipher,
        skey: &Skey,
        iv: Option<&[u8; 16]>,
        iv_len: usize,
        enc: bool,
    ) -> bool {
        let ivp = iv.map_or(core::ptr::null(), |v| v.as_ptr());
        let iv_len = iv_len.min(16);
        // SAFETY: the context, cipher and key are live; iv is NULL or holds iv_len bytes.
        unsafe {
            ffi::EVP_CipherInit_SKEY(
                self.0,
                cipher.as_ptr(),
                skey.as_ptr(),
                ivp,
                iv_len,
                c_int::from(enc),
                core::ptr::null(),
            ) == 1
        }
    }
}

impl SkeyMgmt {
    /// `EVP_SKEYMGMT_get0_imp_settable_params`.
    pub fn imp_settable_params(&self) -> ParamsRef<'_> {
        // SAFETY: the manager is live; the table is owned by it.
        ParamsRef::from_raw(unsafe { ffi::EVP_SKEYMGMT_get0_imp_settable_params(self.as_ptr()) })
    }

    /// `EVP_SKEYMGMT_get0_name`.
    pub fn name(&self) -> Option<String> {
        // SAFETY: the manager is live; the name is owned by it and copied.
        string_at(unsafe { ffi::EVP_SKEYMGMT_get0_name(self.as_ptr()) })
    }
}

impl Skey {
    /// `EVP_SKEY_import(libctx, mgmt_name, propq, selection, params)`.
    pub fn import(
        libctx: Option<&LibCtx>,
        mgmt_name: &str,
        propq: Option<&str>,
        selection: c_int,
        params: &Params,
    ) -> Option<Self> {
        let n = cstring(mgmt_name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the strings are valid or NULL; params is terminated.
        Self::from_ptr(unsafe {
            ffi::EVP_SKEY_import(ctx, n.as_ptr(), ptr_of(&pq), selection, params.as_ptr())
        })
    }
}

// MACs and KDFs (`mac`, `kdf`).

crate::handle!(
    /// A fetched `EVP_MAC`.
    Mac, EVP_MAC, EVP_MAC_free
);
crate::handle!(
    /// An owned `EVP_MAC_CTX`.
    MacCtx, EVP_MAC_CTX, EVP_MAC_CTX_free
);
crate::handle!(
    /// A fetched `EVP_KDF`.
    Kdf, EVP_KDF, EVP_KDF_free
);
crate::handle!(
    /// An owned `EVP_KDF_CTX`.
    KdfCtx, EVP_KDF_CTX, EVP_KDF_CTX_free
);

impl Mac {
    /// `EVP_MAC_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe { ffi::EVP_MAC_fetch(ctx, n.as_ptr(), ptr_of(&pq)) })
    }

    /// `EVP_MAC_settable_ctx_params`.
    pub fn settable_ctx_params(&self) -> ParamsRef<'_> {
        // SAFETY: the MAC is live; the table is owned by it.
        ParamsRef::from_raw(unsafe { ffi::EVP_MAC_settable_ctx_params(self.as_ptr()) })
    }
}

impl MacCtx {
    /// `EVP_MAC_CTX_new(mac)`.
    pub fn new(mac: &Mac) -> Option<Self> {
        // SAFETY: the MAC is live; the context takes its own reference.
        Self::from_ptr(unsafe { ffi::EVP_MAC_CTX_new(mac.as_ptr()) })
    }

    /// `EVP_MAC_CTX_set_params`.
    pub fn set_params(&self, params: &impl crate::params::ParamArray) -> bool {
        // SAFETY: the context is live; params is terminated.
        unsafe { ffi::EVP_MAC_CTX_set_params(self.as_ptr(), params.param_ptr()) == 1 }
    }

    /// `EVP_MAC_init(ctx, NULL, 0, NULL)`.
    pub fn init(&self) -> bool {
        // SAFETY: the context is live; no key and no parameters.
        unsafe { ffi::EVP_MAC_init(self.as_ptr(), core::ptr::null(), 0, core::ptr::null()) == 1 }
    }

    /// `EVP_MAC_update`.
    pub fn update(&self, data: &[u8]) -> bool {
        // SAFETY: the context is live; data is valid for its length.
        unsafe { ffi::EVP_MAC_update(self.as_ptr(), data.as_ptr(), data.len()) == 1 }
    }

    /// `EVP_MAC_final(ctx, NULL, &len, 0)`: the output's length.
    pub fn final_len(&self) -> Option<usize> {
        let mut len = 0usize;
        // SAFETY: the context is live; NULL asks for the length only.
        (unsafe { ffi::EVP_MAC_final(self.as_ptr(), core::ptr::null_mut(), &mut len, 0) } == 1)
            .then_some(len)
    }

    /// `EVP_MAC_final(ctx, out, &len, out.len())`: the output's length.
    pub fn finish(&self, out: &mut [u8]) -> Option<usize> {
        let mut len = 0usize;
        // SAFETY: the context is live; out is writable for its length.
        (unsafe { ffi::EVP_MAC_final(self.as_ptr(), out.as_mut_ptr(), &mut len, out.len()) } == 1)
            .then_some(len)
    }
}

impl Kdf {
    /// `EVP_KDF_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe { ffi::EVP_KDF_fetch(ctx, n.as_ptr(), ptr_of(&pq)) })
    }

    /// `EVP_KDF_settable_ctx_params`.
    pub fn settable_ctx_params(&self) -> ParamsRef<'_> {
        // SAFETY: the KDF is live; the table is owned by it.
        ParamsRef::from_raw(unsafe { ffi::EVP_KDF_settable_ctx_params(self.as_ptr()) })
    }
}

impl KdfCtx {
    /// `EVP_KDF_CTX_new(kdf)`.
    pub fn new(kdf: &Kdf) -> Option<Self> {
        // SAFETY: the KDF is live; the context takes its own reference.
        Self::from_ptr(unsafe { ffi::EVP_KDF_CTX_new(kdf.as_ptr()) })
    }

    /// `EVP_KDF_CTX_set_params`.
    pub fn set_params(&self, params: &Params) -> bool {
        // SAFETY: the context is live; params is terminated.
        unsafe { ffi::EVP_KDF_CTX_set_params(self.as_ptr(), params.as_ptr()) == 1 }
    }

    /// `EVP_KDF_derive(ctx, out, len, NULL)`.
    pub fn derive(&self, out: &mut [u8]) -> bool {
        // SAFETY: the context is live; out is writable for its length.
        unsafe {
            ffi::EVP_KDF_derive(
                self.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                core::ptr::null(),
            ) == 1
        }
    }
}

// Plain digests (`passwd`).

impl Md {
    /// `EVP_md5()` (static).
    pub fn md5() -> Option<Self> {
        // SAFETY: no arguments; EVP_MD_free ignores the static result.
        Self::from_ptr(unsafe { ffi::EVP_md5() }.cast_mut())
    }

    /// `EVP_sha512()` (static).
    pub fn sha512() -> Option<Self> {
        // SAFETY: as in md5.
        Self::from_ptr(unsafe { ffi::EVP_sha512() }.cast_mut())
    }
}

impl MdCtxRef<'_> {
    /// `EVP_DigestUpdate`.
    pub fn update(self, data: &[u8]) -> bool {
        // SAFETY: the context is live; data is valid for its length.
        unsafe { ffi::EVP_DigestUpdate(self.0, data.as_ptr().cast(), data.len()) == 1 }
    }

    /// `EVP_DigestFinal_ex(ctx, buf, NULL)` into a buffer of `EVP_MAX_MD_SIZE`: the digest.
    pub fn finish(self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 64];
        let mut len: core::ffi::c_uint = 0;
        // SAFETY: the context is live; buf holds EVP_MAX_MD_SIZE bytes.
        if unsafe { ffi::EVP_DigestFinal_ex(self.0, buf.as_mut_ptr(), &mut len) } != 1 {
            return None;
        }
        buf.get(..usize::try_from(len).ok()?).map(<[u8]>::to_vec)
    }
}

impl Md {
    /// `EVP_sha1()` (static).
    pub fn sha1() -> Option<Self> {
        // SAFETY: as in md5.
        Self::from_ptr(unsafe { ffi::EVP_sha1() }.cast_mut())
    }

    /// `EVP_MD_get_size`.
    pub fn size(&self) -> c_int {
        // SAFETY: the digest is live.
        unsafe { ffi::EVP_MD_get_size(self.as_ptr()) }
    }
}

// ---- fork G6 (speed) ----

impl MacCtx {
    /// `EVP_MAC_CTX_dup(ctx)`.
    pub fn dup(&self) -> Option<Self> {
        // SAFETY: the context is live.
        Self::from_ptr(unsafe { ffi::EVP_MAC_CTX_dup(self.as_ptr()) })
    }

    /// `EVP_MAC_CTX_get_mac_size`.
    pub fn mac_size(&self) -> usize {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_MAC_CTX_get_mac_size(self.as_ptr()) }
    }
}

impl Md {
    /// `EVP_MD_xof`.
    pub fn is_xof(&self) -> bool {
        // SAFETY: the digest is live.
        unsafe { ffi::EVP_MD_xof(self.as_ptr()) == 1 }
    }

    /// `EVP_Digest(data, len, out, NULL, md, NULL)`.
    pub fn digest(
        &self,
        data: &[u8],
        out: &mut [u8; crate::abi::EVP_MAX_MD_SIZE as usize],
    ) -> bool {
        // SAFETY: data is valid for its length; out holds EVP_MAX_MD_SIZE bytes, the most any
        // digest writes; the digest is live.
        unsafe {
            ffi::EVP_Digest(
                data.as_ptr().cast(),
                data.len(),
                out.as_mut_ptr(),
                core::ptr::null_mut(),
                self.as_ptr(),
                core::ptr::null_mut(),
            ) == 1
        }
    }
}

crate::handle!(
    /// A cipher context.
    CipherCtx, EVP_CIPHER_CTX, EVP_CIPHER_CTX_free
);

/// The most a cipher update writes beyond its input (`EVP_MAX_BLOCK_LENGTH`).
const MAX_BLOCK: usize = crate::abi::EVP_MAX_BLOCK_LENGTH as usize;

impl CipherCtx {
    /// `EVP_CIPHER_CTX_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::EVP_CIPHER_CTX_new() })
    }

    /// `EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, enc)`; `None` leaves each unchanged.
    /// The key and IV must be at least as long as the cipher's.
    pub fn init(
        &self,
        cipher: Option<&Cipher>,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
        enc: core::ffi::c_int,
    ) -> bool {
        let ptr = |b: Option<&[u8]>| b.map_or(core::ptr::null(), <[u8]>::as_ptr);
        let need = |b: Option<&[u8]>, n: core::ffi::c_int| {
            b.is_none_or(|b| b.len() >= usize::try_from(n).unwrap_or(0))
        };
        // The lengths the call will read: the cipher's when one is given, else the
        // context's (which a ctrl may have changed).
        let (kl, il) = match cipher {
            Some(c) => (
                c.key_length(),
                // SAFETY: the cipher is live.
                unsafe { ffi::EVP_CIPHER_get_iv_length(c.as_ptr()) },
            ),
            None => (
                self.key_length(),
                // SAFETY: the context is live.
                unsafe { ffi::EVP_CIPHER_CTX_get_iv_length(self.as_ptr()) },
            ),
        };
        if !need(key, kl) || !need(iv, il) {
            return false;
        }
        // SAFETY: the context is live; the cipher is NULL or live; key and IV are NULL or
        // hold what the cipher reads (checked above).
        unsafe {
            ffi::EVP_CipherInit_ex(
                self.as_ptr(),
                cipher.map_or(core::ptr::null(), |c| c.as_ptr().cast_const()),
                core::ptr::null_mut(),
                ptr(key),
                ptr(iv),
                enc,
            ) == 1
        }
    }

    /// `EVP_CIPHER_CTX_set_key_length`.
    pub fn set_key_length(&self, len: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_CIPHER_CTX_set_key_length(self.as_ptr(), len) }
    }

    /// `EVP_CIPHER_CTX_get_key_length`.
    pub fn key_length(&self) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_CIPHER_CTX_get_key_length(self.as_ptr()) }
    }

    /// `EVP_CIPHER_CTX_set_padding`.
    pub fn set_padding(&self, pad: bool) {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_CIPHER_CTX_set_padding(self.as_ptr(), core::ffi::c_int::from(pad)) };
    }

    /// `EVP_CIPHER_CTX_rand_key` into `key` (at least the key length).
    pub fn rand_key(&self, key: &mut [u8]) -> core::ffi::c_int {
        if usize::try_from(self.key_length()).is_ok_and(|n| key.len() < n) {
            return 0;
        }
        // SAFETY: the context is live; key holds its key length.
        unsafe { ffi::EVP_CIPHER_CTX_rand_key(self.as_ptr(), key.as_mut_ptr()) }
    }

    /// `EVP_CIPHER_CTX_get_block_size`.
    pub fn block_size(&self) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_CIPHER_CTX_get_block_size(self.as_ptr()) }
    }

    /// `EVP_CIPHER_get0_name(EVP_CIPHER_CTX_get0_cipher(ctx))`: `None` without a cipher.
    pub fn cipher_name(&self) -> Option<Option<String>> {
        // SAFETY: the context is live.
        let c = unsafe { ffi::EVP_CIPHER_CTX_get0_cipher(self.as_ptr()) };
        if c.is_null() {
            return None;
        }
        // SAFETY: c is live; its name is owned by it.
        Some(string_at(unsafe { ffi::EVP_CIPHER_get0_name(c) }))
    }

    /// `EVP_CIPHER_CTX_ctrl(ctx, type, arg, NULL)`.
    pub fn ctrl(&self, kind: core::ffi::c_int, arg: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live; commands given NULL read and write nothing.
        unsafe { ffi::EVP_CIPHER_CTX_ctrl(self.as_ptr(), kind, arg, core::ptr::null_mut()) }
    }

    /// `EVP_CIPHER_CTX_ctrl(ctx, type, buf.len(), buf)`: the commands that read or write `arg`
    /// bytes at the pointer (tags, MAC keys, TLS AAD).
    pub fn ctrl_buf(&self, kind: core::ffi::c_int, buf: &mut [u8]) -> core::ffi::c_int {
        let Ok(n) = core::ffi::c_int::try_from(buf.len()) else {
            return 0;
        };
        // SAFETY: the context is live; buf holds the n bytes such a command uses.
        unsafe { ffi::EVP_CIPHER_CTX_ctrl(self.as_ptr(), kind, n, buf.as_mut_ptr().cast()) }
    }

    /// `EVP_CTRL_TLS1_1_MULTIBLOCK_AAD` with `aad` (13 bytes) and the payload length: the
    /// packed length, or <= 0.
    pub fn multiblock_aad(
        &self,
        aad: &mut [u8; 13],
        len: usize,
        interleave: u32,
    ) -> core::ffi::c_int {
        let mut p = crate::abi::EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM {
            out: core::ptr::null_mut(),
            inp: aad.as_ptr(),
            len,
            interleave,
        };
        let n = core::ffi::c_int::try_from(size_of_val(&p)).unwrap_or(0);
        // SAFETY: the context is live; p is the parameter block the command reads (its
        // input is the 13-byte AAD).
        unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                self.as_ptr(),
                crate::abi::EVP_CTRL_TLS1_1_MULTIBLOCK_AAD,
                n,
                (&raw mut p).cast(),
            )
        }
    }

    /// `EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT` of `inp[..len]` into `out` (which must hold
    /// `len + 1024` bytes, as upstream allocates).
    pub fn multiblock_encrypt(
        &self,
        out: &mut [u8],
        inp: &[u8],
        len: usize,
        interleave: u32,
    ) -> core::ffi::c_int {
        if inp.len() < len || out.len() < len.saturating_add(1024) {
            return 0;
        }
        let mut p = crate::abi::EVP_CTRL_TLS1_1_MULTIBLOCK_PARAM {
            out: out.as_mut_ptr(),
            inp: inp.as_ptr(),
            len,
            interleave,
        };
        let n = core::ffi::c_int::try_from(size_of_val(&p)).unwrap_or(0);
        // SAFETY: the context is live; the input and output buffers are as large as the
        // command uses (checked above).
        unsafe {
            ffi::EVP_CIPHER_CTX_ctrl(
                self.as_ptr(),
                crate::abi::EVP_CTRL_TLS1_1_MULTIBLOCK_ENCRYPT,
                n,
                (&raw mut p).cast(),
            )
        }
    }

    /// `EVP_Cipher(ctx, buf, buf, len)`: in place.
    pub fn cipher_in_place(&self, buf: &mut [u8], len: usize) -> core::ffi::c_int {
        let Ok(n) = core::ffi::c_uint::try_from(len) else {
            return 0;
        };
        if buf.len() < len.saturating_add(MAX_BLOCK) {
            return 0;
        }
        let p = buf.as_mut_ptr();
        // SAFETY: the context is live; buf holds len bytes and room for a block more.
        unsafe { ffi::EVP_Cipher(self.as_ptr(), p, p, n) }
    }

    /// `EVP_Cipher(ctx, out, inp, len)`.
    pub fn cipher(&self, out: &mut [u8], inp: &[u8], len: usize) -> core::ffi::c_int {
        let Ok(n) = core::ffi::c_uint::try_from(len) else {
            return 0;
        };
        if inp.len() < len || out.len() < len.saturating_add(MAX_BLOCK) {
            return 0;
        }
        // SAFETY: the context is live; the buffers hold what the call reads and writes.
        unsafe { ffi::EVP_Cipher(self.as_ptr(), out.as_mut_ptr(), inp.as_ptr(), n) }
    }

    fn update_raw(
        &self,
        enc: bool,
        out: *mut u8,
        outl: &mut core::ffi::c_int,
        inp: *const u8,
        inl: core::ffi::c_int,
    ) -> core::ffi::c_int {
        if enc {
            // SAFETY: the callers pass buffers the call may use (see each).
            unsafe { ffi::EVP_EncryptUpdate(self.as_ptr(), out, outl, inp, inl) }
        } else {
            // SAFETY: as above.
            unsafe { ffi::EVP_DecryptUpdate(self.as_ptr(), out, outl, inp, inl) }
        }
    }

    /// `EVP_EncryptUpdate`/`EVP_DecryptUpdate(ctx, buf, &outl, buf, len)`: in place; `buf`
    /// must hold `len` bytes and a block more.
    pub fn update_in_place(
        &self,
        enc: bool,
        buf: &mut [u8],
        len: usize,
    ) -> (core::ffi::c_int, core::ffi::c_int) {
        let mut outl = 0;
        let Ok(n) = core::ffi::c_int::try_from(len) else {
            return (0, outl);
        };
        if buf.len() < len.saturating_add(MAX_BLOCK) {
            return (0, outl);
        }
        let p = buf.as_mut_ptr();
        // Writes at most len plus a block.
        (self.update_raw(enc, p, &mut outl, p, n), outl)
    }

    /// `EVP_EncryptUpdate`/`EVP_DecryptUpdate(ctx, out, &outl, inp, len)`.
    pub fn update(&self, enc: bool, out: &mut [u8], inp: &[u8], len: usize) -> core::ffi::c_int {
        let mut outl = 0;
        let Ok(n) = core::ffi::c_int::try_from(len) else {
            return 0;
        };
        if inp.len() < len || out.len() < len.saturating_add(MAX_BLOCK) {
            return 0;
        }
        self.update_raw(enc, out.as_mut_ptr(), &mut outl, inp.as_ptr(), n)
    }

    /// `EVP_EncryptUpdate`/`EVP_DecryptUpdate(ctx, NULL, &outl, aad, len)`: additional data.
    pub fn update_aad(&self, enc: bool, aad: &[u8]) -> core::ffi::c_int {
        let mut outl = 0;
        let Ok(n) = core::ffi::c_int::try_from(aad.len()) else {
            return 0;
        };
        self.update_raw(enc, core::ptr::null_mut(), &mut outl, aad.as_ptr(), n)
    }

    /// `EVP_EncryptUpdate`/`EVP_DecryptUpdate(ctx, NULL, &outl, NULL, len)`: the total
    /// length (CCM).
    pub fn update_length(&self, enc: bool, len: core::ffi::c_int) -> core::ffi::c_int {
        let mut outl = 0;
        self.update_raw(
            enc,
            core::ptr::null_mut(),
            &mut outl,
            core::ptr::null(),
            len,
        )
    }

    /// `EVP_EncryptFinal_ex`/`EVP_DecryptFinal_ex(ctx, out, &outl)`; `out` holds a block.
    pub fn finish(&self, enc: bool, out: &mut [u8]) -> core::ffi::c_int {
        if out.len() < MAX_BLOCK {
            return 0;
        }
        let mut outl = 0;
        if enc {
            // SAFETY: the context is live; out holds a block, the most a final call writes.
            unsafe { ffi::EVP_EncryptFinal_ex(self.as_ptr(), out.as_mut_ptr(), &mut outl) }
        } else {
            // SAFETY: as above.
            unsafe { ffi::EVP_DecryptFinal_ex(self.as_ptr(), out.as_mut_ptr(), &mut outl) }
        }
    }
}

/// A key-encapsulation or signature algorithm seen by [`kems`] or [`signatures`]: its name
/// and its provider's.
pub struct Provided {
    pub name: String,
    pub provider: String,
}

struct Collect {
    out: Vec<Provided>,
    signature: bool,
}

unsafe extern "C" fn collect_kem(kem: *mut crate::abi::EVP_KEM, arg: *mut core::ffi::c_void) {
    // SAFETY: arg is the Collect that kems passed, live for the walk; kem is live for the
    // callback, and its strings are copied at once.
    let c = unsafe { &mut *arg.cast::<Collect>() };
    // SAFETY: as above.
    let name = string_at(unsafe { ffi::EVP_KEM_get0_name(kem) }).unwrap_or_default();
    // SAFETY: as above.
    let prov = unsafe { ffi::EVP_KEM_get0_provider(kem) };
    // SAFETY: the provider of a live algorithm is live.
    let provider = string_at(unsafe { ffi::OSSL_PROVIDER_get0_name(prov) }).unwrap_or_default();
    c.out.push(Provided { name, provider });
}

unsafe extern "C" fn collect_signature(
    sig: *mut crate::abi::EVP_SIGNATURE,
    arg: *mut core::ffi::c_void,
) {
    // SAFETY: as in collect_kem.
    let c = unsafe { &mut *arg.cast::<Collect>() };
    // SAFETY: as above.
    let name = string_at(unsafe { ffi::EVP_SIGNATURE_get0_name(sig) }).unwrap_or_default();
    // SAFETY: as above.
    let prov = unsafe { ffi::EVP_SIGNATURE_get0_provider(sig) };
    // SAFETY: as above.
    let provider = string_at(unsafe { ffi::OSSL_PROVIDER_get0_name(prov) }).unwrap_or_default();
    c.out.push(Provided { name, provider });
    debug_assert!(c.signature);
}

/// `EVP_KEM_do_all_provided(libctx, ...)`: each KEM, in the order the library gives them.
pub fn kems(libctx: Option<&LibCtx>) -> Vec<Provided> {
    let mut c = Collect {
        out: Vec::new(),
        signature: false,
    };
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    // SAFETY: ctx is NULL or live; the callback gets &mut c back, which outlives the call.
    unsafe { ffi::EVP_KEM_do_all_provided(ctx, Some(collect_kem), (&raw mut c).cast()) };
    c.out
}

/// `EVP_SIGNATURE_do_all_provided(libctx, ...)`: each signature algorithm, in the library's
/// order.
pub fn signatures(libctx: Option<&LibCtx>) -> Vec<Provided> {
    let mut c = Collect {
        out: Vec::new(),
        signature: true,
    };
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    // SAFETY: as above.
    unsafe {
        ffi::EVP_SIGNATURE_do_all_provided(ctx, Some(collect_signature), (&raw mut c).cast())
    };
    c.out
}

/// Whether `EVP_KEM_fetch(libctx, name, propq)` finds one (`is_kem_fetchable`).
pub fn kem_fetchable(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> bool {
    let (Some(n), Some(pq)) = (cstring(name), propq_c(propq)) else {
        return false;
    };
    let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
    // SAFETY: ctx is NULL or live; the strings are valid or NULL; the result is freed here.
    let k = unsafe {
        ffi::EVP_KEM_fetch(
            ctx,
            n.as_ptr(),
            pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
        )
    };
    // SAFETY: k is NULL or a reference owned here.
    unsafe { ffi::EVP_KEM_free(k) };
    !k.is_null()
}

crate::handle!(
    /// A fetched signature algorithm.
    Signature, EVP_SIGNATURE, EVP_SIGNATURE_free
);

impl Signature {
    /// `EVP_SIGNATURE_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: as in Cipher::fetch.
        Self::from_ptr(unsafe {
            ffi::EVP_SIGNATURE_fetch(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }
}
