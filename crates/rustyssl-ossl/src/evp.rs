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

crate::handle!(
    /// An owned `EVP_SKEYMGMT`.
    SkeyMgmt, EVP_SKEYMGMT, EVP_SKEYMGMT_free
);
crate::handle!(
    /// An owned `EVP_SKEY`.
    Skey, EVP_SKEY, EVP_SKEY_free
);

impl SkeyMgmt {
    /// `EVP_SKEYMGMT_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: ctx is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe { ffi::EVP_SKEYMGMT_fetch(ctx, n.as_ptr(), ptr_of(&pq)) })
    }

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
    pub fn set_params(&self, params: &Params) -> bool {
        // SAFETY: the context is live; params is terminated.
        unsafe { ffi::EVP_MAC_CTX_set_params(self.as_ptr(), params.as_ptr()) == 1 }
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
