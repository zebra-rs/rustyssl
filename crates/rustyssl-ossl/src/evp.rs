//! EVP lookups.

use crate::ffi;
use crate::util::{cstring, string_at};

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

crate::handle!(
    /// A fetched MAC algorithm.
    Mac, EVP_MAC, EVP_MAC_free
);
crate::handle!(
    /// A MAC context.
    MacCtx, EVP_MAC_CTX, EVP_MAC_CTX_free
);

impl Mac {
    /// `EVP_MAC_fetch(libctx, name, propq)`.
    pub fn fetch(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let pq = propq_c(propq)?;
        let ctx = libctx.map_or(core::ptr::null_mut(), LibCtx::as_ptr);
        // SAFETY: as in Cipher::fetch.
        Self::from_ptr(unsafe {
            ffi::EVP_MAC_fetch(
                ctx,
                n.as_ptr(),
                pq.as_ref().map_or(core::ptr::null(), |p| p.as_ptr()),
            )
        })
    }

    /// `EVP_MAC_settable_ctx_params`.
    pub fn settable_ctx_params(&self) -> crate::params::Defs<'_> {
        // SAFETY: the MAC is live; the list (or NULL) is owned by it.
        crate::params::Defs(
            unsafe { ffi::EVP_MAC_settable_ctx_params(self.as_ptr()) },
            core::marker::PhantomData,
        )
    }
}

impl MacCtx {
    /// `EVP_MAC_CTX_new(mac)`.
    pub fn new(mac: &Mac) -> Option<Self> {
        // SAFETY: the MAC is live; the context takes its own reference.
        Self::from_ptr(unsafe { ffi::EVP_MAC_CTX_new(mac.as_ptr()) })
    }

    /// `EVP_MAC_CTX_set_params(ctx, params)`.
    pub fn set_params(&self, params: &crate::params::Params) -> bool {
        // SAFETY: the context is live; the list is END-terminated and live.
        unsafe { ffi::EVP_MAC_CTX_set_params(self.as_ptr(), params.as_ptr()) == 1 }
    }

    /// `EVP_MAC_CTX_dup(ctx)`.
    pub fn dup(&self) -> Option<Self> {
        // SAFETY: the context is live.
        Self::from_ptr(unsafe { ffi::EVP_MAC_CTX_dup(self.as_ptr()) })
    }

    /// `EVP_MAC_init(ctx, NULL, 0, NULL)`: with the key already set.
    pub fn init(&self) -> bool {
        // SAFETY: the context is live; no key and no parameters.
        unsafe { ffi::EVP_MAC_init(self.as_ptr(), core::ptr::null(), 0, core::ptr::null()) == 1 }
    }

    /// `EVP_MAC_update(ctx, data, len)`.
    pub fn update(&self, data: &[u8]) -> bool {
        // SAFETY: the context is live; data is valid for its length.
        unsafe { ffi::EVP_MAC_update(self.as_ptr(), data.as_ptr(), data.len()) == 1 }
    }

    /// `EVP_MAC_final(ctx, out, &outl, out.len())`: the length written, on success.
    pub fn finish(&self, out: &mut [u8]) -> Option<usize> {
        let mut outl = 0usize;
        // SAFETY: the context is live; out is writable for its length.
        let ok = unsafe {
            ffi::EVP_MAC_final(self.as_ptr(), out.as_mut_ptr(), &mut outl, out.len()) == 1
        };
        ok.then_some(outl.min(out.len()))
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

impl Cipher {
    /// `EVP_CIPHER_get0_name`.
    pub fn name(&self) -> Option<String> {
        // SAFETY: the cipher is live; the name is owned by it.
        string_at(unsafe { ffi::EVP_CIPHER_get0_name(self.as_ptr()) })
    }

    /// `EVP_CIPHER_get_key_length`.
    pub fn key_length(&self) -> core::ffi::c_int {
        // SAFETY: the cipher is live.
        unsafe { ffi::EVP_CIPHER_get_key_length(self.as_ptr()) }
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
