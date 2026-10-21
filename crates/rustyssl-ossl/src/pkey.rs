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

// ---- Keys, their contexts, and the key commands' calls (Phase 11, fork G2) ----

use core::ffi::{CStr, c_int};

use crate::abi::EVP_PKEY_ASN1_METHOD;
use crate::bio::Bio;
use crate::bn::Bn;
use crate::engine::Engine;
use crate::evp::Cipher;
use crate::params::{ParamList, ParamsRef};

fn engine_ptr(e: Option<&Engine>) -> *mut crate::abi::ENGINE {
    e.map_or(core::ptr::null_mut(), Engine::as_ptr)
}

fn libctx_ptr(l: Option<&LibCtx>) -> *mut crate::abi::OSSL_LIB_CTX {
    l.map_or(core::ptr::null_mut(), LibCtx::as_ptr)
}

/// An optional C string: `Err` if the text holds a NUL.
fn opt_cstring(s: Option<&str>) -> Result<Option<std::ffi::CString>, ()> {
    match s {
        Some(s) => cstring(s).map(Some).ok_or(()),
        None => Ok(None),
    }
}

fn opt_ptr(s: &Option<std::ffi::CString>) -> *const c_char {
    s.as_ref().map_or(core::ptr::null(), |c| c.as_ptr())
}

/// `EVP_PKEY_get_bits(pkey)`, NULL when `None` (which the library reports).
pub fn bits_of(pkey: Option<&Pkey>) -> c_int {
    let k = pkey.map_or(core::ptr::null(), |k| k.as_ptr().cast_const());
    // SAFETY: k is NULL or a live key.
    unsafe { ffi::EVP_PKEY_get_bits(k) }
}

impl Pkey {
    /// `EVP_PKEY_new_raw_private_key(kind, e, key, len)`.
    pub fn new_raw_private_key(kind: c_int, e: Option<&Engine>, key: &[u8]) -> Option<Self> {
        // SAFETY: the engine is NULL or live; key is valid for its length.
        Self::from_ptr(unsafe {
            ffi::EVP_PKEY_new_raw_private_key(kind, engine_ptr(e), key.as_ptr(), key.len())
        })
    }

    /// `EVP_PKEY_get_bits`.
    pub fn bits(&self) -> c_int {
        // SAFETY: the key is live.
        unsafe { ffi::EVP_PKEY_get_bits(self.as_ptr()) }
    }

    /// `EVP_PKEY_get_size`.
    pub fn size(&self) -> c_int {
        // SAFETY: the key is live.
        unsafe { ffi::EVP_PKEY_get_size(self.as_ptr()) }
    }

    /// `EVP_PKEY_get0_type_name`.
    pub fn type_name(&self) -> Option<String> {
        // SAFETY: the key is live; the name is static or the key's, and copied.
        string_at(unsafe { ffi::EVP_PKEY_get0_type_name(self.as_ptr()) })
    }

    /// `EVP_PKEY_get_bn_param(pkey, name, &bn)`: the number when it succeeded.
    pub fn bn_param(&self, name: &CStr) -> Option<Bn> {
        let mut bn: *mut crate::abi::BIGNUM = core::ptr::null_mut();
        // SAFETY: the key is live; name is a valid C string; bn is a valid out-pointer whose
        // result is ours.
        let r = unsafe { ffi::EVP_PKEY_get_bn_param(self.as_ptr(), name.as_ptr(), &mut bn) };
        let bn = Bn::from_ptr(bn);
        if r == 1 { bn } else { None }
    }

    /// `EVP_PKEY_set_utf8_string_param`.
    pub fn set_utf8_string_param(&self, key: &CStr, value: &str) -> bool {
        let Some(v) = cstring(value) else {
            return false;
        };
        // SAFETY: the key is live; both strings are valid.
        unsafe { ffi::EVP_PKEY_set_utf8_string_param(self.as_ptr(), key.as_ptr(), v.as_ptr()) == 1 }
    }

    /// `EVP_PKEY_set_int_param`.
    pub fn set_int_param(&self, key: &CStr, value: c_int) -> bool {
        // SAFETY: the key is live; key is a valid C string.
        unsafe { ffi::EVP_PKEY_set_int_param(self.as_ptr(), key.as_ptr(), value) == 1 }
    }

    /// `EVP_PKEY_set_octet_string_param` (an empty value is passed as NULL, 0).
    pub fn set_octet_string_param(&self, key: &CStr, value: &[u8]) -> bool {
        let p = if value.is_empty() {
            core::ptr::null()
        } else {
            value.as_ptr()
        };
        // SAFETY: the key is live; p is NULL or valid for the length.
        unsafe {
            ffi::EVP_PKEY_set_octet_string_param(self.as_ptr(), key.as_ptr(), p, value.len()) == 1
        }
    }

    /// `EVP_PKEY_set_params`: what it returns.
    pub fn set_params(&self, params: &mut ParamList) -> c_int {
        // SAFETY: the key is live; params is a valid, ended array.
        unsafe { ffi::EVP_PKEY_set_params(self.as_ptr(), params.as_mut_ptr()) }
    }

    /// `EVP_PKEY_print_public(out, pkey, indent, NULL)`.
    pub fn print_public(&self, out: &Bio, indent: c_int) -> c_int {
        // SAFETY: both are live; a NULL print context is allowed.
        unsafe {
            ffi::EVP_PKEY_print_public(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `EVP_PKEY_print_private(out, pkey, indent, NULL)`.
    pub fn print_private(&self, out: &Bio, indent: c_int) -> c_int {
        // SAFETY: as above.
        unsafe {
            ffi::EVP_PKEY_print_private(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `EVP_PKEY_print_params(out, pkey, indent, NULL)`.
    pub fn print_params(&self, out: &Bio, indent: c_int) -> c_int {
        // SAFETY: as above.
        unsafe {
            ffi::EVP_PKEY_print_params(out.as_ptr(), self.as_ptr(), indent, core::ptr::null_mut())
        }
    }

    /// `PEM_write_bio_PrivateKey(out, pkey, cipher, NULL, 0, NULL, pass)`, or its
    /// `_traditional` form: the password (if any) goes as the default callback's data.
    pub fn write_pem_private(
        &self,
        out: &Bio,
        cipher: Option<&Cipher>,
        pass: Option<&str>,
        traditional: bool,
    ) -> c_int {
        let Ok(pass) = opt_cstring(pass) else {
            return 0;
        };
        let c = cipher.map_or(core::ptr::null(), |c| c.as_ptr().cast_const());
        let u = opt_ptr(&pass).cast_mut().cast();
        let (b, k) = (out.as_ptr(), self.as_ptr());
        let null = core::ptr::null();
        if traditional {
            // SAFETY: the BIO and key are live; c is NULL or a live cipher; u is NULL or a C
            // string, which the default callback reads as the password.
            unsafe { ffi::PEM_write_bio_PrivateKey_traditional(b, k, c, null, 0, None, u) }
        } else {
            // SAFETY: as above.
            unsafe { ffi::PEM_write_bio_PrivateKey(b, k, c, null, 0, None, u) }
        }
    }

    /// `PEM_write_bio_PUBKEY`.
    pub fn write_pem_pubkey(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_PUBKEY(out.as_ptr(), self.as_ptr()) }
    }

    /// `PEM_write_bio_Parameters`.
    pub fn write_pem_params(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_Parameters(out.as_ptr(), self.as_ptr()) }
    }

    /// `i2d_PrivateKey_bio`.
    pub fn write_der_private(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2d_PrivateKey_bio(out.as_ptr(), self.as_ptr()) }
    }

    /// `i2d_PUBKEY_bio`.
    pub fn write_der_pubkey(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2d_PUBKEY_bio(out.as_ptr(), self.as_ptr()) }
    }

    /// `i2d_PKCS8PrivateKey_bio(out, pkey, NULL, NULL, 0, NULL, NULL)`.
    pub fn write_der_pkcs8(&self, out: &Bio) -> c_int {
        // SAFETY: both are live; no encryption.
        unsafe {
            ffi::i2d_PKCS8PrivateKey_bio(
                out.as_ptr(),
                self.as_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                0,
                None,
                core::ptr::null_mut(),
            )
        }
    }

    /// `i2d_KeyParams_bio`.
    pub fn write_der_params(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2d_KeyParams_bio(out.as_ptr(), self.as_ptr()) }
    }

    /// `i2b_PublicKey_bio` (MSBLOB).
    pub fn write_msblob_public(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2b_PublicKey_bio(out.as_ptr(), self.as_ptr()) }
    }

    /// Whether `EVP_PKEY_get0_RSA` finds an `RSA`.
    pub fn has_legacy_rsa(&self) -> bool {
        // SAFETY: the key is live; the result is only tested.
        !unsafe { ffi::EVP_PKEY_get0_RSA(self.as_ptr()) }.is_null()
    }

    /// The legacy RSA public key writers of `rsa`'s `try_legacy_encoding`: `None` when the
    /// key has no `RSA` (`EVP_PKEY_get0_RSA`), else whether writing succeeded. `der` picks
    /// `i2d_*_bio` over `PEM_write_bio_*`, `pkcs1` `RSAPublicKey` over `RSA_PUBKEY`.
    pub fn write_legacy_rsa_public(&self, out: &Bio, der: bool, pkcs1: bool) -> Option<bool> {
        // SAFETY: the key is live; the RSA (if any) belongs to it.
        let rsa = unsafe { ffi::EVP_PKEY_get0_RSA(self.as_ptr()) };
        if rsa.is_null() {
            return None;
        }
        let b = out.as_ptr();
        // SAFETY (each call): the BIO is live; rsa is live as long as the key.
        let r = match (der, pkcs1) {
            // SAFETY: as above.
            (true, true) => unsafe { ffi::i2d_RSAPublicKey_bio(b, rsa) },
            // SAFETY: as above.
            (true, false) => unsafe { ffi::i2d_RSA_PUBKEY_bio(b, rsa) },
            // SAFETY: as above.
            (false, true) => unsafe { ffi::PEM_write_bio_RSAPublicKey(b, rsa) },
            // SAFETY: as above.
            (false, false) => unsafe { ffi::PEM_write_bio_RSA_PUBKEY(b, rsa) },
        };
        Some(r > 0)
    }

    /// `PEM_read_bio_Parameters_ex(in, NULL, libctx, propq)`.
    pub fn read_pem_params(
        input: &Bio,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let q = opt_cstring(propq).ok()?;
        // SAFETY: the BIO is live; libctx is NULL or live; q is NULL or valid.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_Parameters_ex(
                input.as_ptr(),
                core::ptr::null_mut(),
                libctx_ptr(libctx),
                opt_ptr(&q),
            )
        })
    }
}

crate::handle!(
    /// An owned `EVP_PKEY_CTX`.
    PkeyCtx, EVP_PKEY_CTX, EVP_PKEY_CTX_free
);

/// The apps' `progress_cb` (`apps/lib/s_cb.c`): one of `.+*\n` (or `?`) for the key
/// generation's progress, to the context's app-data `BIO`.
extern "C" fn progress_cb(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: the library calls this with the live context it is generating with.
    let b = unsafe { ffi::EVP_PKEY_CTX_get_app_data(ctx) }.cast::<crate::abi::BIO>();
    // SAFETY: as above.
    let p = unsafe { ffi::EVP_PKEY_CTX_get_keygen_info(ctx, 0) };
    let c: u8 = match p {
        0 => b'.',
        1 => b'+',
        2 => b'*',
        3 => b'\n',
        4 => 0, // the terminating NUL of `symbols`, as upstream's bounds check allows
        _ => b'?',
    };
    if !b.is_null() {
        // SAFETY: the app data is the program's standard error BIO, live for the program
        // (set by set_app_bio); c is one readable byte.
        unsafe { ffi::BIO_write(b, (&raw const c).cast(), 1) };
        // SAFETY: as above; the flush command takes no pointer.
        unsafe { ffi::BIO_ctrl(b, crate::abi::BIO_CTRL_FLUSH, 0, core::ptr::null_mut()) };
    }
    1
}

impl PkeyCtx {
    /// `EVP_PKEY_CTX_new(pkey, e)`.
    pub fn new(pkey: &Pkey, e: Option<&Engine>) -> Option<Self> {
        // SAFETY: the key is live (the context takes its own reference); e is NULL or live.
        Self::from_ptr(unsafe { ffi::EVP_PKEY_CTX_new(pkey.as_ptr(), engine_ptr(e)) })
    }

    /// `EVP_PKEY_CTX_new_id(id, e)`.
    pub fn new_id(id: c_int, e: Option<&Engine>) -> Option<Self> {
        // SAFETY: e is NULL or live.
        Self::from_ptr(unsafe { ffi::EVP_PKEY_CTX_new_id(id, engine_ptr(e)) })
    }

    /// `EVP_PKEY_CTX_new_from_name(libctx, name, propq)`.
    pub fn from_name(libctx: Option<&LibCtx>, name: &str, propq: Option<&str>) -> Option<Self> {
        let n = cstring(name)?;
        let q = opt_cstring(propq).ok()?;
        // SAFETY: libctx is NULL or live; the strings are valid or NULL.
        Self::from_ptr(unsafe {
            ffi::EVP_PKEY_CTX_new_from_name(libctx_ptr(libctx), n.as_ptr(), opt_ptr(&q))
        })
    }

    /// `EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)`; a `None` key passes NULL.
    pub fn from_pkey(
        libctx: Option<&LibCtx>,
        pkey: Option<&Pkey>,
        propq: Option<&str>,
    ) -> Option<Self> {
        let q = opt_cstring(propq).ok()?;
        let k = pkey.map_or(core::ptr::null_mut(), Pkey::as_ptr);
        // SAFETY: libctx is NULL or live; k is NULL (which the function reports) or live.
        Self::from_ptr(unsafe {
            ffi::EVP_PKEY_CTX_new_from_pkey(libctx_ptr(libctx), k, opt_ptr(&q))
        })
    }

    /// The context, borrowed (for `ctrl_str`).
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

    /// `EVP_PKEY_keygen`: what it returns, and the key.
    pub fn keygen(&self) -> (c_int, Option<Pkey>) {
        let mut k: *mut EVP_PKEY = core::ptr::null_mut();
        // SAFETY: the context is live; k is a valid out-pointer whose result is ours.
        let r = unsafe { ffi::EVP_PKEY_keygen(self.as_ptr(), &mut k) };
        (r, Pkey::from_raw(k))
    }

    /// `EVP_PKEY_paramgen`.
    pub fn paramgen(&self) -> (c_int, Option<Pkey>) {
        let mut k: *mut EVP_PKEY = core::ptr::null_mut();
        // SAFETY: as above.
        let r = unsafe { ffi::EVP_PKEY_paramgen(self.as_ptr(), &mut k) };
        (r, Pkey::from_raw(k))
    }

    /// `EVP_PKEY_fromdata_init`.
    pub fn fromdata_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_fromdata_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_fromdata(ctx, &pkey, selection, params)`.
    pub fn fromdata(&self, selection: c_int, params: &mut ParamList) -> (c_int, Option<Pkey>) {
        let mut k: *mut EVP_PKEY = core::ptr::null_mut();
        // SAFETY: the context is live; params is an ended array; k is a valid out-pointer.
        let r = unsafe {
            ffi::EVP_PKEY_fromdata(self.as_ptr(), &mut k, selection, params.as_mut_ptr())
        };
        (r, Pkey::from_raw(k))
    }

    /// `EVP_PKEY_fromdata` with an array a builder made.
    pub fn fromdata_built(
        &self,
        selection: c_int,
        params: &mut crate::params::BuiltParams,
    ) -> (c_int, Option<Pkey>) {
        let mut k: *mut EVP_PKEY = core::ptr::null_mut();
        // SAFETY: the context is live; params is an ended array; k is a valid out-pointer.
        let r = unsafe {
            ffi::EVP_PKEY_fromdata(self.as_ptr(), &mut k, selection, params.as_mut_ptr())
        };
        (r, Pkey::from_raw(k))
    }

    /// `EVP_PKEY_CTX_set_app_data(ctx, bio)`: the `BIO` [`PkeyCtx::set_progress_cb`]'s
    /// callback writes to; it must live as long as the program (standard error).
    pub fn set_app_bio(&self, bio: &'static Bio) {
        // SAFETY: the context is live; the BIO outlives it.
        unsafe { ffi::EVP_PKEY_CTX_set_app_data(self.as_ptr(), bio.as_ptr().cast()) };
    }

    /// `EVP_PKEY_CTX_set_cb(ctx, progress_cb)`.
    pub fn set_progress_cb(&self) {
        // SAFETY: the context is live; the callback is a plain function that never unwinds.
        unsafe { ffi::EVP_PKEY_CTX_set_cb(self.as_ptr(), Some(progress_cb)) };
    }

    /// `EVP_PKEY_CTX_set_rsa_keygen_bits`.
    pub fn set_rsa_keygen_bits(&self, bits: c_int) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_rsa_keygen_bits(self.as_ptr(), bits) }
    }

    /// `EVP_PKEY_CTX_set1_rsa_keygen_pubexp`.
    pub fn set1_rsa_keygen_pubexp(&self, e: &Bn) -> c_int {
        // SAFETY: both are live; the context copies the number.
        unsafe { ffi::EVP_PKEY_CTX_set1_rsa_keygen_pubexp(self.as_ptr(), e.as_ptr()) }
    }

    /// `EVP_PKEY_CTX_set_rsa_keygen_primes`.
    pub fn set_rsa_keygen_primes(&self, primes: c_int) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_rsa_keygen_primes(self.as_ptr(), primes) }
    }

    /// `EVP_PKEY_CTX_set_dsa_paramgen_bits`.
    pub fn set_dsa_paramgen_bits(&self, bits: c_int) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_dsa_paramgen_bits(self.as_ptr(), bits) }
    }

    /// `EVP_PKEY_CTX_set_dsa_paramgen_q_bits`.
    pub fn set_dsa_paramgen_q_bits(&self, bits: c_int) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_dsa_paramgen_q_bits(self.as_ptr(), bits) }
    }

    /// `EVP_PKEY_CTX_set_dh_paramgen_prime_len`.
    pub fn set_dh_paramgen_prime_len(&self, bits: c_int) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_dh_paramgen_prime_len(self.as_ptr(), bits) }
    }

    /// `EVP_PKEY_CTX_set_dh_paramgen_generator`.
    pub fn set_dh_paramgen_generator(&self, g: c_int) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_dh_paramgen_generator(self.as_ptr(), g) }
    }

    /// `EVP_PKEY_CTX_set_params`.
    pub fn set_params(&self, params: &impl crate::params::ParamArray) -> c_int {
        // SAFETY: the context is live; params is an ended array.
        unsafe { ffi::EVP_PKEY_CTX_set_params(self.as_ptr(), params.param_ptr()) }
    }

    /// `EVP_PKEY_CTX_settable_params`.
    pub fn settable_params(&self) -> ParamsRef<'_> {
        // SAFETY: the context is live; the array belongs to it (or its provider).
        ParamsRef::from_raw(unsafe { ffi::EVP_PKEY_CTX_settable_params(self.as_ptr()) })
    }

    /// `EVP_PKEY_check`.
    pub fn check(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_check(self.as_ptr()) }
    }

    /// `EVP_PKEY_public_check`.
    pub fn public_check(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_public_check(self.as_ptr()) }
    }

    /// `EVP_PKEY_param_check`.
    pub fn param_check(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_param_check(self.as_ptr()) }
    }

    /// `EVP_PKEY_sign_init`.
    pub fn sign_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_sign_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_verify_init`.
    pub fn verify_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_verify_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_verify_recover_init`.
    pub fn verify_recover_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_verify_recover_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_encrypt_init`.
    pub fn encrypt_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_encrypt_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_decrypt_init`.
    pub fn decrypt_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_decrypt_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_derive_init`.
    pub fn derive_init(&self) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_derive_init(self.as_ptr()) }
    }

    /// `EVP_PKEY_encapsulate_init(ctx, NULL)`.
    pub fn encapsulate_init(&self) -> c_int {
        // SAFETY: the context is live; no parameters.
        unsafe { ffi::EVP_PKEY_encapsulate_init(self.as_ptr(), core::ptr::null()) }
    }

    /// `EVP_PKEY_decapsulate_init(ctx, NULL)`.
    pub fn decapsulate_init(&self) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::EVP_PKEY_decapsulate_init(self.as_ptr(), core::ptr::null()) }
    }

    /// `EVP_PKEY_CTX_set_rsa_padding`.
    pub fn set_rsa_padding(&self, pad: c_int) -> c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_rsa_padding(self.as_ptr(), pad) }
    }

    /// `EVP_PKEY_CTX_set_kem_op`.
    pub fn set_kem_op(&self, op: &str) -> c_int {
        let Some(o) = cstring(op) else {
            return 0;
        };
        // SAFETY: the context is live; o is valid.
        unsafe { ffi::EVP_PKEY_CTX_set_kem_op(self.as_ptr(), o.as_ptr()) }
    }

    /// `EVP_PKEY_derive_set_peer`.
    pub fn derive_set_peer(&self, peer: &Pkey) -> c_int {
        // SAFETY: both are live; the context takes its own reference to the peer.
        unsafe { ffi::EVP_PKEY_derive_set_peer(self.as_ptr(), peer.as_ptr()) }
    }

    /// `EVP_PKEY_get0_type_name(EVP_PKEY_CTX_get0_pkey(ctx))`.
    pub fn pkey_type_name(&self) -> Option<String> {
        // SAFETY: the context is live; its key (if any) belongs to it.
        let k = unsafe { ffi::EVP_PKEY_CTX_get0_pkey(self.as_ptr()) };
        if k.is_null() {
            return None;
        }
        // SAFETY: k is live; the name is copied.
        string_at(unsafe { ffi::EVP_PKEY_get0_type_name(k) })
    }

    /// One of the one-shot operations taking input and writing output: `op` is
    /// `EVP_PKEY_sign`, `_verify_recover`, `_encrypt` or `_decrypt`. With `out`, `*outlen` is
    /// set to its length first.
    fn crypt(
        &self,
        op: unsafe fn(*mut EVP_PKEY_CTX, *mut u8, *mut usize, *const u8, usize) -> c_int,
        out: Option<&mut [u8]>,
        outlen: &mut usize,
        input: &[u8],
    ) -> c_int {
        let o = match out {
            Some(b) => {
                *outlen = b.len();
                b.as_mut_ptr()
            }
            None => core::ptr::null_mut(),
        };
        // SAFETY: the context is live; o is NULL (a length query) or writable for *outlen
        // bytes; input is valid for its length.
        unsafe { op(self.as_ptr(), o, outlen, input.as_ptr(), input.len()) }
    }

    /// `EVP_PKEY_sign`.
    pub fn sign(&self, out: Option<&mut [u8]>, outlen: &mut usize, input: &[u8]) -> c_int {
        self.crypt(ffi::EVP_PKEY_sign, out, outlen, input)
    }

    /// `EVP_PKEY_verify_recover`.
    pub fn verify_recover(
        &self,
        out: Option<&mut [u8]>,
        outlen: &mut usize,
        input: &[u8],
    ) -> c_int {
        self.crypt(ffi::EVP_PKEY_verify_recover, out, outlen, input)
    }

    /// `EVP_PKEY_encrypt`.
    pub fn encrypt(&self, out: Option<&mut [u8]>, outlen: &mut usize, input: &[u8]) -> c_int {
        self.crypt(ffi::EVP_PKEY_encrypt, out, outlen, input)
    }

    /// `EVP_PKEY_decrypt`.
    pub fn decrypt(&self, out: Option<&mut [u8]>, outlen: &mut usize, input: &[u8]) -> c_int {
        self.crypt(ffi::EVP_PKEY_decrypt, out, outlen, input)
    }

    /// `EVP_PKEY_verify`.
    pub fn verify(&self, sig: &[u8], data: &[u8]) -> c_int {
        // SAFETY: the context is live; both slices are valid for their lengths.
        unsafe {
            ffi::EVP_PKEY_verify(
                self.as_ptr(),
                sig.as_ptr(),
                sig.len(),
                data.as_ptr(),
                data.len(),
            )
        }
    }

    /// `EVP_PKEY_derive`.
    pub fn derive(&self, out: Option<&mut [u8]>, outlen: &mut usize) -> c_int {
        let o = match out {
            Some(b) => {
                *outlen = b.len();
                b.as_mut_ptr()
            }
            None => core::ptr::null_mut(),
        };
        // SAFETY: the context is live; o is NULL or writable for *outlen bytes.
        unsafe { ffi::EVP_PKEY_derive(self.as_ptr(), o, outlen) }
    }

    /// `EVP_PKEY_encapsulate`.
    pub fn encapsulate(
        &self,
        out: Option<&mut [u8]>,
        outlen: &mut usize,
        secret: Option<&mut [u8]>,
        secretlen: &mut usize,
    ) -> c_int {
        let o = match out {
            Some(b) => {
                *outlen = b.len();
                b.as_mut_ptr()
            }
            None => core::ptr::null_mut(),
        };
        let s = match secret {
            Some(b) => {
                *secretlen = b.len();
                b.as_mut_ptr()
            }
            None => core::ptr::null_mut(),
        };
        // SAFETY: the context is live; o and s are NULL or writable for their lengths.
        unsafe { ffi::EVP_PKEY_encapsulate(self.as_ptr(), o, outlen, s, secretlen) }
    }

    /// `EVP_PKEY_decapsulate`.
    pub fn decapsulate(
        &self,
        secret: Option<&mut [u8]>,
        secretlen: &mut usize,
        input: &[u8],
    ) -> c_int {
        let s = match secret {
            Some(b) => {
                *secretlen = b.len();
                b.as_mut_ptr()
            }
            None => core::ptr::null_mut(),
        };
        // SAFETY: the context is live; s is NULL or writable; input is valid.
        unsafe {
            ffi::EVP_PKEY_decapsulate(self.as_ptr(), s, secretlen, input.as_ptr(), input.len())
        }
    }
}

/// An `EVP_MD_CTX` signing or verifying with a key context the caller set up
/// (`EVP_MD_CTX_set_pkey_ctx`): the digest context is freed first, and doesn't free the key
/// context, which is freed after it.
pub struct MdPkeyCtx {
    md: MdCtx,
    pctx: PkeyCtx,
}

impl MdPkeyCtx {
    /// `EVP_MD_CTX_new()` and `EVP_MD_CTX_set_pkey_ctx(mctx, pctx)`.
    pub fn new(pctx: PkeyCtx) -> Option<Self> {
        let md = MdCtx::new()?;
        // SAFETY: both are live; pctx is kept in self and outlives md (fields drop in order).
        unsafe { ffi::EVP_MD_CTX_set_pkey_ctx(md.as_ptr(), pctx.as_ptr()) };
        Some(Self { md, pctx })
    }

    /// The key context.
    pub fn pkey_ctx(&self) -> &PkeyCtx {
        &self.pctx
    }

    fn init(
        &self,
        sign: bool,
        digest: Option<&str>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        pkey: &Pkey,
    ) -> c_int {
        let (Ok(d), Ok(q)) = (opt_cstring(digest), opt_cstring(propq)) else {
            return 0;
        };
        let lc = libctx_ptr(libctx);
        let (m, null) = (self.md.as_ptr(), core::ptr::null_mut());
        let (dp, qp, k) = (opt_ptr(&d), opt_ptr(&q), pkey.as_ptr());
        if sign {
            // SAFETY: the contexts and key are live; the strings are valid or NULL; no output
            // key context pointer or parameters.
            unsafe { ffi::EVP_DigestSignInit_ex(m, null, dp, lc, qp, k, core::ptr::null()) }
        } else {
            // SAFETY: as above.
            unsafe { ffi::EVP_DigestVerifyInit_ex(m, null, dp, lc, qp, k, core::ptr::null()) }
        }
    }

    /// `EVP_DigestSignInit_ex(mctx, NULL, digest, libctx, propq, pkey, NULL)`.
    pub fn sign_init(
        &self,
        digest: Option<&str>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        pkey: &Pkey,
    ) -> c_int {
        self.init(true, digest, libctx, propq, pkey)
    }

    /// `EVP_DigestVerifyInit_ex(...)`.
    pub fn verify_init(
        &self,
        digest: Option<&str>,
        libctx: Option<&LibCtx>,
        propq: Option<&str>,
        pkey: &Pkey,
    ) -> c_int {
        self.init(false, digest, libctx, propq, pkey)
    }

    /// `EVP_DigestSignUpdate`.
    pub fn sign_update(&self, data: &[u8]) -> c_int {
        // SAFETY: the context is live; data is valid for its length.
        unsafe { ffi::EVP_DigestSignUpdate(self.md.as_ptr(), data.as_ptr().cast(), data.len()) }
    }

    /// `EVP_DigestVerifyUpdate`.
    pub fn verify_update(&self, data: &[u8]) -> c_int {
        // SAFETY: as above.
        unsafe { ffi::EVP_DigestVerifyUpdate(self.md.as_ptr(), data.as_ptr().cast(), data.len()) }
    }

    /// `EVP_DigestSignFinal`.
    pub fn sign_final(&self, out: Option<&mut [u8]>, outlen: &mut usize) -> c_int {
        let o = match out {
            Some(b) => {
                *outlen = b.len();
                b.as_mut_ptr()
            }
            None => core::ptr::null_mut(),
        };
        // SAFETY: the context is live; o is NULL or writable for *outlen bytes.
        unsafe { ffi::EVP_DigestSignFinal(self.md.as_ptr(), o, outlen) }
    }

    /// `EVP_DigestVerifyFinal`.
    pub fn verify_final(&self, sig: &[u8]) -> c_int {
        // SAFETY: the context is live; sig is valid.
        unsafe { ffi::EVP_DigestVerifyFinal(self.md.as_ptr(), sig.as_ptr(), sig.len()) }
    }

    /// `EVP_DigestSign` (one shot).
    pub fn digest_sign(&self, out: Option<&mut [u8]>, outlen: &mut usize, data: &[u8]) -> c_int {
        let o = match out {
            Some(b) => {
                *outlen = b.len();
                b.as_mut_ptr()
            }
            None => core::ptr::null_mut(),
        };
        // SAFETY: the context is live; o is NULL or writable; data is valid.
        unsafe { ffi::EVP_DigestSign(self.md.as_ptr(), o, outlen, data.as_ptr(), data.len()) }
    }

    /// `EVP_DigestVerify` (one shot).
    pub fn digest_verify(&self, sig: &[u8], data: &[u8]) -> c_int {
        // SAFETY: the context is live; both slices are valid.
        unsafe {
            ffi::EVP_DigestVerify(
                self.md.as_ptr(),
                sig.as_ptr(),
                sig.len(),
                data.as_ptr(),
                data.len(),
            )
        }
    }
}

/// `get_legacy_pkey_id` (`apps/lib/engine.c`): the NID of an ENGINE's key method for
/// `algname`, or `NID_undef` (0).
pub fn legacy_pkey_id(algname: &str, e: Option<&Engine>) -> c_int {
    let Some(name) = cstring(algname) else {
        return 0;
    };
    crate::err::set_mark();
    let mut tmpeng: *mut crate::abi::ENGINE = core::ptr::null_mut();
    // SAFETY: tmpeng is a valid out-pointer; name is valid.
    let mut ameth: *const EVP_PKEY_ASN1_METHOD =
        unsafe { ffi::EVP_PKEY_asn1_find_str(&mut tmpeng, name.as_ptr(), -1) };
    // SAFETY: tmpeng is NULL or a functional reference we now release.
    unsafe { ffi::ENGINE_finish(tmpeng) };
    if ameth.is_null() && e.is_some() {
        // SAFETY: e is live; name is valid.
        ameth = unsafe { ffi::ENGINE_get_pkey_asn1_meth_str(engine_ptr(e), name.as_ptr(), -1) };
    } else if tmpeng.is_null() {
        // Only an ENGINE's method counts.
        ameth = core::ptr::null();
    }
    crate::err::pop_to_mark();
    if ameth.is_null() {
        return 0;
    }
    let mut id: c_int = 0;
    // SAFETY: ameth is a live method; the other out-pointers may be NULL.
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

/// `EC_get_builtin_curves`: each curve's NID and comment.
pub fn builtin_curves() -> Vec<(c_int, Option<String>)> {
    // SAFETY: a NULL array with length 0 asks for the count.
    let n = unsafe { ffi::EC_get_builtin_curves(core::ptr::null_mut(), 0) };
    let mut v = vec![
        crate::abi::EC_builtin_curve {
            nid: 0,
            comment: core::ptr::null(),
        };
        n
    ];
    // SAFETY: v holds n entries to fill.
    unsafe { ffi::EC_get_builtin_curves(v.as_mut_ptr(), n) };
    v.iter().map(|c| (c.nid, string_at(c.comment))).collect()
}

impl Pkey {
    /// `PEM_write_bio_PUBKEY`: what it returns.
    pub fn write_pubkey_pem(&self, out: &crate::Bio) -> core::ffi::c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_PUBKEY(out.as_ptr(), self.as_ptr()) }
    }
}

impl Pkey {
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

impl PkeyCtx {
    /// `EVP_PKEY_CTX_is_a`.
    pub fn is_a(&self, name: &str) -> bool {
        let Some(n) = cstring(name) else {
            return false;
        };
        // SAFETY: the context is live; n is a valid C string.
        unsafe { ffi::EVP_PKEY_CTX_is_a(self.as_ptr(), n.as_ptr()) == 1 }
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
}

impl Pkey {
    /// `PEM_read_bio_Parameters(bio, NULL)`.
    pub fn read_params_pem(bio: &crate::Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::PEM_read_bio_Parameters(bio.as_ptr(), core::ptr::null_mut()) })
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

/// A C `int` for a length the C API takes as one; `None` if it doesn't fit.
fn c_len(n: usize) -> Option<core::ffi::c_int> {
    core::ffi::c_int::try_from(n).ok()
}

impl Pkey {
    /// `EVP_PKEY_new()`.
    pub fn new() -> Option<Self> {
        // SAFETY: no arguments.
        Self::from_ptr(unsafe { ffi::EVP_PKEY_new() })
    }

    /// `d2i_PrivateKey(type, NULL, &p, len)`.
    pub fn private_from_der(kind: core::ffi::c_int, der: &[u8]) -> Option<Self> {
        let len = core::ffi::c_long::try_from(der.len()).ok()?;
        let mut p = der.as_ptr();
        // SAFETY: p points to len bytes; the call only reads them and advances p.
        Self::from_ptr(unsafe { ffi::d2i_PrivateKey(kind, core::ptr::null_mut(), &mut p, len) })
    }

    /// `get_dsa` of upstream's `testdsa.h`: a key pair of `kind` ("DSA") from its FFC
    /// parameters and keys, big-endian (`OSSL_PARAM_BLD` with BIGNUMs, `EVP_PKEY_fromdata`).
    pub fn ffc_keypair(
        kind: &str,
        p: &[u8],
        q: &[u8],
        g: &[u8],
        private: &[u8],
        public: &[u8],
    ) -> Option<Self> {
        use crate::abi::{
            EVP_PKEY_KEYPAIR, OSSL_PKEY_PARAM_FFC_G, OSSL_PKEY_PARAM_FFC_P, OSSL_PKEY_PARAM_FFC_Q,
            OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PUB_KEY,
        };
        let pctx = PkeyCtx::from_name(None, kind, None)?;
        let parts = [
            (OSSL_PKEY_PARAM_FFC_P, p),
            (OSSL_PKEY_PARAM_FFC_Q, q),
            (OSSL_PKEY_PARAM_FFC_G, g),
            (OSSL_PKEY_PARAM_PRIV_KEY, private),
            (OSSL_PKEY_PARAM_PUB_KEY, public),
        ];
        let mut bns = Vec::new();
        for (_, bytes) in &parts {
            let n = c_len(bytes.len())?;
            // SAFETY: bytes holds n bytes; a NULL BIGNUM asks for a new one, freed below.
            let bn = unsafe { ffi::BN_bin2bn(bytes.as_ptr(), n, core::ptr::null_mut()) };
            if bn.is_null() {
                break;
            }
            bns.push(bn);
        }
        let mut key = None;
        if bns.len() == parts.len() {
            // SAFETY: no arguments.
            let bld = unsafe { ffi::OSSL_PARAM_BLD_new() };
            if !bld.is_null() {
                let pushed = parts.iter().zip(&bns).all(|((name, _), &bn)| {
                    // SAFETY: bld and bn are live; the name is a static C string.
                    unsafe { ffi::OSSL_PARAM_BLD_push_BN(bld, name.as_ptr(), bn) == 1 }
                });
                let params = if pushed {
                    // SAFETY: bld is live; the list is the caller's, freed below.
                    unsafe { ffi::OSSL_PARAM_BLD_to_param(bld) }
                } else {
                    core::ptr::null_mut()
                };
                if !params.is_null() {
                    let mut pkey: *mut EVP_PKEY = core::ptr::null_mut();
                    let ok = pctx.fromdata_init() > 0
                        // SAFETY: the context is live; params is a live list; pkey is an
                        // out-pointer whose key becomes ours.
                        && unsafe {
                            ffi::EVP_PKEY_fromdata(pctx.as_ptr(), &mut pkey, EVP_PKEY_KEYPAIR, params)
                        } > 0;
                    key = if ok { Pkey::from_ptr(pkey) } else { None };
                    // SAFETY: the list from OSSL_PARAM_BLD_to_param, freed once.
                    unsafe { ffi::OSSL_PARAM_free(params) };
                }
                // SAFETY: the builder is ours, freed once.
                unsafe { ffi::OSSL_PARAM_BLD_free(bld) };
            }
        }
        for bn in bns {
            // SAFETY: each BIGNUM is ours (the builder copied it), freed once.
            unsafe { ffi::BN_free(bn) };
        }
        key
    }
}

impl PkeyCtx {
    /// `EVP_PKEY_sign_message_init(ctx, alg, NULL)`.
    pub fn sign_message_init(&self, alg: &crate::evp::Signature) -> core::ffi::c_int {
        // SAFETY: the context and algorithm are live; no parameters.
        unsafe { ffi::EVP_PKEY_sign_message_init(self.as_ptr(), alg.as_ptr(), core::ptr::null()) }
    }

    /// `EVP_PKEY_verify_message_init(ctx, alg, NULL)`.
    pub fn verify_message_init(&self, alg: &crate::evp::Signature) -> core::ffi::c_int {
        // SAFETY: as above.
        unsafe { ffi::EVP_PKEY_verify_message_init(self.as_ptr(), alg.as_ptr(), core::ptr::null()) }
    }

    /// `EVP_PKEY_sign(ctx, NULL, &siglen, tbs, tbslen)`: the signature's maximum length.
    pub fn sign_length(&self, tbs: &[u8]) -> (core::ffi::c_int, usize) {
        let mut len = 0;
        // SAFETY: the context is live; a NULL signature asks for the length.
        let r = unsafe {
            ffi::EVP_PKEY_sign(
                self.as_ptr(),
                core::ptr::null_mut(),
                &mut len,
                tbs.as_ptr(),
                tbs.len(),
            )
        };
        (r, len)
    }

    /// `EVP_PKEY_derive(ctx, NULL, &len)`: the secret's length.
    pub fn derive_length(&self) -> (core::ffi::c_int, usize) {
        let mut l = 0;
        // SAFETY: the context is live; NULL asks for the length.
        let r = unsafe { ffi::EVP_PKEY_derive(self.as_ptr(), core::ptr::null_mut(), &mut l) };
        (r, l)
    }

    /// `EVP_PKEY_CTX_set_ec_paramgen_curve_nid`.
    pub fn set_ec_paramgen_curve_nid(&self, nid: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_ec_paramgen_curve_nid(self.as_ptr(), nid) }
    }

    /// `EVP_PKEY_CTX_set_dh_nid`.
    pub fn set_dh_nid(&self, nid: core::ffi::c_int) -> core::ffi::c_int {
        // SAFETY: the context is live.
        unsafe { ffi::EVP_PKEY_CTX_set_dh_nid(self.as_ptr(), nid) }
    }

    /// `EVP_PKEY_CTX_set1_id(ctx, id, len)`.
    pub fn set1_id(&self, id: &[u8]) -> core::ffi::c_int {
        let Some(n) = c_len(id.len()) else {
            return 0;
        };
        // SAFETY: the context is live; id is readable for n bytes (copied).
        unsafe { ffi::EVP_PKEY_CTX_set1_id(self.as_ptr(), id.as_ptr().cast(), n) }
    }

    /// `EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &secretlen)`: the lengths.
    pub fn encapsulate_lengths(&self) -> (core::ffi::c_int, usize, usize) {
        let (mut o, mut s) = (0, 0);
        // SAFETY: the context is live; NULL buffers ask for the lengths.
        let r = unsafe {
            ffi::EVP_PKEY_encapsulate(
                self.as_ptr(),
                core::ptr::null_mut(),
                &mut o,
                core::ptr::null_mut(),
                &mut s,
            )
        };
        (r, o, s)
    }

    /// `EVP_PKEY_decapsulate(ctx, NULL, &secretlen, in, inlen)`: the length.
    pub fn decapsulate_length(&self, input: &[u8]) -> (core::ffi::c_int, usize) {
        let mut s = 0;
        // SAFETY: the context is live; NULL asks for the length; input is readable.
        let r = unsafe {
            ffi::EVP_PKEY_decapsulate(
                self.as_ptr(),
                core::ptr::null_mut(),
                &mut s,
                input.as_ptr(),
                input.len(),
            )
        };
        (r, s)
    }
}

impl MdCtx {
    /// `EVP_DigestInit(ctx, md)`.
    pub fn digest_init(&self, md: &crate::evp::Md) -> core::ffi::c_int {
        // SAFETY: both are live.
        unsafe { ffi::EVP_DigestInit(self.as_ptr(), md.as_ptr()) }
    }

    /// `EVP_DigestInit_ex2(ctx, md, NULL)`.
    pub fn digest_init_ex2(&self, md: &crate::evp::Md) -> bool {
        // SAFETY: both are live; no parameters.
        unsafe { ffi::EVP_DigestInit_ex2(self.as_ptr(), md.as_ptr(), core::ptr::null()) == 1 }
    }

    /// `EVP_DigestUpdate(ctx, data, len)`.
    pub fn digest_update(&self, data: &[u8]) -> bool {
        // SAFETY: the context is live; data is readable for its length.
        unsafe { ffi::EVP_DigestUpdate(self.as_ptr(), data.as_ptr().cast(), data.len()) == 1 }
    }

    /// `EVP_DigestFinalXOF(ctx, out, out.len())`.
    pub fn digest_final_xof(&self, out: &mut [u8]) -> bool {
        // SAFETY: the context is live; out is writable for its length.
        unsafe { ffi::EVP_DigestFinalXOF(self.as_ptr(), out.as_mut_ptr(), out.len()) == 1 }
    }

    /// `EVP_DigestSignInit(ctx, NULL, md, NULL, pkey)`, `md` NULL or `EVP_sm3()`.
    pub fn sign_init(&self, sm3: bool, pkey: &Pkey) -> core::ffi::c_int {
        let md = if sm3 {
            // SAFETY: no arguments; a static digest.
            unsafe { ffi::EVP_sm3() }
        } else {
            core::ptr::null()
        };
        // SAFETY: the context and key are live; the key context made stays the context's.
        unsafe {
            ffi::EVP_DigestSignInit(
                self.as_ptr(),
                core::ptr::null_mut(),
                md,
                core::ptr::null_mut(),
                pkey.as_ptr(),
            )
        }
    }

    /// `EVP_DigestSignInit(ctx, NULL, NULL, NULL, NULL)`: again, with the key it has.
    pub fn sign_reinit(&self) -> core::ffi::c_int {
        // SAFETY: the context is live; NULLs keep what it has.
        unsafe {
            ffi::EVP_DigestSignInit(
                self.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        }
    }

    /// `EVP_DigestVerifyInit(ctx, NULL, md, NULL, pkey)`, `md` NULL or `EVP_sm3()`.
    pub fn verify_init(&self, sm3: bool, pkey: &Pkey) -> core::ffi::c_int {
        let md = if sm3 {
            // SAFETY: as in sign_init.
            unsafe { ffi::EVP_sm3() }
        } else {
            core::ptr::null()
        };
        // SAFETY: as in sign_init.
        unsafe {
            ffi::EVP_DigestVerifyInit(
                self.as_ptr(),
                core::ptr::null_mut(),
                md,
                core::ptr::null_mut(),
                pkey.as_ptr(),
            )
        }
    }

    /// `EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, NULL)`.
    pub fn verify_reinit(&self) -> core::ffi::c_int {
        // SAFETY: as in sign_reinit.
        unsafe {
            ffi::EVP_DigestVerifyInit(
                self.as_ptr(),
                core::ptr::null_mut(),
                core::ptr::null(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        }
    }

    /// `EVP_DigestSign(ctx, sig, &siglen, tbs, tbslen)` with `siglen` as given (at most
    /// `sig.len()`).
    pub fn sign(&self, sig: &mut [u8], siglen: usize, tbs: &[u8]) -> (core::ffi::c_int, usize) {
        let mut l = siglen.min(sig.len());
        // SAFETY: the context is live; sig is writable for l bytes; tbs readable.
        let r = unsafe {
            ffi::EVP_DigestSign(
                self.as_ptr(),
                sig.as_mut_ptr(),
                &mut l,
                tbs.as_ptr(),
                tbs.len(),
            )
        };
        (r, l)
    }

    /// `EVP_DigestVerify(ctx, sig, siglen, tbs, tbslen)`.
    pub fn verify(&self, sig: &[u8], tbs: &[u8]) -> core::ffi::c_int {
        // SAFETY: the context is live; both buffers are readable for their lengths.
        unsafe {
            ffi::EVP_DigestVerify(
                self.as_ptr(),
                sig.as_ptr(),
                sig.len(),
                tbs.as_ptr(),
                tbs.len(),
            )
        }
    }

    /// `EVP_MD_CTX_set_pkey_ctx(ctx, pctx)`: the context uses `pctx`, which it doesn't own;
    /// `pctx` must outlive its use here.
    pub fn set_pkey_ctx(&self, pctx: &PkeyCtx) {
        // SAFETY: both are live; the MD context keeps the pointer without owning it, and its
        // owner (the caller) keeps it alive as long as this context uses it.
        unsafe { ffi::EVP_MD_CTX_set_pkey_ctx(self.as_ptr(), pctx.as_ptr()) };
    }
}

/// Fork G6's (`speed`) forms of the one-shot operations: into a buffer the caller sized,
/// returning what the call returned and the length written.
impl PkeyCtx {
    /// `EVP_PKEY_sign(ctx, sig, &siglen, tbs, tbslen)` with `siglen = sig.len()`: what it
    /// returns, and the length.
    pub fn sign_into(&self, sig: &mut [u8], tbs: &[u8]) -> (core::ffi::c_int, usize) {
        let mut len = sig.len();
        // SAFETY: the context is live; sig is writable for len bytes, tbs readable for its.
        let r = unsafe {
            ffi::EVP_PKEY_sign(
                self.as_ptr(),
                sig.as_mut_ptr(),
                &mut len,
                tbs.as_ptr(),
                tbs.len(),
            )
        };
        (r, len)
    }

    /// `EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen)` with `outlen = out.len()`.
    pub fn encrypt_into(&self, out: &mut [u8], input: &[u8]) -> (core::ffi::c_int, usize) {
        let mut len = out.len();
        // SAFETY: as in sign.
        let r = unsafe {
            ffi::EVP_PKEY_encrypt(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut len,
                input.as_ptr(),
                input.len(),
            )
        };
        (r, len)
    }

    /// `EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen)` with `outlen = out.len()`.
    pub fn decrypt_into(&self, out: &mut [u8], input: &[u8]) -> (core::ffi::c_int, usize) {
        let mut len = out.len();
        // SAFETY: as in sign.
        let r = unsafe {
            ffi::EVP_PKEY_decrypt(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut len,
                input.as_ptr(),
                input.len(),
            )
        };
        (r, len)
    }

    /// `EVP_PKEY_derive(ctx, out, &len)` with `len` as given (at most `out.len()`).
    pub fn derive_into(&self, out: &mut [u8], len: usize) -> (core::ffi::c_int, usize) {
        let mut l = len.min(out.len());
        // SAFETY: the context is live; out is writable for l bytes.
        let r = unsafe { ffi::EVP_PKEY_derive(self.as_ptr(), out.as_mut_ptr(), &mut l) };
        (r, l)
    }

    /// `EVP_PKEY_keygen(ctx, &pkey)`, into `into` when given (as upstream passes a key it
    /// made with `EVP_PKEY_new`): what it returns, and the key.
    pub fn keygen_into(&self, into: Option<Pkey>) -> (core::ffi::c_int, Option<Pkey>) {
        let mut p = into.map_or(core::ptr::null_mut(), Pkey::into_ptr);
        // SAFETY: the context is live; p is NULL or a key owned here, which the call fills
        // (or replaces) and which stays ours.
        let r = unsafe { ffi::EVP_PKEY_keygen(self.as_ptr(), &mut p) };
        (r, Pkey::from_ptr(p))
    }

    /// `EVP_PKEY_CTX_set1_rsa_keygen_pubexp` with a BIGNUM of `e` (`BN_set_word`): `None`
    /// when the BIGNUM can't be made.
    pub fn set1_rsa_keygen_pubexp_word(&self, e: core::ffi::c_ulong) -> Option<core::ffi::c_int> {
        // SAFETY: no arguments.
        let bn = unsafe { ffi::BN_new() };
        if bn.is_null() {
            return None;
        }
        // SAFETY: bn is live.
        let r = if unsafe { ffi::BN_set_word(bn, e) } == 1 {
            // SAFETY: the context and bn are live; the context copies bn.
            Some(unsafe { ffi::EVP_PKEY_CTX_set1_rsa_keygen_pubexp(self.as_ptr(), bn) })
        } else {
            None
        };
        // SAFETY: bn is ours, freed once.
        unsafe { ffi::BN_free(bn) };
        r
    }

    /// `EVP_PKEY_encapsulate(ctx, out, &outlen, secret, &secretlen)`, the lengths those of
    /// the buffers: what it returns, and the lengths written.
    pub fn encapsulate_into(
        &self,
        out: &mut [u8],
        secret: &mut [u8],
    ) -> (core::ffi::c_int, usize, usize) {
        let (mut o, mut s) = (out.len(), secret.len());
        // SAFETY: the context is live; the buffers are writable for their lengths.
        let r = unsafe {
            ffi::EVP_PKEY_encapsulate(
                self.as_ptr(),
                out.as_mut_ptr(),
                &mut o,
                secret.as_mut_ptr(),
                &mut s,
            )
        };
        (r, o, s)
    }

    /// `EVP_PKEY_decapsulate(ctx, secret, &secretlen, in, inlen)` with `secretlen` the
    /// buffer's length.
    pub fn decapsulate_into(&self, secret: &mut [u8], input: &[u8]) -> (core::ffi::c_int, usize) {
        let mut s = secret.len();
        // SAFETY: the context is live; the buffers are valid for their lengths.
        let r = unsafe {
            ffi::EVP_PKEY_decapsulate(
                self.as_ptr(),
                secret.as_mut_ptr(),
                &mut s,
                input.as_ptr(),
                input.len(),
            )
        };
        (r, s)
    }
}
