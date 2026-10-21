//! The deprecated hashes (`SHA1(3)`, `SHA256_Init(3)`, `MD5(3)`, `MD4(3)`, `RIPEMD160(3)`,
//! `MDC2(3)`, `WHIRLPOOL(3)`), over [`rustyssl_crypto::lowlevel::hash`].
//!
//! The SHA one-shots digest through `EVP_Q_digest` with the default library context, as
//! OpenSSL's do, so they fail where it has no SHA; the others, and every context function,
//! don't use providers. Where OpenSSL dereferences a null context, input, or output and
//! crashes, these return 0 (null for a one-shot) or do nothing, and a context whose count of
//! buffered octets or bits is past its buffer is refused (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_CRYPTO, MD4_CTX, MD4_DIGEST_LENGTH, MD5_CTX, MD5_DIGEST_LENGTH, MDC2_CTX,
    MDC2_DIGEST_LENGTH, RIPEMD160_CTX, RIPEMD160_DIGEST_LENGTH, SHA_CTX, SHA_DIGEST_LENGTH,
    SHA224_DIGEST_LENGTH, SHA256_CTX, SHA256_DIGEST_LENGTH, SHA384_DIGEST_LENGTH, SHA512_CTX,
    SHA512_DIGEST_LENGTH, WHIRLPOOL_CTX, WHIRLPOOL_DIGEST_LENGTH,
};
use rustyssl_crypto::lowlevel::hash::{
    MD32_BLOCK, Md32, Md32Kind, Mdc2, SHA512_BLOCK, Sha512, Whirlpool, sha256_output_len,
    sha512_output_len,
};

use super::StaticMd;
use crate::evp::md_ctx::EVP_Q_digest;
use crate::ffi::{bytes, ffi_export};
use crate::mem::cleanse;

/// A digest length constant as a `usize`.
const fn size(len: c_int) -> usize {
    len.cast_unsigned() as usize
}

/// An MD4-like context struct, which mirrors as an [`Md32`].
trait Md32Struct {
    /// Which hash's compression function and byte order it takes.
    const KIND: Md32Kind;
    /// Its chaining words.
    fn words(&self) -> [u32; 8];
    /// Sets its chaining words.
    fn set_words(&mut self, h: &[u32; 8]);
    /// Its counts, buffer, and buffered octets.
    fn rest(&mut self) -> (&mut u32, &mut u32, &mut [u32; 16], &mut u32);

    /// The mirror.
    fn load(&mut self) -> Md32 {
        let h = self.words();
        let (nl, nh, words, num) = self.rest();
        let mut data = [0; MD32_BLOCK];
        for (word, chunk) in words.iter().zip(data.as_chunks_mut::<4>().0) {
            *chunk = word.to_ne_bytes();
        }
        Md32 {
            h,
            nl: *nl,
            nh: *nh,
            data,
            num: *num,
        }
    }

    /// Copies the mirror back.
    fn store(&mut self, m: &Md32) {
        self.set_words(&m.h);
        let (nl, nh, words, num) = self.rest();
        *nl = m.nl;
        *nh = m.nh;
        *num = m.num;
        for (word, chunk) in words.iter_mut().zip(m.data.as_chunks::<4>().0) {
            *word = u32::from_ne_bytes(*chunk);
        }
    }
}

/// [`Md32Struct`] for a struct with named chaining words.
macro_rules! md32_named {
    ($ty:ty, $kind:expr, $($field:ident $i:literal),+) => {
        impl Md32Struct for $ty {
            const KIND: Md32Kind = $kind;

            fn words(&self) -> [u32; 8] {
                let mut h = [0; 8];
                $(h[$i] = self.$field;)+
                h
            }

            fn set_words(&mut self, h: &[u32; 8]) {
                $(self.$field = h[$i];)+
            }

            fn rest(&mut self) -> (&mut u32, &mut u32, &mut [u32; 16], &mut u32) {
                (&mut self.Nl, &mut self.Nh, &mut self.data, &mut self.num)
            }
        }
    };
}

md32_named!(MD4_CTX, Md32Kind::Md4, A 0, B 1, C 2, D 3);
md32_named!(MD5_CTX, Md32Kind::Md5, A 0, B 1, C 2, D 3);
md32_named!(RIPEMD160_CTX, Md32Kind::Ripemd160, A 0, B 1, C 2, D 3, E 4);
md32_named!(SHA_CTX, Md32Kind::Sha1, h0 0, h1 1, h2 2, h3 3, h4 4);

impl Md32Struct for SHA256_CTX {
    const KIND: Md32Kind = Md32Kind::Sha256;

    fn words(&self) -> [u32; 8] {
        self.h
    }

    fn set_words(&mut self, h: &[u32; 8]) {
        self.h = *h;
    }

    fn rest(&mut self) -> (&mut u32, &mut u32, &mut [u32; 16], &mut u32) {
        (&mut self.Nl, &mut self.Nh, &mut self.data, &mut self.num)
    }
}

/// `*_Init`: zeroes the whole struct, then sets it as `fresh`. Returns 1, or 0 for null.
///
/// # Safety
/// `c` is null or valid for writes of a `C`.
unsafe fn md32_init<'a, C: Md32Struct>(c: *mut C, fresh: &Md32) -> Option<&'a mut C> {
    if c.is_null() {
        return None;
    }
    // SAFETY: the caller's struct, valid for a write of its size.
    unsafe { c.write_bytes(0, 1) };
    // SAFETY: zeroed, which is a valid struct of integers.
    let c = unsafe { c.as_mut() }?;
    c.store(fresh);
    Some(c)
}

/// `*_Update`. Returns 1, or 0 for null or a corrupt count.
///
/// # Safety
/// `c` is null or a valid `C`; `data` is null or holds `len` octets.
unsafe fn md32_update<C: Md32Struct>(c: *mut C, data: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { c.as_mut() }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let Some(input) = (unsafe { bytes(data.cast(), len) }) else {
        return 0;
    };
    let mut m = c.load();
    if m.update(C::KIND, input).is_err() {
        return 0;
    }
    c.store(&m);
    1
}

/// `*_Final`: finishes, then writes `out_len(c)` octets of the digest to `md`. Returns 1, or 0
/// for null or a corrupt count (changing nothing), or for no length (after finishing).
///
/// # Safety
/// `c` is null or a valid `C`; `md` is null or has room for the digest.
unsafe fn md32_final<C: Md32Struct>(
    md: *mut c_uchar,
    c: *mut C,
    out_len: impl Fn(&C) -> Option<usize>,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { c.as_mut() }) else {
        return 0;
    };
    if md.is_null() {
        return 0;
    }
    let mut m = c.load();
    if m.finish(C::KIND).is_err() {
        return 0;
    }
    c.store(&m);
    let Some(n) = out_len(c) else { return 0 };
    let mut out = [0u8; 32];
    let Some(out) = out.get_mut(..n) else {
        return 0;
    };
    m.output(C::KIND, out);
    // SAFETY: the caller's room for the digest, `n` octets, and our buffer.
    unsafe { ptr::copy_nonoverlapping(out.as_ptr(), md, n) };
    // SAFETY: our buffer.
    unsafe { cleanse(out.as_mut_ptr().cast(), n) };
    1
}

/// `*_Transform`: one block through the compression function. Null does nothing.
///
/// # Safety
/// `c` is null or a valid `C`; `data` is null or holds a block.
unsafe fn md32_transform<C: Md32Struct>(c: *mut C, data: *const c_uchar) {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { c.as_mut() }) else {
        return;
    };
    if data.is_null() {
        return;
    }
    // SAFETY: the caller's block, read as octets whatever its alignment.
    let block = unsafe { data.cast::<[u8; MD32_BLOCK]>().read_unaligned() };
    let mut m = c.load();
    m.transform(C::KIND, &block);
    c.store(&m);
}

/// A one-shot over an [`Md32`] hash into `md` (or `buffer`). Returns where the digest is, or
/// null for null input with a length.
///
/// # Safety
/// `d` is null or holds `n` octets; `md` is null or has room for `len` octets.
unsafe fn md32_oneshot<const N: usize>(
    kind: Md32Kind,
    mut m: Md32,
    d: *const c_uchar,
    n: usize,
    md: *mut c_uchar,
    buffer: &StaticMd<N>,
) -> *mut c_uchar {
    // SAFETY: the caller's guarantee.
    let Some(input) = (unsafe { bytes(d, n) }) else {
        return ptr::null_mut();
    };
    if m.update(kind, input).is_err() || m.finish(kind).is_err() {
        return ptr::null_mut();
    }
    let mut out = [0u8; N];
    m.output(kind, &mut out);
    let md = buffer.or(md);
    // SAFETY: the caller's room for the digest, or the static buffer of its size; our buffer.
    unsafe { ptr::copy_nonoverlapping(out.as_ptr(), md, N) };
    // SAFETY: our buffer.
    unsafe { cleanse(out.as_mut_ptr().cast(), N) };
    md
}

/// A SHA one-shot through `EVP_Q_digest` with `name`, into `md` (or `buffer`).
///
/// # Safety
/// `d` is null or holds `n` octets; `md` is null or has room for the digest.
unsafe fn sha_oneshot<const N: usize>(
    name: &core::ffi::CStr,
    d: *const c_uchar,
    n: usize,
    md: *mut c_uchar,
    buffer: &StaticMd<N>,
) -> *mut c_uchar {
    let md = buffer.or(md);
    // SAFETY: the default context; a static name; the caller's data and room (or the static
    // buffer, of the digest's size).
    let ok = unsafe {
        EVP_Q_digest(
            ptr::null_mut(),
            name.as_ptr(),
            ptr::null(),
            d.cast(),
            n,
            md,
            ptr::null_mut(),
        )
    };
    if ok == 1 { md } else { ptr::null_mut() }
}

ffi_export! {
    /// Starts a SHA-1 context. Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `c` is null or valid for writes of a `SHA_CTX`.
    pub unsafe extern "C" fn SHA1_Init(c: *mut SHA_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { md32_init(c, &Md32::sha1()) }.is_some())
    }
}

ffi_export! {
    /// Absorbs `len` octets at `data`. Returns 1, or 0.
    ///
    /// # Safety
    /// `c` is null or a `SHA_CTX`; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn SHA1_Update(c: *mut SHA_CTX, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_update(c, data, len) }
    }
}

ffi_export! {
    /// Finishes and writes the digest to `md`. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is null or has room for 20 octets; `c` is null or a `SHA_CTX`.
    pub unsafe extern "C" fn SHA1_Final(md: *mut c_uchar, c: *mut SHA_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_final(md, c, |_| Some(size(SHA_DIGEST_LENGTH))) }
    }
}

ffi_export! {
    /// Runs the compression function over the 64 octets at `data`.
    ///
    /// # Safety
    /// `c` is null or a `SHA_CTX`; `data` is null or holds 64 octets.
    pub unsafe extern "C" fn SHA1_Transform(c: *mut SHA_CTX, data: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_transform(c, data) }
    }
}

static SHA1_MD: StaticMd<{ size(SHA_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The SHA-1 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
    /// null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 20 octets.
    pub unsafe extern "C" fn SHA1(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha_oneshot(c"SHA1", d, n, md, &SHA1_MD) }
    }
}

ffi_export! {
    /// Starts a SHA-224 context (`md_len` 28). Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `c` is null or valid for writes of a `SHA256_CTX`.
    pub unsafe extern "C" fn SHA224_Init(c: *mut SHA256_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { md32_init(c, &Md32::sha224()) }) else { return 0 };
        c.md_len = SHA224_DIGEST_LENGTH.cast_unsigned();
        1
    }
}

ffi_export! {
    /// `SHA256_Update`.
    ///
    /// # Safety
    /// As for `SHA256_Update`.
    pub unsafe extern "C" fn SHA224_Update(c: *mut SHA256_CTX, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_update(c, data, len) }
    }
}

ffi_export! {
    /// `SHA256_Final`.
    ///
    /// # Safety
    /// As for `SHA256_Final`.
    pub unsafe extern "C" fn SHA224_Final(md: *mut c_uchar, c: *mut SHA256_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SHA256_Final(md, c) }
    }
}

static SHA224_MD: StaticMd<{ size(SHA224_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The SHA-224 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
    /// null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 28 octets.
    pub unsafe extern "C" fn SHA224(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha_oneshot(c"SHA224", d, n, md, &SHA224_MD) }
    }
}

ffi_export! {
    /// Starts a SHA-256 context (`md_len` 32). Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `c` is null or valid for writes of a `SHA256_CTX`.
    pub unsafe extern "C" fn SHA256_Init(c: *mut SHA256_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { md32_init(c, &Md32::sha256()) }) else { return 0 };
        c.md_len = SHA256_DIGEST_LENGTH.cast_unsigned();
        1
    }
}

ffi_export! {
    /// Absorbs `len` octets at `data`. Returns 1, or 0.
    ///
    /// # Safety
    /// `c` is null or a `SHA256_CTX`; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn SHA256_Update(c: *mut SHA256_CTX, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_update(c, data, len) }
    }
}

ffi_export! {
    /// Finishes and writes the first `md_len` octets of the digest, in whole words, to `md`.
    /// Returns 1, or 0 (after finishing, for an `md_len` past 32).
    ///
    /// # Safety
    /// `md` is null or has room for the digest; `c` is null or a `SHA256_CTX`.
    pub unsafe extern "C" fn SHA256_Final(md: *mut c_uchar, c: *mut SHA256_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_final(md, c, |c| sha256_output_len(c.md_len)) }
    }
}

ffi_export! {
    /// Runs the compression function over the 64 octets at `data`.
    ///
    /// # Safety
    /// `c` is null or a `SHA256_CTX`; `data` is null or holds 64 octets.
    pub unsafe extern "C" fn SHA256_Transform(c: *mut SHA256_CTX, data: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_transform(c, data) }
    }
}

static SHA256_MD: StaticMd<{ size(SHA256_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The SHA-256 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
    /// null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 32 octets.
    pub unsafe extern "C" fn SHA256(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha_oneshot(c"SHA256", d, n, md, &SHA256_MD) }
    }
}

/// `SHA512_CTX`'s mirror.
fn sha512_load(c: &SHA512_CTX) -> Sha512 {
    Sha512 {
        h: c.h,
        nl: c.Nl,
        nh: c.Nh,
        // SAFETY: every octet pattern is a valid value of the union's octet view.
        data: unsafe { c.u.p },
        num: c.num,
    }
}

/// Copies the mirror back.
fn sha512_store(c: &mut SHA512_CTX, m: &Sha512) {
    c.h = m.h;
    c.Nl = m.nl;
    c.Nh = m.nh;
    c.u.p = m.data;
    c.num = m.num;
}

/// `SHA384_Init` and `SHA512_Init`: sets the chaining words, the counts, and `md_len`, keeping
/// the buffer.
///
/// # Safety
/// `c` is null or a `SHA512_CTX`, initialized or not.
unsafe fn sha512_init(c: *mut SHA512_CTX, sha512: bool) -> c_int {
    if c.is_null() {
        return 0;
    }
    // SAFETY: the caller's struct; integers, so any octets are valid values.
    let Some(c) = (unsafe { c.as_mut() }) else {
        return 0;
    };
    let mut m = sha512_load(c);
    if sha512 {
        m.init_sha512();
        c.md_len = SHA512_DIGEST_LENGTH.cast_unsigned();
    } else {
        m.init_sha384();
        c.md_len = SHA384_DIGEST_LENGTH.cast_unsigned();
    }
    sha512_store(c, &m);
    1
}

/// `SHA384_Update` and `SHA512_Update`.
///
/// # Safety
/// `c` is null or a `SHA512_CTX`; `data` is null or holds `len` octets.
unsafe fn sha512_update(c: *mut SHA512_CTX, data: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { c.as_mut() }) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    let Some(input) = (unsafe { bytes(data.cast(), len) }) else {
        return 0;
    };
    let mut m = sha512_load(c);
    if m.update(input).is_err() {
        return 0;
    }
    sha512_store(c, &m);
    1
}

ffi_export! {
    /// Starts a SHA-384 context (`md_len` 48), keeping the buffer's octets. Returns 1, or 0
    /// for null.
    ///
    /// # Safety
    /// `c` is null or valid for reads and writes of a `SHA512_CTX`.
    pub unsafe extern "C" fn SHA384_Init(c: *mut SHA512_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha512_init(c, false) }
    }
}

ffi_export! {
    /// `SHA512_Update`.
    ///
    /// # Safety
    /// As for `SHA512_Update`.
    pub unsafe extern "C" fn SHA384_Update(c: *mut SHA512_CTX, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha512_update(c, data, len) }
    }
}

ffi_export! {
    /// `SHA512_Final`.
    ///
    /// # Safety
    /// As for `SHA512_Final`.
    pub unsafe extern "C" fn SHA384_Final(md: *mut c_uchar, c: *mut SHA512_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SHA512_Final(md, c) }
    }
}

static SHA384_MD: StaticMd<{ size(SHA384_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The SHA-384 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
    /// null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 48 octets.
    pub unsafe extern "C" fn SHA384(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha_oneshot(c"SHA384", d, n, md, &SHA384_MD) }
    }
}

ffi_export! {
    /// Starts a SHA-512 context (`md_len` 64), keeping the buffer's octets. Returns 1, or 0
    /// for null.
    ///
    /// # Safety
    /// `c` is null or valid for reads and writes of a `SHA512_CTX`.
    pub unsafe extern "C" fn SHA512_Init(c: *mut SHA512_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha512_init(c, true) }
    }
}

ffi_export! {
    /// Absorbs `len` octets at `data`. Returns 1, or 0.
    ///
    /// # Safety
    /// `c` is null or a `SHA512_CTX`; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn SHA512_Update(c: *mut SHA512_CTX, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha512_update(c, data, len) }
    }
}

ffi_export! {
    /// Finishes, then writes `md_len` octets of the digest (28, 32, 48, or 64) to `md`.
    /// Returns 1, or 0: for null or a corrupt count before finishing, and for a null `md` or
    /// another `md_len` after (as OpenSSL, which keeps the buffer and count).
    ///
    /// # Safety
    /// `md` is null or has room for the digest; `c` is null or a `SHA512_CTX`.
    pub unsafe extern "C" fn SHA512_Final(md: *mut c_uchar, c: *mut SHA512_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { c.as_mut() }) else { return 0 };
        let mut m = sha512_load(c);
        if m.finish().is_err() {
            return 0;
        }
        sha512_store(c, &m);
        if md.is_null() {
            return 0;
        }
        let Some(n) = sha512_output_len(c.md_len) else { return 0 };
        let mut out = [0u8; 64];
        let Some(out) = out.get_mut(..n) else { return 0 };
        m.output(out);
        // SAFETY: the caller's room for the digest, `n` octets, and our buffer.
        unsafe { ptr::copy_nonoverlapping(out.as_ptr(), md, n) };
        // SAFETY: our buffer.
        unsafe { cleanse(out.as_mut_ptr().cast(), n) };
        1
    }
}

ffi_export! {
    /// Runs the compression function over the 128 octets at `data`.
    ///
    /// # Safety
    /// `c` is null or a `SHA512_CTX`; `data` is null or holds 128 octets.
    pub unsafe extern "C" fn SHA512_Transform(c: *mut SHA512_CTX, data: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { c.as_mut() }) else { return };
        if data.is_null() {
            return;
        }
        // SAFETY: the caller's block, read as octets whatever its alignment.
        let block = unsafe { data.cast::<[u8; SHA512_BLOCK]>().read_unaligned() };
        let mut m = sha512_load(c);
        m.transform(&block);
        sha512_store(c, &m);
    }
}

static SHA512_MD: StaticMd<{ size(SHA512_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The SHA-512 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
    /// null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 64 octets.
    pub unsafe extern "C" fn SHA512(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { sha_oneshot(c"SHA512", d, n, md, &SHA512_MD) }
    }
}

ffi_export! {
    /// Starts an MD4 context. Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `c` is null or valid for writes of an `MD4_CTX`.
    pub unsafe extern "C" fn MD4_Init(c: *mut MD4_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { md32_init(c, &Md32::md4()) }.is_some())
    }
}

ffi_export! {
    /// Absorbs `len` octets at `data`. Returns 1, or 0.
    ///
    /// # Safety
    /// `c` is null or an `MD4_CTX`; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn MD4_Update(c: *mut MD4_CTX, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_update(c, data, len) }
    }
}

ffi_export! {
    /// Finishes and writes the digest to `md`. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is null or has room for 16 octets; `c` is null or an `MD4_CTX`.
    pub unsafe extern "C" fn MD4_Final(md: *mut c_uchar, c: *mut MD4_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_final(md, c, |_| Some(size(MD4_DIGEST_LENGTH))) }
    }
}

ffi_export! {
    /// Runs the compression function over the 64 octets at `data`.
    ///
    /// # Safety
    /// `c` is null or an `MD4_CTX`; `data` is null or holds 64 octets.
    pub unsafe extern "C" fn MD4_Transform(c: *mut MD4_CTX, data: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_transform(c, data) }
    }
}

static MD4_MD: StaticMd<{ size(MD4_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The MD4 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
    /// null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 16 octets.
    pub unsafe extern "C" fn MD4(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_oneshot(Md32Kind::Md4, Md32::md4(), d, n, md, &MD4_MD) }
    }
}

ffi_export! {
    /// Starts an MD5 context. Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `c` is null or valid for writes of an `MD5_CTX`.
    pub unsafe extern "C" fn MD5_Init(c: *mut MD5_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { md32_init(c, &Md32::md5()) }.is_some())
    }
}

ffi_export! {
    /// Absorbs `len` octets at `data`. Returns 1, or 0.
    ///
    /// # Safety
    /// `c` is null or an `MD5_CTX`; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn MD5_Update(c: *mut MD5_CTX, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_update(c, data, len) }
    }
}

ffi_export! {
    /// Finishes and writes the digest to `md`. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is null or has room for 16 octets; `c` is null or an `MD5_CTX`.
    pub unsafe extern "C" fn MD5_Final(md: *mut c_uchar, c: *mut MD5_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_final(md, c, |_| Some(size(MD5_DIGEST_LENGTH))) }
    }
}

ffi_export! {
    /// Runs the compression function over the 64 octets at `data`.
    ///
    /// # Safety
    /// `c` is null or an `MD5_CTX`; `data` is null or holds 64 octets.
    pub unsafe extern "C" fn MD5_Transform(c: *mut MD5_CTX, data: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_transform(c, data) }
    }
}

static MD5_MD: StaticMd<{ size(MD5_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The MD5 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
    /// null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 16 octets.
    pub unsafe extern "C" fn MD5(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_oneshot(Md32Kind::Md5, Md32::md5(), d, n, md, &MD5_MD) }
    }
}

ffi_export! {
    /// Starts a RIPEMD-160 context. Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `c` is null or valid for writes of a `RIPEMD160_CTX`.
    pub unsafe extern "C" fn RIPEMD160_Init(c: *mut RIPEMD160_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { md32_init(c, &Md32::ripemd160()) }.is_some())
    }
}

ffi_export! {
    /// Absorbs `len` octets at `data`. Returns 1, or 0.
    ///
    /// # Safety
    /// `c` is null or a `RIPEMD160_CTX`; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn RIPEMD160_Update(c: *mut RIPEMD160_CTX, data: *const c_void, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_update(c, data, len) }
    }
}

ffi_export! {
    /// Finishes and writes the digest to `md`. Returns 1, or 0.
    ///
    /// # Safety
    /// `md` is null or has room for 20 octets; `c` is null or a `RIPEMD160_CTX`.
    pub unsafe extern "C" fn RIPEMD160_Final(md: *mut c_uchar, c: *mut RIPEMD160_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_final(md, c, |_| Some(size(RIPEMD160_DIGEST_LENGTH))) }
    }
}

ffi_export! {
    /// Runs the compression function over the 64 octets at `b`.
    ///
    /// # Safety
    /// `c` is null or a `RIPEMD160_CTX`; `b` is null or holds 64 octets.
    pub unsafe extern "C" fn RIPEMD160_Transform(c: *mut RIPEMD160_CTX, b: *const c_uchar)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_transform(c, b) }
    }
}

static RIPEMD160_MD: StaticMd<{ size(RIPEMD160_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The RIPEMD-160 of `n` octets at `d`, into `md` or a static buffer. Returns where it is,
    /// or null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 20 octets.
    pub unsafe extern "C" fn RIPEMD160(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { md32_oneshot(Md32Kind::Ripemd160, Md32::ripemd160(), d, n, md, &RIPEMD160_MD) }
    }
}

/// `MDC2_CTX`'s mirror.
fn mdc2_load(c: &MDC2_CTX) -> Mdc2 {
    Mdc2 {
        num: c.num,
        data: c.data,
        h: c.h,
        hh: c.hh,
        pad_type: c.pad_type,
    }
}

/// Copies the mirror back.
fn mdc2_store(c: &mut MDC2_CTX, m: &Mdc2) {
    c.num = m.num;
    c.data = m.data;
    c.h = m.h;
    c.hh = m.hh;
    c.pad_type = m.pad_type;
}

ffi_export! {
    /// Starts an MDC2 context (`pad_type` 1), keeping the buffer's octets. Returns 1, or 0 for
    /// null.
    ///
    /// # Safety
    /// `c` is null or valid for reads and writes of an `MDC2_CTX`.
    pub unsafe extern "C" fn MDC2_Init(c: *mut MDC2_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's struct; integers and octets, so any octets are valid values.
        let Some(c) = (unsafe { c.as_mut() }) else { return 0 };
        let mut m = mdc2_load(c);
        m.init();
        mdc2_store(c, &m);
        1
    }
}

ffi_export! {
    /// Absorbs `len` octets at `data`. Returns 1, or 0.
    ///
    /// # Safety
    /// `c` is null or an `MDC2_CTX`; `data` is null or holds `len` octets.
    pub unsafe extern "C" fn MDC2_Update(c: *mut MDC2_CTX, data: *const c_uchar, len: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { c.as_mut() }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(input) = (unsafe { bytes(data, len) }) else { return 0 };
        let mut m = mdc2_load(c);
        if m.update(input).is_err() {
            return 0;
        }
        mdc2_store(c, &m);
        1
    }
}

ffi_export! {
    /// Pads and absorbs a last block if there's one, then writes the digest to `md`. Returns
    /// 1, or 0.
    ///
    /// # Safety
    /// `md` is null or has room for 16 octets; `c` is null or an `MDC2_CTX`.
    pub unsafe extern "C" fn MDC2_Final(md: *mut c_uchar, c: *mut MDC2_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { c.as_mut() }) else { return 0 };
        if md.is_null() {
            return 0;
        }
        let mut m = mdc2_load(c);
        let Ok(mut out) = m.finish() else { return 0 };
        mdc2_store(c, &m);
        // SAFETY: the caller's room for 16 octets, and our digest.
        unsafe { ptr::copy_nonoverlapping(out.as_ptr(), md, out.len()) };
        // SAFETY: our digest.
        unsafe { cleanse(out.as_mut_ptr().cast(), out.len()) };
        1
    }
}

static MDC2_MD: StaticMd<{ size(MDC2_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The MDC2 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
    /// null.
    ///
    /// # Safety
    /// `d` is null or holds `n` octets; `md` is null or has room for 16 octets.
    pub unsafe extern "C" fn MDC2(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(input) = (unsafe { bytes(d, n) }) else { return ptr::null_mut() };
        let mut m = Mdc2 { num: 0, data: [0; 8], h: [0; 8], hh: [0; 8], pad_type: 0 };
        m.init();
        if m.update(input).is_err() {
            return ptr::null_mut();
        }
        let Ok(mut out) = m.finish() else { return ptr::null_mut() };
        let md = MDC2_MD.or(md);
        // SAFETY: the caller's room for 16 octets or the static buffer, and our digest.
        unsafe { ptr::copy_nonoverlapping(out.as_ptr(), md, out.len()) };
        // SAFETY: our digest.
        unsafe { cleanse(out.as_mut_ptr().cast(), out.len()) };
        md
    }
}

/// `WHIRLPOOL_CTX`'s mirror.
fn whirlpool_load(c: &WHIRLPOOL_CTX) -> Whirlpool {
    Whirlpool {
        // SAFETY: every octet pattern is a valid value of the union's octet view.
        h: unsafe { c.H.c },
        data: c.data,
        bitoff: c.bitoff,
        bitlen: c.bitlen.map(|v| u64::try_from(v).unwrap_or(u64::MAX)),
    }
}

/// Copies the mirror back, field by field (keeping the struct's padding as it was).
fn whirlpool_store(c: &mut WHIRLPOOL_CTX, m: &Whirlpool) {
    c.H.c = m.h;
    c.data = m.data;
    c.bitoff = m.bitoff;
    c.bitlen = m.bitlen.map(|v| usize::try_from(v).unwrap_or(usize::MAX));
}

ffi_export! {
    /// Zeroes the context. Returns 1, or 0 for null.
    ///
    /// # Safety
    /// `c` is null or valid for writes of a `WHIRLPOOL_CTX`.
    pub unsafe extern "C" fn WHIRLPOOL_Init(c: *mut WHIRLPOOL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if c.is_null() {
            return 0;
        }
        // SAFETY: the caller's struct, valid for a write of its size.
        unsafe { c.write_bytes(0, 1) };
        1
    }
}

ffi_export! {
    /// Absorbs the last `bits` bits of the `bits.div_ceil(8)` octets at `inp`: when `bits`
    /// isn't a multiple of 8, the first octet's low-order bits.
    ///
    /// # Safety
    /// `c` is null or a `WHIRLPOOL_CTX`; `inp` is null or holds `bits.div_ceil(8)` octets.
    pub unsafe extern "C" fn WHIRLPOOL_BitUpdate(c: *mut WHIRLPOOL_CTX, inp: *const c_void, bits: usize)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { c.as_mut() }) else { return };
        // SAFETY: the caller's guarantee.
        let Some(input) = (unsafe { bytes(inp.cast(), bits.div_ceil(8)) }) else { return };
        let mut m = whirlpool_load(c);
        if m.bit_update(input, bits).is_ok() {
            whirlpool_store(c, &m);
        }
    }
}

ffi_export! {
    /// Absorbs `bytes` octets at `inp`. Returns 1, or 0.
    ///
    /// # Safety
    /// `c` is null or a `WHIRLPOOL_CTX`; `inp` is null or holds `bytes` octets.
    pub unsafe extern "C" fn WHIRLPOOL_Update(c: *mut WHIRLPOOL_CTX, inp: *const c_void, bytes: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if bytes == 0 {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { c.as_mut() }) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(input) = (unsafe { self::bytes(inp.cast(), bytes) }) else { return 0 };
        let Some(bits) = bytes.checked_mul(8) else { return 0 };
        let mut m = whirlpool_load(c);
        if m.bit_update(input, bits).is_err() {
            return 0;
        }
        whirlpool_store(c, &m);
        1
    }
}

ffi_export! {
    /// Finishes, then writes the digest to `md` and zeroes the context. Returns 1; or 0, for
    /// null or a corrupt count before finishing, and for a null `md` after (as OpenSSL, which
    /// then keeps the context).
    ///
    /// # Safety
    /// `md` is null or has room for 64 octets; `c` is null or a `WHIRLPOOL_CTX`.
    pub unsafe extern "C" fn WHIRLPOOL_Final(md: *mut c_uchar, c: *mut WHIRLPOOL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(ctx) = (unsafe { c.as_mut() }) else { return 0 };
        let mut m = whirlpool_load(ctx);
        if m.finish().is_err() {
            return 0;
        }
        whirlpool_store(ctx, &m);
        if md.is_null() {
            return 0;
        }
        // SAFETY: the caller's room for 64 octets, and the mirror's state.
        unsafe { ptr::copy_nonoverlapping(m.h.as_ptr(), md, m.h.len()) };
        // SAFETY: the caller's context, which nothing else refers to now.
        unsafe { cleanse(c.cast(), size_of::<WHIRLPOOL_CTX>()) };
        1
    }
}

static WHIRLPOOL_MD: StaticMd<{ size(WHIRLPOOL_DIGEST_LENGTH) }> = StaticMd::new();

ffi_export! {
    /// The Whirlpool digest of `bytes` octets at `inp`, into `md` or a static buffer. Returns
    /// where it is, or null.
    ///
    /// # Safety
    /// `inp` is null or holds `bytes` octets; `md` is null or has room for 64 octets.
    pub unsafe extern "C" fn WHIRLPOOL(inp: *const c_void, bytes: usize, md: *mut c_uchar) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(input) = (unsafe { self::bytes(inp.cast(), bytes) }) else { return ptr::null_mut() };
        let Some(bits) = bytes.checked_mul(8) else { return ptr::null_mut() };
        let mut m = Whirlpool::new();
        if m.bit_update(input, bits).is_err() || m.finish().is_err() {
            return ptr::null_mut();
        }
        let md = WHIRLPOOL_MD.or(md);
        // SAFETY: the caller's room for 64 octets or the static buffer, and the mirror's state.
        unsafe { ptr::copy_nonoverlapping(m.h.as_ptr(), md, m.h.len()) };
        md
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed context struct.
    fn zeroed<T>() -> T {
        // SAFETY: the context structs are integers and octets, for which zero is valid.
        unsafe { core::mem::zeroed() }
    }

    /// docs/DEVIATIONS.md: null contexts, inputs, and outputs fail (or do nothing) without
    /// touching anything; the reference crashes.
    #[test]
    fn nulls_fail() {
        let block = [0u8; 128];
        let mut md = [0u8; 64];
        // SAFETY: nulls are the case under test, with buffers and contexts of the right sizes,
        // for each call below.
        assert_eq!(unsafe { SHA1_Init(ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { SHA256_Update(ptr::null_mut(), block.as_ptr().cast(), 1) },
            0
        );
        // SAFETY: as above.
        assert_eq!(unsafe { SHA512_Final(md.as_mut_ptr(), ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { MDC2_Init(ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Init(ptr::null_mut()) }, 0);
        // SAFETY: as above.
        unsafe { MD5_Transform(ptr::null_mut(), block.as_ptr()) };
        // SAFETY: as above.
        unsafe { WHIRLPOOL_BitUpdate(ptr::null_mut(), block.as_ptr().cast(), 8) };

        let mut c: MD5_CTX = zeroed();
        // SAFETY: as above.
        assert_eq!(unsafe { MD5_Init(&raw mut c) }, 1);
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { MD5_Update(&raw mut c, block.as_ptr().cast(), 3) },
            1
        );
        let before = (c.A, c.Nl, c.num, c.data);
        // SAFETY: as above.
        assert_eq!(unsafe { MD5_Update(&raw mut c, ptr::null(), 5) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { MD5_Final(ptr::null_mut(), &raw mut c) }, 0);
        // SAFETY: as above.
        unsafe { MD5_Transform(&raw mut c, ptr::null()) };
        assert_eq!((c.A, c.Nl, c.num, c.data), before);
        // No input is fine, null or not.
        // SAFETY: as above.
        assert_eq!(unsafe { MD5_Update(&raw mut c, ptr::null(), 0) }, 1);

        let mut m: MDC2_CTX = zeroed();
        // SAFETY: as above.
        assert_eq!(unsafe { MDC2_Init(&raw mut m) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { MDC2_Update(&raw mut m, ptr::null(), 3) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { MDC2_Final(ptr::null_mut(), &raw mut m) }, 0);

        // SAFETY: as above.
        assert!(unsafe { MD5(ptr::null(), 3, ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { MDC2(ptr::null(), 3, ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { WHIRLPOOL(ptr::null(), 3, ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        assert!(!unsafe { MD5(ptr::null(), 0, ptr::null_mut()) }.is_null());
    }

    /// docs/DEVIATIONS.md: a count past the buffer, as in a context never initialized, is
    /// refused; the reference reads and writes past the buffer.
    #[test]
    fn corrupt_counts_are_refused() {
        let x = [0x78u8];
        let mut md = [0u8; 64];
        let mut c: SHA256_CTX = zeroed();
        // SAFETY: contexts and buffers of the right sizes, for each call below.
        assert_eq!(unsafe { SHA256_Init(&raw mut c) }, 1);
        c.num = 64;
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { SHA256_Update(&raw mut c, x.as_ptr().cast(), 1) },
            0
        );
        // SAFETY: as above.
        assert_eq!(unsafe { SHA256_Final(md.as_mut_ptr(), &raw mut c) }, 0);
        assert_eq!((c.Nl, c.num), (0, 64));

        let mut s: SHA512_CTX = zeroed();
        // SAFETY: as above.
        assert_eq!(unsafe { SHA512_Init(&raw mut s) }, 1);
        s.num = 1000;
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { SHA512_Update(&raw mut s, x.as_ptr().cast(), 1) },
            0
        );
        // SAFETY: as above.
        assert_eq!(unsafe { SHA512_Final(md.as_mut_ptr(), &raw mut s) }, 0);

        let mut m: MDC2_CTX = zeroed();
        // SAFETY: as above.
        assert_eq!(unsafe { MDC2_Init(&raw mut m) }, 1);
        m.num = 8;
        // SAFETY: as above.
        assert_eq!(unsafe { MDC2_Update(&raw mut m, x.as_ptr(), 1) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { MDC2_Final(md.as_mut_ptr(), &raw mut m) }, 0);

        let mut w: WHIRLPOOL_CTX = zeroed();
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Init(&raw mut w) }, 1);
        w.bitoff = 513;
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { WHIRLPOOL_Update(&raw mut w, x.as_ptr().cast(), 1) },
            0
        );
        // SAFETY: as above.
        unsafe { WHIRLPOOL_BitUpdate(&raw mut w, x.as_ptr().cast(), 3) };
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Final(md.as_mut_ptr(), &raw mut w) }, 0);
        assert_eq!((w.bitoff, w.bitlen[0]), (513, 0));
    }

    /// docs/DEVIATIONS.md: 505 bits, then 8: OpenSSL keeps 513 bits, writing past its buffer,
    /// and its digest is wrong; here the block is compressed, and the digest is the bits'
    /// (checked against the same bits fed as whole octets).
    #[test]
    fn whirlpool_bits_cross_blocks() {
        let msg: Vec<u8> = (0..70u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let mut one = [0u8; 64];
        let mut two = [0u8; 64];
        let mut w: WHIRLPOOL_CTX = zeroed();
        // SAFETY: a context, buffers, and input of the right sizes, for each call below.
        assert_eq!(unsafe { WHIRLPOOL_Init(&raw mut w) }, 1);
        // SAFETY: as above.
        unsafe { WHIRLPOOL_BitUpdate(&raw mut w, msg.as_ptr().cast(), 505) };
        // SAFETY: as above.
        unsafe { WHIRLPOOL_BitUpdate(&raw mut w, msg[64..].as_ptr().cast(), 8) };
        assert_eq!((w.bitoff, w.bitlen[0]), (1, 513));
        // SAFETY: as above.
        unsafe { WHIRLPOOL_BitUpdate(&raw mut w, msg[65..].as_ptr().cast(), 7) };
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Final(one.as_mut_ptr(), &raw mut w) }, 1);

        // The same 520 bits as whole octets: each update gives the low-order bits of its
        // octets taken as one big-endian number.
        let mut bits = Vec::new();
        for (octets, n) in [(&msg[..64], 505), (&msg[64..65], 8), (&msg[65..66], 7)] {
            let all: Vec<bool> = octets
                .iter()
                .flat_map(|b| (0..8).rev().map(move |i| b >> i & 1 == 1))
                .collect();
            bits.extend_from_slice(&all[all.len() - n..]);
        }
        let bits: Vec<u8> = bits
            .chunks(8)
            .map(|c| c.iter().fold(0, |a, &b| a << 1 | u8::from(b)))
            .collect();
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Init(&raw mut w) }, 1);
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { WHIRLPOOL_Update(&raw mut w, bits.as_ptr().cast(), bits.len()) },
            1
        );
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Final(two.as_mut_ptr(), &raw mut w) }, 1);
        assert_eq!(one, two);
    }

    /// docs/DEVIATIONS.md: 4 bits, then 64 whole octets: OpenSSL takes them bit by bit and its
    /// last step runs past the block, as above; here the digest is the bits' (with 4 more, so
    /// they make whole octets to check against).
    #[test]
    fn whirlpool_octets_after_bits_cross_blocks() {
        let msg: Vec<u8> = (0..70u8)
            .map(|i| i.wrapping_mul(7).wrapping_add(3))
            .collect();
        let mut one = [0u8; 64];
        let mut two = [0u8; 64];
        let mut w: WHIRLPOOL_CTX = zeroed();
        // SAFETY: a context, buffers, and input of the right sizes, for each call below.
        assert_eq!(unsafe { WHIRLPOOL_Init(&raw mut w) }, 1);
        // SAFETY: as above.
        unsafe { WHIRLPOOL_BitUpdate(&raw mut w, msg.as_ptr().cast(), 4) };
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { WHIRLPOOL_Update(&raw mut w, msg[1..].as_ptr().cast(), 64) },
            1
        );
        assert_eq!((w.bitoff, w.bitlen[0]), (4, 516));
        // SAFETY: as above.
        unsafe { WHIRLPOOL_BitUpdate(&raw mut w, msg[65..].as_ptr().cast(), 4) };
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Final(one.as_mut_ptr(), &raw mut w) }, 1);

        // The same 520 bits as whole octets: msg[0]'s low 4 bits, msg[1..65], msg[65]'s low 4.
        let mut bits = vec![msg[0] << 4 | msg[1] >> 4];
        for pair in msg[1..65].windows(2) {
            bits.push(pair[0] << 4 | pair[1] >> 4);
        }
        bits.push(msg[64] << 4 | (msg[65] & 0x0f));
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Init(&raw mut w) }, 1);
        // SAFETY: as above.
        assert_eq!(
            // SAFETY: as above.
            unsafe { WHIRLPOOL_Update(&raw mut w, bits.as_ptr().cast(), bits.len()) },
            1
        );
        // SAFETY: as above.
        assert_eq!(unsafe { WHIRLPOOL_Final(two.as_mut_ptr(), &raw mut w) }, 1);
        assert_eq!(one, two);
    }
}

/// MD2, which only the Fedora profile offers (Fedora's libcrypto exports it; upstream's default
/// build, and so rustyssl's, doesn't). OpenSSL's headers declare it only without
/// `OPENSSL_NO_MD2`, so its struct and constants aren't generated: they're `md2.h`'s.
#[cfg(feature = "fedora")]
pub(crate) mod md2 {
    use core::ffi::{c_char, c_int, c_uchar, c_uint};
    use core::ptr;

    use rustyssl_abi::ERR_LIB_CRYPTO;
    use rustyssl_crypto::lowlevel::hash::{MD2_BLOCK, Md2};

    use super::super::StaticMd;
    use crate::ffi::{bytes, ffi_export};
    use crate::mem::cleanse;

    /// `MD2_DIGEST_LENGTH` and `MD2_BLOCK` (`md2.h`).
    pub(crate) const MD2_DIGEST_LENGTH: c_int = 16;

    /// `MD2_CTX` (`md2.h`): `MD2_INT` is `unsigned int`.
    #[repr(C)]
    #[allow(non_camel_case_types)]
    pub(crate) struct MD2_CTX {
        num: c_uint,
        data: [c_uchar; MD2_BLOCK],
        cksm: [c_uint; MD2_BLOCK],
        state: [c_uint; MD2_BLOCK],
    }

    const _: () = assert!(core::mem::size_of::<MD2_CTX>() == 4 + 16 + 64 + 64);

    fn load(c: &MD2_CTX) -> Md2 {
        Md2 { num: c.num, data: c.data, cksm: c.cksm, state: c.state }
    }

    fn store(c: &mut MD2_CTX, m: &Md2) {
        c.num = m.num;
        c.data = m.data;
        c.cksm = m.cksm;
        c.state = m.state;
    }

    ffi_export! {
        /// `md2(int)`: the width of `MD2_INT`.
        ///
        /// # Safety
        /// No preconditions.
        pub unsafe extern "C" fn MD2_options() -> *const c_char
        where failure = ptr::null(), library = ERR_LIB_CRYPTO
        {
            c"md2(int)".as_ptr()
        }
    }

    ffi_export! {
        /// Starts an MD2 context. Returns 1, or 0 for null.
        ///
        /// # Safety
        /// `c` is null or valid for writes of an `MD2_CTX`.
        pub unsafe extern "C" fn MD2_Init(c: *mut MD2_CTX) -> c_int
        where failure = 0, library = ERR_LIB_CRYPTO
        {
            // SAFETY: the caller's struct; integers and octets, so any octets are valid values.
            let Some(c) = (unsafe { c.as_mut() }) else { return 0 };
            store(c, &Md2::default());
            1
        }
    }

    ffi_export! {
        /// Absorbs `len` octets at `data`. Returns 1, or 0.
        ///
        /// # Safety
        /// `c` is null or an `MD2_CTX`; `data` is null or holds `len` octets.
        pub unsafe extern "C" fn MD2_Update(c: *mut MD2_CTX, data: *const c_uchar, len: usize) -> c_int
        where failure = 0, library = ERR_LIB_CRYPTO
        {
            // SAFETY: the caller's guarantee.
            let Some(c) = (unsafe { c.as_mut() }) else { return 0 };
            // SAFETY: the caller's guarantee.
            let Some(input) = (unsafe { bytes(data, len) }) else { return 0 };
            let mut m = load(c);
            if m.update(input).is_err() {
                return 0;
            }
            store(c, &m);
            1
        }
    }

    ffi_export! {
        /// Pads, absorbs the checksum and writes the digest to `md`; the context is cleared.
        /// Returns 1, or 0.
        ///
        /// # Safety
        /// `md` is null or has room for 16 octets; `c` is null or an `MD2_CTX`.
        pub unsafe extern "C" fn MD2_Final(md: *mut c_uchar, c: *mut MD2_CTX) -> c_int
        where failure = 0, library = ERR_LIB_CRYPTO
        {
            // SAFETY: the caller's guarantee.
            let Some(c) = (unsafe { c.as_mut() }) else { return 0 };
            if md.is_null() {
                return 0;
            }
            let mut m = load(c);
            let Ok(mut out) = m.finish() else { return 0 };
            store(c, &m);
            // SAFETY: the caller's room for 16 octets, and our digest.
            unsafe { ptr::copy_nonoverlapping(out.as_ptr(), md, out.len()) };
            // SAFETY: our digest.
            unsafe { cleanse(out.as_mut_ptr().cast(), out.len()) };
            1
        }
    }

    static MD2_MD: StaticMd<{ MD2_BLOCK }> = StaticMd::new();

    ffi_export! {
        /// The MD2 of `n` octets at `d`, into `md` or a static buffer. Returns where it is, or
        /// null.
        ///
        /// # Safety
        /// `d` is null or holds `n` octets; `md` is null or has room for 16 octets.
        pub unsafe extern "C" fn MD2(d: *const c_uchar, n: usize, md: *mut c_uchar) -> *mut c_uchar
        where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
        {
            // SAFETY: the caller's guarantee.
            let Some(input) = (unsafe { bytes(d, n) }) else { return ptr::null_mut() };
            let mut m = Md2::default();
            if m.update(input).is_err() {
                return ptr::null_mut();
            }
            let Ok(mut out) = m.finish() else { return ptr::null_mut() };
            let md = MD2_MD.or(md);
            // SAFETY: the caller's room for 16 octets or the static buffer, and our digest.
            unsafe { ptr::copy_nonoverlapping(out.as_ptr(), md, out.len()) };
            // SAFETY: our digest.
            unsafe { cleanse(out.as_mut_ptr().cast(), out.len()) };
            md
        }
    }
}

#[cfg(all(test, feature = "fedora"))]
mod md2_tests {
    use super::md2::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn md2_low_level_and_evp() {
        let mut out = [0u8; 16];
        // SAFETY: three octets and room for 16.
        unsafe { MD2(b"abc".as_ptr(), 3, out.as_mut_ptr()) };
        assert_eq!(hex(&out), "da853b0d3f88d99b30283a69e6ded6bb");
        // SAFETY: an all-zero MD2_CTX is a valid value of its integers and octets.
        let mut c: MD2_CTX = unsafe { core::mem::zeroed() };
        // SAFETY: a live context, the message's octets, and room for 16.
        unsafe {
            assert_eq!(MD2_Init(&mut c), 1);
            assert_eq!(MD2_Update(&mut c, b"message ".as_ptr(), 8), 1);
            assert_eq!(MD2_Update(&mut c, b"digest".as_ptr(), 6), 1);
            assert_eq!(MD2_Final(out.as_mut_ptr(), &mut c), 1);
        }
        assert_eq!(hex(&out), "ab4f496bfb2a530b219ff33031fe06b0");
        // SAFETY: no preconditions.
        let options = unsafe { core::ffi::CStr::from_ptr(MD2_options()) };
        assert_eq!(options, c"md2(int)");
    }
}
