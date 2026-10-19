//! The legacy digest names (`EVP_get_digestbyname(3)`, `EVP_sha256(3)`, `EVP_MD_do_all(3)`):
//! the static digests `EVP_sha256()` and the like return, the `OBJ_NAME` table that
//! `OPENSSL_INIT_ADD_ALL_DIGESTS` fills with their names (`crypto/evp/c_alld.c`, `names.c`),
//! and the lookup through it and each context's name map.
//!
//! A static digest has no provider: it carries OpenSSL's NIDs, sizes, and flags for the digest
//! (`legacy_sha.c` and the others), `EVP_MD_up_ref` and `EVP_MD_free` do nothing to it, and
//! `EVP_DigestInit_ex` fetches the provider's digest by its short name. The table is also what
//! each context's name map starts with ([`md_nids`]) and where fetched digests find their NIDs.
//! MD4, MDC2, and Whirlpool have static digests as in OpenSSL's default build; using them
//! needs the legacy provider (9.1).

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;
use std::sync::OnceLock;

use rustyssl_abi::{
    ERR_LIB_EVP, EVP_MD, EVP_MD_FLAG_DIGALGID_ABSENT, EVP_MD_FLAG_XOF, MD4_CBLOCK,
    MD4_DIGEST_LENGTH, MD5_CBLOCK, MD5_DIGEST_LENGTH, MDC2_BLOCK, MDC2_DIGEST_LENGTH,
    NID_RSA_SHA3_224, NID_RSA_SHA3_256, NID_RSA_SHA3_384, NID_RSA_SHA3_512, NID_blake2b512,
    NID_blake2s256, NID_md4, NID_md4WithRSAEncryption, NID_md5, NID_md5_sha1,
    NID_md5WithRSAEncryption, NID_mdc2, NID_mdc2WithRSA, NID_ripemd160, NID_ripemd160WithRSA,
    NID_sha1, NID_sha1WithRSAEncryption, NID_sha3_224, NID_sha3_256, NID_sha3_384, NID_sha3_512,
    NID_sha224, NID_sha224WithRSAEncryption, NID_sha256, NID_sha256WithRSAEncryption, NID_sha384,
    NID_sha384WithRSAEncryption, NID_sha512, NID_sha512_224, NID_sha512_224WithRSAEncryption,
    NID_sha512_256, NID_sha512_256WithRSAEncryption, NID_sha512WithRSAEncryption, NID_shake128,
    NID_shake256, NID_sm3, NID_sm3WithRSAEncryption, NID_undef, NID_whirlpool, OBJ_NAME,
    OBJ_NAME_ALIAS, OBJ_NAME_TYPE_MD_METH, OPENSSL_INIT_ADD_ALL_DIGESTS, OSSL_LIB_CTX,
    RIPEMD160_CBLOCK, RIPEMD160_DIGEST_LENGTH, SHA_CBLOCK, SHA_DIGEST_LENGTH, SHA224_DIGEST_LENGTH,
    SHA256_CBLOCK, SHA256_DIGEST_LENGTH, SHA384_DIGEST_LENGTH, SHA512_CBLOCK, SHA512_DIGEST_LENGTH,
    SN_md5, SN_ripemd160, SN_sha1, SN_sha1WithRSA, SN_sha1WithRSAEncryption, WHIRLPOOL_BBLOCK,
    WHIRLPOOL_DIGEST_LENGTH,
};
use rustyssl_crypto::provided::digest::Kind;

use super::digest::{EVP_MD_fetch, EVP_MD_free, Legacy, Md, method};
use super::fetch;
use super::legacy_md_fns as fns;
use crate::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::Handle;
use crate::init::OPENSSL_init_crypto;
use crate::objects::name::{OBJ_NAME_add, OBJ_NAME_do_all, OBJ_NAME_do_all_sorted, OBJ_NAME_get};
use crate::objects::{OBJ_nid2ln, OBJ_nid2sn};
use crate::provider::Ptr;

/// `EVP_MD_FLAG_*` as the flags' type.
const fn md_flag(f: c_int) -> c_ulong {
    f.cast_unsigned() as c_ulong
}
const ABSENT: c_ulong = md_flag(EVP_MD_FLAG_DIGALGID_ABSENT);
const XOF: c_ulong = md_flag(EVP_MD_FLAG_XOF);

/// A size the provider's digest reports, as the static digests' `int` (at most 168).
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
const fn size(kind: Kind) -> c_int {
    kind.size() as c_int
}

/// A block size likewise.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
const fn block(kind: Kind) -> c_int {
    kind.block_size() as c_int
}

/// `OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_DIGESTS, NULL)`.
fn init_digests() -> c_int {
    let opts = OPENSSL_INIT_ADD_ALL_DIGESTS.cast_unsigned();
    // SAFETY: no settings.
    unsafe { OPENSSL_init_crypto(opts, ptr::null()) }
}

/// One static digest: OpenSSL's definition, made into a method on first use and never freed.
struct Static {
    nid: c_int,
    pkey_type: c_int,
    md_size: c_int,
    flags: c_ulong,
    block_size: c_int,
    /// Its C functions (`EVP_MD_meth_get_*`).
    legacy: Legacy,
    handle: OnceLock<Ptr<EVP_MD>>,
}

impl Static {
    const fn new(
        nid: c_int,
        pkey_type: c_int,
        md_size: c_int,
        flags: c_ulong,
        block_size: c_int,
        legacy: Legacy,
    ) -> Self {
        Self {
            nid,
            pkey_type,
            md_size,
            flags,
            block_size,
            legacy,
            handle: OnceLock::new(),
        }
    }

    fn get(&self) -> *const EVP_MD {
        self.handle
            .get_or_init(|| {
                let md = Md::legacy(
                    self.nid,
                    self.pkey_type,
                    self.md_size,
                    self.flags,
                    self.block_size,
                    self.legacy,
                );
                Ptr(EVP_MD::new_handle(md))
            })
            .0
            .cast_const()
    }
}

ffi_export! {
    /// MD4 (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_md4() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_md4, NID_md4WithRSAEncryption, MD4_DIGEST_LENGTH, 0, MD4_CBLOCK, fns::MD4);
        DIGEST.get()
    }
}

ffi_export! {
    /// MD5.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_md5() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_md5, NID_md5WithRSAEncryption, MD5_DIGEST_LENGTH, 0, MD5_CBLOCK, fns::MD5);
        DIGEST.get()
    }
}

ffi_export! {
    /// MD5 and SHA-1 side by side.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_md5_sha1() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_md5_sha1, NID_md5_sha1, size(Kind::Md5Sha1), 0, block(Kind::Md5Sha1), fns::MD5_SHA1);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA-1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha1() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha1, NID_sha1WithRSAEncryption, SHA_DIGEST_LENGTH, ABSENT, SHA_CBLOCK, fns::SHA1);
        DIGEST.get()
    }
}

ffi_export! {
    /// MDC-2 (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_mdc2() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_mdc2, NID_mdc2WithRSA, MDC2_DIGEST_LENGTH, 0, MDC2_BLOCK, fns::MDC2);
        DIGEST.get()
    }
}

ffi_export! {
    /// RIPEMD-160.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_ripemd160() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_ripemd160, NID_ripemd160WithRSA, RIPEMD160_DIGEST_LENGTH, 0, RIPEMD160_CBLOCK, fns::RIPEMD160);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA-224.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha224() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha224, NID_sha224WithRSAEncryption, SHA224_DIGEST_LENGTH, ABSENT, SHA256_CBLOCK, fns::SHA224);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA-256.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha256() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha256, NID_sha256WithRSAEncryption, SHA256_DIGEST_LENGTH, ABSENT, SHA256_CBLOCK, fns::SHA256);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA-384.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha384() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha384, NID_sha384WithRSAEncryption, SHA384_DIGEST_LENGTH, ABSENT, SHA512_CBLOCK, fns::SHA384);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA-512.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha512() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha512, NID_sha512WithRSAEncryption, SHA512_DIGEST_LENGTH, ABSENT, SHA512_CBLOCK, fns::SHA512);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA-512/224.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha512_224() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha512_224, NID_sha512_224WithRSAEncryption, SHA224_DIGEST_LENGTH, ABSENT, SHA512_CBLOCK, fns::SHA512_224);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA-512/256.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha512_256() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha512_256, NID_sha512_256WithRSAEncryption, SHA256_DIGEST_LENGTH, ABSENT, SHA512_CBLOCK, fns::SHA512_256);
        DIGEST.get()
    }
}

ffi_export! {
    /// Whirlpool (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_whirlpool() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_whirlpool, 0, WHIRLPOOL_DIGEST_LENGTH, 0, WHIRLPOOL_BBLOCK / 8, fns::WHIRLPOOL);
        DIGEST.get()
    }
}

ffi_export! {
    /// SM3.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sm3() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sm3, NID_sm3WithRSAEncryption, size(Kind::Sm3), 0, block(Kind::Sm3), fns::NONE);
        DIGEST.get()
    }
}

ffi_export! {
    /// BLAKE2b-512.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_blake2b512() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_blake2b512, 0, size(Kind::Blake2b512), 0, block(Kind::Blake2b512), fns::NONE);
        DIGEST.get()
    }
}

ffi_export! {
    /// BLAKE2s-256.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_blake2s256() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_blake2s256, 0, size(Kind::Blake2s256), 0, block(Kind::Blake2s256), fns::NONE);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA3-224.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha3_224() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha3_224, NID_RSA_SHA3_224, size(Kind::Sha3_224), ABSENT, block(Kind::Sha3_224), fns::NONE);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA3-256.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha3_256() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha3_256, NID_RSA_SHA3_256, size(Kind::Sha3_256), ABSENT, block(Kind::Sha3_256), fns::NONE);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA3-384.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha3_384() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha3_384, NID_RSA_SHA3_384, size(Kind::Sha3_384), ABSENT, block(Kind::Sha3_384), fns::NONE);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHA3-512.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sha3_512() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_sha3_512, NID_RSA_SHA3_512, size(Kind::Sha3_512), ABSENT, block(Kind::Sha3_512), fns::NONE);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHAKE128: its static digest has a size, 16 octets (the provider's has none).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_shake128() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_shake128, 0, 128 / 8, XOF | ABSENT, block(Kind::Shake128), fns::NONE_XOF);
        DIGEST.get()
    }
}

ffi_export! {
    /// SHAKE256: 32 octets, likewise.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_shake256() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_shake256, 0, 256 / 8, XOF | ABSENT, block(Kind::Shake256), fns::NONE_XOF);
        DIGEST.get()
    }
}

ffi_export! {
    /// The NULL digest: no NID, no output.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_md_null() -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static DIGEST: Static = Static::new(NID_undef, NID_undef, 0, 0, 0, fns::NULL_MD);
        DIGEST.get()
    }
}

/// `OBJ_NAME_add` with an alias's or digest's data. 0 on failure.
///
/// # Safety
/// `name` and `data` are NULL or strings or a live digest method.
unsafe fn add(name: *const c_char, kind: c_int, data: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee; the table keeps the pointers, which are static.
    unsafe { OBJ_NAME_add(name, kind, data) }
}

ffi_export! {
    /// Adds `md` to the digest names: its NID's short and long names, and its signature
    /// algorithm's as aliases. Returns 1, or 0 (for NULL too, docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `md` is NULL or a live digest method that outlives its names.
    pub unsafe extern "C" fn EVP_add_digest(md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(md) }) else { return 0 };
        let (nid, pkey) = (m.nid, m.pkey_type);
        // SAFETY: no preconditions.
        let name = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: static strings and the caller's method.
        if unsafe { add(name, OBJ_NAME_TYPE_MD_METH, md.cast()) } == 0 {
            return 0;
        }
        // SAFETY: no preconditions.
        let long = unsafe { OBJ_nid2ln(nid) };
        // SAFETY: as above.
        let mut r = unsafe { add(long, OBJ_NAME_TYPE_MD_METH, md.cast()) };
        if r == 0 {
            return 0;
        }
        if pkey != 0 && nid != pkey {
            let alias = OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS;
            // SAFETY: no preconditions.
            let short = unsafe { OBJ_nid2sn(pkey) };
            // SAFETY: no preconditions.
            let long = unsafe { OBJ_nid2ln(pkey) };
            // SAFETY: static strings.
            if unsafe { add(short, alias, name) } == 0 {
                return 0;
            }
            // SAFETY: as above.
            r = unsafe { add(long, alias, name) };
        }
        r
    }
}

/// `EVP_add_digest_alias`.
///
/// # Safety
/// Both are static strings.
unsafe fn alias(name: &'static core::ffi::CStr, alias: &'static core::ffi::CStr) {
    // SAFETY: the caller's guarantee.
    unsafe {
        add(
            alias.as_ptr(),
            OBJ_NAME_TYPE_MD_METH | OBJ_NAME_ALIAS,
            name.as_ptr(),
        )
    };
}

/// A step of `openssl_add_all_digests_int`.
enum Add {
    Digest(unsafe extern "C" fn() -> *const EVP_MD),
    Alias(&'static core::ffi::CStr, &'static core::ffi::CStr),
}

/// `openssl_add_all_digests_int`: the static digests and their aliases, in OpenSSL's order.
pub(crate) fn add_all_digests() {
    let steps = [
        Add::Digest(EVP_md4),
        Add::Digest(EVP_md5),
        Add::Alias(SN_md5, c"ssl3-md5"),
        Add::Digest(EVP_md5_sha1),
        Add::Digest(EVP_sha1),
        Add::Alias(SN_sha1, c"ssl3-sha1"),
        Add::Alias(SN_sha1WithRSAEncryption, SN_sha1WithRSA),
        Add::Digest(EVP_mdc2),
        Add::Digest(EVP_ripemd160),
        Add::Alias(SN_ripemd160, c"ripemd"),
        Add::Alias(SN_ripemd160, c"rmd160"),
        Add::Digest(EVP_sha224),
        Add::Digest(EVP_sha256),
        Add::Digest(EVP_sha384),
        Add::Digest(EVP_sha512),
        Add::Digest(EVP_sha512_224),
        Add::Digest(EVP_sha512_256),
        Add::Digest(EVP_whirlpool),
        Add::Digest(EVP_sm3),
        Add::Digest(EVP_blake2b512),
        Add::Digest(EVP_blake2s256),
        Add::Digest(EVP_sha3_224),
        Add::Digest(EVP_sha3_256),
        Add::Digest(EVP_sha3_384),
        Add::Digest(EVP_sha3_512),
        Add::Digest(EVP_shake128),
        Add::Digest(EVP_shake256),
    ];
    for step in steps {
        match step {
            Add::Digest(get) => {
                // SAFETY: a getter without preconditions.
                let md = unsafe { get() };
                // SAFETY: a static method.
                unsafe { EVP_add_digest(md) };
            }
            // SAFETY: static strings.
            Add::Alias(name, other) => unsafe { alias(name, other) },
        }
    }
}

/// The digest an `OBJ_NAME` entry's name resolves to (following aliases), or NULL.
///
/// # Safety
/// `entry` is a live entry of the table.
unsafe fn resolve(entry: *const OBJ_NAME) -> *const EVP_MD {
    // SAFETY: the caller's guarantee.
    let e = unsafe { &*entry };
    // SAFETY: the entry's name and type.
    unsafe { OBJ_NAME_get(e.name, e.type_) }.cast()
}

ffi_callback! {
    /// Collects the NID of each digest entry's digest into a `Vec<c_int>`.
    ///
    /// # Safety
    /// `entry` is a live entry; `arg` is a `Vec<c_int>`.
    pub(crate) unsafe extern "C" fn collect_nid(entry: *const OBJ_NAME, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let md = unsafe { resolve(entry) };
        // SAFETY: the table's digest methods.
        if let Some(m) = unsafe { method(md) } {
            // SAFETY: the caller's guarantee.
            unsafe { &mut *arg.cast::<Vec<c_int>>() }.push(m.nid);
        }
    }
}

/// The NIDs of the digest names (`get_legacy_md_names`), in the table's order, after
/// `OPENSSL_INIT_ADD_ALL_DIGESTS`: what each context's name map starts with.
pub(crate) fn md_nids() -> Vec<c_int> {
    init_digests();
    let mut nids: Vec<c_int> = Vec::new();
    // SAFETY: the callback takes the vector.
    unsafe {
        OBJ_NAME_do_all(
            OBJ_NAME_TYPE_MD_METH,
            Some(collect_nid),
            (&raw mut nids).cast(),
        )
    };
    nids
}

/// `ossl_namemap_doall_names` with `digest_from_name`: the first of a number's names that's
/// a digest name.
fn digest_from_names(libctx: *mut OSSL_LIB_CTX, id: u32) -> *const EVP_MD {
    // SAFETY: the caller's context (NULL or live).
    for n in unsafe { fetch::names_in_libctx(libctx, id) } {
        let Ok(c) = std::ffi::CString::new(n) else {
            continue;
        };
        // SAFETY: a string and a type.
        let md = unsafe { OBJ_NAME_get(c.as_ptr(), OBJ_NAME_TYPE_MD_METH) };
        if !md.is_null() {
            return md.cast();
        }
    }
    ptr::null()
}

/// `evp_get_digestbyname_ex`: the digest named `name`, looking up its other names in
/// `libctx`'s name map (fetching once there to learn a new name). NULL if there's none.
///
/// # Safety
/// `libctx` is NULL or a live library context; `name` is NULL or a string.
pub(crate) unsafe fn get_digestbyname_ex(
    libctx: *mut OSSL_LIB_CTX,
    name: *const c_char,
) -> *const EVP_MD {
    if init_digests() == 0 {
        return ptr::null();
    }
    // SAFETY: the caller's guarantee.
    let dp = unsafe { OBJ_NAME_get(name, OBJ_NAME_TYPE_MD_METH) };
    if !dp.is_null() {
        return dp.cast();
    }
    let bytes = if name.is_null() {
        &b""[..]
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes()
    };
    // SAFETY: the caller's guarantee.
    let mut id = unsafe { fetch::number_in_libctx(libctx, bytes) };
    if id == 0 {
        // The name may not be known yet: a fetch teaches the context its names.
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the caller's context and name.
        let fetched = unsafe { EVP_MD_fetch(libctx, name, ptr::null()) };
        // SAFETY: the fetched reference, or NULL.
        unsafe { EVP_MD_free(fetched) };
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: as above.
        id = unsafe { fetch::number_in_libctx(libctx, bytes) };
        if id == 0 {
            return ptr::null();
        }
    }
    digest_from_names(libctx, id)
}

ffi_export! {
    /// The digest named `name`: a digest name's, or else the first digest name among the
    /// names `name` shares a number with in the default context's name map (fetching once to
    /// learn the name if it's new). NULL if there's none.
    ///
    /// # Safety
    /// `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_get_digestbyname(name: *const c_char) -> *const EVP_MD
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the default context; the caller's guarantee.
        unsafe { get_digestbyname_ex(ptr::null_mut(), name) }
    }
}

/// `EVP_MD_do_all`'s callback.
type DoAllFn = unsafe extern "C" fn(*const EVP_MD, *const c_char, *const c_char, *mut c_void);

/// The callback and its argument (`struct doall_md`).
struct DoAll {
    fn_: DoAllFn,
    arg: *mut c_void,
}

ffi_callback! {
    /// `do_all_md_fn`: an alias as `(NULL, alias, name)`, a digest as `(md, name, NULL)`.
    ///
    /// # Safety
    /// `entry` is a live entry; `arg` is a `DoAll`.
    pub(crate) unsafe extern "C" fn do_all_md(entry: *const OBJ_NAME, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let e = unsafe { &*entry };
        // SAFETY: as above.
        let d = unsafe { &*arg.cast::<DoAll>() };
        if e.alias != 0 {
            // SAFETY: the application's callback with the entry's strings.
            unsafe { (d.fn_)(ptr::null(), e.name, e.data, d.arg) };
        } else {
            // SAFETY: as above, with the entry's digest.
            unsafe { (d.fn_)(e.data.cast(), e.name, ptr::null(), d.arg) };
        }
    }
}

ffi_export! {
    /// Calls `fn_` for each digest name, in the table's order, after adding the digests.
    ///
    /// # Safety
    /// `fn_` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_MD_do_all(fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        init_digests();
        let Some(f) = fn_ else { return };
        let mut d = DoAll { fn_: f, arg };
        // SAFETY: the callback takes the `DoAll`.
        unsafe { OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, Some(do_all_md), (&raw mut d).cast()) };
    }
}

ffi_export! {
    /// As [`EVP_MD_do_all`], in order of name.
    ///
    /// # Safety
    /// As for [`EVP_MD_do_all`].
    pub unsafe extern "C" fn EVP_MD_do_all_sorted(fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        init_digests();
        let Some(f) = fn_ else { return };
        let mut d = DoAll { fn_: f, arg };
        // SAFETY: the callback takes the `DoAll`.
        unsafe { OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_MD_METH, Some(do_all_md), (&raw mut d).cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_digests_are_refused() {
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_add_digest(ptr::null()) }, 0);
        // SAFETY: as above.
        let pkey = unsafe { super::super::digest::EVP_MD_get_pkey_type(ptr::null()) };
        assert_eq!(pkey, 0);
    }

    #[test]
    fn static_digests_outlive_frees() {
        // SAFETY: no preconditions.
        let md = unsafe { EVP_sha256() };
        for _ in 0..3 {
            // SAFETY: a static digest, whose frees do nothing.
            unsafe { EVP_MD_free(md.cast_mut()) };
        }
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_sha256() }, md);
        // SAFETY: the live static digest.
        let m = unsafe { method(md) }.map(|m| (m.nid, m.pkey_type));
        assert_eq!(m, Some((NID_sha256, NID_sha256WithRSAEncryption)));
    }
}
