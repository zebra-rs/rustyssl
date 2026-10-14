//! The static digests' own C functions (`legacy_sha.c`, `legacy_md5.c`, ...): `init`,
//! `update`, `final`, and for SHA-1 and MD5+SHA-1 the SSLv3 `ctrl`, each running the
//! low-level function of the digest on the context's `md_data` (`SHA256_Init(md_data)`, ...).
//! `EVP_MD_meth_get_*` reports them, and a copy of a static digest (`EVP_MD_meth_dup`) runs
//! them, on state of the size the application gives it (`EVP_MD_meth_set_app_datasize`;
//! OpenSSL's static digests have none of their own).
//!
//! Only the digests whose state is a public structure (`MD5_CTX`, `SHA256_CTX`, `SHA512_CTX`
//! for SHA-512/224 and /256, `MDC2_CTX`, `WHIRLPOOL_CTX`, ...) have them here: SHA-3, SHAKE,
//! BLAKE2, and SM3 keep theirs in structures OpenSSL doesn't publish, which an application
//! can't size, so they report none (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, EVP_CTRL_SSL3_MASTER_SECRET, EVP_MD_CTX, MD4_CTX, MD5_CTX, MDC2_CTX,
    RIPEMD160_CTX, SHA_CTX, SHA256_CTX, SHA512_CTX, WHIRLPOOL_CTX,
};

use super::digest::Legacy;
use super::md_ctx::EVP_MD_CTX_get0_md_data;
use crate::ffi::ffi_callback;
use crate::lowlevel::hash::{
    MD4_Final, MD4_Init, MD4_Update, MD5_Final, MD5_Init, MD5_Update, MDC2_Final, MDC2_Init,
    MDC2_Update, RIPEMD160_Final, RIPEMD160_Init, RIPEMD160_Update, SHA1_Final, SHA1_Init,
    SHA1_Update, SHA224_Final, SHA224_Init, SHA224_Update, SHA256_Final, SHA256_Init,
    SHA256_Update, SHA384_Final, SHA384_Init, SHA384_Update, SHA512_Final, SHA512_Init,
    SHA512_Update, WHIRLPOOL_Final, WHIRLPOOL_Init, WHIRLPOOL_Update,
};
use crate::mem::OPENSSL_cleanse;

/// The context's `md_data`, as the state type `T`.
///
/// # Safety
/// `ctx` is NULL or a live digest context.
unsafe fn state<T>(ctx: *mut EVP_MD_CTX) -> *mut T {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_MD_CTX_get0_md_data(ctx) }.cast()
}

/// `init`, `update`, and `final` of a digest whose state is `$ctx`, over its low-level
/// functions, and the table of them.
macro_rules! legacy_md {
    ($table:ident, $init:ident, $update:ident, $final_:ident, $ctx:ty, $Init:path, $Update:path, $Final:path, $ctrl:expr) => {
        ffi_callback! {
            /// The static digest's `init`: its low-level `Init` on the context's state.
            ///
            /// # Safety
            /// `ctx` is a live digest context whose state is the digest's.
            pub(crate) unsafe extern "C" fn $init(ctx: *mut EVP_MD_CTX) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { $Init(state::<$ctx>(ctx)) }
            }
        }

        ffi_callback! {
            /// The static digest's `update`: its low-level `Update` on the context's state.
            ///
            /// # Safety
            /// `ctx` is a live digest context whose state is the digest's; `data` holds
            /// `count` octets.
            pub(crate) unsafe extern "C" fn $update(ctx: *mut EVP_MD_CTX, data: *const c_void, count: usize) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { $Update(state::<$ctx>(ctx), data.cast(), count) }
            }
        }

        ffi_callback! {
            /// The static digest's `final`: its low-level `Final` of the context's state.
            ///
            /// # Safety
            /// `ctx` is a live digest context whose state is the digest's; `md` has room for
            /// the digest.
            pub(crate) unsafe extern "C" fn $final_(ctx: *mut EVP_MD_CTX, md: *mut u8) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { $Final(md, state::<$ctx>(ctx)) }
            }
        }

        /// The digest's C functions.
        pub(crate) const $table: Legacy = Legacy {
            ctx_size: 0,
            init: Some($init),
            update: Some($update),
            final_: Some($final_),
            copy: None,
            cleanup: None,
            ctrl: $ctrl,
        };
    };
}

legacy_md!(
    MD4, md4_init, md4_update, md4_final, MD4_CTX, MD4_Init, MD4_Update, MD4_Final, None
);
legacy_md!(
    MD5, md5_init, md5_update, md5_final, MD5_CTX, MD5_Init, MD5_Update, MD5_Final, None
);
legacy_md!(
    SHA1,
    sha1_init,
    sha1_update,
    sha1_final,
    SHA_CTX,
    SHA1_Init,
    SHA1_Update,
    SHA1_Final,
    Some(sha1_int_ctrl)
);
legacy_md!(
    MDC2,
    mdc2_init,
    mdc2_update,
    mdc2_final,
    MDC2_CTX,
    MDC2_Init,
    MDC2_Update,
    MDC2_Final,
    None
);
legacy_md!(
    RIPEMD160,
    ripe_init,
    ripe_update,
    ripe_final,
    RIPEMD160_CTX,
    RIPEMD160_Init,
    RIPEMD160_Update,
    RIPEMD160_Final,
    None
);
legacy_md!(
    SHA224,
    sha224_init,
    sha224_update,
    sha224_final,
    SHA256_CTX,
    SHA224_Init,
    SHA224_Update,
    SHA224_Final,
    None
);
legacy_md!(
    SHA256,
    sha256_init,
    sha256_update,
    sha256_final,
    SHA256_CTX,
    SHA256_Init,
    SHA256_Update,
    SHA256_Final,
    None
);
legacy_md!(
    SHA384,
    sha384_init,
    sha384_update,
    sha384_final,
    SHA512_CTX,
    SHA384_Init,
    SHA384_Update,
    SHA384_Final,
    None
);
legacy_md!(
    SHA512,
    sha512_init,
    sha512_update,
    sha512_final,
    SHA512_CTX,
    SHA512_Init,
    SHA512_Update,
    SHA512_Final,
    None
);
legacy_md!(
    SHA512_224,
    sha512_224_int_init,
    sha512_224_int_update,
    sha512_224_int_final,
    SHA512_CTX,
    sha512_224_init,
    SHA512_Update,
    SHA512_Final,
    None
);
legacy_md!(
    SHA512_256,
    sha512_256_int_init,
    sha512_256_int_update,
    sha512_256_int_final,
    SHA512_CTX,
    sha512_256_init,
    SHA512_Update,
    SHA512_Final,
    None
);
legacy_md!(
    WHIRLPOOL,
    wp_init,
    wp_update,
    wp_final,
    WHIRLPOOL_CTX,
    WHIRLPOOL_Init,
    WHIRLPOOL_Update,
    WHIRLPOOL_Final,
    None
);
legacy_md!(
    MD5_SHA1,
    md5_sha1_int_init,
    md5_sha1_int_update,
    md5_sha1_int_final,
    Md5Sha1Ctx,
    md5_sha1_init,
    md5_sha1_update,
    md5_sha1_final,
    Some(md5_sha1_int_ctrl)
);

// From the reference's `crypto/sha/sha512.c` (`sha512_224_init`, `sha512_256_init`), by a
// script.
/// `sha512_224_init`'s initial hash values.
const SHA512_224_IV: [u64; 8] = [
    0x8c3d37c819544da2,
    0x73e1996689dcd4d6,
    0x1dfab7ae32ff9c82,
    0x679dd514582f9fcf,
    0x0f6d2b697bd44da8,
    0x77e36f7304c48942,
    0x3f9d85a86a1d36c8,
    0x1112e6ad91d692a1,
];
/// `sha512_256_init`'s initial hash values.
const SHA512_256_IV: [u64; 8] = [
    0x22312194fc2bf72c,
    0x9f555fa3c84c64c2,
    0x2393b86b6f53b151,
    0x963877195940eabd,
    0x96283ee2a88effe3,
    0xbe5e1e2553863992,
    0x2b0199fc2c85b8aa,
    0x0eb72ddc81c52ca2,
];

/// `sha512_224_init` or `sha512_256_init`: SHA-512 started from `iv`, giving `md_len` octets.
///
/// # Safety
/// `c` is NULL or valid for writes of a `SHA512_CTX`.
unsafe fn sha512_t_init(c: *mut SHA512_CTX, iv: &[u64; 8], md_len: u32) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { SHA512_Init(c) } == 0 {
        return 0;
    }
    // SAFETY: as above, now initialized.
    let Some(c) = (unsafe { c.as_mut() }) else {
        return 0;
    };
    c.h = *iv;
    c.md_len = md_len;
    1
}

/// `sha512_224_init`.
///
/// # Safety
/// `c` is NULL or valid for writes of a `SHA512_CTX`.
unsafe fn sha512_224_init(c: *mut SHA512_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { sha512_t_init(c, &SHA512_224_IV, 28) }
}

/// `sha512_256_init`.
///
/// # Safety
/// `c` is NULL or valid for writes of a `SHA512_CTX`.
unsafe fn sha512_256_init(c: *mut SHA512_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { sha512_t_init(c, &SHA512_256_IV, 32) }
}

/// MD5+SHA-1's state (`MD5_SHA1_CTX`): the two digests' side by side.
#[repr(C)]
struct Md5Sha1Ctx {
    md5: MD5_CTX,
    sha1: SHA_CTX,
}

/// The two parts of an MD5+SHA-1 state, or `None` for NULL.
///
/// # Safety
/// `c` is NULL or points to an `Md5Sha1Ctx`.
unsafe fn parts(c: *mut Md5Sha1Ctx) -> Option<(*mut MD5_CTX, *mut SHA_CTX)> {
    if c.is_null() {
        return None;
    }
    // SAFETY: the caller's state, its MD5 part.
    let md5 = unsafe { &raw mut (*c).md5 };
    // SAFETY: as above, its SHA-1 part.
    let sha1 = unsafe { &raw mut (*c).sha1 };
    Some((md5, sha1))
}

/// `ossl_md5_sha1_init`.
///
/// # Safety
/// `c` is NULL or valid for writes of an `Md5Sha1Ctx`.
unsafe fn md5_sha1_init(c: *mut Md5Sha1Ctx) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((md5, sha1)) = (unsafe { parts(c) }) else {
        return 0;
    };
    // SAFETY: the state's MD5 part.
    if unsafe { MD5_Init(md5) } == 0 {
        return 0;
    }
    // SAFETY: its SHA-1 part.
    unsafe { SHA1_Init(sha1) }
}

/// `ossl_md5_sha1_update`.
///
/// # Safety
/// `c` is NULL or an `Md5Sha1Ctx`; `data` holds `count` octets.
unsafe fn md5_sha1_update(c: *mut Md5Sha1Ctx, data: *const c_void, count: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((md5, sha1)) = (unsafe { parts(c) }) else {
        return 0;
    };
    // SAFETY: the state's MD5 part and the caller's data.
    if unsafe { MD5_Update(md5, data, count) } == 0 {
        return 0;
    }
    // SAFETY: its SHA-1 part and the caller's data.
    unsafe { SHA1_Update(sha1, data, count) }
}

/// `ossl_md5_sha1_final`: the MD5 digest, then the SHA-1 one.
///
/// # Safety
/// `md` has room for 36 octets; `c` is NULL or an `Md5Sha1Ctx`.
unsafe fn md5_sha1_final(md: *mut u8, c: *mut Md5Sha1Ctx) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((md5, sha1)) = (unsafe { parts(c) }) else {
        return 0;
    };
    // SAFETY: the caller's room and the state's MD5 part.
    if unsafe { MD5_Final(md, md5) } == 0 {
        return 0;
    }
    // SAFETY: as above, past the MD5 digest's 16 octets, and its SHA-1 part.
    unsafe { SHA1_Final(md.wrapping_add(16), sha1) }
}

/// SSLv3's master secret step (RFC 6101, 5.6.8) over one digest's state: `update` the secret
/// and pad 1, keep the inner hash, start again, then `update` the secret, pad 2, and the inner
/// hash, so finishing gives the SSLv3 hash. `None` on failure.
fn ssl3_step(
    ms: &[u8],
    pad_len: usize,
    inner_len: usize,
    mut update: impl FnMut(&[u8]) -> bool,
    mut finish_into: impl FnMut(&mut [u8]) -> bool,
    mut restart: impl FnMut() -> bool,
) -> Option<()> {
    let mut inner = [0u8; 20];
    let inner = inner.get_mut(..inner_len)?;
    let pad1 = [0x36u8; 48];
    let pad2 = [0x5cu8; 48];
    let ok = update(ms)
        && update(pad1.get(..pad_len)?)
        && finish_into(inner)
        && restart()
        && update(ms)
        && update(pad2.get(..pad_len)?)
        && update(inner);
    // SAFETY: our own buffer.
    unsafe { OPENSSL_cleanse(inner.as_mut_ptr().cast(), inner.len()) };
    ok.then_some(())
}

ffi_callback! {
    /// SHA-1's `ctrl` (`ossl_sha1_ctrl`): the SSLv3 master secret step for
    /// `EVP_CTRL_SSL3_MASTER_SECRET` with a 48-octet secret; -2 for any other command.
    ///
    /// # Safety
    /// `ctx` is NULL or a live digest context whose state is a `SHA_CTX`; `ms` holds `mslen`
    /// octets.
    pub(crate) unsafe extern "C" fn sha1_int_ctrl(ctx: *mut EVP_MD_CTX, cmd: c_int, mslen: c_int, ms: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if cmd != EVP_CTRL_SSL3_MASTER_SECRET {
            return -2;
        }
        // SAFETY: the caller's guarantee.
        let sha = if ctx.is_null() { ptr::null_mut() } else { unsafe { state::<SHA_CTX>(ctx) } };
        if sha.is_null() || mslen != 48 || ms.is_null() {
            return 0;
        }
        // SAFETY: the caller's 48 octets.
        let ms = unsafe { core::slice::from_raw_parts(ms.cast::<u8>(), 48) };
        let done = ssl3_step(
            ms,
            40,
            20,
            // SAFETY: the context's SHA-1 state, for each call below.
            |d| unsafe { SHA1_Update(sha, d.as_ptr().cast(), d.len()) } != 0,
            // SAFETY: as above, with room for the 20-octet digest.
            |out| unsafe { SHA1_Final(out.as_mut_ptr(), sha) } != 0,
            // SAFETY: as above.
            || unsafe { SHA1_Init(sha) } != 0,
        );
        c_int::from(done.is_some())
    }
}

ffi_callback! {
    /// MD5+SHA-1's `ctrl` (`ossl_md5_sha1_ctrl`): the SSLv3 master secret step on both
    /// digests (pads of 48 octets for MD5, 40 for SHA-1); -2 for any other command.
    ///
    /// # Safety
    /// `ctx` is a live digest context whose state is an MD5+SHA-1 one; `ms` holds `mslen`
    /// octets.
    pub(crate) unsafe extern "C" fn md5_sha1_int_ctrl(ctx: *mut EVP_MD_CTX, cmd: c_int, mslen: c_int, ms: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if cmd != EVP_CTRL_SSL3_MASTER_SECRET {
            return -2;
        }
        // SAFETY: the caller's guarantee.
        let c = unsafe { state::<Md5Sha1Ctx>(ctx) };
        // SAFETY: the context's state.
        let Some((md5, sha)) = (unsafe { parts(c) }) else { return 0 };
        if mslen != 48 || ms.is_null() {
            return 0;
        }
        // SAFETY: the caller's 48 octets.
        let ms = unsafe { core::slice::from_raw_parts(ms.cast::<u8>(), 48) };
        // OpenSSL updates both with the secret, then each with its own pad, keeps both inner
        // hashes, starts both again, and so on.
        let mut md5_inner = [0u8; 16];
        let mut sha_inner = [0u8; 20];
        let (pad1, pad2) = ([0x36u8; 48], [0x5cu8; 48]);
        let md5_update = |d: &[u8]| {
            // SAFETY: the state's MD5 part and our data.
            unsafe { MD5_Update(md5, d.as_ptr().cast(), d.len()) != 0 }
        };
        let sha_update = |d: &[u8]| {
            // SAFETY: the state's SHA-1 part and our data.
            unsafe { SHA1_Update(sha, d.as_ptr().cast(), d.len()) != 0 }
        };
        let both = |d: &[u8]| {
            // SAFETY: the state and our data.
            unsafe { md5_sha1_update(c, d.as_ptr().cast(), d.len()) != 0 }
        };
        let ok = both(ms)
            && md5_update(&pad1)
            // SAFETY: room for the MD5 digest and the state's MD5 part.
            && unsafe { MD5_Final(md5_inner.as_mut_ptr(), md5) } != 0
            && sha_update(pad1.get(..40).unwrap_or(&[]))
            // SAFETY: room for the SHA-1 digest and the state's SHA-1 part.
            && unsafe { SHA1_Final(sha_inner.as_mut_ptr(), sha) } != 0
            // SAFETY: the state.
            && unsafe { md5_sha1_init(c) } != 0
            && both(ms)
            && md5_update(&pad2)
            && md5_update(&md5_inner)
            && sha_update(pad2.get(..40).unwrap_or(&[]))
            && sha_update(&sha_inner);
        // SAFETY: our buffers.
        unsafe { OPENSSL_cleanse(md5_inner.as_mut_ptr().cast(), 16) };
        // SAFETY: as above.
        unsafe { OPENSSL_cleanse(sha_inner.as_mut_ptr().cast(), 20) };
        c_int::from(ok)
    }
}

ffi_callback! {
    /// The null digest's `init`, `update`, and `final` (`m_null.c`): they do nothing.
    ///
    /// # Safety
    /// Always safe to call.
    pub(crate) unsafe extern "C" fn null_init(_ctx: *mut EVP_MD_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        1
    }
}

ffi_callback! {
    /// The null digest's `update`: nothing.
    ///
    /// # Safety
    /// Always safe to call.
    pub(crate) unsafe extern "C" fn null_update(_ctx: *mut EVP_MD_CTX, _data: *const c_void, _count: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        1
    }
}

ffi_callback! {
    /// The null digest's `final`: nothing.
    ///
    /// # Safety
    /// Always safe to call.
    pub(crate) unsafe extern "C" fn null_final(_ctx: *mut EVP_MD_CTX, _md: *mut u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        1
    }
}

/// A pointer's size (`sizeof(EVP_MD *)`), the null digest's state size.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "a pointer's size, 4 or 8"
)]
const POINTER_SIZE: c_int = core::mem::size_of::<*const c_void>() as c_int;

/// The null digest's C functions; its state is a pointer's size, as OpenSSL's.
pub(crate) const NULL_MD: Legacy = Legacy {
    ctx_size: POINTER_SIZE,
    init: Some(null_init),
    update: Some(null_update),
    final_: Some(null_final),
    copy: None,
    cleanup: None,
    ctrl: None,
};

/// No C functions: the digests whose state OpenSSL doesn't publish (see the module's notes).
pub(crate) const NONE: Legacy = Legacy {
    ctx_size: 0,
    init: None,
    update: None,
    final_: None,
    copy: None,
    cleanup: None,
    ctrl: None,
};
