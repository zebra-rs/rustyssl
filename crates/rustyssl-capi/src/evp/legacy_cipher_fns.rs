//! The static ciphers' own C functions (`e_aes.c`, `e_camellia.c`, `e_seed.c`, `e_bf.c`,
//! `e_cast.c`, `e_idea.c`, `e_rc2.c`, `e_des.c`, `e_des3.c`, `e_xcbc_d.c`, `e_rc4.c`,
//! `e_null.c`): `init`, `do_cipher`, and for some `ctrl` and the AlgorithmIdentifier functions,
//! which `EVP_CIPHER_meth_get_*` reports. They run on the context the way OpenSSL's do: the key
//! schedule in the context's `cipher_data` (of the size `EVP_CIPHER_impl_ctx_size` gives), the
//! chaining state in its `iv`, `num`, and `buf`, the modes the low-level functions
//! (`CRYPTO_cbc128_encrypt`, `BF_cfb64_encrypt`, ...). An engine runs them on state it allocates
//! and copies octet for octet (`dasync`), so the state is plain octets, as OpenSSL's is: the
//! public key schedules (`AES_KEY`, `DES_key_schedule`, ...) and function pointers.
//!
//! The ciphers whose state OpenSSL keeps in structures of its own (the AEAD modes, XTS, the key
//! wraps, ARIA, SM4, ChaCha20, RC4-HMAC-MD5) have functions here that fail with
//! `EVP_R_UNSUPPORTED_CIPHER` where OpenSSL's work (docs/DEVIATIONS.md): no slot OpenSSL fills
//! is left NULL, so a caller that calls what it's given doesn't call NULL. What OpenSSL
//! dereferences without checking (a context without its state, a NULL key, a schedule never
//! set) fails here instead.

use core::ffi::{c_int, c_long, c_uint, c_ulong, c_void};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    AES_KEY, ASN1_TYPE, BF_KEY, CAMELLIA_KEY, CAST_KEY, DES_cblock, DES_key_schedule, ERR_LIB_EVP,
    ERR_R_PASSED_NULL_PARAMETER, EVP_CIPH_CBC_MODE, EVP_CIPH_CCM_MODE, EVP_CIPH_CFB_MODE,
    EVP_CIPH_ECB_MODE, EVP_CIPH_FLAG_CUSTOM_CIPHER, EVP_CIPH_FLAG_LENGTH_BITS, EVP_CIPH_GCM_MODE,
    EVP_CIPH_MODE, EVP_CIPH_OCB_MODE, EVP_CIPH_OFB_MODE, EVP_CIPH_XTS_MODE, EVP_CIPHER_CTX,
    EVP_CTRL_GET_RC2_KEY_BITS, EVP_CTRL_INIT, EVP_CTRL_RAND_KEY, EVP_CTRL_SET_RC2_KEY_BITS,
    EVP_MAX_IV_LENGTH, EVP_R_AES_KEY_SETUP_FAILED, EVP_R_CAMELLIA_KEY_SETUP_FAILED,
    EVP_R_INITIALIZATION_ERROR, EVP_R_INVALID_KEY_LENGTH, EVP_R_UNSUPPORTED_CIPHER,
    EVP_R_UNSUPPORTED_KEY_SIZE, IDEA_KEY_SCHEDULE, NID_aes_128_cbc, NID_aes_128_cfb1,
    NID_aes_128_cfb8, NID_aes_128_cfb128, NID_aes_128_ctr, NID_aes_128_ecb, NID_aes_128_ofb128,
    NID_aes_192_cbc, NID_aes_192_cfb1, NID_aes_192_cfb8, NID_aes_192_cfb128, NID_aes_192_ctr,
    NID_aes_192_ecb, NID_aes_192_ofb128, NID_aes_256_cbc, NID_aes_256_cfb1, NID_aes_256_cfb8,
    NID_aes_256_cfb128, NID_aes_256_ctr, NID_aes_256_ecb, NID_aes_256_ofb128, NID_aria_128_cbc,
    NID_aria_128_cfb128, NID_aria_128_ecb, NID_aria_128_ofb128, NID_aria_192_cbc,
    NID_aria_192_cfb128, NID_aria_192_ecb, NID_aria_192_ofb128, NID_aria_256_cbc,
    NID_aria_256_cfb128, NID_aria_256_ecb, NID_aria_256_ofb128, NID_bf_cbc, NID_bf_cfb64,
    NID_bf_ecb, NID_bf_ofb64, NID_camellia_128_cbc, NID_camellia_128_cfb1, NID_camellia_128_cfb8,
    NID_camellia_128_cfb128, NID_camellia_128_ctr, NID_camellia_128_ecb, NID_camellia_128_ofb128,
    NID_camellia_192_cbc, NID_camellia_192_cfb1, NID_camellia_192_cfb8, NID_camellia_192_cfb128,
    NID_camellia_192_ctr, NID_camellia_192_ecb, NID_camellia_192_ofb128, NID_camellia_256_cbc,
    NID_camellia_256_cfb1, NID_camellia_256_cfb8, NID_camellia_256_cfb128, NID_camellia_256_ctr,
    NID_camellia_256_ecb, NID_camellia_256_ofb128, NID_cast5_cbc, NID_cast5_cfb64, NID_cast5_ecb,
    NID_cast5_ofb64, NID_chacha20_poly1305, NID_des_cbc, NID_des_cfb1, NID_des_cfb8, NID_des_cfb64,
    NID_des_ecb, NID_des_ede_cbc, NID_des_ede_cfb64, NID_des_ede_ecb, NID_des_ede_ofb64,
    NID_des_ede3_cbc, NID_des_ede3_cfb1, NID_des_ede3_cfb8, NID_des_ede3_cfb64, NID_des_ede3_ecb,
    NID_des_ede3_ofb64, NID_des_ofb64, NID_desx_cbc, NID_idea_cbc, NID_idea_cfb64, NID_idea_ecb,
    NID_idea_ofb64, NID_rc2_40_cbc, NID_rc2_64_cbc, NID_rc2_cbc, NID_rc2_cfb64, NID_rc2_ecb,
    NID_rc2_ofb64, NID_rc4, NID_rc4_40, NID_rc4_hmac_md5, NID_seed_cbc, NID_seed_cfb128,
    NID_seed_ecb, NID_seed_ofb128, NID_undef, RC2_KEY, RC4_KEY, SEED_KEY_SCHEDULE, block128_f,
};

use super::cipher::{EVP_CIPHER_get_flags, Legacy, LegacyDoCipherFn, LegacyInitFn};
use super::cipher_asn1::{EVP_CIPHER_get_asn1_iv, EVP_CIPHER_set_asn1_iv};
use super::cipher_ctx::{
    EVP_CIPHER_CTX_buf_noconst, EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_get_block_size,
    EVP_CIPHER_CTX_get_cipher_data, EVP_CIPHER_CTX_get_iv_length, EVP_CIPHER_CTX_get_key_length,
    EVP_CIPHER_CTX_get_num, EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_is_encrypting,
    EVP_CIPHER_CTX_iv_noconst, EVP_CIPHER_CTX_original_iv, EVP_CIPHER_CTX_set_key_length,
    EVP_CIPHER_CTX_set_num, EVP_CIPHER_CTX_test_flags, EVP_CipherInit_ex,
};
use crate::asn1::tpl::util::{ASN1_TYPE_get_int_octetstring, ASN1_TYPE_set_int_octetstring};
use crate::err;
use crate::ffi::ffi_callback;
use crate::lowlevel::aes::{AES_decrypt, AES_encrypt, AES_set_decrypt_key, AES_set_encrypt_key};
use crate::lowlevel::ciphers::{
    Camellia_decrypt, Camellia_encrypt, Camellia_set_key, IDEA_cbc_encrypt, IDEA_cfb64_encrypt,
    IDEA_ecb_encrypt, IDEA_ofb64_encrypt, IDEA_set_decrypt_key, IDEA_set_encrypt_key,
    SEED_cbc_encrypt, SEED_cfb128_encrypt, SEED_ecb_encrypt, SEED_ofb128_encrypt, SEED_set_key,
};
use crate::lowlevel::des::{
    DES_cfb_encrypt, DES_cfb64_encrypt, DES_ecb_encrypt, DES_ecb3_encrypt, DES_ede3_cbc_encrypt,
    DES_ede3_cfb_encrypt, DES_ede3_cfb64_encrypt, DES_ede3_ofb64_encrypt, DES_ncbc_encrypt,
    DES_ofb64_encrypt, DES_set_key_unchecked, DES_set_odd_parity, DES_xcbc_encrypt,
};
use crate::lowlevel::legacy::{
    BF_cbc_encrypt, BF_cfb64_encrypt, BF_ecb_encrypt, BF_ofb64_encrypt, BF_set_key,
    CAST_cbc_encrypt, CAST_cfb64_encrypt, CAST_ecb_encrypt, CAST_ofb64_encrypt, CAST_set_key,
    RC2_cbc_encrypt, RC2_cfb64_encrypt, RC2_ecb_encrypt, RC2_ofb64_encrypt, RC2_set_key, RC4,
    RC4_set_key,
};
use crate::lowlevel::modes::{
    CRYPTO_cbc128_decrypt, CRYPTO_cbc128_encrypt, CRYPTO_cfb128_1_encrypt, CRYPTO_cfb128_8_encrypt,
    CRYPTO_cfb128_encrypt, CRYPTO_ctr128_encrypt, CRYPTO_ofb128_encrypt,
};
use crate::rand_lib::RAND_priv_bytes;

/// `EVP_MAXCHUNK`: the most the mode functions taking a `long` length get at once.
const MAXCHUNK: usize = 1 << 30;
/// `MAXBITCHUNK` (`e_aes.c`): the most octets a 1-bit CFB call gets at once.
const MAXBITCHUNK: usize = 1 << (usize::BITS - 4);
/// `EVP_MAX_IV_LENGTH` as an array length.
const MAX_IV: usize = EVP_MAX_IV_LENGTH.cast_unsigned() as usize;

/// A pointer to the field at `offset` of the state at `d` (no access is made).
fn field<S, F>(d: *mut S, offset: usize) -> *mut F {
    d.wrapping_byte_add(offset).cast()
}

/// The context's state as `S` (`EVP_C_DATA`), or `None` (with an error) without one.
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn state<S>(ctx: *mut EVP_CIPHER_CTX) -> Option<*mut S> {
    // SAFETY: the caller's guarantee.
    let d = unsafe { EVP_CIPHER_CTX_get_cipher_data(ctx) }.cast::<S>();
    if d.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, "legacy cipher");
        return None;
    }
    Some(d)
}

/// The context's IV (the legacy `ctx->iv`), for the low-level functions.
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn iv(ctx: *mut EVP_CIPHER_CTX) -> *mut u8 {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_CIPHER_CTX_iv_noconst(ctx) }
}

/// Whether the context encrypts (1) or decrypts (0).
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn enc(ctx: *mut EVP_CIPHER_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) }
}

/// `EVP_CIPHER_CTX_get_mode`: the mode of the context's cipher.
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn mode(ctx: *mut EVP_CIPHER_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let c = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
    // SAFETY: the context's cipher, or NULL.
    let flags = unsafe { EVP_CIPHER_get_flags(c) };
    mode_of(flags)
}

/// The mode in `flags`.
fn mode_of(flags: c_ulong) -> c_int {
    let m = flags & c_ulong::try_from(EVP_CIPH_MODE).unwrap_or(0);
    c_int::try_from(m).unwrap_or(0)
}

/// Whether the context counts 1-bit CFB lengths in bits (`EVP_CIPH_FLAG_LENGTH_BITS`).
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn length_bits(ctx: *mut EVP_CIPHER_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    unsafe { EVP_CIPHER_CTX_test_flags(ctx, EVP_CIPH_FLAG_LENGTH_BITS) != 0 }
}

/// Runs `f` on the context's `num` (`EVP_CIPHER_CTX_get_num` and `_set_num` around it).
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn with_num(ctx: *mut EVP_CIPHER_CTX, f: impl FnOnce(*mut c_int)) {
    // SAFETY: the caller's guarantee.
    let mut num = unsafe { EVP_CIPHER_CTX_get_num(ctx) };
    f(&raw mut num);
    // SAFETY: as above.
    unsafe { EVP_CIPHER_CTX_set_num(ctx, num) };
}

/// The `EVP_MAXCHUNK` loop of the mode functions that take a `long` length: `f` on each chunk.
fn chunked(
    in_: *const u8,
    out: *mut u8,
    len: usize,
    mut f: impl FnMut(*const u8, *mut u8, c_long),
) {
    let mut done = 0;
    while done < len {
        let n = (len - done).min(MAXCHUNK);
        f(
            in_.wrapping_add(done),
            out.wrapping_add(done),
            c_long::try_from(n).unwrap_or(0),
        );
        done += n;
    }
}

/// `BLOCK_CIPHER_ecb_loop`: `f` at each whole block's offset, by the context's cipher's block
/// size (a partial block at the end is left, as OpenSSL leaves it).
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn ecb_loop(ctx: *mut EVP_CIPHER_CTX, len: usize, mut f: impl FnMut(usize)) {
    // SAFETY: the caller's guarantee.
    let bl = usize::try_from(unsafe { EVP_CIPHER_CTX_get_block_size(ctx) }).unwrap_or(0);
    if bl == 0 || len < bl {
        return;
    }
    let mut i = 0;
    while i <= len - bl {
        f(i);
        i += bl;
    }
}

/// Fails an init given no key (OpenSSL's reads through it).
fn no_key(function: &str) -> c_int {
    err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, function);
    0
}

/// An `init` callback over an `unsafe fn(ctx, key, enc) -> c_int`.
macro_rules! init_fn {
    ($name:ident, $imp:expr, $doc:literal) => {
        ffi_callback! {
            #[doc = $doc]
            ///
            /// # Safety
            /// `ctx` is a live cipher context whose state is the cipher's; `key` is NULL or
            /// holds the context's key length.
            pub(crate) unsafe extern "C" fn $name(ctx: *mut EVP_CIPHER_CTX, key: *const u8, iv: *const u8, enc: c_int) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                let _ = iv;
                // SAFETY: the caller's guarantee.
                unsafe { $imp(ctx, key, enc) }
            }
        }
    };
}

/// A `do_cipher` callback over an `unsafe fn(ctx, out, in, len) -> c_int`.
macro_rules! do_fn {
    ($name:ident, $imp:expr, $doc:literal) => {
        ffi_callback! {
            #[doc = $doc]
            ///
            /// # Safety
            /// `ctx` is a live cipher context whose state is the cipher's; the buffers hold
            /// `len` octets (bits, for 1-bit CFB with `EVP_CIPH_FLAG_LENGTH_BITS`).
            pub(crate) unsafe extern "C" fn $name(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, in_: *const u8, len: usize) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { $imp(ctx, out, in_, len) }
            }
        }
    };
}

/// A `ctrl` callback over an `unsafe fn(ctx, type, arg, ptr) -> c_int`.
macro_rules! ctrl_fn {
    ($name:ident, $imp:expr, $doc:literal) => {
        ffi_callback! {
            #[doc = $doc]
            ///
            /// # Safety
            /// `ctx` is a live cipher context whose state is the cipher's; `ptr` is what the
            /// command takes.
            pub(crate) unsafe extern "C" fn $name(ctx: *mut EVP_CIPHER_CTX, type_: c_int, arg: c_int, ptr: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { $imp(ctx, type_, arg, ptr) }
            }
        }
    };
}

// ---- The 128-bit block ciphers with a block function (`e_aes.c`, `e_camellia.c`) ----

/// `EVP_AES_KEY` and `EVP_CAMELLIA_KEY`: the key schedule, the block function its direction
/// chose, and the stream function OpenSSL may use (NULL here: the block function does the
/// work, with the same results).
#[repr(C)]
pub(crate) struct Key128<K> {
    ks: K,
    block: block128_f,
    stream: *const c_void,
}

/// A 128-bit block cipher family: its key setup and block functions.
trait Family128 {
    type K;
    /// The error a failed key setup raises.
    const SETUP_FAILED: c_int;
    /// Whether a key length of 0 fails first (`EVP_R_INVALID_KEY_LENGTH`), as AES's does.
    const CHECKS_LENGTH: bool;
    /// The key setup of `bits` bits, for decryption when `decrypt`: negative on failure.
    ///
    /// # Safety
    /// `key` is NULL or holds the key; `ks` is room for the schedule.
    unsafe fn set_key(key: *const u8, bits: c_int, ks: *mut Self::K, decrypt: bool) -> c_int;
    /// The block function of the direction.
    fn block(decrypt: bool) -> block128_f;
}

/// A `block128_f` over a block function taking its key type.
macro_rules! block_fn {
    ($name:ident, $f:path, $doc:literal) => {
        ffi_callback! {
            #[doc = $doc]
            ///
            /// # Safety
            /// `key` is the function's key schedule; the blocks are 16 octets.
            pub(crate) unsafe extern "C" fn $name(in_: *const u8, out: *mut u8, key: *const c_void)
            where failure = (), library = ERR_LIB_EVP
            {
                // SAFETY: the caller's guarantee.
                unsafe { $f(in_, out, key.cast()) }
            }
        }
    };
}

block_fn!(
    aes_block_enc,
    AES_encrypt,
    "`AES_encrypt` as a `block128_f`."
);
block_fn!(
    aes_block_dec,
    AES_decrypt,
    "`AES_decrypt` as a `block128_f`."
);
block_fn!(
    cmll_block_enc,
    Camellia_encrypt,
    "`Camellia_encrypt` as a `block128_f`."
);
block_fn!(
    cmll_block_dec,
    Camellia_decrypt,
    "`Camellia_decrypt` as a `block128_f`."
);

/// AES.
struct Aes;

impl Family128 for Aes {
    type K = AES_KEY;
    const SETUP_FAILED: c_int = EVP_R_AES_KEY_SETUP_FAILED;
    const CHECKS_LENGTH: bool = true;

    unsafe fn set_key(key: *const u8, bits: c_int, ks: *mut AES_KEY, decrypt: bool) -> c_int {
        if decrypt {
            // SAFETY: the caller's guarantee.
            unsafe { AES_set_decrypt_key(key, bits, ks) }
        } else {
            // SAFETY: as above.
            unsafe { AES_set_encrypt_key(key, bits, ks) }
        }
    }

    fn block(decrypt: bool) -> block128_f {
        Some(if decrypt {
            aes_block_dec
        } else {
            aes_block_enc
        })
    }
}

/// Camellia (one schedule for both directions).
struct Camellia;

impl Family128 for Camellia {
    type K = CAMELLIA_KEY;
    const SETUP_FAILED: c_int = EVP_R_CAMELLIA_KEY_SETUP_FAILED;
    const CHECKS_LENGTH: bool = false;

    unsafe fn set_key(key: *const u8, bits: c_int, ks: *mut CAMELLIA_KEY, _decrypt: bool) -> c_int {
        // SAFETY: the caller's guarantee.
        unsafe { Camellia_set_key(key, bits, ks) }
    }

    fn block(decrypt: bool) -> block128_f {
        Some(if decrypt {
            cmll_block_dec
        } else {
            cmll_block_enc
        })
    }
}

/// `aes_init_key`/`camellia_init_key`: the schedule for the direction (decryption only for
/// ECB and CBC decryption) and its block function.
///
/// # Safety
/// `ctx` is a live cipher context whose state is a `Key128<F::K>`; `key` is NULL or holds the
/// context's key length.
unsafe fn init128<F: Family128>(ctx: *mut EVP_CIPHER_CTX, key: *const u8, enc: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Key128<F::K>>(ctx) }) else {
        return 0;
    };
    // SAFETY: as above.
    let bits = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) }.saturating_mul(8);
    if F::CHECKS_LENGTH && bits <= 0 {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_KEY_LENGTH, "aes_init_key");
        return 0;
    }
    // SAFETY: as above.
    let m = unsafe { mode(ctx) };
    let decrypt = (m == EVP_CIPH_ECB_MODE || m == EVP_CIPH_CBC_MODE) && enc == 0;
    let ks = field::<_, F::K>(d, offset_of!(Key128<F::K>, ks));
    // SAFETY: the state's schedule; the caller's key.
    let ret = unsafe { F::set_key(key, bits, ks, decrypt) };
    let block = field::<_, block128_f>(d, offset_of!(Key128<F::K>, block));
    // SAFETY: the state's field.
    unsafe { block.write(F::block(decrypt)) };
    let stream = field::<_, *const c_void>(d, offset_of!(Key128<F::K>, stream));
    // SAFETY: as above.
    unsafe { stream.write(ptr::null()) };
    if ret < 0 {
        err::raise(ERR_LIB_EVP, F::SETUP_FAILED, "init_key");
        return 0;
    }
    1
}

/// The state's schedule and block function, or `None` (with an error) before a key is set.
///
/// # Safety
/// `ctx` is a live cipher context whose state is a `Key128<K>`.
unsafe fn keyed128<K>(
    ctx: *mut EVP_CIPHER_CTX,
) -> Option<(
    *const c_void,
    unsafe extern "C" fn(*const u8, *mut u8, *const c_void),
)> {
    // SAFETY: the caller's guarantee.
    let d = unsafe { state::<Key128<K>>(ctx) }?;
    let block = field::<_, block128_f>(d, offset_of!(Key128<K>, block));
    // SAFETY: the state's field (zeroed, so NULL, until set).
    let Some(f) = (unsafe { block.read() }) else {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, "legacy cipher");
        return None;
    };
    Some((
        field::<_, c_void>(d, offset_of!(Key128<K>, ks)).cast_const(),
        f,
    ))
}

/// The modes of a 128-bit cipher with a block function (`aes_*_cipher`).
#[derive(Clone, Copy)]
enum Mode128 {
    Ecb,
    Cbc,
    Ofb,
    Cfb128,
    Cfb8,
    Cfb1,
    Ctr,
}

/// `aes_<mode>_cipher` and `camellia_<mode>_cipher`.
///
/// # Safety
/// `ctx` is a live cipher context whose state is a `Key128<K>`; the buffers hold `len`
/// octets (bits, for 1-bit CFB with `EVP_CIPH_FLAG_LENGTH_BITS`).
unsafe fn do128<K>(
    m: Mode128,
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some((ks, f)) = (unsafe { keyed128::<K>(ctx) }) else {
        return 0;
    };
    let block = Some(f);
    // SAFETY: as above.
    let iv = unsafe { iv(ctx) };
    // SAFETY: as above.
    let e = unsafe { enc(ctx) };
    match m {
        Mode128::Ecb => {
            let step = |i: usize| {
                // SAFETY: a whole block within the caller's buffers; the state's schedule.
                unsafe { f(in_.wrapping_add(i), out.wrapping_add(i), ks) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { ecb_loop(ctx, len, step) };
        }
        Mode128::Cbc if e != 0 => {
            // SAFETY: the caller's buffers, the state's schedule, the context's IV.
            unsafe { CRYPTO_cbc128_encrypt(in_, out, len, ks, iv, block) };
        }
        Mode128::Cbc => {
            // SAFETY: as above.
            unsafe { CRYPTO_cbc128_decrypt(in_, out, len, ks, iv, block) };
        }
        Mode128::Ofb => {
            let op = |num: *mut c_int| {
                // SAFETY: the buffers, the schedule, the IV, and the context's `num`.
                unsafe { CRYPTO_ofb128_encrypt(in_, out, len, ks, iv, num, block) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }
        Mode128::Cfb128 => {
            let op = |num: *mut c_int| {
                // SAFETY: as above.
                unsafe { CRYPTO_cfb128_encrypt(in_, out, len, ks, iv, num, e, block) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }
        Mode128::Cfb8 => {
            let op = |num: *mut c_int| {
                // SAFETY: as above.
                unsafe { CRYPTO_cfb128_8_encrypt(in_, out, len, ks, iv, num, e, block) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }
        Mode128::Cfb1 => {
            // SAFETY: as above.
            let (bits, chunk) = if unsafe { length_bits(ctx) } {
                (true, usize::MAX)
            } else {
                (false, MAXBITCHUNK)
            };
            let mut done = 0;
            while done < len {
                let n = (len - done).min(chunk);
                let nbits = if bits { n } else { n.saturating_mul(8) };
                let (i, o) = if bits {
                    (in_, out)
                } else {
                    (in_.wrapping_add(done), out.wrapping_add(done))
                };
                let op = |num: *mut c_int| {
                    // SAFETY: as above; `n` octets are `n * 8` bits.
                    unsafe { CRYPTO_cfb128_1_encrypt(i, o, nbits, ks, iv, num, e, block) };
                };
                // SAFETY: the caller's guarantee.
                unsafe { with_num(ctx, op) };
                done += n;
            }
        }
        Mode128::Ctr => {
            // SAFETY: the caller's guarantee.
            let Ok(mut num) = c_uint::try_from(unsafe { EVP_CIPHER_CTX_get_num(ctx) }) else {
                return 0;
            };
            // SAFETY: as above.
            let buf = unsafe { EVP_CIPHER_CTX_buf_noconst(ctx) };
            // SAFETY: the buffers, the schedule, the IV, and the keystream buffer.
            unsafe { CRYPTO_ctr128_encrypt(in_, out, len, ks, iv, buf, &raw mut num, block) };
            // SAFETY: as above; `num` is under 16.
            unsafe { EVP_CIPHER_CTX_set_num(ctx, c_int::try_from(num).unwrap_or(0)) };
        }
    }
    1
}

init_fn!(aes_init, init128::<Aes>, "`aes_init_key`.");
init_fn!(cmll_init, init128::<Camellia>, "`camellia_init_key`.");

/// The `do_cipher` callbacks of the 128-bit families.
macro_rules! do128_fns {
    ($K:ty, $($name:ident => $m:ident),*) => {
        $(do_fn!($name, |c, o, i, l| do128::<$K>(Mode128::$m, c, o, i, l), "A mode function of the 128-bit block cipher (`aes_<mode>_cipher`).");)*
    };
}

do128_fns!(AES_KEY, aes_ecb => Ecb, aes_cbc => Cbc, aes_ofb => Ofb, aes_cfb => Cfb128, aes_cfb8 => Cfb8, aes_cfb1 => Cfb1, aes_ctr => Ctr);
do128_fns!(CAMELLIA_KEY, cmll_ecb => Ecb, cmll_cbc => Cbc, cmll_ofb => Ofb, cmll_cfb => Cfb128, cmll_cfb8 => Cfb8, cmll_cfb1 => Cfb1, cmll_ctr => Ctr);

// ---- The generic block-cipher macros' families: SEED, Blowfish, CAST5, IDEA, RC2 ----

/// `EVP_SEED_KEY`, `EVP_BF_KEY`, `EVP_CAST_KEY`, `EVP_IDEA_KEY`: the schedule alone.
#[repr(C)]
pub(crate) struct Ks<K> {
    ks: K,
}

/// `EVP_RC2_KEY`: the effective key bits, then the schedule.
#[repr(C)]
pub(crate) struct Rc2Key {
    key_bits: c_int,
    ks: RC2_KEY,
}

/// A family of the generic macros: its state, the schedule within it, and the low-level mode
/// functions on that schedule.
trait Generic {
    type S;
    type K;
    /// The schedule's offset in the state.
    const KS: usize;
    /// # Safety
    /// The pointers are what the low-level function takes.
    unsafe fn ecb(i: *const u8, o: *mut u8, ks: *mut Self::K, enc: c_int);
    /// # Safety
    /// As above.
    unsafe fn cbc(i: *const u8, o: *mut u8, l: c_long, ks: *mut Self::K, iv: *mut u8, enc: c_int);
    /// # Safety
    /// As above.
    unsafe fn cfb(
        i: *const u8,
        o: *mut u8,
        l: c_long,
        ks: *mut Self::K,
        iv: *mut u8,
        num: *mut c_int,
        enc: c_int,
    );
    /// # Safety
    /// As above.
    unsafe fn ofb(
        i: *const u8,
        o: *mut u8,
        l: c_long,
        ks: *mut Self::K,
        iv: *mut u8,
        num: *mut c_int,
    );
}

/// A family of the generic macros over its low-level functions.
macro_rules! generic {
    ($fam:ident, $S:ty, $K:ty, $ks:expr, |$i:ident, $o:ident, $ks_:ident, $e:ident| $ecb:expr, $cbc:path, $cfb:path, $ofb:path) => {
        struct $fam;
        impl Generic for $fam {
            type S = $S;
            type K = $K;
            const KS: usize = $ks;
            unsafe fn ecb($i: *const u8, $o: *mut u8, $ks_: *mut $K, $e: c_int) {
                // SAFETY: the caller's guarantee.
                unsafe { $ecb }
            }
            unsafe fn cbc(i: *const u8, o: *mut u8, l: c_long, ks: *mut $K, iv: *mut u8, enc: c_int) {
                // SAFETY: the caller's guarantee.
                unsafe { $cbc(i, o, l, ks, iv, enc) }
            }
            unsafe fn cfb(i: *const u8, o: *mut u8, l: c_long, ks: *mut $K, iv: *mut u8, num: *mut c_int, enc: c_int) {
                // SAFETY: the caller's guarantee.
                unsafe { $cfb(i, o, l, ks, iv, num, enc) }
            }
            unsafe fn ofb(i: *const u8, o: *mut u8, l: c_long, ks: *mut $K, iv: *mut u8, num: *mut c_int) {
                // SAFETY: the caller's guarantee.
                unsafe { $ofb(i, o, l, ks, iv, num) }
            }
        }
    };
}

generic!(
    Bf,
    Ks<BF_KEY>,
    BF_KEY,
    offset_of!(Ks<BF_KEY>, ks),
    |i, o, ks, e| BF_ecb_encrypt(i, o, ks, e),
    BF_cbc_encrypt,
    BF_cfb64_encrypt,
    BF_ofb64_encrypt
);
generic!(
    Cast,
    Ks<CAST_KEY>,
    CAST_KEY,
    offset_of!(Ks<CAST_KEY>, ks),
    |i, o, ks, e| CAST_ecb_encrypt(i, o, ks, e),
    CAST_cbc_encrypt,
    CAST_cfb64_encrypt,
    CAST_ofb64_encrypt
);
generic!(
    Idea,
    Ks<IDEA_KEY_SCHEDULE>,
    IDEA_KEY_SCHEDULE,
    offset_of!(Ks<IDEA_KEY_SCHEDULE>, ks),
    |i, o, ks, e| {
        let _ = e;
        IDEA_ecb_encrypt(i, o, ks)
    },
    IDEA_cbc_encrypt,
    IDEA_cfb64_encrypt,
    IDEA_ofb64_encrypt
);
generic!(
    Rc2,
    Rc2Key,
    RC2_KEY,
    offset_of!(Rc2Key, ks),
    |i, o, ks, e| RC2_ecb_encrypt(i, o, ks, e),
    RC2_cbc_encrypt,
    RC2_cfb64_encrypt,
    RC2_ofb64_encrypt
);

/// SEED's low-level functions take `size_t` lengths and constant schedules.
struct Seed;

impl Generic for Seed {
    type S = Ks<SEED_KEY_SCHEDULE>;
    type K = SEED_KEY_SCHEDULE;
    const KS: usize = offset_of!(Ks<SEED_KEY_SCHEDULE>, ks);

    unsafe fn ecb(i: *const u8, o: *mut u8, ks: *mut SEED_KEY_SCHEDULE, enc: c_int) {
        // SAFETY: the caller's guarantee.
        unsafe { SEED_ecb_encrypt(i, o, ks, enc) }
    }

    unsafe fn cbc(
        i: *const u8,
        o: *mut u8,
        l: c_long,
        ks: *mut SEED_KEY_SCHEDULE,
        iv: *mut u8,
        enc: c_int,
    ) {
        // SAFETY: the caller's guarantee.
        unsafe { SEED_cbc_encrypt(i, o, usize::try_from(l).unwrap_or(0), ks, iv, enc) }
    }

    unsafe fn cfb(
        i: *const u8,
        o: *mut u8,
        l: c_long,
        ks: *mut SEED_KEY_SCHEDULE,
        iv: *mut u8,
        num: *mut c_int,
        enc: c_int,
    ) {
        // SAFETY: the caller's guarantee.
        unsafe { SEED_cfb128_encrypt(i, o, usize::try_from(l).unwrap_or(0), ks, iv, num, enc) }
    }

    unsafe fn ofb(
        i: *const u8,
        o: *mut u8,
        l: c_long,
        ks: *mut SEED_KEY_SCHEDULE,
        iv: *mut u8,
        num: *mut c_int,
    ) {
        // SAFETY: the caller's guarantee.
        unsafe { SEED_ofb128_encrypt(i, o, usize::try_from(l).unwrap_or(0), ks, iv, num) }
    }
}

/// The modes of the generic macros.
#[derive(Clone, Copy)]
enum ModeG {
    Ecb,
    Cbc,
    Cfb,
    Ofb,
}

/// `<cname>_<mode>_cipher` of the generic macros.
///
/// # Safety
/// `ctx` is a live cipher context whose state is a `G::S`; the buffers hold `len` octets.
unsafe fn do_generic<G: Generic>(
    m: ModeG,
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<G::S>(ctx) }) else {
        return 0;
    };
    let ks = field::<_, G::K>(d, G::KS);
    // SAFETY: as above.
    let iv = unsafe { iv(ctx) };
    // SAFETY: as above.
    let e = unsafe { enc(ctx) };
    match m {
        ModeG::Ecb => {
            let step = |i: usize| {
                // SAFETY: a whole block within the caller's buffers; the state's schedule.
                unsafe { G::ecb(in_.wrapping_add(i), out.wrapping_add(i), ks, e) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { ecb_loop(ctx, len, step) };
        }
        ModeG::Cbc => chunked(in_, out, len, |i, o, l| {
            // SAFETY: a chunk of the caller's buffers, the state's schedule, the IV.
            unsafe { G::cbc(i, o, l, ks, iv, e) };
        }),
        ModeG::Cfb => chunked(in_, out, len, |i, o, l| {
            let op = |num: *mut c_int| {
                // SAFETY: as above, and the context's `num`.
                unsafe { G::cfb(i, o, l, ks, iv, num, e) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }),
        ModeG::Ofb => chunked(in_, out, len, |i, o, l| {
            let op = |num: *mut c_int| {
                // SAFETY: as above.
                unsafe { G::ofb(i, o, l, ks, iv, num) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }),
    }
    1
}

/// The `do_cipher` callbacks of the generic macros' families.
macro_rules! generic_fns {
    ($G:ty, $($name:ident => $m:ident),*) => {
        $(do_fn!($name, |c, o, i, l| do_generic::<$G>(ModeG::$m, c, o, i, l), "A mode function of the generic block-cipher macros (`<cname>_<mode>_cipher`).");)*
    };
}

generic_fns!(Seed, seed_ecb => Ecb, seed_cbc => Cbc, seed_cfb => Cfb, seed_ofb => Ofb);
generic_fns!(Bf, bf_ecb => Ecb, bf_cbc => Cbc, bf_cfb => Cfb, bf_ofb => Ofb);
generic_fns!(Cast, cast_ecb => Ecb, cast_cbc => Cbc, cast_cfb => Cfb, cast_ofb => Ofb);
generic_fns!(Idea, idea_ecb => Ecb, idea_cbc => Cbc, idea_cfb => Cfb, idea_ofb => Ofb);
generic_fns!(Rc2, rc2_ecb => Ecb, rc2_cbc => Cbc, rc2_cfb => Cfb, rc2_ofb => Ofb);

/// The context's key length if it's positive (or, unless `nonzero`, zero).
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn key_len(ctx: *mut EVP_CIPHER_CTX, nonzero: bool) -> Option<c_int> {
    // SAFETY: the caller's guarantee.
    let len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    (len > 0 || (!nonzero && len == 0)).then_some(len)
}

/// `seed_init_key`.
///
/// # Safety
/// As for an `init`.
unsafe fn seed_init_imp(ctx: *mut EVP_CIPHER_CTX, key: *const u8, _enc: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Ks<SEED_KEY_SCHEDULE>>(ctx) }) else {
        return 0;
    };
    if key.is_null() {
        return no_key("seed_init_key");
    }
    let ks = field::<_, SEED_KEY_SCHEDULE>(d, offset_of!(Ks<SEED_KEY_SCHEDULE>, ks));
    // SAFETY: the caller's key; the state's schedule.
    unsafe { SEED_set_key(key, ks) };
    1
}

/// `bf_init_key`.
///
/// # Safety
/// As for an `init`.
unsafe fn bf_init_imp(ctx: *mut EVP_CIPHER_CTX, key: *const u8, _enc: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Ks<BF_KEY>>(ctx) }) else {
        return 0;
    };
    // SAFETY: as above.
    let Some(len) = (unsafe { key_len(ctx, false) }) else {
        return 0;
    };
    if key.is_null() {
        return no_key("bf_init_key");
    }
    // SAFETY: the state's schedule; the caller's key of the context's key length.
    unsafe { BF_set_key(field(d, offset_of!(Ks<BF_KEY>, ks)), len, key) };
    1
}

/// `cast_init_key`.
///
/// # Safety
/// As for an `init`.
unsafe fn cast_init_imp(ctx: *mut EVP_CIPHER_CTX, key: *const u8, _enc: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Ks<CAST_KEY>>(ctx) }) else {
        return 0;
    };
    // SAFETY: as above.
    let Some(len) = (unsafe { key_len(ctx, true) }) else {
        return 0;
    };
    if key.is_null() {
        return no_key("cast_init_key");
    }
    // SAFETY: as above.
    unsafe { CAST_set_key(field(d, offset_of!(Ks<CAST_KEY>, ks)), len, key) };
    1
}

/// `idea_init_key`: OFB and CFB use the encryption schedule either way.
///
/// # Safety
/// As for an `init`.
unsafe fn idea_init_imp(ctx: *mut EVP_CIPHER_CTX, key: *const u8, enc: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Ks<IDEA_KEY_SCHEDULE>>(ctx) }) else {
        return 0;
    };
    if key.is_null() {
        return no_key("idea_init_key");
    }
    // SAFETY: as above.
    let m = unsafe { mode(ctx) };
    let ks = field::<_, IDEA_KEY_SCHEDULE>(d, offset_of!(Ks<IDEA_KEY_SCHEDULE>, ks));
    if enc != 0 || m == EVP_CIPH_OFB_MODE || m == EVP_CIPH_CFB_MODE {
        // SAFETY: the caller's key; the state's schedule.
        unsafe { IDEA_set_encrypt_key(key, ks) };
    } else {
        let mut tmp = core::mem::MaybeUninit::<IDEA_KEY_SCHEDULE>::zeroed();
        // SAFETY: the caller's key; a local schedule.
        unsafe { IDEA_set_encrypt_key(key, tmp.as_mut_ptr()) };
        // SAFETY: the local schedule and the state's.
        unsafe { IDEA_set_decrypt_key(tmp.as_mut_ptr(), ks) };
        // SAFETY: the local schedule, of its size.
        unsafe {
            crate::mem::OPENSSL_cleanse(tmp.as_mut_ptr().cast(), size_of::<IDEA_KEY_SCHEDULE>())
        };
    }
    1
}

/// `rc2_init_key`: with the effective key bits `EVP_CTRL_INIT` set.
///
/// # Safety
/// As for an `init`.
unsafe fn rc2_init_imp(ctx: *mut EVP_CIPHER_CTX, key: *const u8, _enc: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Rc2Key>(ctx) }) else {
        return 0;
    };
    if key.is_null() {
        return no_key("rc2_init_key");
    }
    let bits = field::<_, c_int>(d, offset_of!(Rc2Key, key_bits));
    // SAFETY: the state's field.
    let bits = unsafe { bits.read() };
    // SAFETY: the caller's guarantee.
    let len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
    // SAFETY: the state's schedule; the caller's key.
    unsafe { RC2_set_key(field(d, offset_of!(Rc2Key, ks)), len, key, bits) };
    1
}

init_fn!(seed_init, seed_init_imp, "`seed_init_key`.");
init_fn!(bf_init, bf_init_imp, "`bf_init_key`.");
init_fn!(cast_init, cast_init_imp, "`cast_init_key`.");
init_fn!(idea_init, idea_init_imp, "`idea_init_key`.");
init_fn!(rc2_init, rc2_init_imp, "`rc2_init_key`.");

/// `rc2_ctrl`: the effective key bits.
///
/// # Safety
/// As for a `ctrl`.
unsafe fn rc2_ctrl_imp(
    ctx: *mut EVP_CIPHER_CTX,
    type_: c_int,
    arg: c_int,
    ptr: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Rc2Key>(ctx) }) else {
        return 0;
    };
    let bits = field::<_, c_int>(d, offset_of!(Rc2Key, key_bits));
    match type_ {
        EVP_CTRL_INIT => {
            // SAFETY: the caller's guarantee.
            let len = unsafe { EVP_CIPHER_CTX_get_key_length(ctx) };
            // SAFETY: the state's field.
            unsafe { bits.write(len.saturating_mul(8)) };
            1
        }
        EVP_CTRL_GET_RC2_KEY_BITS if !ptr.is_null() => {
            // SAFETY: the state's field.
            let b = unsafe { bits.read() };
            // SAFETY: the caller's room for an `int`.
            unsafe { ptr.cast::<c_int>().write(b) };
            1
        }
        EVP_CTRL_GET_RC2_KEY_BITS => 0,
        EVP_CTRL_SET_RC2_KEY_BITS if arg > 0 => {
            // SAFETY: the state's field.
            unsafe { bits.write(arg) };
            1
        }
        EVP_CTRL_SET_RC2_KEY_BITS => 0,
        _ => -1,
    }
}

ctrl_fn!(rc2_ctrl, rc2_ctrl_imp, "`rc2_ctrl`.");

/// `rc2_meth_to_magic`: the effective key bits' version number, 0 for other bits.
///
/// # Safety
/// `ctx` is a live cipher context.
unsafe fn rc2_magic(ctx: *mut EVP_CIPHER_CTX) -> c_long {
    let mut bits: c_int = 0;
    // SAFETY: the caller's guarantee; room for the bits.
    if unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GET_RC2_KEY_BITS, 0, (&raw mut bits).cast()) }
        <= 0
    {
        return 0;
    }
    match bits {
        128 => 0x3a,
        64 => 0x78,
        40 => 0xa0,
        _ => 0,
    }
}

ffi_callback! {
    /// `rc2_set_asn1_type_and_iv`: the RC2 version and the original IV.
    ///
    /// # Safety
    /// `c` is a live cipher context; `type_` is NULL or a live `ASN1_TYPE`.
    pub(crate) unsafe extern "C" fn rc2_set_asn1(c: *mut EVP_CIPHER_CTX, type_: *mut ASN1_TYPE) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        if type_.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let num = unsafe { rc2_magic(c) };
        // SAFETY: as above.
        let j = unsafe { EVP_CIPHER_CTX_get_iv_length(c) };
        // SAFETY: as above.
        let oiv = unsafe { EVP_CIPHER_CTX_original_iv(c) };
        // SAFETY: the caller's type; the context's original IV, of its IV length.
        unsafe { ASN1_TYPE_set_int_octetstring(type_, num, oiv.cast_mut(), j) }
    }
}

ffi_callback! {
    /// `rc2_get_asn1_type_and_iv`: the effective key bits from the version, and the IV.
    ///
    /// # Safety
    /// `c` is a live cipher context; `type_` is NULL or a live `ASN1_TYPE`.
    pub(crate) unsafe extern "C" fn rc2_get_asn1(c: *mut EVP_CIPHER_CTX, type_: *mut ASN1_TYPE) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        if type_.is_null() {
            return 0;
        }
        let mut num: c_long = 0;
        let mut ivbuf = [0u8; MAX_IV];
        // SAFETY: the caller's guarantee.
        let l = unsafe { EVP_CIPHER_CTX_get_iv_length(c) };
        if usize::try_from(l).map_or(true, |l| l > MAX_IV) {
            return -1;
        }
        // SAFETY: the caller's type; room for `l` octets.
        let i = unsafe { ASN1_TYPE_get_int_octetstring(type_, &raw mut num, ivbuf.as_mut_ptr(), l) };
        if i != l {
            return -1;
        }
        let key_bits = match num {
            0x3a => 128,
            0x78 => 64,
            0xa0 => 40,
            _ => {
                err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_KEY_SIZE, "rc2_magic_to_meth");
                return -1;
            }
        };
        if i > 0 {
            // SAFETY: the context; the IV read above.
            let ok = unsafe { EVP_CipherInit_ex(c, ptr::null(), ptr::null_mut(), ptr::null(), ivbuf.as_ptr(), -1) };
            if ok == 0 {
                return -1;
            }
        }
        // SAFETY: the context.
        if unsafe { EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_SET_RC2_KEY_BITS, key_bits, ptr::null_mut()) } <= 0 {
            return -1;
        }
        // SAFETY: as above.
        if unsafe { EVP_CIPHER_CTX_set_key_length(c, key_bits / 8) } <= 0 {
            return -1;
        }
        i
    }
}

// ---- DES (`e_des.c`, `e_des3.c`, `e_xcbc_d.c`) ----

/// `EVP_DES_KEY`: the schedule, and the stream function OpenSSL may use (NULL here).
#[repr(C)]
pub(crate) struct DesKey {
    ks: DES_key_schedule,
    stream: *const c_void,
}

/// `DES_EDE_KEY`: three schedules, and the stream function (NULL here).
#[repr(C)]
pub(crate) struct DesEdeKey {
    ks: [DES_key_schedule; 3],
    stream: *const c_void,
}

/// `DESX_CBC_KEY`: the schedule and the whitening keys.
#[repr(C)]
pub(crate) struct DesxKey {
    ks: DES_key_schedule,
    inw: DES_cblock,
    outw: DES_cblock,
}

/// The modes of the DES ciphers.
#[derive(Clone, Copy)]
enum ModeD {
    Ecb,
    Cbc,
    Cfb64,
    Cfb8,
    Cfb1,
    Ofb,
}

/// DES's 1-bit CFB, a bit at a time: `f` from a one-octet input with the bit at the top to a
/// one-octet output whose top bit goes into `out`.
///
/// # Safety
/// `in_` and `out` hold `bits` bits.
unsafe fn cfb1_bits(
    in_: *const u8,
    out: *mut u8,
    bits: usize,
    mut f: impl FnMut(*const u8, *mut u8),
) {
    for n in 0..bits {
        let shift = u32::try_from(n % 8).unwrap_or(0);
        // SAFETY: within the caller's buffers.
        let byte = unsafe { in_.wrapping_add(n / 8).read() };
        let c = [if byte & (0x80 >> shift) != 0 {
            0x80u8
        } else {
            0
        }];
        let mut d = [0u8];
        f(c.as_ptr(), d.as_mut_ptr());
        let o = out.wrapping_add(n / 8);
        // SAFETY: within the caller's buffers.
        let was = unsafe { o.read() };
        let bit = d.first().copied().unwrap_or(0);
        // SAFETY: as above.
        unsafe { o.write((was & !(0x80 >> shift)) | ((bit & 0x80) >> shift)) };
    }
}

/// `des_<mode>_cipher`.
///
/// # Safety
/// `ctx` is a live cipher context whose state is a `DesKey`; the buffers hold `len` octets.
unsafe fn do_des(
    m: ModeD,
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<DesKey>(ctx) }) else {
        return 0;
    };
    let ks = field::<_, DES_key_schedule>(d, offset_of!(DesKey, ks));
    // SAFETY: as above.
    let iv = unsafe { iv(ctx) }.cast::<DES_cblock>();
    // SAFETY: as above.
    let e = unsafe { enc(ctx) };
    match m {
        ModeD::Ecb => {
            let step = |i: usize| {
                // SAFETY: a whole block within the caller's buffers; the state's schedule.
                unsafe {
                    DES_ecb_encrypt(
                        in_.wrapping_add(i).cast_mut().cast(),
                        out.wrapping_add(i).cast(),
                        ks,
                        e,
                    )
                };
            };
            // SAFETY: the caller's guarantee.
            unsafe { ecb_loop(ctx, len, step) };
        }
        ModeD::Cbc => chunked(in_, out, len, |i, o, l| {
            // SAFETY: a chunk of the caller's buffers, the schedule, the IV.
            unsafe { DES_ncbc_encrypt(i, o, l, ks, iv, e) };
        }),
        ModeD::Cfb64 => chunked(in_, out, len, |i, o, l| {
            let op = |num: *mut c_int| {
                // SAFETY: as above, and the context's `num`.
                unsafe { DES_cfb64_encrypt(i, o, l, ks, iv, num, e) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }),
        ModeD::Ofb => chunked(in_, out, len, |i, o, l| {
            let op = |num: *mut c_int| {
                // SAFETY: as above.
                unsafe { DES_ofb64_encrypt(i, o, l, ks, iv, num) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }),
        ModeD::Cfb8 => chunked(in_, out, len, |i, o, l| {
            // SAFETY: as above.
            unsafe { DES_cfb_encrypt(i, o, 8, l, ks, iv, e) };
        }),
        ModeD::Cfb1 => {
            let step = |c: *const u8, o: *mut u8| {
                // SAFETY: one-octet buffers, the schedule, the IV.
                unsafe { DES_cfb_encrypt(c, o, 1, 1, ks, iv, e) };
            };
            // SAFETY: the caller's buffers of `len` octets.
            unsafe { cfb1_bits(in_, out, len.saturating_mul(8), step) };
        }
    }
    1
}

/// `des_ede_<mode>_cipher` (and `des_ede3_*`).
///
/// # Safety
/// `ctx` is a live cipher context whose state is a `DesEdeKey`; the buffers hold `len` octets
/// (bits, for 1-bit CFB with `EVP_CIPH_FLAG_LENGTH_BITS`).
unsafe fn do_ede(
    m: ModeD,
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<DesEdeKey>(ctx) }) else {
        return 0;
    };
    let k1 = field::<_, DES_key_schedule>(d, offset_of!(DesEdeKey, ks));
    let k2 = k1.wrapping_add(1);
    let k3 = k1.wrapping_add(2);
    // SAFETY: as above.
    let iv = unsafe { iv(ctx) }.cast::<DES_cblock>();
    // SAFETY: as above.
    let e = unsafe { enc(ctx) };
    match m {
        ModeD::Ecb => {
            let step = |i: usize| {
                // SAFETY: a whole block within the caller's buffers; the state's schedules.
                unsafe {
                    DES_ecb3_encrypt(
                        in_.wrapping_add(i).cast_mut().cast(),
                        out.wrapping_add(i).cast(),
                        k1,
                        k2,
                        k3,
                        e,
                    )
                };
            };
            // SAFETY: the caller's guarantee.
            unsafe { ecb_loop(ctx, len, step) };
        }
        ModeD::Cbc => chunked(in_, out, len, |i, o, l| {
            // SAFETY: a chunk of the caller's buffers, the schedules, the IV.
            unsafe { DES_ede3_cbc_encrypt(i, o, l, k1, k2, k3, iv, e) };
        }),
        ModeD::Cfb64 => chunked(in_, out, len, |i, o, l| {
            let op = |num: *mut c_int| {
                // SAFETY: as above, and the context's `num`.
                unsafe { DES_ede3_cfb64_encrypt(i, o, l, k1, k2, k3, iv, num, e) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }),
        ModeD::Ofb => chunked(in_, out, len, |i, o, l| {
            let op = |num: *mut c_int| {
                // SAFETY: as above.
                unsafe { DES_ede3_ofb64_encrypt(i, o, l, k1, k2, k3, iv, num) };
            };
            // SAFETY: the caller's guarantee.
            unsafe { with_num(ctx, op) };
        }),
        ModeD::Cfb8 => chunked(in_, out, len, |i, o, l| {
            // SAFETY: as above.
            unsafe { DES_ede3_cfb_encrypt(i, o, 8, l, k1, k2, k3, iv, e) };
        }),
        ModeD::Cfb1 => {
            // SAFETY: the caller's guarantee.
            let bits = if unsafe { length_bits(ctx) } {
                len
            } else {
                len.saturating_mul(8)
            };
            let step = |c: *const u8, o: *mut u8| {
                // SAFETY: one-octet buffers, the schedules, the IV.
                unsafe { DES_ede3_cfb_encrypt(c, o, 1, 1, k1, k2, k3, iv, e) };
            };
            // SAFETY: the caller's buffers of `bits` bits.
            unsafe { cfb1_bits(in_, out, bits, step) };
        }
    }
    1
}

/// `desx_cbc_cipher`.
///
/// # Safety
/// `ctx` is a live cipher context whose state is a `DesxKey`; the buffers hold `len` octets.
unsafe fn desx_do_imp(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, in_: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<DesxKey>(ctx) }) else {
        return 0;
    };
    let ks = field::<_, DES_key_schedule>(d, offset_of!(DesxKey, ks));
    let inw = field(d, offset_of!(DesxKey, inw));
    let outw = field(d, offset_of!(DesxKey, outw));
    // SAFETY: as above.
    let iv = unsafe { iv(ctx) }.cast::<DES_cblock>();
    // SAFETY: as above.
    let e = unsafe { enc(ctx) };
    chunked(in_, out, len, |i, o, l| {
        // SAFETY: a chunk of the caller's buffers, the state's schedule and keys, the IV.
        unsafe { DES_xcbc_encrypt(i, o, l, ks, iv, inw, outw, e) };
    });
    1
}

/// The `do_cipher` callbacks of the DES ciphers.
macro_rules! des_fns {
    ($imp:ident, $($name:ident => $m:ident),*) => {
        $(do_fn!($name, |c, o, i, l| $imp(ModeD::$m, c, o, i, l), "A mode function of the DES ciphers (`des_<mode>_cipher`).");)*
    };
}

des_fns!(do_des, des_ecb => Ecb, des_cbc => Cbc, des_cfb64 => Cfb64, des_cfb8 => Cfb8, des_cfb1 => Cfb1, des_ofb => Ofb);
des_fns!(do_ede, ede_ecb => Ecb, ede_cbc => Cbc, ede_cfb64 => Cfb64, ede3_cfb8 => Cfb8, ede3_cfb1 => Cfb1, ede_ofb => Ofb);
do_fn!(desx_cbc, desx_do_imp, "`desx_cbc_cipher`.");

/// `des_init_key`, `des_ede_init_key` (`three` false: the third key the first), and
/// `des_ede3_init_key`.
///
/// # Safety
/// As for an `init`; the state is a `DesKey` for one key, else a `DesEdeKey`.
unsafe fn des_keys(ctx: *mut EVP_CIPHER_CTX, key: *const u8, keys: usize) -> c_int {
    if key.is_null() {
        return no_key("des_init_key");
    }
    let (ks, stream) = if keys == 1 {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { state::<DesKey>(ctx) }) else {
            return 0;
        };
        (
            field::<_, DES_key_schedule>(d, offset_of!(DesKey, ks)),
            field::<_, *const c_void>(d, offset_of!(DesKey, stream)),
        )
    } else {
        // SAFETY: as above.
        let Some(d) = (unsafe { state::<DesEdeKey>(ctx) }) else {
            return 0;
        };
        (
            field::<_, DES_key_schedule>(d, offset_of!(DesEdeKey, ks)),
            field::<_, *const c_void>(d, offset_of!(DesEdeKey, stream)),
        )
    };
    // SAFETY: the state's field.
    unsafe { stream.write(ptr::null()) };
    for k in 0..keys.min(3) {
        // SAFETY: the caller's key holds `keys` DES keys; the state's schedules.
        unsafe {
            DES_set_key_unchecked(
                key.wrapping_add(8 * k).cast_mut().cast(),
                ks.wrapping_add(k),
            )
        };
    }
    if keys == 2 {
        // SAFETY: the state's first and third schedules.
        unsafe { ptr::copy_nonoverlapping(ks, ks.wrapping_add(2), 1) };
    }
    1
}

/// `desx_cbc_init_key`: the schedule, then the whitening keys.
///
/// # Safety
/// As for an `init`.
unsafe fn desx_init_imp(ctx: *mut EVP_CIPHER_CTX, key: *const u8, _enc: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<DesxKey>(ctx) }) else {
        return 0;
    };
    if key.is_null() {
        return no_key("desx_cbc_init_key");
    }
    // SAFETY: the caller's key; the state's schedule.
    unsafe { DES_set_key_unchecked(key.cast_mut().cast(), field(d, offset_of!(DesxKey, ks))) };
    // SAFETY: the key's second eight octets; the state's field.
    unsafe { ptr::copy_nonoverlapping(key.wrapping_add(8), field(d, offset_of!(DesxKey, inw)), 8) };
    // SAFETY: the key's third eight octets; the state's field.
    unsafe {
        ptr::copy_nonoverlapping(key.wrapping_add(16), field(d, offset_of!(DesxKey, outw)), 8)
    };
    1
}

init_fn!(des_init, |c, k, _e| des_keys(c, k, 1), "`des_init_key`.");
init_fn!(
    des_ede_init,
    |c, k, _e| des_keys(c, k, 2),
    "`des_ede_init_key`."
);
init_fn!(
    des_ede3_init,
    |c, k, _e| des_keys(c, k, 3),
    "`des_ede3_init_key`."
);
init_fn!(desx_init, desx_init_imp, "`desx_cbc_init_key`.");

/// `des_ctrl` (`keys` 1) and `des3_ctrl`: a random key with odd parity.
///
/// # Safety
/// As for a `ctrl`.
unsafe fn des_ctrl_imp(
    ctx: *mut EVP_CIPHER_CTX,
    type_: c_int,
    ptr: *mut c_void,
    three: bool,
) -> c_int {
    if type_ != EVP_CTRL_RAND_KEY {
        return -1;
    }
    let kl = if three {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_CIPHER_CTX_get_key_length(ctx) }
    } else {
        8
    };
    // SAFETY: the caller's room for the key length.
    if kl < 0 || ptr.is_null() || unsafe { RAND_priv_bytes(ptr.cast(), kl) } <= 0 {
        return 0;
    }
    let k = ptr.cast::<DES_cblock>();
    for (i, min) in [(0, 0), (1, 16), (2, 24)] {
        if kl >= min && (three || i == 0) {
            // SAFETY: a DES key within the caller's buffer.
            unsafe { DES_set_odd_parity(k.wrapping_add(i)) };
        }
    }
    1
}

ctrl_fn!(
    des_ctrl,
    |c, t, _a, p| des_ctrl_imp(c, t, p, false),
    "`des_ctrl`."
);
ctrl_fn!(
    des3_ctrl,
    |c, t, _a, p| des_ctrl_imp(c, t, p, true),
    "`des3_ctrl`."
);

// ---- RC4 and NULL ----

/// `rc4_init_key`.
///
/// # Safety
/// As for an `init`.
unsafe fn rc4_init_imp(ctx: *mut EVP_CIPHER_CTX, key: *const u8, _enc: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Ks<RC4_KEY>>(ctx) }) else {
        return 0;
    };
    // SAFETY: as above.
    let Some(len) = (unsafe { key_len(ctx, true) }) else {
        return 0;
    };
    if key.is_null() {
        return no_key("rc4_init_key");
    }
    // SAFETY: the state's key; the caller's key of the context's key length.
    unsafe { RC4_set_key(field(d, offset_of!(Ks<RC4_KEY>, ks)), len, key) };
    1
}

/// `rc4_cipher`.
///
/// # Safety
/// As for a `do_cipher`.
unsafe fn rc4_do_imp(ctx: *mut EVP_CIPHER_CTX, out: *mut u8, in_: *const u8, len: usize) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(d) = (unsafe { state::<Ks<RC4_KEY>>(ctx) }) else {
        return 0;
    };
    // SAFETY: the state's key; the caller's buffers.
    unsafe { RC4(field(d, offset_of!(Ks<RC4_KEY>, ks)), len, in_, out) };
    1
}

/// `null_cipher`: the input copied, unless in place.
///
/// # Safety
/// As for a `do_cipher`.
unsafe fn null_do_imp(
    _ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    in_: *const u8,
    len: usize,
) -> c_int {
    if in_ != out.cast_const() && len > 0 {
        if in_.is_null() || out.is_null() {
            err::raise(ERR_LIB_EVP, ERR_R_PASSED_NULL_PARAMETER, "null_cipher");
            return 0;
        }
        // SAFETY: the caller's buffers of `len` octets.
        unsafe { ptr::copy(in_, out, len) };
    }
    1
}

/// `null_init_key`: nothing to set.
///
/// # Safety
/// No preconditions.
unsafe fn null_init_imp(_ctx: *mut EVP_CIPHER_CTX, _key: *const u8, _enc: c_int) -> c_int {
    1
}

init_fn!(rc4_init, rc4_init_imp, "`rc4_init_key`.");
do_fn!(rc4_do, rc4_do_imp, "`rc4_cipher`.");
init_fn!(null_init, null_init_imp, "`null_init_key`.");
do_fn!(null_do, null_do_imp, "`null_cipher`.");

// ---- The ciphers whose state OpenSSL doesn't publish: they fail ----

/// Raises the error of the failing functions; `ret` is what they return.
fn unsupported_error(ret: c_int) -> c_int {
    err::raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_CIPHER, "legacy cipher");
    ret
}

/// An `init` that fails.
///
/// # Safety
/// No preconditions.
unsafe fn unsupported_init_imp(_ctx: *mut EVP_CIPHER_CTX, _key: *const u8, _enc: c_int) -> c_int {
    unsupported_error(0)
}

/// A `do_cipher` that fails (0).
///
/// # Safety
/// No preconditions.
unsafe fn unsupported_do_imp(
    _ctx: *mut EVP_CIPHER_CTX,
    _out: *mut u8,
    _in: *const u8,
    _len: usize,
) -> c_int {
    unsupported_error(0)
}

/// A custom cipher's `do_cipher` that fails (-1).
///
/// # Safety
/// No preconditions.
unsafe fn unsupported_custom_do_imp(
    _ctx: *mut EVP_CIPHER_CTX,
    _out: *mut u8,
    _in: *const u8,
    _len: usize,
) -> c_int {
    unsupported_error(-1)
}

/// A `ctrl` that knows no command (-1).
///
/// # Safety
/// No preconditions.
unsafe fn unsupported_ctrl_imp(
    _ctx: *mut EVP_CIPHER_CTX,
    _type: c_int,
    _arg: c_int,
    _ptr: *mut c_void,
) -> c_int {
    -1
}

init_fn!(
    unsupported_init,
    unsupported_init_imp,
    "An `init` that fails: the cipher's legacy functions aren't here (docs/DEVIATIONS.md)."
);
do_fn!(
    unsupported_do,
    unsupported_do_imp,
    "A `do_cipher` that fails."
);
do_fn!(
    unsupported_custom_do,
    unsupported_custom_do_imp,
    "A custom cipher's `do_cipher` that fails."
);
ctrl_fn!(
    unsupported_ctrl,
    unsupported_ctrl_imp,
    "A `ctrl` that knows no command."
);

ffi_callback! {
    /// A `cleanup` with nothing to clean up: the failing ciphers keep no state.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn unsupported_cleanup(ctx: *mut EVP_CIPHER_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let _ = ctx;
        1
    }
}

/// The size of a state type, as the `int` `EVP_CIPHER_impl_ctx_size` gives.
fn size<T>() -> c_int {
    c_int::try_from(size_of::<T>()).unwrap_or(0)
}

/// A table with these functions.
fn table(ctx_size: c_int, init: LegacyInitFn, do_cipher: LegacyDoCipherFn) -> Legacy {
    Legacy {
        ctx_size,
        init: Some(init),
        do_cipher: Some(do_cipher),
        ..Legacy::default()
    }
}

/// With the generic AlgorithmIdentifier functions (the IV as an OCTET STRING).
fn with_iv_asn1(l: Legacy) -> Legacy {
    Legacy {
        set_asn1: Some(EVP_CIPHER_set_asn1_iv),
        get_asn1: Some(EVP_CIPHER_get_asn1_iv),
        ..l
    }
}

/// The static cipher `nid`'s functions, in the slots OpenSSL's fills; `flags` its flags.
#[expect(
    non_upper_case_globals,
    reason = "the NIDs are OpenSSL's names, matched as patterns"
)]
pub(crate) fn for_static(nid: c_int, flags: c_ulong) -> Legacy {
    let a = size::<Key128<AES_KEY>>();
    let c = size::<Key128<CAMELLIA_KEY>>();
    let seed = size::<Ks<SEED_KEY_SCHEDULE>>();
    let bf = size::<Ks<BF_KEY>>();
    let cast = size::<Ks<CAST_KEY>>();
    let idea = size::<Ks<IDEA_KEY_SCHEDULE>>();
    let rc2 = size::<Rc2Key>();
    let des = size::<DesKey>();
    let ede = size::<DesEdeKey>();
    let des1 = |l: Legacy| Legacy {
        ctrl: Some(des_ctrl),
        ..with_iv_asn1(l)
    };
    let des3 = |l: Legacy| Legacy {
        ctrl: Some(des3_ctrl),
        ..l
    };
    let rc2_t = |l: Legacy| Legacy {
        ctrl: Some(rc2_ctrl),
        set_asn1: Some(rc2_set_asn1),
        get_asn1: Some(rc2_get_asn1),
        ..l
    };
    match nid {
        NID_aes_128_ecb | NID_aes_192_ecb | NID_aes_256_ecb => table(a, aes_init, aes_ecb),
        NID_aes_128_cbc | NID_aes_192_cbc | NID_aes_256_cbc => table(a, aes_init, aes_cbc),
        NID_aes_128_cfb128 | NID_aes_192_cfb128 | NID_aes_256_cfb128 => table(a, aes_init, aes_cfb),
        NID_aes_128_cfb8 | NID_aes_192_cfb8 | NID_aes_256_cfb8 => table(a, aes_init, aes_cfb8),
        NID_aes_128_cfb1 | NID_aes_192_cfb1 | NID_aes_256_cfb1 => table(a, aes_init, aes_cfb1),
        NID_aes_128_ofb128 | NID_aes_192_ofb128 | NID_aes_256_ofb128 => table(a, aes_init, aes_ofb),
        NID_aes_128_ctr | NID_aes_192_ctr | NID_aes_256_ctr => table(a, aes_init, aes_ctr),
        NID_camellia_128_ecb | NID_camellia_192_ecb | NID_camellia_256_ecb => {
            table(c, cmll_init, cmll_ecb)
        }
        NID_camellia_128_cbc | NID_camellia_192_cbc | NID_camellia_256_cbc => {
            table(c, cmll_init, cmll_cbc)
        }
        NID_camellia_128_cfb128 | NID_camellia_192_cfb128 | NID_camellia_256_cfb128 => {
            table(c, cmll_init, cmll_cfb)
        }
        NID_camellia_128_cfb8 | NID_camellia_192_cfb8 | NID_camellia_256_cfb8 => {
            table(c, cmll_init, cmll_cfb8)
        }
        NID_camellia_128_cfb1 | NID_camellia_192_cfb1 | NID_camellia_256_cfb1 => {
            table(c, cmll_init, cmll_cfb1)
        }
        NID_camellia_128_ofb128 | NID_camellia_192_ofb128 | NID_camellia_256_ofb128 => {
            table(c, cmll_init, cmll_ofb)
        }
        NID_camellia_128_ctr | NID_camellia_192_ctr | NID_camellia_256_ctr => {
            table(c, cmll_init, cmll_ctr)
        }
        NID_seed_ecb => table(seed, seed_init, seed_ecb),
        NID_seed_cbc => table(seed, seed_init, seed_cbc),
        NID_seed_cfb128 => table(seed, seed_init, seed_cfb),
        NID_seed_ofb128 => table(seed, seed_init, seed_ofb),
        NID_bf_ecb => with_iv_asn1(table(bf, bf_init, bf_ecb)),
        NID_bf_cbc => with_iv_asn1(table(bf, bf_init, bf_cbc)),
        NID_bf_cfb64 => with_iv_asn1(table(bf, bf_init, bf_cfb)),
        NID_bf_ofb64 => with_iv_asn1(table(bf, bf_init, bf_ofb)),
        NID_cast5_ecb => with_iv_asn1(table(cast, cast_init, cast_ecb)),
        NID_cast5_cbc => with_iv_asn1(table(cast, cast_init, cast_cbc)),
        NID_cast5_cfb64 => with_iv_asn1(table(cast, cast_init, cast_cfb)),
        NID_cast5_ofb64 => with_iv_asn1(table(cast, cast_init, cast_ofb)),
        NID_idea_ecb => with_iv_asn1(table(idea, idea_init, idea_ecb)),
        NID_idea_cbc => with_iv_asn1(table(idea, idea_init, idea_cbc)),
        NID_idea_cfb64 => with_iv_asn1(table(idea, idea_init, idea_cfb)),
        NID_idea_ofb64 => with_iv_asn1(table(idea, idea_init, idea_ofb)),
        NID_rc2_ecb => rc2_t(table(rc2, rc2_init, rc2_ecb)),
        NID_rc2_cbc | NID_rc2_40_cbc | NID_rc2_64_cbc => rc2_t(table(rc2, rc2_init, rc2_cbc)),
        NID_rc2_cfb64 => rc2_t(table(rc2, rc2_init, rc2_cfb)),
        NID_rc2_ofb64 => rc2_t(table(rc2, rc2_init, rc2_ofb)),
        NID_des_ecb => des1(table(des, des_init, des_ecb)),
        NID_des_cbc => des1(table(des, des_init, des_cbc)),
        NID_des_cfb64 => des1(table(des, des_init, des_cfb64)),
        NID_des_cfb8 => des1(table(des, des_init, des_cfb8)),
        NID_des_cfb1 => des1(table(des, des_init, des_cfb1)),
        NID_des_ofb64 => des1(table(des, des_init, des_ofb)),
        NID_des_ede_ecb => des3(table(ede, des_ede_init, ede_ecb)),
        NID_des_ede_cbc => des3(table(ede, des_ede_init, ede_cbc)),
        NID_des_ede_cfb64 => des3(table(ede, des_ede_init, ede_cfb64)),
        NID_des_ede_ofb64 => des3(table(ede, des_ede_init, ede_ofb)),
        NID_des_ede3_ecb => des3(table(ede, des_ede3_init, ede_ecb)),
        NID_des_ede3_cbc => des3(table(ede, des_ede3_init, ede_cbc)),
        NID_des_ede3_cfb64 => des3(table(ede, des_ede3_init, ede_cfb64)),
        NID_des_ede3_ofb64 => des3(table(ede, des_ede3_init, ede_ofb)),
        NID_des_ede3_cfb8 => des3(table(ede, des_ede3_init, ede3_cfb8)),
        NID_des_ede3_cfb1 => des3(table(ede, des_ede3_init, ede3_cfb1)),
        NID_desx_cbc => with_iv_asn1(table(size::<DesxKey>(), desx_init, desx_cbc)),
        NID_rc4 | NID_rc4_40 => table(size::<Ks<RC4_KEY>>(), rc4_init, rc4_do),
        NID_undef => table(0, null_init, null_do),
        _ => unsupported(nid, flags),
    }
}

/// The failing functions of a cipher kept out here, in the slots OpenSSL's fills.
#[expect(
    non_upper_case_globals,
    reason = "the NIDs are OpenSSL's names, matched as patterns"
)]
fn unsupported(nid: c_int, flags: c_ulong) -> Legacy {
    let custom = flags & c_ulong::try_from(EVP_CIPH_FLAG_CUSTOM_CIPHER).unwrap_or(0) != 0;
    let mut l = table(
        0,
        unsupported_init,
        if custom {
            unsupported_custom_do
        } else {
            unsupported_do
        },
    );
    let m = mode_of(flags);
    let aead = m == EVP_CIPH_GCM_MODE || m == EVP_CIPH_OCB_MODE || nid == NID_chacha20_poly1305;
    if aead {
        l.cleanup = Some(unsupported_cleanup);
    }
    if aead || m == EVP_CIPH_CCM_MODE || m == EVP_CIPH_XTS_MODE || nid == NID_rc4_hmac_md5 {
        l.ctrl = Some(unsupported_ctrl);
    }
    if matches!(
        nid,
        NID_aria_128_cbc
            | NID_aria_128_cfb128
            | NID_aria_128_ecb
            | NID_aria_128_ofb128
            | NID_aria_192_cbc
            | NID_aria_192_cfb128
            | NID_aria_192_ecb
            | NID_aria_192_ofb128
            | NID_aria_256_cbc
            | NID_aria_256_cfb128
            | NID_aria_256_ecb
            | NID_aria_256_ofb128
    ) {
        l = with_iv_asn1(l);
    }
    l
}
