//! The default provider's random generators (`deflt_rands` in `providers/defltprov.c`), and the
//! base provider's seed source: CTR-DRBG (`drbg_ctr.c`), HASH-DRBG (`drbg_hash.c`), and
//! HMAC-DRBG (`drbg_hmac.c`) over the DRBG framework of `drbg.c`; SEED-SRC (`seed_src.c`); and
//! TEST-RAND (`test_rng.c`).
//!
//! The framework is the reference's: the state machine (uninstantiated, ready, error, with an
//! automatic restart), the limits each mechanism publishes, the default personalization string,
//! entropy from the parent's `get_seed` (or, without a parent, the core's source), nonces from
//! the parent's `nonce` (or extra entropy from a parent without one, or the core's nonce),
//! reseeding after a number of requests, an interval of time, a fork, the parent's reseed, or
//! for prediction resistance, and the strength checks against the parent. As in the reference,
//! the mechanisms run over the EVP layer: CTR-DRBG over `EVP_CIPHER_CTX` (an ECB context for
//! the updates and derivation function, a CTR one for output), HASH-DRBG over `EVP_MD_CTX`, and
//! HMAC-DRBG over `EVP_MAC_CTX`, with the methods fetched from the provider's library context
//! (with `provider=default` unless `properties` say otherwise). The backend's mechanisms
//! (`rustyssl_crypto::rand`) are the fuzz target's oracle.
//!
//! Each context keeps its state behind a mutex, so it's safe to share whether or not locking
//! was enabled (the reference's DRBGs lock only once it is); `lock` and `unlock` succeed and do
//! nothing, as `ossl_drbg_lock` does. A DRBG calls into its parent through the parent's
//! dispatch table, which may be another provider's.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_LIB_RAND, ERR_R_EVP_LIB, ERR_R_RAND_LIB, EVP_CIPHER, EVP_CIPHER_CTX,
    EVP_MAC_CTX, EVP_MD, EVP_MD_CTX, EVP_RAND_STATE_ERROR, EVP_RAND_STATE_READY,
    EVP_RAND_STATE_UNINITIALISED, OSSL_ALG_PARAM_DIGEST, OSSL_ALG_PARAM_MAC, OSSL_ALGORITHM,
    OSSL_DISPATCH, OSSL_DRBG_PARAM_CIPHER, OSSL_DRBG_PARAM_DIGEST, OSSL_DRBG_PARAM_MAC,
    OSSL_DRBG_PARAM_MAX_ADINLEN, OSSL_DRBG_PARAM_MAX_ENTROPYLEN, OSSL_DRBG_PARAM_MAX_NONCELEN,
    OSSL_DRBG_PARAM_MAX_PERSLEN, OSSL_DRBG_PARAM_MIN_ENTROPYLEN, OSSL_DRBG_PARAM_MIN_NONCELEN,
    OSSL_DRBG_PARAM_PROPERTIES, OSSL_DRBG_PARAM_RESEED_COUNTER, OSSL_DRBG_PARAM_RESEED_REQUESTS,
    OSSL_DRBG_PARAM_RESEED_TIME, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, OSSL_DRBG_PARAM_USE_DF,
    OSSL_FUNC_RAND_CLEAR_SEED, OSSL_FUNC_RAND_ENABLE_LOCKING, OSSL_FUNC_RAND_FREECTX,
    OSSL_FUNC_RAND_GENERATE, OSSL_FUNC_RAND_GET_CTX_PARAMS, OSSL_FUNC_RAND_GET_SEED,
    OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS, OSSL_FUNC_RAND_INSTANTIATE, OSSL_FUNC_RAND_LOCK,
    OSSL_FUNC_RAND_NEWCTX, OSSL_FUNC_RAND_NONCE, OSSL_FUNC_RAND_RESEED,
    OSSL_FUNC_RAND_SET_CTX_PARAMS, OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
    OSSL_FUNC_RAND_UNINSTANTIATE, OSSL_FUNC_RAND_UNLOCK, OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
    OSSL_MAC_PARAM_DIGEST, OSSL_MAC_PARAM_PROPERTIES, OSSL_PARAM, OSSL_PARAM_INTEGER,
    OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING,
    OSSL_RAND_PARAM_GENERATE, OSSL_RAND_PARAM_MAX_REQUEST, OSSL_RAND_PARAM_STATE,
    OSSL_RAND_PARAM_STRENGTH, OSSL_RAND_PARAM_TEST_ENTROPY, OSSL_RAND_PARAM_TEST_NONCE,
    PROV_R_ADDITIONAL_INPUT_TOO_LONG, PROV_R_ALREADY_INSTANTIATED,
    PROV_R_DERIVATION_FUNCTION_INIT_FAILED, PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK,
    PROV_R_ERROR_INSTANTIATING_DRBG, PROV_R_ERROR_RETRIEVING_ENTROPY,
    PROV_R_ERROR_RETRIEVING_NONCE, PROV_R_GENERATE_ERROR, PROV_R_IN_ERROR_STATE,
    PROV_R_INSUFFICIENT_DRBG_STRENGTH, PROV_R_INVALID_DIGEST, PROV_R_INVALID_MAC,
    PROV_R_MISSING_CIPHER, PROV_R_MISSING_MAC, PROV_R_NOT_INSTANTIATED,
    PROV_R_PARENT_CANNOT_SUPPLY_ENTROPY_SEED, PROV_R_PARENT_LOCKING_NOT_ENABLED,
    PROV_R_PARENT_STRENGTH_TOO_WEAK, PROV_R_PERSONALISATION_STRING_TOO_LONG,
    PROV_R_REQUEST_TOO_LARGE_FOR_DRBG, PROV_R_REQUIRE_CTR_MODE_CIPHER, PROV_R_RESEED_ERROR,
    PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT, PROV_R_UNABLE_TO_FIND_CIPHERS,
    PROV_R_UNABLE_TO_GET_PARENT_STRENGTH, PROV_R_UNABLE_TO_INITIALISE_CIPHERS,
    PROV_R_UNABLE_TO_LOCK_PARENT, PROV_R_UNABLE_TO_RESEED, PROV_R_VALUE_ERROR,
    PROV_R_XOF_DIGESTS_NOT_ALLOWED, RAND_R_ENTROPY_INPUT_TOO_LONG, RAND_R_ENTROPY_OUT_OF_RANGE,
};

use super::builtin::libctx_of;
use super::kdfs::macctx_load;
use super::macs::{Prov, boxed, is_empty, locate, unbox, wipe};
use super::tables::{
    ALG_END, Algorithms, Dispatch, END, PARAM_END, Params, alg, base_alg, defn, entry,
};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher::{
    EVP_CIPHER_fetch, EVP_CIPHER_free, EVP_CIPHER_get_key_length, EVP_CIPHER_get0_name,
};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CipherInit_ex, EVP_CipherUpdate,
};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_MD_get0_name};
use crate::evp::mac::{
    EVP_MAC_CTX_free, EVP_MAC_CTX_get0_mac, EVP_MAC_CTX_new, EVP_MAC_CTX_set_params, EVP_MAC_fetch,
    EVP_MAC_final, EVP_MAC_free, EVP_MAC_get0_name, EVP_MAC_init, EVP_MAC_update,
};
use crate::evp::md_ctx::{
    EVP_DigestFinal, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
    EVP_MD_xof,
};
use crate::evp::rand::{
    ClearSeedFn, CtxParamsListFn, FreeCtxFn, GenerateFn, GetCtxParamsFn, GetSeedFn, InstantiateFn,
    LockingFn, NewCtxFn, NonceFn, ReseedFn, SetCtxParamsFn, UninstantiateFn, UnlockFn,
    VerifyZeroizationFn,
};
use crate::ffi::ffi_callback;
use crate::params::{
    OSSL_PARAM_construct_uint, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_get_int,
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_size_t, OSSL_PARAM_get_time_t, OSSL_PARAM_get_uint,
    OSSL_PARAM_get_utf8_string_ptr, OSSL_PARAM_locate, OSSL_PARAM_set_int, OSSL_PARAM_set_size_t,
    OSSL_PARAM_set_time_t, OSSL_PARAM_set_uint, OSSL_PARAM_set_utf8_string, end,
};
use crate::rand::{Pool, Seed, get_entropy, get_nonce};
use crate::secure::{CRYPTO_secure_clear_free, CRYPTO_secure_malloc};

/// `DRBG_MAX_LENGTH`.
const MAX_LENGTH: usize = 0x7fff_ffff;
/// `RESEED_INTERVAL`: requests between reseeds.
const RESEED_INTERVAL: c_uint = 1 << 8;
/// `TIME_INTERVAL`: seconds between reseeds.
const TIME_INTERVAL: i64 = 60 * 60;
/// `DRBG_DEFAULT_PERS_STRING`, with its terminating NUL (the reference passes its `sizeof`).
const DEFAULT_PERS: &[u8] = b"OpenSSL NIST SP 800-90A DRBG\0";
/// `EVP_MAX_MD_SIZE`.
const MAX_MD: usize = 64;
/// The reference's request limit, 2^16 octets.
const MAX_REQUEST: usize = 1 << 16;

/// The process id, which the reference's `openssl_get_fork_id` is.
fn fork_id() -> c_int {
    // SAFETY: no preconditions.
    unsafe { libc::getpid() }
}

/// `time(NULL)`.
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn raise(reason: c_int, function: &str) {
    err::raise(ERR_LIB_PROV, reason, function);
}

/// Locks a context's state, through a poisoning (the state is valid after any panic, which
/// `ffi_callback!` catches).
fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An algorithm context shared by reference (a context may be used by many threads).
///
/// # Safety
/// `vctx` is NULL or a box of a `T` from its `newctx`.
unsafe fn shared<'a, T>(vctx: *mut c_void) -> Option<&'a T> {
    // SAFETY: the caller's guarantee.
    unsafe { vctx.cast::<T>().as_ref() }
}

/// An optional input's octets, `None` for NULL.
///
/// # Safety
/// `p` is NULL or holds `len` octets.
unsafe fn input<'a>(p: *const c_uchar, len: usize) -> Option<&'a [u8]> {
    // SAFETY: the caller's guarantee.
    (!p.is_null()).then(|| unsafe { core::slice::from_raw_parts(p, len) })
}

/// The bytes of a context's address, which the reference passes as additional input to the
/// parent it seeds from (`(unsigned char *)&drbg, sizeof(drbg)`).
fn address_bytes<T>(p: *const T) -> [u8; size_of::<usize>()] {
    p.addr().to_ne_bytes()
}

// -------------------------------------------------------------------------------------------
// The parent

/// The parent's context and the functions the DRBG found in its dispatch table.
#[derive(Clone, Copy)]
struct Parent {
    ctx: *mut c_void,
    enable_locking: Option<LockingFn>,
    lock: Option<LockingFn>,
    unlock: Option<UnlockFn>,
    get_ctx_params: Option<GetCtxParamsFn>,
    nonce: Option<NonceFn>,
    get_seed: Option<GetSeedFn>,
    clear_seed: Option<ClearSeedFn>,
}

// SAFETY: the parent is another random context, which its own provider makes safe to share (the
// EVP layer holds a reference to it for as long as the child lives).
unsafe impl Send for Parent {}

impl Parent {
    /// `find_call` of each function in the parent's table.
    ///
    /// # Safety
    /// `dispatch` is NULL or a table ended by a zero id, whose functions have the types their
    /// ids stand for.
    unsafe fn new(ctx: *mut c_void, dispatch: *const OSSL_DISPATCH) -> Self {
        let mut p = Self {
            ctx,
            enable_locking: None,
            lock: None,
            unlock: None,
            get_ctx_params: None,
            nonce: None,
            get_seed: None,
            clear_seed: None,
        };
        let mut at = dispatch;
        // SAFETY: the caller's guarantee.
        while let Some(d) = unsafe { at.as_ref() } {
            if d.function_id == 0 {
                break;
            }
            at = at.wrapping_add(1);
            let Some(f) = d.function else { continue };
            /// The first of each id, as `find_call` finds.
            macro_rules! set {
                ($field:ident) => {
                    if p.$field.is_none() {
                        // SAFETY: the caller's guarantee of the function type for this id.
                        p.$field = Some(unsafe { core::mem::transmute_copy(&f) });
                    }
                };
            }
            match d.function_id {
                OSSL_FUNC_RAND_ENABLE_LOCKING => set!(enable_locking),
                OSSL_FUNC_RAND_LOCK => set!(lock),
                OSSL_FUNC_RAND_UNLOCK => set!(unlock),
                OSSL_FUNC_RAND_GET_CTX_PARAMS => set!(get_ctx_params),
                OSSL_FUNC_RAND_NONCE => set!(nonce),
                OSSL_FUNC_RAND_GET_SEED => set!(get_seed),
                OSSL_FUNC_RAND_CLEAR_SEED => set!(clear_seed),
                _ => {}
            }
        }
        p
    }

    fn present(&self) -> bool {
        !self.ctx.is_null()
    }

    /// `ossl_drbg_lock_parent`.
    fn lock(&self) -> bool {
        if let (true, Some(lock)) = (self.present(), self.lock) {
            // SAFETY: the parent's function with its context.
            if unsafe { lock(self.ctx) } == 0 {
                raise(PROV_R_PARENT_LOCKING_NOT_ENABLED, "ossl_drbg_lock_parent");
                return false;
            }
        }
        true
    }

    /// `ossl_drbg_unlock_parent`.
    fn unlock(&self) {
        if let (true, Some(unlock)) = (self.present(), self.unlock) {
            // SAFETY: the parent's function with its context.
            unsafe { unlock(self.ctx) };
        }
    }

    /// `get_parent_strength`.
    fn strength(&self) -> Option<c_uint> {
        const F: &str = "get_parent_strength";
        let Some(get) = self.get_ctx_params else {
            raise(PROV_R_UNABLE_TO_GET_PARENT_STRENGTH, F);
            return None;
        };
        let mut strength: c_uint = 0;
        // SAFETY: a static key and a local.
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH.as_ptr(), &raw mut strength)
            },
            end(),
        ];
        if !self.lock() {
            raise(PROV_R_UNABLE_TO_LOCK_PARENT, F);
            return None;
        }
        // SAFETY: the parent's function with its context and a local array.
        let r = unsafe { get(self.ctx, params.as_mut_ptr()) };
        self.unlock();
        if r == 0 {
            raise(PROV_R_UNABLE_TO_GET_PARENT_STRENGTH, F);
            return None;
        }
        Some(strength)
    }

    /// `get_parent_reseed_count` (the child's own counter less 2 if the parent won't lock).
    fn reseed_count(&self, own: c_uint) -> c_uint {
        let mut r: c_uint = 0;
        // SAFETY: a static key and a local.
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_uint(OSSL_DRBG_PARAM_RESEED_COUNTER.as_ptr(), &raw mut r)
            },
            end(),
        ];
        if !self.lock() {
            raise(PROV_R_UNABLE_TO_LOCK_PARENT, "get_parent_reseed_count");
            let r = own.wrapping_sub(2);
            return if r == 0 { c_uint::MAX } else { r };
        }
        let ok = match self.get_ctx_params {
            // SAFETY: the parent's function with its context and a local array.
            Some(get) => (unsafe { get(self.ctx, params.as_mut_ptr()) }) != 0,
            None => false,
        };
        self.unlock();
        if ok { r } else { 0 }
    }
}

/// Entropy for an instantiation or reseed: the core's, or a seed the parent lent (to be given
/// back with its `clear_seed`).
enum Entropy {
    None,
    Owned(Seed),
    Lent(*mut c_uchar, usize),
}

impl Entropy {
    fn len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Owned(s) => s.0.len(),
            Self::Lent(_, n) => *n,
        }
    }

    /// The octets, `None` for none (a NULL buffer).
    fn octets(&self) -> Option<&[u8]> {
        match self {
            Self::None => None,
            Self::Owned(s) => Some(&s.0),
            // SAFETY: the parent's seed, of `n` octets, until it's given back.
            Self::Lent(p, n) => unsafe { input(*p, *n) },
        }
    }
}

// -------------------------------------------------------------------------------------------
// The mechanisms

/// `PROV_DRBG_CTR`.
struct CtrState {
    ctx_ecb: *mut EVP_CIPHER_CTX,
    ctx_ctr: *mut EVP_CIPHER_CTX,
    ctx_df: *mut EVP_CIPHER_CTX,
    cipher_ecb: *mut EVP_CIPHER,
    cipher_ctr: *mut EVP_CIPHER,
    keylen: usize,
    use_df: bool,
    k: [u8; 32],
    v: [u8; 16],
    bltmp: [u8; 16],
    bltmp_pos: usize,
    kx: [u8; 48],
}

/// `PROV_DRBG_HASH`'s seed lengths and buffers.
const HASH_MAX_SEEDLEN: usize = 888 / 8;
const HASH_SMALL_SEEDLEN: usize = 440 / 8;

/// `PROV_DRBG_HASH`.
struct HashState {
    digest: Prov<EVP_MD>,
    ctx: *mut EVP_MD_CTX,
    blocklen: usize,
    v: [u8; HASH_MAX_SEEDLEN],
    c: [u8; HASH_MAX_SEEDLEN],
    vtmp: [u8; HASH_MAX_SEEDLEN],
}

/// `PROV_DRBG_HMAC`: the HMAC context and digest, K and V (of `blocklen` octets). HMAC-DRBG-KDF
/// runs it too.
pub(super) struct HmacState {
    pub(super) ctx: *mut EVP_MAC_CTX,
    pub(super) digest: Prov<EVP_MD>,
    pub(super) k: [u8; MAX_MD],
    pub(super) v: [u8; MAX_MD],
    pub(super) blocklen: usize,
}

/// A DRBG's mechanism and its state.
enum Mech {
    Ctr(Box<CtrState>),
    Hash(Box<HashState>),
    Hmac(Box<HmacState>),
}

// SAFETY: the EVP contexts are the mechanism's own, used under its DRBG's mutex.
unsafe impl Send for Mech {}

impl Drop for CtrState {
    fn drop(&mut self) {
        // SAFETY: the contexts and ciphers this owns, or NULL.
        unsafe {
            EVP_CIPHER_CTX_free(self.ctx_ecb);
        }
        // SAFETY: as above.
        unsafe { EVP_CIPHER_CTX_free(self.ctx_ctr) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_CTX_free(self.ctx_df) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_free(self.cipher_ecb) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_free(self.cipher_ctr) };
        wipe(&mut self.k);
        wipe(&mut self.v);
        wipe(&mut self.bltmp);
        wipe(&mut self.kx);
    }
}

impl Drop for HashState {
    fn drop(&mut self) {
        // SAFETY: the context this owns, or NULL.
        unsafe { EVP_MD_CTX_free(self.ctx) };
        wipe(&mut self.v);
        wipe(&mut self.c);
        wipe(&mut self.vtmp);
    }
}

impl Drop for HmacState {
    fn drop(&mut self) {
        // SAFETY: the context this owns, or NULL.
        unsafe { EVP_MAC_CTX_free(self.ctx) };
        wipe(&mut self.k);
        wipe(&mut self.v);
    }
}

impl HmacState {
    pub(super) fn new() -> Self {
        Self {
            ctx: ptr::null_mut(),
            digest: Prov::NONE,
            k: [0; MAX_MD],
            v: [0; MAX_MD],
            blocklen: 0,
        }
    }

    /// `do_hmac`: K = HMAC(K, V || inbyte || inputs), then V = HMAC(K, V).
    fn do_hmac(&mut self, inbyte: u8, inputs: &[&[u8]]) -> bool {
        let n = self.blocklen.min(MAX_MD);
        let byte = [inbyte];
        // SAFETY: the live context (the callers check); K and V of at least `n` octets.
        let mut ok = unsafe { EVP_MAC_init(self.ctx, self.k.as_ptr(), n, ptr::null()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(self.ctx, self.v.as_ptr(), n) } != 0
            // SAFETY: as above; one octet.
            && unsafe { EVP_MAC_update(self.ctx, byte.as_ptr(), 1) } != 0;
        for i in inputs.iter().filter(|i| !i.is_empty()) {
            // SAFETY: as above; the input's octets.
            ok = ok && unsafe { EVP_MAC_update(self.ctx, i.as_ptr(), i.len()) } != 0;
        }
        // SAFETY: as above; room for any digest.
        ok = ok
            && unsafe { EVP_MAC_final(self.ctx, self.k.as_mut_ptr(), ptr::null_mut(), MAX_MD) }
                != 0;
        // SAFETY: as above.
        ok && unsafe { EVP_MAC_init(self.ctx, self.k.as_ptr(), n, ptr::null()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MAC_update(self.ctx, self.v.as_ptr(), n) } != 0
            // SAFETY: as above.
            && unsafe { EVP_MAC_final(self.ctx, self.v.as_mut_ptr(), ptr::null_mut(), MAX_MD) } != 0
    }

    /// `drbg_hmac_update`: a round of `do_hmac` with 0, and one with 1 if there's input.
    fn update(&mut self, inputs: &[&[u8]]) -> bool {
        if !self.do_hmac(0, inputs) {
            return false;
        }
        if inputs.iter().all(|i| i.is_empty()) {
            return true;
        }
        self.do_hmac(1, inputs)
    }

    /// `ossl_drbg_hmac_init`: K = 0, V = 1, then the update with the inputs.
    pub(super) fn init(&mut self, entropy: &[u8], nonce: &[u8], pers: &[u8]) -> bool {
        if self.ctx.is_null() {
            raise(PROV_R_MISSING_MAC, "ossl_drbg_hmac_init");
            return false;
        }
        let n = self.blocklen.min(MAX_MD);
        self.k.iter_mut().take(n).for_each(|b| *b = 0);
        self.v.iter_mut().take(n).for_each(|b| *b = 1);
        self.update(&[entropy, nonce, pers])
    }

    /// `ossl_drbg_hmac_generate`: V = HMAC(K, V) blocks, the ones before the last chained
    /// through the output (V itself takes only the last), then the update with `adin`.
    pub(super) fn generate(&mut self, out: &mut [u8], adin: &[u8]) -> bool {
        if self.ctx.is_null() {
            return false;
        }
        if !adin.is_empty() && !self.update(&[adin]) {
            return false;
        }
        let n = self.blocklen.min(MAX_MD);
        let (mut pos, mut prev): (usize, Option<usize>) = (0, None);
        loop {
            let temp = match prev {
                Some(at) => out.get(at..at + n).map_or(ptr::null(), <[u8]>::as_ptr),
                None => self.v.as_ptr(),
            };
            // SAFETY: the live context; K of `n` octets; `temp` of `n` octets (V, or the
            // output block before).
            if unsafe { EVP_MAC_init(self.ctx, self.k.as_ptr(), n, ptr::null()) } == 0
                || temp.is_null()
                // SAFETY: as above.
                || unsafe { EVP_MAC_update(self.ctx, temp, n) } == 0
            {
                return false;
            }
            // Without a block length (a digest refused but kept), each block would advance by
            // nothing: the reference loops forever (docs/DEVIATIONS.md).
            if n == 0 {
                return false;
            }
            let rest = out.len() - pos;
            if rest > n {
                let Some(dst) = out.get_mut(pos..) else {
                    return false;
                };
                // SAFETY: as above; room for `rest` octets, more than a block.
                if unsafe { EVP_MAC_final(self.ctx, dst.as_mut_ptr(), ptr::null_mut(), rest) } == 0
                {
                    return false;
                }
                prev = Some(pos);
            } else {
                // SAFETY: as above; room for any digest.
                if unsafe { EVP_MAC_final(self.ctx, self.v.as_mut_ptr(), ptr::null_mut(), MAX_MD) }
                    == 0
                {
                    return false;
                }
                let (Some(dst), Some(src)) = (out.get_mut(pos..), self.v.get(..rest)) else {
                    return false;
                };
                dst.copy_from_slice(src);
                break;
            }
            pos += n;
        }
        self.update(&[adin])
    }
}

/// The first `n` octets of `b` (all of them if it's shorter).
fn head(b: &[u8], n: usize) -> &[u8] {
    b.get(..n).unwrap_or(b)
}

/// `inc_128`: V + 1, as a 128-bit big-endian number.
fn inc_128(v: &mut [u8; 16]) {
    let n = u128::from_be_bytes(*v).wrapping_add(1);
    *v = n.to_be_bytes();
}

/// `AES_BLOCK_SIZE`.
const BLOCK: usize = 16;

impl CtrState {
    fn new() -> Self {
        Self {
            ctx_ecb: ptr::null_mut(),
            ctx_ctr: ptr::null_mut(),
            ctx_df: ptr::null_mut(),
            cipher_ecb: ptr::null_mut(),
            cipher_ctr: ptr::null_mut(),
            keylen: 0,
            use_df: true,
            k: [0; 32],
            v: [0; 16],
            bltmp: [0; 16],
            bltmp_pos: 0,
            kx: [0; 48],
        }
    }

    /// `ctr_XOR`: the input XORed into K, and what's past the key into V.
    fn xor(&mut self, input: &[u8]) {
        let keylen = self.keylen.min(32);
        for (k, i) in self.k.iter_mut().zip(input.iter().take(keylen)) {
            *k ^= i;
        }
        if input.len() <= keylen {
            return;
        }
        for (v, i) in self.v.iter_mut().zip(input.iter().skip(keylen).take(16)) {
            *v ^= i;
        }
    }

    /// `ctr_BCC_block`: `in` XORed into KX's first `len` octets, which are encrypted in place
    /// with the derivation function's key.
    fn bcc_block(&mut self, input: &[u8]) -> bool {
        let len = input.len().min(48);
        for (k, i) in self.kx.iter_mut().zip(input) {
            *k ^= i;
        }
        let Ok(inl) = c_int::try_from(len) else {
            return false;
        };
        let mut outlen = c_int::try_from(BLOCK).unwrap_or(0);
        // SAFETY: the derivation function's live context; KX holds `len` octets, encrypted in
        // place.
        let ok = unsafe {
            EVP_CipherUpdate(
                self.ctx_df,
                self.kx.as_mut_ptr(),
                &raw mut outlen,
                self.kx.as_ptr(),
                inl,
            )
        } != 0;
        ok && outlen == inl
    }

    /// `ctr_BCC_blocks`: one block of input for each of KX's two or three chains.
    fn bcc_blocks(&mut self, block: &[u8; 16]) -> bool {
        let mut tmp = [0u8; 48];
        let n = if self.keylen == 16 { 2 } else { 3 };
        for chunk in tmp.chunks_mut(16).take(n) {
            chunk.copy_from_slice(block);
        }
        let r = tmp.get(..n * 16).is_some_and(|t| {
            let t: Vec<u8> = t.to_vec();
            self.bcc_block(&t)
        });
        wipe(&mut tmp);
        r
    }

    /// `ctr_BCC_init`.
    fn bcc_init(&mut self) -> bool {
        let mut bltmp = [0u8; 48];
        self.kx = [0; 48];
        let n = if self.keylen == 16 { 2 } else { 3 };
        bltmp[BLOCK + 3] = 1;
        bltmp[BLOCK * 2 + 3] = 2;
        let Some(b) = bltmp.get(..n * BLOCK) else {
            return false;
        };
        let b = b.to_vec();
        self.bcc_block(&b)
    }

    /// `ctr_BCC_update`.
    fn bcc_update(&mut self, input: Option<&[u8]>) -> bool {
        let Some(mut input) = input.filter(|i| !i.is_empty()) else {
            return true;
        };
        if self.bltmp_pos != 0 {
            let left = 16 - self.bltmp_pos;
            if input.len() >= left {
                let (head, rest) = input.split_at(left);
                if let Some(dst) = self.bltmp.get_mut(self.bltmp_pos..) {
                    dst.copy_from_slice(head);
                }
                let b = self.bltmp;
                if !self.bcc_blocks(&b) {
                    return false;
                }
                self.bltmp_pos = 0;
                input = rest;
            }
        }
        let (blocks, tail) = input.as_chunks::<16>();
        for b in blocks {
            if !self.bcc_blocks(b) {
                return false;
            }
        }
        if !tail.is_empty() {
            if let Some(dst) = self
                .bltmp
                .get_mut(self.bltmp_pos..self.bltmp_pos + tail.len())
            {
                dst.copy_from_slice(tail);
            }
            self.bltmp_pos += tail.len();
        }
        true
    }

    /// `ctr_BCC_final`.
    fn bcc_final(&mut self) -> bool {
        if self.bltmp_pos != 0 {
            if let Some(rest) = self.bltmp.get_mut(self.bltmp_pos..) {
                rest.fill(0);
            }
            let b = self.bltmp;
            if !self.bcc_blocks(&b) {
                return false;
            }
        }
        true
    }

    /// `ctr_df`: the derivation function over the three inputs into KX.
    fn df(&mut self, in1: Option<&[u8]>, in2: Option<&[u8]>, in3: Option<&[u8]>) -> bool {
        if !self.bcc_init() {
            return false;
        }
        let len = |i: Option<&[u8]>| i.map_or(0, <[u8]>::len);
        let inlen = len(in1).wrapping_add(len(in2)).wrapping_add(len(in3));
        let l = u32::try_from(inlen & 0xffff_ffff)
            .unwrap_or(0)
            .to_be_bytes();
        self.bltmp[..4].copy_from_slice(&l);
        self.bltmp[4..7].fill(0);
        self.bltmp[7] = u8::try_from((self.keylen + 16) & 0xff).unwrap_or(0);
        self.bltmp_pos = 8;
        if !self.bcc_update(in1)
            || !self.bcc_update(in2)
            || !self.bcc_update(in3)
            || !self.bcc_update(Some(&[0x80]))
            || !self.bcc_final()
        {
            return false;
        }
        // SAFETY: the ECB context, keyed with KX's first `keylen` octets.
        if unsafe {
            EVP_CipherInit_ex(
                self.ctx_ecb,
                ptr::null(),
                ptr::null_mut(),
                self.kx.as_ptr(),
                ptr::null(),
                -1,
            )
        } == 0
        {
            return false;
        }
        let steps: &[(usize, usize)] = if self.keylen == 16 {
            &[(16, 0), (0, 16)]
        } else {
            &[(self.keylen, 0), (0, 16), (16, 32)]
        };
        for &(from, to) in steps {
            let Some(src) = self.kx.get(from..from + BLOCK) else {
                return false;
            };
            let block: [u8; 16] = src.try_into().unwrap_or([0; 16]);
            let mut outlen: c_int = 0;
            let mut out = [0u8; 16];
            // SAFETY: the ECB context; a block in and room for one out.
            if unsafe {
                EVP_CipherUpdate(
                    self.ctx_ecb,
                    out.as_mut_ptr(),
                    &raw mut outlen,
                    block.as_ptr(),
                    16,
                )
            } == 0
                || outlen != 16
            {
                return false;
            }
            if let Some(dst) = self.kx.get_mut(to..to + BLOCK) {
                dst.copy_from_slice(&out);
            }
        }
        true
    }

    /// `ctr_update`: K and V from encrypting V+1 (and V+2), then the inputs (through the
    /// derivation function, or XORed in), and both contexts keyed with K.
    fn update(
        &mut self,
        seedlen: usize,
        in1: Option<&[u8]>,
        in2: Option<&[u8]>,
        nonce: Option<&[u8]>,
    ) -> bool {
        let mut v_tmp = [0u8; 48];
        v_tmp[..16].copy_from_slice(&self.v);
        inc_128(&mut self.v);
        v_tmp[16..32].copy_from_slice(&self.v);
        let len = if self.keylen == 16 {
            32
        } else {
            inc_128(&mut self.v);
            v_tmp[32..48].copy_from_slice(&self.v);
            48
        };
        let mut out = [0u8; 48];
        let mut outlen: c_int = 0;
        let inl = c_int::try_from(len).unwrap_or(0);
        // SAFETY: the ECB context; `len` octets in and room for them out.
        let ok = unsafe {
            EVP_CipherUpdate(
                self.ctx_ecb,
                out.as_mut_ptr(),
                &raw mut outlen,
                v_tmp.as_ptr(),
                inl,
            )
        } != 0;
        wipe(&mut v_tmp);
        if !ok || outlen != inl {
            wipe(&mut out);
            return false;
        }
        let keylen = self.keylen.min(32);
        let (key, rest) = out.split_at(keylen);
        if let Some(k) = self.k.get_mut(..keylen) {
            k.copy_from_slice(key);
        }
        if let Some(v) = rest.get(..16) {
            self.v.copy_from_slice(v);
        }
        wipe(&mut out);
        if self.use_df {
            if (in1.is_some() || nonce.is_some() || in2.is_some()) && !self.df(in1, nonce, in2) {
                return false;
            }
            if in1.is_some_and(|i| !i.is_empty()) {
                let kx = self.kx;
                self.xor(head(&kx, seedlen));
            }
        } else {
            self.xor(in1.unwrap_or_default());
            self.xor(in2.unwrap_or_default());
        }
        // SAFETY: the contexts, keyed with K.
        if unsafe {
            EVP_CipherInit_ex(
                self.ctx_ecb,
                ptr::null(),
                ptr::null_mut(),
                self.k.as_ptr(),
                ptr::null(),
                -1,
            )
        } == 0
        {
            return false;
        }
        // SAFETY: as above.
        let r = unsafe {
            EVP_CipherInit_ex(
                self.ctx_ctr,
                ptr::null(),
                ptr::null_mut(),
                self.k.as_ptr(),
                ptr::null(),
                -1,
            )
        };
        r != 0
    }

    /// `drbg_ctr_generate`.
    fn generate(&mut self, seedlen: usize, out: &mut [u8], adin: Option<&[u8]>) -> bool {
        let mut adin = adin;
        // The length the final update sees: the derivation function's result is reused for
        // it (`adin = NULL, adinlen = 1`).
        let mut reuse_kx = false;
        if let Some(a) = adin.filter(|a| !a.is_empty()) {
            inc_128(&mut self.v);
            if !self.update(seedlen, Some(a), None, None) {
                return false;
            }
            if self.use_df {
                adin = None;
                reuse_kx = true;
            }
        } else {
            adin = adin.map(|_| &[][..]);
        }
        inc_128(&mut self.v);
        if out.is_empty() {
            inc_128(&mut self.v);
            return self.final_update(seedlen, adin, reuse_kx);
        }
        out.fill(0);
        let mut pos = 0usize;
        while pos < out.len() {
            // SAFETY: the CTR context, given V as its counter.
            if unsafe {
                EVP_CipherInit_ex(
                    self.ctx_ctr,
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    self.v.as_ptr(),
                    -1,
                )
            } == 0
            {
                return false;
            }
            let mut buflen = (out.len() - pos).min(1 << 30);
            let mut blocks = u32::try_from(buflen.div_ceil(16)).unwrap_or(0);
            let ctr = u32::from_be_bytes(self.v[12..16].try_into().unwrap_or([0; 4]));
            let mut ctr32 = ctr.wrapping_add(blocks);
            if ctr32 < blocks {
                if ctr32 != 0 {
                    blocks -= ctr32;
                    buflen = usize::try_from(blocks).unwrap_or(0) * 16;
                    ctr32 = 0;
                }
                // `ctr96_inc`: the upper 96 bits + 1.
                let mut hi = [0u8; 16];
                hi[4..16].copy_from_slice(&self.v[..12]);
                let n = u128::from_be_bytes(hi).wrapping_add(1).to_be_bytes();
                self.v[..12].copy_from_slice(&n[4..16]);
            }
            self.v[12..16].copy_from_slice(&ctr32.to_be_bytes());
            let Some(chunk) = out.get_mut(pos..pos + buflen) else {
                return false;
            };
            let Ok(inl) = c_int::try_from(buflen) else {
                return false;
            };
            let mut outl: c_int = 0;
            // SAFETY: the CTR context; the chunk of zeros encrypted in place.
            if unsafe {
                EVP_CipherUpdate(
                    self.ctx_ctr,
                    chunk.as_mut_ptr(),
                    &raw mut outl,
                    chunk.as_ptr(),
                    inl,
                )
            } == 0
                || outl != inl
            {
                return false;
            }
            pos += buflen;
        }
        self.final_update(seedlen, adin, reuse_kx)
    }

    /// The update closing a generation: with the additional input, or with the derivation
    /// function's earlier result reused.
    fn final_update(&mut self, seedlen: usize, adin: Option<&[u8]>, reuse_kx: bool) -> bool {
        if reuse_kx {
            return self.update_reusing_kx(seedlen);
        }
        self.update(seedlen, adin, None, None)
    }

    /// `ctr_update(drbg, NULL, 1, ...)` with the derivation function: K and V advanced, KX
    /// XORed in.
    fn update_reusing_kx(&mut self, seedlen: usize) -> bool {
        let use_df = self.use_df;
        self.use_df = false;
        let kx = self.kx;
        let r = self.update(seedlen, Some(head(&kx, seedlen)), None, None);
        self.use_df = use_df;
        r
    }

    fn uninstantiate(&mut self) {
        wipe(&mut self.k);
        wipe(&mut self.v);
        wipe(&mut self.bltmp);
        wipe(&mut self.kx);
        self.bltmp_pos = 0;
    }

    fn zeroized(&self) -> bool {
        self.k
            .iter()
            .chain(&self.v)
            .chain(&self.bltmp)
            .chain(&self.kx)
            .all(|&b| b == 0)
            && self.bltmp_pos == 0
    }
}

impl HashState {
    fn new() -> Self {
        Self {
            digest: Prov::NONE,
            ctx: ptr::null_mut(),
            blocklen: 0,
            v: [0; HASH_MAX_SEEDLEN],
            c: [0; HASH_MAX_SEEDLEN],
            vtmp: [0; HASH_MAX_SEEDLEN],
        }
    }

    /// One `EVP_DigestInit_ex`, then the updates.
    fn start(&self, parts: &[&[u8]]) -> bool {
        // SAFETY: the live context; the digest (or NULL, which fails).
        let mut ok =
            unsafe { EVP_DigestInit_ex(self.ctx, self.digest.method, ptr::null_mut()) } != 0;
        for p in parts {
            // SAFETY: as above; the part's octets.
            ok = ok && unsafe { EVP_DigestUpdate(self.ctx, p.as_ptr().cast(), p.len()) } != 0;
        }
        ok
    }

    /// `EVP_DigestFinal` into `out` (room for the digest).
    fn finish(&self, out: *mut u8) -> bool {
        // SAFETY: the live context; the caller's room.
        let r = unsafe { EVP_DigestFinal(self.ctx, out, ptr::null_mut()) };
        r != 0
    }

    /// `hash_df`: `seedlen` octets of Hash(counter || bits || [inbyte] || inputs) blocks into
    /// `which` (V or C).
    fn df(&mut self, seedlen: usize, into_c: bool, inbyte: Option<u8>, inputs: &[&[u8]]) -> bool {
        let bits = u32::try_from(seedlen.wrapping_mul(8) & 0xffff_ffff)
            .unwrap_or(0)
            .to_be_bytes();
        let mut tmp = vec![1u8, bits[0], bits[1], bits[2], bits[3]];
        if let Some(b) = inbyte {
            tmp.push(b);
        }
        let mut out = [0u8; HASH_MAX_SEEDLEN];
        let (mut pos, mut outlen) = (0usize, seedlen.min(HASH_MAX_SEEDLEN));
        loop {
            let mut parts: Vec<&[u8]> = vec![&tmp];
            parts.extend_from_slice(inputs);
            if !self.start(&parts) {
                wipe(&mut out);
                return false;
            }
            // Without a block length (a digest refused but kept), each block would advance by
            // nothing: the reference loops forever (docs/DEVIATIONS.md).
            if self.blocklen == 0 {
                wipe(&mut out);
                return false;
            }
            if outlen < self.blocklen {
                let mut vtmp = self.vtmp;
                if !self.finish(vtmp.as_mut_ptr()) {
                    return false;
                }
                if let (Some(dst), Some(src)) = (out.get_mut(pos..pos + outlen), vtmp.get(..outlen))
                {
                    dst.copy_from_slice(src);
                }
                wipe(&mut vtmp);
                self.vtmp
                    .iter_mut()
                    .take(self.blocklen)
                    .for_each(|b| *b = 0);
                break;
            }
            let mut block = [0u8; MAX_MD];
            if !self.finish(block.as_mut_ptr()) {
                wipe(&mut out);
                return false;
            }
            if let (Some(dst), Some(src)) = (
                out.get_mut(pos..pos + self.blocklen),
                block.get(..self.blocklen),
            ) {
                dst.copy_from_slice(src);
            }
            wipe(&mut block);
            outlen -= self.blocklen;
            if outlen == 0 {
                break;
            }
            if let Some(t) = tmp.first_mut() {
                *t = t.wrapping_add(1);
            }
            pos += self.blocklen;
        }
        let n = seedlen.min(HASH_MAX_SEEDLEN);
        let dst = if into_c { &mut self.c } else { &mut self.v };
        if let Some(d) = dst.get_mut(..n) {
            d.copy_from_slice(head(&out, n));
        }
        wipe(&mut out);
        true
    }

    /// `add_bytes`: `dst` (of `seedlen` octets) + `input`, as big-endian numbers.
    fn add_bytes(seedlen: usize, dst: &mut [u8; HASH_MAX_SEEDLEN], input: &[u8]) {
        let Some(d) = dst.get_mut(..seedlen) else {
            return;
        };
        let mut carry = 0u16;
        let n = input.len().min(d.len());
        let (high, low) = d.split_at_mut(d.len() - n);
        for (x, &a) in low.iter_mut().rev().zip(input.iter().rev()) {
            let sum = u16::from(*x) + u16::from(a) + carry;
            *x = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
        if carry != 0 {
            for x in high.iter_mut().rev() {
                *x = x.wrapping_add(1);
                if *x != 0 {
                    break;
                }
            }
        }
    }

    /// `add_hash_to_v`: V + Hash(inbyte || V || adin).
    fn add_hash_to_v(&mut self, seedlen: usize, inbyte: u8, adin: Option<&[u8]>) -> bool {
        let v = self.v;
        let byte = [inbyte];
        let mut parts: Vec<&[u8]> = vec![&byte, v.get(..seedlen).unwrap_or(&v)];
        if let Some(a) = adin {
            parts.push(a);
        }
        if !self.start(&parts) {
            return false;
        }
        let mut vtmp = [0u8; HASH_MAX_SEEDLEN];
        if !self.finish(vtmp.as_mut_ptr()) {
            return false;
        }
        self.vtmp = vtmp;
        let n = self.blocklen.min(seedlen);
        Self::add_bytes(seedlen, &mut self.v, head(&vtmp, n));
        true
    }

    /// `hash_gen`: Hash(data), Hash(data + 1), ... from V.
    fn generate(&mut self, seedlen: usize, out: &mut [u8]) -> bool {
        if out.is_empty() {
            return true;
        }
        self.vtmp = self.v;
        let mut pos = 0usize;
        loop {
            let data = self.vtmp;
            if !self.start(&[head(&data, seedlen)]) {
                return false;
            }
            // As in `df`.
            if self.blocklen == 0 {
                return false;
            }
            let rest = out.len() - pos;
            if rest < self.blocklen {
                let mut vtmp = [0u8; HASH_MAX_SEEDLEN];
                if !self.finish(vtmp.as_mut_ptr()) {
                    return false;
                }
                self.vtmp = vtmp;
                if let (Some(dst), Some(src)) = (out.get_mut(pos..), vtmp.get(..rest)) {
                    dst.copy_from_slice(src);
                }
                return true;
            }
            let mut block = [0u8; MAX_MD];
            if !self.finish(block.as_mut_ptr()) {
                return false;
            }
            if let (Some(dst), Some(src)) = (
                out.get_mut(pos..pos + self.blocklen),
                block.get(..self.blocklen),
            ) {
                dst.copy_from_slice(src);
            }
            wipe(&mut block);
            pos += self.blocklen;
            if pos == out.len() {
                break;
            }
            Self::add_bytes(seedlen, &mut self.vtmp, &[1]);
        }
        true
    }

    fn uninstantiate(&mut self) {
        wipe(&mut self.v);
        wipe(&mut self.c);
        wipe(&mut self.vtmp);
    }

    fn zeroized(&self) -> bool {
        self.v
            .iter()
            .chain(&self.c)
            .chain(&self.vtmp)
            .all(|&b| b == 0)
    }
}

// -------------------------------------------------------------------------------------------
// The framework (`PROV_DRBG`)

/// `PROV_DRBG`.
struct Drbg {
    provctx: *mut c_void,
    parent: Parent,
    locking: bool,
    fork_id: c_int,
    strength: c_uint,
    max_request: usize,
    min_entropylen: usize,
    max_entropylen: usize,
    min_noncelen: usize,
    max_noncelen: usize,
    max_perslen: usize,
    max_adinlen: usize,
    generate_counter: c_uint,
    reseed_interval: c_uint,
    reseed_time: i64,
    reseed_time_interval: i64,
    reseed_next_counter: c_uint,
    parent_reseed_counter: c_uint,
    seedlen: usize,
    state: c_int,
    mech: Mech,
}

// SAFETY: the provider context is the provider's, shared by its algorithms; the parent and
// mechanism are as their own `Send` implementations say.
unsafe impl Send for Drbg {}

/// A DRBG's algorithm context: its state behind a mutex, and its reseed counter, which children
/// read.
struct DrbgCtx {
    reseed_counter: AtomicU32,
    inner: Mutex<Drbg>,
}

/// The library context's nonce counter (`PROV_DRBG_NONCE_GLOBAL`'s `rand_nonce_count`).
static NONCE_COUNT: AtomicI32 = AtomicI32::new(0);

const STATE_UNINIT: c_int = EVP_RAND_STATE_UNINITIALISED as c_int;
const STATE_READY: c_int = EVP_RAND_STATE_READY as c_int;
const STATE_ERROR: c_int = EVP_RAND_STATE_ERROR as c_int;

impl DrbgCtx {
    /// `get_entropy`: from the core without a parent, else from the parent's seed (at the
    /// parent's strength or more).
    fn get_entropy(
        &self,
        d: &Drbg,
        entropy: usize,
        min_len: usize,
        max_len: usize,
        pr: c_int,
    ) -> Entropy {
        let bits = c_int::try_from(entropy).unwrap_or(c_int::MAX);
        if !d.parent.present() {
            return get_entropy(bits, min_len, max_len).map_or(Entropy::None, Entropy::Owned);
        }
        let Some(get_seed) = d.parent.get_seed else {
            raise(PROV_R_PARENT_CANNOT_SUPPLY_ENTROPY_SEED, "get_entropy");
            return Entropy::None;
        };
        let Some(p_str) = d.parent.strength() else {
            return Entropy::None;
        };
        if d.strength > p_str {
            raise(PROV_R_PARENT_STRENGTH_TOO_WEAK, "get_entropy");
            return Entropy::None;
        }
        if !d.parent.lock() {
            return Entropy::None;
        }
        let ask = if bits > 0 {
            bits
        } else {
            c_int::try_from(d.strength).unwrap_or(c_int::MAX)
        };
        let adin = address_bytes(ptr::from_ref(self));
        let mut out: *mut c_uchar = ptr::null_mut();
        // SAFETY: the parent's function with its context, a local for the seed, and the
        // additional input.
        let n = unsafe {
            get_seed(
                d.parent.ctx,
                &raw mut out,
                ask,
                min_len,
                max_len,
                pr,
                adin.as_ptr(),
                adin.len(),
            )
        };
        d.parent.unlock();
        if out.is_null() {
            Entropy::Lent(ptr::null_mut(), n)
        } else {
            Entropy::Lent(out, n)
        }
    }

    /// `cleanup_entropy`: a lent seed goes back to the parent.
    fn cleanup_entropy(d: &Drbg, e: Entropy) {
        if let (Entropy::Lent(p, n), true, Some(clear)) =
            (e, d.parent.present(), d.parent.clear_seed)
        {
            {
                if !d.parent.lock() {
                    return;
                }
                // SAFETY: the parent's function with its context and its own seed.
                unsafe { clear(d.parent.ctx, p, n) };
                d.parent.unlock();
            }
        }
    }

    /// `prov_drbg_get_nonce` without a parent: the core's nonce, salted with the context and
    /// a count.
    fn core_nonce(&self, d: &Drbg) -> Option<Seed> {
        let count = NONCE_COUNT.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let mut salt = [0u8; 16];
        let addr = address_bytes(ptr::from_ref(self));
        let (a, b) = salt.split_at_mut(8);
        if let Some(a) = a.get_mut(..addr.len()) {
            a.copy_from_slice(&addr);
        }
        if let Some(b) = b.get_mut(..4) {
            b.copy_from_slice(&count.to_ne_bytes());
        }
        get_nonce(d.min_noncelen, d.max_noncelen, &salt)
    }

    /// `ossl_prov_drbg_instantiate`.
    fn instantiate(&self, d: &mut Drbg, strength: c_uint, pr: c_int, pers: Option<&[u8]>) -> bool {
        const F: &str = "ossl_prov_drbg_instantiate";
        // The reference's early failures jump to its end, which answers whether the DRBG is
        // ready: an instantiated one raises the error and succeeds.
        if strength > d.strength {
            raise(PROV_R_INSUFFICIENT_DRBG_STRENGTH, F);
            return d.state == STATE_READY;
        }
        let mut min_entropy = usize::try_from(d.strength).unwrap_or(usize::MAX);
        let (mut min_entropylen, mut max_entropylen) = (d.min_entropylen, d.max_entropylen);
        let pers = pers.unwrap_or(DEFAULT_PERS);
        if pers.len() > d.max_perslen {
            raise(PROV_R_PERSONALISATION_STRING_TOO_LONG, F);
            return d.state == STATE_READY;
        }
        if d.state != STATE_UNINIT {
            raise(
                if d.state == STATE_ERROR {
                    PROV_R_IN_ERROR_STATE
                } else {
                    PROV_R_ALREADY_INSTANTIATED
                },
                F,
            );
            return d.state == STATE_READY;
        }
        d.state = STATE_ERROR;
        let mut nonce: Option<Seed> = None;
        if d.min_noncelen > 0 {
            if let Some(parent_nonce) = d.parent.nonce {
                // SAFETY: the parent's function with its context, asked for the length only.
                let n = unsafe {
                    parent_nonce(
                        d.parent.ctx,
                        ptr::null_mut(),
                        d.strength,
                        d.min_noncelen,
                        d.max_noncelen,
                    )
                };
                if n == 0 {
                    raise(PROV_R_ERROR_RETRIEVING_NONCE, F);
                    return false;
                }
                let mut buf = Seed(vec![0u8; n]);
                // SAFETY: as above, with room for the `n` octets.
                let m = unsafe {
                    parent_nonce(
                        d.parent.ctx,
                        buf.0.as_mut_ptr(),
                        d.strength,
                        d.min_noncelen,
                        d.max_noncelen,
                    )
                };
                if m != n {
                    raise(PROV_R_ERROR_RETRIEVING_NONCE, F);
                    return false;
                }
                nonce = Some(buf);
            } else if d.parent.present() {
                min_entropy =
                    min_entropy.saturating_add(usize::try_from(d.strength / 2).unwrap_or(0));
                min_entropylen = min_entropylen.saturating_add(d.min_noncelen);
                max_entropylen = max_entropylen.saturating_add(d.max_noncelen);
            } else {
                let got = self.core_nonce(d);
                let n = got.as_ref().map_or(0, |s| s.0.len());
                if n < d.min_noncelen || n > d.max_noncelen {
                    raise(PROV_R_ERROR_RETRIEVING_NONCE, F);
                    return false;
                }
                nonce = got;
            }
        }
        let counter = self.reseed_counter.load(Ordering::Relaxed);
        d.reseed_next_counter = counter;
        if d.reseed_next_counter != 0 {
            d.reseed_next_counter = d.reseed_next_counter.wrapping_add(1);
            if d.reseed_next_counter == 0 {
                d.reseed_next_counter = 1;
            }
        }
        let entropy = self.get_entropy(d, min_entropy, min_entropylen, max_entropylen, pr);
        let len = entropy.len();
        if len < min_entropylen || len > max_entropylen {
            raise(PROV_R_ERROR_RETRIEVING_ENTROPY, F);
            Self::cleanup_entropy(d, entropy);
            return false;
        }
        let nonce_octets = nonce.as_ref().map(|s| &s.0[..]);
        let ok = mech_instantiate(d, entropy.octets(), nonce_octets, pers);
        Self::cleanup_entropy(d, entropy);
        if !ok {
            raise(PROV_R_ERROR_INSTANTIATING_DRBG, F);
            return false;
        }
        d.state = STATE_READY;
        d.generate_counter = 1;
        d.reseed_time = now();
        self.reseed_counter
            .store(d.reseed_next_counter, Ordering::Relaxed);
        true
    }

    /// `rand_drbg_restart`.
    fn restart(&self, d: &mut Drbg) -> bool {
        if d.state == STATE_ERROR {
            mech_uninstantiate(d);
        }
        if d.state == STATE_UNINIT {
            let strength = d.strength;
            self.instantiate(d, strength, 0, None);
        }
        d.state == STATE_READY
    }

    /// The restart a reseed or generation tries, and its errors.
    fn ready(&self, d: &mut Drbg, function: &str) -> bool {
        if d.state != STATE_READY {
            self.restart(d);
            if d.state == STATE_ERROR {
                raise(PROV_R_IN_ERROR_STATE, function);
                return false;
            }
            if d.state == STATE_UNINIT {
                raise(PROV_R_NOT_INSTANTIATED, function);
                return false;
            }
        }
        true
    }

    /// `ossl_prov_drbg_reseed_unlocked`.
    fn reseed(&self, d: &mut Drbg, pr: c_int, ent: Option<&[u8]>, adin: Option<&[u8]>) -> bool {
        const F: &str = "ossl_prov_drbg_reseed_unlocked";
        if !self.ready(d, F) {
            return false;
        }
        if let Some(e) = ent {
            if e.len() < d.min_entropylen {
                err::raise(ERR_LIB_RAND, RAND_R_ENTROPY_OUT_OF_RANGE, F);
                d.state = STATE_ERROR;
                return false;
            }
            if e.len() > d.max_entropylen {
                err::raise(ERR_LIB_RAND, RAND_R_ENTROPY_INPUT_TOO_LONG, F);
                d.state = STATE_ERROR;
                return false;
            }
        }
        let mut adin = adin;
        if adin.is_some_and(|a| a.len() > d.max_adinlen) {
            raise(PROV_R_ADDITIONAL_INPUT_TOO_LONG, F);
            return false;
        }
        d.state = STATE_ERROR;
        d.reseed_next_counter = self.reseed_counter.load(Ordering::Relaxed);
        if d.reseed_next_counter != 0 {
            d.reseed_next_counter = d.reseed_next_counter.wrapping_add(1);
            if d.reseed_next_counter == 0 {
                d.reseed_next_counter = 1;
            }
        }
        if let Some(e) = ent {
            if !mech_reseed(d, Some(e), adin) {
                raise(PROV_R_UNABLE_TO_RESEED, F);
                return false;
            }
            adin = None;
        }
        let (min, max, strength) = (
            d.min_entropylen,
            d.max_entropylen,
            usize::try_from(d.strength).unwrap_or(0),
        );
        let entropy = self.get_entropy(d, strength, min, max, pr);
        let len = entropy.len();
        let ok = if len < min || len > max {
            raise(PROV_R_ERROR_RETRIEVING_ENTROPY, F);
            false
        } else if mech_reseed(d, entropy.octets(), adin) {
            d.state = STATE_READY;
            d.generate_counter = 1;
            d.reseed_time = now();
            self.reseed_counter
                .store(d.reseed_next_counter, Ordering::Relaxed);
            if d.parent.present() {
                let own = self.reseed_counter.load(Ordering::Relaxed);
                d.parent_reseed_counter = d.parent.reseed_count(own);
            }
            true
        } else {
            false
        };
        Self::cleanup_entropy(d, entropy);
        ok
    }

    /// `ossl_prov_drbg_generate`.
    fn generate(
        &self,
        d: &mut Drbg,
        out: &mut [u8],
        strength: c_uint,
        pr: c_int,
        adin: Option<&[u8]>,
    ) -> bool {
        const F: &str = "ossl_prov_drbg_generate";
        if !self.ready(d, F) {
            return false;
        }
        if strength > d.strength {
            raise(PROV_R_INSUFFICIENT_DRBG_STRENGTH, F);
            return false;
        }
        if out.len() > d.max_request {
            raise(PROV_R_REQUEST_TOO_LARGE_FOR_DRBG, F);
            return false;
        }
        if adin.map_or(0, <[u8]>::len) > d.max_adinlen {
            raise(PROV_R_ADDITIONAL_INPUT_TOO_LONG, F);
            return false;
        }
        let mut reseed_required = false;
        let id = fork_id();
        if d.fork_id != id {
            d.fork_id = id;
            reseed_required = true;
        }
        if d.reseed_interval > 0 && d.generate_counter >= d.reseed_interval {
            reseed_required = true;
        }
        if d.reseed_time_interval > 0 {
            let t = now();
            if t < d.reseed_time || t - d.reseed_time >= d.reseed_time_interval {
                reseed_required = true;
            }
        }
        if d.parent.present() {
            let own = self.reseed_counter.load(Ordering::Relaxed);
            if d.parent.reseed_count(own) != d.parent_reseed_counter {
                reseed_required = true;
            }
        }
        let mut adin = adin;
        if reseed_required || pr != 0 {
            if !self.reseed(d, pr, None, adin) {
                raise(PROV_R_RESEED_ERROR, F);
                return false;
            }
            adin = None;
        }
        if !mech_generate(d, out, adin) {
            d.state = STATE_ERROR;
            raise(PROV_R_GENERATE_ERROR, F);
            return false;
        }
        d.generate_counter = d.generate_counter.wrapping_add(1);
        true
    }
}

/// The mechanism's instantiate (`drbg->instantiate`).
fn mech_instantiate(
    d: &mut Drbg,
    entropy: Option<&[u8]>,
    nonce: Option<&[u8]>,
    pers: &[u8],
) -> bool {
    let seedlen = d.seedlen;
    match &mut d.mech {
        Mech::Ctr(c) => {
            if entropy.is_none() {
                return false;
            }
            c.k = [0; 32];
            c.v = [0; 16];
            // SAFETY: the ECB context (or NULL, which fails), keyed with K.
            if unsafe {
                EVP_CipherInit_ex(
                    c.ctx_ecb,
                    ptr::null(),
                    ptr::null_mut(),
                    c.k.as_ptr(),
                    ptr::null(),
                    -1,
                )
            } == 0
            {
                return false;
            }
            inc_128(&mut c.v);
            c.update(seedlen, entropy, Some(pers), nonce)
        }
        Mech::Hash(h) => {
            // SAFETY: the context this owns, or NULL.
            unsafe { EVP_MD_CTX_free(h.ctx) };
            // SAFETY: no preconditions.
            h.ctx = unsafe { EVP_MD_CTX_new() };
            if h.ctx.is_null() {
                return false;
            }
            let inputs = [entropy.unwrap_or_default(), nonce.unwrap_or_default(), pers];
            if !h.df(seedlen, false, None, &inputs) {
                return false;
            }
            let v = h.v;
            h.df(seedlen, true, Some(0), &[head(&v, seedlen)])
        }
        Mech::Hmac(m) => m.init(entropy.unwrap_or_default(), nonce.unwrap_or_default(), pers),
    }
}

/// The mechanism's reseed (`drbg->reseed`).
fn mech_reseed(d: &mut Drbg, entropy: Option<&[u8]>, adin: Option<&[u8]>) -> bool {
    let seedlen = d.seedlen;
    match &mut d.mech {
        Mech::Ctr(c) => {
            if entropy.is_none() {
                return false;
            }
            inc_128(&mut c.v);
            c.update(seedlen, entropy, adin, None)
        }
        Mech::Hash(h) => {
            let v = h.v;
            let inputs = [
                head(&v, seedlen),
                entropy.unwrap_or_default(),
                adin.unwrap_or_default(),
            ];
            // hash_df(C, 0x01, V, ent, adin), then V = C and C = hash_df(0x00, V).
            if !h.df(seedlen, true, Some(1), &inputs) {
                return false;
            }
            h.v = h.c;
            let v = h.v;
            h.df(seedlen, true, Some(0), &[head(&v, seedlen)])
        }
        Mech::Hmac(m) => m.update(&[entropy.unwrap_or_default(), adin.unwrap_or_default()]),
    }
}

/// The mechanism's generate (`drbg->generate`).
fn mech_generate(d: &mut Drbg, out: &mut [u8], adin: Option<&[u8]>) -> bool {
    let (seedlen, counter) = (d.seedlen, d.generate_counter);
    match &mut d.mech {
        Mech::Ctr(c) => c.generate(seedlen, out, adin),
        Mech::Hash(h) => {
            if h.ctx.is_null() {
                return false;
            }
            if let Some(a) = adin.filter(|a| !a.is_empty())
                && !h.add_hash_to_v(seedlen, 0x02, Some(a))
            {
                return false;
            }
            if !h.generate(seedlen, out) || !h.add_hash_to_v(seedlen, 0x03, None) {
                return false;
            }
            let c = h.c;
            HashState::add_bytes(seedlen, &mut h.v, head(&c, seedlen));
            HashState::add_bytes(seedlen, &mut h.v, &counter.to_be_bytes());
            true
        }
        Mech::Hmac(m) => m.generate(out, adin.unwrap_or_default()),
    }
}

/// The mechanism's uninstantiate: its secrets wiped, the state uninstantiated.
fn mech_uninstantiate(d: &mut Drbg) {
    match &mut d.mech {
        Mech::Ctr(c) => c.uninstantiate(),
        Mech::Hash(h) => h.uninstantiate(),
        Mech::Hmac(m) => {
            wipe(&mut m.k);
            wipe(&mut m.v);
        }
    }
    d.state = STATE_UNINIT;
}

// -------------------------------------------------------------------------------------------
// The mechanisms' parameters

/// `drbg_ctr_init_lengths`.
fn ctr_init_lengths(d: &mut Drbg) {
    let Mech::Ctr(c) = &d.mech else { return };
    let (keylen, use_df) = (c.keylen, c.use_df);
    d.max_request = MAX_REQUEST;
    if use_df {
        d.min_entropylen = 0;
        d.max_entropylen = MAX_LENGTH;
        d.min_noncelen = 0;
        d.max_noncelen = MAX_LENGTH;
        d.max_perslen = MAX_LENGTH;
        d.max_adinlen = MAX_LENGTH;
        if keylen > 0 {
            d.min_entropylen = keylen;
            d.min_noncelen = keylen / 2;
        }
    } else {
        let len = if keylen > 0 { d.seedlen } else { MAX_LENGTH };
        d.min_entropylen = len;
        d.max_entropylen = len;
        d.min_noncelen = 0;
        d.max_noncelen = 0;
        d.max_perslen = len;
        d.max_adinlen = len;
    }
}

/// `drbg_ctr_init`: the contexts for the ciphers, the strength and seed length from the key
/// length, and the derivation function's context.
fn ctr_init(d: &mut Drbg) -> bool {
    const F: &str = "drbg_ctr_init";
    const DF_KEY: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let Mech::Ctr(c) = &mut d.mech else {
        return false;
    };
    if c.cipher_ctr.is_null() {
        raise(PROV_R_MISSING_CIPHER, F);
        return false;
    }
    // SAFETY: the cipher this holds.
    let keylen = usize::try_from(unsafe { EVP_CIPHER_get_key_length(c.cipher_ctr) }).unwrap_or(0);
    // A CTR cipher with a longer key than K holds can't be a DRBG's (no such cipher exists).
    if keylen > 32 {
        raise(PROV_R_UNABLE_TO_INITIALISE_CIPHERS, F);
        return false;
    }
    c.keylen = keylen;
    if c.ctx_ecb.is_null() {
        // SAFETY: no preconditions.
        c.ctx_ecb = unsafe { EVP_CIPHER_CTX_new() };
    }
    if c.ctx_ctr.is_null() {
        // SAFETY: no preconditions.
        c.ctx_ctr = unsafe { EVP_CIPHER_CTX_new() };
    }
    let free_contexts = |c: &mut CtrState| {
        // SAFETY: the contexts this owns, or NULL.
        unsafe { EVP_CIPHER_CTX_free(c.ctx_ecb) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_CTX_free(c.ctx_ctr) };
        c.ctx_ecb = ptr::null_mut();
        c.ctx_ctr = ptr::null_mut();
    };
    if c.ctx_ecb.is_null() || c.ctx_ctr.is_null() {
        raise(ERR_R_EVP_LIB, F);
        free_contexts(c);
        return false;
    }
    // SAFETY: the contexts and ciphers this holds.
    let ok = unsafe { EVP_CipherInit_ex(c.ctx_ecb, c.cipher_ecb, ptr::null_mut(), ptr::null(), ptr::null(), 1) } != 0
        // SAFETY: as above.
        && unsafe { EVP_CipherInit_ex(c.ctx_ctr, c.cipher_ctr, ptr::null_mut(), ptr::null(), ptr::null(), 1) } != 0;
    if !ok {
        raise(PROV_R_UNABLE_TO_INITIALISE_CIPHERS, F);
        free_contexts(c);
        return false;
    }
    d.strength = c_uint::try_from(keylen * 8).unwrap_or(0);
    d.seedlen = keylen + 16;
    if c.use_df {
        if c.ctx_df.is_null() {
            // SAFETY: no preconditions.
            c.ctx_df = unsafe { EVP_CIPHER_CTX_new() };
        }
        if c.ctx_df.is_null() {
            raise(ERR_R_EVP_LIB, F);
            free_contexts(c);
            return false;
        }
        // SAFETY: the context and cipher this holds; the key (of up to 32 octets).
        if unsafe {
            EVP_CipherInit_ex(
                c.ctx_df,
                c.cipher_ecb,
                ptr::null_mut(),
                DF_KEY.as_ptr(),
                ptr::null(),
                1,
            )
        } == 0
        {
            raise(PROV_R_DERIVATION_FUNCTION_INIT_FAILED, F);
            free_contexts(c);
            return false;
        }
    }
    ctr_init_lengths(d);
    true
}

/// The query a DRBG fetches its methods with: `properties`, or `provider=default`.
fn propquery(params: *const OSSL_PARAM) -> Result<*const c_char, ()> {
    // SAFETY: the callers' guarantee: `params` is NULL or a parameter array.
    match unsafe { locate(params, OSSL_DRBG_PARAM_PROPERTIES) } {
        Some(p) if p.data_type == OSSL_PARAM_UTF8_STRING as u32 => Ok(p.data.cast_const().cast()),
        Some(_) => Err(()),
        None => Ok(c"provider=default".as_ptr()),
    }
}

/// `drbg_ctr_set_ctx_params_locked`.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn ctr_set_params(d: &mut Drbg, params: *const OSSL_PARAM) -> bool {
    const F: &str = "drbg_ctr_set_ctx_params_locked";
    // SAFETY: the DRBG's provider context.
    let libctx = unsafe { libctx_of(d.provctx) };
    let mut cipher_init = false;
    // SAFETY: the caller's guarantee.
    if let Some(p) = unsafe { locate(params, OSSL_DRBG_PARAM_USE_DF) } {
        let mut i: c_int = 0;
        // SAFETY: a parameter of the caller's array; a local.
        if unsafe { OSSL_PARAM_get_int(p, &raw mut i) } != 0 {
            if let Mech::Ctr(c) = &mut d.mech {
                c.use_df = i != 0;
            }
            cipher_init = true;
        }
    }
    let Ok(propq) = propquery(params) else {
        return false;
    };
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_DRBG_PARAM_CIPHER) } {
        if p.data_type != OSSL_PARAM_UTF8_STRING as u32 || p.data_size < 3 || p.data.is_null() {
            return false;
        }
        // SAFETY: a UTF-8 string parameter's data: a C string.
        let base = unsafe { CStr::from_ptr(p.data.cast_const().cast()) };
        let bytes = base.to_bytes();
        // The reference compares the C string from `data_size - 3`; for a string of its
        // `data_size` that is the last three characters.
        let tail_ok = bytes.len() == p.data_size
            && bytes
                .get(p.data_size - 3..)
                .is_some_and(|t| t.eq_ignore_ascii_case(b"CTR"));
        if !tail_ok {
            raise(PROV_R_REQUIRE_CTR_MODE_CIPHER, F);
            return false;
        }
        let mut ecb = bytes.get(..p.data_size - 3).unwrap_or_default().to_vec();
        ecb.extend_from_slice(b"ECB");
        let Ok(ecb) = std::ffi::CString::new(ecb) else {
            return false;
        };
        let Mech::Ctr(c) = &mut d.mech else {
            return false;
        };
        // SAFETY: the ciphers this holds, or NULL.
        unsafe { EVP_CIPHER_free(c.cipher_ecb) };
        // SAFETY: as above.
        unsafe { EVP_CIPHER_free(c.cipher_ctr) };
        // SAFETY: the provider's library context; the names and query.
        c.cipher_ctr = unsafe { EVP_CIPHER_fetch(libctx, base.as_ptr(), propq) };
        // SAFETY: as above.
        c.cipher_ecb = unsafe { EVP_CIPHER_fetch(libctx, ecb.as_ptr(), propq) };
        if c.cipher_ctr.is_null() || c.cipher_ecb.is_null() {
            raise(PROV_R_UNABLE_TO_FIND_CIPHERS, F);
            return false;
        }
        cipher_init = true;
    }
    if cipher_init && !ctr_init(d) {
        return false;
    }
    // SAFETY: the caller's guarantee.
    unsafe { common_set_params(d, params) }
}

/// `ossl_drbg_verify_digest` outside FIPS: no XOF.
fn verify_digest(md: *const EVP_MD) -> bool {
    // SAFETY: a live digest.
    if unsafe { EVP_MD_xof(md) } != 0 {
        raise(PROV_R_XOF_DIGESTS_NOT_ALLOWED, "ossl_drbg_verify_digest");
        return false;
    }
    true
}

/// `drbg_hash_set_ctx_params_locked`: the digest (fetched with `provider=default` unless
/// `properties` say otherwise, falling back to the plain load), and the lengths it sets.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn hash_set_params(d: &mut Drbg, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the DRBG's provider context.
    let libctx = unsafe { libctx_of(d.provctx) };
    let Mech::Hash(h) = &mut d.mech else {
        return false;
    };
    // `drbg_fetch_digest_from_prov`.
    // SAFETY: the caller's guarantee.
    let props = match unsafe { locate(params, OSSL_DRBG_PARAM_PROPERTIES) } {
        Some(p) if p.data_type == OSSL_PARAM_UTF8_STRING as u32 => p.data.cast_const().cast(),
        _ => c"provider=default".as_ptr(),
    };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: as above.
    let fetched: Option<*mut EVP_MD> = match unsafe { locate(params, OSSL_ALG_PARAM_DIGEST) } {
        None => Some(ptr::null_mut()),
        Some(p) if p.data_type != OSSL_PARAM_UTF8_STRING as u32 => None,
        Some(p) => {
            // SAFETY: the provider's library context; the parameter's string; the query.
            let md = unsafe { EVP_MD_fetch(libctx, p.data.cast_const().cast(), props) };
            (!md.is_null()).then_some(md)
        }
    };
    match fetched {
        None => {
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
            // SAFETY: the caller's array.
            if !unsafe { h.digest.load(params, OSSL_ALG_PARAM_DIGEST, libctx) } {
                return false;
            }
        }
        Some(md) => {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            if !md.is_null() {
                h.digest.reset();
                h.digest.method = md;
            }
        }
    }
    let md = h.digest.method;
    if !md.is_null() {
        if !verify_digest(md) {
            return false;
        }
        // SAFETY: a live digest.
        let Some(size) = usize::try_from(unsafe { EVP_MD_get_size(md) })
            .ok()
            .filter(|&n| n > 0)
        else {
            return false;
        };
        h.blocklen = size;
        d.strength = c_uint::try_from((size >> 3) * 64).unwrap_or(256).min(256);
        d.seedlen = if size > 32 {
            HASH_MAX_SEEDLEN
        } else {
            HASH_SMALL_SEEDLEN
        };
        d.min_entropylen = usize::try_from(d.strength / 8).unwrap_or(0);
        d.min_noncelen = d.min_entropylen / 2;
    }
    // SAFETY: the caller's guarantee.
    unsafe { common_set_params(d, params) }
}

/// `drbg_fetch_algs_from_prov`: the digest and the MAC (HMAC unless `mac` says otherwise),
/// fetched with the query, the MAC context made with the digest; false (with errors) if any
/// part fails, which leaves no MAC context if it got that far.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn hmac_fetch_algs(
    params: *const OSSL_PARAM,
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    macctx: &mut *mut EVP_MAC_CTX,
    digest: &mut *mut EVP_MD,
    propq: *const c_char,
) -> bool {
    const F: &str = "drbg_fetch_algs_from_prov";
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { locate(params, OSSL_ALG_PARAM_DIGEST) }) else {
        raise(PROV_R_INVALID_DIGEST, F);
        return false;
    };
    let mut digest_name: *const c_char = ptr::null();
    // SAFETY: a parameter of the caller's array; a local.
    if unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &raw mut digest_name) } == 0 {
        raise(PROV_R_VALUE_ERROR, F);
        return false;
    }
    // SAFETY: the library context; the parameter's string; the query.
    let md = unsafe { EVP_MD_fetch(libctx, p.data.cast_const().cast(), propq) };
    if md.is_null() {
        raise(PROV_R_INVALID_DIGEST, F);
        return false;
    }
    // SAFETY: the digest the caller holds, or NULL.
    unsafe { EVP_MD_free(*digest) };
    *digest = md;
    let mut hmac_name: *const c_char = c"HMAC".as_ptr();
    // SAFETY: the caller's guarantee.
    if let Some(p) = unsafe { locate(params, OSSL_ALG_PARAM_MAC) } {
        // SAFETY: a parameter of the caller's array; a local.
        if unsafe { OSSL_PARAM_get_utf8_string_ptr(p, &raw mut hmac_name) } == 0 {
            raise(PROV_R_VALUE_ERROR, F);
            return false;
        }
    }
    // SAFETY: the caller's context, replaced.
    unsafe { EVP_MAC_CTX_free(*macctx) };
    *macctx = ptr::null_mut();
    // SAFETY: the library context; the name; the query.
    let mac = unsafe { EVP_MAC_fetch(libctx, hmac_name, propq) };
    if mac.is_null() {
        return false;
    }
    // SAFETY: the method just fetched.
    *macctx = unsafe { EVP_MAC_CTX_new(mac) };
    // SAFETY: as above; the context holds its own reference.
    unsafe { EVP_MAC_free(mac) };
    // SAFETY: static keys; the caller's strings, which outlive the call.
    let mac_params = [
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_DIGEST.as_ptr(),
                digest_name.cast_mut(),
                0,
            )
        },
        // SAFETY: as above.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_MAC_PARAM_PROPERTIES.as_ptr(),
                propq.cast_mut(),
                0,
            )
        },
        end(),
    ];
    // SAFETY: the new context (or NULL, which fails); the array above.
    if unsafe { EVP_MAC_CTX_set_params(*macctx, mac_params.as_ptr()) } == 0 {
        raise(PROV_R_INVALID_MAC, F);
        // SAFETY: the context made here.
        unsafe { EVP_MAC_CTX_free(*macctx) };
        *macctx = ptr::null_mut();
        return false;
    }
    true
}

/// `drbg_hmac_set_ctx_params_locked`.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn hmac_set_params(d: &mut Drbg, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the DRBG's provider context.
    let libctx = unsafe { libctx_of(d.provctx) };
    let Mech::Hmac(m) = &mut d.mech else {
        return false;
    };
    // SAFETY: the caller's guarantee.
    let props = match unsafe { locate(params, OSSL_DRBG_PARAM_PROPERTIES) } {
        Some(p) if p.data_type == OSSL_PARAM_UTF8_STRING as u32 => p.data.cast_const().cast(),
        _ => c"provider=default".as_ptr(),
    };
    let mut prov_md: *mut EVP_MD = ptr::null_mut();
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the caller's guarantee; the context's MAC context; a local.
    if unsafe { hmac_fetch_algs(params, libctx, &mut m.ctx, &mut prov_md, props) } {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
        if !prov_md.is_null() {
            m.digest.reset();
            m.digest.method = prov_md;
        }
    } else {
        // SAFETY: as above.
        unsafe { ERR_pop_to_mark() };
        // SAFETY: the digest fetched (or NULL).
        unsafe { EVP_MD_free(prov_md) };
        // SAFETY: the caller's array.
        if !unsafe { m.digest.load(params, OSSL_ALG_PARAM_DIGEST, libctx) } {
            return false;
        }
        // SAFETY: the context's MAC context; the caller's array.
        if !unsafe {
            macctx_load(
                &mut m.ctx,
                params,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                libctx,
            )
        } {
            return false;
        }
    }
    let md = m.digest.method;
    if !md.is_null() && !verify_digest(md) {
        return false;
    }
    if !md.is_null() && !m.ctx.is_null() {
        // SAFETY: a live digest.
        let Some(size) = usize::try_from(unsafe { EVP_MD_get_size(md) })
            .ok()
            .filter(|&n| n > 0)
        else {
            return false;
        };
        m.blocklen = size;
        d.strength = c_uint::try_from((size >> 3) * 64).unwrap_or(256).min(256);
        d.seedlen = size;
        d.min_entropylen = usize::try_from(d.strength / 8).unwrap_or(0);
        d.min_noncelen = d.min_entropylen / 2;
    }
    // SAFETY: the caller's guarantee.
    unsafe { common_set_params(d, params) }
}

/// `ossl_drbg_set_ctx_params`: the reseed intervals.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn common_set_params(d: &mut Drbg, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { is_empty(params) } {
        return true;
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_DRBG_PARAM_RESEED_REQUESTS) } {
        // SAFETY: a parameter of the caller's array; the DRBG's field.
        if unsafe { OSSL_PARAM_get_uint(p, &raw mut d.reseed_interval) } == 0 {
            return false;
        }
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL) } {
        let mut t: libc::time_t = 0;
        // SAFETY: as above; a local.
        if unsafe { OSSL_PARAM_get_time_t(p, &raw mut t) } == 0 {
            return false;
        }
        d.reseed_time_interval = t;
    }
    true
}

/// The mechanism's `set_ctx_params` (with the common ones).
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn set_params(d: &mut Drbg, params: *const OSSL_PARAM) -> bool {
    match d.mech {
        // SAFETY: the caller's guarantee.
        Mech::Ctr(_) => unsafe { ctr_set_params(d, params) },
        // SAFETY: as above.
        Mech::Hash(_) => unsafe { hash_set_params(d, params) },
        // SAFETY: as above.
        Mech::Hmac(_) => unsafe { hmac_set_params(d, params) },
    }
}

/// A located parameter, if there.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn find(params: *mut OSSL_PARAM, key: &CStr) -> *mut OSSL_PARAM {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_PARAM_locate(params, key.as_ptr()) }
}

/// The mechanism's `get_ctx_params`: its own parameters, then `ossl_drbg_get_ctx_params`.
///
/// # Safety
/// `params` is a parameter array.
unsafe fn get_params(d: &Drbg, params: *mut OSSL_PARAM) -> bool {
    let set_name = |key: &CStr, name: *const c_char| -> bool {
        // SAFETY: the caller's guarantee.
        let p = unsafe { find(params, key) };
        // SAFETY: a parameter of the caller's array; the method's name.
        p.is_null() || (!name.is_null() && unsafe { OSSL_PARAM_set_utf8_string(p, name) } != 0)
    };
    match &d.mech {
        Mech::Ctr(c) => {
            // SAFETY: the caller's guarantee.
            let p = unsafe { find(params, OSSL_DRBG_PARAM_USE_DF) };
            // SAFETY: a parameter of the caller's array.
            if !p.is_null() && unsafe { OSSL_PARAM_set_int(p, c_int::from(c.use_df)) } == 0 {
                return false;
            }
            let name = if c.cipher_ctr.is_null() {
                ptr::null()
            } else {
                // SAFETY: the cipher this holds.
                unsafe { EVP_CIPHER_get0_name(c.cipher_ctr) }
            };
            if !set_name(OSSL_DRBG_PARAM_CIPHER, name) {
                return false;
            }
        }
        Mech::Hash(h) => {
            let md = h.digest.method;
            // SAFETY: the digest this holds.
            let name = if md.is_null() {
                ptr::null()
            } else {
                // SAFETY: the digest this holds.
                unsafe { EVP_MD_get0_name(md) }
            };
            if !set_name(OSSL_DRBG_PARAM_DIGEST, name) {
                return false;
            }
        }
        Mech::Hmac(m) => {
            let name = if m.ctx.is_null() {
                ptr::null()
            } else {
                // SAFETY: the live context.
                let mac = unsafe { EVP_MAC_CTX_get0_mac(m.ctx) };
                // SAFETY: its method.
                unsafe { EVP_MAC_get0_name(mac) }
            };
            if !set_name(OSSL_DRBG_PARAM_MAC, name) {
                return false;
            }
            let md = m.digest.method;
            // SAFETY: the digest this holds.
            let name = if md.is_null() {
                ptr::null()
            } else {
                // SAFETY: the digest this holds.
                unsafe { EVP_MD_get0_name(md) }
            };
            if !set_name(OSSL_DRBG_PARAM_DIGEST, name) {
                return false;
            }
        }
    }
    let int = |key: &CStr, v: c_int| -> bool {
        // SAFETY: the caller's guarantee.
        let p = unsafe { find(params, key) };
        // SAFETY: a parameter of the caller's array.
        p.is_null() || unsafe { OSSL_PARAM_set_int(p, v) } != 0
    };
    let size = |key: &CStr, v: usize| -> bool {
        // SAFETY: the caller's guarantee.
        let p = unsafe { find(params, key) };
        // SAFETY: a parameter of the caller's array.
        p.is_null() || unsafe { OSSL_PARAM_set_size_t(p, v) } != 0
    };
    let time = |key: &CStr, v: i64| -> bool {
        // SAFETY: the caller's guarantee.
        let p = unsafe { find(params, key) };
        // SAFETY: a parameter of the caller's array.
        p.is_null() || unsafe { OSSL_PARAM_set_time_t(p, v) } != 0
    };
    let strength = c_int::try_from(d.strength).unwrap_or(c_int::MAX);
    if !int(OSSL_RAND_PARAM_STATE, d.state)
        || !int(OSSL_RAND_PARAM_STRENGTH, strength)
        || !size(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, d.min_entropylen)
        || !size(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, d.max_entropylen)
        || !size(OSSL_DRBG_PARAM_MIN_NONCELEN, d.min_noncelen)
        || !size(OSSL_DRBG_PARAM_MAX_NONCELEN, d.max_noncelen)
        || !size(OSSL_DRBG_PARAM_MAX_PERSLEN, d.max_perslen)
        || !size(OSSL_DRBG_PARAM_MAX_ADINLEN, d.max_adinlen)
    {
        return false;
    }
    // SAFETY: the caller's guarantee.
    let p = unsafe { find(params, OSSL_DRBG_PARAM_RESEED_REQUESTS) };
    // SAFETY: a parameter of the caller's array.
    if !p.is_null() && unsafe { OSSL_PARAM_set_uint(p, d.reseed_interval) } == 0 {
        return false;
    }
    time(OSSL_DRBG_PARAM_RESEED_TIME, d.reseed_time)
        && time(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, d.reseed_time_interval)
}

// -------------------------------------------------------------------------------------------
// The DRBGs' dispatch functions

/// Which mechanism a `newctx` makes.
#[derive(Clone, Copy)]
enum Kind {
    Ctr,
    Hash,
    Hmac,
}

/// `ossl_rand_drbg_new` with the mechanism's `dnew`.
///
/// # Safety
/// `provctx` is the provider's context; `parent` is NULL or a random context whose functions
/// `parent_dispatch` gives.
unsafe fn drbg_new(
    provctx: *mut c_void,
    parent: *mut c_void,
    parent_dispatch: *const OSSL_DISPATCH,
    kind: Kind,
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let parent = unsafe {
        Parent::new(
            parent,
            if parent.is_null() {
                ptr::null()
            } else {
                parent_dispatch
            },
        )
    };
    let mut d = Drbg {
        provctx,
        parent,
        locking: false,
        fork_id: fork_id(),
        strength: 0,
        max_request: 0,
        min_entropylen: 0,
        max_entropylen: MAX_LENGTH,
        min_noncelen: 0,
        max_noncelen: MAX_LENGTH,
        max_perslen: MAX_LENGTH,
        max_adinlen: MAX_LENGTH,
        generate_counter: 1,
        reseed_interval: RESEED_INTERVAL,
        reseed_time: 0,
        reseed_time_interval: TIME_INTERVAL,
        reseed_next_counter: 0,
        parent_reseed_counter: 0,
        seedlen: 0,
        state: STATE_UNINIT,
        mech: match kind {
            Kind::Ctr => Mech::Ctr(Box::new(CtrState::new())),
            Kind::Hash => Mech::Hash(Box::new(HashState::new())),
            Kind::Hmac => Mech::Hmac(Box::new(HmacState::new())),
        },
    };
    match kind {
        Kind::Ctr => ctr_init_lengths(&mut d),
        Kind::Hash => {
            d.seedlen = HASH_MAX_SEEDLEN;
            d.max_request = MAX_REQUEST;
        }
        Kind::Hmac => d.max_request = MAX_REQUEST,
    }
    if d.parent.present() {
        let Some(p_str) = d.parent.strength() else {
            return ptr::null_mut();
        };
        if d.strength > p_str {
            raise(PROV_R_PARENT_STRENGTH_TOO_WEAK, "ossl_rand_drbg_new");
            return ptr::null_mut();
        }
    }
    boxed(DrbgCtx {
        reseed_counter: AtomicU32::new(1),
        inner: Mutex::new(d),
    })
}

/// Runs `f` with the DRBG locked; `None` for NULL.
///
/// # Safety
/// `vctx` is NULL or a DRBG context.
unsafe fn with_drbg<R>(vctx: *mut c_void, f: impl FnOnce(&DrbgCtx, &mut Drbg) -> R) -> Option<R> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { shared::<DrbgCtx>(vctx) }?;
    let mut d = guard(&c.inner);
    Some(f(c, &mut d))
}

macro_rules! drbg_newctx {
    ($name:ident, $kind:expr, $doc:literal) => {
        ffi_callback! {
            #[doc = $doc]
            ///
            /// # Safety
            /// `provctx` is the provider's context; `parent` is NULL or a random context whose
            /// functions `parent_dispatch` gives.
            pub(crate) unsafe extern "C" fn $name(provctx: *mut c_void, parent: *mut c_void, parent_dispatch: *const OSSL_DISPATCH) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { drbg_new(provctx, parent, parent_dispatch, $kind) }
            }
        }
    };
}

drbg_newctx!(
    ctr_new,
    Kind::Ctr,
    "`drbg_ctr_new_wrapper`: CTR-DRBG, with the derivation function and no cipher yet."
);
drbg_newctx!(
    hash_new,
    Kind::Hash,
    "`drbg_hash_new_wrapper`: HASH-DRBG, with no digest yet."
);
drbg_newctx!(
    hmac_new,
    Kind::Hmac,
    "`drbg_hmac_new_wrapper`: HMAC-DRBG, with no digest yet."
);

ffi_callback! {
    /// The DRBGs' `freectx`.
    ///
    /// # Safety
    /// `vctx` is NULL or a DRBG context, not used afterwards.
    pub(crate) unsafe extern "C" fn drbg_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<DrbgCtx>(vctx) };
    }
}

ffi_callback! {
    /// The DRBGs' `instantiate` wrapper: the parameters, then the instantiation.
    ///
    /// # Safety
    /// `vctx` is a DRBG context; `pstr` holds `pstr_len` octets (or is NULL); `params` is NULL
    /// or a parameter array.
    pub(crate) unsafe extern "C" fn drbg_instantiate(vctx: *mut c_void, strength: c_uint, prediction_resistance: c_int, pstr: *const c_uchar, pstr_len: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let pers = unsafe { input(pstr, pstr_len) };
        let instantiate = |c: &DrbgCtx, d: &mut Drbg| {
            // SAFETY: the caller's guarantee.
            (unsafe { set_params(d, params) }) && c.instantiate(d, strength, prediction_resistance, pers)
        };
        // SAFETY: as above.
        let r = unsafe { with_drbg(vctx, instantiate) };
        c_int::from(r.unwrap_or(false))
    }
}

ffi_callback! {
    /// The DRBGs' `uninstantiate`: secrets wiped, uninstantiated.
    ///
    /// # Safety
    /// `vctx` is a DRBG context.
    pub(crate) unsafe extern "C" fn drbg_uninstantiate(vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { with_drbg(vctx, |_, d| mech_uninstantiate(d)) }.is_some())
    }
}

ffi_callback! {
    /// The DRBGs' `generate` wrapper (`ossl_prov_drbg_generate`).
    ///
    /// # Safety
    /// `vctx` is a DRBG context; `out` has room for `outlen` octets; `adin` holds `adin_len`
    /// octets (or is NULL).
    pub(crate) unsafe extern "C" fn drbg_generate(vctx: *mut c_void, out: *mut c_uchar, outlen: usize, strength: c_uint, prediction_resistance: c_int, adin: *const c_uchar, adin_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        if out.is_null() && outlen != 0 {
            return 0;
        }
        let out: &mut [u8] = if outlen == 0 {
            &mut []
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { core::slice::from_raw_parts_mut(out, outlen) }
        };
        // SAFETY: as above.
        let adin = unsafe { input(adin, adin_len) };
        // SAFETY: as above.
        let r = unsafe { with_drbg(vctx, |c, d| c.generate(d, out, strength, prediction_resistance, adin)) };
        c_int::from(r.unwrap_or(false))
    }
}

ffi_callback! {
    /// The DRBGs' `reseed` wrapper (`ossl_prov_drbg_reseed`).
    ///
    /// # Safety
    /// `vctx` is a DRBG context; `ent` and `adin` hold their lengths (or are NULL).
    pub(crate) unsafe extern "C" fn drbg_reseed(vctx: *mut c_void, prediction_resistance: c_int, ent: *const c_uchar, ent_len: usize, adin: *const c_uchar, adin_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let ent = unsafe { input(ent, ent_len) };
        // SAFETY: as above.
        let adin = unsafe { input(adin, adin_len) };
        // SAFETY: as above.
        let r = unsafe { with_drbg(vctx, |c, d| c.reseed(d, prediction_resistance, ent, adin)) };
        c_int::from(r.unwrap_or(false))
    }
}

ffi_callback! {
    /// `ossl_drbg_enable_locking`: the parent's locking enabled first.
    ///
    /// # Safety
    /// `vctx` is NULL or a DRBG context.
    pub(crate) unsafe extern "C" fn drbg_enable_locking(vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        let enable_parent = |_: &DrbgCtx, d: &mut Drbg| {
                if !d.locking {
                    if let Some(enable) = d.parent.enable_locking {
                        // SAFETY: the parent's function with its context.
                        if unsafe { enable(d.parent.ctx) } == 0 {
                            raise(PROV_R_PARENT_LOCKING_NOT_ENABLED, "ossl_drbg_enable_locking");
                            return false;
                        }
                    }
                    d.locking = true;
                }
                true
        };
        // SAFETY: the caller's guarantee.
        let r = unsafe { with_drbg(vctx, enable_parent) };
        c_int::from(r.unwrap_or(true))
    }
}

ffi_callback! {
    /// `ossl_drbg_lock`, `seed_src_lock`, and TEST-RAND's: 1 (each context locks itself).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rand_lock(_vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        1
    }
}

ffi_callback! {
    /// `ossl_drbg_unlock` and the others: nothing.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rand_unlock(_vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
    }
}

ffi_callback! {
    /// The DRBGs' `get_ctx_params`: the request limit and reseed counter (alone, if they're
    /// all asked for), else the mechanism's parameters and the common ones.
    ///
    /// # Safety
    /// `vctx` is a DRBG context; `params` is a parameter array (NULL fails here, where the
    /// reference would crash).
    pub(crate) unsafe extern "C" fn drbg_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        if params.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(c) = (unsafe { shared::<DrbgCtx>(vctx) }) else { return 0 };
        let mut cnt = 0usize;
        // SAFETY: the caller's array.
        let p = unsafe { find(params, OSSL_RAND_PARAM_MAX_REQUEST) };
        if !p.is_null() {
            let max_request = guard(&c.inner).max_request;
            // SAFETY: a parameter of the caller's array.
            if unsafe { OSSL_PARAM_set_size_t(p, max_request) } == 0 {
                return 0;
            }
            cnt += 1;
        }
        // SAFETY: as above.
        let p = unsafe { find(params, OSSL_DRBG_PARAM_RESEED_COUNTER) };
        if !p.is_null() {
            // SAFETY: as above.
            if unsafe { OSSL_PARAM_set_uint(p, c.reseed_counter.load(Ordering::Relaxed)) } == 0 {
                return 0;
            }
            cnt += 1;
        }
        // SAFETY: the caller's array has at least `cnt` parameters before its end.
        if unsafe { (*params.wrapping_add(cnt)).key }.is_null() {
            return 1;
        }
        let d = guard(&c.inner);
        // SAFETY: the caller's array.
        c_int::from(unsafe { get_params(&d, params) })
    }
}

ffi_callback! {
    /// The DRBGs' `set_ctx_params`.
    ///
    /// # Safety
    /// `vctx` is a DRBG context; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn drbg_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let set = |_: &DrbgCtx, d: &mut Drbg| unsafe { set_params(d, params) };
        // SAFETY: as above.
        c_int::from(unsafe { with_drbg(vctx, set) }.unwrap_or(false))
    }
}

ffi_callback! {
    /// The DRBGs' `verify_zeroization`: whether the mechanism's secrets are all zero.
    ///
    /// # Safety
    /// `vctx` is a DRBG context.
    pub(crate) unsafe extern "C" fn drbg_verify_zeroization(vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe {
            with_drbg(vctx, |_, d| match &d.mech {
                Mech::Ctr(c) => c.zeroized(),
                Mech::Hash(h) => h.zeroized(),
                Mech::Hmac(m) => m.k.iter().chain(&m.v).all(|&b| b == 0),
            })
        };
        c_int::from(r.unwrap_or(false))
    }
}

ffi_callback! {
    /// `ossl_drbg_get_seed`: `entropy` bits' worth of output (between the lengths) in a
    /// secure buffer, generated with the DRBG's own address as additional input.
    ///
    /// # Safety
    /// `vctx` is a DRBG context; `pout` is valid for a write.
    pub(crate) unsafe extern "C" fn drbg_get_seed(vctx: *mut c_void, pout: *mut *mut c_uchar, entropy: c_int, min_len: usize, max_len: usize, prediction_resistance: c_int, _adin: *const c_uchar, _adin_len: usize) -> usize
    where failure = 0, library = ERR_LIB_PROV
    {
        let mut bytes = usize::try_from(entropy).map_or(0, |e| e.div_ceil(8));
        bytes = bytes.max(min_len).min(max_len);
        // SAFETY: a size; the secure heap or the allocator.
        let buffer = unsafe { CRYPTO_secure_malloc(bytes, ptr::null(), 0) }.cast::<u8>();
        if buffer.is_null() {
            return 0;
        }
        // SAFETY: the buffer just allocated, of `bytes` octets.
        let out = unsafe { core::slice::from_raw_parts_mut(buffer, bytes) };
        let adin = address_bytes(vctx.cast_const());
        // SAFETY: the caller's guarantee.
        let ok = unsafe {
            with_drbg(vctx, |c, d| {
                let strength = d.strength;
                c.generate(d, out, strength, prediction_resistance, Some(&adin))
            })
        }
        .unwrap_or(false);
        if !ok {
            // SAFETY: the buffer allocated above.
            unsafe { CRYPTO_secure_clear_free(buffer.cast(), bytes, ptr::null(), 0) };
            raise(PROV_R_GENERATE_ERROR, "ossl_drbg_get_seed");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        unsafe { pout.write(buffer) };
        bytes
    }
}

ffi_callback! {
    /// `ossl_drbg_clear_seed` and `seed_clear_seed`: frees a seed `get_seed` made.
    ///
    /// # Safety
    /// `out` is NULL or a seed of `outlen` octets from this provider's `get_seed`.
    pub(crate) unsafe extern "C" fn rand_clear_seed(_vctx: *mut c_void, out: *mut c_uchar, outlen: usize)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { CRYPTO_secure_clear_free(out.cast(), outlen, ptr::null(), 0) };
    }
}

/// The parameters each DRBG reports (`OSSL_PARAM_DRBG_GETTABLE_CTX_COMMON`) after its own.
macro_rules! drbg_gettable {
    ($($own:expr),* $(,)?) => {
        Params([
            $($own,)*
            defn(OSSL_RAND_PARAM_STATE, OSSL_PARAM_INTEGER as c_int, size_of::<c_int>()),
            defn(OSSL_RAND_PARAM_STRENGTH, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<c_uint>()),
            defn(OSSL_RAND_PARAM_MAX_REQUEST, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<usize>()),
            defn(OSSL_DRBG_PARAM_MIN_ENTROPYLEN, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<usize>()),
            defn(OSSL_DRBG_PARAM_MAX_ENTROPYLEN, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<usize>()),
            defn(OSSL_DRBG_PARAM_MIN_NONCELEN, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<usize>()),
            defn(OSSL_DRBG_PARAM_MAX_NONCELEN, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<usize>()),
            defn(OSSL_DRBG_PARAM_MAX_PERSLEN, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<usize>()),
            defn(OSSL_DRBG_PARAM_MAX_ADINLEN, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<usize>()),
            defn(OSSL_DRBG_PARAM_RESEED_COUNTER, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<c_uint>()),
            defn(OSSL_DRBG_PARAM_RESEED_TIME, OSSL_PARAM_INTEGER as c_int, size_of::<libc::time_t>()),
            defn(OSSL_DRBG_PARAM_RESEED_REQUESTS, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<c_uint>()),
            defn(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<u64>()),
            PARAM_END,
        ])
    };
}

/// The parameters each DRBG takes (`OSSL_PARAM_DRBG_SETTABLE_CTX_COMMON`) after its own.
macro_rules! drbg_settable {
    ($($own:expr),* $(,)?) => {
        Params([
            $($own,)*
            defn(OSSL_DRBG_PARAM_RESEED_REQUESTS, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<c_uint>()),
            defn(OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, OSSL_PARAM_UNSIGNED_INTEGER as c_int, size_of::<u64>()),
            PARAM_END,
        ])
    };
}

static CTR_GETTABLE: Params<16> = drbg_gettable!(
    defn(OSSL_DRBG_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_DRBG_PARAM_USE_DF,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>()
    ),
);
static CTR_SETTABLE: Params<6> = drbg_settable!(
    defn(
        OSSL_DRBG_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0
    ),
    defn(OSSL_DRBG_PARAM_CIPHER, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(
        OSSL_DRBG_PARAM_USE_DF,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>()
    ),
);
static HASH_GETTABLE: Params<15> = drbg_gettable!(defn(
    OSSL_DRBG_PARAM_DIGEST,
    OSSL_PARAM_UTF8_STRING as c_int,
    0
));
static HASH_SETTABLE: Params<5> = drbg_settable!(
    defn(
        OSSL_DRBG_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0
    ),
    defn(OSSL_DRBG_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
);
static HMAC_GETTABLE: Params<16> = drbg_gettable!(
    defn(OSSL_DRBG_PARAM_MAC, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_DRBG_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
);
static HMAC_SETTABLE: Params<6> = drbg_settable!(
    defn(
        OSSL_DRBG_PARAM_PROPERTIES,
        OSSL_PARAM_UTF8_STRING as c_int,
        0
    ),
    defn(OSSL_DRBG_PARAM_DIGEST, OSSL_PARAM_UTF8_STRING as c_int, 0),
    defn(OSSL_DRBG_PARAM_MAC, OSSL_PARAM_UTF8_STRING as c_int, 0),
);

macro_rules! param_list {
    ($name:ident, $list:ident, $doc:literal) => {
        ffi_callback! {
            #[doc = $doc]
            ///
            /// # Safety
            /// No preconditions.
            pub(crate) unsafe extern "C" fn $name(_ctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
            where failure = ptr::null(), library = ERR_LIB_PROV
            {
                $list.0.as_ptr()
            }
        }
    };
}

param_list!(
    ctr_gettable,
    CTR_GETTABLE,
    "`drbg_ctr_gettable_ctx_params`."
);
param_list!(
    ctr_settable,
    CTR_SETTABLE,
    "`drbg_ctr_settable_ctx_params`."
);
param_list!(
    hash_gettable,
    HASH_GETTABLE,
    "`drbg_hash_gettable_ctx_params`."
);
param_list!(
    hash_settable,
    HASH_SETTABLE,
    "`drbg_hash_settable_ctx_params`."
);
param_list!(
    hmac_gettable,
    HMAC_GETTABLE,
    "`drbg_hmac_gettable_ctx_params`."
);
param_list!(
    hmac_settable,
    HMAC_SETTABLE,
    "`drbg_hmac_settable_ctx_params`."
);

/// A DRBG's dispatch table with its `newctx` and parameter lists.
macro_rules! drbg_table {
    ($new:ident, $settable:ident, $gettable:ident) => {
        Dispatch([
            entry!(OSSL_FUNC_RAND_NEWCTX, $new, NewCtxFn),
            entry!(OSSL_FUNC_RAND_FREECTX, drbg_free, FreeCtxFn),
            entry!(OSSL_FUNC_RAND_INSTANTIATE, drbg_instantiate, InstantiateFn),
            entry!(
                OSSL_FUNC_RAND_UNINSTANTIATE,
                drbg_uninstantiate,
                UninstantiateFn
            ),
            entry!(OSSL_FUNC_RAND_GENERATE, drbg_generate, GenerateFn),
            entry!(OSSL_FUNC_RAND_RESEED, drbg_reseed, ReseedFn),
            entry!(
                OSSL_FUNC_RAND_ENABLE_LOCKING,
                drbg_enable_locking,
                LockingFn
            ),
            entry!(OSSL_FUNC_RAND_LOCK, rand_lock, LockingFn),
            entry!(OSSL_FUNC_RAND_UNLOCK, rand_unlock, UnlockFn),
            entry!(
                OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
                $settable,
                CtxParamsListFn
            ),
            entry!(
                OSSL_FUNC_RAND_SET_CTX_PARAMS,
                drbg_set_ctx_params,
                SetCtxParamsFn
            ),
            entry!(
                OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
                $gettable,
                CtxParamsListFn
            ),
            entry!(
                OSSL_FUNC_RAND_GET_CTX_PARAMS,
                drbg_get_ctx_params,
                GetCtxParamsFn
            ),
            entry!(
                OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
                drbg_verify_zeroization,
                VerifyZeroizationFn
            ),
            entry!(OSSL_FUNC_RAND_GET_SEED, drbg_get_seed, GetSeedFn),
            entry!(OSSL_FUNC_RAND_CLEAR_SEED, rand_clear_seed, ClearSeedFn),
            END,
        ])
    };
}

static CTR_FUNCTIONS: Dispatch<17> = drbg_table!(ctr_new, ctr_settable, ctr_gettable);
static HASH_FUNCTIONS: Dispatch<17> = drbg_table!(hash_new, hash_settable, hash_gettable);
static HMAC_FUNCTIONS: Dispatch<17> = drbg_table!(hmac_new, hmac_settable, hmac_gettable);

// -------------------------------------------------------------------------------------------
// SEED-SRC

/// `PROV_SEED_SRC`: its state.
struct SeedSrc {
    state: AtomicI32,
}

ffi_callback! {
    /// `seed_src_new`: refused (with `PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT`) under a
    /// parent.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn seed_src_new(_provctx: *mut c_void, parent: *mut c_void, _parent_dispatch: *const OSSL_DISPATCH) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        if !parent.is_null() {
            raise(PROV_R_SEED_SOURCES_MUST_NOT_HAVE_A_PARENT, "seed_src_new");
            return ptr::null_mut();
        }
        boxed(SeedSrc { state: AtomicI32::new(STATE_UNINIT) })
    }
}

ffi_callback! {
    /// `seed_src_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a seed source, not used afterwards.
    pub(crate) unsafe extern "C" fn seed_src_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<SeedSrc>(vctx) };
    }
}

ffi_callback! {
    /// `seed_src_instantiate`: ready.
    ///
    /// # Safety
    /// `vctx` is a seed source.
    pub(crate) unsafe extern "C" fn seed_src_instantiate(vctx: *mut c_void, _strength: c_uint, _pr: c_int, _pstr: *const c_uchar, _pstr_len: usize, _params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { shared::<SeedSrc>(vctx) }) else { return 0 };
        s.state.store(STATE_READY, Ordering::Relaxed);
        1
    }
}

ffi_callback! {
    /// `seed_src_uninstantiate`.
    ///
    /// # Safety
    /// `vctx` is a seed source.
    pub(crate) unsafe extern "C" fn seed_src_uninstantiate(vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { shared::<SeedSrc>(vctx) }) else { return 0 };
        s.state.store(STATE_UNINIT, Ordering::Relaxed);
        1
    }
}

/// The error a seed source not ready raises.
fn seed_src_not_ready(s: &SeedSrc, function: &str) -> bool {
    let state = s.state.load(Ordering::Relaxed);
    if state != STATE_READY {
        raise(
            if state == STATE_ERROR {
                PROV_R_IN_ERROR_STATE
            } else {
                PROV_R_NOT_INSTANTIATED
            },
            function,
        );
        return true;
    }
    false
}

ffi_callback! {
    /// `seed_src_generate`: `outlen` octets of the operating system's entropy (with `strength`
    /// bits, which must fit), the additional input mixed in.
    ///
    /// # Safety
    /// `vctx` is a seed source; `out` has room for `outlen` octets; `adin` holds `adin_len`
    /// octets (or is NULL).
    pub(crate) unsafe extern "C" fn seed_src_generate(vctx: *mut c_void, out: *mut c_uchar, outlen: usize, strength: c_uint, _pr: c_int, adin: *const c_uchar, adin_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { shared::<SeedSrc>(vctx) }) else { return 0 };
        if seed_src_not_ready(s, "seed_src_generate") {
            return 0;
        }
        let mut pool = Pool::new(c_int::try_from(strength).unwrap_or(c_int::MAX), outlen, outlen);
        if pool.acquire_entropy() == 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if !pool.adin_mix_in(unsafe { input(adin, adin_len) }.unwrap_or_default()) {
            return 0;
        }
        let got = pool.octets();
        if out.is_null() && !got.is_empty() {
            return 0;
        }
        // SAFETY: the caller's room for `outlen` octets, which the pool's length is.
        unsafe { ptr::copy_nonoverlapping(got.as_ptr(), out, got.len().min(outlen)) };
        1
    }
}

ffi_callback! {
    /// `seed_src_reseed`: nothing to do once ready.
    ///
    /// # Safety
    /// `vctx` is a seed source.
    pub(crate) unsafe extern "C" fn seed_src_reseed(vctx: *mut c_void, _pr: c_int, _ent: *const c_uchar, _ent_len: usize, _adin: *const c_uchar, _adin_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { shared::<SeedSrc>(vctx) }) else { return 0 };
        c_int::from(!seed_src_not_ready(s, "seed_src_reseed"))
    }
}

ffi_callback! {
    /// `seed_src_get_ctx_params`: the state, a strength of 1024, and a request limit of 128.
    ///
    /// # Safety
    /// `vctx` is a seed source; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn seed_src_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { shared::<SeedSrc>(vctx) }) else { return 0 };
        // SAFETY: as above.
        let p = unsafe { find(params, OSSL_RAND_PARAM_STATE) };
        // SAFETY: a parameter of the caller's array.
        if !p.is_null() && unsafe { OSSL_PARAM_set_int(p, s.state.load(Ordering::Relaxed)) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let p = unsafe { find(params, OSSL_RAND_PARAM_STRENGTH) };
        // SAFETY: as above.
        if !p.is_null() && unsafe { OSSL_PARAM_set_int(p, 1024) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let p = unsafe { find(params, OSSL_RAND_PARAM_MAX_REQUEST) };
        // SAFETY: as above.
        if !p.is_null() && unsafe { OSSL_PARAM_set_size_t(p, 128) } == 0 {
            return 0;
        }
        1
    }
}

static SEED_SRC_GETTABLE: Params<4> = Params([
    defn(
        OSSL_RAND_PARAM_STATE,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_RAND_PARAM_STRENGTH,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<c_uint>(),
    ),
    defn(
        OSSL_RAND_PARAM_MAX_REQUEST,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<usize>(),
    ),
    PARAM_END,
]);
param_list!(
    seed_src_gettable,
    SEED_SRC_GETTABLE,
    "`seed_src_gettable_ctx_params`."
);

ffi_callback! {
    /// `seed_src_verify_zeroization` and TEST-RAND's: 1 (they keep no secrets).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rand_zeroized(_vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        1
    }
}

ffi_callback! {
    /// `seed_get_seed`: `entropy` bits of the operating system's in `min_len` to `max_len`
    /// octets, the additional input mixed in, in a secure buffer; 0 (with
    /// `PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK`) if they can't be had.
    ///
    /// # Safety
    /// `pout` is valid for a write; `adin` holds `adin_len` octets (or is NULL).
    pub(crate) unsafe extern "C" fn seed_get_seed(_vctx: *mut c_void, pout: *mut *mut c_uchar, entropy: c_int, min_len: usize, max_len: usize, _pr: c_int, adin: *const c_uchar, adin_len: usize) -> usize
    where failure = 0, library = ERR_LIB_PROV
    {
        let mut pool = Pool::new(entropy, min_len, max_len);
        // SAFETY: the caller's guarantee.
        let adin = unsafe { input(adin, adin_len) }.unwrap_or_default();
        if pool.acquire_entropy() == 0 || !pool.adin_mix_in(adin) {
            raise(PROV_R_ENTROPY_SOURCE_STRENGTH_TOO_WEAK, "seed_get_seed");
            return 0;
        }
        let seed = pool.into_seed();
        let n = seed.0.len();
        // SAFETY: a size; the secure heap or the allocator.
        let buffer = unsafe { CRYPTO_secure_malloc(n, ptr::null(), 0) }.cast::<u8>();
        if buffer.is_null() {
            err::raise(ERR_LIB_PROV, ERR_R_RAND_LIB, "seed_get_seed");
            return 0;
        }
        // SAFETY: the buffer just allocated, of `n` octets.
        unsafe { ptr::copy_nonoverlapping(seed.0.as_ptr(), buffer, n) };
        // SAFETY: the caller's guarantee.
        unsafe { pout.write(buffer) };
        n
    }
}

ffi_callback! {
    /// `seed_src_enable_locking` and TEST-RAND's: 1.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn rand_enable_locking(_vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        1
    }
}

static SEED_SRC_FUNCTIONS: Dispatch<15> = Dispatch([
    entry!(OSSL_FUNC_RAND_NEWCTX, seed_src_new, NewCtxFn),
    entry!(OSSL_FUNC_RAND_FREECTX, seed_src_free, FreeCtxFn),
    entry!(
        OSSL_FUNC_RAND_INSTANTIATE,
        seed_src_instantiate,
        InstantiateFn
    ),
    entry!(
        OSSL_FUNC_RAND_UNINSTANTIATE,
        seed_src_uninstantiate,
        UninstantiateFn
    ),
    entry!(OSSL_FUNC_RAND_GENERATE, seed_src_generate, GenerateFn),
    entry!(OSSL_FUNC_RAND_RESEED, seed_src_reseed, ReseedFn),
    entry!(
        OSSL_FUNC_RAND_ENABLE_LOCKING,
        rand_enable_locking,
        LockingFn
    ),
    entry!(OSSL_FUNC_RAND_LOCK, rand_lock, LockingFn),
    entry!(OSSL_FUNC_RAND_UNLOCK, rand_unlock, UnlockFn),
    entry!(
        OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        seed_src_gettable,
        CtxParamsListFn
    ),
    entry!(
        OSSL_FUNC_RAND_GET_CTX_PARAMS,
        seed_src_get_ctx_params,
        GetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
        rand_zeroized,
        VerifyZeroizationFn
    ),
    entry!(OSSL_FUNC_RAND_GET_SEED, seed_get_seed, GetSeedFn),
    entry!(OSSL_FUNC_RAND_CLEAR_SEED, rand_clear_seed, ClearSeedFn),
    END,
]);

// -------------------------------------------------------------------------------------------
// TEST-RAND

/// `PROV_TEST_RNG`.
struct TestRng {
    generate: c_uint,
    state: c_int,
    strength: c_uint,
    max_request: usize,
    entropy: Option<Seed>,
    entropy_pos: usize,
    nonce: Option<Seed>,
    seed: u32,
}

impl TestRng {
    /// `gen_byte`: xorshift32's next state's low octet.
    fn gen_byte(&mut self) -> u8 {
        let mut n = self.seed;
        n ^= n << 13;
        n ^= n >> 17;
        n ^= n << 5;
        self.seed = n;
        n.to_le_bytes()[0]
    }
}

/// TEST-RAND's context.
struct TestCtx(Mutex<TestRng>);

/// Runs `f` with the test generator locked.
///
/// # Safety
/// `vctx` is NULL or a test generator.
unsafe fn with_test<R>(vctx: *mut c_void, f: impl FnOnce(&mut TestRng) -> R) -> Option<R> {
    // SAFETY: the caller's guarantee.
    let c = unsafe { shared::<TestCtx>(vctx) }?;
    let mut t = guard(&c.0);
    Some(f(&mut t))
}

ffi_callback! {
    /// `test_rng_new` (any parent ignored).
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn test_rng_new(_provctx: *mut c_void, _parent: *mut c_void, _parent_dispatch: *const OSSL_DISPATCH) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        boxed(TestCtx(Mutex::new(TestRng {
            generate: 0,
            state: STATE_UNINIT,
            strength: 0,
            max_request: usize::try_from(c_int::MAX).unwrap_or(usize::MAX),
            entropy: None,
            entropy_pos: 0,
            nonce: None,
            seed: 0,
        })))
    }
}

ffi_callback! {
    /// `test_rng_free`.
    ///
    /// # Safety
    /// `vctx` is NULL or a test generator, not used afterwards.
    pub(crate) unsafe extern "C" fn test_rng_free(vctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<TestCtx>(vctx) };
    }
}

/// `test_rng_set_ctx_params`.
///
/// # Safety
/// `params` is NULL or a parameter array.
unsafe fn test_set_params(t: &mut TestRng, params: *const OSSL_PARAM) -> bool {
    // SAFETY: the caller's guarantee.
    if unsafe { is_empty(params) } {
        return true;
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_RAND_PARAM_STRENGTH) } {
        // SAFETY: a parameter of the caller's array; the generator's field.
        if unsafe { OSSL_PARAM_get_uint(p, &raw mut t.strength) } == 0 {
            return false;
        }
    }
    for (key, is_entropy) in [
        (OSSL_RAND_PARAM_TEST_ENTROPY, true),
        (OSSL_RAND_PARAM_TEST_NONCE, false),
    ] {
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, key) } {
            let mut buf: *mut c_void = ptr::null_mut();
            let mut len = 0usize;
            // SAFETY: as above; locals for the buffer and its length.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut buf, 0, &raw mut len) } == 0 {
                return false;
            }
            let octets = if len == 0 || buf.is_null() {
                Vec::new()
            } else {
                // SAFETY: the buffer just allocated, of `len` octets.
                unsafe { core::slice::from_raw_parts(buf.cast::<u8>(), len) }.to_vec()
            };
            // SAFETY: the buffer allocated above.
            unsafe { crate::mem::release_clean(buf, len.max(1)) };
            if is_entropy {
                t.entropy = Some(Seed(octets));
                t.entropy_pos = 0;
            } else {
                t.nonce = Some(Seed(octets));
            }
        }
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_RAND_PARAM_MAX_REQUEST) } {
        // SAFETY: as above.
        if unsafe { OSSL_PARAM_get_size_t(p, &raw mut t.max_request) } == 0 {
            return false;
        }
    }
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_RAND_PARAM_GENERATE) } {
        // SAFETY: as above.
        if unsafe { OSSL_PARAM_get_uint(p, &raw mut t.generate) } == 0 {
            return false;
        }
    }
    true
}

ffi_callback! {
    /// `test_rng_instantiate`: the parameters, then ready (failing silently above its strength),
    /// the entropy from its start and the generator's seed reset.
    ///
    /// # Safety
    /// `vctx` is a test generator; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn test_rng_instantiate(vctx: *mut c_void, strength: c_uint, _pr: c_int, _pstr: *const c_uchar, _pstr_len: usize, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        let instantiate = |t: &mut TestRng| {
                // SAFETY: the caller's guarantee.
                if !unsafe { test_set_params(t, params) } || strength > t.strength {
                    return false;
                }
                t.state = STATE_READY;
                t.entropy_pos = 0;
                t.seed = 221_953_166;
                true
        };
        // SAFETY: the caller's guarantee.
        let r = unsafe { with_test(vctx, instantiate) };
        c_int::from(r.unwrap_or(false))
    }
}

ffi_callback! {
    /// `test_rng_uninstantiate`.
    ///
    /// # Safety
    /// `vctx` is a test generator.
    pub(crate) unsafe extern "C" fn test_rng_uninstantiate(vctx: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe {
            with_test(vctx, |t| {
                t.entropy_pos = 0;
                t.state = STATE_UNINIT;
            })
        };
        c_int::from(r.is_some())
    }
}

ffi_callback! {
    /// `test_rng_generate`: the xorshift generator's octets, or the next octets of the entropy
    /// (failing silently if too few are left or above its strength). Its state isn't checked.
    ///
    /// # Safety
    /// `vctx` is a test generator; `out` has room for `outlen` octets.
    pub(crate) unsafe extern "C" fn test_rng_generate(vctx: *mut c_void, out: *mut c_uchar, outlen: usize, strength: c_uint, _pr: c_int, _adin: *const c_uchar, _adin_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        if out.is_null() && outlen != 0 {
            return 0;
        }
        let out: &mut [u8] = if outlen == 0 {
            &mut []
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { core::slice::from_raw_parts_mut(out, outlen) }
        };
        // SAFETY: the caller's guarantee.
        let r = unsafe {
            with_test(vctx, |t| {
                if strength > t.strength {
                    return false;
                }
                if t.generate != 0 {
                    out.iter_mut().for_each(|b| *b = t.gen_byte());
                    return true;
                }
                let have = t.entropy.as_ref().map_or(0, |e| e.0.len());
                if have - t.entropy_pos.min(have) < outlen {
                    return false;
                }
                let pos = t.entropy_pos;
                let Some(src) = t.entropy.as_ref().and_then(|e| e.0.get(pos..pos + outlen)) else { return false };
                out.copy_from_slice(src);
                t.entropy_pos += outlen;
                true
            })
        };
        c_int::from(r.unwrap_or(false))
    }
}

ffi_callback! {
    /// `test_rng_reseed`: 1.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn test_rng_reseed(_vctx: *mut c_void, _pr: c_int, _ent: *const c_uchar, _ent_len: usize, _adin: *const c_uchar, _adin_len: usize) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        1
    }
}

ffi_callback! {
    /// `test_rng_nonce`: `min_noncelen` generated octets, or the nonce (up to `max_noncelen`);
    /// 0 above its strength or without a nonce. Asked for the length only (NULL `out`) in
    /// generating mode, it says `min_noncelen` without generating (the reference writes through
    /// NULL; docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `vctx` is a test generator; `out` is NULL or has room for the octets.
    pub(crate) unsafe extern "C" fn test_rng_nonce(vctx: *mut c_void, out: *mut c_uchar, strength: c_uint, min_noncelen: usize, max_noncelen: usize) -> usize
    where failure = 0, library = ERR_LIB_PROV
    {
        let nonce = |t: &mut TestRng| {
                if strength > t.strength {
                    return 0;
                }
                if t.generate != 0 {
                    if !out.is_null() {
                        for i in 0..min_noncelen {
                            let b = t.gen_byte();
                            // SAFETY: the caller's room for `min_noncelen` octets.
                            unsafe { out.wrapping_add(i).write(b) };
                        }
                    }
                    return min_noncelen;
                }
                let Some(nonce) = t.nonce.as_ref() else { return 0 };
                let n = nonce.0.len().min(max_noncelen);
                if !out.is_null() {
                    // SAFETY: the caller's room for the octets.
                    unsafe { ptr::copy_nonoverlapping(nonce.0.as_ptr(), out, n) };
                }
                n
        };
        // SAFETY: the caller's guarantee.
        let r = unsafe { with_test(vctx, nonce) };
        r.unwrap_or(0)
    }
}

ffi_callback! {
    /// `test_rng_get_ctx_params`: the state, strength, request limit, and generating mode.
    ///
    /// # Safety
    /// `vctx` is a test generator; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn test_rng_get_ctx_params(vctx: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        let get = |t: &mut TestRng| {
            let strength = c_int::try_from(t.strength).unwrap_or(c_int::MAX);
            let int = |key: &CStr, v: c_int| {
                // SAFETY: the caller's guarantee.
                let p = unsafe { find(params, key) };
                // SAFETY: a parameter of the caller's array.
                p.is_null() || unsafe { OSSL_PARAM_set_int(p, v) } != 0
            };
            // SAFETY: as above.
            let p = unsafe { find(params, OSSL_RAND_PARAM_MAX_REQUEST) };
            // SAFETY: as above.
            let max_ok = p.is_null() || unsafe { OSSL_PARAM_set_size_t(p, t.max_request) } != 0;
            if !int(OSSL_RAND_PARAM_STATE, t.state) || !int(OSSL_RAND_PARAM_STRENGTH, strength) || !max_ok {
                return false;
            }
            // SAFETY: as above.
            let p = unsafe { find(params, OSSL_RAND_PARAM_GENERATE) };
            // SAFETY: as above.
            p.is_null() || unsafe { OSSL_PARAM_set_uint(p, t.generate) } != 0
        };
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { with_test(vctx, get) }.unwrap_or(false))
    }
}

ffi_callback! {
    /// `test_rng_set_ctx_params`.
    ///
    /// # Safety
    /// `vctx` is a test generator; `params` is NULL or a parameter array.
    pub(crate) unsafe extern "C" fn test_rng_set_ctx_params(vctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let set = |t: &mut TestRng| unsafe { test_set_params(t, params) };
        // SAFETY: as above.
        c_int::from(unsafe { with_test(vctx, set) }.unwrap_or(false))
    }
}

ffi_callback! {
    /// `test_rng_get_seed`: the entropy itself (not a copy, and not consumed), up to `max_len`
    /// octets.
    ///
    /// # Safety
    /// `vctx` is a test generator; `pout` is valid for a write.
    pub(crate) unsafe extern "C" fn test_rng_get_seed(vctx: *mut c_void, pout: *mut *mut c_uchar, _entropy: c_int, _min_len: usize, max_len: usize, _pr: c_int, _adin: *const c_uchar, _adin_len: usize) -> usize
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe {
            with_test(vctx, |t| match t.entropy.as_mut() {
                Some(e) => (e.0.as_mut_ptr(), e.0.len().min(max_len)),
                None => (ptr::null_mut(), 0),
            })
        };
        let (p, n) = r.unwrap_or((ptr::null_mut(), 0));
        // SAFETY: the caller's guarantee.
        unsafe { pout.write(p) };
        n
    }
}

static TEST_GETTABLE: Params<5> = Params([
    defn(
        OSSL_RAND_PARAM_STATE,
        OSSL_PARAM_INTEGER as c_int,
        size_of::<c_int>(),
    ),
    defn(
        OSSL_RAND_PARAM_STRENGTH,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<c_uint>(),
    ),
    defn(
        OSSL_RAND_PARAM_MAX_REQUEST,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<usize>(),
    ),
    defn(
        OSSL_RAND_PARAM_GENERATE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<c_uint>(),
    ),
    PARAM_END,
]);
static TEST_SETTABLE: Params<6> = Params([
    defn(
        OSSL_RAND_PARAM_TEST_ENTROPY,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_RAND_PARAM_TEST_NONCE,
        OSSL_PARAM_OCTET_STRING as c_int,
        0,
    ),
    defn(
        OSSL_RAND_PARAM_STRENGTH,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<c_uint>(),
    ),
    defn(
        OSSL_RAND_PARAM_MAX_REQUEST,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<usize>(),
    ),
    defn(
        OSSL_RAND_PARAM_GENERATE,
        OSSL_PARAM_UNSIGNED_INTEGER as c_int,
        size_of::<c_uint>(),
    ),
    PARAM_END,
]);
param_list!(
    test_rng_gettable,
    TEST_GETTABLE,
    "`test_rng_gettable_ctx_params`."
);
param_list!(
    test_rng_settable,
    TEST_SETTABLE,
    "`test_rng_settable_ctx_params`."
);

static TEST_FUNCTIONS: Dispatch<17> = Dispatch([
    entry!(OSSL_FUNC_RAND_NEWCTX, test_rng_new, NewCtxFn),
    entry!(OSSL_FUNC_RAND_FREECTX, test_rng_free, FreeCtxFn),
    entry!(
        OSSL_FUNC_RAND_INSTANTIATE,
        test_rng_instantiate,
        InstantiateFn
    ),
    entry!(
        OSSL_FUNC_RAND_UNINSTANTIATE,
        test_rng_uninstantiate,
        UninstantiateFn
    ),
    entry!(OSSL_FUNC_RAND_GENERATE, test_rng_generate, GenerateFn),
    entry!(OSSL_FUNC_RAND_RESEED, test_rng_reseed, ReseedFn),
    entry!(OSSL_FUNC_RAND_NONCE, test_rng_nonce, NonceFn),
    entry!(
        OSSL_FUNC_RAND_ENABLE_LOCKING,
        rand_enable_locking,
        LockingFn
    ),
    entry!(OSSL_FUNC_RAND_LOCK, rand_lock, LockingFn),
    entry!(OSSL_FUNC_RAND_UNLOCK, rand_unlock, UnlockFn),
    entry!(
        OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
        test_rng_settable,
        CtxParamsListFn
    ),
    entry!(
        OSSL_FUNC_RAND_SET_CTX_PARAMS,
        test_rng_set_ctx_params,
        SetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
        test_rng_gettable,
        CtxParamsListFn
    ),
    entry!(
        OSSL_FUNC_RAND_GET_CTX_PARAMS,
        test_rng_get_ctx_params,
        GetCtxParamsFn
    ),
    entry!(
        OSSL_FUNC_RAND_VERIFY_ZEROIZATION,
        rand_zeroized,
        VerifyZeroizationFn
    ),
    entry!(OSSL_FUNC_RAND_GET_SEED, test_rng_get_seed, GetSeedFn),
    END,
]);

/// `deflt_rands` (without JITTER, which the default build leaves out), in the reference's order.
static DEFAULT_RANDS: Algorithms<6> = Algorithms([
    alg(c"CTR-DRBG", &CTR_FUNCTIONS),
    alg(c"HASH-DRBG", &HASH_FUNCTIONS),
    alg(c"HMAC-DRBG", &HMAC_FUNCTIONS),
    alg(c"SEED-SRC", &SEED_SRC_FUNCTIONS),
    alg(c"TEST-RAND", &TEST_FUNCTIONS),
    ALG_END,
]);

/// The default provider's random table.
pub(crate) fn default_rands() -> *const OSSL_ALGORITHM {
    DEFAULT_RANDS.0.as_ptr()
}

/// `base_rands`: the seed source.
static BASE_RANDS: Algorithms<2> =
    Algorithms([base_alg(c"SEED-SRC", &SEED_SRC_FUNCTIONS), ALG_END]);

/// The base provider's random table.
pub(crate) fn base_rands() -> *const OSSL_ALGORITHM {
    BASE_RANDS.0.as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::rand::{
        EVP_RAND_CTX_free, EVP_RAND_CTX_get_params, EVP_RAND_CTX_new, EVP_RAND_CTX_set_params,
        EVP_RAND_fetch, EVP_RAND_free, EVP_RAND_instantiate, EVP_RAND_nonce,
    };
    use crate::params::{OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_uint};

    /// A context of the random algorithm `name` under `parent`.
    fn rand_ctx(
        name: &CStr,
        parent: *mut rustyssl_abi::EVP_RAND_CTX,
    ) -> *mut rustyssl_abi::EVP_RAND_CTX {
        // SAFETY: a static name.
        let rand = unsafe { EVP_RAND_fetch(ptr::null_mut(), name.as_ptr(), ptr::null()) };
        // SAFETY: the method just fetched; the caller's parent.
        let ctx = unsafe { EVP_RAND_CTX_new(rand, parent) };
        // SAFETY: as above.
        unsafe { EVP_RAND_free(rand) };
        ctx
    }

    /// A TEST-RAND of strength 256 with entropy, and with generating mode if asked for.
    fn test_rand(generate: bool) -> *mut rustyssl_abi::EVP_RAND_CTX {
        let t = rand_ctx(c"TEST-RAND", ptr::null_mut());
        let entropy = [7u8; 48];
        let (mut strength, mut gen_mode): (c_uint, c_uint) = (256, c_uint::from(generate));
        // SAFETY: a static key; a local that outlives the call.
        let p_strength = unsafe {
            OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH.as_ptr(), &raw mut strength)
        };
        // SAFETY: as above.
        let p_generate = unsafe {
            OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_GENERATE.as_ptr(), &raw mut gen_mode)
        };
        // SAFETY: as above.
        let p_entropy = unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_RAND_PARAM_TEST_ENTROPY.as_ptr(),
                entropy.as_ptr().cast_mut().cast(),
                entropy.len(),
            )
        };
        let params = [p_strength, p_generate, p_entropy, end()];
        // SAFETY: the context; the parameters above.
        assert_eq!(unsafe { EVP_RAND_CTX_set_params(t, params.as_ptr()) }, 1);
        t
    }

    /// docs/DEVIATIONS.md: a CTR-DRBG without a cipher, instantiated under a parent that gives
    /// it entropy, fails (the reference initializes a NULL cipher context).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn ctr_drbg_without_a_cipher_fails() {
        let t = test_rand(false);
        let ctx = rand_ctx(c"CTR-DRBG", t);
        assert_eq!(
            // SAFETY: the context.
            unsafe { EVP_RAND_instantiate(ctx, 0, 0, ptr::null(), 0, ptr::null()) },
            0
        );
        // SAFETY: the test's contexts.
        unsafe { EVP_RAND_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_RAND_CTX_free(t) };
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: TEST-RAND in generating mode, asked a nonce's length (NULL output),
    /// says it without generating (the reference writes through NULL). A DRBG asks so when it
    /// takes a nonce from it.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn test_rand_nonce_length_in_generating_mode() {
        let t = test_rand(true);
        let ctx = rand_ctx(c"HASH-DRBG", t);
        let digest = c"SHA256";
        // SAFETY: a static key and string.
        let params = [
            unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_DRBG_PARAM_DIGEST.as_ptr(),
                    digest.as_ptr().cast_mut(),
                    0,
                )
            },
            end(),
        ];
        // SAFETY: the context; the parameters above.
        assert_eq!(unsafe { EVP_RAND_CTX_set_params(ctx, params.as_ptr()) }, 1);
        assert_eq!(
            // SAFETY: as above.
            unsafe { EVP_RAND_instantiate(ctx, 0, 0, ptr::null(), 0, ptr::null()) },
            1
        );
        let mut nonce = [0u8; 4];
        // SAFETY: the context; room for the nonce.
        assert_eq!(unsafe { EVP_RAND_nonce(ctx, nonce.as_mut_ptr(), 4) }, 1);
        // SAFETY: the test's contexts.
        unsafe { EVP_RAND_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_RAND_CTX_free(t) };
    }

    /// docs/DEVIATIONS.md: HASH- and HMAC-DRBG over a digest of no size (the NULL digest)
    /// fail to instantiate and generate (the reference loops forever).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn drbgs_over_a_digest_of_no_size_fail() {
        for name in [c"HASH-DRBG", c"HMAC-DRBG"] {
            let ctx = rand_ctx(name, ptr::null_mut());
            let digest = c"NULL";
            // SAFETY: a static key and string.
            let params = [
                unsafe {
                    OSSL_PARAM_construct_utf8_string(
                        OSSL_DRBG_PARAM_DIGEST.as_ptr(),
                        digest.as_ptr().cast_mut(),
                        0,
                    )
                },
                end(),
            ];
            // SAFETY: the context; the parameters above.
            assert_eq!(unsafe { EVP_RAND_CTX_set_params(ctx, params.as_ptr()) }, 0);
            let mut out = [0u8; 64];
            // SAFETY: the context; room for the output.
            let r = unsafe {
                crate::evp::rand::EVP_RAND_generate(ctx, out.as_mut_ptr(), 64, 0, 0, ptr::null(), 0)
            };
            assert_eq!(r, 0);
            // SAFETY: the test's context.
            unsafe { EVP_RAND_CTX_free(ctx) };
        }
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: a DRBG asked for NULL parameters fails (the reference reads through
    /// NULL), and a CTR-DRBG `cipher` whose size isn't its string's length is refused (the
    /// reference reads, and writes, past the string).
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn bad_drbg_parameters_are_refused() {
        let ctx = rand_ctx(c"CTR-DRBG", ptr::null_mut());
        // SAFETY: the context; NULL is the case under test.
        assert_eq!(unsafe { EVP_RAND_CTX_get_params(ctx, ptr::null_mut()) }, 0);
        let name = c"AES-128-CTR";
        // SAFETY: a static key and string; the size is the case under test.
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_DRBG_PARAM_CIPHER.as_ptr(),
                    name.as_ptr().cast_mut(),
                    0,
                )
            },
            end(),
        ];
        params[0].data_size = 20;
        // SAFETY: the context; the parameters above.
        assert_eq!(unsafe { EVP_RAND_CTX_set_params(ctx, params.as_ptr()) }, 0);
        params[0].data_size = 11;
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_RAND_CTX_set_params(ctx, params.as_ptr()) }, 1);
        // SAFETY: the test's context.
        unsafe { EVP_RAND_CTX_free(ctx) };
        crate::err::take_all();
    }
}
