//! The RAND layer's entropy and nonces (`rand_pool.c`, `prov_seed.c`, and the Unix seeding of
//! `rand_unix.c`): the pool a seed or nonce is gathered in, with the reference's length rules
//! and errors, filled from the operating system; and the core's entropy and nonce sources a
//! DRBG without a parent (and SEED-SRC) draws on.
//!
//! The pool asks for its entropy's octets (at least its minimum length, at most its maximum,
//! which is capped at `RAND_POOL_MAX_LENGTH`); asking for more than fits raises
//! `RAND_R_RANDOM_POOL_OVERFLOW` and gathers nothing. As the reference does with its two Unix
//! sources (the `getrandom`/`getentropy` system call, then the random device, which Linux
//! skips), a pool that gathered nothing asks a second time outside Linux, so an overflow is
//! raised twice there and once on Linux. A nonce is the
//! process id, the thread id, and a timestamp, followed by its caller's salt.

use core::ffi::c_int;

use rustyssl_abi::{
    ERR_LIB_RAND, RAND_R_ENTROPY_INPUT_TOO_LONG, RAND_R_RANDOM_POOL_IS_EMPTY,
    RAND_R_RANDOM_POOL_OVERFLOW,
};

use crate::err;

/// `RAND_POOL_MAX_LENGTH`: `RAND_POOL_FACTOR` (256) * 3 * (`RAND_DRBG_STRENGTH` (256) / 16).
const POOL_MAX_LENGTH: usize = 256 * 3 * (256 / 16);

/// The Unix sources that ask the pool for entropy: the system call, then the random device,
/// which on Linux (from kernel 4.8, the reference's `DEVRANDOM_SAFE_KERNEL`) is skipped, as
/// the system call already waited for the kernel's pool (`wait_random_seeded`).
const SOURCES: usize = if cfg!(target_os = "linux") { 1 } else { 2 };

/// A buffer of random octets, wiped when dropped.
pub(crate) struct Seed(pub(crate) Vec<u8>);

impl Drop for Seed {
    fn drop(&mut self) {
        crate::provider::macs::wipe(&mut self.0);
    }
}

/// `RAND_POOL`: octets gathered toward `entropy_requested` bits and `min_len` octets, at most
/// `max_len`.
pub(crate) struct Pool {
    buffer: Seed,
    entropy: usize,
    entropy_requested: usize,
    min_len: usize,
    max_len: usize,
}

impl Pool {
    /// `ossl_rand_pool_new`. A negative entropy is the huge `size_t` the reference converts it
    /// to.
    pub(crate) fn new(entropy_requested: c_int, min_len: usize, max_len: usize) -> Self {
        let requested = usize::try_from(entropy_requested).unwrap_or_else(|_| {
            0usize.wrapping_sub(usize::try_from(entropy_requested.unsigned_abs()).unwrap_or(0))
        });
        Self {
            buffer: Seed(Vec::new()),
            entropy: 0,
            entropy_requested: requested,
            min_len,
            max_len: max_len.min(POOL_MAX_LENGTH),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.buffer.0.len()
    }

    /// The entropy gathered, in bits.
    pub(crate) fn entropy(&self) -> usize {
        self.entropy
    }

    /// `ossl_rand_pool_entropy_available`: the entropy, once there's enough of it and of the
    /// octets; else 0.
    pub(crate) fn entropy_available(&self) -> usize {
        if self.entropy < self.entropy_requested || self.len() < self.min_len {
            return 0;
        }
        self.entropy
    }

    /// `ossl_rand_pool_bytes_needed` with an entropy factor of 1: the octets still to gather
    /// (0, with `RAND_R_RANDOM_POOL_OVERFLOW`, if they wouldn't fit).
    fn bytes_needed(&mut self) -> usize {
        let entropy_needed = self.entropy_requested.saturating_sub(self.entropy);
        let mut bytes = entropy_needed.wrapping_add(7) / 8;
        let room = self.max_len - self.len();
        if bytes > room {
            let text = format!(
                "entropy_factor=1, entropy_needed={entropy_needed}, bytes_needed={bytes},pool->max_len={}, pool->len={}",
                self.max_len,
                self.len()
            );
            err::raise_with_text(
                ERR_LIB_RAND,
                RAND_R_RANDOM_POOL_OVERFLOW,
                "ossl_rand_pool_bytes_needed",
                &text,
            );
            return 0;
        }
        if self.len() < self.min_len && bytes < self.min_len - self.len() {
            bytes = self.min_len - self.len();
        }
        bytes
    }

    /// Gathers `n` octets of the operating system's entropy (a bit each); false if it failed.
    fn gather(&mut self, n: usize) -> bool {
        if n == 0 {
            return true;
        }
        let at = self.len();
        self.buffer.0.resize(at + n, 0);
        let Some(fresh) = self.buffer.0.get_mut(at..) else {
            return false;
        };
        if rustyssl_crypto::rand::os_entropy(fresh).is_err() {
            self.buffer.0.truncate(at);
            return false;
        }
        self.entropy = self.entropy.saturating_add(n.saturating_mul(8));
        true
    }

    /// `ossl_pool_acquire_entropy` on Unix: the system call, then (if that gathered too
    /// little) the random device, each asked for what's still needed. The entropy available.
    pub(crate) fn acquire_entropy(&mut self) -> usize {
        for _source in 0..SOURCES {
            let n = self.bytes_needed();
            self.gather(n);
            let available = self.entropy_available();
            if available > 0 {
                return available;
            }
        }
        self.entropy_available()
    }

    /// `ossl_rand_pool_add` of octets with no entropy: false, with
    /// `RAND_R_ENTROPY_INPUT_TOO_LONG`, if they don't fit.
    pub(crate) fn add(&mut self, data: &[u8]) -> bool {
        if data.len() > self.max_len - self.len() {
            err::raise(
                ERR_LIB_RAND,
                RAND_R_ENTROPY_INPUT_TOO_LONG,
                "ossl_rand_pool_add",
            );
            return false;
        }
        self.buffer.0.extend_from_slice(data);
        true
    }

    /// `ossl_rand_pool_adin_mix_in`: the additional input XORed over the octets, cyclically.
    pub(crate) fn adin_mix_in(&mut self, adin: &[u8]) -> bool {
        if adin.is_empty() {
            return true;
        }
        if self.buffer.0.is_empty() {
            err::raise(
                ERR_LIB_RAND,
                RAND_R_RANDOM_POOL_IS_EMPTY,
                "ossl_rand_pool_adin_mix_in",
            );
            return false;
        }
        let n = self.len();
        for (i, &a) in adin.iter().enumerate() {
            if let Some(b) = self.buffer.0.get_mut(i % n) {
                *b ^= a;
            }
        }
        true
    }

    /// The octets gathered (`ossl_rand_pool_detach`).
    pub(crate) fn into_seed(mut self) -> Seed {
        Seed(core::mem::take(&mut self.buffer.0))
    }

    /// The octets gathered so far.
    pub(crate) fn octets(&self) -> &[u8] {
        &self.buffer.0
    }
}

/// `ossl_rand_get_entropy` (the core's `get_user_entropy` while there's no seed source):
/// `entropy` bits of the operating system's in `min_len` to `max_len` octets, or `None`.
pub(crate) fn get_entropy(entropy: c_int, min_len: usize, max_len: usize) -> Option<Seed> {
    let mut pool = Pool::new(entropy, min_len, max_len);
    (pool.acquire_entropy() > 0).then(|| pool.into_seed())
}

/// `ossl_pool_add_nonce_data`'s structure: the process id (padded), the thread id, and a
/// timestamp in microseconds.
fn nonce_data() -> [u8; 24] {
    let mut data = [0u8; 24];
    // SAFETY: no preconditions.
    let pid = unsafe { libc::getpid() };
    thread_local!(static THREAD: u8 = const { 0 });
    let tid = THREAD.with(|t| u64::try_from(core::ptr::from_ref(t).addr()).unwrap_or(0));
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX));
    let (a, rest) = data.split_at_mut(8);
    let (b, c) = rest.split_at_mut(8);
    if let Some(p) = a.get_mut(..4) {
        p.copy_from_slice(&pid.to_ne_bytes());
    }
    b.copy_from_slice(&tid.to_ne_bytes());
    c.copy_from_slice(&time.to_ne_bytes());
    data
}

/// `ossl_rand_get_nonce` (the core's `get_user_nonce` while there's no seed source): the
/// nonce data and the salt, in `min_len` to `max_len` octets; `None` (with the error) if they
/// don't fit.
pub(crate) fn get_nonce(min_len: usize, max_len: usize, salt: &[u8]) -> Option<Seed> {
    let mut pool = Pool::new(0, min_len, max_len);
    if !pool.add(&nonce_data()) || !pool.add(salt) {
        return None;
    }
    Some(pool.into_seed())
}

/// Entropy the core gives a DRBG without a parent (`ossl_rand_get_user_entropy`): the
/// operating system's, or, once its context made a seed source that gives seeds, the seed
/// source's (given back with its `clear_seed`).
pub(crate) enum UserEntropy {
    Os(Option<Seed>),
    Seeded {
        /// The seed source, with a reference.
        seed: *mut rustyssl_abi::EVP_RAND_CTX,
        buf: *mut u8,
        len: usize,
    },
}

impl UserEntropy {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Os(s) => s.as_ref().map_or(0, |s| s.0.len()),
            Self::Seeded { len, .. } => *len,
        }
    }

    /// The octets, `None` for none (a NULL buffer).
    pub(crate) fn octets(&self) -> Option<&[u8]> {
        match self {
            Self::Os(s) => s.as_ref().map(|s| &s.0[..]),
            Self::Seeded { buf, len, .. } => {
                // SAFETY: the seed source's seed, of `len` octets, until it's given back.
                (!buf.is_null()).then(|| unsafe { core::slice::from_raw_parts(*buf, *len) })
            }
        }
    }
}

impl Drop for UserEntropy {
    /// `ossl_rand_cleanup_user_entropy`.
    fn drop(&mut self) {
        if let Self::Seeded { seed, buf, len } = *self {
            // SAFETY: the seed source and its own seed.
            unsafe { crate::evp::rand::clear_seed(seed, buf, len) };
            // SAFETY: the reference taken for it.
            unsafe { crate::evp::rand::EVP_RAND_CTX_free(seed) };
        }
    }
}

/// `ossl_rand_get_user_entropy` for the context a provider was loaded into.
pub(crate) fn user_entropy(
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    entropy: c_int,
    min_len: usize,
    max_len: usize,
) -> UserEntropy {
    let seed = crate::rand_lib::seed_of(libctx);
    if !seed.is_null() {
        // SAFETY: the seed source, held.
        if unsafe { crate::evp::rand::can_seed(seed) } {
            let mut buf: *mut u8 = core::ptr::null_mut();
            // SAFETY: as above; a local for the seed.
            let len = unsafe {
                crate::evp::rand::get_seed(
                    seed,
                    &raw mut buf,
                    entropy,
                    min_len,
                    max_len,
                    core::ptr::null(),
                    0,
                )
            };
            return UserEntropy::Seeded { seed, buf, len };
        }
        // SAFETY: the reference taken for it.
        unsafe { crate::evp::rand::EVP_RAND_CTX_free(seed) };
    }
    UserEntropy::Os(get_entropy(entropy, min_len, max_len))
}

/// `ossl_rand_get_user_nonce` for the context a provider was loaded into: the core's nonce, or,
/// once the context made a seed source, `min_len` octets of it with the salt as additional
/// input.
pub(crate) fn user_nonce(
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    min_len: usize,
    max_len: usize,
    salt: &[u8],
) -> Option<Seed> {
    let seed = crate::rand_lib::seed_of(libctx);
    if seed.is_null() {
        return get_nonce(min_len, max_len, salt);
    }
    // The reference's `OPENSSL_malloc(0)` is NULL: no nonce.
    let mut out = (min_len > 0).then(|| Seed(vec![0u8; min_len]));
    if let Some(o) = out.as_mut() {
        // SAFETY: the seed source; room for `min_len` octets; the salt.
        if unsafe {
            crate::evp::rand::EVP_RAND_generate(
                seed,
                o.0.as_mut_ptr(),
                min_len,
                0,
                0,
                salt.as_ptr(),
                salt.len(),
            )
        } == 0
        {
            out = None;
        }
    }
    // SAFETY: the reference taken for it.
    unsafe { crate::evp::rand::EVP_RAND_CTX_free(seed) };
    out
}
