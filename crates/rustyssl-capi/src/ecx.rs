//! ECX keys (OpenSSL's `ECX_KEY`, `ecx_key.c` and `ecx_backend.c`): X25519, X448, Ed25519, and
//! Ed448 keys as the providers hold them, a type, a public key, and an optional private key,
//! shared by reference (the key managers' data, which the exchanges and signatures take
//! references to). The public key derived from a private key is `rustyssl_crypto::ecx`'s.
//!
//! As in OpenSSL, deriving an Ed25519 public key fetches SHA-512 with the key's library context
//! and properties, so a key whose properties exclude it can't be made from its private key.

use core::ffi::{CStr, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustyssl_abi::OSSL_LIB_CTX;

use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::provider::Ptr;
use crate::provider::macs::wipe;

/// The largest key (Ed448's 57 octets).
pub(crate) const MAX_KEYLEN: usize = 57;

/// `ECX_KEY_TYPE`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    dead_code,
    reason = "X448's and Ed448's key managers come with step 4.5b"
)]
pub(crate) enum EcxType {
    X25519,
    X448,
    Ed25519,
    Ed448,
}

impl EcxType {
    /// The keys' length.
    pub(crate) const fn keylen(self) -> usize {
        match self {
            Self::X25519 | Self::Ed25519 => 32,
            Self::X448 => 56,
            Self::Ed448 => 57,
        }
    }

    /// Whether it signs (EdDSA).
    pub(crate) const fn is_ed(self) -> bool {
        matches!(self, Self::Ed25519 | Self::Ed448)
    }
}

/// What a key holds, behind its lock.
pub(crate) struct State {
    pub(crate) propq: Option<CString>,
    /// The public key in the first `keylen` octets (zeros until it has one).
    pub(crate) pubkey: [u8; MAX_KEYLEN],
    pub(crate) haspubkey: bool,
    pub(crate) privkey: Option<Vec<u8>>,
}

impl Drop for State {
    fn drop(&mut self) {
        if let Some(p) = self.privkey.as_mut() {
            wipe(p);
        }
    }
}

/// `ECX_KEY`.
pub(crate) struct EcxKey {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    pub(crate) kind: EcxType,
    state: Mutex<State>,
}

impl EcxKey {
    /// The key's parts.
    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The keys' length.
    pub(crate) fn keylen(&self) -> usize {
        self.kind.keylen()
    }

    /// The public key's octets.
    #[expect(dead_code, reason = "the exchange and signatures (step 4.5a2) use it")]
    pub(crate) fn public(&self) -> Vec<u8> {
        let s = self.lock();
        s.pubkey.get(..self.keylen()).unwrap_or_default().to_vec()
    }
}

/// `ossl_ecx_key_new`: an empty key of `kind`, as key data (a reference).
pub(crate) fn new(libctx: *mut OSSL_LIB_CTX, kind: EcxType, propq: Option<&CStr>) -> *mut c_void {
    let k = EcxKey {
        libctx: Ptr(libctx),
        kind,
        state: Mutex::new(State {
            propq: propq.map(CStr::to_owned),
            pubkey: [0; MAX_KEYLEN],
            haspubkey: false,
            privkey: None,
        }),
    };
    Arc::into_raw(Arc::new(k)).cast_mut().cast()
}

/// The key behind key data.
///
/// # Safety
/// `p` is NULL or key data from [`new`] with a reference alive.
pub(crate) unsafe fn key<'a>(p: *const c_void) -> Option<&'a EcxKey> {
    // SAFETY: the caller's guarantee.
    unsafe { p.cast::<EcxKey>().as_ref() }
}

/// `ossl_ecx_key_up_ref`.
#[expect(dead_code, reason = "the exchange and signatures (step 4.5a2) use it")]
///
/// # Safety
/// `p` is key data from [`new`] with a reference alive.
pub(crate) unsafe fn up_ref(p: *const c_void) {
    // SAFETY: the caller's guarantee.
    unsafe { Arc::increment_strong_count(p.cast::<EcxKey>()) };
}

/// `ossl_ecx_key_free`: gives up a reference (NULL does nothing).
///
/// # Safety
/// `p` is NULL or key data from [`new`] whose reference the caller gives up.
pub(crate) unsafe fn free(p: *mut c_void) {
    if !p.is_null() {
        // SAFETY: the caller's guarantee.
        drop(unsafe { Arc::from_raw(p.cast::<EcxKey>().cast_const()) });
    }
}

/// `ossl_ecx_public_from_private`: the public key of the key's private key, or `false` (when
/// SHA-512 can't be fetched for EdDSA, or for a type whose arithmetic isn't here yet).
pub(crate) fn public_from_private(k: &EcxKey, s: &mut State) -> bool {
    let Some(private) = s.privkey.as_deref() else {
        return false;
    };
    let public = match k.kind {
        EcxType::X25519 => {
            let Ok(p) = <[u8; 32]>::try_from(private) else {
                return false;
            };
            Some(rustyssl_crypto::ecx::x25519_public_from_private(&p).to_vec())
        }
        EcxType::Ed25519 => {
            let propq = s.propq.as_deref().map_or(ptr::null(), CStr::as_ptr);
            // SAFETY: the key's library context; a static name; the key's query.
            let md = unsafe { EVP_MD_fetch(k.libctx.0, c"SHA512".as_ptr(), propq) };
            if md.is_null() {
                return false;
            }
            // SAFETY: the reference fetched above.
            unsafe { EVP_MD_free(md) };
            let Ok(p) = <[u8; 32]>::try_from(private) else {
                return false;
            };
            rustyssl_crypto::ecx::ed25519_public_from_private(&p).map(|v| v.to_vec())
        }
        EcxType::X448 | EcxType::Ed448 => None,
    };
    let Some(public) = public else { return false };
    let Some(dst) = s.pubkey.get_mut(..public.len()) else {
        return false;
    };
    dst.copy_from_slice(&public);
    true
}

/// `ossl_ecx_key_dup`: a new key with the selected parts.
pub(crate) fn dup(k: &EcxKey, public: bool, private: bool) -> *mut c_void {
    let s = k.lock();
    let n = new(k.libctx.0, k.kind, s.propq.as_deref());
    // SAFETY: the key just made.
    if let Some(d) = unsafe { key(n) } {
        let mut ds = d.lock();
        if public && s.haspubkey {
            ds.pubkey = s.pubkey;
            ds.haspubkey = true;
        }
        if private {
            ds.privkey.clone_from(&s.privkey);
        }
    }
    n
}
