//! ECX keys (OpenSSL's `ECX_KEY`, `ecx_key.c` and `ecx_backend.c`): X25519, X448, Ed25519, and
//! Ed448 keys as the providers hold them, a type, a public key, and an optional private key,
//! shared by reference (the key managers' data, which the exchanges and signatures take
//! references to). The public key derived from a private key is `rustyssl_crypto::ecx`'s.
//!
//! As in OpenSSL, deriving an Ed25519 public key fetches SHA-512 with the key's library context
//! and properties, so a key whose properties exclude it can't be made from its private key.

use core::ffi::{CStr, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    EC_R_FAILED_MAKING_PUBLIC_KEY, EC_R_INVALID_ENCODING, ERR_LIB_EC, EVP_PKEY_ED25519,
    EVP_PKEY_X25519, OSSL_LIB_CTX, OSSL_PARAM, OSSL_PARAM_OCTET_STRING, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PUB_KEY,
};

use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::ffi::bytes;
use crate::provider::Ptr;
use crate::provider::macs::{locate, wipe};
use crate::rand_lib::RAND_priv_bytes_ex;

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

/// `OSSL_PARAM_OCTET_STRING` as a parameter's type.
const OCTETS_TYPE: u32 = OSSL_PARAM_OCTET_STRING.cast_unsigned();

/// An octet-string parameter's octets, if it is one.
pub(crate) fn octet_param(p: &OSSL_PARAM) -> Option<&[u8]> {
    if p.data_type != OCTETS_TYPE {
        return None;
    }
    // SAFETY: an octet-string parameter's data holds its size.
    unsafe { bytes(p.data.cast(), p.data_size) }
}

/// `ossl_ecx_key_fromdata`: the private key (if `include_private`) and the public key, each of
/// the key's length, the public key derived when it's absent.
///
/// # Safety
/// `params` is NULL or an array.
pub(crate) unsafe fn key_fromdata(
    k: &EcxKey,
    params: *const OSSL_PARAM,
    include_private: bool,
) -> bool {
    // SAFETY: the caller's array; static names.
    let p_pub = unsafe { locate(params, OSSL_PKEY_PARAM_PUB_KEY) };
    let p_priv = if include_private {
        // SAFETY: as above.
        unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) }
    } else {
        None
    };
    if p_pub.is_none() && p_priv.is_none() {
        return false;
    }
    let keylen = k.keylen();
    let mut s = k.lock();
    if let Some(p) = p_priv {
        // `OSSL_PARAM_get_octet_string` with room for the key's length.
        let Some(d) = octet_param(p).filter(|d| d.len() <= keylen) else {
            return false;
        };
        if d.len() != keylen {
            return false;
        }
        if let Some(old) = s.privkey.as_mut() {
            wipe(old);
        }
        s.privkey = Some(d.to_vec());
    }
    if let Some(p) = p_pub {
        let Some(q) = octet_param(p).filter(|q| q.len() <= MAX_KEYLEN) else {
            return false;
        };
        if let Some(dst) = s.pubkey.get_mut(..q.len()) {
            dst.copy_from_slice(q);
        }
        if q.len() != keylen {
            return false;
        }
    } else if !public_from_private(k, &mut s) {
        err::raise(
            ERR_LIB_EC,
            rustyssl_abi::EC_R_FAILED_MAKING_PUBLIC_KEY,
            "ossl_ecx_public_from_private",
        );
        return false;
    }
    s.haspubkey = true;
    true
}

/// The ECX type of a key type (`KEYNID2TYPE`), for the types whose arithmetic is here.
pub(crate) fn type_of(pkey_id: c_int) -> Option<EcxType> {
    match pkey_id {
        EVP_PKEY_X25519 => Some(EcxType::X25519),
        EVP_PKEY_ED25519 => Some(EcxType::Ed25519),
        _ => None,
    }
}

/// What `key_op` makes a key from.
pub(crate) enum KeyOp<'a> {
    Public(&'a [u8]),
    Private(&'a [u8]),
    Keygen,
}

/// `ossl_ecx_key_op` (without an algorithm identifier): a new key of `kind` from a public key
/// or a private key of the type's length, or with a random private key (clamped for X25519),
/// the public key derived from a private one; NULL with an EC error.
pub(crate) fn key_op(libctx: *mut OSSL_LIB_CTX, kind: EcxType, op: &KeyOp<'_>) -> *mut c_void {
    const F: &str = "ossl_ecx_key_op";
    let keylen = kind.keylen();
    if let KeyOp::Public(p) | KeyOp::Private(p) = op
        && p.len() != keylen
    {
        err::raise(ERR_LIB_EC, EC_R_INVALID_ENCODING, F);
        return ptr::null_mut();
    }
    let h = new(libctx, kind, None);
    // SAFETY: the key just made.
    let Some(k) = (unsafe { key(h) }) else {
        return ptr::null_mut();
    };
    let ok = {
        let mut s = k.lock();
        match op {
            KeyOp::Public(p) => {
                if let Some(dst) = s.pubkey.get_mut(..keylen) {
                    dst.copy_from_slice(p);
                }
                s.haspubkey = true;
                true
            }
            KeyOp::Private(d) => {
                s.privkey = Some(d.to_vec());
                derive_public(k, &mut s)
            }
            KeyOp::Keygen => {
                let mut d = vec![0u8; keylen];
                // SAFETY: the key's library context; room for the key.
                if (unsafe { RAND_priv_bytes_ex(libctx, d.as_mut_ptr(), keylen, 0) }) <= 0 {
                    wipe(&mut d);
                    false
                } else {
                    if kind == EcxType::X25519
                        && let [first, .., last] = d.as_mut_slice()
                    {
                        *first &= 248;
                        *last &= 127;
                        *last |= 64;
                    }
                    s.privkey = Some(d);
                    derive_public(k, &mut s)
                }
            }
        }
    };
    if !ok {
        // SAFETY: the key made above.
        unsafe { free(h) };
        return ptr::null_mut();
    }
    h
}

/// The public key from the private key (`ossl_ecx_public_from_private`), raising
/// `EC_R_FAILED_MAKING_PUBLIC_KEY` if it can't be made.
fn derive_public(k: &EcxKey, s: &mut State) -> bool {
    if !public_from_private(k, s) {
        err::raise(ERR_LIB_EC, EC_R_FAILED_MAKING_PUBLIC_KEY, "ossl_ecx_key_op");
        return false;
    }
    s.haspubkey = true;
    true
}

/// Whether SHA-512 can be fetched with the properties given, as `ossl_ed25519_sign` and
/// `ossl_ed25519_verify` fetch it.
pub(crate) fn sha512_available(libctx: *mut OSSL_LIB_CTX, propq: Option<&CStr>) -> bool {
    let propq = propq.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: a library context; a static name; a query or NULL.
    let md = unsafe { EVP_MD_fetch(libctx, c"SHA512".as_ptr(), propq) };
    if md.is_null() {
        return false;
    }
    // SAFETY: the reference fetched above.
    unsafe { EVP_MD_free(md) };
    true
}
