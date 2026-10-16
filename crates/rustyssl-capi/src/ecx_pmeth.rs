//! The built-in X25519 and ED25519 `EVP_PKEY_METHOD`s' functions (`ecx_meth.c`), which an
//! application that copies or wraps the built-in methods (`EVP_PKEY_meth_find`,
//! `EVP_PKEY_meth_copy`) calls, on keys of either form (a provided key through its legacy copy).
//!
//! As in OpenSSL, key generation draws a private key (clamped for X25519) for the method's
//! type, deriving writes X25519's secret (zeros from a low-order peer, then refused without an
//! error), and EdDSA signs and verifies pure Ed25519 only, refusing any digest but none.
//!
//! OpenSSL's derive writes the 32-octet secret whatever room the caller gives, and signs with
//! a key without a private key by reading NULL; this one refuses both (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    EC_R_BUFFER_TOO_SMALL, EC_R_INVALID_DIGEST_TYPE, EC_R_INVALID_KEY, EC_R_INVALID_PEER_KEY,
    EC_R_INVALID_PRIVATE_KEY, EC_R_KEYS_NOT_SET, ERR_LIB_EC, EVP_MD_CTX, EVP_PKEY,
    EVP_PKEY_CTRL_DIGESTINIT, EVP_PKEY_CTRL_MD, EVP_PKEY_CTRL_PEER_KEY, EVP_PKEY_CTX,
};
use rustyssl_crypto::ecx::{Dom, ED25519_SIGSIZE, KEYLEN};

use crate::ecx::{self, EcxKey, KeyOp, sha512_available};
use crate::err;
use crate::evp::legacy_md::EVP_md_null;
use crate::evp::pkey::{EVP_PKEY_assign, get_legacy, pkey};
use crate::evp::pkey_ctx::{EVP_PKEY_CTX_get0_peerkey, EVP_PKEY_CTX_get0_pkey, context};
use crate::evp::sigver::EVP_MD_CTX_get_pkey_ctx;
use crate::ffi::{bytes, ffi_callback};
use crate::provider::macs::wipe;

/// The ECX key of a key (`evp_pkey_get_legacy`: a provided key's legacy copy), or none.
///
/// # Safety
/// `p` is NULL or a live key of an ECX type.
unsafe fn legacy<'a>(p: *const EVP_PKEY) -> Option<&'a EcxKey> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { pkey(p) }?;
    // SAFETY: the key's legacy data, an ECX key, or NULL.
    unsafe { ecx::key(get_legacy(k)) }
}

/// A key's private key, if it has one.
fn private(k: &EcxKey) -> Option<[u8; KEYLEN]> {
    k.lock()
        .privkey
        .as_deref()
        .and_then(|d| <[u8; KEYLEN]>::try_from(d).ok())
}

/// A key's public key.
fn public(k: &EcxKey) -> Option<[u8; KEYLEN]> {
    <[u8; KEYLEN]>::try_from(k.public()).ok()
}

ffi_callback! {
    /// `pkey_ecx_keygen`: a key of the method's type with a random private key.
    ///
    /// # Safety
    /// `ctx` is a live context of the method; `pkey` is a live key.
    pub(crate) unsafe extern "C" fn pkey_ecx_keygen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(id) = (unsafe { context(ctx) }).map(|c| c.lock().legacy_keytype()) else { return 0 };
        let Some(kind) = ecx::type_of(id) else { return 0 };
        let h = ecx::key_op(ptr::null_mut(), kind, &KeyOp::Keygen);
        if h.is_null() {
            return 0;
        }
        // SAFETY: the caller's key; the new ECX key, which it takes.
        if unsafe { EVP_PKEY_assign(pkey, id, h) } == 0 {
            // SAFETY: the reference not taken.
            unsafe { ecx::free(h) };
        }
        1
    }
}

ffi_callback! {
    /// `pkey_ecx_derive25519`: the secret's length (32) when `key` is NULL, else the secret
    /// (refused if `*keylen` is less than 32).
    ///
    /// # Safety
    /// `ctx` is a live context; `key` is NULL or has room for `*keylen` octets; `keylen` is a
    /// live `size_t`.
    pub(crate) unsafe extern "C" fn pkey_ecx_derive25519(ctx: *mut EVP_PKEY_CTX, key: *mut c_uchar, keylen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "validate_ecx_derive";
        // SAFETY: the caller's guarantee.
        let pk = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
        // SAFETY: as above.
        let peer = unsafe { EVP_PKEY_CTX_get0_peerkey(ctx) };
        if pk.is_null() || peer.is_null() {
            err::raise(ERR_LIB_EC, EC_R_KEYS_NOT_SET, F);
            return 0;
        }
        // SAFETY: the context's keys.
        let k = unsafe { legacy(pk) };
        let Some(mut d) = k.and_then(private) else {
            err::raise(ERR_LIB_EC, EC_R_INVALID_PRIVATE_KEY, F);
            return 0;
        };
        // SAFETY: as above.
        let Some(q) = (unsafe { legacy(peer) }).and_then(public) else {
            wipe(&mut d);
            err::raise(ERR_LIB_EC, EC_R_INVALID_PEER_KEY, F);
            return 0;
        };
        if !key.is_null() {
            // SAFETY: the caller's guarantee.
            if unsafe { keylen.read() } < KEYLEN {
                wipe(&mut d);
                err::raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL, "pkey_ecx_derive25519");
                return 0;
            }
            let shared = rustyssl_crypto::ecx::x25519(&d, &q);
            let zeros = [0u8; KEYLEN];
            let out: &[u8; KEYLEN] = shared.as_deref().unwrap_or(&zeros);
            // SAFETY: the caller's room for at least 32 octets; a local.
            unsafe { ptr::copy_nonoverlapping(out.as_ptr(), key, KEYLEN) };
            if shared.is_none() {
                wipe(&mut d);
                return 0;
            }
        }
        wipe(&mut d);
        // SAFETY: the caller's guarantee.
        unsafe { keylen.write(KEYLEN) };
        1
    }
}

ffi_callback! {
    /// `pkey_ecx_ctrl`: only the peer key (which needs nothing); -2 for others.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pkey_ecx_ctrl(_ctx: *mut EVP_PKEY_CTX, type_: c_int, _p1: c_int, _p2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        if type_ == EVP_PKEY_CTRL_PEER_KEY { 1 } else { -2 }
    }
}

/// The ECX key of a digest context's key, or none with `EC_R_INVALID_KEY`.
///
/// # Safety
/// `ctx` is a live digest context.
unsafe fn ed_key<'a>(ctx: *const EVP_MD_CTX) -> Option<&'a EcxKey> {
    // SAFETY: the caller's guarantee.
    let pctx = unsafe { EVP_MD_CTX_get_pkey_ctx(ctx) };
    let pk = if pctx.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the digest context's key context.
        unsafe { EVP_PKEY_CTX_get0_pkey(pctx) }
    };
    // SAFETY: its key, or NULL.
    let k = unsafe { legacy(pk) };
    if k.is_none() {
        err::raise(ERR_LIB_EC, EC_R_INVALID_KEY, "pkey_ecd_digestsign25519");
    }
    k
}

ffi_callback! {
    /// `pkey_ecd_digestsign25519`: the signature's size when `sig` is NULL, else pure Ed25519's
    /// signature of `tbs`.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sig` is NULL or has room for `*siglen` octets; `siglen`
    /// is a live `size_t`; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn pkey_ecd_digestsign25519(ctx: *mut EVP_MD_CTX, sig: *mut c_uchar, siglen: *mut usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ed_key(ctx) }) else { return 0 };
        if sig.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(ED25519_SIGSIZE) };
            return 1;
        }
        // SAFETY: as above.
        if unsafe { siglen.read() } < ED25519_SIGSIZE {
            err::raise(ERR_LIB_EC, EC_R_BUFFER_TOO_SMALL, "pkey_ecd_digestsign25519");
            return 0;
        }
        // SAFETY: as above.
        let Some(tbs) = (unsafe { bytes(tbs, tbslen) }) else { return 0 };
        let (Some(mut d), Some(q)) = (private(k), public(k)) else { return 0 };
        let signed = if sha512_available(ptr::null_mut(), None) {
            rustyssl_crypto::ecx::ed25519_sign(tbs, &q, &d, &Dom::default())
        } else {
            None
        };
        wipe(&mut d);
        let Some(s) = signed else { return 0 };
        // SAFETY: the caller's room for at least 64 octets; a local.
        unsafe { ptr::copy_nonoverlapping(s.as_ptr(), sig, s.len()) };
        // SAFETY: the caller's guarantee.
        unsafe { siglen.write(ED25519_SIGSIZE) };
        1
    }
}

ffi_callback! {
    /// `pkey_ecd_digestverify25519`: whether `sig` (of exactly 64 octets) is pure Ed25519's
    /// signature of `tbs`.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sig` holds `siglen` octets; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn pkey_ecd_digestverify25519(ctx: *mut EVP_MD_CTX, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { ed_key(ctx) }) else { return 0 };
        if siglen != ED25519_SIGSIZE {
            return 0;
        }
        // SAFETY: as above.
        let Some(sig) = (unsafe { bytes(sig, siglen) }) else { return 0 };
        // SAFETY: as above.
        let Some(tbs) = (unsafe { bytes(tbs, tbslen) }) else { return 0 };
        let (Ok(sig), Some(q)) = (<&[u8; ED25519_SIGSIZE]>::try_from(sig), public(k)) else {
            return 0;
        };
        let propq = k.lock().propq.clone();
        if !sha512_available(k.libctx.0, propq.as_deref()) {
            return 0;
        }
        c_int::from(rustyssl_crypto::ecx::ed25519_verify(tbs, sig, &q, &Dom::default()))
    }
}

ffi_callback! {
    /// `pkey_ecd_ctrl`: no digest but none (or the null digest); 1 for a digest init; -2 for
    /// others.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn pkey_ecd_ctrl(_ctx: *mut EVP_PKEY_CTX, type_: c_int, _p1: c_int, p2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        match type_ {
            EVP_PKEY_CTRL_MD => {
                // SAFETY: no preconditions.
                if p2.is_null() || p2.cast_const().cast() == unsafe { EVP_md_null() } {
                    return 1;
                }
                err::raise(ERR_LIB_EC, EC_R_INVALID_DIGEST_TYPE, "pkey_ecd_ctrl");
                0
            }
            EVP_PKEY_CTRL_DIGESTINIT => 1,
            _ => -2,
        }
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::{EVP_PKEY_ED25519, EVP_PKEY_X25519};

    use super::*;
    use crate::ecx::EcxType;
    use crate::evp::exchange::{EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
    use crate::evp::md_ctx::{EVP_MD_CTX_free, EVP_MD_CTX_new};
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new};
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new};
    use crate::evp::sigver::EVP_MD_CTX_set_pkey_ctx;

    /// A legacy key of `kind` with the given parts, made without arithmetic (which Miri runs
    /// slowly): the public key isn't derived from the private key.
    fn legacy_key(kind: EcxType, id: c_int, privkey: Option<[u8; 32]>) -> *mut EVP_PKEY {
        let h = ecx::new(ptr::null_mut(), kind, None);
        // SAFETY: the key just made.
        let k = unsafe { ecx::key(h) }.expect("a key");
        {
            let mut s = k.lock();
            s.privkey = privkey.map(|d| d.to_vec());
            s.pubkey[0] = 9;
            s.haspubkey = true;
        }
        // SAFETY: no preconditions.
        let pk = unsafe { EVP_PKEY_new() };
        // SAFETY: the key takes the ECX key.
        assert_eq!(unsafe { EVP_PKEY_assign(pk, id, h) }, 1);
        pk
    }

    /// docs/DEVIATIONS.md: X25519's legacy derive into less room than the secret, which
    /// OpenSSL writes past, is refused, and nothing is written.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn derive_into_less_room_is_refused() {
        let a = legacy_key(EcxType::X25519, EVP_PKEY_X25519, Some([0x40; 32]));
        let b = legacy_key(EcxType::X25519, EVP_PKEY_X25519, None);
        // SAFETY: a live key.
        let ctx = unsafe { EVP_PKEY_CTX_new(a, ptr::null_mut()) };
        // SAFETY: a live context.
        assert_eq!(unsafe { EVP_PKEY_derive_init(ctx) }, 1);
        // SAFETY: a live context and key.
        assert_eq!(unsafe { EVP_PKEY_derive_set_peer(ctx, b) }, 1);
        let mut out = [0x77u8; 32];
        let mut len = 31;
        // SAFETY: a live context; room for `len` octets.
        let r = unsafe { pkey_ecx_derive25519(ctx, out.as_mut_ptr(), &raw mut len) };
        assert_eq!(r, 0);
        assert_eq!(len, 31);
        assert_eq!(out, [0x77; 32]);
        // SAFETY: made above, freed once each.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(a) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(b) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    /// docs/DEVIATIONS.md: ED25519's legacy digest-sign with a key without a private key, which
    /// OpenSSL reads from NULL, fails.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn signing_without_a_private_key_fails() {
        let pk = legacy_key(EcxType::Ed25519, EVP_PKEY_ED25519, None);
        // SAFETY: a live key.
        let pctx = unsafe { EVP_PKEY_CTX_new(pk, ptr::null_mut()) };
        // SAFETY: no preconditions.
        let mctx = unsafe { EVP_MD_CTX_new() };
        // SAFETY: live contexts.
        unsafe { EVP_MD_CTX_set_pkey_ctx(mctx, pctx) };
        let mut sig = [0u8; 64];
        let mut len = sig.len();
        // SAFETY: a live context; room for `len` octets; a message.
        let r = unsafe {
            pkey_ecd_digestsign25519(mctx, sig.as_mut_ptr(), &raw mut len, b"abc".as_ptr(), 3)
        };
        assert_eq!(r, 0);
        // SAFETY: live contexts.
        unsafe { EVP_MD_CTX_set_pkey_ctx(mctx, ptr::null_mut()) };
        // SAFETY: made above, freed once each.
        unsafe { EVP_MD_CTX_free(mctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_CTX_free(pctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(pk) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
