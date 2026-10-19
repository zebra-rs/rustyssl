//! The default provider's ML-KEM-512, ML-KEM-768, and ML-KEM-1024 key managers
//! (`ml_kem_kmgmt.c`, with `ml_kem.c`'s key handling over `rustyssl_crypto::mlkem`): keys made
//! empty (once SHA3-256, SHA3-512, SHAKE128, and SHAKE256 can be fetched with the properties),
//! imported from a seed, an expanded private key, or a public key (checked against each other
//! when more than one is given, then a pairwise test), exported, described (sizes, strengths,
//! the keys and seed), given an encoded public key once, compared by their public keys' hashes,
//! copied by selection, validated, and generated (random, or from a seed, used once).
//!
//! As in OpenSSL, the provider's configuration sets each new key's flags:
//! `ml-kem.retain_seed` (keep the seed of a key made from one), `ml-kem.prefer_seed` (make the
//! key from the seed when both it and a private key are imported), and `ml-kem.import_pct_type`
//! (the pairwise test on import: `random`, `fixed`, or none).

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    CMS_RECIPINFO_KEM, ERR_LIB_CRYPTO, ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, NID_HKDF_SHA256,
    OSSL_CALLBACK, OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
    OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
    OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GET_PARAMS,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_VALIDATE, OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_BITS,
    OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM, OSSL_PKEY_PARAM_CMS_RI_TYPE,
    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OSSL_PKEY_PARAM_MAX_SIZE,
    OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE, OSSL_PKEY_PARAM_ML_KEM_PREFER_SEED,
    OSSL_PKEY_PARAM_ML_KEM_RETAIN_SEED, OSSL_PKEY_PARAM_ML_KEM_SEED, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PROPERTIES, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
    OSSL_PKEY_PARAM_SECURITY_CATEGORY, PROV_R_INVALID_KEY, PROV_R_INVALID_KEY_LENGTH,
    PROV_R_INVALID_SEED_LENGTH, PROV_R_MISSING_KEY,
    PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
};
use rustyssl_crypto::mlkem::{self, PrivateKey, PublicKey, RANDOM_BYTES, SEED_BYTES, Variant};

use super::Ptr;
use super::builtin::{conf_bool, conf_param, libctx_of};
use super::macs::{boxed, context, is_empty, locate, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ecx::digest_available;
use crate::err;
use crate::ffi::{bytes, ffi_callback};
use crate::params::build::{
    OSSL_PARAM_BLD_free, OSSL_PARAM_BLD_new, OSSL_PARAM_BLD_push_octet_string,
    OSSL_PARAM_BLD_to_param,
};
use crate::params::dup::OSSL_PARAM_free;
use crate::params::{
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_locate,
    OSSL_PARAM_set_int,
};
use crate::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};

const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
const OCTETS_TYPE: u32 = OSSL_PARAM_OCTET_STRING.cast_unsigned();
const UTF8_TYPE: u32 = OSSL_PARAM_UTF8_STRING.cast_unsigned();
const INT_SIZE: usize = size_of::<c_int>();

/// `ML_KEM_KEY_RANDOM_PCT`.
pub(crate) const RANDOM_PCT: c_int = 1;
/// `ML_KEM_KEY_FIXED_PCT`.
pub(crate) const FIXED_PCT: c_int = 2;
/// `ML_KEM_KEY_PREFER_SEED`.
const PREFER_SEED: c_int = 4;
/// `ML_KEM_KEY_RETAIN_SEED`.
const RETAIN_SEED: c_int = 8;
/// `ML_KEM_KEY_PCT_TYPE`.
const PCT_TYPE: c_int = RANDOM_PCT | FIXED_PCT;
/// `ML_KEM_KEY_PROV_FLAGS_DEFAULT`.
const FLAGS_DEFAULT: c_int = RANDOM_PCT | PREFER_SEED | RETAIN_SEED;

/// What a key holds: nothing yet, a public key, a private key (with its public key), or what
/// a PrivateKeyInfo decoded to, which loading makes the key from.
pub(crate) enum Material {
    Empty,
    Public(PublicKey),
    Private(PrivateKey),
    Pending(Prekey),
}

/// A decoded PrivateKeyInfo's seed and expanded private key (`ossl_ml_kem_set_seed` and the
/// key's `encoded_dk`), wiped when dropped.
pub(crate) struct Prekey {
    seed: Option<[u8; SEED_BYTES]>,
    dk: Option<Vec<u8>>,
}

impl Drop for Prekey {
    fn drop(&mut self) {
        if let Some(s) = self.seed.as_mut() {
            wipe(s);
        }
        if let Some(d) = self.dk.as_mut() {
            wipe(d);
        }
    }
}

impl Material {
    /// The public key, if there is one.
    pub(crate) fn public(&self) -> Option<&PublicKey> {
        match self {
            Self::Empty | Self::Pending(_) => None,
            Self::Public(p) => Some(p),
            Self::Private(k) => Some(k.public()),
        }
    }

    /// The private key, if there is one.
    pub(crate) fn private(&self) -> Option<&PrivateKey> {
        match self {
            Self::Private(k) => Some(k),
            _ => None,
        }
    }
}

/// `ML_KEM_KEY`: a variant's key, immutable once it has key material.
pub(crate) struct MlKemKey {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    pub(crate) variant: Variant,
    /// The `ML_KEM_KEY_*` flags.
    flags: c_int,
    material: Mutex<Material>,
}

impl MlKemKey {
    /// The key material.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Material> {
        self.material.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn has_public(&self) -> bool {
        self.lock().public().is_some()
    }

    fn has_private(&self) -> bool {
        self.lock().private().is_some()
    }

    /// The security strength the key's random draws ask for.
    pub(crate) fn strength(&self) -> c_uint {
        self.variant.security_bits()
    }
}

/// The key behind key data.
///
/// # Safety
/// `keydata` is NULL or key data from one of these key managers.
pub(crate) unsafe fn key<'a>(keydata: *const c_void) -> Option<&'a MlKemKey> {
    // SAFETY: the caller's guarantee.
    unsafe { keydata.cast::<MlKemKey>().as_ref() }
}

/// `ossl_ml_kem_key_new`: an empty key, once the SHA3 digests can be fetched with `propq`.
fn key_new(libctx: *mut OSSL_LIB_CTX, propq: Option<&CStr>, variant: Variant) -> Option<MlKemKey> {
    let fetched = [c"SHAKE128", c"SHAKE256", c"SHA3-256", c"SHA3-512"]
        .map(|name| digest_available(libctx, name, propq));
    if fetched.contains(&false) {
        err::raise_with_text(
            ERR_LIB_CRYPTO,
            ERR_R_INTERNAL_ERROR,
            "ossl_ml_kem_key_new",
            &format!(
                "missing SHA3 digest algorithms while creating {} key",
                variant.name()
            ),
        );
        return None;
    }
    Some(MlKemKey {
        libctx: Ptr(libctx),
        variant,
        flags: FLAGS_DEFAULT,
        material: Mutex::new(Material::Empty),
    })
}

/// `ossl_prov_ml_kem_new`: [`key_new`] with the flags the provider's configuration sets, as key
/// data.
///
/// # Safety
/// `provctx` is the default provider's context.
unsafe fn prov_new(provctx: *mut c_void, propq: Option<&CStr>, variant: Variant) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(provctx) };
    let Some(mut k) = key_new(libctx, propq, variant) else {
        return ptr::null_mut();
    };
    // SAFETY: as above, for each.
    let pct = unsafe { conf_param(provctx, OSSL_PKEY_PARAM_ML_KEM_IMPORT_PCT_TYPE) };
    let pct = pct.as_ref().map_or(&b"random"[..], |v| v.to_bytes());
    // SAFETY: as above.
    if unsafe { conf_bool(provctx, OSSL_PKEY_PARAM_ML_KEM_RETAIN_SEED, true) } {
        k.flags |= RETAIN_SEED;
    } else {
        k.flags &= !RETAIN_SEED;
    }
    // SAFETY: as above.
    if unsafe { conf_bool(provctx, OSSL_PKEY_PARAM_ML_KEM_PREFER_SEED, true) } {
        k.flags |= PREFER_SEED;
    } else {
        k.flags &= !PREFER_SEED;
    }
    if pct.eq_ignore_ascii_case(b"random") {
        k.flags |= RANDOM_PCT;
    } else if pct.eq_ignore_ascii_case(b"fixed") {
        k.flags |= FIXED_PCT;
    } else {
        k.flags &= !PCT_TYPE;
    }
    boxed(k)
}

/// Raises `PROV_R_INVALID_KEY` with `text`.
#[track_caller]
fn invalid_key(function: &str, text: &str) {
    err::raise_with_text(ERR_LIB_PROV, PROV_R_INVALID_KEY, function, text);
}

/// Raises a parse failure's error, as OpenSSL's `parse_pubkey` and `parse_prvkey` do.
#[track_caller]
fn parse_error(e: mlkem::Error, variant: Variant) {
    let name = variant.name();
    match e {
        mlkem::Error::InvalidPublicVector => {
            invalid_key("parse_pubkey", &format!("{name} invalid public 't' vector"));
        }
        mlkem::Error::InvalidPrivateVector => {
            invalid_key(
                "parse_prvkey",
                &format!("{name} invalid private 's' vector"),
            );
        }
        mlkem::Error::HashMismatch => {
            invalid_key("parse_prvkey", &format!("{name} public key hash mismatch"));
        }
        mlkem::Error::Internal => err::raise_with_text(
            ERR_LIB_CRYPTO,
            ERR_R_INTERNAL_ERROR,
            "parse_pubkey",
            &format!("internal error while parsing {name} public key"),
        ),
        mlkem::Error::Length => {}
    }
}

/// `ossl_ml_kem_genkey` from `seed`, keeping `d` if the key's flags say so; `None` (with an
/// error) if it fails.
fn generate(k: &MlKemKey, seed: &[u8; SEED_BYTES]) -> Option<PrivateKey> {
    let Some(mut p) = PrivateKey::generate(k.variant, seed) else {
        err::raise_with_text(
            ERR_LIB_CRYPTO,
            ERR_R_INTERNAL_ERROR,
            "genkey",
            &format!(
                "internal error while generating {} private key",
                k.variant.name()
            ),
        );
        return None;
    };
    if k.flags & RETAIN_SEED == 0 {
        p.forget_seed();
    }
    Some(p)
}

/// `ml_kem_pairwise_test`: an encapsulation (random entropy, or `0x55` octets) to the key's
/// public key decapsulates with its private key to the same secret; true without both keys or
/// a test type.
pub(crate) fn pairwise(k: &MlKemKey, flags: c_int) -> bool {
    if !k.has_private() || flags & PCT_TYPE == 0 {
        return true;
    }
    let mut entropy = [0x55u8; RANDOM_BYTES];
    let drawn = flags & RANDOM_PCT == 0
        // SAFETY: the key's library context; room for the entropy.
        || unsafe { RAND_bytes_ex(k.libctx.0, entropy.as_mut_ptr(), RANDOM_BYTES, k.strength()) } >= 1;
    let ok = drawn && {
        let m = k.lock();
        m.private().is_some_and(|p| {
            p.public().encapsulate(&entropy).is_some_and(|(c, secret)| {
                p.decapsulate(&c)
                    .is_some_and(|out| out.as_slice() == secret.as_slice())
            })
        })
    };
    wipe(&mut entropy);
    if !ok {
        invalid_key(
            "ml_kem_pairwise_test",
            &format!(
                "public part of {} private key fails to match private",
                k.variant.name()
            ),
        );
    }
    ok
}

ffi_callback! {
    /// `ml_kem_has`: always for no key part; the public key; else the private key.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ml_kem_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        c_int::from(match selection & KEYPAIR {
            0 => true,
            PUBLIC => k.has_public(),
            _ => k.has_private(),
        })
    }
}

ffi_callback! {
    /// `ml_kem_match`: equal for no key part; else by `ossl_ml_kem_pubkey_cmp` (the public
    /// keys' hashes, or both without one).
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are NULL or live key data.
    pub(crate) unsafe extern "C" fn ml_kem_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        if selection & KEYPAIR == 0 {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let (Some(k1), Some(k2)) = (unsafe { key(keydata1) }, unsafe { key(keydata2) }) else {
            return 0;
        };
        let h1 = k1.lock().public().map(|p| *p.hash());
        let h2 = k2.lock().public().map(|p| *p.hash());
        c_int::from(match (h1, h2) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            _ => false,
        })
    }
}

ffi_callback! {
    /// `ml_kem_validate`: the parts the selection names, and the pair's random pairwise test.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ml_kem_validate(keydata: *const c_void, selection: c_int, _checktype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { ml_kem_has(keydata, selection) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == KEYPAIR {
            return c_int::from(pairwise(k, RANDOM_PCT));
        }
        1
    }
}

/// An octet-string parameter's octets (`OSSL_PARAM_get_octet_string_ptr`), or `None` if it
/// isn't one.
fn octets_ptr(p: &OSSL_PARAM) -> Option<&[u8]> {
    let mut data: *const c_void = ptr::null();
    let mut len = 0;
    // SAFETY: a parameter; places for the pointer and length.
    if unsafe { OSSL_PARAM_get_octet_string_ptr(p, &raw mut data, &raw mut len) } != 1 {
        return None;
    }
    // SAFETY: the parameter's own octets, which outlive the call.
    unsafe { bytes(data.cast::<u8>(), len) }
}

/// `ml_kem_key_fromdata`: a seed (`d || z`, made into the key), an expanded private key, or a
/// public key, the private ones only if `include_private`; each given one checked against the
/// others.
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn key_fromdata(k: &MlKemKey, params: *const OSSL_PARAM, include_private: bool) -> bool {
    const F: &str = "ml_kem_key_fromdata";
    if k.has_public() {
        return false;
    }
    // SAFETY: the caller's guarantee.
    if !unsafe {
        crate::provider::param_decoders::decode(
            params,
            &crate::provider::param_decoders::ML_KEM_KEY_TYPE_PARAMS,
        )
    } {
        return false;
    }
    let v = k.variant;
    let name = v.name();
    let (mut seed, mut prv): (&[u8], &[u8]) = (&[], &[]);
    if include_private {
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_ML_KEM_SEED) } {
            let Some(s) = octets_ptr(p) else { return false };
            seed = s;
        }
        if !seed.is_empty() && seed.len() != SEED_BYTES {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH, F);
            return false;
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) } {
            let Some(s) = octets_ptr(p) else { return false };
            prv = s;
        }
        if !prv.is_empty() && prv.len() != v.private_key_bytes() {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, F);
            return false;
        }
    }
    let mut public: &[u8] = &[];
    // SAFETY: as above.
    if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PUB_KEY) } {
        let Some(s) = octets_ptr(p) else { return false };
        public = s;
    }
    if !public.is_empty() && public.len() != v.public_key_bytes() {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, F);
        return false;
    }
    if seed.is_empty() && public.is_empty() && prv.is_empty() {
        err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
        return false;
    }
    // The public key embedded in `dk = dk_pke || ek || H(ek) || z`.
    if !public.is_empty() && !prv.is_empty() {
        let off = prv
            .len()
            .saturating_sub(RANDOM_BYTES + mlkem::PKHASH_BYTES + public.len());
        if prv.get(off..off.saturating_add(public.len())) != Some(public) {
            invalid_key(
                F,
                &format!("explicit {name} public key does not match private"),
            );
            return false;
        }
    }
    let material = if !seed.is_empty() && (prv.is_empty() || k.flags & PREFER_SEED != 0) {
        let z = seed.get(RANDOM_BYTES..).unwrap_or_default();
        if !prv.is_empty() && prv.get(prv.len().saturating_sub(RANDOM_BYTES)..) != Some(z) {
            invalid_key(
                "check_seed",
                &format!("private {name} key implicit rejection secret does not match seed"),
            );
            return false;
        }
        let Ok(s) = <&[u8; SEED_BYTES]>::try_from(seed) else {
            return false;
        };
        let Some(p) = generate(k, s) else {
            return false;
        };
        if !prv.is_empty() && p.encode().as_slice() != prv {
            invalid_key(
                "check_prvenc",
                &format!("explicit {name} private key does not match seed"),
            );
            return false;
        }
        Material::Private(p)
    } else if !prv.is_empty() {
        match PrivateKey::parse(v, prv) {
            Ok(p) => Material::Private(p),
            Err(e) => {
                parse_error(e, v);
                return false;
            }
        }
    } else {
        match PublicKey::parse(v, public) {
            Ok(p) => Material::Public(p),
            Err(e) => {
                parse_error(e, v);
                return false;
            }
        }
    };
    *k.lock() = material;
    true
}

ffi_callback! {
    /// `ml_kem_import`: the key pair (which must be selected), then, with a private key, the
    /// pairwise test the key's flags ask for (the key emptied if it fails).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_kem_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 0;
        }
        let include_private = selection & PRIVATE != 0;
        // SAFETY: the caller's array.
        if !unsafe { key_fromdata(k, params, include_private) } {
            return 0;
        }
        if include_private && !pairwise(k, k.flags) {
            *k.lock() = Material::Empty;
            return 0;
        }
        1
    }
}

ffi_callback! {
    /// `ml_kem_export`: the seed and the private key (if selected and present), and the public
    /// key (if selected); a key without a public key fails with `PROV_R_MISSING_KEY`.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` is called with `cbarg`.
    pub(crate) unsafe extern "C" fn ml_kem_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 0;
        }
        let (seed, private, public) = {
            let m = k.lock();
            let Some(p) = m.public() else {
                drop(m);
                err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "ml_kem_export");
                return 0;
            };
            let public = (selection & PUBLIC != 0).then(|| p.encode());
            let (seed, private) = match m.private() {
                Some(d) if selection & PRIVATE != 0 => (d.seed(), Some(d.encode())),
                _ => (None, None),
            };
            (seed, private, public)
        };
        // SAFETY: no preconditions.
        let bld = unsafe { OSSL_PARAM_BLD_new() };
        if bld.is_null() {
            return 0;
        }
        let push = |name: &CStr, v: &[u8]| {
            // SAFETY: the builder; a static name; octets that outlive the array's making.
            (unsafe { OSSL_PARAM_BLD_push_octet_string(bld, name.as_ptr(), v.as_ptr().cast(), v.len()) }) != 0
        };
        let ok = seed.as_ref().is_none_or(|s| push(OSSL_PKEY_PARAM_ML_KEM_SEED, s.as_slice()))
            && private.as_ref().is_none_or(|d| push(OSSL_PKEY_PARAM_PRIV_KEY, d.as_slice()))
            && public.as_ref().is_none_or(|q| push(OSSL_PKEY_PARAM_PUB_KEY, q));
        let mut ret = 0;
        if ok {
            // SAFETY: the builder.
            let params = unsafe { OSSL_PARAM_BLD_to_param(bld) };
            if !params.is_null() {
                if let Some(cb) = param_cb {
                    // SAFETY: the caller's callback and argument; the array, freed after.
                    ret = unsafe { cb(params, cbarg) };
                }
                let mut p = params;
                // SAFETY: the array made above, ended by a NULL key.
                while let Some(q) = unsafe { p.as_ref() } {
                    if q.key.is_null() {
                        break;
                    }
                    if !q.data.is_null() {
                        // SAFETY: the parameter's own octets.
                        unsafe { crate::mem::OPENSSL_cleanse(q.data, q.data_size) };
                    }
                    p = p.wrapping_add(1);
                }
                // SAFETY: the array made above.
                unsafe { OSSL_PARAM_free(params) };
            }
        }
        // SAFETY: the builder made above.
        unsafe { OSSL_PARAM_BLD_free(bld) };
        ret
    }
}

/// `ml_kem_imexport_types`' list.
static KEY_TYPES: Params<4> = Params([
    defn(OSSL_PKEY_PARAM_ML_KEM_SEED, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_kem_imexport_types`.
    pub(crate) unsafe extern "C" fn ml_kem_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        if selection & KEYPAIR != 0 { KEY_TYPES.0.as_ptr() } else { ptr::null() }
    }
}

/// Writes `v` into the octet-string parameter named `name` if the array has it (its size
/// alone when it has no room given); false for another type or too little room.
///
/// # Safety
/// `params` is NULL or an array whose entries may be written.
unsafe fn put(params: *mut OSSL_PARAM, name: &CStr, v: &[u8]) -> bool {
    // SAFETY: the caller's array; a static name.
    let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
    // SAFETY: a parameter of the array, or NULL.
    let Some(p) = (unsafe { p.as_mut() }) else {
        return true;
    };
    if p.data_type != OCTETS_TYPE {
        return false;
    }
    p.return_size = v.len();
    if p.data.is_null() {
        return true;
    }
    if p.data_size < v.len() {
        return false;
    }
    // SAFETY: the parameter's room, at least `v.len()` octets.
    unsafe { ptr::copy_nonoverlapping(v.as_ptr(), p.data.cast::<u8>(), v.len()) };
    true
}

/// Sets the integer parameter named `name` to `v`, if the array has it.
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn set_int(params: *mut OSSL_PARAM, name: &CStr, v: impl TryInto<c_int>) -> bool {
    let v = v.try_into().unwrap_or(c_int::MAX);
    // SAFETY: the caller's array; a static name.
    let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
    // SAFETY: a parameter of the array.
    p.is_null() || unsafe { OSSL_PARAM_set_int(p, v) } != 0
}

ffi_callback! {
    /// `ml_kem_get_params`: the bits, security bits, and largest output (the ciphertext's
    /// length); the public key (as it and as the encoded public key), the private key, and the
    /// seed, each if the key has it.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_kem_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::ML_KEM_GET_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        let v = k.variant;
        // SAFETY: the caller's array, for each.
        if !(unsafe { set_int(params, OSSL_PKEY_PARAM_BITS, v.bits()) }
            // SAFETY: as above.
            && unsafe { set_int(params, OSSL_PKEY_PARAM_SECURITY_BITS, v.security_bits()) }
            // SAFETY: as above.
            && unsafe { set_int(params, OSSL_PKEY_PARAM_MAX_SIZE, v.ciphertext_bytes()) }
            // SAFETY: as above.
            && unsafe { set_int(params, OSSL_PKEY_PARAM_SECURITY_CATEGORY, v.security_category()) }
            // CMS's KEMRecipientInfo (from 3.6): the recipient info type, and the KDF's
            // AlgorithmIdentifier, HKDF-SHA256 with absent parameters.
            // SAFETY: as above.
            && unsafe { set_int(params, OSSL_PKEY_PARAM_CMS_RI_TYPE, CMS_RECIPINFO_KEM) })
        {
            return 0;
        }
        let kdf_alg = super::kdfs::oid_der(NID_HKDF_SHA256).and_then(|oid| {
            let mut aid = vec![0x30, u8::try_from(oid.len()).ok()?];
            aid.extend_from_slice(&oid);
            Some(aid)
        });
        let Some(kdf_alg) = kdf_alg else { return 0 };
        // SAFETY: the caller's array.
        if !unsafe { put(params, OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM, &kdf_alg) } {
            return 0;
        }
        let (public, private, seed) = {
            let m = k.lock();
            let public = m.public().map(PublicKey::encode);
            let private = m.private().map(PrivateKey::encode);
            let seed = m.private().and_then(PrivateKey::seed);
            (public, private, seed)
        };
        if let Some(q) = public.as_deref() {
            for name in [OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY] {
                // SAFETY: the caller's array.
                if !unsafe { put(params, name, q) } {
                    return 0;
                }
            }
        }
        if let Some(d) = private.as_ref() {
            // SAFETY: as above.
            if !unsafe { put(params, OSSL_PKEY_PARAM_PRIV_KEY, d.as_slice()) } {
                return 0;
            }
        }
        if let Some(s) = seed.as_ref() {
            // SAFETY: as above.
            if !unsafe { put(params, OSSL_PKEY_PARAM_ML_KEM_SEED, s.as_slice()) } {
                return 0;
            }
        }
        1
    }
}

/// `ml_kem_gettable_params`' list.
static GETTABLE: Params<11> = Params([
    defn(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
        OSSL_PARAM_INTEGER,
        INT_SIZE,
    ),
    defn(OSSL_PKEY_PARAM_ML_KEM_SEED, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(OSSL_PKEY_PARAM_CMS_RI_TYPE, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(
        OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_kem_gettable_params`.
    pub(crate) unsafe extern "C" fn ml_kem_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `ml_kem_set_params`: an encoded public key of the variant's length, given to a key without
    /// key material.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_kem_set_params(keydata: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::ML_KEM_SET_PARAMS) } {
            return 0;
        }
        const F: &str = "ml_kem_set_params";
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: as above.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        let Some(p) = (unsafe { locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) }) else {
            return 1;
        };
        let Some(q) = octets_ptr(p).filter(|q| q.len() == k.variant.public_key_bytes()) else {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, F);
            return 0;
        };
        if k.has_public() {
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                F,
                "ML-KEM keys cannot be mutated",
            );
            return 0;
        }
        match PublicKey::parse(k.variant, q) {
            Ok(public) => {
                *k.lock() = Material::Public(public);
                1
            }
            Err(e) => {
                parse_error(e, k.variant);
                0
            }
        }
    }
}

/// `ml_kem_settable_params`' list.
static SETTABLE: Params<2> = Params([
    defn(
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_kem_settable_params`.
    pub(crate) unsafe extern "C" fn ml_kem_settable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

/// `PROV_ML_KEM_GEN_CTX`.
struct GenCtx {
    provctx: *mut c_void,
    propq: Option<CString>,
    selection: c_int,
    variant: Variant,
    /// The seed, for one generation.
    seed: Option<[u8; SEED_BYTES]>,
}

impl Drop for GenCtx {
    fn drop(&mut self) {
        if let Some(s) = self.seed.as_mut() {
            wipe(s);
        }
    }
}

ffi_callback! {
    /// `ml_kem_gen_set_params`: the properties, and a seed of exactly 64 octets.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_kem_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::ML_KEM_GEN_SET_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else { return 0 };
        // SAFETY: as above.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PROPERTIES) } {
            if p.data_type != UTF8_TYPE || p.data.is_null() {
                return 0;
            }
            // SAFETY: a UTF-8 string parameter's data is a string.
            g.propq = Some(unsafe { CStr::from_ptr(p.data.cast::<c_char>()) }.to_owned());
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_ML_KEM_SEED) } {
            let mut buf = [0u8; SEED_BYTES];
            let mut out = buf.as_mut_ptr().cast::<c_void>();
            let mut len = SEED_BYTES;
            // SAFETY: the parameter; room for a seed.
            let got = unsafe { OSSL_PARAM_get_octet_string(p, &raw mut out, SEED_BYTES, &raw mut len) };
            if let Some(old) = g.seed.as_mut() {
                wipe(old);
            }
            if got != 0 && len == SEED_BYTES {
                g.seed = Some(buf);
                wipe(&mut buf);
                return 1;
            }
            wipe(&mut buf);
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH, "ml_kem_gen_set_params");
            g.seed = None;
            return 0;
        }
        1
    }
}

/// `ml_kem_gen_settable_params`' list.
static GEN_SETTABLE: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_ML_KEM_SEED, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_kem_gen_settable_params`.
    pub(crate) unsafe extern "C" fn ml_kem_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

/// `ml_kem_gen_init`: a generation context for a selection with parameters or a private key.
///
/// # Safety
/// `provctx` is the default provider's context; `params` is NULL or an array.
unsafe fn gen_init(
    provctx: *mut c_void,
    selection: c_int,
    params: *const OSSL_PARAM,
    variant: Variant,
) -> *mut c_void {
    if selection & (OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | PRIVATE) == 0 {
        return ptr::null_mut();
    }
    let g = boxed(GenCtx {
        provctx,
        propq: None,
        selection,
        variant,
        seed: None,
    });
    // SAFETY: the context just made; the caller's array.
    if unsafe { ml_kem_gen_set_params(g, params) } == 0 {
        // SAFETY: the context just made, freed once.
        unsafe { unbox::<GenCtx>(g) };
        return ptr::null_mut();
    }
    g
}

ffi_callback! {
    /// `ml_kem_gen`: nothing for a public key alone; an empty key for no key part; otherwise a
    /// key from the seed set (used once) or a random one.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context.
    pub(crate) unsafe extern "C" fn ml_kem_gen(genctx: *mut c_void, _cb: OSSL_CALLBACK, _cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else { return ptr::null_mut() };
        if g.selection & KEYPAIR == PUBLIC {
            return ptr::null_mut();
        }
        // SAFETY: the context's provider context.
        let h = unsafe { prov_new(g.provctx, g.propq.as_deref(), g.variant) };
        // SAFETY: the key just made, or NULL.
        let Some(k) = (unsafe { key(h) }) else { return ptr::null_mut() };
        if g.selection & KEYPAIR == 0 {
            return h;
        }
        // The seed, used once: copied out and wiped from the context.
        let given = g.seed;
        if let Some(s) = g.seed.as_mut() {
            wipe(s);
        }
        g.seed = None;
        let mut seed = match given {
            Some(s) => s,
            None => {
                let mut s = [0u8; SEED_BYTES];
                // SAFETY: the key's library context; room for a seed.
                if unsafe { RAND_priv_bytes_ex(k.libctx.0, s.as_mut_ptr(), SEED_BYTES, k.strength()) } <= 0 {
                    // SAFETY: the key made above.
                    unsafe { unbox::<MlKemKey>(h) };
                    return ptr::null_mut();
                }
                s
            }
        };
        let generated = generate(k, &seed);
        wipe(&mut seed);
        let Some(p) = generated else {
            // SAFETY: as above.
            unsafe { unbox::<MlKemKey>(h) };
            return ptr::null_mut();
        };
        *k.lock() = Material::Private(p);
        h
    }
}

ffi_callback! {
    /// `ml_kem_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn ml_kem_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

/// `ml_kem_load`'s completion of a decoded key: from the seed (checked against the expanded
/// key's implicit-rejection secret and, when it's made from the seed, the whole expanded key)
/// when there's no expanded key or the key prefers its seed, else from the expanded key with
/// the pairwise test. False (with OpenSSL's errors) on failure.
fn complete(k: &MlKemKey, pre: &Prekey) -> bool {
    let name = k.variant.name();
    if let (Some(seed), Some(dk)) = (&pre.seed, &pre.dk)
        && dk.get(dk.len().saturating_sub(RANDOM_BYTES)..) != seed.get(RANDOM_BYTES..)
    {
        invalid_key(
            "check_seed",
            &format!("private {name} key implicit rejection secret does not match seed"),
        );
        return false;
    }
    if let Some(seed) = pre
        .seed
        .as_ref()
        .filter(|_| pre.dk.is_none() || k.flags & PREFER_SEED != 0)
    {
        let Some(p) = generate(k, seed) else {
            return false;
        };
        if let Some(dk) = &pre.dk
            && p.encode().as_slice() != dk.as_slice()
        {
            invalid_key(
                "check_prvenc",
                &format!("explicit {name} private key does not match seed"),
            );
            return false;
        }
        *k.lock() = Material::Private(p);
        return true;
    }
    let Some(dk) = &pre.dk else { return true };
    match PrivateKey::parse(k.variant, dk) {
        Ok(p) => *k.lock() = Material::Private(p),
        Err(e) => {
            parse_error(e, k.variant);
            invalid_key("ml_kem_load", &format!("error parsing {name} private key"));
            return false;
        }
    }
    pairwise(k, k.flags)
}

ffi_callback! {
    /// `ml_kem_load`: the key the reference points to, the reference cleared; a decoded key
    /// made from its seed or expanded key first (freed, giving NULL, if that fails). As in
    /// OpenSSL, a whole key that kept its seed can't be made from it again, and is freed too.
    ///
    /// # Safety
    /// `reference` is NULL or points to `reference_sz` writable octets holding live key data's
    /// pointer.
    pub(crate) unsafe extern "C" fn ml_kem_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        if reference.is_null() || reference_sz != size_of::<*mut c_void>() {
            return ptr::null_mut();
        }
        let slot = reference.cast::<*mut c_void>().cast_mut();
        // SAFETY: the caller's guarantee.
        let h = unsafe { slot.read_unaligned() };
        // SAFETY: as above: writable.
        unsafe { slot.write_unaligned(ptr::null_mut()) };
        // SAFETY: the key data the reference held.
        let Some(k) = (unsafe { key(h) }) else { return ptr::null_mut() };
        let pending = {
            let mut m = k.lock();
            match core::mem::replace(&mut *m, Material::Empty) {
                Material::Pending(pre) => Some(pre),
                other => {
                    *m = other;
                    None
                }
            }
        };
        let ok = match pending {
            Some(pre) => complete(k, &pre),
            None => !k.lock().private().is_some_and(|p| p.seed().is_some()),
        };
        if !ok {
            // SAFETY: the key, now the caller's no longer.
            unsafe { unbox::<MlKemKey>(h) };
            return ptr::null_mut();
        }
        h
    }
}

/// `ossl_ml_kem_d2i_PUBKEY`: a key of the variant (with the default flags) from a
/// SubjectPublicKeyInfo of exactly its length and prefix; NULL otherwise.
///
/// # Safety
/// `provctx` is the default provider's context.
pub(crate) unsafe fn d2i_pubkey(
    provctx: *mut c_void,
    propq: Option<&CStr>,
    variant: Variant,
    nid: c_int,
    der: &[u8],
) -> *mut c_void {
    use super::ml_codecs::{SPKI_OVERHEAD, oid_octets, spki_prefix};
    let pk = variant.public_key_bytes();
    let prefix = oid_octets(nid).and_then(|o| spki_prefix(&o, pk));
    let (Some(prefix), true) = (prefix, der.len() == SPKI_OVERHEAD + pk) else {
        return ptr::null_mut();
    };
    if der.get(..SPKI_OVERHEAD) != Some(&prefix[..]) {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(provctx) };
    let Some(k) = key_new(libctx, propq, variant) else {
        return ptr::null_mut();
    };
    match PublicKey::parse(variant, der.get(SPKI_OVERHEAD..).unwrap_or_default()) {
        Ok(p) => {
            *k.lock() = Material::Public(p);
            boxed(k)
        }
        Err(e) => {
            parse_error(e, variant);
            err::raise_with_text(
                ERR_LIB_PROV,
                rustyssl_abi::PROV_R_BAD_ENCODING,
                "ossl_ml_kem_d2i_PUBKEY",
                &format!(
                    "error parsing {} public key from input SPKI",
                    variant.name()
                ),
            );
            ptr::null_mut()
        }
    }
}

/// `ossl_ml_kem_d2i_PKCS8`: a key of the variant (with the provider's flags) holding a
/// PrivateKeyInfo's seed and expanded key, by the configuration's enabled input formats, for
/// loading to make the key from; NULL otherwise.
///
/// # Safety
/// `provctx` is the default provider's context.
pub(crate) unsafe fn d2i_pkcs8(
    provctx: *mut c_void,
    propq: Option<&CStr>,
    variant: Variant,
    nid: c_int,
    der: &[u8],
) -> *mut c_void {
    use super::ml_codecs::{Refused, formats, order, parse};
    let name = variant.name();
    // SAFETY: the caller's guarantee.
    let Some((key_octets, ptype, alg)) = (unsafe { super::der2key::p8_parts(der) }) else {
        return ptr::null_mut();
    };
    if alg != nid {
        return ptr::null_mut();
    }
    let table = formats(
        SEED_BYTES,
        variant.private_key_bytes(),
        variant.public_key_bytes(),
    );
    // SAFETY: as above.
    let list = unsafe { conf_param(provctx, rustyssl_abi::OSSL_PKEY_PARAM_ML_KEM_INPUT_FORMATS) };
    let Some(slots) = order(name, &table, "input", list.as_deref()) else {
        return ptr::null_mut();
    };
    if ptype != rustyssl_abi::V_ASN1_UNDEF {
        err::raise_with_text(
            ERR_LIB_PROV,
            rustyssl_abi::PROV_R_UNEXPECTED_KEY_PARAMETERS,
            "ossl_ml_kem_d2i_PKCS8",
            &format!("unexpected parameters with a PKCS#8 {name} private key"),
        );
        return ptr::null_mut();
    }
    let parts = match parse(
        &key_octets,
        &slots,
        SEED_BYTES,
        variant.private_key_bytes(),
        variant.public_key_bytes(),
    ) {
        Ok(p) => p,
        Err(Refused::NoFormat) => {
            err::raise_with_text(
                ERR_LIB_PROV,
                rustyssl_abi::PROV_R_ML_KEM_NO_FORMAT,
                "ossl_ml_kem_d2i_PKCS8",
                &format!("no matching enabled {name} private key input formats"),
            );
            return ptr::null_mut();
        }
        Err(Refused::Malformed) => return ptr::null_mut(),
    };
    let seed = parts
        .seed
        .and_then(|s| <[u8; SEED_BYTES]>::try_from(s).ok());
    let dk = parts.private.map(<[u8]>::to_vec);
    // SAFETY: as above.
    let h = unsafe { prov_new(provctx, propq, variant) };
    // SAFETY: the new key data, or NULL.
    if let Some(k) = unsafe { key(h) } {
        *k.lock() = Material::Pending(Prekey { seed, dk });
    }
    h
}

ffi_callback! {
    /// `ml_kem_dup` (`ossl_ml_kem_key_dup`): the key parts the selection names that the key has
    /// (a private key bringing its public key and seed).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ml_kem_dup(keydata: *const c_void, selection: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return ptr::null_mut() };
        let material = {
            let m = k.lock();
            match (&*m, selection & KEYPAIR) {
                (Material::Private(p), s) if s & PRIVATE != 0 => Material::Private(p.clone()),
                (_, s) if s & PUBLIC != 0 => m.public().cloned().map_or(Material::Empty, Material::Public),
                _ => Material::Empty,
            }
        };
        boxed(MlKemKey {
            libctx: k.libctx,
            variant: k.variant,
            flags: k.flags,
            material: Mutex::new(material),
        })
    }
}

ffi_callback! {
    /// `ml_kem_free_key`.
    ///
    /// # Safety
    /// `keydata` is NULL or key data the caller gives up.
    pub(crate) unsafe extern "C" fn ml_kem_free_key(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<MlKemKey>(keydata) };
    }
}

type NewFn = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type FreeFn = unsafe extern "C" fn(*mut c_void);
type HasFn = unsafe extern "C" fn(*const c_void, c_int) -> c_int;
type MatchFn = unsafe extern "C" fn(*const c_void, *const c_void, c_int) -> c_int;
type ImportFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> c_int;
type TypesFn = unsafe extern "C" fn(c_int) -> *const OSSL_PARAM;
type ExportFn = unsafe extern "C" fn(*mut c_void, c_int, OSSL_CALLBACK, *mut c_void) -> c_int;
type GetParamsFn = unsafe extern "C" fn(*mut c_void, *mut OSSL_PARAM) -> c_int;
type SetParamsFn = unsafe extern "C" fn(*mut c_void, *const OSSL_PARAM) -> c_int;
type ListFn = unsafe extern "C" fn(*mut c_void) -> *const OSSL_PARAM;
type GenInitFn = unsafe extern "C" fn(*mut c_void, c_int, *const OSSL_PARAM) -> *mut c_void;
type GenListFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> *const OSSL_PARAM;
type GenFn = unsafe extern "C" fn(*mut c_void, OSSL_CALLBACK, *mut c_void) -> *mut c_void;
type LoadFn = unsafe extern "C" fn(*const c_void, usize) -> *mut c_void;
type DupFn = unsafe extern "C" fn(*const c_void, c_int) -> *mut c_void;
type ValidateFn = unsafe extern "C" fn(*const c_void, c_int, c_int) -> c_int;

/// `DECLARE_VARIANT`: one variant's functions and dispatch table.
macro_rules! ml_kem_keymgmt {
    ($table:ident, $variant:expr, $new:ident, $gen_init:ident) => {
        ffi_callback! {
            /// The variant's `ml_kem_*_new`.
            ///
            /// # Safety
            /// `provctx` is the default provider's context.
            pub(crate) unsafe extern "C" fn $new(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { prov_new(provctx, None, $variant) }
            }
        }
        ffi_callback! {
            /// The variant's `ml_kem_*_gen_init`.
            ///
            /// # Safety
            /// As for `gen_init`.
            pub(crate) unsafe extern "C" fn $gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { gen_init(provctx, selection, params, $variant) }
            }
        }
        /// `ossl_ml_kem_*_keymgmt_functions`.
        pub(crate) static $table: Dispatch<21> = Dispatch([
            entry!(OSSL_FUNC_KEYMGMT_NEW, $new, NewFn),
            entry!(OSSL_FUNC_KEYMGMT_FREE, ml_kem_free_key, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, ml_kem_get_params, GetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, ml_kem_gettable_params, ListFn),
            entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, ml_kem_set_params, SetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, ml_kem_settable_params, ListFn),
            entry!(OSSL_FUNC_KEYMGMT_HAS, ml_kem_has, HasFn),
            entry!(OSSL_FUNC_KEYMGMT_MATCH, ml_kem_match, MatchFn),
            entry!(OSSL_FUNC_KEYMGMT_VALIDATE, ml_kem_validate, ValidateFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, $gen_init, GenInitFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, ml_kem_gen_set_params, SetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, ml_kem_gen_settable_params, GenListFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN, ml_kem_gen, GenFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, ml_kem_gen_cleanup, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_LOAD, ml_kem_load, LoadFn),
            entry!(OSSL_FUNC_KEYMGMT_DUP, ml_kem_dup, DupFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT, ml_kem_import, ImportFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, ml_kem_imexport_types, TypesFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT, ml_kem_export, ExportFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, ml_kem_imexport_types, TypesFn),
            END,
        ]);
    };
}

ml_kem_keymgmt!(
    ML_KEM_512_KEYMGMT,
    Variant::MlKem512,
    ml_kem_512_new,
    ml_kem_512_gen_init
);
ml_kem_keymgmt!(
    ML_KEM_768_KEYMGMT,
    Variant::MlKem768,
    ml_kem_768_new,
    ml_kem_768_gen_init
);
ml_kem_keymgmt!(
    ML_KEM_1024_KEYMGMT,
    Variant::MlKem1024,
    ml_kem_1024_new,
    ml_kem_1024_gen_init
);

/// `ossl_ml_kem_i2d_pubkey`: the public key's octets, or `None` (with `PROV_R_NOT_A_PUBLIC_KEY`).
///
/// # Safety
/// `keydata` is NULL or live key data.
pub(crate) unsafe fn i2d_pubkey(keydata: *const c_void) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { key(keydata) }?;
    let public = k.lock().public().map(|p| p.encode().to_vec());
    if public.is_none() {
        err::raise_with_text(
            ERR_LIB_PROV,
            rustyssl_abi::PROV_R_NOT_A_PUBLIC_KEY,
            "ossl_ml_kem_i2d_pubkey",
            &format!("no {} public key data available", k.variant.name()),
        );
    }
    public
}

/// `ossl_ml_kem_i2d_prvkey`: the private key in the first output format (the provider's
/// `ml-kem.output_formats` order) the key can fill, or `None` with OpenSSL's errors.
///
/// # Safety
/// `keydata` is NULL or live key data; `provctx` is the default provider's context.
pub(crate) unsafe fn i2d_prvkey(keydata: *const c_void, provctx: *mut c_void) -> Option<Vec<u8>> {
    use super::ml_codecs::{formats, order, output_format, write};
    // SAFETY: the caller's guarantee.
    let k = unsafe { key(keydata) }?;
    let variant = k.variant;
    let name = variant.name();
    let parts = k.lock().private().map(|p| {
        (
            p.encode().to_vec(),
            p.seed().map(|s| s.to_vec()),
            p.public().encode().to_vec(),
        )
    });
    let Some((mut sk, mut seed, pk)) = parts else {
        err::raise_with_text(
            ERR_LIB_PROV,
            rustyssl_abi::PROV_R_NOT_A_PRIVATE_KEY,
            "ossl_ml_kem_i2d_prvkey",
            &format!("no {name} private key data available"),
        );
        return None;
    };
    let table = formats(
        SEED_BYTES,
        variant.private_key_bytes(),
        variant.public_key_bytes(),
    );
    // SAFETY: the caller's guarantee.
    let list = unsafe {
        super::builtin::conf_param(provctx, rustyssl_abi::OSSL_PKEY_PARAM_ML_KEM_OUTPUT_FORMATS)
    };
    let out = order(name, &table, "output", list.as_deref()).and_then(|slots| {
        let f = output_format(
            &slots,
            seed.is_some(),
            SEED_BYTES,
            variant.private_key_bytes(),
            variant.public_key_bytes(),
        );
        let Some(f) = f else {
            err::raise_with_text(
                ERR_LIB_PROV,
                rustyssl_abi::PROV_R_ML_KEM_NO_FORMAT,
                "ossl_ml_kem_i2d_prvkey",
                &format!("no matching enabled {name} private key output formats"),
            );
            return None;
        };
        let w = write(&f, seed.as_deref(), &sk, &pk);
        if w.is_none() {
            err::raise_with_text(
                ERR_LIB_PROV,
                rustyssl_abi::ERR_R_INTERNAL_ERROR,
                "ossl_ml_kem_i2d_prvkey",
                &format!("error encoding {name} private key"),
            );
        }
        w
    });
    wipe(&mut sk);
    if let Some(s) = seed.as_mut() {
        wipe(s);
    }
    out
}
