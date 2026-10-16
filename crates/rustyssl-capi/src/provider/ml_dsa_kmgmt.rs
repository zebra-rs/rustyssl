//! The default provider's ML-DSA-44, ML-DSA-65, and ML-DSA-87 key managers (`ml_dsa_kmgmt.c`,
//! with `ml_dsa_key.c`'s key handling over `rustyssl_crypto::mldsa`): keys made empty (once
//! SHAKE-128 and SHAKE-256 can be fetched with the properties), imported from a seed, a private
//! key, or a public key (a given public key checked against the private key's), exported,
//! described (sizes, strength, the keys and seed, an empty mandatory digest), compared, copied
//! by selection, validated (the pair), and generated (random, or from a seed, which the
//! generation context keeps).
//!
//! As in OpenSSL, the provider's configuration sets each new key's flags:
//! `ml-dsa.retain_seed` (keep the seed of a key made from one) and `ml-dsa.prefer_seed` (make
//! the key from the seed when both it and a private key are imported). Unlike ML-KEM, an import
//! runs no pairwise test, and a generation seed shorter than 32 octets is taken by the
//! parameters and then fails the generation without an error.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_PROV, OSSL_CALLBACK, OSSL_FUNC_KEYMGMT_DUP, OSSL_FUNC_KEYMGMT_EXPORT,
    OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_FREE, OSSL_FUNC_KEYMGMT_GEN,
    OSSL_FUNC_KEYMGMT_GEN_CLEANUP, OSSL_FUNC_KEYMGMT_GEN_INIT, OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
    OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_GET_PARAMS,
    OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS, OSSL_FUNC_KEYMGMT_IMPORT,
    OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_LOAD, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_VALIDATE, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_BITS,
    OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PKEY_PARAM_ML_DSA_PREFER_SEED,
    OSSL_PKEY_PARAM_ML_DSA_RETAIN_SEED, OSSL_PKEY_PARAM_ML_DSA_SEED, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PROPERTIES, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
    PROV_R_FAILED_TO_GENERATE_KEY, PROV_R_INVALID_KEY, PROV_R_INVALID_KEY_LENGTH,
    PROV_R_INVALID_SEED_LENGTH, PROV_R_MISSING_KEY,
};
use rustyssl_crypto::mldsa::{self, PrivateKey, PublicKey, SEED_BYTES, Variant};

use super::Ptr;
use super::builtin::{conf_bool, libctx_of};
use super::macs::{boxed, context, locate, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ecx::digest_available;
use crate::err;
use crate::ffi::{bytes, ffi_callback};
use crate::mem::CRYPTO_memcmp;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_octet_string,
    OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_utf8_string, OSSL_PARAM_locate,
    OSSL_PARAM_set_int, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string,
};
use crate::rand_lib::RAND_priv_bytes_ex;

const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
const INT_SIZE: usize = size_of::<c_int>();

/// `ML_DSA_KEY_PREFER_SEED`.
const PREFER_SEED: c_int = 1;
/// `ML_DSA_KEY_RETAIN_SEED`.
const RETAIN_SEED: c_int = 2;
/// `ML_DSA_KEY_PROV_FLAGS_DEFAULT`.
const FLAGS_DEFAULT: c_int = PREFER_SEED | RETAIN_SEED;

/// What a key holds: nothing yet, a public key, or a private key (with its public key).
pub(crate) enum Material {
    Empty,
    Public(PublicKey),
    Private(PrivateKey),
}

impl Material {
    /// The public key, if there is one.
    pub(crate) fn public(&self) -> Option<&PublicKey> {
        match self {
            Self::Empty => None,
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

/// `ML_DSA_KEY`: a variant's key, immutable once it has key material.
pub(crate) struct MlDsaKey {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    pub(crate) variant: Variant,
    /// The `ML_DSA_KEY_*` flags.
    flags: c_int,
    material: Mutex<Material>,
}

impl MlDsaKey {
    /// The key material.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Material> {
        self.material.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The key behind key data.
///
/// # Safety
/// `keydata` is NULL or key data from one of these key managers.
pub(crate) unsafe fn key<'a>(keydata: *const c_void) -> Option<&'a MlDsaKey> {
    // SAFETY: the caller's guarantee.
    unsafe { keydata.cast::<MlDsaKey>().as_ref() }
}

/// `ossl_prov_ml_dsa_new`: an empty key, once SHAKE-128 and SHAKE-256 can be fetched with
/// `propq`, with the flags the provider's configuration sets, as key data.
///
/// # Safety
/// `provctx` is the default provider's context.
unsafe fn prov_new(provctx: *mut c_void, propq: Option<&CStr>, variant: Variant) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(provctx) };
    let fetched = [c"SHAKE-128", c"SHAKE-256"].map(|name| digest_available(libctx, name, propq));
    if fetched.contains(&false) {
        return ptr::null_mut();
    }
    let mut flags = FLAGS_DEFAULT;
    // SAFETY: as above, for each.
    if unsafe { conf_bool(provctx, OSSL_PKEY_PARAM_ML_DSA_RETAIN_SEED, true) } {
        flags |= RETAIN_SEED;
    } else {
        flags &= !RETAIN_SEED;
    }
    // SAFETY: as above.
    if unsafe { conf_bool(provctx, OSSL_PKEY_PARAM_ML_DSA_PREFER_SEED, true) } {
        flags |= PREFER_SEED;
    } else {
        flags &= !PREFER_SEED;
    }
    boxed(MlDsaKey {
        libctx: Ptr(libctx),
        variant,
        flags,
        material: Mutex::new(Material::Empty),
    })
}

/// `ossl_ml_dsa_generate_key` from `seed` (random if `None`), keeping the seed if the key's
/// flags say so, and checking the key against `sk` if one is given.
fn generate(
    k: &MlDsaKey,
    seed: Option<&[u8; SEED_BYTES]>,
    sk: Option<&[u8]>,
) -> Option<PrivateKey> {
    let mut drawn = [0u8; SEED_BYTES];
    let seed = match seed {
        Some(s) => s,
        None => {
            // SAFETY: the key's library context; room for a seed.
            if unsafe { RAND_priv_bytes_ex(k.libctx.0, drawn.as_mut_ptr(), SEED_BYTES, 0) } <= 0 {
                return None;
            }
            &drawn
        }
    };
    let generated = PrivateKey::generate(k.variant, seed);
    wipe(&mut drawn);
    let mut p = generated?;
    if k.flags & RETAIN_SEED == 0 {
        p.forget_seed();
    }
    if let Some(sk) = sk
        && p.encoding() != sk
    {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_INVALID_KEY,
            "ossl_ml_dsa_generate_key",
            &format!(
                "explicit {} private key does not match seed",
                k.variant.name()
            ),
        );
        return None;
    }
    Some(p)
}

ffi_callback! {
    /// `ml_dsa_has`: always for no key part; else the public key, and the private key if
    /// selected.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ml_dsa_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 1;
        }
        let m = k.lock();
        c_int::from(m.public().is_some() && (selection & PRIVATE == 0 || m.private().is_some()))
    }
}

ffi_callback! {
    /// `ml_dsa_match` (`ossl_ml_dsa_key_equal`): the same variant, and for the key pair, the
    /// public keys if both have one, else the private keys if selected and both have one.
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are NULL or live key data.
    pub(crate) unsafe extern "C" fn ml_dsa_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let (Some(k1), Some(k2)) = (unsafe { key(keydata1) }, unsafe { key(keydata2) }) else {
            return 0;
        };
        if k1.variant != k2.variant {
            return 0;
        }
        if selection & KEYPAIR == 0 {
            return 1;
        }
        let (pub1, prv1) = {
            let m = k1.lock();
            (m.public().map(|p| p.encode().to_vec()), m.private().map(|p| p.encoding().to_vec()))
        };
        let (pub2, prv2) = {
            let m = k2.lock();
            (m.public().map(|p| p.encode().to_vec()), m.private().map(|p| p.encoding().to_vec()))
        };
        let mut checked = false;
        let mut ok = true;
        if selection & PUBLIC != 0
            && let (Some(a), Some(b)) = (&pub1, &pub2)
        {
            ok = a == b;
            checked = true;
        }
        if ok
            && !checked
            && selection & PRIVATE != 0
            && let (Some(a), Some(b)) = (&prv1, &prv2)
        {
            // SAFETY: two buffers of the variant's private key length.
            ok = a.len() == b.len() && unsafe { CRYPTO_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) } == 0;
            checked = true;
        }
        for mut v in [prv1, prv2].into_iter().flatten() {
            wipe(&mut v);
        }
        c_int::from(ok && checked)
    }
}

ffi_callback! {
    /// `ml_dsa_validate`: the parts the selection names, and for the pair, that the private key
    /// makes the public key.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ml_dsa_validate(keydata: *const c_void, selection: c_int, _checktype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { ml_dsa_has(keydata, selection) } == 0 {
            return 0;
        }
        if selection & KEYPAIR != KEYPAIR {
            return 1;
        }
        // SAFETY: as above.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        let m = k.lock();
        c_int::from(m.private().is_some_and(|p| p.pairwise(p.public())))
    }
}

/// An octet-string parameter's octets (`OSSL_PARAM_get_octet_string_ptr`): `Err` if it isn't
/// one, else whether its data is NULL, and the octets.
fn octets_ptr(p: &OSSL_PARAM) -> Result<(bool, &[u8]), ()> {
    let mut data: *const c_void = ptr::null();
    let mut len = 0;
    // SAFETY: a parameter; places for the pointer and length.
    if unsafe { OSSL_PARAM_get_octet_string_ptr(p, &raw mut data, &raw mut len) } != 1 {
        return Err(());
    }
    // SAFETY: the parameter's own octets, which outlive the call.
    let v = unsafe { bytes(data.cast::<u8>(), len) }.ok_or(())?;
    Ok((data.is_null(), v))
}

/// `ml_dsa_key_fromdata`: a public key, and (if `include_private`) a seed (made into the key)
/// or a private key; a given public key must be the key's.
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn key_fromdata(k: &MlDsaKey, params: *const OSSL_PARAM, include_private: bool) -> bool {
    const F: &str = "ml_dsa_key_fromdata";
    let v = k.variant;
    let name = v.name();
    let given = |name: &CStr| -> Result<Option<&[u8]>, ()> {
        // SAFETY: the caller's array; a static name.
        match unsafe { locate(params, name) } {
            None => Ok(None),
            Some(p) => octets_ptr(p).map(|(null, b)| (!null).then_some(b)),
        }
    };
    let Ok(pk) = given(OSSL_PKEY_PARAM_PUB_KEY) else {
        return false;
    };
    if pk.is_some_and(|pk| pk.len() != v.public_key_bytes()) {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_INVALID_KEY_LENGTH,
            F,
            &format!("Invalid {name} public key length"),
        );
        return false;
    }
    let (mut seed, mut sk) = (None, None);
    if include_private {
        let Ok(s) = given(OSSL_PKEY_PARAM_ML_DSA_SEED) else {
            return false;
        };
        if s.is_some_and(|s| s.len() != SEED_BYTES) {
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH, F);
            return false;
        }
        seed = s;
        let Ok(s) = given(OSSL_PKEY_PARAM_PRIV_KEY) else {
            return false;
        };
        if s.is_some_and(|s| s.len() != v.private_key_bytes()) {
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_INVALID_KEY_LENGTH,
                F,
                &format!("Invalid {name} private key length"),
            );
            return false;
        }
        sk = s;
    }
    let (seed, sk, pk) = (
        seed.filter(|s| !s.is_empty()),
        sk.filter(|s| !s.is_empty()),
        pk.filter(|s| !s.is_empty()),
    );
    if seed.is_none() && sk.is_none() && pk.is_none() {
        err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
        return false;
    }
    if k.lock().public().is_some() {
        return false;
    }
    let material = if let Some(seed) = seed.filter(|_| sk.is_none() || k.flags & PREFER_SEED != 0) {
        let Ok(seed) = <&[u8; SEED_BYTES]>::try_from(seed) else {
            return false;
        };
        let Some(p) = generate(k, Some(seed), sk) else {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY, F);
            return false;
        };
        Material::Private(p)
    } else if let Some(sk) = sk {
        match PrivateKey::parse(v, sk) {
            Ok(p) => Material::Private(p),
            Err(mldsa::Error::Mismatch) => {
                err::raise_with_text(
                    ERR_LIB_PROV,
                    PROV_R_INVALID_KEY,
                    "ossl_ml_dsa_sk_decode",
                    &format!("{name} private key does not match its pubkey part"),
                );
                return false;
            }
            Err(_) => return false,
        }
    } else if let Some(pk) = pk {
        match PublicKey::parse(v, pk) {
            Ok(p) => Material::Public(p),
            Err(_) => return false,
        }
    } else {
        return false;
    };
    if let (Some(pk), true) = (pk, seed.is_some() || sk.is_some())
        && material.public().is_some_and(|p| p.encode() != pk)
    {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_INVALID_KEY,
            F,
            &format!("explicit {name} public key does not match private"),
        );
        return false;
    }
    *k.lock() = material;
    true
}

ffi_callback! {
    /// `ml_dsa_import`: the key pair (which must be selected).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_dsa_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 0;
        }
        // SAFETY: the caller's array.
        c_int::from(unsafe { key_fromdata(k, params, selection & PRIVATE != 0) })
    }
}

ffi_callback! {
    /// `ml_dsa_export`: the seed and private key (if selected and present), and the public key
    /// (if selected and present); nothing to export fails.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` is called with `cbarg`.
    pub(crate) unsafe extern "C" fn ml_dsa_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 0;
        }
        let (mut seed, mut private, public) = {
            let m = k.lock();
            let (seed, private) = match m.private() {
                Some(p) if selection & PRIVATE != 0 => (p.seed().map(|s| s.to_vec()), Some(p.encoding().to_vec())),
                _ => (None, None),
            };
            let public = (selection & PUBLIC != 0).then(|| m.public().map(|p| p.encode().to_vec())).flatten();
            (seed, private, public)
        };
        let mut params = Vec::with_capacity(4);
        // The parameters point into the copies, which outlive the callback.
        let mut public = public;
        for (name, v) in [
            (OSSL_PKEY_PARAM_ML_DSA_SEED, seed.as_mut()),
            (OSSL_PKEY_PARAM_PRIV_KEY, private.as_mut()),
            (OSSL_PKEY_PARAM_PUB_KEY, public.as_mut()),
        ] {
            if let Some(v) = v {
                // SAFETY: a static name; octets that outlive the array.
                params.push(unsafe { OSSL_PARAM_construct_octet_string(name.as_ptr(), v.as_mut_ptr().cast(), v.len()) });
            }
        }
        let mut ret = 0;
        if !params.is_empty() {
            // SAFETY: no preconditions.
            params.push(unsafe { OSSL_PARAM_construct_end() });
            if let Some(cb) = param_cb {
                // SAFETY: the caller's callback and argument; the array, alive until after.
                ret = unsafe { cb(params.as_ptr(), cbarg) };
            }
        }
        for v in [seed.as_mut(), private.as_mut()].into_iter().flatten() {
            wipe(v);
        }
        ret
    }
}

/// `ml_dsa_imexport_types`' list.
static KEY_TYPES: Params<4> = Params([
    defn(OSSL_PKEY_PARAM_ML_DSA_SEED, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_dsa_imexport_types`.
    pub(crate) unsafe extern "C" fn ml_dsa_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        if selection & KEYPAIR != 0 { KEY_TYPES.0.as_ptr() } else { ptr::null() }
    }
}

ffi_callback! {
    /// `ml_dsa_get_params`: the bits (eight times the public key's length), security bits, and
    /// largest signature; the seed, private key, and public key, each if the key has it; and an
    /// empty mandatory digest.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_dsa_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        let v = k.variant;
        let ints = [
            (OSSL_PKEY_PARAM_BITS, v.public_key_bytes().saturating_mul(8)),
            (OSSL_PKEY_PARAM_SECURITY_BITS, usize::try_from(v.lambda()).unwrap_or(0)),
            (OSSL_PKEY_PARAM_MAX_SIZE, v.signature_bytes()),
        ];
        for (name, value) in ints {
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            // SAFETY: a parameter of the array.
            if !p.is_null() && unsafe { OSSL_PARAM_set_int(p, c_int::try_from(value).unwrap_or(c_int::MAX)) } == 0 {
                return 0;
            }
        }
        let (mut seed, mut private, public) = {
            let m = k.lock();
            (
                m.private().and_then(PrivateKey::seed).map(|s| s.to_vec()),
                m.private().map(|p| p.encoding().to_vec()),
                m.public().map(|p| p.encode().to_vec()),
            )
        };
        let mut ok = true;
        for (name, v) in [
            (OSSL_PKEY_PARAM_ML_DSA_SEED, seed.as_deref()),
            (OSSL_PKEY_PARAM_PRIV_KEY, private.as_deref()),
            (OSSL_PKEY_PARAM_PUB_KEY, public.as_deref()),
        ] {
            let Some(v) = v else { continue };
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            // SAFETY: a parameter of the array; the octets.
            if !p.is_null() && unsafe { OSSL_PARAM_set_octet_string(p, v.as_ptr().cast(), v.len()) } == 0 {
                ok = false;
                break;
            }
        }
        for v in [seed.as_mut(), private.as_mut()].into_iter().flatten() {
            wipe(v);
        }
        if !ok {
            return 0;
        }
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST.as_ptr()) };
        // SAFETY: a parameter of the array; a static string.
        c_int::from(p.is_null() || unsafe { OSSL_PARAM_set_utf8_string(p, c"".as_ptr()) } != 0)
    }
}

/// `ml_dsa_gettable_params`' list.
static GETTABLE: Params<8> = Params([
    defn(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_ML_DSA_SEED, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_dsa_gettable_params`.
    pub(crate) unsafe extern "C" fn ml_dsa_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

/// `struct ml_dsa_gen_ctx`.
struct GenCtx {
    provctx: *mut c_void,
    propq: Option<CString>,
    /// The seed (of any length up to 32; empty for none), kept for every generation.
    entropy: [u8; SEED_BYTES],
    entropy_len: usize,
}

impl Drop for GenCtx {
    fn drop(&mut self) {
        wipe(&mut self.entropy);
    }
}

ffi_callback! {
    /// `ml_dsa_gen_set_params`: a seed of at most 32 octets, and the properties.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_dsa_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_ML_DSA_SEED) } {
            let mut out = g.entropy.as_mut_ptr().cast::<c_void>();
            // SAFETY: the parameter; the context's room for a seed.
            if unsafe { OSSL_PARAM_get_octet_string(p, &raw mut out, SEED_BYTES, &raw mut g.entropy_len) } == 0 {
                g.entropy_len = 0;
                return 0;
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PROPERTIES) } {
            g.propq = None;
            let mut s: *mut c_char = ptr::null_mut();
            // SAFETY: the parameter; a place for a new string.
            if unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, 0) } == 0 {
                return 0;
            }
            // SAFETY: the string just made.
            g.propq = Some(unsafe { CStr::from_ptr(s) }.to_owned());
            // SAFETY: the string just made, freed once.
            unsafe { crate::mem::CRYPTO_free(s.cast(), c"".as_ptr(), 0) };
        }
        1
    }
}

/// `ml_dsa_gen_settable_params`' list.
static GEN_SETTABLE: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_ML_DSA_SEED, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `ml_dsa_gen_settable_params`.
    pub(crate) unsafe extern "C" fn ml_dsa_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `ml_dsa_gen_init`: a generation context, whatever the selection.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn ml_dsa_gen_init(provctx: *mut c_void, _selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        let g = boxed(GenCtx { provctx, propq: None, entropy: [0; SEED_BYTES], entropy_len: 0 });
        // SAFETY: the context just made; the caller's array.
        if unsafe { ml_dsa_gen_set_params(g, params) } == 0 {
            // SAFETY: the context just made, freed once.
            unsafe { unbox::<GenCtx>(g) };
            return ptr::null_mut();
        }
        g
    }
}

/// `ml_dsa_gen`: a key from the context's seed (failing without an error for one that isn't
/// 32 octets) or a random one.
///
/// # Safety
/// `genctx` is NULL or a live generation context.
unsafe fn gen_key(genctx: *mut c_void, variant: Variant) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else {
        return ptr::null_mut();
    };
    // SAFETY: the context's provider context.
    let h = unsafe { prov_new(g.provctx, g.propq.as_deref(), variant) };
    // SAFETY: the key just made, or NULL.
    let Some(k) = (unsafe { key(h) }) else {
        return ptr::null_mut();
    };
    let seed = match g.entropy_len {
        0 => None,
        SEED_BYTES => Some(&g.entropy),
        _ => {
            // SAFETY: the key made above, freed once.
            unsafe { unbox::<MlDsaKey>(h) };
            return ptr::null_mut();
        }
    };
    let Some(p) = generate(k, seed, None) else {
        err::raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY, "ml_dsa_gen");
        // SAFETY: as above.
        unsafe { unbox::<MlDsaKey>(h) };
        return ptr::null_mut();
    };
    *k.lock() = Material::Private(p);
    h
}

ffi_callback! {
    /// `ml_dsa_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn ml_dsa_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

ffi_callback! {
    /// `ml_dsa_load`: the key the reference points to, the reference cleared.
    ///
    /// # Safety
    /// `reference` is NULL or points to `reference_sz` writable octets holding live key data's
    /// pointer.
    pub(crate) unsafe extern "C" fn ml_dsa_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
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
        h
    }
}

ffi_callback! {
    /// `ml_dsa_dup_key` (`ossl_ml_dsa_key_dup`): for the key pair, the public key and, if
    /// selected, the private key and seed.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn ml_dsa_dup_key(keydata: *const c_void, selection: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return ptr::null_mut() };
        let material = {
            let m = k.lock();
            if selection & KEYPAIR == 0 {
                Material::Empty
            } else {
                match (&*m, selection & PRIVATE != 0) {
                    (Material::Private(p), true) => Material::Private(p.clone()),
                    _ => m.public().cloned().map_or(Material::Empty, Material::Public),
                }
            }
        };
        boxed(MlDsaKey {
            libctx: k.libctx,
            variant: k.variant,
            flags: k.flags,
            material: Mutex::new(material),
        })
    }
}

ffi_callback! {
    /// `ml_dsa_free_key`.
    ///
    /// # Safety
    /// `keydata` is NULL or key data the caller gives up.
    pub(crate) unsafe extern "C" fn ml_dsa_free_key(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<MlDsaKey>(keydata) };
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

/// `MAKE_KEYMGMT_FUNCTIONS`: one variant's functions and dispatch table.
macro_rules! ml_dsa_keymgmt {
    ($table:ident, $variant:expr, $new:ident, $gen:ident) => {
        ffi_callback! {
            /// The variant's `ml_dsa_*_new_key`.
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
            /// The variant's `ml_dsa_*_gen`.
            ///
            /// # Safety
            /// `genctx` is NULL or a live generation context.
            pub(crate) unsafe extern "C" fn $gen(genctx: *mut c_void, _cb: OSSL_CALLBACK, _cbarg: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { gen_key(genctx, $variant) }
            }
        }
        /// `ossl_ml_dsa_*_keymgmt_functions`.
        pub(crate) static $table: Dispatch<19> = Dispatch([
            entry!(OSSL_FUNC_KEYMGMT_NEW, $new, NewFn),
            entry!(OSSL_FUNC_KEYMGMT_FREE, ml_dsa_free_key, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_HAS, ml_dsa_has, HasFn),
            entry!(OSSL_FUNC_KEYMGMT_MATCH, ml_dsa_match, MatchFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT, ml_dsa_import, ImportFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, ml_dsa_imexport_types, TypesFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT, ml_dsa_export, ExportFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, ml_dsa_imexport_types, TypesFn),
            entry!(OSSL_FUNC_KEYMGMT_LOAD, ml_dsa_load, LoadFn),
            entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, ml_dsa_get_params, GetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, ml_dsa_gettable_params, ListFn),
            entry!(OSSL_FUNC_KEYMGMT_VALIDATE, ml_dsa_validate, ValidateFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, ml_dsa_gen_init, GenInitFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN, $gen, GenFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, ml_dsa_gen_cleanup, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, ml_dsa_gen_set_params, SetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, ml_dsa_gen_settable_params, GenListFn),
            entry!(OSSL_FUNC_KEYMGMT_DUP, ml_dsa_dup_key, DupFn),
            END,
        ]);
    };
}

ml_dsa_keymgmt!(
    ML_DSA_44_KEYMGMT,
    Variant::MlDsa44,
    ml_dsa_44_new_key,
    ml_dsa_44_gen
);
ml_dsa_keymgmt!(
    ML_DSA_65_KEYMGMT,
    Variant::MlDsa65,
    ml_dsa_65_new_key,
    ml_dsa_65_gen
);
ml_dsa_keymgmt!(
    ML_DSA_87_KEYMGMT,
    Variant::MlDsa87,
    ml_dsa_87_new_key,
    ml_dsa_87_gen
);
