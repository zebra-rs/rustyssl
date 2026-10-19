//! The default provider's twelve SLH-DSA key managers (`slh_dsa_kmgmt.c`, with
//! `slh_dsa_key.c`'s key handling over `rustyssl_crypto::slhdsa`): keys made empty (once the
//! parameter set's digests, and HMAC for SHA-2, can be fetched), imported from a private key
//! (`4n` octets, or `2n` with a separate public key) or a public key (`2n`), exported,
//! described (sizes, strength, the keys, an empty mandatory digest), compared, copied by
//! selection, validated (the pair recomputes the root), and generated (from the context's
//! `SK.seed || SK.prf || PK.seed`, or random).
//!
//! As in OpenSSL, keys are taken as given (only validation checks them), an import that fails
//! after its private key was read leaves the key empty, a public key imported into a key with a
//! private key keeps the private half, and a generation seed of the wrong length is taken by
//! the parameters and then fails the generation without an error.

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
    OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PROPERTIES, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
    OSSL_PKEY_PARAM_SECURITY_CATEGORY, OSSL_PKEY_PARAM_SLH_DSA_SEED,
};
use rustyssl_crypto::slhdsa::{MAX_N, PrivateKey, PublicKey, Variant};

use super::Ptr;
use super::builtin::libctx_of;
use super::macs::{boxed, context, locate, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::ecx::digest_available;
use crate::evp::mac::{EVP_MAC_fetch, EVP_MAC_free};
use crate::ffi::ffi_callback;
use crate::mem::CRYPTO_memcmp;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_get_octet_string,
    OSSL_PARAM_locate, OSSL_PARAM_set_int, OSSL_PARAM_set_octet_string, OSSL_PARAM_set_utf8_string,
};
use crate::rand_lib::{RAND_bytes_ex, RAND_priv_bytes_ex};

const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
const INT_SIZE: usize = size_of::<c_int>();

/// What a key holds: nothing, a public key, or a private key (with its public key).
pub(crate) enum Material {
    Empty,
    Public(PublicKey),
    Private(PrivateKey),
}

impl Material {
    /// The public key's encoding, if there is one.
    pub(crate) fn public(&self) -> Option<PublicKey> {
        match self {
            Self::Empty => None,
            Self::Public(p) => Some(p.clone()),
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

/// `SLH_DSA_KEY`: a parameter set's key.
pub(crate) struct SlhDsaKey {
    pub(crate) libctx: Ptr<OSSL_LIB_CTX>,
    pub(crate) variant: Variant,
    material: Mutex<Material>,
}

impl SlhDsaKey {
    /// The key material.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Material> {
        self.material.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The key behind key data.
///
/// # Safety
/// `keydata` is NULL or key data from one of these key managers.
pub(crate) unsafe fn key<'a>(keydata: *const c_void) -> Option<&'a SlhDsaKey> {
    // SAFETY: the caller's guarantee.
    unsafe { keydata.cast::<SlhDsaKey>().as_ref() }
}

/// `slh_dsa_key_hash_init`'s fetches: SHAKE-256, or SHA2-256 (and SHA2-512 for categories 3
/// and 5) and HMAC, with `propq`.
fn hashes_available(libctx: *mut OSSL_LIB_CTX, variant: Variant, propq: Option<&CStr>) -> bool {
    if variant.is_shake() {
        return digest_available(libctx, c"SHAKE-256", propq);
    }
    if !digest_available(libctx, c"SHA2-256", propq)
        || (variant.security_category() != 1 && !digest_available(libctx, c"SHA2-512", propq))
    {
        return false;
    }
    let q = propq.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: a library context; a static name; a query or NULL.
    let mac = unsafe { EVP_MAC_fetch(libctx, c"HMAC".as_ptr(), q) };
    if mac.is_null() {
        return false;
    }
    // SAFETY: the reference fetched above.
    unsafe { EVP_MAC_free(mac) };
    true
}

/// `ossl_slh_dsa_key_new`: an empty key, once its hashes can be fetched with `propq`.
fn new_key(libctx: *mut OSSL_LIB_CTX, propq: Option<&CStr>, variant: Variant) -> *mut c_void {
    if !hashes_available(libctx, variant, propq) {
        return ptr::null_mut();
    }
    boxed(SlhDsaKey {
        libctx: Ptr(libctx),
        variant,
        material: Mutex::new(Material::Empty),
    })
}

ffi_callback! {
    /// `slh_dsa_has`: always for no key part; else the public key, and the private key if
    /// selected.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn slh_dsa_has(keydata: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 1;
        }
        let m = k.lock();
        c_int::from(!matches!(*m, Material::Empty) && (selection & PRIVATE == 0 || m.private().is_some()))
    }
}

ffi_callback! {
    /// `slh_dsa_match` (`ossl_slh_dsa_key_equal`): the same parameter set, and for the key pair,
    /// the public keys if both have one, else (if selected) the private keys' first `2n` octets
    /// if both have one.
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are NULL or live key data.
    pub(crate) unsafe extern "C" fn slh_dsa_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
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
        let half = k1.variant.public_key_bytes();
        let parts = |k: &SlhDsaKey| {
            let m = k.lock();
            let public = m.public().map(|p| p.encoding().to_vec());
            let private = m.private().map(|p| p.encoding().get(..half).unwrap_or_default().to_vec());
            (public, private)
        };
        let (pub1, prv1) = parts(k1);
        let (pub2, prv2) = parts(k2);
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
            // SAFETY: two buffers of `2n` octets.
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
    /// `slh_dsa_validate`: the parts the selection names, and for the pair, that the seeds make
    /// the root.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn slh_dsa_validate(keydata: *const c_void, selection: c_int, _checktype: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if unsafe { slh_dsa_has(keydata, selection) } == 0 {
            return 0;
        }
        if selection & KEYPAIR != KEYPAIR {
            return 1;
        }
        // SAFETY: as above.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        let private = k.lock().private().cloned();
        c_int::from(private.is_some_and(|p| p.pairwise()))
    }
}

/// An octet-string parameter read into `buf` (at most its length): `None` if
/// `OSSL_PARAM_get_octet_string` fails, else the length read.
///
/// # Safety
/// `p` is a parameter of a live array.
unsafe fn read_octets(p: *const OSSL_PARAM, buf: &mut [u8]) -> Option<usize> {
    let mut out = buf.as_mut_ptr().cast::<c_void>();
    let mut len = 0;
    // SAFETY: the caller's parameter; the buffer's room.
    (unsafe { OSSL_PARAM_get_octet_string(p, &raw mut out, buf.len(), &raw mut len) } == 1)
        .then_some(len)
}

/// `ossl_slh_dsa_key_fromdata`: a private key of `4n` octets (a public key ignored), or of `2n`
/// with a public key of `2n`, or (without a private key) a public key, which keeps any private
/// half the key had. A private key that can't be read fails with the key as it was; any other
/// failure leaves it empty.
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn key_fromdata(k: &SlhDsaKey, params: *const OSSL_PARAM, include_private: bool) -> bool {
    let v = k.variant;
    let half = v.public_key_bytes();
    let mut buf = [0u8; 4 * MAX_N];
    let mut secret = None;
    // SAFETY: the caller's array; a static name.
    let priv_param = include_private
        .then(|| unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) })
        .flatten();
    if let Some(p) = priv_param {
        let room = buf.get_mut(..v.private_key_bytes()).unwrap_or_default();
        // SAFETY: a parameter of the array.
        let Some(len) = (unsafe { read_octets(p, room) }) else {
            return false;
        };
        if len == v.private_key_bytes() {
            let key = PrivateKey::from_bytes(v, room);
            wipe(&mut buf);
            let Some(key) = key else { return false };
            *k.lock() = Material::Private(key);
            return true;
        }
        if len != half {
            wipe(&mut buf);
            *k.lock() = Material::Empty;
            return false;
        }
        secret = Some(());
    }
    let mut m = k.lock();
    let (sk, pk) = buf.split_at_mut(half);
    let kept = if secret.is_some() {
        true
    } else if let Some(p) = m.private() {
        // The key's private half, kept.
        sk.copy_from_slice(p.encoding().get(..half).unwrap_or_default());
        true
    } else {
        false
    };
    // SAFETY: the caller's array; a static name.
    let read = unsafe { locate(params, OSSL_PKEY_PARAM_PUB_KEY) }
        // SAFETY: a parameter of the array.
        .and_then(|p| unsafe { read_octets(p, pk.get_mut(..half).unwrap_or_default()) });
    let material = match read {
        Some(len) if len == half => {
            let pk = pk.get(..half).unwrap_or_default();
            if kept {
                buf.get(..v.private_key_bytes())
                    .and_then(|b| PrivateKey::from_bytes(v, b))
                    .map(Material::Private)
            } else {
                PublicKey::from_bytes(v, pk).map(Material::Public)
            }
        }
        _ => None,
    };
    wipe(&mut buf);
    let ok = material.is_some();
    *m = material.unwrap_or(Material::Empty);
    ok
}

ffi_callback! {
    /// `slh_dsa_import`: the key pair (which must be selected).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn slh_dsa_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::SLH_DSA_IMPORT) } {
            return 0;
        }
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
    /// `slh_dsa_export`: for a key with a public key, the private key (if selected and present)
    /// and the public key (if selected), even none.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` is called with `cbarg`.
    pub(crate) unsafe extern "C" fn slh_dsa_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 0;
        }
        let (mut private, mut public) = {
            let m = k.lock();
            let Some(public) = m.public() else { return 0 };
            let private = (selection & PRIVATE != 0).then(|| m.private().map(|p| p.encoding().to_vec())).flatten();
            (private, (selection & PUBLIC != 0).then(|| public.encoding().to_vec()))
        };
        let mut params = Vec::with_capacity(3);
        for (name, v) in [(OSSL_PKEY_PARAM_PRIV_KEY, private.as_mut()), (OSSL_PKEY_PARAM_PUB_KEY, public.as_mut())] {
            if let Some(v) = v {
                // SAFETY: a static name; octets that outlive the array.
                params.push(unsafe { OSSL_PARAM_construct_octet_string(name.as_ptr(), v.as_mut_ptr().cast(), v.len()) });
            }
        }
        // SAFETY: no preconditions.
        params.push(unsafe { OSSL_PARAM_construct_end() });
        let mut ret = 0;
        if let Some(cb) = param_cb {
            // SAFETY: the caller's callback and argument; the array, alive until after.
            ret = unsafe { cb(params.as_ptr(), cbarg) };
        }
        if let Some(v) = private.as_mut() {
            wipe(v);
        }
        ret
    }
}

/// `slh_dsa_key_types`.
static KEY_TYPES: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `slh_dsa_imexport_types`.
    pub(crate) unsafe extern "C" fn slh_dsa_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        if selection & KEYPAIR != 0 { KEY_TYPES.0.as_ptr() } else { ptr::null() }
    }
}

ffi_callback! {
    /// `slh_dsa_get_params`: the bits (eight times the public key's length), security bits
    /// (eight times `n`), and signature length; the private and public keys, each if the key
    /// has it; and an empty mandatory digest.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn slh_dsa_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::SLH_DSA_GET_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        let v = k.variant;
        let ints = [
            (OSSL_PKEY_PARAM_BITS, v.public_key_bytes().saturating_mul(8)),
            (OSSL_PKEY_PARAM_SECURITY_BITS, v.n().saturating_mul(8)),
            (OSSL_PKEY_PARAM_MAX_SIZE, v.signature_bytes()),
            (
                OSSL_PKEY_PARAM_SECURITY_CATEGORY,
                usize::try_from(v.security_category()).unwrap_or(0),
            ),
        ];
        for (name, value) in ints {
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            // SAFETY: a parameter of the array.
            if !p.is_null() && unsafe { OSSL_PARAM_set_int(p, c_int::try_from(value).unwrap_or(c_int::MAX)) } == 0 {
                return 0;
            }
        }
        let (mut private, public) = {
            let m = k.lock();
            (m.private().map(|p| p.encoding().to_vec()), m.public().map(|p| p.encoding().to_vec()))
        };
        let mut ok = true;
        for (name, v) in [(OSSL_PKEY_PARAM_PRIV_KEY, private.as_deref()), (OSSL_PKEY_PARAM_PUB_KEY, public.as_deref())] {
            let Some(v) = v else { continue };
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            // SAFETY: a parameter of the array; the octets.
            if !p.is_null() && unsafe { OSSL_PARAM_set_octet_string(p, v.as_ptr().cast(), v.len()) } == 0 {
                ok = false;
                break;
            }
        }
        if let Some(v) = private.as_mut() {
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

/// `slh_dsa_params`.
static GETTABLE: Params<8> = Params([
    defn(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
        OSSL_PARAM_INTEGER,
        INT_SIZE,
    ),
    defn(OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `slh_dsa_gettable_params`.
    pub(crate) unsafe extern "C" fn slh_dsa_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

/// `struct slh_dsa_gen_ctx`.
struct GenCtx {
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
    /// `SK.seed || SK.prf || PK.seed` (any length up to `3 * 32`; empty for none).
    entropy: [u8; 3 * MAX_N],
    entropy_len: usize,
}

impl Drop for GenCtx {
    fn drop(&mut self) {
        wipe(&mut self.entropy);
    }
}

ffi_callback! {
    /// `slh_dsa_gen_set_params`: seeds of at most 96 octets, and the properties (which must be
    /// a UTF-8 string).
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn slh_dsa_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::SLH_DSA_GEN_SET_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_SLH_DSA_SEED) } {
            // SAFETY: a parameter of the array.
            match unsafe { read_octets(p, &mut g.entropy) } {
                Some(len) => g.entropy_len = len,
                None => {
                    g.entropy_len = 0;
                    return 0;
                }
            }
        }
        // SAFETY: as above.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PROPERTIES) } {
            if p.data_type != OSSL_PARAM_UTF8_STRING as u32 {
                return 0;
            }
            g.propq = if p.data.is_null() {
                None
            } else {
                // SAFETY: a UTF-8 string parameter's NUL-terminated data.
                Some(unsafe { CStr::from_ptr(p.data.cast::<c_char>()) }.to_owned())
            };
        }
        1
    }
}

/// `slh_dsa_gen_settable_params`' list.
static GEN_SETTABLE: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    defn(OSSL_PKEY_PARAM_SLH_DSA_SEED, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `slh_dsa_gen_settable_params`.
    pub(crate) unsafe extern "C" fn slh_dsa_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `slh_dsa_gen_init`: a generation context, whatever the selection.
    ///
    /// # Safety
    /// `provctx` is the default provider's context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn slh_dsa_gen_init(provctx: *mut c_void, _selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        let g = boxed(GenCtx {
            // SAFETY: the caller's guarantee.
            libctx: unsafe { libctx_of(provctx) },
            propq: None,
            entropy: [0; 3 * MAX_N],
            entropy_len: 0,
        });
        // SAFETY: the context just made; the caller's array.
        if unsafe { slh_dsa_gen_set_params(g, params) } == 0 {
            // SAFETY: the context just made, freed once.
            unsafe { unbox::<GenCtx>(g) };
            return ptr::null_mut();
        }
        g
    }
}

/// `slh_dsa_gen` (`ossl_slh_dsa_generate_key`): a key from the context's seeds (failing for
/// seeds that aren't `3n` octets) or random ones (`SK.seed` and `SK.prf` private, `PK.seed`
/// public), all without an error.
///
/// # Safety
/// `genctx` is NULL or a live generation context.
unsafe fn gen_key(genctx: *mut c_void, variant: Variant) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else {
        return ptr::null_mut();
    };
    let h = new_key(g.libctx, g.propq.as_deref(), variant);
    // SAFETY: the key just made, or NULL.
    let Some(k) = (unsafe { key(h) }) else {
        return ptr::null_mut();
    };
    let n = variant.n();
    let mut seeds = [0u8; 3 * MAX_N];
    let drawn = if g.entropy_len != 0 {
        if g.entropy_len == n.saturating_mul(3) {
            seeds.copy_from_slice(&g.entropy);
            true
        } else {
            false
        }
    } else {
        let (sk, pk) = seeds.split_at_mut(n.saturating_mul(2));
        // SAFETY: the context's library context; room for `SK.seed || SK.prf`.
        let private = unsafe { RAND_priv_bytes_ex(g.libctx, sk.as_mut_ptr(), sk.len(), 0) } > 0;
        // SAFETY: as above; room for `PK.seed`.
        private && unsafe { RAND_bytes_ex(g.libctx, pk.as_mut_ptr(), n, 0) } > 0
    };
    let generated = drawn
        .then(|| {
            seeds
                .get(..n.saturating_mul(3))
                .and_then(|s| PrivateKey::generate(variant, s))
        })
        .flatten();
    wipe(&mut seeds);
    let Some(p) = generated else {
        // SAFETY: the key made above, freed once.
        unsafe { unbox::<SlhDsaKey>(h) };
        return ptr::null_mut();
    };
    *k.lock() = Material::Private(p);
    h
}

ffi_callback! {
    /// `slh_dsa_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn slh_dsa_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

ffi_callback! {
    /// `slh_dsa_load`: the key the reference points to, the reference cleared.
    ///
    /// # Safety
    /// `reference` is NULL or points to `reference_sz` writable octets holding live key data's
    /// pointer.
    pub(crate) unsafe extern "C" fn slh_dsa_load(reference: *const c_void, reference_sz: usize) -> *mut c_void
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
    /// `slh_dsa_dup_key` (`ossl_slh_dsa_key_dup`): for the key pair, the public key and, if
    /// the private key is selected, the private key.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn slh_dsa_dup_key(keydata: *const c_void, selection: c_int) -> *mut c_void
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
                    _ => m.public().map_or(Material::Empty, Material::Public),
                }
            }
        };
        boxed(SlhDsaKey {
            libctx: k.libctx,
            variant: k.variant,
            material: Mutex::new(material),
        })
    }
}

ffi_callback! {
    /// `slh_dsa_free_key`.
    ///
    /// # Safety
    /// `keydata` is NULL or key data the caller gives up.
    pub(crate) unsafe extern "C" fn slh_dsa_free_key(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<SlhDsaKey>(keydata) };
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

/// `MAKE_KEYMGMT_FUNCTIONS`: one parameter set's functions and dispatch table.
macro_rules! slh_dsa_keymgmt {
    ($table:ident, $variant:expr, $new:ident, $gen:ident) => {
        ffi_callback! {
            /// The parameter set's `slh_dsa_*_new_key`.
            ///
            /// # Safety
            /// `provctx` is the default provider's context.
            pub(crate) unsafe extern "C" fn $new(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                new_key(unsafe { libctx_of(provctx) }, None, $variant)
            }
        }
        ffi_callback! {
            /// The parameter set's `slh_dsa_*_gen`.
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
        /// `ossl_slh_dsa_*_keymgmt_functions`.
        pub(crate) static $table: Dispatch<19> = Dispatch([
            entry!(OSSL_FUNC_KEYMGMT_NEW, $new, NewFn),
            entry!(OSSL_FUNC_KEYMGMT_FREE, slh_dsa_free_key, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_DUP, slh_dsa_dup_key, DupFn),
            entry!(OSSL_FUNC_KEYMGMT_HAS, slh_dsa_has, HasFn),
            entry!(OSSL_FUNC_KEYMGMT_MATCH, slh_dsa_match, MatchFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT, slh_dsa_import, ImportFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, slh_dsa_imexport_types, TypesFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT, slh_dsa_export, ExportFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, slh_dsa_imexport_types, TypesFn),
            entry!(OSSL_FUNC_KEYMGMT_LOAD, slh_dsa_load, LoadFn),
            entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, slh_dsa_get_params, GetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, slh_dsa_gettable_params, ListFn),
            entry!(OSSL_FUNC_KEYMGMT_VALIDATE, slh_dsa_validate, ValidateFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, slh_dsa_gen_init, GenInitFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN, $gen, GenFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, slh_dsa_gen_cleanup, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, slh_dsa_gen_set_params, SetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, slh_dsa_gen_settable_params, GenListFn),
            END,
        ]);
    };
}

slh_dsa_keymgmt!(
    SHA2_128S_KEYMGMT,
    Variant::Sha2_128s,
    slh_dsa_sha2_128s_new_key,
    slh_dsa_sha2_128s_gen
);
slh_dsa_keymgmt!(
    SHA2_128F_KEYMGMT,
    Variant::Sha2_128f,
    slh_dsa_sha2_128f_new_key,
    slh_dsa_sha2_128f_gen
);
slh_dsa_keymgmt!(
    SHA2_192S_KEYMGMT,
    Variant::Sha2_192s,
    slh_dsa_sha2_192s_new_key,
    slh_dsa_sha2_192s_gen
);
slh_dsa_keymgmt!(
    SHA2_192F_KEYMGMT,
    Variant::Sha2_192f,
    slh_dsa_sha2_192f_new_key,
    slh_dsa_sha2_192f_gen
);
slh_dsa_keymgmt!(
    SHA2_256S_KEYMGMT,
    Variant::Sha2_256s,
    slh_dsa_sha2_256s_new_key,
    slh_dsa_sha2_256s_gen
);
slh_dsa_keymgmt!(
    SHA2_256F_KEYMGMT,
    Variant::Sha2_256f,
    slh_dsa_sha2_256f_new_key,
    slh_dsa_sha2_256f_gen
);
slh_dsa_keymgmt!(
    SHAKE_128S_KEYMGMT,
    Variant::Shake128s,
    slh_dsa_shake_128s_new_key,
    slh_dsa_shake_128s_gen
);
slh_dsa_keymgmt!(
    SHAKE_128F_KEYMGMT,
    Variant::Shake128f,
    slh_dsa_shake_128f_new_key,
    slh_dsa_shake_128f_gen
);
slh_dsa_keymgmt!(
    SHAKE_192S_KEYMGMT,
    Variant::Shake192s,
    slh_dsa_shake_192s_new_key,
    slh_dsa_shake_192s_gen
);
slh_dsa_keymgmt!(
    SHAKE_192F_KEYMGMT,
    Variant::Shake192f,
    slh_dsa_shake_192f_new_key,
    slh_dsa_shake_192f_gen
);
slh_dsa_keymgmt!(
    SHAKE_256S_KEYMGMT,
    Variant::Shake256s,
    slh_dsa_shake_256s_new_key,
    slh_dsa_shake_256s_gen
);
slh_dsa_keymgmt!(
    SHAKE_256F_KEYMGMT,
    Variant::Shake256f,
    slh_dsa_shake_256f_new_key,
    slh_dsa_shake_256f_gen
);

/// `BARE_ALGOR`: an AlgorithmIdentifier that is only its OID.
#[repr(C)]
struct BareAlgor {
    oid: *mut rustyssl_abi::ASN1_OBJECT,
}

/// `BARE_PUBKEY`: a SubjectPublicKeyInfo with a `BARE_ALGOR`.
#[repr(C)]
struct BarePubkey {
    algor: BareAlgor,
    pubkey: *mut rustyssl_abi::ASN1_BIT_STRING,
}

static BARE_ALGOR_TT: crate::asn1::tpl::statics::Templates<1> =
    crate::asn1::tpl::statics::Templates([crate::asn1::tpl::template_at(
        0,
        0,
        core::mem::offset_of!(BareAlgor, oid),
        c"oid",
        crate::asn1::tpl::items::ASN1_OBJECT_it,
    )]);

static BARE_ALGOR: crate::asn1::tpl::Item =
    crate::asn1::tpl::statics::sequence::<BareAlgor, 1>(&BARE_ALGOR_TT, None, c"BARE_ALGOR");

extern "C" fn bare_algor_it() -> *const rustyssl_abi::ASN1_ITEM {
    &raw const BARE_ALGOR.0
}

static BARE_PUBKEY_TT: crate::asn1::tpl::statics::Templates<2> =
    crate::asn1::tpl::statics::Templates([
        crate::asn1::tpl::template_at(
            rustyssl_abi::ASN1_TFLG_EMBED,
            0,
            core::mem::offset_of!(BarePubkey, algor),
            c"algor",
            bare_algor_it,
        ),
        crate::asn1::tpl::template_at(
            0,
            0,
            core::mem::offset_of!(BarePubkey, pubkey),
            c"pubkey",
            crate::asn1::tpl::items::ASN1_BIT_STRING_it,
        ),
    ]);

static BARE_PUBKEY: crate::asn1::tpl::Item =
    crate::asn1::tpl::statics::sequence::<BarePubkey, 2>(&BARE_PUBKEY_TT, None, c"BARE_PUBKEY");

extern "C" fn bare_pubkey_it() -> *const rustyssl_abi::ASN1_ITEM {
    &raw const BARE_PUBKEY.0
}

/// Raises `PROV_R_BAD_ENCODING` from `slh_dsa_d2i_PUBKEY` with `text`.
#[track_caller]
fn bad_encoding(text: &str) {
    crate::err::raise_with_text(
        ERR_LIB_PROV,
        rustyssl_abi::PROV_R_BAD_ENCODING,
        "slh_dsa_d2i_PUBKEY",
        text,
    );
}

/// `slh_dsa_d2i_PUBKEY` (`decode_der2key.c`): a key of the parameter set from a
/// SubjectPublicKeyInfo of exactly its length, with an AlgorithmIdentifier of its OID alone
/// and a BIT STRING of the public key; NULL (with OpenSSL's errors) otherwise.
///
/// # Safety
/// `provctx` is the default provider's context; `propq` is NULL or a string.
pub(crate) unsafe fn d2i_pubkey(
    provctx: *mut c_void,
    propq: Option<&CStr>,
    variant: Variant,
    nid: c_int,
    der: &[u8],
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let libctx = unsafe { libctx_of(provctx) };
    let h = new_key(libctx, propq, variant);
    // SAFETY: the new key data, or NULL.
    let Some(k) = (unsafe { key(h) }) else {
        return ptr::null_mut();
    };
    let name = variant.name();
    let fail = || {
        // SAFETY: made above.
        unsafe { unbox::<SlhDsaKey>(h) };
        ptr::null_mut()
    };
    let len = variant.public_key_bytes();
    if der.len() != 18 + len {
        bad_encoding(&format!(
            "unexpected {name} public key length: {} != {}",
            der.len(),
            18 + len
        ));
        return fail();
    }
    let Ok(dlen) = core::ffi::c_long::try_from(der.len()) else {
        return fail();
    };
    let mut p = der.as_ptr();
    // SAFETY: no preconditions.
    let it = bare_pubkey_it();
    // SAFETY: a new value; the octets; the item.
    let v =
        unsafe { crate::asn1::tpl::decode::ASN1_item_d2i(ptr::null_mut(), &raw mut p, dlen, it) };
    // SAFETY: the decoded structure, or NULL.
    let Some(spki) = (unsafe { v.cast::<BarePubkey>().as_ref() }) else {
        bad_encoding(&format!("malformed {name} public key ASN.1 encoding"));
        return fail();
    };
    let free_spki = || {
        // SAFETY: decoded above, freed once.
        unsafe { crate::asn1::tpl::free::ASN1_item_free(v, it) };
    };
    // SAFETY: the decoded BIT STRING.
    let bits = unsafe { &*spki.pubkey };
    if bits.flags & 0x7 != 0 || p != der.as_ptr().wrapping_add(der.len()) {
        bad_encoding(&format!("malformed {name} public key ASN.1 encoding"));
        free_spki();
        return fail();
    }
    // SAFETY: no preconditions.
    let want = unsafe { crate::objects::OBJ_nid2obj(nid) };
    // SAFETY: the type's object; the decoded one.
    if unsafe { crate::objects::OBJ_cmp(want, spki.algor.oid) } != 0 {
        bad_encoding(&format!(
            "unexpected algorithm OID for an {name} public key"
        ));
        free_spki();
        return fail();
    }
    // SAFETY: the BIT STRING's octets.
    let octets = unsafe { crate::ffi::bytes(bits.data, usize::try_from(bits.length).unwrap_or(0)) };
    let public = octets.and_then(|o| PublicKey::from_bytes(variant, o));
    free_spki();
    let Some(public) = public else {
        bad_encoding(&format!(
            "failed to parse {name} public key from input data"
        ));
        return fail();
    };
    *k.lock() = Material::Public(public);
    h
}

/// `slh_dsa_d2i_PKCS8` (`decode_der2key.c`): a key of the parameter set from a
/// PrivateKeyInfo without parameters whose key octets are its whole private key; NULL
/// otherwise.
///
/// # Safety
/// `provctx` is the default provider's context; `propq` is NULL or a string.
pub(crate) unsafe fn d2i_pkcs8(
    provctx: *mut c_void,
    propq: Option<&CStr>,
    variant: Variant,
    nid: c_int,
    der: &[u8],
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    let Some((octets, ptype, alg)) = (unsafe { super::der2key::p8_parts(der) }) else {
        return ptr::null_mut();
    };
    let name = variant.name();
    (|| {
        if ptype != rustyssl_abi::V_ASN1_UNDEF {
            crate::err::raise_with_text(
                ERR_LIB_PROV,
                rustyssl_abi::PROV_R_UNEXPECTED_KEY_PARAMETERS,
                "slh_dsa_d2i_PKCS8",
                &format!("unexpected parameters with a PKCS#8 {name} private key"),
            );
            return ptr::null_mut();
        }
        if alg != nid {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let libctx = unsafe { libctx_of(provctx) };
        let h = new_key(libctx, propq, variant);
        // SAFETY: the new key data, or NULL.
        let Some(k) = (unsafe { key(h) }) else {
            return ptr::null_mut();
        };
        let Some(private) = PrivateKey::from_bytes(variant, &octets) else {
            // SAFETY: made above.
            unsafe { unbox::<SlhDsaKey>(h) };
            return ptr::null_mut();
        };
        *k.lock() = Material::Private(private);
        h
    })()
}
