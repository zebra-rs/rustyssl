//! The default provider's hybrid ML-KEM key managers (`mlx_kmgmt.c`): X25519MLKEM768,
//! X448MLKEM1024, SecP256r1MLKEM768, and SecP384r1MLKEM1024, each a key pair of ML-KEM and of an
//! ECDH group, held as two `EVP_PKEY`s made through EVP from the same library context and
//! properties.
//!
//! The encodings concatenate the two keys' (ML-KEM's first, except for the NIST curves, whose
//! ECDH key comes first): the public keys, the private keys (ML-KEM's expanded one), and in the
//! KEM the ciphertexts and the secrets. As in OpenSSL, a key is set once (from an import, an
//! encoded public key, or a generation) and never mutated; the private key is read from and
//! written to the components as octet strings, so a NIST curve's (an integer parameter) can be
//! neither imported nor exported; and copies are of no key or the whole pair.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_PROV, ERR_R_INTERNAL_ERROR, EVP_PKEY, OSSL_CALLBACK, OSSL_FUNC_KEYMGMT_DUP,
    OSSL_FUNC_KEYMGMT_EXPORT, OSSL_FUNC_KEYMGMT_EXPORT_TYPES, OSSL_FUNC_KEYMGMT_FREE,
    OSSL_FUNC_KEYMGMT_GEN, OSSL_FUNC_KEYMGMT_GEN_CLEANUP, OSSL_FUNC_KEYMGMT_GEN_INIT,
    OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
    OSSL_FUNC_KEYMGMT_GET_PARAMS, OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, OSSL_FUNC_KEYMGMT_HAS,
    OSSL_FUNC_KEYMGMT_IMPORT, OSSL_FUNC_KEYMGMT_IMPORT_TYPES, OSSL_FUNC_KEYMGMT_MATCH,
    OSSL_FUNC_KEYMGMT_NEW, OSSL_FUNC_KEYMGMT_SET_PARAMS, OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
    OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS, OSSL_KEYMGMT_SELECT_KEYPAIR,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_STRING, OSSL_PARAM_UTF8_STRING, OSSL_PKEY_PARAM_BITS,
    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_MAX_SIZE,
    OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_PROPERTIES, OSSL_PKEY_PARAM_PUB_KEY,
    OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PKEY_PARAM_SECURITY_CATEGORY, PROV_R_INVALID_KEY,
    PROV_R_INVALID_KEY_LENGTH, PROV_R_MISSING_KEY, PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
    PROV_R_OUTPUT_BUFFER_TOO_SMALL, PROV_R_UNSUPPORTED_SELECTION,
};

use super::Ptr;
use super::builtin::libctx_of;
use super::macs::{boxed, context, is_empty, locate, unbox, wipe};
use super::tables::{Dispatch, END, PARAM_END, Params, defn, entry};
use crate::err;
use crate::evp::pkey::{
    EVP_PKEY_dup, EVP_PKEY_eq, EVP_PKEY_export, EVP_PKEY_free, EVP_PKEY_up_ref,
};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_fromdata, EVP_PKEY_fromdata_init,
    quick_keygen,
};
use crate::ffi::{bytes, ffi_callback};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    OSSL_PARAM_get_octet_string, OSSL_PARAM_get_octet_string_ptr, OSSL_PARAM_get_utf8_string,
    OSSL_PARAM_locate, OSSL_PARAM_set_int,
};

const KEYPAIR: c_int = OSSL_KEYMGMT_SELECT_KEYPAIR;
const PUBLIC: c_int = OSSL_KEYMGMT_SELECT_PUBLIC_KEY;
const PRIVATE: c_int = OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
/// `minimal_selection`: what generation needs and what the components are imported with.
const MINIMAL: c_int = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
const INT_SIZE: usize = size_of::<c_int>();

/// `ML_KEM_SHARED_SECRET_BYTES`.
pub(crate) const ML_KEM_SECRET: usize = 32;

/// `ML_KEM_VINFO`'s sizes for the ML-KEM half.
pub(crate) struct MlKemInfo {
    pub(crate) name: &'static CStr,
    pub(crate) pubkey_bytes: usize,
    pub(crate) prvkey_bytes: usize,
    pub(crate) ctext_bytes: usize,
    bits: c_int,
    secbits: c_int,
    /// The ML-KEM parameter set, for its NIST security category.
    variant: rustyssl_crypto::mlkem::Variant,
}

const ML_KEM_768: MlKemInfo = MlKemInfo {
    name: c"ML-KEM-768",
    variant: rustyssl_crypto::mlkem::Variant::MlKem768,
    pubkey_bytes: 1184,
    prvkey_bytes: 2400,
    ctext_bytes: 1088,
    bits: 768,
    secbits: 192,
};
const ML_KEM_1024: MlKemInfo = MlKemInfo {
    name: c"ML-KEM-1024",
    variant: rustyssl_crypto::mlkem::Variant::MlKem1024,
    pubkey_bytes: 1568,
    prvkey_bytes: 3168,
    ctext_bytes: 1568,
    bits: 1024,
    secbits: 256,
};

/// `ECDH_VINFO`: a hybrid's ECDH half and where ML-KEM's goes.
pub(crate) struct Hybrid {
    pub(crate) algorithm_name: &'static CStr,
    pub(crate) group_name: Option<&'static CStr>,
    pub(crate) pubkey_bytes: usize,
    pub(crate) prvkey_bytes: usize,
    pub(crate) shsec_bytes: usize,
    /// 0 when ML-KEM's part comes first, 1 when second.
    pub(crate) ml_kem_slot: usize,
    pub(crate) ml_kem: MlKemInfo,
}

impl Hybrid {
    /// The public key's length: both halves'.
    pub(crate) const fn public_len(&self) -> usize {
        self.ml_kem.pubkey_bytes.saturating_add(self.pubkey_bytes)
    }

    /// The private key's length.
    pub(crate) const fn private_len(&self) -> usize {
        self.ml_kem.prvkey_bytes.saturating_add(self.prvkey_bytes)
    }

    /// The ciphertext's length: ML-KEM's and the ephemeral ECDH public key.
    pub(crate) const fn ciphertext_len(&self) -> usize {
        self.ml_kem.ctext_bytes.saturating_add(self.pubkey_bytes)
    }

    /// The secret's length.
    pub(crate) const fn secret_len(&self) -> usize {
        ML_KEM_SECRET.saturating_add(self.shsec_bytes)
    }

    /// Where ML-KEM's part of an encoding starts, given the ECDH part's length.
    pub(crate) const fn ml_kem_offset(&self, ecdh_len: usize) -> usize {
        if self.ml_kem_slot == 0 { 0 } else { ecdh_len }
    }

    /// Where the ECDH part of an encoding starts, given ML-KEM's part's length.
    pub(crate) const fn ecdh_offset(&self, ml_kem_len: usize) -> usize {
        if self.ml_kem_slot == 0 { ml_kem_len } else { 0 }
    }
}

/// `hybrid_vtable`.
static P256: Hybrid = Hybrid {
    algorithm_name: c"EC",
    group_name: Some(c"P-256"),
    pubkey_bytes: 65,
    prvkey_bytes: 32,
    shsec_bytes: 32,
    ml_kem_slot: 1,
    ml_kem: ML_KEM_768,
};
static P384: Hybrid = Hybrid {
    algorithm_name: c"EC",
    group_name: Some(c"P-384"),
    pubkey_bytes: 97,
    prvkey_bytes: 48,
    shsec_bytes: 48,
    ml_kem_slot: 1,
    ml_kem: ML_KEM_1024,
};
static X25519: Hybrid = Hybrid {
    algorithm_name: c"X25519",
    group_name: None,
    pubkey_bytes: 32,
    prvkey_bytes: 32,
    shsec_bytes: 32,
    ml_kem_slot: 0,
    ml_kem: ML_KEM_768,
};
static X448: Hybrid = Hybrid {
    algorithm_name: c"X448",
    group_name: None,
    pubkey_bytes: 56,
    prvkey_bytes: 56,
    shsec_bytes: 56,
    ml_kem_slot: 0,
    ml_kem: ML_KEM_1024,
};

/// `MLX_HAVE_*`.
const HAVE_NOKEYS: u8 = 0;
const HAVE_PUBKEY: u8 = 1;
const HAVE_PRVKEY: u8 = 2;

/// The key's mutable part, set once.
struct Inner {
    propq: Option<CString>,
    mkey: Ptr<EVP_PKEY>,
    xkey: Ptr<EVP_PKEY>,
    state: u8,
}

impl Inner {
    /// Frees the components (`load_keys`' failure).
    fn clear(&mut self) {
        for k in [&mut self.mkey, &mut self.xkey] {
            // SAFETY: a reference this holds, or NULL.
            unsafe { EVP_PKEY_free(k.0) };
            k.0 = ptr::null_mut();
        }
        self.state = HAVE_NOKEYS;
    }
}

/// `MLX_KEY`.
pub(crate) struct MlxKey {
    libctx: Ptr<OSSL_LIB_CTX>,
    pub(crate) info: &'static Hybrid,
    inner: Mutex<Inner>,
}

impl Drop for MlxKey {
    fn drop(&mut self) {
        self.lock().clear();
    }
}

/// References to a key's components, freed on drop.
pub(crate) struct Components {
    pub(crate) libctx: *mut OSSL_LIB_CTX,
    pub(crate) propq: Option<CString>,
    pub(crate) mkey: *mut EVP_PKEY,
    pub(crate) xkey: *mut EVP_PKEY,
    pub(crate) state: u8,
}

impl Drop for Components {
    fn drop(&mut self) {
        // SAFETY: references taken by `MlxKey::components`, or NULL.
        unsafe { EVP_PKEY_free(self.mkey) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(self.xkey) };
    }
}

impl Components {
    /// The properties, or NULL.
    pub(crate) fn propq(&self) -> *const c_char {
        self.propq.as_deref().map_or(ptr::null(), CStr::as_ptr)
    }
}

impl MlxKey {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `mlx_kem_have_pubkey`.
    pub(crate) fn has_public(&self) -> bool {
        self.lock().state >= HAVE_PUBKEY
    }

    /// `mlx_kem_have_prvkey`.
    pub(crate) fn has_private(&self) -> bool {
        self.lock().state >= HAVE_PRVKEY
    }

    /// The components with references of their own, used without the lock.
    pub(crate) fn components(&self) -> Components {
        let s = self.lock();
        for k in [s.mkey, s.xkey] {
            if !k.0.is_null() {
                // SAFETY: a live key this holds.
                unsafe { EVP_PKEY_up_ref(k.0) };
            }
        }
        Components {
            libctx: self.libctx.0,
            propq: s.propq.clone(),
            mkey: s.mkey.0,
            xkey: s.xkey.0,
            state: s.state,
        }
    }
}

/// The key behind key data.
///
/// # Safety
/// `keydata` is NULL or key data from one of these key managers.
pub(crate) unsafe fn key<'a>(keydata: *const c_void) -> Option<&'a MlxKey> {
    // SAFETY: the caller's guarantee.
    unsafe { keydata.cast::<MlxKey>().as_ref() }
}

/// `mlx_kem_key_new`: an empty key.
fn key_new(
    info: &'static Hybrid,
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
) -> *mut c_void {
    boxed(MlxKey {
        libctx: Ptr(libctx),
        info,
        inner: Mutex::new(Inner {
            propq,
            mkey: Ptr::default(),
            xkey: Ptr::default(),
            state: HAVE_NOKEYS,
        }),
    })
}

ffi_callback! {
    /// `mlx_kem_key_free`.
    ///
    /// # Safety
    /// `keydata` is NULL or key data the caller gives up.
    pub(crate) unsafe extern "C" fn mlx_kem_key_free(keydata: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<MlxKey>(keydata) };
    }
}

ffi_callback! {
    /// `mlx_kem_has`: always for no key part, the public key for it alone, else the private key.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn mlx_kem_has(keydata: *const c_void, selection: c_int) -> c_int
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
    /// `mlx_kem_match`: the same hybrid, and for the key pair, both without keys or both
    /// components equal (as EVP compares them: any nonzero result).
    ///
    /// # Safety
    /// `keydata1` and `keydata2` are NULL or live key data.
    pub(crate) unsafe extern "C" fn mlx_kem_match(keydata1: *const c_void, keydata2: *const c_void, selection: c_int) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let (Some(k1), Some(k2)) = (unsafe { key(keydata1) }, unsafe { key(keydata2) }) else {
            return 0;
        };
        if !ptr::eq(k1.info, k2.info) {
            return 0;
        }
        if selection & KEYPAIR == 0 {
            return 1;
        }
        let (c1, c2) = (k1.components(), k2.components());
        let (have1, have2) = (c1.state >= HAVE_PUBKEY, c2.state >= HAVE_PUBKEY);
        if have1 != have2 {
            return 0;
        }
        if !have1 {
            return 1;
        }
        // SAFETY: live components.
        let m = unsafe { EVP_PKEY_eq(c1.mkey, c2.mkey) } != 0;
        // SAFETY: as above.
        c_int::from(m && unsafe { EVP_PKEY_eq(c1.xkey, c2.xkey) } != 0)
    }
}

/// `EXPORT_CB_ARG`: where the components' exported keys go, and how many were.
struct ExportArg<'a> {
    algorithm_name: &'a CStr,
    pubenc: Option<&'a mut [u8]>,
    prvenc: Option<&'a mut [u8]>,
    pubcount: usize,
    prvcount: usize,
    puboff: usize,
    prvoff: usize,
    publen: usize,
    prvlen: usize,
}

/// Reads an octet-string parameter into `dst`: `None` if `OSSL_PARAM_get_octet_string` fails,
/// else the length read.
///
/// # Safety
/// `p` is a parameter of a live array.
unsafe fn read_into(p: *const OSSL_PARAM, dst: &mut [u8]) -> Option<usize> {
    let mut out = dst.as_mut_ptr().cast::<c_void>();
    let mut len = 0;
    // SAFETY: the caller's parameter; the slice's room.
    (unsafe { OSSL_PARAM_get_octet_string(p, &raw mut out, dst.len(), &raw mut len) } == 1)
        .then_some(len)
}

ffi_callback! {
    /// `export_sub_cb`: a component's public and private keys, if exported, into their slots,
    /// which they must fill.
    ///
    /// # Safety
    /// `params` is NULL or an array; `varg` is an `ExportArg`.
    pub(crate) unsafe extern "C" fn export_sub_cb(params: *const OSSL_PARAM, varg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(a) = (unsafe { varg.cast::<ExportArg<'_>>().as_mut() }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        let name = a.algorithm_name.to_string_lossy();
        if let Some(enc) = a.pubenc.as_deref_mut()
            // SAFETY: the caller's array; a static name.
            && let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PUB_KEY) }
        {
            let slot = enc.get_mut(a.puboff..a.puboff.saturating_add(a.publen)).unwrap_or_default();
            // SAFETY: a parameter of the array.
            let Some(len) = (unsafe { read_into(p, slot) }) else { return 0 };
            if len != a.publen {
                err::raise_with_text(
                    ERR_LIB_PROV,
                    ERR_R_INTERNAL_ERROR,
                    "export_sub_cb",
                    &format!("Unexpected {name} public key length {len} != {}", a.publen),
                );
                return 0;
            }
            a.pubcount = a.pubcount.saturating_add(1);
        }
        if let Some(enc) = a.prvenc.as_deref_mut()
            // SAFETY: the caller's array; a static name.
            && let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) }
        {
            let slot = enc.get_mut(a.prvoff..a.prvoff.saturating_add(a.prvlen)).unwrap_or_default();
            // SAFETY: a parameter of the array.
            let Some(len) = (unsafe { read_into(p, slot) }) else { return 0 };
            if len != a.prvlen {
                err::raise_with_text(
                    ERR_LIB_PROV,
                    ERR_R_INTERNAL_ERROR,
                    "export_sub_cb",
                    &format!("Unexpected {name} private key length {len} != {}", a.prvlen),
                );
                return 0;
            }
            a.prvcount = a.prvcount.saturating_add(1);
        }
        1
    }
}

/// `export_sub`: each component's parts the selection names, into their slots.
fn export_sub(arg: &mut ExportArg<'_>, selection: c_int, info: &Hybrid, c: &Components) -> bool {
    arg.pubcount = 0;
    arg.prvcount = 0;
    for slot in 0..2 {
        let pkey = if slot == info.ml_kem_slot {
            arg.algorithm_name = info.ml_kem.name;
            arg.puboff = slot.saturating_mul(info.pubkey_bytes);
            arg.prvoff = slot.saturating_mul(info.prvkey_bytes);
            arg.publen = info.ml_kem.pubkey_bytes;
            arg.prvlen = info.ml_kem.prvkey_bytes;
            c.mkey
        } else {
            arg.algorithm_name = info.algorithm_name;
            arg.puboff = info.ecdh_offset(info.ml_kem.pubkey_bytes);
            arg.prvoff = info.ecdh_offset(info.ml_kem.prvkey_bytes);
            arg.publen = info.pubkey_bytes;
            arg.prvlen = info.prvkey_bytes;
            c.xkey
        };
        let varg = core::ptr::from_mut(arg).cast::<c_void>();
        // SAFETY: a live component; the callback above and its argument.
        if unsafe { EVP_PKEY_export(pkey, selection, Some(export_sub_cb), varg) } == 0 {
            return false;
        }
    }
    true
}

ffi_callback! {
    /// `mlx_kem_export`: for a key with a public key, the public key (if selected) and the
    /// private key (if selected and present), each only if both components gave theirs.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `param_cb` is called with `cbarg`.
    pub(crate) unsafe extern "C" fn mlx_kem_export(keydata: *mut c_void, selection: c_int, param_cb: OSSL_CALLBACK, cbarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        if selection & KEYPAIR == 0 {
            return 0;
        }
        let c = k.components();
        if c.state < HAVE_PUBKEY {
            err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, "mlx_kem_export");
            return 0;
        }
        let info = k.info;
        let mut pubenc = (selection & PUBLIC != 0).then(|| vec![0u8; info.public_len()]);
        let mut prvenc = (c.state >= HAVE_PRVKEY && selection & PRIVATE != 0).then(|| vec![0u8; info.private_len()]);
        let mut arg = ExportArg {
            algorithm_name: info.ml_kem.name,
            pubenc: pubenc.as_deref_mut(),
            prvenc: prvenc.as_deref_mut(),
            pubcount: 0,
            prvcount: 0,
            puboff: 0,
            prvoff: 0,
            publen: 0,
            prvlen: 0,
        };
        let mut ret = 0;
        if export_sub(&mut arg, selection, info, &c) {
            let (pubcount, prvcount) = (arg.pubcount, arg.prvcount);
            let mut params = Vec::with_capacity(3);
            for (name, v, count) in [
                (OSSL_PKEY_PARAM_PUB_KEY, pubenc.as_mut(), pubcount),
                (OSSL_PKEY_PARAM_PRIV_KEY, prvenc.as_mut(), prvcount),
            ] {
                if let Some(v) = v.filter(|_| count == 2) {
                    // SAFETY: a static name; octets that outlive the array.
                    params.push(unsafe { OSSL_PARAM_construct_octet_string(name.as_ptr(), v.as_mut_ptr().cast(), v.len()) });
                }
            }
            // SAFETY: no preconditions.
            params.push(unsafe { OSSL_PARAM_construct_end() });
            if let Some(cb) = param_cb {
                // SAFETY: the caller's callback and argument; the array, alive until after.
                ret = unsafe { cb(params.as_ptr(), cbarg) };
            }
        }
        if let Some(v) = prvenc.as_mut() {
            wipe(v);
        }
        ret
    }
}

/// `key_types`.
static KEY_TYPES: Params<3> = Params([
    defn(OSSL_PKEY_PARAM_PUB_KEY, OSSL_PARAM_OCTET_STRING, 0),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `mlx_kem_imexport_types`.
    pub(crate) unsafe extern "C" fn mlx_kem_imexport_types(selection: c_int) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        if selection & KEYPAIR != 0 { KEY_TYPES.0.as_ptr() } else { ptr::null() }
    }
}

/// `load_slot`: one component from its part of an encoding (`pname` names it), through EVP
/// with the key's library context and properties.
fn load_slot(
    k: &MlxKey,
    inner: &mut Inner,
    pname: &CStr,
    slot: usize,
    input: &[u8],
    mbytes: usize,
    xbytes: usize,
) -> bool {
    let info = k.info;
    let (alg, group, off, len) = if slot == info.ml_kem_slot {
        (info.ml_kem.name, None, info.ml_kem_offset(xbytes), mbytes)
    } else {
        (
            info.algorithm_name,
            info.group_name,
            info.ecdh_offset(mbytes),
            xbytes,
        )
    };
    let Some(part) = input.get(off..off.saturating_add(len)) else {
        return false;
    };
    let mut val = part.to_vec();
    let propq = inner.propq.as_deref().map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: the key's library context; a static name; the properties or NULL.
    let ctx = unsafe { EVP_PKEY_CTX_new_from_name(k.libctx.0, alg.as_ptr(), propq) };
    let mut out: *mut EVP_PKEY = ptr::null_mut();
    // SAFETY: the context made above, or NULL.
    let mut ok = !ctx.is_null() && unsafe { EVP_PKEY_fromdata_init(ctx) } > 0;
    if ok {
        // SAFETY: a static name; the copy, which outlives the array.
        let mut params = [
            unsafe {
                OSSL_PARAM_construct_octet_string(pname.as_ptr(), val.as_mut_ptr().cast(), len)
            },
            PARAM_END,
            PARAM_END,
        ];
        if let (Some(g), Some(slot)) = (group, params.get_mut(1)) {
            // SAFETY: static strings.
            *slot = unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_GROUP_NAME.as_ptr(),
                    g.as_ptr().cast_mut(),
                    0,
                )
            };
        }
        // SAFETY: the context; a place for the key; the array.
        ok = unsafe { EVP_PKEY_fromdata(ctx, &raw mut out, MINIMAL, params.as_mut_ptr()) } > 0;
    }
    wipe(&mut val);
    // SAFETY: made above, or NULL.
    unsafe { EVP_PKEY_CTX_free(ctx) };
    let dst = if slot == info.ml_kem_slot {
        &mut inner.mkey
    } else {
        &mut inner.xkey
    };
    if !out.is_null() {
        // SAFETY: what the slot held, or NULL.
        unsafe { EVP_PKEY_free(dst.0) };
        dst.0 = out;
    }
    ok
}

/// `load_keys`: both components from the private key if given, else the public key.
fn load_keys(k: &MlxKey, inner: &mut Inner, public: &[u8], private: &[u8]) -> bool {
    let info = k.info;
    for slot in 0..2 {
        let ok = if !private.is_empty() {
            load_slot(
                k,
                inner,
                OSSL_PKEY_PARAM_PRIV_KEY,
                slot,
                private,
                info.ml_kem.prvkey_bytes,
                info.prvkey_bytes,
            )
        } else if !public.is_empty() {
            load_slot(
                k,
                inner,
                OSSL_PKEY_PARAM_PUB_KEY,
                slot,
                public,
                info.ml_kem.pubkey_bytes,
                info.pubkey_bytes,
            )
        } else {
            true
        };
        if !ok {
            inner.clear();
            return false;
        }
    }
    inner.state = if private.is_empty() {
        HAVE_PUBKEY
    } else {
        HAVE_PRVKEY
    };
    true
}

/// An octet-string parameter's octets (`OSSL_PARAM_get_octet_string_ptr`), or `None`.
///
/// # Safety
/// `p` is a parameter of a live array.
unsafe fn octets<'a>(p: *const OSSL_PARAM) -> Option<&'a [u8]> {
    let mut data: *const c_void = ptr::null();
    let mut len = 0;
    // SAFETY: the caller's parameter; places for the pointer and length.
    if unsafe { OSSL_PARAM_get_octet_string_ptr(p, &raw mut data, &raw mut len) } != 1 {
        return None;
    }
    // SAFETY: the parameter's own octets.
    unsafe { bytes(data.cast::<u8>(), len) }
}

/// `mlx_kem_key_fromdata`: a key without key material, from a public key, a private key, or
/// both (the public key then ignored), each of its full length.
///
/// # Safety
/// `params` is NULL or an array.
unsafe fn key_fromdata(k: &MlxKey, params: *const OSSL_PARAM, include_private: bool) -> bool {
    const F: &str = "mlx_kem_key_fromdata";
    let mut inner = k.lock();
    if inner.state >= HAVE_PUBKEY {
        return false;
    }
    // SAFETY: the caller's guarantee.
    if !unsafe {
        crate::provider::param_decoders::decode(
            params,
            &crate::provider::param_decoders::ML_KEM_IMPORT_EXPORT,
        )
    } {
        return false;
    }
    let info = k.info;
    let mut public: &[u8] = &[];
    // SAFETY: the caller's array; a static name.
    if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PUB_KEY) } {
        // SAFETY: a parameter of the array.
        let Some(v) = (unsafe { octets(p) }) else {
            return false;
        };
        public = v;
    }
    let mut private: &[u8] = &[];
    if include_private
        // SAFETY: the caller's array; a static name.
        && let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PRIV_KEY) }
    {
        // SAFETY: a parameter of the array.
        let Some(v) = (unsafe { octets(p) }) else {
            return false;
        };
        private = v;
    }
    if public.is_empty() && private.is_empty() {
        err::raise(ERR_LIB_PROV, PROV_R_MISSING_KEY, F);
        return false;
    }
    if (!public.is_empty() && public.len() != info.public_len())
        || (!private.is_empty() && private.len() != info.private_len())
    {
        err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH, F);
        return false;
    }
    load_keys(k, &mut inner, public, private)
}

ffi_callback! {
    /// `mlx_kem_import`: the key pair (which must be selected).
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mlx_kem_import(keydata: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> c_int
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

/// `mlx_kem_gettable_params`' list.
static GETTABLE: Params<7> = Params([
    defn(OSSL_PKEY_PARAM_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_SECURITY_BITS, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(OSSL_PKEY_PARAM_MAX_SIZE, OSSL_PARAM_INTEGER, INT_SIZE),
    defn(
        OSSL_PKEY_PARAM_SECURITY_CATEGORY,
        OSSL_PARAM_INTEGER,
        INT_SIZE,
    ),
    defn(
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PARAM_OCTET_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `mlx_kem_gettable_params`.
    pub(crate) unsafe extern "C" fn mlx_kem_gettable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GETTABLE.0.as_ptr()
    }
}

/// An output octet-string parameter for a key part of `len` octets: `Err` if it isn't an octet
/// string or its room is too small (an error), `Ok(None)` for a size query (its return size
/// set), else its room.
///
/// # Safety
/// `p` is NULL or a parameter of a live, writable array.
unsafe fn out_param<'a>(
    p: *mut OSSL_PARAM,
    len: usize,
    what: &str,
) -> Result<Option<&'a mut [u8]>, ()> {
    // SAFETY: the caller's guarantee.
    let Some(p) = (unsafe { p.as_mut() }) else {
        return Ok(None);
    };
    if p.data_type != OSSL_PARAM_OCTET_STRING as u32 {
        return Err(());
    }
    p.return_size = len;
    if p.data.is_null() {
        return Ok(None);
    }
    if p.data_size < len {
        err::raise_with_text(
            ERR_LIB_PROV,
            PROV_R_OUTPUT_BUFFER_TOO_SMALL,
            "mlx_kem_get_params",
            &format!(
                "{what} key output buffer too short: {} < {len}",
                p.data_size
            ),
        );
        return Err(());
    }
    // SAFETY: the parameter's room of `data_size` (at least `len`) octets.
    Ok(Some(unsafe {
        core::slice::from_raw_parts_mut(p.data.cast::<u8>(), len)
    }))
}

ffi_callback! {
    /// `mlx_kem_get_params`: ML-KEM's bits and security bits, the ciphertext's length, and for a
    /// key with key material, the encoded public key and the private key (if it has one), each
    /// only if both components give theirs.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mlx_kem_get_params(keydata: *mut c_void, params: *mut OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::MLX_GET_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        let info = k.info;
        let max = c_int::try_from(info.ciphertext_len()).unwrap_or(c_int::MAX);
        for (name, value) in [
            (OSSL_PKEY_PARAM_BITS, info.ml_kem.bits),
            (OSSL_PKEY_PARAM_SECURITY_BITS, info.ml_kem.secbits),
            (OSSL_PKEY_PARAM_MAX_SIZE, max),
            (
                OSSL_PKEY_PARAM_SECURITY_CATEGORY,
                c_int::try_from(info.ml_kem.variant.security_category()).unwrap_or(0),
            ),
        ] {
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, name.as_ptr()) };
            // SAFETY: a parameter of the array.
            if !p.is_null() && unsafe { OSSL_PARAM_set_int(p, value) } == 0 {
                return 0;
            }
        }
        let c = k.components();
        if c.state < HAVE_PUBKEY {
            return 1;
        }
        // SAFETY: the caller's array; a static name.
        let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr()) };
        // SAFETY: a parameter of the array, or NULL.
        let Ok(mut pubenc) = (unsafe { out_param(p, info.public_len(), "public") }) else { return 0 };
        let mut prvenc = None;
        if c.state >= HAVE_PRVKEY {
            // SAFETY: the caller's array; a static name.
            let p = unsafe { OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY.as_ptr()) };
            // SAFETY: a parameter of the array, or NULL.
            let Ok(v) = (unsafe { out_param(p, info.private_len(), "private") }) else { return 0 };
            prvenc = v;
        }
        if pubenc.is_none() && prvenc.is_none() {
            return 1;
        }
        let mut selection = if prvenc.is_some() { PRIVATE } else { 0 };
        if pubenc.is_some() {
            selection |= PUBLIC;
        }
        if info.group_name.is_some() {
            selection |= OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
        }
        let (want_pub, want_prv) = (pubenc.is_some(), prvenc.is_some());
        let mut arg = ExportArg {
            algorithm_name: info.ml_kem.name,
            pubenc: pubenc.as_deref_mut(),
            prvenc: prvenc.as_deref_mut(),
            pubcount: 0,
            prvcount: 0,
            puboff: 0,
            prvoff: 0,
            publen: 0,
            prvlen: 0,
        };
        let ok = export_sub(&mut arg, selection, info, &c)
            && (!want_pub || arg.pubcount == 2)
            && (!want_prv || arg.prvcount == 2);
        if !ok {
            for v in [pubenc, prvenc].into_iter().flatten() {
                wipe(v);
            }
            return 0;
        }
        1
    }
}

/// `mlx_kem_settable_params`' list.
static SETTABLE: Params<3> = Params([
    defn(
        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
        OSSL_PARAM_OCTET_STRING,
        0,
    ),
    defn(OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `mlx_kem_settable_params`.
    pub(crate) unsafe extern "C" fn mlx_kem_settable_params(_provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        SETTABLE.0.as_ptr()
    }
}

ffi_callback! {
    /// `mlx_kem_set_params`: an encoded public key (with the properties to make its components
    /// with) for a key without key material.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mlx_kem_set_params(keydata: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::MLX_SET_PARAMS) } {
            return 0;
        }
        const F: &str = "mlx_kem_set_params";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array; a static name.
        let Some(p) = (unsafe { locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY) }) else {
            return 1;
        };
        let mut inner = k.lock();
        if inner.state >= HAVE_PUBKEY {
            drop(inner);
            err::raise_with_text(
                ERR_LIB_PROV,
                PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                F,
                "keys cannot be mutated",
            );
            return 0;
        }
        // SAFETY: a parameter of the array.
        let Some(public) = (unsafe { octets(p) }) else { return 0 };
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PROPERTIES) } {
            inner.propq = None;
            let mut s: *mut c_char = ptr::null_mut();
            // SAFETY: a parameter of the array; a place for a new string.
            if unsafe { OSSL_PARAM_get_utf8_string(p, &raw mut s, 0) } == 0 {
                return 0;
            }
            // SAFETY: the string just made.
            inner.propq = Some(unsafe { CStr::from_ptr(s) }.to_owned());
            // SAFETY: the string just made, freed once.
            unsafe { crate::mem::CRYPTO_free(s.cast(), c"".as_ptr(), 0) };
        }
        if public.len() != k.info.public_len() {
            drop(inner);
            err::raise(ERR_LIB_PROV, PROV_R_INVALID_KEY, F);
            return 0;
        }
        c_int::from(load_keys(k, &mut inner, public, &[]))
    }
}

/// `PROV_ML_KEM_GEN_CTX`.
struct GenCtx {
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
    selection: c_int,
    info: &'static Hybrid,
}

ffi_callback! {
    /// `mlx_kem_gen_set_params`: the properties (which must be a UTF-8 string).
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context; `params` is NULL or an array.
    pub(crate) unsafe extern "C" fn mlx_kem_gen_set_params(genctx: *mut c_void, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { crate::provider::param_decoders::decode(params, &crate::provider::param_decoders::MLX_GEN_SET_PARAMS) } {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else { return 0 };
        // SAFETY: the caller's guarantee.
        if unsafe { is_empty(params) } {
            return 1;
        }
        // SAFETY: the caller's array; a static name.
        if let Some(p) = unsafe { locate(params, OSSL_PKEY_PARAM_PROPERTIES) } {
            if p.data_type != OSSL_PARAM_UTF8_STRING as u32 || p.data.is_null() {
                return 0;
            }
            // SAFETY: a UTF-8 string parameter's NUL-terminated data.
            g.propq = Some(unsafe { CStr::from_ptr(p.data.cast::<c_char>()) }.to_owned());
        }
        1
    }
}

/// `mlx_kem_gen_settable_params`' list (the properties, listed as an octet string).
static GEN_SETTABLE: Params<2> = Params([
    defn(OSSL_PKEY_PARAM_PROPERTIES, OSSL_PARAM_UTF8_STRING, 0),
    PARAM_END,
]);

ffi_callback! {
    /// `mlx_kem_gen_settable_params`.
    pub(crate) unsafe extern "C" fn mlx_kem_gen_settable_params(_genctx: *mut c_void, _provctx: *mut c_void) -> *const OSSL_PARAM
    where failure = ptr::null(), library = ERR_LIB_PROV
    {
        GEN_SETTABLE.0.as_ptr()
    }
}

/// `mlx_kem_gen_init`: a generation context, for a selection with the domain parameters or the
/// private key.
///
/// # Safety
/// `provctx` is NULL or the default provider's context; `params` is NULL or an array.
unsafe fn gen_init(
    info: &'static Hybrid,
    provctx: *mut c_void,
    selection: c_int,
    params: *const OSSL_PARAM,
) -> *mut c_void {
    if selection & MINIMAL == 0 {
        return ptr::null_mut();
    }
    let libctx = if provctx.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { libctx_of(provctx) }
    };
    let g = boxed(GenCtx {
        libctx,
        propq: None,
        selection,
        info,
    });
    // SAFETY: the context just made; the caller's array.
    if unsafe { mlx_kem_gen_set_params(g, params) } == 0 {
        // SAFETY: the context just made, freed once.
        unsafe { unbox::<GenCtx>(g) };
        return ptr::null_mut();
    }
    g
}

ffi_callback! {
    /// `mlx_kem_gen`: an empty key when no key part is selected, else both components
    /// generated with the context's properties (which the key takes, leaving none for the next
    /// generation); a selection of the public key alone fails.
    ///
    /// # Safety
    /// `genctx` is NULL or a live generation context.
    pub(crate) unsafe extern "C" fn mlx_kem_gen(genctx: *mut c_void, _cb: OSSL_CALLBACK, _cbarg: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(g) = (unsafe { context::<GenCtx>(genctx) }) else { return ptr::null_mut() };
        if g.selection & KEYPAIR == PUBLIC {
            return ptr::null_mut();
        }
        let h = key_new(g.info, g.libctx, g.propq.take());
        if g.selection & KEYPAIR == 0 {
            return h;
        }
        // SAFETY: the key just made.
        let Some(k) = (unsafe { key(h) }) else { return ptr::null_mut() };
        let info = k.info;
        let mut inner = k.lock();
        let propq = inner.propq.as_deref().map_or(ptr::null(), CStr::as_ptr);
        let end = PARAM_END;
        // SAFETY: the key's library context; a static name; the properties or NULL; no
        // parameters.
        let mkey = unsafe { quick_keygen(g.libctx, info.ml_kem.name.as_ptr(), propq, [end].as_ptr()) };
        let xparams = match info.group_name {
            // SAFETY: static strings.
            Some(group) => [unsafe { OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME.as_ptr(), group.as_ptr().cast_mut(), 0) }, PARAM_END],
            None => [PARAM_END, PARAM_END],
        };
        // SAFETY: as above; the array.
        let xkey = unsafe { quick_keygen(g.libctx, info.algorithm_name.as_ptr(), propq, xparams.as_ptr()) };
        inner.mkey = Ptr(mkey);
        inner.xkey = Ptr(xkey);
        if mkey.is_null() || xkey.is_null() {
            drop(inner);
            // SAFETY: the key made above, freed once (with any component).
            unsafe { unbox::<MlxKey>(h) };
            return ptr::null_mut();
        }
        inner.state = HAVE_PRVKEY;
        h
    }
}

ffi_callback! {
    /// `mlx_kem_gen_cleanup`.
    ///
    /// # Safety
    /// `genctx` is NULL or a generation context the caller gives up.
    pub(crate) unsafe extern "C" fn mlx_kem_gen_cleanup(genctx: *mut c_void)
    where failure = (), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        unsafe { unbox::<GenCtx>(genctx) };
    }
}

ffi_callback! {
    /// `mlx_kem_dup`: a copy without key material (none selected, or the key has none) or with
    /// both components copied (the whole pair selected); other selections fail.
    ///
    /// # Safety
    /// `keydata` is NULL or live key data.
    pub(crate) unsafe extern "C" fn mlx_kem_dup(keydata: *const c_void, selection: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PROV
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(keydata) }) else { return ptr::null_mut() };
        let c = k.components();
        let copy = |state: u8, mkey: *mut EVP_PKEY, xkey: *mut EVP_PKEY| {
            boxed(MlxKey {
                libctx: k.libctx,
                info: k.info,
                inner: Mutex::new(Inner { propq: c.propq.clone(), mkey: Ptr(mkey), xkey: Ptr(xkey), state }),
            })
        };
        if c.mkey.is_null() {
            if c.xkey.is_null() {
                return copy(c.state, ptr::null_mut(), ptr::null_mut());
            }
            return ptr::null_mut();
        }
        match selection & KEYPAIR {
            0 => copy(HAVE_NOKEYS, ptr::null_mut(), ptr::null_mut()),
            KEYPAIR => {
                // SAFETY: a live component.
                let m = unsafe { EVP_PKEY_dup(c.mkey) };
                // SAFETY: as above.
                let x = unsafe { EVP_PKEY_dup(c.xkey) };
                let h = copy(c.state, m, x);
                if m.is_null() || x.is_null() {
                    // SAFETY: the copy made above, freed once (with any component).
                    unsafe { unbox::<MlxKey>(h) };
                    return ptr::null_mut();
                }
                h
            }
            _ => {
                err::raise_with_text(
                    ERR_LIB_PROV,
                    PROV_R_UNSUPPORTED_SELECTION,
                    "mlx_kem_dup",
                    "duplication of partial key material not supported",
                );
                ptr::null_mut()
            }
        }
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
type DupFn = unsafe extern "C" fn(*const c_void, c_int) -> *mut c_void;

/// `DECLARE_DISPATCH(name, variant)`: a hybrid's new-key and generation callbacks and table.
macro_rules! mlx_keymgmt {
    ($table:ident, $info:ident, $new:ident, $gen_init:ident) => {
        ffi_callback! {
            /// The hybrid's `mlx_*_kem_new`.
            ///
            /// # Safety
            /// `provctx` is NULL or the default provider's context.
            pub(crate) unsafe extern "C" fn $new(provctx: *mut c_void) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                let libctx = if provctx.is_null() {
                    ptr::null_mut()
                } else {
                    // SAFETY: the caller's guarantee.
                    unsafe { libctx_of(provctx) }
                };
                key_new(&$info, libctx, None)
            }
        }
        ffi_callback! {
            /// The hybrid's `mlx_*_kem_gen_init`.
            ///
            /// # Safety
            /// `provctx` is NULL or the default provider's context; `params` is NULL or an
            /// array.
            pub(crate) unsafe extern "C" fn $gen_init(provctx: *mut c_void, selection: c_int, params: *const OSSL_PARAM) -> *mut c_void
            where failure = ptr::null_mut(), library = ERR_LIB_PROV
            {
                // SAFETY: the caller's guarantee.
                unsafe { gen_init(&$info, provctx, selection, params) }
            }
        }
        /// `ossl_mlx_*_kem_kmgmt_functions`.
        pub(crate) static $table: Dispatch<19> = Dispatch([
            entry!(OSSL_FUNC_KEYMGMT_NEW, $new, NewFn),
            entry!(OSSL_FUNC_KEYMGMT_FREE, mlx_kem_key_free, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_GET_PARAMS, mlx_kem_get_params, GetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, mlx_kem_gettable_params, ListFn),
            entry!(OSSL_FUNC_KEYMGMT_SET_PARAMS, mlx_kem_set_params, SetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, mlx_kem_settable_params, ListFn),
            entry!(OSSL_FUNC_KEYMGMT_HAS, mlx_kem_has, HasFn),
            entry!(OSSL_FUNC_KEYMGMT_MATCH, mlx_kem_match, MatchFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_INIT, $gen_init, GenInitFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, mlx_kem_gen_set_params, SetParamsFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, mlx_kem_gen_settable_params, GenListFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN, mlx_kem_gen, GenFn),
            entry!(OSSL_FUNC_KEYMGMT_GEN_CLEANUP, mlx_kem_gen_cleanup, FreeFn),
            entry!(OSSL_FUNC_KEYMGMT_DUP, mlx_kem_dup, DupFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT, mlx_kem_import, ImportFn),
            entry!(OSSL_FUNC_KEYMGMT_IMPORT_TYPES, mlx_kem_imexport_types, TypesFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT, mlx_kem_export, ExportFn),
            entry!(OSSL_FUNC_KEYMGMT_EXPORT_TYPES, mlx_kem_imexport_types, TypesFn),
            END,
        ]);
    };
}

mlx_keymgmt!(P256_KEYMGMT, P256, mlx_p256_kem_new, mlx_p256_kem_gen_init);
mlx_keymgmt!(P384_KEYMGMT, P384, mlx_p384_kem_new, mlx_p384_kem_gen_init);
mlx_keymgmt!(
    X25519_KEYMGMT,
    X25519,
    mlx_x25519_kem_new,
    mlx_x25519_kem_gen_init
);
mlx_keymgmt!(X448_KEYMGMT, X448, mlx_x448_kem_new, mlx_x448_kem_gen_init);
