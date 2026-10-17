//! Hybrid Public Key Encryption (RFC 9180; `hpke.c`, `hpke_util.c`): `OSSL_HPKE_CTX` and the
//! `OSSL_HPKE_*` functions, in the base, psk, auth, and psk-auth modes over the default
//! provider's DHKEMs, HKDF, and AEADs.
//!
//! As OpenSSL's, everything goes through EVP with the context's library context and
//! properties: the KEM through `EVP_PKEY_encapsulate` and `_decapsulate` (the "DHKEM"
//! operation), the key schedule through the HKDF `EVP_KDF` in its extract-only and expand-only
//! modes, and the AEAD through an `EVP_CIPHER` fetched when the context is made. The errors
//! are OpenSSL's, each failure inside adding `ERR_R_INTERNAL_ERROR` on its way out.

use core::ffi::{CStr, c_char, c_int, c_uchar};
use core::ptr;
use std::ffi::CString;
use std::sync::{Mutex, MutexGuard, PoisonError};

use rustyssl_abi::{
    ERR_LIB_CRYPTO, ERR_LIB_PROV, ERR_R_FETCH_FAILED, ERR_R_INTERNAL_ERROR,
    ERR_R_PASSED_INVALID_ARGUMENT, ERR_R_PASSED_NULL_PARAMETER, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED,
    EVP_CIPHER, EVP_CTRL_AEAD_GET_TAG, EVP_CTRL_AEAD_SET_IVLEN, EVP_CTRL_AEAD_SET_TAG, EVP_KDF_CTX,
    EVP_KDF_HKDF_MODE_EXPAND_ONLY, EVP_KDF_HKDF_MODE_EXTRACT_ONLY, EVP_PKEY, LN_aes_128_gcm,
    LN_aes_256_gcm, LN_chacha20_poly1305, LN_sha256, LN_sha384, LN_sha512,
    OSSL_HPKE_AEAD_ID_AES_GCM_128, OSSL_HPKE_AEAD_ID_AES_GCM_256,
    OSSL_HPKE_AEAD_ID_CHACHA_POLY1305, OSSL_HPKE_AEAD_ID_EXPORTONLY, OSSL_HPKE_AEADSTR_AES128GCM,
    OSSL_HPKE_AEADSTR_AES256GCM, OSSL_HPKE_AEADSTR_CP, OSSL_HPKE_AEADSTR_EXP, OSSL_HPKE_CTX,
    OSSL_HPKE_KDF_ID_HKDF_SHA256, OSSL_HPKE_KDF_ID_HKDF_SHA384, OSSL_HPKE_KDF_ID_HKDF_SHA512,
    OSSL_HPKE_KDFSTR_256, OSSL_HPKE_KDFSTR_384, OSSL_HPKE_KDFSTR_512, OSSL_HPKE_KEM_ID_P256,
    OSSL_HPKE_KEM_ID_P384, OSSL_HPKE_KEM_ID_P521, OSSL_HPKE_KEM_ID_RESERVED, OSSL_HPKE_KEM_ID_X448,
    OSSL_HPKE_KEM_ID_X25519, OSSL_HPKE_KEMSTR_P256, OSSL_HPKE_KEMSTR_P384, OSSL_HPKE_KEMSTR_P521,
    OSSL_HPKE_KEMSTR_X448, OSSL_HPKE_KEMSTR_X25519, OSSL_HPKE_MAX_INFOLEN, OSSL_HPKE_MAX_PARMLEN,
    OSSL_HPKE_MIN_PSKLEN, OSSL_HPKE_MODE_AUTH, OSSL_HPKE_MODE_BASE, OSSL_HPKE_MODE_PSK,
    OSSL_HPKE_MODE_PSKAUTH, OSSL_HPKE_ROLE_RECEIVER, OSSL_HPKE_ROLE_SENDER, OSSL_HPKE_SUITE,
    OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_INFO, OSSL_KDF_PARAM_KEY, OSSL_KDF_PARAM_MODE,
    OSSL_KDF_PARAM_PROPERTIES, OSSL_KDF_PARAM_SALT, OSSL_KEM_PARAM_IKME, OSSL_KEM_PARAM_OPERATION,
    OSSL_KEM_PARAM_OPERATION_DHKEM, OSSL_LIB_CTX, OSSL_PKEY_PARAM_DHKEM_IKM,
    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, OSSL_PKEY_PARAM_GROUP_NAME,
    PROV_R_FAILED_DURING_DERIVATION, PROV_R_INVALID_AEAD, PROV_R_INVALID_CURVE, PROV_R_INVALID_KDF,
    PROV_R_OUTPUT_BUFFER_TOO_SMALL,
};
use rustyssl_crypto::bn::Zeroizing;

use crate::err;
use crate::evp::cipher::{EVP_CIPHER_fetch, EVP_CIPHER_free};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex,
    EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex,
    EVP_EncryptUpdate,
};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_CTX_set_params, EVP_KDF_derive, EVP_KDF_fetch,
    EVP_KDF_free,
};
use crate::evp::kem::{
    EVP_PKEY_auth_decapsulate_init, EVP_PKEY_auth_encapsulate_init, EVP_PKEY_decapsulate,
    EVP_PKEY_decapsulate_init, EVP_PKEY_encapsulate, EVP_PKEY_encapsulate_init,
};
use crate::evp::pkey::params::{EVP_PKEY_get_octet_string_param, EVP_PKEY_set1_encoded_public_key};
use crate::evp::pkey::raw::EVP_PKEY_new_raw_public_key_ex;
use crate::evp::pkey::{EVP_PKEY_dup, EVP_PKEY_free};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_from_name, EVP_PKEY_CTX_new_from_pkey,
    EVP_PKEY_CTX_set_params, EVP_PKEY_generate, EVP_PKEY_keygen_init, EVP_PKEY_paramgen,
    EVP_PKEY_paramgen_init,
};
use crate::ffi::{bytes, ffi_export};
use crate::handle::{Handle, handle_type};
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string,
    OSSL_PARAM_construct_utf8_string,
};
use crate::rand_lib::RAND_bytes_ex;

/// `OSSL_HPKE_MAXSIZE` (`hpke.c`): the room for the key schedule's context and secret.
const MAXSIZE: usize = 512;
/// `OSSL_HPKE_MAX_NONCELEN` (`internal/hpke_util.h`).
const MAX_NONCELEN: usize = 12;
/// `OSSL_HPKE_MAX_SUITESTR` (`hpke_util.c`).
const MAX_SUITESTR: usize = 38;

/// `LABEL_HPKEV1`, the KDF labels' version.
const LABEL_HPKEV1: &[u8] = b"HPKE-v1";
/// `OSSL_HPKE_SEC51LABEL`, the key schedule's protocol label.
const SEC51: &[u8] = b"HPKE";

/// `OSSL_HPKE_KEM_INFO`.
struct KemInfo {
    id: u16,
    keytype: &'static CStr,
    groupname: Option<&'static CStr>,
    nenc: usize,
    npk: usize,
    nsk: usize,
}

/// `OSSL_HPKE_KDF_INFO`.
struct KdfInfo {
    id: u16,
    mdname: &'static CStr,
    nh: usize,
}

/// `OSSL_HPKE_AEAD_INFO`.
struct AeadInfo {
    id: u16,
    name: Option<&'static CStr>,
    taglen: usize,
    nk: usize,
    nn: usize,
}

/// A table entry's 16-bit identifier from the header's `int`.
const fn id16(v: c_int) -> u16 {
    let [_, _, hi, lo] = v.to_be_bytes();
    assert!(v >= 0 && v <= 0xffff);
    u16::from_be_bytes([hi, lo])
}

/// `hpke_kem_tab`.
static KEMS: [KemInfo; 5] = [
    KemInfo {
        id: id16(OSSL_HPKE_KEM_ID_P256),
        keytype: c"EC",
        groupname: Some(OSSL_HPKE_KEMSTR_P256),
        nenc: 65,
        npk: 65,
        nsk: 32,
    },
    KemInfo {
        id: id16(OSSL_HPKE_KEM_ID_P384),
        keytype: c"EC",
        groupname: Some(OSSL_HPKE_KEMSTR_P384),
        nenc: 97,
        npk: 97,
        nsk: 48,
    },
    KemInfo {
        id: id16(OSSL_HPKE_KEM_ID_P521),
        keytype: c"EC",
        groupname: Some(OSSL_HPKE_KEMSTR_P521),
        nenc: 133,
        npk: 133,
        nsk: 66,
    },
    KemInfo {
        id: id16(OSSL_HPKE_KEM_ID_X25519),
        keytype: OSSL_HPKE_KEMSTR_X25519,
        groupname: None,
        nenc: 32,
        npk: 32,
        nsk: 32,
    },
    KemInfo {
        id: id16(OSSL_HPKE_KEM_ID_X448),
        keytype: OSSL_HPKE_KEMSTR_X448,
        groupname: None,
        nenc: 56,
        npk: 56,
        nsk: 56,
    },
];

/// `hpke_kdf_tab`.
static KDFS: [KdfInfo; 3] = [
    KdfInfo {
        id: id16(OSSL_HPKE_KDF_ID_HKDF_SHA256),
        mdname: LN_sha256,
        nh: 32,
    },
    KdfInfo {
        id: id16(OSSL_HPKE_KDF_ID_HKDF_SHA384),
        mdname: LN_sha384,
        nh: 48,
    },
    KdfInfo {
        id: id16(OSSL_HPKE_KDF_ID_HKDF_SHA512),
        mdname: LN_sha512,
        nh: 64,
    },
];

/// `hpke_aead_tab` (the export-only entry last, which the random choice leaves out).
static AEADS: [AeadInfo; 4] = [
    AeadInfo {
        id: id16(OSSL_HPKE_AEAD_ID_AES_GCM_128),
        name: Some(LN_aes_128_gcm),
        taglen: 16,
        nk: 16,
        nn: MAX_NONCELEN,
    },
    AeadInfo {
        id: id16(OSSL_HPKE_AEAD_ID_AES_GCM_256),
        name: Some(LN_aes_256_gcm),
        taglen: 16,
        nk: 32,
        nn: MAX_NONCELEN,
    },
    AeadInfo {
        id: id16(OSSL_HPKE_AEAD_ID_CHACHA_POLY1305),
        name: Some(LN_chacha20_poly1305),
        taglen: 16,
        nk: 32,
        nn: MAX_NONCELEN,
    },
    AeadInfo {
        id: id16(OSSL_HPKE_AEAD_ID_EXPORTONLY),
        name: None,
        taglen: 0,
        nk: 0,
        nn: 0,
    },
];

/// `kemstrtab`, `kdfstrtab`, and `aeadstrtab`: each identifier's names.
type Names = [(u16, [&'static CStr; 4])];
static KEM_NAMES: [(u16, [&CStr; 4]); 5] = [
    (
        id16(OSSL_HPKE_KEM_ID_P256),
        [OSSL_HPKE_KEMSTR_P256, c"0x10", c"0x10", c"16"],
    ),
    (
        id16(OSSL_HPKE_KEM_ID_P384),
        [OSSL_HPKE_KEMSTR_P384, c"0x11", c"0x11", c"17"],
    ),
    (
        id16(OSSL_HPKE_KEM_ID_P521),
        [OSSL_HPKE_KEMSTR_P521, c"0x12", c"0x12", c"18"],
    ),
    (
        id16(OSSL_HPKE_KEM_ID_X25519),
        [OSSL_HPKE_KEMSTR_X25519, c"0x20", c"0x20", c"32"],
    ),
    (
        id16(OSSL_HPKE_KEM_ID_X448),
        [OSSL_HPKE_KEMSTR_X448, c"0x21", c"0x21", c"33"],
    ),
];
static KDF_NAMES: [(u16, [&CStr; 4]); 3] = [
    (
        id16(OSSL_HPKE_KDF_ID_HKDF_SHA256),
        [OSSL_HPKE_KDFSTR_256, c"0x1", c"0x01", c"1"],
    ),
    (
        id16(OSSL_HPKE_KDF_ID_HKDF_SHA384),
        [OSSL_HPKE_KDFSTR_384, c"0x2", c"0x02", c"2"],
    ),
    (
        id16(OSSL_HPKE_KDF_ID_HKDF_SHA512),
        [OSSL_HPKE_KDFSTR_512, c"0x3", c"0x03", c"3"],
    ),
];
static AEAD_NAMES: [(u16, [&CStr; 4]); 4] = [
    (
        id16(OSSL_HPKE_AEAD_ID_AES_GCM_128),
        [OSSL_HPKE_AEADSTR_AES128GCM, c"0x1", c"0x01", c"1"],
    ),
    (
        id16(OSSL_HPKE_AEAD_ID_AES_GCM_256),
        [OSSL_HPKE_AEADSTR_AES256GCM, c"0x2", c"0x02", c"2"],
    ),
    (
        id16(OSSL_HPKE_AEAD_ID_CHACHA_POLY1305),
        [OSSL_HPKE_AEADSTR_CP, c"0x3", c"0x03", c"3"],
    ),
    (
        id16(OSSL_HPKE_AEAD_ID_EXPORTONLY),
        [OSSL_HPKE_AEADSTR_EXP, c"ff", c"0xff", c"255"],
    ),
];

/// `ossl_HPKE_KEM_INFO_find_id`.
fn kem_by_id(id: u16) -> Option<&'static KemInfo> {
    let found = (id != id16(OSSL_HPKE_KEM_ID_RESERVED))
        .then(|| KEMS.iter().find(|k| k.id == id))
        .flatten();
    if found.is_none() {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_INVALID_CURVE,
            "ossl_HPKE_KEM_INFO_find_id",
        );
    }
    found
}

/// `ossl_HPKE_KDF_INFO_find_id`.
fn kdf_by_id(id: u16) -> Option<&'static KdfInfo> {
    let found = KDFS.iter().find(|k| k.id == id);
    if found.is_none() {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_INVALID_KDF,
            "ossl_HPKE_KDF_INFO_find_id",
        );
    }
    found
}

/// `ossl_HPKE_AEAD_INFO_find_id`.
fn aead_by_id(id: u16) -> Option<&'static AeadInfo> {
    let found = AEADS.iter().find(|a| a.id == id);
    if found.is_none() {
        err::raise(
            ERR_LIB_PROV,
            PROV_R_INVALID_AEAD,
            "ossl_HPKE_AEAD_INFO_find_id",
        );
    }
    found
}

/// `hpke_suite_check`: the suite's KEM, KDF, and AEAD, each found or an error.
fn suite_infos(
    suite: OSSL_HPKE_SUITE,
) -> Option<(&'static KemInfo, &'static KdfInfo, &'static AeadInfo)> {
    let kem = kem_by_id(suite.kem_id)?;
    let kdf = kdf_by_id(suite.kdf_id)?;
    let aead = aead_by_id(suite.aead_id)?;
    Some((kem, kdf, aead))
}

/// `ossl_rand_uniform_uint32`: a uniform number below `upper` from the library context's
/// random bits, or `None`.
fn rand_uniform(libctx: *mut OSSL_LIB_CTX, upper: u32) -> Option<u32> {
    let draw = || {
        let mut b = [0u8; 4];
        // SAFETY: the caller's library context; room for four octets.
        (unsafe { RAND_bytes_ex(libctx, b.as_mut_ptr(), 4, 0) } > 0).then(|| u32::from_ne_bytes(b))
    };
    if upper <= 1 {
        return Some(0);
    }
    let halves = |p: u64| {
        (
            u32::try_from(p >> 32).unwrap_or(0),
            u32::try_from(p & 0xffff_ffff).unwrap_or(0),
        )
    };
    let (i, mut f) = halves(u64::from(upper) * u64::from(draw()?));
    if f <= 1u32.wrapping_add(!upper) {
        return Some(i);
    }
    for _ in 0..10 {
        let (f2, low) = halves(u64::from(upper) * u64::from(draw()?));
        f = f.wrapping_add(f2);
        if f < f2 {
            return Some(i + 1);
        }
        if f != u32::MAX {
            return Some(i);
        }
        f = low;
    }
    Some(i)
}

/// The KDF context of `ossl_kdf_ctx_create("HKDF", mdname, ...)`.
struct Kdf(*mut EVP_KDF_CTX);

impl Drop for Kdf {
    fn drop(&mut self) {
        // SAFETY: made by `Kdf::new`, or NULL.
        unsafe { EVP_KDF_CTX_free(self.0) };
    }
}

impl Kdf {
    /// `ossl_kdf_ctx_create`: HKDF of the digest, or `None` (with `ERR_R_FETCH_FAILED` when
    /// it can't be fetched).
    fn new(mdname: &CStr, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> Option<Self> {
        // SAFETY: the caller's library context and properties; a static name.
        let kdf = unsafe { EVP_KDF_fetch(libctx, c"HKDF".as_ptr(), propq) };
        if kdf.is_null() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_FETCH_FAILED, "ossl_kdf_ctx_create");
            return None;
        }
        // SAFETY: the method fetched.
        let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
        // SAFETY: as above.
        unsafe { EVP_KDF_free(kdf) };
        if kctx.is_null() {
            return None;
        }
        let k = Kdf(kctx);
        let mut params = vec![
            // SAFETY: a static name; the digest's name, read during the call.
            unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_KDF_PARAM_DIGEST.as_ptr(),
                    mdname.as_ptr().cast_mut(),
                    0,
                )
            },
        ];
        if !propq.is_null() {
            // SAFETY: as above, the properties.
            params.push(unsafe {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_KDF_PARAM_PROPERTIES.as_ptr(),
                    propq.cast_mut(),
                    0,
                )
            });
        }
        // SAFETY: no preconditions.
        params.push(unsafe { OSSL_PARAM_construct_end() });
        // SAFETY: the context; the parameters.
        (unsafe { EVP_KDF_CTX_set_params(k.0, params.as_ptr()) } > 0).then_some(k)
    }

    /// `kdf_derive`: HKDF in `mode` into `out`.
    fn derive(
        &self,
        out: &mut [u8],
        mode: c_int,
        salt: Option<&[u8]>,
        key: &[u8],
        info: Option<&[u8]>,
    ) -> bool {
        let mut mode = mode;
        // SAFETY: a static name; a local that outlives the call.
        let mut params =
            vec![unsafe { OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE.as_ptr(), &raw mut mode) }];
        if let Some(s) = salt {
            // SAFETY: as above, the octets.
            params.push(unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_KDF_PARAM_SALT.as_ptr(),
                    s.as_ptr().cast_mut().cast(),
                    s.len(),
                )
            });
        }
        // SAFETY: as above.
        params.push(unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY.as_ptr(),
                key.as_ptr().cast_mut().cast(),
                key.len(),
            )
        });
        if let Some(i) = info {
            // SAFETY: as above.
            params.push(unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_KDF_PARAM_INFO.as_ptr(),
                    i.as_ptr().cast_mut().cast(),
                    i.len(),
                )
            });
        }
        // SAFETY: no preconditions.
        params.push(unsafe { OSSL_PARAM_construct_end() });
        // SAFETY: the context; room for the output; the parameters.
        let ok =
            unsafe { EVP_KDF_derive(self.0, out.as_mut_ptr(), out.len(), params.as_ptr()) } > 0;
        if !ok {
            err::raise(ERR_LIB_PROV, PROV_R_FAILED_DURING_DERIVATION, "kdf_derive");
        }
        ok
    }

    /// `ossl_hpke_labeled_extract`: `Extract(salt, "HPKE-v1" || protocol || suite || label ||
    /// ikm)` into `out`.
    fn labeled_extract(
        &self,
        out: &mut [u8],
        salt: Option<&[u8]>,
        protocol: &[u8],
        suite: &[u8],
        label: &[u8],
        ikm: &[u8],
    ) -> bool {
        let labeled = Zeroizing::new([LABEL_HPKEV1, protocol, suite, label, ikm].concat());
        self.derive(out, EVP_KDF_HKDF_MODE_EXTRACT_ONLY, salt, &labeled, None)
    }

    /// `ossl_hpke_labeled_expand`: `Expand(prk, I2OSP(L, 2) || "HPKE-v1" || protocol || suite
    /// || label || info, L)`, `L` being `out`'s length.
    fn labeled_expand(
        &self,
        out: &mut [u8],
        prk: &[u8],
        protocol: &[u8],
        suite: &[u8],
        label: &[u8],
        info: &[u8],
    ) -> bool {
        let Ok(len) = u16::try_from(out.len()) else {
            err::raise(
                ERR_LIB_PROV,
                PROV_R_OUTPUT_BUFFER_TOO_SMALL,
                "ossl_hpke_labeled_expand",
            );
            return false;
        };
        let labeled = [
            &len.to_be_bytes()[..],
            LABEL_HPKEV1,
            protocol,
            suite,
            label,
            info,
        ]
        .concat();
        self.derive(
            out,
            EVP_KDF_HKDF_MODE_EXPAND_ONLY,
            None,
            prk,
            Some(&labeled),
        )
    }
}

/// An `EVP_PKEY` this owns.
struct Pkey(*mut EVP_PKEY);

impl Drop for Pkey {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { EVP_PKEY_free(self.0) };
    }
}

/// What a context holds (`struct ossl_hpke_ctx_st`).
struct State {
    libctx: *mut OSSL_LIB_CTX,
    propq: Option<CString>,
    mode: c_int,
    suite: OSSL_HPKE_SUITE,
    aead: &'static AeadInfo,
    aead_ciph: *mut EVP_CIPHER,
    role: c_int,
    seq: u64,
    shared_secret: Option<Zeroizing<Vec<u8>>>,
    key: Option<Zeroizing<Vec<u8>>>,
    nonce: Option<Zeroizing<Vec<u8>>>,
    exportersec: Option<Zeroizing<Vec<u8>>>,
    pskid: Option<CString>,
    psk: Option<Zeroizing<Vec<u8>>>,
    authpriv: Pkey,
    authpub: Option<Vec<u8>>,
    ikme: Option<Zeroizing<Vec<u8>>>,
}

impl Drop for State {
    fn drop(&mut self) {
        // SAFETY: the reference this holds, or NULL.
        unsafe { EVP_CIPHER_free(self.aead_ciph) };
    }
}

impl State {
    fn propq(&self) -> *const c_char {
        self.propq.as_deref().map_or(ptr::null(), CStr::as_ptr)
    }

    /// The suite's six octets, for the key schedule's labels.
    fn suitebuf(&self) -> [u8; 6] {
        let mut b = [0u8; 6];
        b[..2].copy_from_slice(&self.suite.kem_id.to_be_bytes());
        b[2..4].copy_from_slice(&self.suite.kdf_id.to_be_bytes());
        b[4..].copy_from_slice(&self.suite.aead_id.to_be_bytes());
        b
    }

    fn is_auth(&self) -> bool {
        self.mode == OSSL_HPKE_MODE_AUTH || self.mode == OSSL_HPKE_MODE_PSKAUTH
    }
}

/// `OSSL_HPKE_CTX`'s object.
pub(crate) struct Hpke(Mutex<State>);

// SAFETY: the raw pointers are to objects this holds references to (a cipher and a key, both
// safe to share) or to the application's library context; the state is behind a lock.
unsafe impl Send for Hpke {}
// SAFETY: as above.
unsafe impl Sync for Hpke {}

handle_type!(OSSL_HPKE_CTX => Hpke);

impl Hpke {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The context behind a handle.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn hctx<'a>(ctx: *mut OSSL_HPKE_CTX) -> Option<&'a Hpke> {
    // SAFETY: the caller's guarantee.
    unsafe { OSSL_HPKE_CTX::get(ctx) }
}

fn invalid(f: &str) {
    err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT, f);
}

fn internal(f: &str) {
    err::raise(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR, f);
}

fn not_now(f: &str) {
    err::raise(ERR_LIB_CRYPTO, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, f);
}

/// The C string's octets (up to its NUL), or `None` for NULL.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn c_str<'a>(s: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the caller's guarantee.
    (!s.is_null()).then(|| unsafe { CStr::from_ptr(s) })
}

ffi_export! {
    /// A new HPKE context of the mode (base, psk, auth, or psk-auth), suite, and role (sender
    /// or receiver), with the suite's AEAD fetched (unless it's export-only); NULL with
    /// `ERR_R_PASSED_INVALID_ARGUMENT` for a mode, suite, or role there's none of.
    ///
    /// # Safety
    /// `libctx` is NULL or live; `propq` is NULL or a C string.
    pub unsafe extern "C" fn OSSL_HPKE_CTX_new(mode: c_int, suite: OSSL_HPKE_SUITE, role: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut OSSL_HPKE_CTX
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_CTX_new";
        if !matches!(mode, OSSL_HPKE_MODE_BASE | OSSL_HPKE_MODE_PSK | OSSL_HPKE_MODE_AUTH | OSSL_HPKE_MODE_PSKAUTH) {
            invalid(F);
            return ptr::null_mut();
        }
        let Some((_, _, aead)) = suite_infos(suite) else {
            invalid(F);
            return ptr::null_mut();
        };
        if role != OSSL_HPKE_ROLE_SENDER && role != OSSL_HPKE_ROLE_RECEIVER {
            invalid(F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let propq = unsafe { c_str(propq) }.map(CStr::to_owned);
        let mut aead_ciph = ptr::null_mut();
        if c_int::from(suite.aead_id) != OSSL_HPKE_AEAD_ID_EXPORTONLY {
            let name = aead.name.unwrap_or(c"");
            // SAFETY: the caller's library context; the cipher's name; the properties.
            aead_ciph = unsafe { EVP_CIPHER_fetch(libctx, name.as_ptr(), propq.as_deref().map_or(ptr::null(), CStr::as_ptr)) };
            if aead_ciph.is_null() {
                err::raise(ERR_LIB_CRYPTO, ERR_R_FETCH_FAILED, F);
                return ptr::null_mut();
            }
        }
        OSSL_HPKE_CTX::new_handle(Hpke(Mutex::new(State {
            libctx,
            propq,
            mode,
            suite,
            aead,
            aead_ciph,
            role,
            seq: 0,
            shared_secret: None,
            key: None,
            nonce: None,
            exportersec: None,
            pskid: None,
            psk: None,
            authpriv: Pkey(ptr::null_mut()),
            authpub: None,
            ikme: None,
        })))
    }
}

ffi_export! {
    /// Frees the context and wipes its secrets (NULL does nothing).
    ///
    /// # Safety
    /// `ctx` is NULL or a context the caller gives up.
    pub unsafe extern "C" fn OSSL_HPKE_CTX_free(ctx: *mut OSSL_HPKE_CTX)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { OSSL_HPKE_CTX::free(ctx) };
    }
}

ffi_export! {
    /// Sets the pre-shared key (32 to 66 octets) and its identifier (1 to 66 characters) of a
    /// psk or psk-auth context: 1, or 0 with `ERR_R_PASSED_INVALID_ARGUMENT`.
    ///
    /// # Safety
    /// `ctx` is NULL or live; `pskid` is NULL or a C string; `psk` is NULL or holds `psklen`
    /// octets.
    pub unsafe extern "C" fn OSSL_HPKE_CTX_set1_psk(ctx: *mut OSSL_HPKE_CTX, pskid: *const c_char, psk: *const c_uchar, psklen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_CTX_set1_psk";
        // SAFETY: the caller's guarantee.
        let (Some(h), Some(id)) = (unsafe { hctx(ctx) }, unsafe { c_str(pskid) }) else {
            invalid(F);
            return 0;
        };
        let max = usize::try_from(OSSL_HPKE_MAX_PARMLEN).unwrap_or(0);
        let min = usize::try_from(OSSL_HPKE_MIN_PSKLEN).unwrap_or(0);
        if psk.is_null() || psklen == 0 || psklen > max || psklen < min || id.to_bytes().len() > max || id.to_bytes().is_empty() {
            invalid(F);
            return 0;
        }
        let mut s = h.lock();
        if s.mode != OSSL_HPKE_MODE_PSK && s.mode != OSSL_HPKE_MODE_PSKAUTH {
            invalid(F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { bytes(psk, psklen) }) else { return 0 };
        s.psk = Some(Zeroizing::new(p.to_vec()));
        s.pskid = Some(id.to_owned());
        1
    }
}

ffi_export! {
    /// Sets a sender's input key material for its ephemeral key (1 to 66 octets), which makes
    /// its encapsulation deterministic: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or live; `ikme` is NULL or holds `ikmelen` octets.
    pub unsafe extern "C" fn OSSL_HPKE_CTX_set1_ikme(ctx: *mut OSSL_HPKE_CTX, ikme: *const c_uchar, ikmelen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_CTX_set1_ikme";
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hctx(ctx) }).filter(|_| !ikme.is_null()) else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        if ikmelen == 0 || ikmelen > usize::try_from(OSSL_HPKE_MAX_PARMLEN).unwrap_or(0) {
            invalid(F);
            return 0;
        }
        let mut s = h.lock();
        if s.role != OSSL_HPKE_ROLE_SENDER {
            invalid(F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { bytes(ikme, ikmelen) }) else { return 0 };
        s.ikme = Some(Zeroizing::new(k.to_vec()));
        1
    }
}

ffi_export! {
    /// Sets an auth or psk-auth sender's private authentication key (a copy): 1, or 0.
    ///
    /// # Safety
    /// `ctx` and `priv_` are NULL or live.
    pub unsafe extern "C" fn OSSL_HPKE_CTX_set1_authpriv(ctx: *mut OSSL_HPKE_CTX, priv_: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_CTX_set1_authpriv";
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hctx(ctx) }).filter(|_| !priv_.is_null()) else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        let mut s = h.lock();
        if !s.is_auth() || s.role != OSSL_HPKE_ROLE_SENDER {
            invalid(F);
            return 0;
        }
        s.authpriv = Pkey(ptr::null_mut());
        // SAFETY: the caller's key.
        s.authpriv = Pkey(unsafe { EVP_PKEY_dup(priv_) });
        c_int::from(!s.authpriv.0.is_null())
    }
}

/// A public key of the KEM's type from its encoding: a NIST curve's point through parameter
/// generation (`evp_pkey_new_raw_nist_public_key`), an ECX key raw; NULL on failure.
///
/// # Safety
/// `s`'s library context is NULL or live.
unsafe fn public_key(s: &State, kem: &KemInfo, pub_: &[u8]) -> *mut EVP_PKEY {
    let Some(group) = kem.groupname else {
        // SAFETY: the context's library context and properties; the key's octets.
        return unsafe {
            EVP_PKEY_new_raw_public_key_ex(
                s.libctx,
                kem.keytype.as_ptr(),
                s.propq(),
                pub_.as_ptr(),
                pub_.len(),
            )
        };
    };
    // SAFETY: as above.
    let cctx = unsafe { EVP_PKEY_CTX_new_from_name(s.libctx, c"EC".as_ptr(), s.propq()) };
    let params = [
        // SAFETY: a static name and group.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME.as_ptr(),
                group.as_ptr().cast_mut(),
                0,
            )
        },
        // SAFETY: no preconditions.
        unsafe { OSSL_PARAM_construct_end() },
    ];
    let mut ret = ptr::null_mut();
    let ok = !cctx.is_null()
        // SAFETY: the context.
        && unsafe { EVP_PKEY_paramgen_init(cctx) } > 0
        // SAFETY: as above, the parameters.
        && unsafe { EVP_PKEY_CTX_set_params(cctx, params.as_ptr()) } > 0
        // SAFETY: as above, a place for the key.
        && unsafe { EVP_PKEY_paramgen(cctx, &raw mut ret) } > 0
        // SAFETY: the key made; the octets.
        && unsafe { EVP_PKEY_set1_encoded_public_key(ret, pub_.as_ptr(), pub_.len()) } == 1;
    // SAFETY: made above, or NULL.
    unsafe { EVP_PKEY_CTX_free(cctx) };
    if !ok {
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(ret) };
        internal("evp_pkey_new_raw_nist_public_key");
        return ptr::null_mut();
    }
    ret
}

ffi_export! {
    /// Sets an auth or psk-auth receiver's sender's public key (its encoding, checked by
    /// making a key of it): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or live; `pub_` is NULL or holds `publen` octets.
    pub unsafe extern "C" fn OSSL_HPKE_CTX_set1_authpub(ctx: *mut OSSL_HPKE_CTX, pub_: *const c_uchar, publen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_CTX_set1_authpub";
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hctx(ctx) }).filter(|_| !pub_.is_null() && publen != 0) else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        let mut s = h.lock();
        if !s.is_auth() || s.role != OSSL_HPKE_ROLE_RECEIVER {
            invalid(F);
            return 0;
        }
        let Some(kem) = kem_by_id(s.suite.kem_id) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { bytes(pub_, publen) }) else { return 0 };
        // SAFETY: the context's library context.
        let pubp = Pkey(unsafe { public_key(&s, kem, p) });
        if pubp.0.is_null() {
            invalid(F);
            return 0;
        }
        let mut lpub = vec![0u8; MAXSIZE];
        let mut lpublen = 0;
        // SAFETY: the key made; room for `MAXSIZE`; a local for the length.
        if unsafe { EVP_PKEY_get_octet_string_param(pubp.0, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr(), lpub.as_mut_ptr(), MAXSIZE, &raw mut lpublen) } != 1 {
            internal(F);
            return 0;
        }
        lpub.truncate(lpublen);
        s.authpub = Some(lpub);
        1
    }
}

ffi_export! {
    /// The context's sequence number: 1, or 0 with `ERR_R_PASSED_NULL_PARAMETER`.
    ///
    /// # Safety
    /// `ctx` is NULL or live; `seq` is NULL or a live `uint64_t`.
    pub unsafe extern "C" fn OSSL_HPKE_CTX_get_seq(ctx: *mut OSSL_HPKE_CTX, seq: *mut u64) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let (Some(h), Some(out)) = (unsafe { hctx(ctx) }, unsafe { seq.as_mut() }) else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, "OSSL_HPKE_CTX_get_seq");
            return 0;
        };
        *out = h.lock().seq;
        1
    }
}

ffi_export! {
    /// Sets a receiver's sequence number (a sender's can't be): 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or live.
    pub unsafe extern "C" fn OSSL_HPKE_CTX_set_seq(ctx: *mut OSSL_HPKE_CTX, seq: u64) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hctx(ctx) }) else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, "OSSL_HPKE_CTX_set_seq");
            return 0;
        };
        let mut s = h.lock();
        if s.role == OSSL_HPKE_ROLE_SENDER {
            invalid("OSSL_HPKE_CTX_set_seq");
            return 0;
        }
        s.seq = seq;
        1
    }
}

/// An `EVP_PKEY_CTX` this owns.
struct PkeyCtx(*mut rustyssl_abi::EVP_PKEY_CTX);

impl Drop for PkeyCtx {
    fn drop(&mut self) {
        // SAFETY: made here, or NULL.
        unsafe { EVP_PKEY_CTX_free(self.0) };
    }
}

/// `hpke_encap`: the shared secret of an encapsulation to the recipient's public key (the
/// ephemeral key from the context's `ikme`, the sender's authentication key in the auth
/// modes), its encapsulated key into `enc`.
///
/// # Safety
/// `enc` has room for `*enclen` octets.
unsafe fn hpke_encap(s: &mut State, enc: *mut c_uchar, enclen: &mut usize, pub_: &[u8]) -> bool {
    const F: &str = "hpke_encap";
    if s.shared_secret.is_some() {
        not_now(F);
        return false;
    }
    let Some(kem) = kem_by_id(s.suite.kem_id) else {
        internal(F);
        return false;
    };
    // SAFETY: the context's library context.
    let pk_r = Pkey(unsafe { public_key(s, kem, pub_) });
    if pk_r.0.is_null() {
        internal(F);
        return false;
    }
    // SAFETY: as above, the key.
    let pctx = PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_pkey(s.libctx, pk_r.0, s.propq()) });
    if pctx.0.is_null() {
        internal(F);
        return false;
    }
    let mut params = vec![
        // SAFETY: static strings.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_KEM_PARAM_OPERATION.as_ptr(),
                OSSL_KEM_PARAM_OPERATION_DHKEM.as_ptr().cast_mut(),
                0,
            )
        },
    ];
    if let Some(ikme) = &s.ikme {
        // SAFETY: a static name; the octets, read during the initialization.
        params.push(unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_KEM_PARAM_IKME.as_ptr(),
                ikme.as_ptr().cast_mut().cast(),
                ikme.len(),
            )
        });
    }
    // SAFETY: no preconditions.
    params.push(unsafe { OSSL_PARAM_construct_end() });
    let init = if s.is_auth() {
        // SAFETY: the context; the authentication key (or NULL); the parameters.
        unsafe { EVP_PKEY_auth_encapsulate_init(pctx.0, s.authpriv.0, params.as_ptr()) }
    } else {
        // SAFETY: as above.
        unsafe { EVP_PKEY_encapsulate_init(pctx.0, params.as_ptr()) }
    };
    if init != 1 {
        internal(F);
        return false;
    }
    let mut lenclen = *enclen;
    let mut lsslen = 0;
    // SAFETY: the context; locals for the lengths.
    if unsafe {
        EVP_PKEY_encapsulate(
            pctx.0,
            ptr::null_mut(),
            &raw mut lenclen,
            ptr::null_mut(),
            &raw mut lsslen,
        )
    } != 1
    {
        internal(F);
        return false;
    }
    if lenclen > *enclen {
        invalid(F);
        return false;
    }
    let mut secret = Zeroizing::new(vec![0u8; lsslen]);
    let mut sslen = lsslen;
    // SAFETY: the context; the caller's room; the secret's room.
    if unsafe { EVP_PKEY_encapsulate(pctx.0, enc, enclen, secret.as_mut_ptr(), &raw mut sslen) }
        != 1
    {
        internal(F);
        return false;
    }
    secret.truncate(sslen);
    s.shared_secret = Some(secret);
    true
}

/// `hpke_decap`: the shared secret of the encapsulated key with the recipient's private key
/// (and the sender's public authentication key in the auth modes).
///
/// # Safety
/// `priv_` is a live key.
unsafe fn hpke_decap(s: &mut State, enc: &[u8], priv_: *mut EVP_PKEY) -> bool {
    const F: &str = "hpke_decap";
    if s.shared_secret.is_some() {
        not_now(F);
        return false;
    }
    // SAFETY: the context's library context; the caller's key.
    let pctx = PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_pkey(s.libctx, priv_, s.propq()) });
    if pctx.0.is_null() {
        internal(F);
        return false;
    }
    let params = [
        // SAFETY: static strings.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_KEM_PARAM_OPERATION.as_ptr(),
                OSSL_KEM_PARAM_OPERATION_DHKEM.as_ptr().cast_mut(),
                0,
            )
        },
        // SAFETY: no preconditions.
        unsafe { OSSL_PARAM_construct_end() },
    ];
    let mut spub = Pkey(ptr::null_mut());
    let init = if s.is_auth() {
        let Some(kem) = kem_by_id(s.suite.kem_id) else {
            internal(F);
            return false;
        };
        let authpub = s.authpub.clone().unwrap_or_default();
        // SAFETY: the context's library context.
        spub = Pkey(unsafe { public_key(s, kem, &authpub) });
        if spub.0.is_null() {
            internal(F);
            return false;
        }
        // SAFETY: the context; the sender's key; the parameters.
        unsafe { EVP_PKEY_auth_decapsulate_init(pctx.0, spub.0, params.as_ptr()) }
    } else {
        // SAFETY: as above.
        unsafe { EVP_PKEY_decapsulate_init(pctx.0, params.as_ptr()) }
    };
    if init != 1 {
        internal(F);
        return false;
    }
    let mut lsslen = 0;
    // SAFETY: the context; a local for the length; the encapsulated key.
    if unsafe {
        EVP_PKEY_decapsulate(
            pctx.0,
            ptr::null_mut(),
            &raw mut lsslen,
            enc.as_ptr(),
            enc.len(),
        )
    } != 1
    {
        internal(F);
        return false;
    }
    let mut secret = Zeroizing::new(vec![0u8; lsslen]);
    // SAFETY: as above, the secret's room.
    if unsafe {
        EVP_PKEY_decapsulate(
            pctx.0,
            secret.as_mut_ptr(),
            &raw mut lsslen,
            enc.as_ptr(),
            enc.len(),
        )
    } != 1
    {
        internal(F);
        return false;
    }
    secret.truncate(lsslen);
    s.shared_secret = Some(secret);
    drop(spub);
    true
}

/// `hpke_do_middle`: the key schedule (RFC 9180, 5.1) from the shared secret, the info, and
/// the pre-shared key: the AEAD's key and base nonce (unless export-only) and the exporter
/// secret.
fn do_middle(s: &mut State, info: &[u8]) -> bool {
    const F: &str = "hpke_do_middle";
    if s.exportersec.is_some() {
        not_now(F);
        return false;
    }
    if kem_by_id(s.suite.kem_id).is_none() {
        internal(F);
        return false;
    }
    let Some(aead) = aead_by_id(s.suite.aead_id) else {
        internal(F);
        return false;
    };
    let Some(kdf) = kdf_by_id(s.suite.kdf_id) else {
        internal(F);
        return false;
    };
    let halflen = kdf.nh;
    if 2 * halflen > MAXSIZE - 1 {
        internal(F);
        return false;
    }
    if (s.mode == OSSL_HPKE_MODE_PSK || s.mode == OSSL_HPKE_MODE_PSKAUTH)
        && (s.psk.as_ref().is_none_or(|p| p.is_empty()) || s.pskid.is_none())
    {
        invalid(F);
        return false;
    }
    let Some(kctx) = Kdf::new(kdf.mdname, s.libctx, s.propq()) else {
        internal(F);
        return false;
    };
    let pskid: &[u8] = if s.psk.is_none() {
        &[]
    } else {
        s.pskid.as_deref().map_or(&[], CStr::to_bytes)
    };
    let suite = s.suitebuf();
    let mut ks_context = Zeroizing::new(vec![0u8; 1 + 2 * halflen]);
    let Some((mode, hashes)) = ks_context.split_first_mut() else {
        return false;
    };
    *mode = u8::try_from(s.mode % 256).unwrap_or(0);
    let (psk_id_hash, info_hash) = hashes.split_at_mut(halflen);
    if !kctx.labeled_extract(psk_id_hash, None, SEC51, &suite, b"psk_id_hash", pskid) {
        internal(F);
        return false;
    }
    if !kctx.labeled_extract(info_hash, None, SEC51, &suite, b"info_hash", info) {
        internal(F);
        return false;
    }
    let mut secret = Zeroizing::new(vec![0u8; kdf.nh]);
    let shared: &[u8] = s.shared_secret.as_deref().map_or(&[], |v| v);
    let psk: &[u8] = s.psk.as_deref().map_or(&[], |v| v);
    // The shared secret is the salt (NULL, so no salt, before an encapsulation).
    let salt = s.shared_secret.as_ref().map(|_| shared);
    if !kctx.labeled_extract(&mut secret, salt, SEC51, &suite, b"secret", psk) {
        internal(F);
        return false;
    }
    if c_int::from(s.suite.aead_id) != OSSL_HPKE_AEAD_ID_EXPORTONLY {
        let mut nonce = Zeroizing::new(vec![0u8; aead.nn]);
        if !kctx.labeled_expand(
            &mut nonce,
            &secret,
            SEC51,
            &suite,
            b"base_nonce",
            &ks_context,
        ) {
            internal(F);
            return false;
        }
        s.nonce = Some(nonce);
        let mut key = Zeroizing::new(vec![0u8; aead.nk]);
        if !kctx.labeled_expand(&mut key, &secret, SEC51, &suite, b"key", &ks_context) {
            internal(F);
            return false;
        }
        s.key = Some(key);
    }
    let mut exp = Zeroizing::new(vec![0u8; kdf.nh]);
    if !kctx.labeled_expand(&mut exp, &secret, SEC51, &suite, b"exp", &ks_context) {
        internal(F);
        return false;
    }
    s.exportersec = Some(exp);
    true
}

/// The info's octets: none for NULL with length 0; `None` (with the error) for more than
/// `OSSL_HPKE_MAX_INFOLEN` or NULL with a length.
///
/// # Safety
/// `info` is NULL or holds `infolen` octets.
unsafe fn info_of<'a>(info: *const c_uchar, infolen: usize, f: &str) -> Option<&'a [u8]> {
    if infolen > usize::try_from(OSSL_HPKE_MAX_INFOLEN).unwrap_or(0)
        || (infolen > 0 && info.is_null())
    {
        invalid(f);
        return None;
    }
    // SAFETY: the caller's guarantee.
    unsafe { bytes(info, infolen) }
}

ffi_export! {
    /// A sender's encapsulation to the recipient's public key: the encapsulated key into
    /// `enc` (with room for `*enclen` octets, at least the suite's), then the key schedule
    /// over `info`: 1, or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or live; `enc` is NULL or has room for `*enclen` octets; `enclen` is NULL
    /// or live; `pub_` holds `publen` octets; `info` is NULL or holds `infolen`.
    pub unsafe extern "C" fn OSSL_HPKE_encap(ctx: *mut OSSL_HPKE_CTX, enc: *mut c_uchar, enclen: *mut usize, pub_: *const c_uchar, publen: usize, info: *const c_uchar, infolen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_encap";
        // SAFETY: the caller's guarantee.
        let (Some(h), Some(el)) = (unsafe { hctx(ctx) }, unsafe { enclen.as_mut() }) else {
            invalid(F);
            return 0;
        };
        if enc.is_null() || *el == 0 || pub_.is_null() || publen == 0 {
            invalid(F);
            return 0;
        }
        let mut s = h.lock();
        if s.role != OSSL_HPKE_ROLE_SENDER {
            invalid(F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(info) = (unsafe { info_of(info, infolen, F) }) else { return 0 };
        let minenc = public_encap_size(s.suite);
        if minenc == 0 || minenc > *el {
            invalid(F);
            return 0;
        }
        if s.shared_secret.is_some() {
            not_now(F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(p) = (unsafe { bytes(pub_, publen) }) else { return 0 };
        // SAFETY: the caller's room.
        if !unsafe { hpke_encap(&mut s, enc, el, p) } {
            internal(F);
            return 0;
        }
        c_int::from(do_middle(&mut s, info))
    }
}

ffi_export! {
    /// A receiver's decapsulation of the encapsulated key with its private key, then the key
    /// schedule over `info`: 1, or 0.
    ///
    /// # Safety
    /// `ctx` and `recippriv` are NULL or live; `enc` holds `enclen` octets; `info` is NULL or
    /// holds `infolen`.
    pub unsafe extern "C" fn OSSL_HPKE_decap(ctx: *mut OSSL_HPKE_CTX, enc: *const c_uchar, enclen: usize, recippriv: *mut EVP_PKEY, info: *const c_uchar, infolen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_decap";
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hctx(ctx) }) else {
            invalid(F);
            return 0;
        };
        if enc.is_null() || enclen == 0 || recippriv.is_null() {
            invalid(F);
            return 0;
        }
        let mut s = h.lock();
        if s.role != OSSL_HPKE_ROLE_RECEIVER {
            invalid(F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(info) = (unsafe { info_of(info, infolen, F) }) else { return 0 };
        let minenc = public_encap_size(s.suite);
        if minenc == 0 || minenc > enclen {
            invalid(F);
            return 0;
        }
        if s.shared_secret.is_some() {
            not_now(F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(e) = (unsafe { bytes(enc, enclen) }) else { return 0 };
        // SAFETY: the caller's key.
        if !unsafe { hpke_decap(&mut s, e, recippriv) } {
            internal(F);
            return 0;
        }
        c_int::from(do_middle(&mut s, info))
    }
}

/// `hpke_seqnonce2buf`: the base nonce XORed with the sequence number.
fn seqnonce(s: &State) -> Option<[u8; MAX_NONCELEN]> {
    let nonce = s.nonce.as_ref()?;
    if nonce.len() != MAX_NONCELEN {
        return None;
    }
    let mut buf = [0u8; MAX_NONCELEN];
    buf[MAX_NONCELEN - 8..].copy_from_slice(&s.seq.to_be_bytes());
    for (b, n) in buf.iter_mut().zip(nonce.iter()) {
        *b ^= n;
    }
    Some(buf)
}

/// An `EVP_CIPHER_CTX` this owns.
struct CipherCtx(*mut rustyssl_abi::EVP_CIPHER_CTX);

impl Drop for CipherCtx {
    fn drop(&mut self) {
        // SAFETY: made here, or NULL.
        unsafe { EVP_CIPHER_CTX_free(self.0) };
    }
}

/// `hpke_aead_enc`: the plaintext sealed with the AEAD under the key and `iv`, the tag after
/// it, into `ct` (with room for `*ctlen`, more than the tag and at least the plaintext with
/// it); wiped on failure.
///
/// # Safety
/// `ct` has room for `*ctlen` octets.
unsafe fn aead_enc(
    s: &State,
    iv: &[u8],
    aad: Option<&[u8]>,
    pt: &[u8],
    ct: *mut c_uchar,
    ctlen: &mut usize,
) -> bool {
    const F: &str = "hpke_aead_enc";
    let taglen = s.aead.taglen;
    if *ctlen <= taglen || pt.len() > *ctlen - taglen {
        invalid(F);
        return false;
    }
    // SAFETY: no preconditions.
    let c = CipherCtx(unsafe { EVP_CIPHER_CTX_new() });
    if c.0.is_null() {
        return false;
    }
    let key = s.key.as_deref().map_or(ptr::null(), |k| k.as_ptr());
    let (Ok(noncelen), Ok(ptl), Ok(tl)) = (
        c_int::try_from(MAX_NONCELEN),
        c_int::try_from(pt.len()),
        c_int::try_from(taglen),
    ) else {
        return false;
    };
    let mut len = 0;
    let ok = 'out: {
        // SAFETY: the context; the context's cipher.
        if unsafe { EVP_EncryptInit_ex(c.0, s.aead_ciph, ptr::null_mut(), ptr::null(), ptr::null()) } != 1
            // SAFETY: as above.
            || unsafe { EVP_CIPHER_CTX_ctrl(c.0, EVP_CTRL_AEAD_SET_IVLEN, noncelen, ptr::null_mut()) } != 1
            // SAFETY: as above, the key and IV.
            || unsafe { EVP_EncryptInit_ex(c.0, ptr::null(), ptr::null_mut(), key, iv.as_ptr()) } != 1
        {
            internal(F);
            break 'out false;
        }
        if let Some(a) = aad.filter(|a| !a.is_empty()) {
            let Ok(al) = c_int::try_from(a.len()) else {
                break 'out false;
            };
            // SAFETY: as above, the AAD.
            if unsafe { EVP_EncryptUpdate(c.0, ptr::null_mut(), &raw mut len, a.as_ptr(), al) } != 1
            {
                internal(F);
                break 'out false;
            }
        }
        // SAFETY: as above; room for the plaintext.
        if unsafe { EVP_EncryptUpdate(c.0, ct, &raw mut len, pt.as_ptr(), ptl) } != 1 {
            internal(F);
            break 'out false;
        }
        *ctlen = usize::try_from(len).unwrap_or(0);
        // SAFETY: as above, after what was written.
        if unsafe { EVP_EncryptFinal_ex(c.0, ct.wrapping_add(*ctlen), &raw mut len) } != 1 {
            internal(F);
            break 'out false;
        }
        *ctlen += usize::try_from(len).unwrap_or(0);
        // SAFETY: as above; room for the tag after the ciphertext.
        if unsafe {
            EVP_CIPHER_CTX_ctrl(
                c.0,
                EVP_CTRL_AEAD_GET_TAG,
                tl,
                ct.wrapping_add(*ctlen).cast(),
            )
        } != 1
        {
            internal(F);
            break 'out false;
        }
        *ctlen += taglen;
        true
    };
    if !ok {
        // SAFETY: the caller's room.
        unsafe { ptr::write_bytes(ct, 0, *ctlen) };
    }
    ok
}

/// `hpke_aead_dec`: the ciphertext (its tag last) opened with the AEAD into `pt` (with room
/// for `*ptlen`, at least the ciphertext without the tag); wiped on failure.
///
/// # Safety
/// `pt` has room for `*ptlen` octets.
unsafe fn aead_dec(
    s: &State,
    iv: &[u8],
    aad: Option<&[u8]>,
    ct: &[u8],
    pt: *mut c_uchar,
    ptlen: &mut usize,
) -> bool {
    const F: &str = "hpke_aead_dec";
    let taglen = s.aead.taglen;
    if ct.len() <= taglen || *ptlen < ct.len() - taglen {
        invalid(F);
        return false;
    }
    // SAFETY: no preconditions.
    let c = CipherCtx(unsafe { EVP_CIPHER_CTX_new() });
    if c.0.is_null() {
        return false;
    }
    let key = s.key.as_deref().map_or(ptr::null(), |k| k.as_ptr());
    let (body, tag) = ct.split_at(ct.len() - taglen);
    let (Ok(noncelen), Ok(bl), Ok(tl)) = (
        c_int::try_from(MAX_NONCELEN),
        c_int::try_from(body.len()),
        c_int::try_from(taglen),
    ) else {
        return false;
    };
    let mut len = 0;
    let ok = 'out: {
        // SAFETY: the context; the context's cipher.
        if unsafe { EVP_DecryptInit_ex(c.0, s.aead_ciph, ptr::null_mut(), ptr::null(), ptr::null()) } != 1
            // SAFETY: as above.
            || unsafe { EVP_CIPHER_CTX_ctrl(c.0, EVP_CTRL_AEAD_SET_IVLEN, noncelen, ptr::null_mut()) } != 1
            // SAFETY: as above, the key and IV.
            || unsafe { EVP_DecryptInit_ex(c.0, ptr::null(), ptr::null_mut(), key, iv.as_ptr()) } != 1
        {
            internal(F);
            break 'out false;
        }
        if let Some(a) = aad.filter(|a| !a.is_empty()) {
            let Ok(al) = c_int::try_from(a.len()) else {
                break 'out false;
            };
            // SAFETY: as above, the AAD.
            if unsafe { EVP_DecryptUpdate(c.0, ptr::null_mut(), &raw mut len, a.as_ptr(), al) } != 1
            {
                internal(F);
                break 'out false;
            }
        }
        // SAFETY: as above; room for the plaintext.
        if unsafe { EVP_DecryptUpdate(c.0, pt, &raw mut len, body.as_ptr(), bl) } != 1 {
            internal(F);
            break 'out false;
        }
        *ptlen = usize::try_from(len).unwrap_or(0);
        // SAFETY: as above, the tag (which the cipher copies).
        if unsafe {
            EVP_CIPHER_CTX_ctrl(
                c.0,
                EVP_CTRL_AEAD_SET_TAG,
                tl,
                tag.as_ptr().cast_mut().cast(),
            )
        } == 0
        {
            internal(F);
            break 'out false;
        }
        // SAFETY: as above, after what was written.
        if unsafe { EVP_DecryptFinal_ex(c.0, pt.wrapping_add(*ptlen), &raw mut len) } <= 0 {
            internal(F);
            break 'out false;
        }
        true
    };
    if !ok {
        // SAFETY: the caller's room.
        unsafe { ptr::write_bytes(pt, 0, *ptlen) };
    }
    ok
}

ffi_export! {
    /// A sender's AEAD encryption of the plaintext with the AAD under the next nonce, the
    /// ciphertext and tag into `ct` (with room for `*ctlen`): 1 (and the sequence number
    /// moves on), or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or live; `ct` is NULL or has room for `*ctlen` octets; `ctlen` is NULL or
    /// live; `aad` is NULL or holds `aadlen` octets; `pt` holds `ptlen`.
    pub unsafe extern "C" fn OSSL_HPKE_seal(ctx: *mut OSSL_HPKE_CTX, ct: *mut c_uchar, ctlen: *mut usize, aad: *const c_uchar, aadlen: usize, pt: *const c_uchar, ptlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_seal";
        // SAFETY: the caller's guarantee.
        let (Some(h), Some(cl)) = (unsafe { hctx(ctx) }, unsafe { ctlen.as_mut() }) else {
            invalid(F);
            return 0;
        };
        if ct.is_null() || *cl == 0 || pt.is_null() || ptlen == 0 {
            invalid(F);
            return 0;
        }
        let mut s = h.lock();
        if s.role != OSSL_HPKE_ROLE_SENDER {
            invalid(F);
            return 0;
        }
        if s.seq.wrapping_add(1) == 0 {
            not_now(F);
            return 0;
        }
        if s.key.is_none() || s.nonce.is_none() {
            invalid(F);
            return 0;
        }
        let Some(iv) = seqnonce(&s) else {
            internal(F);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let (Some(p), a) = (unsafe { bytes(pt, ptlen) }, unsafe { bytes(aad, aadlen) }) else { return 0 };
        let a = if aad.is_null() { None } else { a };
        // SAFETY: the caller's room.
        if !unsafe { aead_enc(&s, &iv, a, p, ct, cl) } {
            internal(F);
            return 0;
        }
        s.seq += 1;
        1
    }
}

ffi_export! {
    /// A receiver's AEAD decryption of the ciphertext (its tag last) with the AAD under the
    /// next nonce into `pt` (with room for `*ptlen`): 1 (and the sequence number moves on),
    /// or 0.
    ///
    /// # Safety
    /// `ctx` is NULL or live; `pt` is NULL or has room for `*ptlen` octets; `ptlen` is NULL or
    /// live; `aad` is NULL or holds `aadlen` octets; `ct` holds `ctlen`.
    pub unsafe extern "C" fn OSSL_HPKE_open(ctx: *mut OSSL_HPKE_CTX, pt: *mut c_uchar, ptlen: *mut usize, aad: *const c_uchar, aadlen: usize, ct: *const c_uchar, ctlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_open";
        // SAFETY: the caller's guarantee.
        let (Some(h), Some(pl)) = (unsafe { hctx(ctx) }, unsafe { ptlen.as_mut() }) else {
            invalid(F);
            return 0;
        };
        if pt.is_null() || *pl == 0 || ct.is_null() || ctlen == 0 {
            invalid(F);
            return 0;
        }
        let mut s = h.lock();
        if s.role != OSSL_HPKE_ROLE_RECEIVER {
            invalid(F);
            return 0;
        }
        if s.seq.wrapping_add(1) == 0 {
            not_now(F);
            return 0;
        }
        if s.key.is_none() || s.nonce.is_none() {
            invalid(F);
            return 0;
        }
        let Some(iv) = seqnonce(&s) else {
            internal(F);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let (Some(c), a) = (unsafe { bytes(ct, ctlen) }, unsafe { bytes(aad, aadlen) }) else { return 0 };
        let a = if aad.is_null() { None } else { a };
        // SAFETY: the caller's room.
        if !unsafe { aead_dec(&s, &iv, a, c, pt, pl) } {
            internal(F);
            return 0;
        }
        s.seq += 1;
        1
    }
}

ffi_export! {
    /// A secret of `secretlen` octets exported from the context under the label (at most 66
    /// octets): 1, or 0 (before the key schedule, `ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED`).
    ///
    /// # Safety
    /// `ctx` is NULL or live; `secret` is NULL or has room for `secretlen` octets; `label` is
    /// NULL or holds `labellen`.
    pub unsafe extern "C" fn OSSL_HPKE_export(ctx: *mut OSSL_HPKE_CTX, secret: *mut c_uchar, secretlen: usize, label: *const c_uchar, labellen: usize) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_export";
        // SAFETY: the caller's guarantee.
        let Some(h) = (unsafe { hctx(ctx) }) else {
            invalid(F);
            return 0;
        };
        if secret.is_null() || secretlen == 0 || labellen > usize::try_from(OSSL_HPKE_MAX_PARMLEN).unwrap_or(0) || (labellen > 0 && label.is_null()) {
            invalid(F);
            return 0;
        }
        let s = h.lock();
        let Some(exp) = s.exportersec.as_ref() else {
            not_now(F);
            return 0;
        };
        let Some(kdf) = kdf_by_id(s.suite.kdf_id) else {
            internal(F);
            return 0;
        };
        let Some(kctx) = Kdf::new(kdf.mdname, s.libctx, s.propq()) else {
            internal(F);
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let Some(l) = (unsafe { bytes(label, labellen) }) else { return 0 };
        // SAFETY: the caller's room for `secretlen`.
        let out = unsafe { core::slice::from_raw_parts_mut(secret, secretlen) };
        let ok = kctx.labeled_expand(out, exp, SEC51, &s.suitebuf(), b"sec", l);
        if !ok {
            internal(F);
        }
        c_int::from(ok)
    }
}

ffi_export! {
    /// A key pair for the suite's KEM (from the input key material when given, at most 66
    /// octets): the private key into `*priv_` and the encoded public key into `pub_` (with
    /// room for `*publen`): 1, or 0.
    ///
    /// # Safety
    /// `pub_` is NULL or has room for `*publen` octets; `publen` and `priv_` are NULL or live;
    /// `ikm` is NULL or holds `ikmlen`; `libctx` is NULL or live; `propq` is NULL or a C
    /// string.
    pub unsafe extern "C" fn OSSL_HPKE_keygen(suite: OSSL_HPKE_SUITE, pub_: *mut c_uchar, publen: *mut usize, priv_: *mut *mut EVP_PKEY, ikm: *const c_uchar, ikmlen: usize, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_keygen";
        // SAFETY: the caller's guarantee.
        let (Some(pl), Some(out)) = (unsafe { publen.as_mut() }, unsafe { priv_.as_mut() }) else {
            invalid(F);
            return 0;
        };
        if pub_.is_null() || *pl == 0 {
            invalid(F);
            return 0;
        }
        let Some((kem, _, _)) = suite_infos(suite) else {
            invalid(F);
            return 0;
        };
        if (ikmlen > 0 && ikm.is_null()) || (ikmlen == 0 && !ikm.is_null()) || ikmlen > usize::try_from(OSSL_HPKE_MAX_PARMLEN).unwrap_or(0) {
            invalid(F);
            return 0;
        }
        let mut params = Vec::new();
        let pctx = if let Some(group) = kem.groupname {
            // SAFETY: a static name and group.
            params.push(unsafe { OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME.as_ptr(), group.as_ptr().cast_mut(), 0) });
            // SAFETY: the caller's library context and properties.
            PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_name(libctx, c"EC".as_ptr(), propq) })
        } else {
            // SAFETY: as above.
            PkeyCtx(unsafe { EVP_PKEY_CTX_new_from_name(libctx, kem.keytype.as_ptr(), propq) })
        };
        // SAFETY: the context.
        if pctx.0.is_null() || unsafe { EVP_PKEY_keygen_init(pctx.0) } <= 0 {
            internal(F);
            return 0;
        }
        if !ikm.is_null() {
            // SAFETY: a static name; the caller's octets, read during the call.
            params.push(unsafe { OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_DHKEM_IKM.as_ptr(), ikm.cast_mut().cast(), ikmlen) });
        }
        // SAFETY: no preconditions.
        params.push(unsafe { OSSL_PARAM_construct_end() });
        // SAFETY: the context; the parameters.
        if unsafe { EVP_PKEY_CTX_set_params(pctx.0, params.as_ptr()) } <= 0 {
            internal(F);
            return 0;
        }
        let mut sk = ptr::null_mut();
        // SAFETY: as above, a place for the key.
        if unsafe { EVP_PKEY_generate(pctx.0, &raw mut sk) } <= 0 {
            internal(F);
            return 0;
        }
        drop(pctx);
        let sk = Pkey(sk);
        // SAFETY: the key; the caller's room and length.
        if unsafe { EVP_PKEY_get_octet_string_param(sk.0, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.as_ptr(), pub_, *pl, publen) } != 1 {
            internal(F);
            return 0;
        }
        *out = sk.0;
        core::mem::forget(sk);
        1
    }
}

ffi_export! {
    /// 1 if the suite is one of the KEMs, KDFs, and AEADs there are; 0 (with the first
    /// unknown one's error) if not.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_HPKE_suite_check(suite: OSSL_HPKE_SUITE) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        c_int::from(suite_infos(suite).is_some())
    }
}

ffi_export! {
    /// GREASE (RFC 8701's idea, for ECH): the suite given (or a random one, never export-only),
    /// a real public key of its KEM as the encapsulated key, and `ctlen` random octets as the
    /// ciphertext: 1, or 0.
    ///
    /// # Safety
    /// `suite_in` is NULL or live; `suite` is NULL or live; `enc` is NULL or has room for
    /// `*enclen` octets (`enclen` live when it isn't); `ct` is NULL or has room for `ctlen`;
    /// `libctx` is NULL or live; `propq` is NULL or a C string.
    pub unsafe extern "C" fn OSSL_HPKE_get_grease_value(suite_in: *const OSSL_HPKE_SUITE, suite: *mut OSSL_HPKE_SUITE, enc: *mut c_uchar, enclen: *mut usize, ct: *mut c_uchar, ctlen: usize, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "OSSL_HPKE_get_grease_value";
        // SAFETY: the caller's guarantee.
        let Some(out) = (unsafe { suite.as_mut() }) else {
            invalid(F);
            return 0;
        };
        if enc.is_null() || enclen.is_null() || ct.is_null() || ctlen == 0 {
            invalid(F);
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let chosen = match unsafe { suite_in.as_ref() } {
            Some(s) => *s,
            None => {
                let pick = |n: usize| usize::try_from(rand_uniform(libctx, u32::try_from(n).unwrap_or(1))?).ok();
                let (Some(k), Some(d), Some(a)) = (pick(KEMS.len()), pick(KDFS.len()), pick(AEADS.len() - 1)) else {
                    internal(F);
                    return 0;
                };
                let (Some(k), Some(d), Some(a)) = (KEMS.get(k), KDFS.get(d), AEADS.get(a)) else {
                    internal(F);
                    return 0;
                };
                OSSL_HPKE_SUITE { kem_id: k.id, kdf_id: d.id, aead_id: a.id }
            }
        };
        let Some((kem, _, aead)) = suite_infos(chosen) else {
            internal(F);
            return 0;
        };
        *out = chosen;
        // SAFETY: the caller's guarantee.
        let el = unsafe { &mut *enclen };
        if aead.taglen >= ctlen || kem.npk > *el {
            internal(F);
            return 0;
        }
        let mut fake = ptr::null_mut();
        // SAFETY: the caller's room for the public key; a place for the key.
        if unsafe { OSSL_HPKE_keygen(chosen, enc, enclen, &raw mut fake, ptr::null(), 0, libctx, propq) } != 1 {
            internal(F);
            return 0;
        }
        // SAFETY: the key made.
        unsafe { EVP_PKEY_free(fake) };
        // SAFETY: the caller's room for `ctlen`.
        if unsafe { RAND_bytes_ex(libctx, ct, ctlen, 0) } <= 0 {
            internal(F);
            return 0;
        }
        1
    }
}

/// `synonyms_name2id`: the identifier one of whose names (in any case) is `name`, or 0.
fn name2id(name: &[u8], table: &Names) -> u16 {
    table
        .iter()
        .find(|(_, names)| {
            names
                .iter()
                .any(|n| n.to_bytes().eq_ignore_ascii_case(name))
        })
        .map_or(0, |(id, _)| *id)
}

ffi_export! {
    /// The suite of a string "kem,kdf,aead", each by name or number (in any case): 1, or 0
    /// (with an error for NULL, empty, or 38 or more characters; without one otherwise).
    ///
    /// # Safety
    /// `str_` is NULL or a C string; `suite` is NULL or live.
    pub unsafe extern "C" fn OSSL_HPKE_str2suite(str_: *const c_char, suite: *mut OSSL_HPKE_SUITE) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        const F: &str = "ossl_hpke_str2suite";
        // SAFETY: the caller's guarantee.
        let (Some(s), Some(out)) = (unsafe { c_str(str_) }, unsafe { suite.as_mut() }) else {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        let s = s.to_bytes();
        if s.is_empty() {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        if s.len() >= MAX_SUITESTR {
            err::raise(ERR_LIB_CRYPTO, ERR_R_PASSED_INVALID_ARGUMENT, F);
            return 0;
        }
        if s.last() == Some(&b',') || s.iter().filter(|&&c| c == b',').count() != 2 {
            return 0;
        }
        let mut parts = s.split(|&c| c == b',');
        let (Some(k), Some(d), Some(a)) = (parts.next(), parts.next(), parts.next()) else { return 0 };
        let kem = name2id(k, &KEM_NAMES);
        if kem == 0 {
            return 0;
        }
        let kdf = name2id(d, &KDF_NAMES);
        if kdf == 0 {
            return 0;
        }
        let aead = name2id(a, &AEAD_NAMES);
        if aead == 0 {
            return 0;
        }
        *out = OSSL_HPKE_SUITE { kem_id: kem, kdf_id: kdf, aead_id: aead };
        1
    }
}

/// `hpke_expansion`: the encapsulated key's and a ciphertext's lengths for the suite.
fn expansion(suite: OSSL_HPKE_SUITE, clearlen: usize) -> Option<(usize, usize)> {
    let Some((kem, _, aead)) = suite_infos(suite) else {
        invalid("hpke_expansion");
        return None;
    };
    Some((kem.nenc, clearlen.wrapping_add(aead.taglen)))
}

/// `OSSL_HPKE_get_public_encap_size`.
fn public_encap_size(suite: OSSL_HPKE_SUITE) -> usize {
    expansion(suite, 16).map_or(0, |(e, _)| e)
}

ffi_export! {
    /// The ciphertext's length for `clearlen` octets of plaintext (the AEAD's tag added), or
    /// 0 for a suite there's none of.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_HPKE_get_ciphertext_size(suite: OSSL_HPKE_SUITE, clearlen: usize) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        expansion(suite, clearlen).map_or(0, |(_, c)| c)
    }
}

ffi_export! {
    /// The encapsulated key's length for the suite, or 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_HPKE_get_public_encap_size(suite: OSSL_HPKE_SUITE) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        public_encap_size(suite)
    }
}

ffi_export! {
    /// The recommended length of input key material for the suite's KEM (its private key's),
    /// or 0.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn OSSL_HPKE_get_recommended_ikmelen(suite: OSSL_HPKE_SUITE) -> usize
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        suite_infos(suite).map_or(0, |(k, _, _)| k.nsk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_found_in_any_case() {
        assert_eq!(name2id(b"x25519", &KEM_NAMES), 0x20);
        assert_eq!(name2id(b"0X12", &KEM_NAMES), 0x12);
        assert_eq!(name2id(b"HKDF-SHA384", &KDF_NAMES), 2);
        assert_eq!(name2id(b"FF", &AEAD_NAMES), 0xffff);
        assert_eq!(name2id(b"", &AEAD_NAMES), 0);
        assert_eq!(name2id(b"0x04", &KDF_NAMES), 0);
    }

    #[test]
    #[cfg_attr(miri, ignore = "draws random numbers, which seeds from the system")]
    fn uniform_numbers_stay_below_the_bound() {
        for upper in [1, 2, 3, 5, 1000, u32::MAX] {
            for _ in 0..50 {
                assert!(
                    rand_uniform(ptr::null_mut(), upper)
                        .is_some_and(|v| v < upper || upper == 1 && v == 0)
                );
            }
        }
    }

    #[test]
    fn the_sequence_number_goes_into_the_nonce() {
        let (kem, _, aead) = suite_infos(OSSL_HPKE_SUITE {
            kem_id: 0x20,
            kdf_id: 1,
            aead_id: 1,
        })
        .unwrap_or_else(|| unreachable!());
        assert_eq!(kem.nenc, 32);
        let mut s = State {
            libctx: ptr::null_mut(),
            propq: None,
            mode: 0,
            suite: OSSL_HPKE_SUITE {
                kem_id: 0x20,
                kdf_id: 1,
                aead_id: 1,
            },
            aead,
            aead_ciph: ptr::null_mut(),
            role: 0,
            seq: 0x0102,
            shared_secret: None,
            key: None,
            nonce: Some(Zeroizing::new(vec![0xff; 12])),
            exportersec: None,
            pskid: None,
            psk: None,
            authpriv: Pkey(ptr::null_mut()),
            authpub: None,
            ikme: None,
        };
        let n = seqnonce(&s).unwrap_or_default();
        assert_eq!(n[..10], [0xff; 10]);
        assert_eq!(n[10..], [0xfe, 0xfd]);
        s.nonce = Some(Zeroizing::new(vec![0; 8]));
        assert!(seqnonce(&s).is_none());
    }
}
