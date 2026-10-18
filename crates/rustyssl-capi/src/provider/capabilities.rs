//! The default provider's capabilities (`providers/common/capabilities.c`): the TLS groups
//! (`TLS-GROUP`) and signature algorithms (`TLS-SIGALG`) libssl learns from it, as parameter
//! sets given one by one to the caller's callback.

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    DTLS1_2_VERSION, DTLS1_VERSION, OSSL_CALLBACK, OSSL_CAPABILITY_TLS_GROUP_ALG,
    OSSL_CAPABILITY_TLS_GROUP_ID, OSSL_CAPABILITY_TLS_GROUP_IS_KEM,
    OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,
    OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,
    OSSL_CAPABILITY_TLS_GROUP_NAME, OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,
    OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT,
    OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS,
    OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS,
    OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, OSSL_CAPABILITY_TLS_SIGALG_NAME,
    OSSL_CAPABILITY_TLS_SIGALG_OID, OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS, OSSL_PARAM,
    OSSL_PARAM_INTEGER, OSSL_PARAM_UNMODIFIED, OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_STRING,
    TLS1_2_VERSION, TLS1_3_VERSION, TLS1_VERSION,
};

/// The TLS group code points (`include/internal/tlsgroups.h`; IANA's TLS Supported Groups).
/// Only an internal header defines them, so they're listed here.
pub(crate) mod group_id {
    pub(crate) const SECT163K1: u32 = 0x0001;
    pub(crate) const SECT163R1: u32 = 0x0002;
    pub(crate) const SECT163R2: u32 = 0x0003;
    pub(crate) const SECT193R1: u32 = 0x0004;
    pub(crate) const SECT193R2: u32 = 0x0005;
    pub(crate) const SECT233K1: u32 = 0x0006;
    pub(crate) const SECT233R1: u32 = 0x0007;
    pub(crate) const SECT239K1: u32 = 0x0008;
    pub(crate) const SECT283K1: u32 = 0x0009;
    pub(crate) const SECT283R1: u32 = 0x000A;
    pub(crate) const SECT409K1: u32 = 0x000B;
    pub(crate) const SECT409R1: u32 = 0x000C;
    pub(crate) const SECT571K1: u32 = 0x000D;
    pub(crate) const SECT571R1: u32 = 0x000E;
    pub(crate) const SECP160K1: u32 = 0x000F;
    pub(crate) const SECP160R1: u32 = 0x0010;
    pub(crate) const SECP160R2: u32 = 0x0011;
    pub(crate) const SECP192K1: u32 = 0x0012;
    pub(crate) const SECP192R1: u32 = 0x0013;
    pub(crate) const SECP224K1: u32 = 0x0014;
    pub(crate) const SECP224R1: u32 = 0x0015;
    pub(crate) const SECP256K1: u32 = 0x0016;
    pub(crate) const SECP256R1: u32 = 0x0017;
    pub(crate) const SECP384R1: u32 = 0x0018;
    pub(crate) const SECP521R1: u32 = 0x0019;
    pub(crate) const BRAINPOOLP256R1: u32 = 0x001A;
    pub(crate) const BRAINPOOLP384R1: u32 = 0x001B;
    pub(crate) const BRAINPOOLP512R1: u32 = 0x001C;
    pub(crate) const X25519: u32 = 0x001D;
    pub(crate) const X448: u32 = 0x001E;
    pub(crate) const BRAINPOOLP256R1_TLS13: u32 = 0x001F;
    pub(crate) const BRAINPOOLP384R1_TLS13: u32 = 0x0020;
    pub(crate) const BRAINPOOLP512R1_TLS13: u32 = 0x0021;
    pub(crate) const FFDHE2048: u32 = 0x0100;
    pub(crate) const FFDHE3072: u32 = 0x0101;
    pub(crate) const FFDHE4096: u32 = 0x0102;
    pub(crate) const FFDHE6144: u32 = 0x0103;
    pub(crate) const FFDHE8192: u32 = 0x0104;
    pub(crate) const MLKEM512: u32 = 0x0200;
    pub(crate) const MLKEM768: u32 = 0x0201;
    pub(crate) const MLKEM1024: u32 = 0x0202;
    pub(crate) const SECP256R1_MLKEM768: u32 = 0x11EB;
    pub(crate) const X25519_MLKEM768: u32 = 0x11EC;
    pub(crate) const SECP384R1_MLKEM1024: u32 = 0x11ED;
}

/// ML-KEM's security bits (`include/crypto/ml_kem.h`).
const ML_KEM_512_SECBITS: u32 = 128;
/// See [`ML_KEM_512_SECBITS`].
const ML_KEM_768_SECBITS: u32 = 192;
/// See [`ML_KEM_512_SECBITS`].
const ML_KEM_1024_SECBITS: u32 = 256;

/// A group's constants (`TLS_GROUP_CONSTANTS`).
struct GroupConstants {
    group_id: c_uint,
    secbits: c_uint,
    mintls: c_int,
    maxtls: c_int,
    mindtls: c_int,
    maxdtls: c_int,
    is_kem: c_uint,
}

const fn g(
    group_id: u32,
    secbits: u32,
    mintls: c_int,
    maxtls: c_int,
    mindtls: c_int,
    maxdtls: c_int,
    is_kem: u32,
) -> GroupConstants {
    GroupConstants {
        group_id,
        secbits,
        mintls,
        maxtls,
        mindtls,
        maxdtls,
        is_kem,
    }
}

use group_id as id;

const T1: c_int = TLS1_VERSION;
const T12: c_int = TLS1_2_VERSION;
const T13: c_int = TLS1_3_VERSION;
const D1: c_int = DTLS1_VERSION;
const D12: c_int = DTLS1_2_VERSION;

/// `group_list[]`, in OpenSSL's order (indices are referred to below).
static GROUP_LIST: [GroupConstants; 44] = [
    g(id::SECT163K1, 80, T1, T12, D1, D12, 0),
    g(id::SECT163R1, 80, T1, T12, D1, D12, 0),
    g(id::SECT163R2, 80, T1, T12, D1, D12, 0),
    g(id::SECT193R1, 80, T1, T12, D1, D12, 0),
    g(id::SECT193R2, 80, T1, T12, D1, D12, 0),
    g(id::SECT233K1, 112, T1, T12, D1, D12, 0),
    g(id::SECT233R1, 112, T1, T12, D1, D12, 0),
    g(id::SECT239K1, 112, T1, T12, D1, D12, 0),
    g(id::SECT283K1, 128, T1, T12, D1, D12, 0),
    g(id::SECT283R1, 128, T1, T12, D1, D12, 0),
    g(id::SECT409K1, 192, T1, T12, D1, D12, 0),
    g(id::SECT409R1, 192, T1, T12, D1, D12, 0),
    g(id::SECT571K1, 256, T1, T12, D1, D12, 0),
    g(id::SECT571R1, 256, T1, T12, D1, D12, 0),
    g(id::SECP160K1, 80, T1, T12, D1, D12, 0),
    g(id::SECP160R1, 80, T1, T12, D1, D12, 0),
    g(id::SECP160R2, 80, T1, T12, D1, D12, 0),
    g(id::SECP192K1, 80, T1, T12, D1, D12, 0),
    g(id::SECP192R1, 80, T1, T12, D1, D12, 0),
    g(id::SECP224K1, 112, T1, T12, D1, D12, 0),
    g(id::SECP224R1, 112, T1, T12, D1, D12, 0),
    g(id::SECP256K1, 128, T1, T12, D1, D12, 0),
    g(id::SECP256R1, 128, T1, 0, D1, 0, 0),
    g(id::SECP384R1, 192, T1, 0, D1, 0, 0),
    g(id::SECP521R1, 256, T1, 0, D1, 0, 0),
    g(id::BRAINPOOLP256R1, 128, T1, T12, D1, D12, 0),
    g(id::BRAINPOOLP384R1, 192, T1, T12, D1, D12, 0),
    g(id::BRAINPOOLP512R1, 256, T1, T12, D1, D12, 0),
    g(id::X25519, 128, T1, 0, D1, 0, 0),
    g(id::X448, 224, T1, 0, D1, 0, 0),
    g(id::BRAINPOOLP256R1_TLS13, 128, T13, 0, -1, -1, 0),
    g(id::BRAINPOOLP384R1_TLS13, 192, T13, 0, -1, -1, 0),
    g(id::BRAINPOOLP512R1_TLS13, 256, T13, 0, -1, -1, 0),
    g(id::FFDHE2048, 112, T13, 0, -1, -1, 0),
    g(id::FFDHE3072, 128, T13, 0, -1, -1, 0),
    g(id::FFDHE4096, 128, T13, 0, -1, -1, 0),
    g(id::FFDHE6144, 128, T13, 0, -1, -1, 0),
    g(id::FFDHE8192, 192, T13, 0, -1, -1, 0),
    g(id::MLKEM512, ML_KEM_512_SECBITS, T13, 0, -1, -1, 1),
    g(id::MLKEM768, ML_KEM_768_SECBITS, T13, 0, -1, -1, 1),
    g(id::MLKEM1024, ML_KEM_1024_SECBITS, T13, 0, -1, -1, 1),
    g(id::X25519_MLKEM768, ML_KEM_768_SECBITS, T13, 0, -1, -1, 1),
    g(
        id::SECP256R1_MLKEM768,
        ML_KEM_768_SECBITS,
        T13,
        0,
        -1,
        -1,
        1,
    ),
    g(
        id::SECP384R1_MLKEM1024,
        ML_KEM_1024_SECBITS,
        T13,
        0,
        -1,
        -1,
        1,
    ),
];

/// A `TLS_GROUP_ENTRY`: the TLS name, the provider's name for it, its algorithm, and its
/// constants' index.
pub(crate) struct GroupEntry {
    /// The name libssl lists it by.
    pub(crate) tls_name: &'static CStr,
    /// The provider's name for the group (empty for KEM groups).
    pub(crate) internal_name: &'static CStr,
    /// The key management algorithm.
    pub(crate) algorithm: &'static CStr,
    idx: usize,
}

const fn e(
    tls_name: &'static CStr,
    internal_name: &'static CStr,
    algorithm: &'static CStr,
    idx: usize,
) -> GroupEntry {
    GroupEntry {
        tls_name,
        internal_name,
        algorithm,
        idx,
    }
}

/// `param_group_list[]`, in OpenSSL's order, for the default build (EC, EC2M, DH, ECX, ML-KEM,
/// and the deprecated TLS EC groups are all in; no FIPS module).
pub(crate) static GROUPS: [GroupEntry; 59] = [
    e(c"X25519MLKEM768", c"", c"X25519MLKEM768", 41),
    e(c"x25519", c"X25519", c"X25519", 28),
    e(c"x448", c"X448", c"X448", 29),
    e(c"secp256r1", c"prime256v1", c"EC", 22),
    e(c"P-256", c"prime256v1", c"EC", 22),
    e(c"secp384r1", c"secp384r1", c"EC", 23),
    e(c"P-384", c"secp384r1", c"EC", 23),
    e(c"secp521r1", c"secp521r1", c"EC", 24),
    e(c"P-521", c"secp521r1", c"EC", 24),
    e(c"ffdhe2048", c"ffdhe2048", c"DH", 33),
    e(c"ffdhe3072", c"ffdhe3072", c"DH", 34),
    e(c"MLKEM512", c"", c"ML-KEM-512", 38),
    e(c"MLKEM768", c"", c"ML-KEM-768", 39),
    e(c"MLKEM1024", c"", c"ML-KEM-1024", 40),
    e(c"brainpoolP256r1", c"brainpoolP256r1", c"EC", 25),
    e(c"brainpoolP384r1", c"brainpoolP384r1", c"EC", 26),
    e(c"brainpoolP512r1", c"brainpoolP512r1", c"EC", 27),
    e(c"brainpoolP256r1tls13", c"brainpoolP256r1", c"EC", 30),
    e(c"brainpoolP384r1tls13", c"brainpoolP384r1", c"EC", 31),
    e(c"brainpoolP512r1tls13", c"brainpoolP512r1", c"EC", 32),
    e(c"SecP256r1MLKEM768", c"", c"SecP256r1MLKEM768", 42),
    e(c"SecP384r1MLKEM1024", c"", c"SecP384r1MLKEM1024", 43),
    e(c"ffdhe4096", c"ffdhe4096", c"DH", 35),
    e(c"ffdhe6144", c"ffdhe6144", c"DH", 36),
    e(c"ffdhe8192", c"ffdhe8192", c"DH", 37),
    e(c"sect163k1", c"sect163k1", c"EC", 0),
    e(c"K-163", c"sect163k1", c"EC", 0),
    e(c"sect163r1", c"sect163r1", c"EC", 1),
    e(c"sect163r2", c"sect163r2", c"EC", 2),
    e(c"B-163", c"sect163r2", c"EC", 2),
    e(c"sect193r1", c"sect193r1", c"EC", 3),
    e(c"sect193r2", c"sect193r2", c"EC", 4),
    e(c"sect233k1", c"sect233k1", c"EC", 5),
    e(c"K-233", c"sect233k1", c"EC", 5),
    e(c"sect233r1", c"sect233r1", c"EC", 6),
    e(c"B-233", c"sect233r1", c"EC", 6),
    e(c"sect239k1", c"sect239k1", c"EC", 7),
    e(c"sect283k1", c"sect283k1", c"EC", 8),
    e(c"K-283", c"sect283k1", c"EC", 8),
    e(c"sect283r1", c"sect283r1", c"EC", 9),
    e(c"B-283", c"sect283r1", c"EC", 9),
    e(c"sect409k1", c"sect409k1", c"EC", 10),
    e(c"K-409", c"sect409k1", c"EC", 10),
    e(c"sect409r1", c"sect409r1", c"EC", 11),
    e(c"B-409", c"sect409r1", c"EC", 11),
    e(c"sect571k1", c"sect571k1", c"EC", 12),
    e(c"K-571", c"sect571k1", c"EC", 12),
    e(c"sect571r1", c"sect571r1", c"EC", 13),
    e(c"B-571", c"sect571r1", c"EC", 13),
    e(c"secp160k1", c"secp160k1", c"EC", 14),
    e(c"secp160r1", c"secp160r1", c"EC", 15),
    e(c"secp160r2", c"secp160r2", c"EC", 16),
    e(c"secp192k1", c"secp192k1", c"EC", 17),
    e(c"secp192r1", c"prime192v1", c"EC", 18),
    e(c"P-192", c"prime192v1", c"EC", 18),
    e(c"secp224k1", c"secp224k1", c"EC", 19),
    e(c"secp224r1", c"secp224r1", c"EC", 20),
    e(c"P-224", c"secp224r1", c"EC", 20),
    e(c"secp256k1", c"secp256k1", c"EC", 21),
];

/// A signature algorithm's constants (`TLS_SIGALG_CONSTANTS`).
struct SigalgConstants {
    code_point: c_uint,
    sec_bits: c_uint,
    min_tls: c_int,
    max_tls: c_int,
    min_dtls: c_int,
    max_dtls: c_int,
}

static SIGALG_CONSTANTS: [SigalgConstants; 3] = [
    SigalgConstants {
        code_point: 0x0904,
        sec_bits: 128,
        min_tls: T13,
        max_tls: 0,
        min_dtls: -1,
        max_dtls: -1,
    },
    SigalgConstants {
        code_point: 0x0905,
        sec_bits: 192,
        min_tls: T13,
        max_tls: 0,
        min_dtls: -1,
        max_dtls: -1,
    },
    SigalgConstants {
        code_point: 0x0906,
        sec_bits: 256,
        min_tls: T13,
        max_tls: 0,
        min_dtls: -1,
        max_dtls: -1,
    },
];

/// A `TLS_SIGALG_ENTRY`: the IANA name, the algorithm, its OID, and its constants' index.
pub(crate) struct SigalgEntry {
    /// The IANA name.
    pub(crate) iana_name: &'static CStr,
    /// The signature algorithm's name.
    pub(crate) name: &'static CStr,
    /// Its OID.
    pub(crate) oid: &'static CStr,
    idx: usize,
}

/// `param_sigalg_list[]` (ML-DSA is in the default build).
pub(crate) static SIGALGS: [SigalgEntry; 3] = [
    SigalgEntry {
        iana_name: c"mldsa44",
        name: c"ML-DSA-44",
        oid: c"2.16.840.1.101.3.4.3.17",
        idx: 0,
    },
    SigalgEntry {
        iana_name: c"mldsa65",
        name: c"ML-DSA-65",
        oid: c"2.16.840.1.101.3.4.3.18",
        idx: 1,
    },
    SigalgEntry {
        iana_name: c"mldsa87",
        name: c"ML-DSA-87",
        oid: c"2.16.840.1.101.3.4.3.19",
        idx: 2,
    },
];

/// The return size of a parameter OpenSSL's `OSSL_PARAM_*` constructors make
/// (`OSSL_PARAM_UNMODIFIED`).
fn unmodified() -> usize {
    usize::try_from(OSSL_PARAM_UNMODIFIED).unwrap_or(usize::MAX)
}

/// `OSSL_PARAM_utf8_string(key, s, sizeof(s))`: the size counts the terminating NUL, as
/// `sizeof` of a string literal does.
fn utf8(key: &'static CStr, s: &'static CStr) -> OSSL_PARAM {
    OSSL_PARAM {
        key: key.as_ptr(),
        data_type: OSSL_PARAM_UTF8_STRING.cast_unsigned(),
        data: s.as_ptr().cast_mut().cast(),
        data_size: s.to_bytes_with_nul().len(),
        return_size: unmodified(),
    }
}

/// `OSSL_PARAM_uint(key, p)`.
fn uint(key: &'static CStr, p: &'static c_uint) -> OSSL_PARAM {
    OSSL_PARAM {
        key: key.as_ptr(),
        data_type: OSSL_PARAM_UNSIGNED_INTEGER.cast_unsigned(),
        data: ptr::from_ref(p).cast_mut().cast(),
        data_size: size_of::<c_uint>(),
        return_size: unmodified(),
    }
}

/// `OSSL_PARAM_int(key, p)`.
fn int(key: &'static CStr, p: &'static c_int) -> OSSL_PARAM {
    OSSL_PARAM {
        key: key.as_ptr(),
        data_type: OSSL_PARAM_INTEGER.cast_unsigned(),
        data: ptr::from_ref(p).cast_mut().cast(),
        data_size: size_of::<c_int>(),
        return_size: unmodified(),
    }
}

/// `OSSL_PARAM_END`.
fn end() -> OSSL_PARAM {
    OSSL_PARAM {
        key: ptr::null(),
        data_type: 0,
        data: ptr::null_mut(),
        data_size: 0,
        return_size: 0,
    }
}

/// The parameters of one group entry, as `TLS_GROUP_ENTRY` builds them.
fn group_params(e: &'static GroupEntry) -> Option<[OSSL_PARAM; 11]> {
    let c = GROUP_LIST.get(e.idx)?;
    Some([
        utf8(OSSL_CAPABILITY_TLS_GROUP_NAME, e.tls_name),
        utf8(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, e.internal_name),
        utf8(OSSL_CAPABILITY_TLS_GROUP_ALG, e.algorithm),
        uint(OSSL_CAPABILITY_TLS_GROUP_ID, &c.group_id),
        uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, &c.secbits),
        int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, &c.mintls),
        int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, &c.maxtls),
        int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, &c.mindtls),
        int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, &c.maxdtls),
        uint(OSSL_CAPABILITY_TLS_GROUP_IS_KEM, &c.is_kem),
        end(),
    ])
}

/// The parameters of one signature algorithm entry, as `TLS_SIGALG_ENTRY` builds them.
fn sigalg_params(e: &'static SigalgEntry) -> Option<[OSSL_PARAM; 10]> {
    let c = SIGALG_CONSTANTS.get(e.idx)?;
    Some([
        utf8(OSSL_CAPABILITY_TLS_SIGALG_IANA_NAME, e.iana_name),
        utf8(OSSL_CAPABILITY_TLS_SIGALG_NAME, e.name),
        utf8(OSSL_CAPABILITY_TLS_SIGALG_OID, e.oid),
        uint(OSSL_CAPABILITY_TLS_SIGALG_CODE_POINT, &c.code_point),
        uint(OSSL_CAPABILITY_TLS_SIGALG_SECURITY_BITS, &c.sec_bits),
        int(OSSL_CAPABILITY_TLS_SIGALG_MIN_TLS, &c.min_tls),
        int(OSSL_CAPABILITY_TLS_SIGALG_MAX_TLS, &c.max_tls),
        int(OSSL_CAPABILITY_TLS_SIGALG_MIN_DTLS, &c.min_dtls),
        int(OSSL_CAPABILITY_TLS_SIGALG_MAX_DTLS, &c.max_dtls),
        end(),
    ])
}

/// The offered group entries, in order.
pub(crate) fn groups() -> impl Iterator<Item = &'static GroupEntry> {
    GROUPS.iter()
}

/// Whether `a` names `b`, ignoring ASCII case (`OPENSSL_strcasecmp`).
fn eq_ignore_case(a: &CStr, b: &str) -> bool {
    a.to_bytes().eq_ignore_ascii_case(b.as_bytes())
}

/// `ossl_prov_get_capabilities`: each parameter set of `capability` to `cb`, stopping at the
/// first it refuses (0). 0 for an unknown capability.
///
/// # Safety
/// `capability` is NULL or a NUL-terminated string; `cb` takes `arg`.
pub(crate) unsafe fn get_capabilities(
    capability: *const c_char,
    cb: OSSL_CALLBACK,
    arg: *mut c_void,
) -> c_int {
    if capability.is_null() {
        return 0;
    }
    // SAFETY: the caller's string.
    let cap = unsafe { CStr::from_ptr(capability) };
    let Some(cb) = cb else { return 0 };
    if eq_ignore_case(cap, "TLS-GROUP") {
        for e in groups() {
            let Some(params) = group_params(e) else {
                return 0;
            };
            // SAFETY: the caller's callback with a terminated parameter array that outlives the
            // call (its data are statics).
            if unsafe { cb(params.as_ptr(), arg) } == 0 {
                return 0;
            }
        }
        return 1;
    }
    if eq_ignore_case(cap, "TLS-SIGALG") {
        for e in &SIGALGS {
            let Some(params) = sigalg_params(e) else {
                return 0;
            };
            // SAFETY: as above.
            if unsafe { cb(params.as_ptr(), arg) } == 0 {
                return 0;
            }
        }
        return 1;
    }
    0
}

/// The default provider's `get_capabilities`.
///
/// # Safety
/// As for [`get_capabilities`].
pub(crate) unsafe extern "C" fn default_get_capabilities(
    _provctx: *mut c_void,
    capability: *const c_char,
    cb: OSSL_CALLBACK,
    arg: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { get_capabilities(capability, cb, arg) }
}
