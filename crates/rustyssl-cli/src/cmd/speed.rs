//! `openssl speed` (`apps/speed.c`): algorithm benchmarks.
//!
//! The timings differ from run to run by nature (ADR 0007, decision 4); everything else is
//! upstream's: the option handling and messages, which algorithms run and in what order, the
//! output's lines and layout (`-mr` included), `-multi`'s child processes, `-async_jobs`, the
//! exit codes. Runs are timed as upstream times them: `SIGALRM` ends each one, and the time is
//! the process's user CPU time (`times`), or the elapsed time with `-elapsed`.

use std::cell::RefCell;
use std::io::{Read, Write};

use rustyssl_ossl::abi::{
    ERR_LIB_EVP, ERR_R_UNSUPPORTED, EVP_CIPH_CCM_MODE, EVP_CIPH_FLAG_AEAD_CIPHER,
    EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK, EVP_CIPH_GCM_MODE, EVP_CIPH_GCM_SIV_MODE, EVP_CIPH_OCB_MODE,
    EVP_CIPH_SIV_MODE, EVP_CTRL_AEAD_GET_TAG, EVP_CTRL_AEAD_SET_IVLEN, EVP_CTRL_AEAD_SET_MAC_KEY,
    EVP_CTRL_AEAD_SET_TAG, EVP_CTRL_AEAD_TLS1_AAD, EVP_CTRL_SET_SPEED, EVP_PKEY_DH, EVP_PKEY_DSA,
    EVP_PKEY_RSA, EVP_PKEY_SM2, EVP_R_UNSUPPORTED_ALGORITHM, NID_ED448, NID_ED25519,
    NID_X9_62_prime192v1, NID_X9_62_prime256v1, NID_X448, NID_X25519, NID_brainpoolP256r1,
    NID_brainpoolP256t1, NID_brainpoolP384r1, NID_brainpoolP384t1, NID_brainpoolP512r1,
    NID_brainpoolP512t1, NID_ffdhe2048, NID_ffdhe3072, NID_ffdhe4096, NID_ffdhe6144, NID_ffdhe8192,
    NID_secp160r1, NID_secp224r1, NID_secp384r1, NID_secp521r1, NID_sect163k1, NID_sect163r2,
    NID_sect233k1, NID_sect233r1, NID_sect283k1, NID_sect283r1, NID_sect409k1, NID_sect409r1,
    NID_sect571k1, NID_sect571r1, NID_sm2, OPENSSL_BUILT_ON, OPENSSL_CFLAGS, OPENSSL_CPU_INFO,
    OPENSSL_FULL_VERSION_STRING, OSSL_ALG_PARAM_CIPHER, OSSL_MAC_PARAM_DIGEST, OSSL_MAC_PARAM_IV,
    OSSL_MAC_PARAM_KEY, OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_RSA_BITS, RSA_F4,
    RSA_PKCS1_PADDING,
};
use rustyssl_ossl::async_job::{self, Failure, Jobs};
use rustyssl_ossl::evp::{self, Cipher, CipherCtx, Mac, MacCtx, Signature};
use rustyssl_ossl::params::ParamValues;
use rustyssl_ossl::pkey::{MdCtx, Pkey, PkeyCtx};
use rustyssl_ossl::{crypto, err, os, rand};

use crate::generated::options::speed::{OPTIONS, Opt};
use crate::lib::apps::{ConfigFile, app_bail_out, app_load_config_modules};
use crate::lib::engine::{self, Engine};
use crate::lib::keygen;
use crate::lib::opt::{self, Parser, eprintf};
use crate::lib::{app_libctx, app_rand, io};

/// `SECONDS`, `PKEY_SECONDS`.
const SECONDS: i32 = 3;
const PKEY_SECONDS: i32 = 10;
/// `MAX_ALGNAME_SUFFIX`.
const MAX_ALGNAME_SUFFIX: usize = 100;
/// `MAX_MISALIGNMENT`, `MISALIGN`, `MAX_ECDH_SIZE`, `MAX_FFDH_SIZE`.
const MAX_MISALIGNMENT: i32 = 63;
const MISALIGN: i32 = 64;
const MAX_ECDH_SIZE: usize = 256;
const MAX_FFDH_SIZE: usize = 1024;
/// `RSA_DEFAULT_PRIME_NUM`.
const RSA_DEFAULT_PRIME_NUM: i32 = 2;
/// `MAX_KEM_NUM`, `MAX_SIG_NUM`.
const MAX_KEM_NUM: usize = 111;
const MAX_SIG_NUM: usize = 256;
/// `TAG_LEN`, `AEAD_IVLEN`, `EVP_AEAD_TLS1_AAD_LEN`.
const TAG_LEN: usize = 16;
const AEAD_IVLEN: usize = 12;
const AAD_LEN: usize = 13;
const AEAD_IVLEN_C: i32 = 12;
const TAG_LEN_C: i32 = 16;
/// `SHA256_DIGEST_LENGTH`.
const SHA256_DIGEST_LENGTH: usize = 32;
/// Room past each buffer's end, for what a cipher may write beyond its input.
const SLACK: usize = 64;

const LENGTHS_LIST: [i32; 6] = [16, 64, 256, 1024, 8 * 1024, 16 * 1024];
const AEAD_LENGTHS_LIST: [i32; 6] = [2, 31, 136, 1024, 8 * 1024, 16 * 1024];

// The symmetric algorithms (`D_*`), in upstream's order.
const D_MD2: usize = 0;
const D_MDC2: usize = 1;
const D_MD4: usize = 2;
const D_MD5: usize = 3;
const D_SHA1: usize = 4;
const D_RMD160: usize = 5;
const D_SHA256: usize = 6;
const D_SHA512: usize = 7;
const D_WHIRLPOOL: usize = 8;
const D_HMAC: usize = 9;
const D_CBC_DES: usize = 10;
const D_EDE3_DES: usize = 11;
const D_RC4: usize = 12;
const D_CBC_CAST: usize = 18;
const D_CBC_128_AES: usize = 19;
const D_CBC_256_CML: usize = 24;
const D_CBC_128_CML: usize = 22;
const D_EVP: usize = 25;
const D_GHASH: usize = 26;
const D_RAND: usize = 27;
const D_EVP_CMAC: usize = 28;
const D_KMAC128: usize = 29;
const D_KMAC256: usize = 30;
const ALGOR_NUM: usize = 31;
// The table sizes as `strtoint`'s bounds.
const ALGOR_NUM_I: i64 = 31;
const ECDSA_NUM_I: i64 = 22;
const EC_NUM_I: i64 = 24;
const MAX_KEM_NUM_I: i64 = 111;
const MAX_SIG_NUM_I: i64 = 256;

/// `names`: what each algorithm is called.
const NAMES: [&str; ALGOR_NUM] = [
    "md2",
    "mdc2",
    "md4",
    "md5",
    "sha1",
    "rmd160",
    "sha256",
    "sha512",
    "whirlpool",
    "hmac(sha256)",
    "des-cbc",
    "des-ede3",
    "rc4",
    "idea-cbc",
    "seed-cbc",
    "rc2-cbc",
    "rc5-cbc",
    "blowfish",
    "cast-cbc",
    "aes-128-cbc",
    "aes-192-cbc",
    "aes-256-cbc",
    "camellia-128-cbc",
    "camellia-192-cbc",
    "camellia-256-cbc",
    "evp",
    "ghash",
    "rand",
    "cmac",
    "kmac128",
    "kmac256",
];

/// `doit_choices`: the names (and aliases) algorithms are chosen by.
const DOIT_CHOICES: &[(&str, usize)] = &[
    ("md2", D_MD2),
    ("mdc2", D_MDC2),
    ("md4", D_MD4),
    ("md5", D_MD5),
    ("hmac", D_HMAC),
    ("sha1", D_SHA1),
    ("sha256", D_SHA256),
    ("sha512", D_SHA512),
    ("whirlpool", D_WHIRLPOOL),
    ("ripemd", D_RMD160),
    ("rmd160", D_RMD160),
    ("ripemd160", D_RMD160),
    ("rc4", D_RC4),
    ("des-cbc", D_CBC_DES),
    ("des-ede3", D_EDE3_DES),
    ("aes-128-cbc", D_CBC_128_AES),
    ("aes-192-cbc", D_CBC_128_AES + 1),
    ("aes-256-cbc", D_CBC_128_AES + 2),
    ("camellia-128-cbc", D_CBC_128_CML),
    ("camellia-192-cbc", D_CBC_128_CML + 1),
    ("camellia-256-cbc", D_CBC_128_CML + 2),
    ("rc2-cbc", 15),
    ("rc2", 15),
    ("rc5-cbc", 16),
    ("rc5", 16),
    ("idea-cbc", 13),
    ("idea", 13),
    ("seed-cbc", 14),
    ("seed", 14),
    ("bf-cbc", 17),
    ("blowfish", 17),
    ("bf", 17),
    ("cast-cbc", D_CBC_CAST),
    ("cast", D_CBC_CAST),
    ("cast5", D_CBC_CAST),
    ("ghash", D_GHASH),
    ("rand", D_RAND),
    ("kmac128", D_KMAC128),
    ("kmac256", D_KMAC256),
];

const DSA_CHOICES: [&str; 2] = ["dsa1024", "dsa2048"];
const DSA_BITS: [u32; 2] = [1024, 2048];
const RSA_CHOICES: [&str; 7] = [
    "rsa512", "rsa1024", "rsa2048", "rsa3072", "rsa4096", "rsa7680", "rsa15360",
];
const RSA_BITS: [u32; 7] = [512, 1024, 2048, 3072, 4096, 7680, 15360];
const FFDH_CHOICES: [&str; 5] = ["ffdh2048", "ffdh3072", "ffdh4096", "ffdh6144", "ffdh8192"];

/// `FFDH_PARAMS`: name, NID, bits.
const FFDH_PARAMS: [(&str, i32, u32); 5] = [
    ("ffdh2048", NID_ffdhe2048, 2048),
    ("ffdh3072", NID_ffdhe3072, 3072),
    ("ffdh4096", NID_ffdhe4096, 4096),
    ("ffdh6144", NID_ffdhe6144, 6144),
    ("ffdh8192", NID_ffdhe8192, 8192),
];

/// `EC_CURVE`.
struct Curve {
    name: &'static str,
    nid: i32,
    bits: u32,
    sigsize: usize,
}

const fn curve(name: &'static str, nid: i32, bits: u32) -> Curve {
    Curve {
        name,
        nid,
        bits,
        sigsize: 0,
    }
}

const ECDSA_NUM: usize = 22;
const EC_NUM: usize = 24;
const ECDSA_CHOICES: [&str; ECDSA_NUM] = [
    "ecdsap160",
    "ecdsap192",
    "ecdsap224",
    "ecdsap256",
    "ecdsap384",
    "ecdsap521",
    "ecdsak163",
    "ecdsak233",
    "ecdsak283",
    "ecdsak409",
    "ecdsak571",
    "ecdsab163",
    "ecdsab233",
    "ecdsab283",
    "ecdsab409",
    "ecdsab571",
    "ecdsabrp256r1",
    "ecdsabrp256t1",
    "ecdsabrp384r1",
    "ecdsabrp384t1",
    "ecdsabrp512r1",
    "ecdsabrp512t1",
];
const ECDH_CHOICES: [&str; EC_NUM] = [
    "ecdhp160",
    "ecdhp192",
    "ecdhp224",
    "ecdhp256",
    "ecdhp384",
    "ecdhp521",
    "ecdhk163",
    "ecdhk233",
    "ecdhk283",
    "ecdhk409",
    "ecdhk571",
    "ecdhb163",
    "ecdhb233",
    "ecdhb283",
    "ecdhb409",
    "ecdhb571",
    "ecdhbrp256r1",
    "ecdhbrp256t1",
    "ecdhbrp384r1",
    "ecdhbrp384t1",
    "ecdhbrp512r1",
    "ecdhbrp512t1",
    "ecdhx25519",
    "ecdhx448",
];
const EC_CURVES: [Curve; EC_NUM] = [
    curve("secp160r1", NID_secp160r1, 160),
    curve("nistp192", NID_X9_62_prime192v1, 192),
    curve("nistp224", NID_secp224r1, 224),
    curve("nistp256", NID_X9_62_prime256v1, 256),
    curve("nistp384", NID_secp384r1, 384),
    curve("nistp521", NID_secp521r1, 521),
    curve("nistk163", NID_sect163k1, 163),
    curve("nistk233", NID_sect233k1, 233),
    curve("nistk283", NID_sect283k1, 283),
    curve("nistk409", NID_sect409k1, 409),
    curve("nistk571", NID_sect571k1, 571),
    curve("nistb163", NID_sect163r2, 163),
    curve("nistb233", NID_sect233r1, 233),
    curve("nistb283", NID_sect283r1, 283),
    curve("nistb409", NID_sect409r1, 409),
    curve("nistb571", NID_sect571r1, 571),
    curve("brainpoolP256r1", NID_brainpoolP256r1, 256),
    curve("brainpoolP256t1", NID_brainpoolP256t1, 256),
    curve("brainpoolP384r1", NID_brainpoolP384r1, 384),
    curve("brainpoolP384t1", NID_brainpoolP384t1, 384),
    curve("brainpoolP512r1", NID_brainpoolP512r1, 512),
    curve("brainpoolP512t1", NID_brainpoolP512t1, 512),
    curve("X25519", NID_X25519, 253),
    curve("X448", NID_X448, 448),
];
const EDDSA_CHOICES: [&str; 2] = ["ed25519", "ed448"];
const ED_CURVES: [Curve; 2] = [
    Curve {
        name: "Ed25519",
        nid: NID_ED25519,
        bits: 253,
        sigsize: 64,
    },
    Curve {
        name: "Ed448",
        nid: NID_ED448,
        bits: 456,
        sigsize: 114,
    },
];
const SM2_CHOICES: [&str; 1] = ["curveSM2"];
const SM2_CURVES: [Curve; 1] = [curve("CurveSM2", NID_sm2, 256)];
/// `SM2_ID`.
const SM2_ID: &[u8] = b"TLSv1.3+GM+Cipher+Suite";

const KEY32: [u8; 32] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
    0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56,
];
const DESKEY: [u8; 24] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12,
    0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
];
/// `iv`: `MAX_BLOCK_SIZE` bits, twice.
const IV: [u8; 32] = [0; 32];
const AEAD_IV: [u8; AEAD_IVLEN] = [0; AEAD_IVLEN];

/// Upstream's benchmark keys, `apps/testrsa.h` and `apps/testdsa.h` (vendored).
const TESTRSA_H: &str = include_str!("../../../../abi/openssl-3.6/apps/testrsa.h");
const TESTDSA_H: &str = include_str!("../../../../abi/openssl-3.6/apps/testdsa.h");

/// The `static unsigned char NAME[] = { 0x.., ... };` arrays of a C header, by name.
fn c_arrays(src: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = src;
    while let Some(at) = rest.find("static unsigned char ") {
        rest = rest
            .get(at + "static unsigned char ".len()..)
            .unwrap_or_default();
        let Some(br) = rest.find('[') else { break };
        let name = rest.get(..br).unwrap_or_default().trim().to_owned();
        let (Some(open), Some(close)) = (rest.find('{'), rest.find("};")) else {
            break;
        };
        let body = rest.get(open + 1..close).unwrap_or_default();
        let bytes = body
            .split(',')
            .filter_map(|t| {
                let t = t.trim();
                let h = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X"))?;
                u8::from_str_radix(h, 16).ok()
            })
            .collect();
        out.push((name, bytes));
        rest = rest.get(close + 2..).unwrap_or_default();
    }
    out
}

fn array(arrays: &[(String, Vec<u8>)], name: &str) -> Vec<u8> {
    arrays
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, b)| b.clone())
        .unwrap_or_default()
}

/// `get_dsa` of `testdsa.h`.
fn get_dsa(bits: u32) -> Option<Pkey> {
    let a = c_arrays(TESTDSA_H);
    let part = |p: &str| array(&a, &format!("dsa{bits}_{p}"));
    if ![512, 1024, 2048].contains(&bits) {
        return None;
    }
    Pkey::ffc_keypair(
        "DSA",
        &part("p"),
        &part("q"),
        &part("g"),
        &part("priv"),
        &part("pub"),
    )
}

/// A C `%.*f`/`%*.*f` of `v`: infinities and NaNs as C prints them.
fn cf(v: f64, width: usize, prec: usize) -> String {
    let s = if v.is_nan() {
        if v.is_sign_negative() {
            "-nan".to_owned()
        } else {
            "nan".to_owned()
        }
    } else if v.is_infinite() {
        if v < 0.0 {
            "-inf".to_owned()
        } else {
            "inf".to_owned()
        }
    } else {
        format!("{v:.prec$}")
    };
    format!("{s:>width$}")
}

/// C's `%f`.
fn f6(v: f64) -> String {
    cf(v, 0, 6)
}

/// `strtoint` of `do_multi`: a whole base-10 number in `[min, upper)`.
fn strtoint(s: &str, min: i64, upper: i64) -> Option<usize> {
    let v: i64 = s.parse().ok()?;
    if s.starts_with('+') || !(min <= v && v < upper) {
        // strtol accepts a leading '+'.
        if let Some(t) = s.strip_prefix('+')
            && !t.starts_with(['+', '-'])
        {
            let v: i64 = t.parse().ok()?;
            return (min <= v && v < upper)
                .then(|| usize::try_from(v).ok())
                .flatten();
        }
        return None;
    }
    usize::try_from(v).ok()
}

/// C's `atof`: the longest number at the start of `s` (after blanks), else 0.
fn atof(s: &str) -> f64 {
    let t = s.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let b = t.as_bytes();
    let mut i = 0;
    if matches!(b.first(), Some(b'+' | b'-')) {
        i = 1;
    }
    let lower = t.to_ascii_lowercase();
    let body = lower.get(i..).unwrap_or_default();
    let neg = b.first() == Some(&b'-');
    if body.starts_with("inf") {
        return if neg {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    if body.starts_with("nan") {
        return if neg { -f64::NAN } else { f64::NAN };
    }
    let mut end = i;
    let mut digits = false;
    while b.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
        digits = true;
    }
    if b.get(end) == Some(&b'.') {
        end += 1;
        while b.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
            digits = true;
        }
    }
    if !digits {
        return 0.0;
    }
    if matches!(b.get(end), Some(b'e' | b'E')) {
        let mut e = end + 1;
        if matches!(b.get(e), Some(b'+' | b'-')) {
            e += 1;
        }
        if b.get(e).is_some_and(u8::is_ascii_digit) {
            while b.get(e).is_some_and(u8::is_ascii_digit) {
                e += 1;
            }
            end = e;
        }
    }
    t.get(..end).and_then(|n| n.parse().ok()).unwrap_or(0.0)
}

/// `sscanf(name, "rsa%u%s", &bits, sfx) == 1`: `rsa` and a number, then nothing.
fn rsa_bits(name: &str) -> Option<u32> {
    if name.len() >= MAX_ALGNAME_SUFFIX + 4 {
        return None;
    }
    let rest = name.strip_prefix("rsa")?;
    let rest = rest.trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c']);
    let (neg, digits) = match rest.as_bytes().first() {
        Some(b'+') => (false, rest.get(1..)?),
        Some(b'-') => (true, rest.get(1..)?),
        _ => (false, rest),
    };
    let n = digits.bytes().take_while(u8::is_ascii_digit).count();
    if n == 0 {
        return None;
    }
    let tail = digits.get(n..)?;
    if !tail
        .trim_start_matches([' ', '\t', '\n', '\r', '\x0b', '\x0c'])
        .is_empty()
    {
        return None;
    }
    // %u wraps out-of-range and negative values as strtoul does.
    let v = digits.get(..n)?.parse::<u64>().unwrap_or(u64::MAX);
    let v = u32::try_from(v).unwrap_or(u32::MAX);
    Some(if neg { v.wrapping_neg() } else { v })
}

/// The C library's `atoi` of a key's bit count (`atoi(sig_name + 3)`).
fn atoi(s: &str) -> i32 {
    crate::lib::apps::atoi(s)
}

/// `a[i]`, or the default past the end.
fn at<T: Copy + Default>(a: &[T], i: usize) -> T {
    a.get(i).copied().unwrap_or_default()
}

/// `a[i] = v` (nothing past the end).
fn set<T>(a: &mut [T], i: usize, v: T) {
    if let Some(s) = a.get_mut(i) {
        *s = v;
    }
}

/// `a[i][j] = v` (nothing past the ends).
fn set2<const N: usize>(a: &mut [[f64; N]], i: usize, j: usize, v: f64) {
    if let Some(s) = a.get_mut(i).and_then(|r| r.get_mut(j)) {
        *s = v;
    }
}

/// `openssl_speed_sec_t`.
#[derive(Clone, Copy)]
struct Seconds {
    sym: i32,
    rsa: i32,
    dsa: i32,
    ecdsa: i32,
    ecdh: i32,
    eddsa: i32,
    sm2: i32,
    ffdh: i32,
    kem: i32,
    sig: i32,
}

/// The SM2 contexts of one looparg: the digest contexts use the key contexts (which they
/// don't own), so they are dropped first.
struct Sm2 {
    ctx: MdCtx,
    vfy_ctx: MdCtx,
    pctx: PkeyCtx,
    vfy_pctx: PkeyCtx,
    pkey: Pkey,
}

/// `loopargs_t`: one job's buffers and contexts.
#[derive(Default)]
struct LoopArgs {
    buf_malloc: Vec<u8>,
    buf2_malloc: Vec<u8>,
    misalign: usize,
    key: Vec<u8>,
    tag: [u8; TAG_LEN],
    buflen: usize,
    sigsize: usize,
    encsize: usize,
    rsa_sign_ctx: [Option<PkeyCtx>; 7],
    rsa_verify_ctx: [Option<PkeyCtx>; 7],
    rsa_encrypt_ctx: [Option<PkeyCtx>; 7],
    rsa_decrypt_ctx: [Option<PkeyCtx>; 7],
    dsa_sign_ctx: [Option<PkeyCtx>; 2],
    dsa_verify_ctx: [Option<PkeyCtx>; 2],
    ecdsa_sign_ctx: Vec<Option<PkeyCtx>>,
    ecdsa_verify_ctx: Vec<Option<PkeyCtx>>,
    ecdh_ctx: Vec<Option<PkeyCtx>>,
    eddsa_ctx: [Option<MdCtx>; 2],
    eddsa_ctx2: [Option<MdCtx>; 2],
    sm2: [Option<Sm2>; 1],
    secret_a: Vec<u8>,
    secret_b: Vec<u8>,
    outlen: [usize; EC_NUM],
    ffdh_ctx: [Option<PkeyCtx>; 5],
    secret_ff_a: Vec<u8>,
    secret_ff_b: Vec<u8>,
    ctx: Option<CipherCtx>,
    mctx: Option<MacCtx>,
    kem_gen_ctx: Vec<Option<PkeyCtx>>,
    kem_encaps_ctx: Vec<Option<PkeyCtx>>,
    kem_decaps_ctx: Vec<Option<PkeyCtx>>,
    kem_out_len: Vec<usize>,
    kem_secret_len: Vec<usize>,
    kem_out: Vec<Vec<u8>>,
    kem_send_secret: Vec<Vec<u8>>,
    kem_rcv_secret: Vec<Vec<u8>>,
    sig_gen_ctx: Vec<Option<PkeyCtx>>,
    sig_sign_ctx: Vec<Option<PkeyCtx>>,
    sig_verify_ctx: Vec<Option<PkeyCtx>>,
    sig_max_sig_len: Vec<usize>,
    sig_act_sig_len: Vec<usize>,
    sig_sig: Vec<Vec<u8>>,
}

impl LoopArgs {
    /// `buf`: the input buffer, misaligned as asked, with its slack.
    fn buf(&mut self) -> &mut [u8] {
        self.buf_malloc.get_mut(self.misalign..).unwrap_or_default()
    }

    /// `buf` and `buf2` together.
    fn bufs(&mut self) -> (&mut [u8], &mut [u8]) {
        let m = self.misalign;
        (
            self.buf_malloc.get_mut(m..).unwrap_or_default(),
            self.buf2_malloc.get_mut(m..).unwrap_or_default(),
        )
    }
}

/// `speed.c`'s globals.
struct State {
    mr: bool,
    usertime: bool,
    testmode: bool,
    testmoderesult: std::cell::Cell<bool>,
    lengths: Vec<i32>,
    testnum: usize,
    algindex: usize,
    mode_op: i32,
    aead: bool,
    decrypt: bool,
    aad: [u8; AAD_LEN],
    names: [String; ALGOR_NUM],
    results: [[f64; 6]; ALGOR_NUM],
    evp_md_name: Option<String>,
    tmstart: i64,
}

impl State {
    fn new() -> Self {
        let mut aad = [0u8; AAD_LEN];
        aad[0] = 0xcc;
        State {
            mr: false,
            usertime: true,
            testmode: false,
            testmoderesult: std::cell::Cell::new(false),
            lengths: LENGTHS_LIST.to_vec(),
            testnum: 0,
            algindex: 0,
            mode_op: 0,
            aead: false,
            decrypt: false,
            aad,
            names: NAMES.map(str::to_owned),
            results: [[0.0; 6]; ALGOR_NUM],
            evp_md_name: None,
            tmstart: 0,
        }
    }

    /// `names[alg]`.
    fn name(&self, alg: usize) -> String {
        self.names.get(alg).cloned().unwrap_or_default()
    }

    /// `lengths[t]`.
    fn length(&self, t: usize) -> i32 {
        at(&self.lengths, t)
    }

    /// `lengths[testnum]`.
    fn len(&self) -> usize {
        self.lengths
            .get(self.testnum)
            .and_then(|&l| usize::try_from(l).ok())
            .unwrap_or(0)
    }

    /// `COND`: the run goes on, and test mode stops after one operation.
    fn cond(&self, count: i32) -> bool {
        os::running() && count < if self.testmode { 1 } else { i32::MAX }
    }

    /// `dofail`.
    fn dofail(&self) {
        io::print_errors();
        self.testmoderesult.set(true);
    }

    /// `app_tminterval(stop, usertime)`.
    fn tminterval(&mut self, stop: bool) -> f64 {
        let (now, utime) = os::times();
        let now = if self.usertime { utime } else { now };
        if !stop {
            self.tmstart = now;
            return 0.0;
        }
        let tck = os::clock_ticks();
        // The tick counts are small enough to convert exactly.
        #[allow(clippy::cast_precision_loss)]
        let r = (now - self.tmstart) as f64 / tck as f64;
        r
    }

    /// `Time_F(START)`.
    fn time_start(&mut self) {
        self.tminterval(false);
    }

    /// `Time_F(STOP)`.
    fn time_stop(&mut self) -> f64 {
        let r = self.tminterval(true);
        os::alarm(0);
        r
    }

    /// Starts a timed run (`run = 1; alarm(tm)`).
    fn start_run(tm: i32) {
        os::set_running(true);
        os::alarm(u32::try_from(tm).unwrap_or(0));
    }

    /// `print_message`.
    fn print_message(&self, s: &str, length: i32, tm: i32) {
        if self.mr {
            eprintf!("+DT:{s}:{tm}:{length}\n");
        } else {
            eprintf!("Doing {s} ops for {tm}s on {length} size blocks: ");
        }
        State::start_run(tm);
    }

    /// `pkey_print_message`.
    fn pkey_print_message(&self, s: &str, s2: &str, bits: u32, tm: i32) {
        if self.mr {
            eprintf!("+DTP:{bits}:{s}:{s2}:{tm}\n");
        } else {
            eprintf!("Doing {bits} bits {s} {s2} ops for {tm}s: ");
        }
        State::start_run(tm);
    }

    /// `kskey_print_message`.
    fn kskey_print_message(&self, s: &str, s2: &str, tm: i32) {
        if self.mr {
            eprintf!("+DTP:{s}:{s2}:{tm}\n");
        } else {
            eprintf!("Doing {s} {s2} ops for {tm}s: ");
        }
        State::start_run(tm);
    }

    /// `print_result`.
    fn print_result(&mut self, alg: usize, run_no: usize, count: i32, time_used: f64) {
        let name = self.names.get(alg).cloned().unwrap_or_default();
        if count == -1 {
            eprintf!("{name} error!\n");
            self.dofail();
            return;
        }
        if self.mr {
            eprintf!("+R:{count}:{name}:{}\n", f6(time_used));
        } else {
            eprintf!("{count} {name} ops in {}s\n", cf(time_used, 0, 2));
        }
        let len = f64::from(self.lengths.get(run_no).copied().unwrap_or(0));
        if let Some(r) = self.results.get_mut(alg).and_then(|r| r.get_mut(run_no)) {
            *r = f64::from(count) / time_used * len;
        }
    }
}

/// A benchmark's loop: one job's operations, counted.
type LoopFn = fn(&State, &mut LoopArgs) -> i32;

/// `run_benchmark`.
fn run_benchmark(
    st: &mut State,
    jobs: Option<&mut Jobs>,
    loopargs: &[RefCell<LoopArgs>],
    f: LoopFn,
) -> i32 {
    let Some(jobs) = jobs else {
        return match loopargs.first() {
            Some(l) => f(st, &mut l.borrow_mut()),
            None => -1,
        };
    };
    let state: &State = st;
    let run = |i: usize| match loopargs.get(i) {
        Some(l) => match l.try_borrow_mut() {
            Ok(mut l) => f(state, &mut l),
            Err(_) => -1,
        },
        None => -1,
    };
    let mut failed = |e: Failure| {
        match e {
            Failure::Job => eprintf!("Failure in the job\n"),
            Failure::TooManyFds => eprintf!("Too many fds in ASYNC_WAIT_CTX\n"),
            Failure::MaxFd(max_fd) => eprintf!(
                "Error: max_fd ({max_fd}) must be smaller than FD_SETSIZE ({}). Decrease the value of async_jobs\n",
                os::fd_setsize()
            ),
            Failure::Select => eprintf!("Failure in the select\n"),
        };
        state.dofail();
    };
    jobs.run(&run, &mut failed)
}

/// `EVP_Digest_loop`.
fn digest_loop(st: &State, a: &mut LoopArgs, mdname: &str) -> i32 {
    let Some(md) = opt::md_silent(mdname) else {
        return -1;
    };
    let len = st.len();
    let mut digest = [0u8; rustyssl_ossl::abi::EVP_MAX_MD_SIZE as usize];
    let mut count = 0;
    if md.is_xof() {
        let Some(ctx) = MdCtx::new() else {
            return -1;
        };
        while st.cond(count) {
            let data = a.buf().get(..len).unwrap_or_default();
            if !ctx.digest_init_ex2(&md)
                || !ctx.digest_update(data)
                || !ctx.digest_final_xof(&mut digest)
            {
                return -1;
            }
            count += 1;
        }
    } else {
        while st.cond(count) {
            let data = a.buf().get(..len).unwrap_or_default();
            if !md.digest(data, &mut digest) {
                return -1;
            }
            count += 1;
        }
    }
    count
}

fn evp_digest_md_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let name = st.evp_md_name.clone().unwrap_or_default();
    digest_loop(st, a, &name)
}

fn md2_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "md2")
}

fn mdc2_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "mdc2")
}

fn md4_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "md4")
}

fn md5_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "md5")
}

fn sha1_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "sha1")
}

fn sha256_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "sha256")
}

fn sha512_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "sha512")
}

fn whirlpool_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "whirlpool")
}

fn rmd160_loop(st: &State, a: &mut LoopArgs) -> i32 {
    digest_loop(st, a, "ripemd160")
}

/// `EVP_MAC_loop`.
fn mac_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let len = st.len();
    let Some(mctx) = a.mctx.take() else {
        return -1;
    };
    let mut mac = [0u8; rustyssl_ossl::abi::EVP_MAX_MD_SIZE as usize];
    let mut count = 0;
    let mut ok = true;
    while st.cond(count) {
        let data = a.buf().get(..len).unwrap_or_default();
        if !mctx.init() || !mctx.update(data) || mctx.finish(&mut mac).is_none() {
            ok = false;
            break;
        }
        count += 1;
    }
    a.mctx = Some(mctx);
    if ok { count } else { -1 }
}

/// `EVP_Cipher_loop`.
fn cipher_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let len = st.len();
    let Some(ctx) = a.ctx.take() else {
        return -1;
    };
    let mut count = 0;
    let mut ok = true;
    while st.cond(count) {
        if ctx.cipher_in_place(a.buf(), len) <= 0 {
            ok = false;
            break;
        }
        count += 1;
    }
    a.ctx = Some(ctx);
    if ok { count } else { -1 }
}

/// `GHASH_loop`.
fn ghash_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let len = st.len();
    let Some(mctx) = a.mctx.take() else {
        return -1;
    };
    let mut count = 0;
    let mut ok = true;
    while st.cond(count) {
        if !mctx.update(a.buf().get(..len).unwrap_or_default()) {
            ok = false;
            break;
        }
        count += 1;
    }
    a.mctx = Some(mctx);
    if ok { count } else { -1 }
}

/// `RAND_bytes_loop`.
fn rand_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let len = st.len();
    let mut count = 0;
    while st.cond(count) {
        rand::bytes(a.buf().get_mut(..len).unwrap_or_default());
        count += 1;
    }
    count
}

/// `EVP_Update_loop`.
fn update_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let len = st.len();
    let Some(ctx) = a.ctx.take() else {
        return 0;
    };
    let enc = !st.decrypt;
    let mut count = 0;
    while st.cond(count) {
        let (rc, _) = ctx.update_in_place(enc, a.buf(), len);
        if rc != 1 {
            // Resets the IV, in case the counter overflowed.
            ctx.init(None, None, Some(&IV), -1);
        }
        count += 1;
    }
    if ctx.finish(enc, a.buf()) == 0 {
        eprintf!("Error finalizing cipher loop\n");
    }
    a.ctx = Some(ctx);
    count
}

/// The fatal failures of the AEAD loops: the message, `dofail`, and `exit(1)`.
fn aead_fail(message: &str) -> ! {
    eprintf!("{message}");
    io::print_errors();
    crate::exit(1)
}

/// `EVP_Update_loop_aead_enc`.
fn update_loop_aead_enc(st: &State, a: &mut LoopArgs) -> i32 {
    let len = st.len();
    let Some(ctx) = a.ctx.take() else {
        return 0;
    };
    let mode = st.mode_op;
    let key = a.key.clone();
    let mut realcount = 0;
    let mut count = 0;
    while st.cond(count) {
        if mode != EVP_CIPH_SIV_MODE && ctx.ctrl(EVP_CTRL_AEAD_SET_IVLEN, AEAD_IVLEN_C) == 0 {
            aead_fail("\nFailed to set iv length\n");
        }
        if mode != EVP_CIPH_GCM_MODE
            && mode != EVP_CIPH_SIV_MODE
            && mode != EVP_CIPH_GCM_SIV_MODE
            && ctx.ctrl(EVP_CTRL_AEAD_SET_TAG, TAG_LEN_C) == 0
        {
            aead_fail("\nFailed to set tag length\n");
        }
        if !ctx.init(None, Some(&key), Some(&AEAD_IV), -1) {
            aead_fail("\nFailed to set key and iv\n");
        }
        if mode == EVP_CIPH_CCM_MODE
            && ctx.update_length(true, i32::try_from(len).unwrap_or(0)) == 0
        {
            aead_fail("\nCouldn't set input text length\n");
        }
        if st.aead && ctx.update_aad(true, &st.aad) == 0 {
            aead_fail("\nCouldn't insert AAD when encrypting\n");
        }
        if ctx.update_in_place(true, a.buf(), len).0 == 0 {
            aead_fail("\nFailed to encrypt the data\n");
        }
        if ctx.finish(true, a.buf()) != 0 {
            realcount += 1;
        }
        count += 1;
    }
    a.ctx = Some(ctx);
    realcount
}

/// `EVP_Update_loop_aead_dec`: decrypts `buf` into `buf2`.
fn update_loop_aead_dec(st: &State, a: &mut LoopArgs) -> i32 {
    let len = st.len();
    let Some(ctx) = a.ctx.take() else {
        return 0;
    };
    let mode = st.mode_op;
    let key = a.key.clone();
    let mut realcount = 0;
    let mut count = 0;
    while st.cond(count) {
        if mode != EVP_CIPH_SIV_MODE && ctx.ctrl(EVP_CTRL_AEAD_SET_IVLEN, AEAD_IVLEN_C) == 0 {
            aead_fail("\nFailed to set iv length\n");
        }
        if mode != EVP_CIPH_SIV_MODE
            && mode != EVP_CIPH_GCM_MODE
            && mode != EVP_CIPH_GCM_SIV_MODE
            && ctx.ctrl(EVP_CTRL_AEAD_SET_TAG, TAG_LEN_C) == 0
        {
            aead_fail("\nFailed to set tag length\n");
        }
        if !ctx.init(None, Some(&key), Some(&AEAD_IV), -1) {
            aead_fail("\nFailed to set key and iv\n");
        }
        if mode != EVP_CIPH_SIV_MODE && !ctx.init(None, None, Some(&AEAD_IV), 0) {
            aead_fail("\nFailed to set iv\n");
        }
        let mut tag = a.tag;
        if ctx.ctrl_buf(EVP_CTRL_AEAD_SET_TAG, &mut tag) == 0 {
            aead_fail("\nFailed to set tag\n");
        }
        if mode == EVP_CIPH_CCM_MODE
            && ctx.update_length(false, i32::try_from(len).unwrap_or(0)) == 0
        {
            aead_fail("\nCouldn't set cipher text length\n");
        }
        if st.aead && ctx.update_aad(false, &st.aad) == 0 {
            aead_fail("\nCouldn't insert AAD when decrypting\n");
        }
        let (buf, out) = a.bufs();
        if ctx.update(false, out, buf, len) == 0 {
            aead_fail("\nFailed to decrypt the data\n");
        }
        if ctx.finish(false, out) != 0 {
            realcount += 1;
        }
        count += 1;
    }
    a.ctx = Some(ctx);
    realcount
}

/// The asymmetric loops' shared shape: `op` once per round, failing with `message`.
fn pkey_loop(
    st: &State,
    a: &mut LoopArgs,
    message: &str,
    mut op: impl FnMut(&mut LoopArgs) -> bool,
) -> i32 {
    let mut count = 0;
    while st.cond(count) {
        if !op(a) {
            eprintf!("{message}");
            st.dofail();
            return -1;
        }
        count += 1;
    }
    count
}

fn rsa_sign_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    pkey_loop(st, a, "RSA sign failure\n", |a| {
        let ctx = a.rsa_sign_ctx.get_mut(t).and_then(Option::take);
        let Some(ctx) = ctx else { return false };
        let n = a.buflen;
        let (buf, buf2) = a.bufs();
        let (r, l) = ctx.sign_into(
            buf2.get_mut(..n).unwrap_or_default(),
            buf.get(..36).unwrap_or_default(),
        );
        a.sigsize = l;
        if let Some(s) = a.rsa_sign_ctx.get_mut(t) {
            *s = Some(ctx);
        }
        r > 0
    })
}

fn rsa_verify_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    pkey_loop(st, a, "RSA verify failure\n", |a| {
        let n = a.sigsize;
        let ctx = a.rsa_verify_ctx.get_mut(t).and_then(Option::take);
        let Some(ctx) = ctx else { return false };
        let (buf, buf2) = a.bufs();
        let r = ctx.verify(
            buf2.get(..n).unwrap_or_default(),
            buf.get(..36).unwrap_or_default(),
        );
        if let Some(s) = a.rsa_verify_ctx.get_mut(t) {
            *s = Some(ctx);
        }
        r > 0
    })
}

fn rsa_encrypt_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    pkey_loop(st, a, "RSA encrypt failure\n", |a| {
        let ctx = a.rsa_encrypt_ctx.get_mut(t).and_then(Option::take);
        let Some(ctx) = ctx else { return false };
        let n = a.buflen;
        let (buf, buf2) = a.bufs();
        let (r, l) = ctx.encrypt_into(
            buf2.get_mut(..n).unwrap_or_default(),
            buf.get(..36).unwrap_or_default(),
        );
        a.encsize = l;
        if let Some(s) = a.rsa_encrypt_ctx.get_mut(t) {
            *s = Some(ctx);
        }
        r > 0
    })
}

fn rsa_decrypt_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    pkey_loop(st, a, "RSA decrypt failure\n", |a| {
        let ctx = a.rsa_decrypt_ctx.get_mut(t).and_then(Option::take);
        let Some(ctx) = ctx else { return false };
        let (n, e) = (a.buflen, a.encsize);
        let (buf, buf2) = a.bufs();
        let (r, _) = ctx.decrypt_into(
            buf.get_mut(..n).unwrap_or_default(),
            buf2.get(..e).unwrap_or_default(),
        );
        if let Some(s) = a.rsa_decrypt_ctx.get_mut(t) {
            *s = Some(ctx);
        }
        r > 0
    })
}

/// `FFDH_derive_key_loop`.
fn ffdh_derive_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let mut count = 0;
    while st.cond(count) {
        if let Some(Some(ctx)) = a.ffdh_ctx.get(t) {
            // The length may come back smaller (no padding).
            let _ = ctx.derive_into(&mut a.secret_ff_a, MAX_FFDH_SIZE);
        }
        count += 1;
    }
    count
}

fn sign_loop_with(
    st: &State,
    a: &mut LoopArgs,
    message: &str,
    tbs: usize,
    pick: fn(&mut LoopArgs) -> &mut [Option<PkeyCtx>],
) -> i32 {
    let t = st.testnum;
    pkey_loop(st, a, message, |a| {
        let ctx = pick(a).get_mut(t).and_then(Option::take);
        let Some(ctx) = ctx else { return false };
        let n = a.buflen;
        let (buf, buf2) = a.bufs();
        let (r, l) = ctx.sign_into(
            buf2.get_mut(..n).unwrap_or_default(),
            buf.get(..tbs).unwrap_or_default(),
        );
        a.sigsize = l;
        if let Some(s) = pick(a).get_mut(t) {
            *s = Some(ctx);
        }
        r > 0
    })
}

fn verify_loop_with(
    st: &State,
    a: &mut LoopArgs,
    message: &str,
    tbs: usize,
    pick: fn(&mut LoopArgs) -> &mut [Option<PkeyCtx>],
) -> i32 {
    let t = st.testnum;
    pkey_loop(st, a, message, |a| {
        let n = a.sigsize;
        let ctx = pick(a).get_mut(t).and_then(Option::take);
        let Some(ctx) = ctx else { return false };
        let (buf, buf2) = a.bufs();
        let r = ctx.verify(
            buf2.get(..n).unwrap_or_default(),
            buf.get(..tbs).unwrap_or_default(),
        );
        if let Some(s) = pick(a).get_mut(t) {
            *s = Some(ctx);
        }
        r > 0
    })
}

fn dsa_sign_loop(st: &State, a: &mut LoopArgs) -> i32 {
    sign_loop_with(st, a, "DSA sign failure\n", 20, |a| &mut a.dsa_sign_ctx)
}

fn dsa_verify_loop(st: &State, a: &mut LoopArgs) -> i32 {
    verify_loop_with(st, a, "DSA verify failure\n", 20, |a| &mut a.dsa_verify_ctx)
}

fn ecdsa_sign_loop(st: &State, a: &mut LoopArgs) -> i32 {
    sign_loop_with(st, a, "ECDSA sign failure\n", 20, |a| &mut a.ecdsa_sign_ctx)
}

fn ecdsa_verify_loop(st: &State, a: &mut LoopArgs) -> i32 {
    verify_loop_with(st, a, "ECDSA verify failure\n", 20, |a| {
        &mut a.ecdsa_verify_ctx
    })
}

/// `ECDH_EVP_derive_key_loop`.
fn ecdh_derive_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let mut count = 0;
    while st.cond(count) {
        let len = a.outlen.get(t).copied().unwrap_or(0);
        if let Some(Some(ctx)) = a.ecdh_ctx.get(t) {
            let (_, l) = ctx.derive_into(&mut a.secret_a, len);
            if let Some(o) = a.outlen.get_mut(t) {
                *o = l;
            }
        }
        count += 1;
    }
    count
}

/// `EdDSA_sign_loop`.
fn eddsa_sign_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let mut count = 0;
    while st.cond(count) {
        let ctx = a.eddsa_ctx.get_mut(t).and_then(Option::take);
        let Some(ctx) = ctx else { return -1 };
        let ok = ctx.sign_reinit() != 0;
        let mut signed = true;
        if ok {
            let n = a.sigsize;
            let (buf, buf2) = a.bufs();
            let (r, l) = ctx.sign(buf2, n, buf.get(..20).unwrap_or_default());
            a.sigsize = l;
            signed = r != 0;
        }
        if let Some(s) = a.eddsa_ctx.get_mut(t) {
            *s = Some(ctx);
        }
        if !ok {
            eprintf!("EdDSA sign init failure\n");
            st.dofail();
            return -1;
        }
        if !signed {
            eprintf!("EdDSA sign failure\n");
            st.dofail();
            return -1;
        }
        count += 1;
    }
    count
}

/// `EdDSA_verify_loop`.
fn eddsa_verify_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let mut count = 0;
    while st.cond(count) {
        let ctx = a.eddsa_ctx2.get_mut(t).and_then(Option::take);
        let Some(ctx) = ctx else { return -1 };
        let ok = ctx.verify_reinit() != 0;
        let mut verified = true;
        if ok {
            let n = a.sigsize;
            let (buf, buf2) = a.bufs();
            verified = ctx.verify(
                buf2.get(..n).unwrap_or_default(),
                buf.get(..20).unwrap_or_default(),
            ) == 1;
        }
        if let Some(s) = a.eddsa_ctx2.get_mut(t) {
            *s = Some(ctx);
        }
        if !ok {
            eprintf!("EdDSA verify init failure\n");
            st.dofail();
            return -1;
        }
        if !verified {
            eprintf!("EdDSA verify failure\n");
            st.dofail();
            return -1;
        }
        count += 1;
    }
    count
}

/// `SM2_sign_loop`.
fn sm2_sign_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let Some(sm2) = a.sm2.get_mut(t).and_then(Option::take) else {
        return -1;
    };
    let max_size = usize::try_from(sm2.pkey.size()).unwrap_or(0);
    let mut count = 0;
    let mut result = None;
    while st.cond(count) {
        if sm2.ctx.sign_init(true, &sm2.pkey) == 0 {
            eprintf!("SM2 init sign failure\n");
            st.dofail();
            result = Some(-1);
            break;
        }
        let (buf, buf2) = a.bufs();
        let (r, l) = sm2
            .ctx
            .sign(buf2, max_size, buf.get(..20).unwrap_or_default());
        if r == 0 {
            eprintf!("SM2 sign failure\n");
            st.dofail();
            result = Some(-1);
            break;
        }
        // The latest size, for the verifications.
        a.sigsize = l;
        count += 1;
    }
    if let Some(s) = a.sm2.get_mut(t) {
        *s = Some(sm2);
    }
    result.unwrap_or(count)
}

/// `SM2_verify_loop`.
fn sm2_verify_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let Some(sm2) = a.sm2.get_mut(t).and_then(Option::take) else {
        return -1;
    };
    let n = a.sigsize;
    let mut count = 0;
    let mut result = None;
    while st.cond(count) {
        if sm2.vfy_ctx.verify_init(true, &sm2.pkey) == 0 {
            eprintf!("SM2 verify init failure\n");
            st.dofail();
            result = Some(-1);
            break;
        }
        let (buf, buf2) = a.bufs();
        if sm2.vfy_ctx.verify(
            buf2.get(..n).unwrap_or_default(),
            buf.get(..20).unwrap_or_default(),
        ) != 1
        {
            eprintf!("SM2 verify failure\n");
            st.dofail();
            result = Some(-1);
            break;
        }
        count += 1;
    }
    if let Some(s) = a.sm2.get_mut(t) {
        *s = Some(sm2);
    }
    result.unwrap_or(count)
}

/// `KEM_keygen_loop`.
fn kem_keygen_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let Some(Some(ctx)) = a.kem_gen_ctx.get(st.testnum) else {
        return -1;
    };
    let mut count = 0;
    while st.cond(count) {
        if ctx.keygen_into(None).0 <= 0 {
            return -1;
        }
        count += 1;
    }
    count
}

/// `KEM_encaps_loop`.
fn kem_encaps_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let mut out_len = a.kem_out_len.get(t).copied().unwrap_or(0);
    let mut secret_len = a.kem_secret_len.get(t).copied().unwrap_or(0);
    let Some(Some(ctx)) = a.kem_encaps_ctx.get(t) else {
        return -1;
    };
    let (Some(out), Some(secret)) = (a.kem_out.get_mut(t), a.kem_send_secret.get_mut(t)) else {
        return -1;
    };
    let mut count = 0;
    while st.cond(count) {
        let o = out.get_mut(..out_len).unwrap_or_default();
        let s = secret.get_mut(..secret_len).unwrap_or_default();
        let (r, ol, sl) = ctx.encapsulate_into(o, s);
        if r <= 0 {
            return -1;
        }
        (out_len, secret_len) = (ol, sl);
        count += 1;
    }
    count
}

/// `KEM_decaps_loop`.
fn kem_decaps_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let out_len = a.kem_out_len.get(t).copied().unwrap_or(0);
    let mut secret_len = a.kem_secret_len.get(t).copied().unwrap_or(0);
    let Some(Some(ctx)) = a.kem_decaps_ctx.get(t) else {
        return -1;
    };
    let (Some(out), Some(secret)) = (a.kem_out.get(t), a.kem_send_secret.get_mut(t)) else {
        return -1;
    };
    let mut count = 0;
    while st.cond(count) {
        let s = secret.get_mut(..secret_len).unwrap_or_default();
        let (r, sl) = ctx.decapsulate_into(s, out.get(..out_len).unwrap_or_default());
        if r <= 0 {
            return -1;
        }
        secret_len = sl;
        count += 1;
    }
    count
}

/// `SIG_keygen_loop`.
fn sig_keygen_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let Some(Some(ctx)) = a.sig_gen_ctx.get(st.testnum) else {
        return -1;
    };
    let mut count = 0;
    while st.cond(count) {
        let _ = ctx.keygen_into(None);
        count += 1;
    }
    count
}

/// `SIG_sign_loop`: into its own buffer, keeping the stored signature.
fn sig_sign_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let max = a.sig_max_sig_len.get(t).copied().unwrap_or(0);
    let Some(Some(ctx)) = a.sig_sign_ctx.get(t) else {
        return -1;
    };
    let mut sig = vec![0u8; max];
    let md = [0u8; SHA256_DIGEST_LENGTH];
    let mut count = 0;
    while st.cond(count) {
        if ctx.sign_into(&mut sig, &md).0 <= 0 {
            eprintf!("SIG sign failure at count {count}\n");
            st.dofail();
            return -1;
        }
        count += 1;
    }
    count
}

/// `SIG_verify_loop`.
fn sig_verify_loop(st: &State, a: &mut LoopArgs) -> i32 {
    let t = st.testnum;
    let len = a.sig_act_sig_len.get(t).copied().unwrap_or(0);
    let (Some(Some(ctx)), Some(sig)) = (a.sig_verify_ctx.get(t), a.sig_sig.get(t)) else {
        return -1;
    };
    let md = [0u8; SHA256_DIGEST_LENGTH];
    let mut count = 0;
    while st.cond(count) {
        if ctx.verify(sig.get(..len).unwrap_or_default(), &md) <= 0 {
            eprintf!("SIG verify failure at count {count}\n");
            st.dofail();
            return -1;
        }
        count += 1;
    }
    count
}

/// `have_md`.
fn have_md(name: &str) -> bool {
    let Some(md) = opt::md_silent(name) else {
        return false;
    };
    MdCtx::new().is_some_and(|ctx| ctx.digest_init(&md) > 0)
}

/// `have_cipher`.
fn have_cipher(name: &str) -> bool {
    let Some(cipher) = opt::cipher_silent(name) else {
        return false;
    };
    CipherCtx::new().is_some_and(|ctx| ctx.init(Some(&cipher), None, None, 1))
}

/// `init_evp_cipher_ctx`.
fn init_evp_cipher_ctx(name: &str, key: &[u8], keylen: i32) -> Option<CipherCtx> {
    let cipher = opt::cipher_silent(name)?;
    let ctx = CipherCtx::new()?;
    if !ctx.init(Some(&cipher), None, None, 1)
        || ctx.set_key_length(keylen) <= 0
        || !ctx.init(None, Some(key), Some(&IV), 1)
    {
        return None;
    }
    Some(ctx)
}

/// `check_block_size`.
fn check_block_size(ctx: Option<&CipherCtx>, length: i32) -> bool {
    let (name, blocksize) = match ctx {
        Some(c) => (c.cipher_name(), c.block_size()),
        None => (None, 0),
    };
    let Some(name) = name.filter(|_| blocksize > 0) else {
        eprintf!("\nInvalid cipher!\n");
        return false;
    };
    if length % blocksize != 0 {
        let name = name.unwrap_or_else(|| "(null)".to_owned());
        eprintf!("\nRequested encryption length not a multiple of block size for {name}!\n");
        return false;
    }
    true
}

/// `get_ecdsa`: a key on the curve (EC, or a curve with its own key type).
fn get_ecdsa(st: &mut State, curve: &Curve) -> Option<Pkey> {
    if err::peek_error() != 0 {
        eprintf!("WARNING: the error queue contains previous unhandled errors.\n");
        st.dofail();
    }
    let kctx = match PkeyCtx::new_id(curve.nid, None) {
        Some(k) => Some(k),
        None => {
            // The expected "unsupported algorithm" error is handled here.
            let error = err::peek_error();
            if error == err::peek_last_error()
                && err::lib(error) == ERR_LIB_EVP
                && (err::reason(error) == EVP_R_UNSUPPORTED_ALGORITHM
                    || err::reason(error) == ERR_R_UNSUPPORTED)
            {
                err::get_error();
            }
            if err::peek_error() != 0 {
                eprintf!("Unhandled error in the error queue during EC key setup.\n");
                st.dofail();
                return None;
            }
            let params = PkeyCtx::from_name(None, "EC", None).and_then(|pctx| {
                if pctx.paramgen_init() <= 0 || pctx.set_ec_paramgen_curve_nid(curve.nid) <= 0 {
                    return None;
                }
                match pctx.paramgen() {
                    (r, Some(p)) if r > 0 => Some(p),
                    _ => None,
                }
            });
            let Some(params) = params else {
                eprintf!("EC params init failure.\n");
                st.dofail();
                return None;
            };
            PkeyCtx::new(&params, None)
        }
    };
    let key = kctx.and_then(|k| {
        if k.keygen_init() <= 0 {
            return None;
        }
        match k.keygen_into(None) {
            (r, Some(key)) if r > 0 => Some(key),
            _ => None,
        }
    });
    if key.is_none() {
        eprintf!("EC key generation failure.\n");
        st.dofail();
    }
    key
}

/// `stop_it`: no more of this kind, from `test_num` on.
fn stop_it(doit: &mut [u8], test_num: usize) {
    for d in doit.iter_mut().skip(test_num) {
        *d = 0;
    }
}

/// Writes to standard output (`printf`).
fn out(text: &str) {
    let _ = io::out().write_all(text.as_bytes());
}

/// What `run` hands back to `main`.
struct Outcome {
    ret: i32,
    engine: Option<Engine>,
    async_init: bool,
}

pub fn main(argv: &[String]) -> i32 {
    let mut st = State::new();
    let mut o = Outcome {
        ret: 1,
        engine: None,
        async_init: false,
    };
    if let Some(ret) = run(argv, &mut st, &mut o) {
        return ret;
    }
    if o.ret == 0 && st.testmode {
        o.ret = i32::from(st.testmoderesult.get());
    }
    io::print_errors();
    if o.async_init {
        async_job::cleanup_thread();
    }
    // release_engine.
    drop(o.engine.take());
    o.ret
}

/// `do_multi`: forks `multi` children, which run the benchmarks with `-mr` and come back
/// `false`; the parent reads their results and comes back `true`.
fn do_multi(st: &mut State, results: &mut Results, multi: i32, size_num: usize) -> bool {
    let mut pipes = Vec::new();
    for n in 0..multi {
        match os::fork_to_pipe() {
            Err(os::ForkError::Pipe) => {
                eprintf!("pipe failure\n");
                crate::exit(1);
            }
            Err(os::ForkError::Dup) => {
                eprintf!("dup failed\n");
                crate::exit(1);
            }
            Ok(os::Forked::Child) => {
                st.mr = true;
                st.usertime = false;
                return false;
            }
            Ok(os::Forked::Parent(f)) => pipes.push(f),
        }
        out(&format!("Forked child {n}\n"));
    }

    for (n, mut f) in pipes.into_iter().enumerate() {
        let mut data = Vec::new();
        let _ = f.read_to_end(&mut data);
        // fgets into a 1024-byte buffer: lines, or 1023-byte pieces of longer ones.
        let mut rest = data.as_slice();
        while !rest.is_empty() {
            let end = rest
                .iter()
                .take(1023)
                .position(|&b| b == b'\n')
                .map_or(rest.len().min(1023), |p| p + 1);
            let (chunk, tail) = rest.split_at(end);
            rest = tail;
            let line = chunk.strip_suffix(b"\n").unwrap_or(chunk);
            let line = line.split(|&b| b == 0).next().unwrap_or_default();
            let buf = String::from_utf8_lossy(line).into_owned();
            if !buf.starts_with('+') {
                eprintf!("Don't understand line '{buf}' from child {n}\n");
                continue;
            }
            out(&format!("Got: {buf} from {n}\n"));
            results.merge(&buf, n, size_num);
        }
    }
    for _ in 0..multi {
        let status = loop {
            match os::wait() {
                Ok(s) => break s,
                Err(e) if e == libc_eintr() => {}
                Err(e) => {
                    eprintf!("Waitng for child failed with 0x{e:x}\n");
                    return true;
                }
            }
        };
        match status {
            os::ChildStatus::Exited(code) if code != 0 => {
                eprintf!("Child exited with {code}\n");
            }
            os::ChildStatus::Signaled(sig) => {
                eprintf!("Child terminated by signal {sig}\n");
            }
            _ => {}
        }
    }
    true
}

/// `EINTR`.
fn libc_eintr() -> i32 {
    4
}

/// The asymmetric results (`rsa_results`, ...) and the KEM and signature lists.
struct Results {
    sym: [[f64; 6]; ALGOR_NUM],
    rsa: [[f64; 4]; 7],
    dsa: [[f64; 2]; 2],
    ecdsa: [[f64; 2]; ECDSA_NUM],
    ecdh: [f64; EC_NUM],
    eddsa: [[f64; 2]; 2],
    sm2: [[f64; 2]; 1],
    ffdh: [f64; 5],
    kems: Vec<[f64; 3]>,
    sigs: Vec<[f64; 3]>,
}

impl Results {
    /// One `+F...` line of a child's (`do_multi`'s parsing).
    fn merge(&mut self, buf: &str, n: usize, size_num: usize) {
        // sstrsep on ':': the next field, empty at the end.
        let fields = |p: &str| -> Vec<String> { p.split(':').map(str::to_owned).collect() };
        let add2 = |slot: &mut [f64; 2], f: &[String], from: usize| {
            for (j, v) in slot.iter_mut().enumerate() {
                *v += atof(f.get(from + j).map_or("", String::as_str));
            }
        };
        if let Some(p) = buf.strip_prefix("+F:") {
            let f = fields(p);
            if let Some(alg) = strtoint(f.first().map_or("", String::as_str), 0, ALGOR_NUM_I) {
                for j in 0..size_num {
                    if let Some(r) = self.sym.get_mut(alg).and_then(|r| r.get_mut(j)) {
                        *r += atof(f.get(2 + j).map_or("", String::as_str));
                    }
                }
            }
        } else if let Some(p) = buf.strip_prefix("+F2:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, 7)
                && let Some(r) = self.rsa.get_mut(k)
            {
                for (j, v) in r.iter_mut().enumerate() {
                    *v += atof(f.get(2 + j).map_or("", String::as_str));
                }
            }
        } else if let Some(p) = buf.strip_prefix("+F3:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, 2)
                && let Some(r) = self.dsa.get_mut(k)
            {
                add2(r, &f, 2);
            }
        } else if let Some(p) = buf.strip_prefix("+F4:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, ECDSA_NUM_I)
                && let Some(r) = self.ecdsa.get_mut(k)
            {
                add2(r, &f, 2);
            }
        } else if let Some(p) = buf.strip_prefix("+F5:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, EC_NUM_I)
                && let Some(r) = self.ecdh.get_mut(k)
            {
                *r += atof(f.get(2).map_or("", String::as_str));
            }
        } else if let Some(p) = buf.strip_prefix("+F6:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, 2)
                && let Some(r) = self.eddsa.get_mut(k)
            {
                add2(r, &f, 3);
            }
        } else if let Some(p) = buf.strip_prefix("+F7:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, 1)
                && let Some(r) = self.sm2.get_mut(k)
            {
                add2(r, &f, 3);
            }
        } else if let Some(p) = buf.strip_prefix("+F8:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, 5)
                && let Some(r) = self.ffdh.get_mut(k)
            {
                *r += atof(f.get(2).map_or("", String::as_str));
            }
        } else if let Some(p) = buf.strip_prefix("+F9:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, MAX_KEM_NUM_I) {
                if self.kems.len() <= k {
                    self.kems.resize(k + 1, [0.0; 3]);
                }
                if let Some(r) = self.kems.get_mut(k) {
                    for (j, v) in r.iter_mut().enumerate() {
                        *v += atof(f.get(1 + j).map_or("", String::as_str));
                    }
                }
            }
        } else if let Some(p) = buf.strip_prefix("+F10:") {
            let f = fields(p);
            if let Some(k) = strtoint(f.first().map_or("", String::as_str), 0, MAX_SIG_NUM_I) {
                if self.sigs.len() <= k {
                    self.sigs.resize(k + 1, [0.0; 3]);
                }
                if let Some(r) = self.sigs.get_mut(k) {
                    for (j, v) in r.iter_mut().enumerate() {
                        *v += atof(f.get(1 + j).map_or("", String::as_str));
                    }
                }
            }
        } else if !buf.starts_with("+H:") {
            eprintf!("Unknown type '{buf}' from child {n}\n");
        }
    }
}

/// `mac_setup`: a MAC context with `params` for each looparg.
fn mac_setup(name: &str, params: &ParamValues, loopargs: &[RefCell<LoopArgs>]) -> Option<Mac> {
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let mac = Mac::fetch(lc.as_deref(), name, pq.as_deref())?;
    for l in loopargs {
        let ctx = MacCtx::new(&mac)?;
        if !ctx.set_params(params) {
            return None;
        }
        l.borrow_mut().mctx = Some(ctx);
    }
    Some(mac)
}

/// `mac_teardown`.
fn mac_teardown(loopargs: &[RefCell<LoopArgs>]) {
    for l in loopargs {
        l.borrow_mut().mctx = None;
    }
}

/// `main` up to `end:`: `Some(ret)` returns at once (upstream's `return`), `None` goes on to
/// the end with `o.ret`.
fn run(argv: &[String], st: &mut State, o: &mut Outcome) -> Option<i32> {
    let mut p = Parser::new(argv, OPTIONS);
    let prog = p.prog();
    let opterr = |prog: &str| {
        eprintf!("{prog}: Use -help for summary.\n");
    };
    let mut doit = [0u8; ALGOR_NUM];
    let mut evp_cipher: Option<Cipher> = None;
    let mut evp_mac_mdname = "sha256".to_owned();
    let mut evp_mac_ciphername = "aes-128-cbc".to_owned();
    let mut engine_id: Option<String> = None;
    let (mut multi, mut async_jobs, mut misalign) = (0i32, 0usize, 0i32);
    let (mut multiblock, mut domlock) = (false, false);
    let mut lengths_single = 0i32;
    let mut bytes_given = false;
    let mut size_num = LENGTHS_LIST.len();
    let mut primes = RSA_DEFAULT_PRIME_NUM;
    let (mut do_kems, mut do_sigs) = (false, false);
    let mut _conf = None;
    let mut seconds = Seconds {
        sym: SECONDS,
        rsa: PKEY_SECONDS,
        dsa: PKEY_SECONDS,
        ecdsa: PKEY_SECONDS,
        ecdh: PKEY_SECONDS,
        eddsa: PKEY_SECONDS,
        sm2: PKEY_SECONDS,
        ffdh: PKEY_SECONDS,
        kem: PKEY_SECONDS,
        sig: PKEY_SECONDS,
    };

    loop {
        match p.next() {
            Opt::EOF => break,
            Opt::ERR => {
                opterr(&prog);
                return None;
            }
            Opt::HELP => {
                opt::help(OPTIONS);
                o.ret = 0;
                return None;
            }
            Opt::ELAPSED => st.usertime = false,
            Opt::EVP => {
                if at(doit.as_slice(), D_EVP) != 0 {
                    eprintf!("{prog}: -evp option cannot be used more than once\n");
                    opterr(&prog);
                    return None;
                }
                let arg = p.arg().to_owned();
                err::set_mark();
                evp_cipher = opt::cipher_silent(&arg);
                if evp_cipher.is_none() && have_md(&arg) {
                    st.evp_md_name = Some(arg.clone());
                }
                if evp_cipher.is_none() && st.evp_md_name.is_none() {
                    err::clear_last_mark();
                    eprintf!("{prog}: {arg} is an unknown cipher or digest\n");
                    return None;
                }
                err::pop_to_mark();
                set(doit.as_mut_slice(), D_EVP, 1);
            }
            Opt::HMAC => {
                let arg = p.arg().to_owned();
                if !have_md(&arg) {
                    eprintf!("{prog}: {arg} is an unknown digest\n");
                    return None;
                }
                evp_mac_mdname = arg;
                set(doit.as_mut_slice(), D_HMAC, 1);
            }
            Opt::CMAC => {
                let arg = p.arg().to_owned();
                if !have_cipher(&arg) {
                    eprintf!("{prog}: {arg} is an unknown cipher\n");
                    return None;
                }
                evp_mac_ciphername = arg;
                set(doit.as_mut_slice(), D_EVP_CMAC, 1);
            }
            Opt::DECRYPT => st.decrypt = true,
            // The engine is set up later, after any fork.
            Opt::ENGINE => engine_id = Some(p.arg().to_owned()),
            Opt::MULTI => multi = p.int_arg(),
            Opt::ASYNCJOBS => {
                let n = p.int_arg();
                async_jobs = usize::try_from(n).unwrap_or(0);
                if n > 99999 {
                    eprintf!("{prog}: too many async_jobs\n");
                    opterr(&prog);
                    return None;
                }
                if !async_job::is_capable() {
                    eprintf!("{prog}: async_jobs specified but async not supported\n");
                    if st.testmode {
                        // Success in test mode.
                        return Some(0);
                    }
                    opterr(&prog);
                    return None;
                }
            }
            Opt::MISALIGN => {
                misalign = p.int_arg();
                if misalign > MISALIGN {
                    eprintf!("{prog}: Maximum offset is {MISALIGN}\n");
                    opterr(&prog);
                    return None;
                }
            }
            Opt::MR => st.mr = true,
            Opt::MB => multiblock = true,
            Opt::OPT_R(r) => {
                if !app_rand::opt_rand(r, p.arg()) {
                    return None;
                }
            }
            Opt::OPT_PROV(pv) => {
                if !app_libctx::opt_provider(pv, p.arg()) {
                    return None;
                }
            }
            Opt::CONFIG => {
                _conf = Some(app_load_config_modules(Some(&ConfigFile::Given(
                    p.arg().to_owned(),
                )))?);
            }
            Opt::PRIMES => primes = p.int_arg(),
            Opt::SECONDS => {
                let s = p.int_arg();
                seconds = Seconds {
                    sym: s,
                    rsa: s,
                    dsa: s,
                    ecdsa: s,
                    ecdh: s,
                    eddsa: s,
                    sm2: s,
                    ffdh: s,
                    kem: s,
                    sig: s,
                };
            }
            Opt::BYTES => {
                lengths_single = p.int_arg();
                bytes_given = true;
                st.lengths = vec![lengths_single];
                size_num = 1;
            }
            Opt::AEAD => st.aead = true,
            Opt::KEM => do_kems = true,
            Opt::SIG => do_sigs = true,
            Opt::MLOCK => {
                domlock = true;
                if !cfg!(target_os = "linux") {
                    eprintf!("{prog}: -mlock not supported on this platform\n");
                    return None;
                }
            }
            Opt::TESTMODE => st.testmode = true,
        }
    }

    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();

    // Every KEM there is.
    let mut kems_algname: Vec<String> = Vec::new();
    let mut kems_doit = [0u8; MAX_KEM_NUM];
    for kem in evp::kems(lc.as_deref()) {
        err::set_mark();
        let fetchable = evp::kem_fetchable(lc.as_deref(), &kem.name, pq.as_deref());
        err::pop_to_mark();
        if !fetchable {
            continue;
        }
        let add: Vec<String> = match kem.name.as_str() {
            "RSA" => RSA_CHOICES.iter().map(|s| (*s).to_owned()).collect(),
            "EC" => ["ECP-256", "ECP-384", "ECP-521"]
                .map(str::to_owned)
                .to_vec(),
            n => vec![n.to_owned()],
        };
        if kems_algname.len() + add.len() >= MAX_KEM_NUM {
            eprintf!("Too many KEMs registered. Change MAX_KEM_NUM.\n");
            return None;
        }
        for name in add {
            if let Some(d) = kems_doit.get_mut(kems_algname.len()) {
                *d = 1;
            }
            kems_algname.push(name);
        }
    }

    // Every signature algorithm there is, but those benchmarked elsewhere.
    let mut sigs_algname: Vec<String> = Vec::new();
    let mut sigs_doit = [0u8; MAX_SIG_NUM];
    for sig in evp::signatures(lc.as_deref()) {
        err::set_mark();
        let fetchable = Signature::fetch(lc.as_deref(), &sig.name, pq.as_deref()).is_some();
        err::pop_to_mark();
        if !fetchable {
            continue;
        }
        let n = sig.name.as_str();
        let add: Vec<String> = if n == "RSA" {
            RSA_CHOICES.iter().map(|s| (*s).to_owned()).collect()
        } else if n == "DSA" {
            DSA_CHOICES.iter().map(|s| (*s).to_owned()).collect()
        } else if !["RSA", "DSA", "ED25519", "ED448", "ECDSA"]
            .iter()
            .any(|p| n.starts_with(p))
            && !["HMAC", "SIPHASH", "POLY1305", "CMAC", "SM2"].contains(&n)
        {
            vec![n.to_owned()]
        } else {
            Vec::new()
        };
        if add.is_empty() {
            continue;
        }
        if sigs_algname.len() + add.len() >= MAX_SIG_NUM {
            eprintf!("Too many signatures registered. Change MAX_SIG_NUM.\n");
            return None;
        }
        for name in add {
            if let Some(d) = sigs_doit.get_mut(sigs_algname.len()) {
                *d = 1;
            }
            sigs_algname.push(name);
        }
    }

    // The remaining arguments are algorithms.
    let algos: Vec<String> = p.rest().to_vec();
    if !app_rand::load() {
        return None;
    }

    let mut rsa_doit = [0u8; 7];
    let mut ffdh_doit = [0u8; 5];
    let mut dsa_doit = [0u8; 2];
    let mut ecdsa_doit = [0u8; ECDSA_NUM];
    let mut ecdh_doit = [0u8; EC_NUM];
    let mut eddsa_doit = [0u8; 2];
    let mut sm2_doit = [0u8; 1];
    let found = |list: &[&str], a: &str| list.iter().position(|n| *n == a);
    for algo in &algos {
        let algo = algo.as_str();
        let mut algo_found = false;
        if let Some((_, i)) = DOIT_CHOICES.iter().find(|(n, _)| *n == algo) {
            set(doit.as_mut_slice(), *i, 1);
            algo_found = true;
        }
        if algo == "des" {
            set(doit.as_mut_slice(), D_CBC_DES, 1);
            set(doit.as_mut_slice(), D_EDE3_DES, 1);
            algo_found = true;
        }
        if algo == "sha" {
            set(doit.as_mut_slice(), D_SHA1, 1);
            set(doit.as_mut_slice(), D_SHA256, 1);
            set(doit.as_mut_slice(), D_SHA512, 1);
            algo_found = true;
        }
        // Just for compatibility.
        if algo == "openssl" {
            algo_found = true;
        }
        if algo.starts_with("rsa") {
            if algo == "rsa" {
                rsa_doit = [1; 7];
                algo_found = true;
            }
            if let Some(i) = found(&RSA_CHOICES, algo) {
                set(rsa_doit.as_mut_slice(), i, 1);
                algo_found = true;
            }
        }
        if algo.starts_with("ffdh") {
            if algo == "ffdh" {
                ffdh_doit = [1; 5];
                algo_found = true;
            }
            if let Some(i) = found(&FFDH_CHOICES, algo) {
                set(ffdh_doit.as_mut_slice(), i, 2);
                algo_found = true;
            }
        }
        if algo.starts_with("dsa") {
            if algo == "dsa" {
                dsa_doit = [1; 2];
                algo_found = true;
            }
            if let Some(i) = found(&DSA_CHOICES, algo) {
                set(dsa_doit.as_mut_slice(), i, 2);
                algo_found = true;
            }
        }
        if algo == "aes" {
            for i in 0..3 {
                set(doit.as_mut_slice(), D_CBC_128_AES + i, 1);
            }
            algo_found = true;
        }
        if algo == "camellia" {
            for i in 0..3 {
                set(doit.as_mut_slice(), D_CBC_128_CML + i, 1);
            }
            algo_found = true;
        }
        if algo.starts_with("ecdsa") {
            if algo == "ecdsa" {
                ecdsa_doit = [1; ECDSA_NUM];
                algo_found = true;
            }
            if let Some(i) = found(&ECDSA_CHOICES, algo) {
                set(ecdsa_doit.as_mut_slice(), i, 2);
                algo_found = true;
            }
        }
        if algo.starts_with("ecdh") {
            if algo == "ecdh" {
                ecdh_doit = [1; EC_NUM];
                algo_found = true;
            }
            if let Some(i) = found(&ECDH_CHOICES, algo) {
                set(ecdh_doit.as_mut_slice(), i, 2);
                algo_found = true;
            }
        }
        if algo == "eddsa" {
            eddsa_doit = [1; 2];
            algo_found = true;
        }
        if let Some(i) = found(&EDDSA_CHOICES, algo) {
            set(eddsa_doit.as_mut_slice(), i, 2);
            algo_found = true;
        }
        if algo == "sm2" {
            sm2_doit = [1; 1];
            algo_found = true;
        }
        if let Some(i) = found(&SM2_CHOICES, algo) {
            set(sm2_doit.as_mut_slice(), i, 2);
            algo_found = true;
        }
        if let Some(i) = kems_algname.iter().position(|n| n == algo) {
            if let Some(d) = kems_doit.get_mut(i) {
                *d = d.wrapping_add(1);
            }
            do_kems = true;
            algo_found = true;
        }
        if let Some(i) = sigs_algname.iter().position(|n| n == algo) {
            if let Some(d) = sigs_doit.get_mut(i) {
                *d = d.wrapping_add(1);
            }
            do_sigs = true;
            algo_found = true;
        }
        if algo == "kmac" {
            set(doit.as_mut_slice(), D_KMAC128, 1);
            set(doit.as_mut_slice(), D_KMAC256, 1);
            algo_found = true;
        }
        if algo == "cmac" {
            set(doit.as_mut_slice(), D_EVP_CMAC, 1);
            algo_found = true;
        }
        if !algo_found {
            eprintf!("{prog}: Unknown algorithm {algo}\n");
            return None;
        }
    }

    let has_flag =
        |c: &Cipher, flag: core::ffi::c_int| u64::try_from(flag).is_ok_and(|f| c.flags() & f != 0);

    // Sanity checks.
    if st.aead {
        match &evp_cipher {
            None => {
                eprintf!("-aead can be used only with an AEAD cipher\n");
                return None;
            }
            Some(c) if !has_flag(c, EVP_CIPH_FLAG_AEAD_CIPHER) => {
                eprintf!(
                    "{} is not an AEAD cipher\n",
                    c.name().unwrap_or_else(|| "(null)".into())
                );
                return None;
            }
            Some(_) => {}
        }
    }
    // Some explicitly chosen: the others are off.
    for (doit, len) in [
        (&mut kems_doit[..], kems_algname.len()),
        (&mut sigs_doit[..], sigs_algname.len()),
    ] {
        if len > 0 && doit.iter().take(len).copied().max().unwrap_or(0) > 1 {
            for d in doit.iter_mut().take(len) {
                *d = d.wrapping_sub(1);
            }
        }
    }
    if multiblock {
        match &evp_cipher {
            None => {
                eprintf!("-mb can be used only with a multi-block capable cipher\n");
                return None;
            }
            Some(c) if !has_flag(c, EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK) => {
                eprintf!(
                    "{} is not a multi-block capable\n",
                    c.name().unwrap_or_else(|| "(null)".into())
                );
                return None;
            }
            Some(_) if async_jobs > 0 => {
                eprintf!("Async mode is not supported with -mb");
                return None;
            }
            Some(_) => {}
        }
    }

    // The job pool for async mode.
    if async_jobs > 0 {
        o.async_init = async_job::init_thread(async_jobs, async_jobs);
        if !o.async_init {
            eprintf!("Error creating the ASYNC job pool\n");
            return None;
        }
    }

    let loopargs_len = if async_jobs == 0 { 1 } else { async_jobs };
    let mut buflen = st.lengths.get(size_num - 1).copied().unwrap_or(0);
    // The size of the RSA benchmark's random vector.
    if buflen < 36 {
        buflen = 36;
    }
    if i32::MAX - (MAX_MISALIGNMENT + 1) < buflen {
        eprintf!("Error: buffer size too large\n");
        return None;
    }
    buflen += MAX_MISALIGNMENT + 1;
    let buflen_u = usize::try_from(buflen).unwrap_or(0);
    let misalign_u = usize::try_from(misalign).unwrap_or(0);
    let mut jobs = None;
    if async_jobs > 0 {
        jobs = Jobs::new(loopargs_len);
        if jobs.is_none() {
            eprintf!("Error creating the ASYNC_WAIT_CTX\n");
            return None;
        }
    }
    let loopargs: Vec<RefCell<LoopArgs>> = (0..loopargs_len)
        .map(|_| {
            RefCell::new(LoopArgs {
                buf_malloc: vec![0; buflen_u + SLACK],
                buf2_malloc: vec![0; buflen_u + SLACK],
                misalign: misalign_u,
                buflen: buflen_u.saturating_sub(misalign_u),
                sigsize: buflen_u.saturating_sub(misalign_u),
                secret_a: vec![0; MAX_ECDH_SIZE],
                secret_b: vec![0; MAX_ECDH_SIZE],
                secret_ff_a: vec![0; MAX_FFDH_SIZE],
                secret_ff_b: vec![0; MAX_FFDH_SIZE],
                ecdsa_sign_ctx: (0..ECDSA_NUM).map(|_| None).collect(),
                ecdsa_verify_ctx: (0..ECDSA_NUM).map(|_| None).collect(),
                ecdh_ctx: (0..EC_NUM).map(|_| None).collect(),
                kem_gen_ctx: (0..MAX_KEM_NUM).map(|_| None).collect(),
                kem_encaps_ctx: (0..MAX_KEM_NUM).map(|_| None).collect(),
                kem_decaps_ctx: (0..MAX_KEM_NUM).map(|_| None).collect(),
                kem_out_len: vec![0; MAX_KEM_NUM],
                kem_secret_len: vec![0; MAX_KEM_NUM],
                kem_out: vec![Vec::new(); MAX_KEM_NUM],
                kem_send_secret: vec![Vec::new(); MAX_KEM_NUM],
                kem_rcv_secret: vec![Vec::new(); MAX_KEM_NUM],
                sig_gen_ctx: (0..MAX_SIG_NUM).map(|_| None).collect(),
                sig_sign_ctx: (0..MAX_SIG_NUM).map(|_| None).collect(),
                sig_verify_ctx: (0..MAX_SIG_NUM).map(|_| None).collect(),
                sig_max_sig_len: vec![0; MAX_SIG_NUM],
                sig_act_sig_len: vec![0; MAX_SIG_NUM],
                sig_sig: vec![Vec::new(); MAX_SIG_NUM],
                ..LoopArgs::default()
            })
        })
        .collect();

    let mut res = Results {
        sym: [[0.0; 6]; ALGOR_NUM],
        rsa: [[0.0; 4]; 7],
        dsa: [[0.0; 2]; 2],
        ecdsa: [[0.0; 2]; ECDSA_NUM],
        ecdh: [0.0; EC_NUM],
        eddsa: [[0.0; 2]; 2],
        sm2: [[0.0; 2]; 1],
        ffdh: [0.0; 5],
        kems: vec![[0.0; 3]; MAX_KEM_NUM],
        sigs: vec![[0.0; 3]; MAX_SIG_NUM],
    };
    let mut pr_header = 0;
    let mut show_res = false;
    if multi != 0 && do_multi(st, &mut res, multi, size_num) {
        show_res = true;
        st.results = res.sym;
    }

    if !show_res {
        if domlock {
            for l in &loopargs {
                let l = l.borrow();
                // Upstream locks the first buffer twice.
                os::mlock(&l.buf_malloc);
                os::mlock(&l.buf_malloc);
            }
        }

        // The engine, after the fork.
        o.engine = engine::setup_engine(engine_id.as_deref(), false);

        // No parameters: everything.
        if algos.is_empty()
            && at(doit.as_slice(), D_EVP) == 0
            && at(doit.as_slice(), D_HMAC) == 0
            && at(doit.as_slice(), D_EVP_CMAC) == 0
            && !do_kems
            && !do_sigs
        {
            doit = [1; ALGOR_NUM];
            set(doit.as_mut_slice(), D_EVP, 0);
            set(doit.as_mut_slice(), D_EVP_CMAC, 0);
            err::set_mark();
            for i in D_MD2..=D_WHIRLPOOL {
                if !have_md(NAMES.get(i).copied().unwrap_or_default()) {
                    set(doit.as_mut_slice(), i, 0);
                }
            }
            for i in D_CBC_DES..=D_CBC_256_CML {
                if !have_cipher(NAMES.get(i).copied().unwrap_or_default()) {
                    set(doit.as_mut_slice(), i, 0);
                }
            }
            if Mac::fetch(lc.as_deref(), "GMAC", pq.as_deref()).is_none() {
                set(doit.as_mut_slice(), D_GHASH, 0);
            }
            if Mac::fetch(lc.as_deref(), "HMAC", pq.as_deref()).is_none() {
                set(doit.as_mut_slice(), D_HMAC, 0);
            }
            err::pop_to_mark();
            rsa_doit = [1; 7];
            ffdh_doit = [1; 5];
            dsa_doit = [1; 2];
            ecdsa_doit = [1; ECDSA_NUM];
            ecdh_doit = [1; EC_NUM];
            eddsa_doit = [1; 2];
            sm2_doit = [1; 1];
            kems_doit = [1; MAX_KEM_NUM];
            do_kems = true;
            sigs_doit = [1; MAX_SIG_NUM];
            do_sigs = true;
        }
    }
    if !show_res {
        pr_header = doit.iter().filter(|&&d| d != 0).count();
        if !st.usertime && !st.mr {
            eprintf!("You have chosen to measure elapsed time instead of user CPU time.\n");
        }
        os::catch_alarm();

        let mut digest_runs: Vec<(usize, LoopFn)> = vec![
            (D_MD2, md2_loop),
            (D_MDC2, mdc2_loop),
            (D_MD4, md4_loop),
            (D_MD5, md5_loop),
            (D_SHA1, sha1_loop),
            (D_SHA256, sha256_loop),
            (D_SHA512, sha512_loop),
            (D_WHIRLPOOL, whirlpool_loop),
            (D_RMD160, rmd160_loop),
        ];
        for (alg, f) in digest_runs.drain(..) {
            if at(doit.as_slice(), alg) == 0 {
                continue;
            }
            for t in 0..size_num {
                st.testnum = t;
                let name = st.name(alg);
                st.print_message(&name, st.length(t), seconds.sym);
                st.time_start();
                let count = run_benchmark(st, jobs.as_mut(), &loopargs, f);
                let d = st.time_stop();
                st.print_result(alg, t, count, d);
                if count < 0 {
                    break;
                }
            }
        }

        if at(doit.as_slice(), D_HMAC) != 0 {
            let hmac_key = b"This is a key...";
            st.names[D_HMAC] = format!("hmac({evp_mac_mdname})");
            let params = ParamValues::new()
                .utf8(s(OSSL_MAC_PARAM_DIGEST), &evp_mac_mdname)
                .octets(s(OSSL_MAC_PARAM_KEY), hmac_key);
            mac_setup("HMAC", &params, &loopargs)?;
            mac_benchmark(
                st,
                jobs.as_mut(),
                &loopargs,
                D_HMAC,
                size_num,
                seconds.sym,
                mac_loop,
            );
            mac_teardown(&loopargs);
        }

        let cipher_run = |st: &mut State,
                          jobs: &mut Option<Jobs>,
                          alg: usize,
                          cname: &str,
                          key: &[u8],
                          keylen: i32| {
            let mut ok = true;
            for l in &loopargs {
                if !ok {
                    break;
                }
                let ctx = init_evp_cipher_ctx(cname, key, keylen);
                ok = ctx.is_some();
                l.borrow_mut().ctx = ctx;
            }
            st.algindex = alg;
            for t in 0..size_num {
                if !ok {
                    break;
                }
                st.testnum = t;
                let first = loopargs.first().map(|l| l.borrow_mut().ctx.take());
                let first = first.flatten();
                let good = check_block_size(first.as_ref(), st.length(t));
                if let Some(l) = loopargs.first() {
                    l.borrow_mut().ctx = first;
                }
                if !good {
                    break;
                }
                let name = st.name(alg);
                st.print_message(&name, st.length(t), seconds.sym);
                st.time_start();
                let count = run_benchmark(st, jobs.as_mut(), &loopargs, cipher_loop);
                let d = st.time_stop();
                st.print_result(alg, t, count, d);
            }
            for l in &loopargs {
                l.borrow_mut().ctx = None;
            }
        };
        if at(doit.as_slice(), D_CBC_DES) != 0 {
            cipher_run(st, &mut jobs, D_CBC_DES, "des-cbc", &DESKEY, 8);
        }
        if at(doit.as_slice(), D_EDE3_DES) != 0 {
            cipher_run(st, &mut jobs, D_EDE3_DES, "des-ede3-cbc", &DESKEY, 24);
        }
        for k in 0..3 {
            let alg = D_CBC_128_AES + k;
            if at(doit.as_slice(), alg) != 0 {
                let name = st.name(alg);
                cipher_run(
                    st,
                    &mut jobs,
                    alg,
                    &name,
                    &KEY32,
                    16 + 8 * i32::try_from(k).unwrap_or(0),
                );
            }
        }
        for k in 0..3 {
            let alg = D_CBC_128_CML + k;
            if at(doit.as_slice(), alg) != 0 {
                let name = st.name(alg);
                cipher_run(
                    st,
                    &mut jobs,
                    alg,
                    &name,
                    &KEY32,
                    16 + 8 * i32::try_from(k).unwrap_or(0),
                );
            }
        }
        for alg in D_RC4..=D_CBC_CAST {
            if at(doit.as_slice(), alg) != 0 {
                let name = st.name(alg);
                cipher_run(st, &mut jobs, alg, &name, &KEY32, 16);
            }
        }

        if at(doit.as_slice(), D_GHASH) != 0 {
            let params = ParamValues::new()
                .utf8(s(OSSL_ALG_PARAM_CIPHER), "aes-128-gcm")
                .octets(s(OSSL_MAC_PARAM_IV), b"0123456789ab")
                .octets(s(OSSL_MAC_PARAM_KEY), KEY32.get(..16).unwrap_or_default());
            mac_setup("GMAC", &params, &loopargs)?;
            // GHASH_loop only updates: the contexts are initialized here.
            for l in &loopargs {
                if !l.borrow().mctx.as_ref().is_some_and(MacCtx::init) {
                    return None;
                }
            }
            mac_benchmark(
                st,
                jobs.as_mut(),
                &loopargs,
                D_GHASH,
                size_num,
                seconds.sym,
                ghash_loop,
            );
            mac_teardown(&loopargs);
        }

        if at(doit.as_slice(), D_RAND) != 0 {
            for t in 0..size_num {
                st.testnum = t;
                st.print_message(&st.name(D_RAND), st.length(t), seconds.sym);
                st.time_start();
                let count = run_benchmark(st, jobs.as_mut(), &loopargs, rand_loop);
                let d = st.time_stop();
                st.print_result(D_RAND, t, count, d);
            }
        }

        // EVP: authenticated encryption, with additional data or not, or neither.
        if at(doit.as_slice(), D_EVP) != 0 {
            if let Some(cipher) = &evp_cipher {
                if multiblock && has_flag(cipher, EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK) {
                    multiblock_speed(st, cipher, lengths_single, &seconds);
                    o.ret = 0;
                    return None;
                }
                st.names[D_EVP] = cipher.name().unwrap_or_else(|| "(null)".into());
                st.mode_op = cipher.mode();
                if st.aead && !bytes_given {
                    st.lengths = AEAD_LENGTHS_LIST.to_vec();
                    size_num = AEAD_LENGTHS_LIST.len();
                }
                let m = st.mode_op;
                let ae_mode = [
                    EVP_CIPH_GCM_MODE,
                    EVP_CIPH_CCM_MODE,
                    EVP_CIPH_OCB_MODE,
                    EVP_CIPH_SIV_MODE,
                    EVP_CIPH_GCM_SIV_MODE,
                ]
                .contains(&m);
                let loopfunc: LoopFn = if !ae_mode {
                    update_loop
                } else if st.decrypt {
                    update_loop_aead_dec
                } else {
                    update_loop_aead_enc
                };
                for t in 0..size_num {
                    st.testnum = t;
                    let name = st.name(D_EVP);
                    st.print_message(&name, st.length(t), seconds.sym);
                    for l in &loopargs {
                        evp_setup(st, cipher, &mut l.borrow_mut(), ae_mode);
                    }
                    st.time_start();
                    let count = run_benchmark(st, jobs.as_mut(), &loopargs, loopfunc);
                    let d = st.time_stop();
                    for l in &loopargs {
                        let mut l = l.borrow_mut();
                        l.key.clear();
                        l.ctx = None;
                    }
                    st.print_result(D_EVP, t, count, d);
                }
            } else if let Some(md) = st.evp_md_name.clone() {
                st.names[D_EVP] = md;
                for t in 0..size_num {
                    st.testnum = t;
                    let name = st.name(D_EVP);
                    st.print_message(&name, st.length(t), seconds.sym);
                    st.time_start();
                    let count = run_benchmark(st, jobs.as_mut(), &loopargs, evp_digest_md_loop);
                    let d = st.time_stop();
                    st.print_result(D_EVP, t, count, d);
                    if count < 0 {
                        break;
                    }
                }
            }
        }

        if at(doit.as_slice(), D_EVP_CMAC) != 0 {
            let cipher = opt::cipher(&evp_mac_ciphername)?;
            let keylen = cipher.key_length();
            drop(cipher);
            if keylen <= 0 || usize::try_from(keylen).is_ok_and(|k| k > KEY32.len()) {
                eprintf!("\nRequested CMAC cipher with unsupported key length.\n");
                return None;
            }
            st.names[D_EVP_CMAC] = format!("cmac({evp_mac_ciphername})");
            let params = ParamValues::new()
                .utf8(s(OSSL_ALG_PARAM_CIPHER), &evp_mac_ciphername)
                .octets(
                    s(OSSL_MAC_PARAM_KEY),
                    KEY32
                        .get(..usize::try_from(keylen).unwrap_or(0))
                        .unwrap_or_default(),
                );
            mac_setup("CMAC", &params, &loopargs)?;
            mac_benchmark(
                st,
                jobs.as_mut(),
                &loopargs,
                D_EVP_CMAC,
                size_num,
                seconds.sym,
                mac_loop,
            );
            mac_teardown(&loopargs);
        }

        for (alg, mac, keylen) in [(D_KMAC128, "KMAC-128", 16), (D_KMAC256, "KMAC-256", 32)] {
            if at(doit.as_slice(), alg) == 0 {
                continue;
            }
            let params = ParamValues::new().octets(
                s(OSSL_MAC_PARAM_KEY),
                KEY32.get(..keylen).unwrap_or_default(),
            );
            mac_setup(mac, &params, &loopargs)?;
            mac_benchmark(
                st,
                jobs.as_mut(),
                &loopargs,
                alg,
                size_num,
                seconds.sym,
                mac_loop,
            );
            mac_teardown(&loopargs);
        }

        for l in &loopargs {
            if rand::bytes(l.borrow_mut().buf().get_mut(..36).unwrap_or_default()) <= 0 {
                return None;
            }
        }

        let ctx = Asym {
            loopargs: &loopargs,
            res: &mut res,
        };
        asymmetric(
            st,
            &mut jobs,
            ctx,
            &seconds,
            primes,
            &mut rsa_doit,
            &mut dsa_doit,
            &mut ecdsa_doit,
            &mut ecdh_doit,
            &mut eddsa_doit,
            &mut sm2_doit,
            &mut ffdh_doit,
        );
        kems_and_sigs(
            st,
            &mut jobs,
            &loopargs,
            &mut res,
            &seconds,
            &kems_algname,
            &mut kems_doit,
            do_kems,
            &sigs_algname,
            &mut sigs_doit,
            do_sigs,
        );
    }

    // show_res:
    if !st.mr {
        out(&format!(
            "version: {}\n",
            crypto::version(OPENSSL_FULL_VERSION_STRING)
        ));
        out(&format!("{}\n", crypto::version(OPENSSL_BUILT_ON)));
        out(&format!("options: {}\n", crypto::bn_options()));
        out(&format!("{}\n", crypto::version(OPENSSL_CFLAGS)));
        out(&format!("{}\n", crypto::version(OPENSSL_CPU_INFO)));
    }
    if pr_header > 0 {
        let mut t = if st.mr {
            "+H".to_owned()
        } else {
            "The 'numbers' are in 1000s of bytes per second processed.\ntype        ".to_owned()
        };
        for &l in st.lengths.iter().take(size_num) {
            t.push_str(&if st.mr {
                format!(":{l}")
            } else {
                format!("{l:7} bytes")
            });
        }
        t.push('\n');
        out(&t);
    }
    for k in 0..ALGOR_NUM {
        if at(doit.as_slice(), k) == 0 {
            continue;
        }
        let alg_name = if k == D_EVP {
            match &evp_cipher {
                None => st.evp_md_name.clone().unwrap_or_else(|| "(null)".into()),
                Some(c) => match c.name() {
                    Some(n) => n,
                    None => app_bail_out("failed to get name of cipher\n"),
                },
            }
        } else {
            st.name(k)
        };
        let mut t = if st.mr {
            format!("+F:{k}:{alg_name}")
        } else {
            format!("{alg_name:<13}")
        };
        for r in st.results.get(k).into_iter().flatten().take(size_num) {
            if *r > 10000.0 && !st.mr {
                t.push_str(&format!(" {}k", cf(r / 1e3, 11, 2)));
            } else if st.mr {
                t.push_str(&format!(":{}", cf(*r, 0, 2)));
            } else {
                t.push_str(&format!(" {} ", cf(*r, 11, 2)));
            }
        }
        t.push('\n');
        out(&t);
    }
    print_asymmetric(
        st,
        &res,
        &rsa_doit,
        &dsa_doit,
        &ecdsa_doit,
        &ecdh_doit,
        &eddsa_doit,
        &sm2_doit,
        &ffdh_doit,
    );
    let mut first = true;
    for (k, name) in kems_algname.iter().enumerate() {
        if kems_doit.get(k).copied().unwrap_or(0) == 0 || !do_kems {
            continue;
        }
        if first && !st.mr {
            out(&format!(
                "{:31}keygen    encaps    decaps keygens/s  encaps/s  decaps/s\n",
                " "
            ));
            first = false;
        }
        let r = res.kems.get(k).copied().unwrap_or([0.0; 3]);
        out(&kem_sig_row(st.mr, 9, k, name, r));
    }
    let mut first = true;
    for (k, name) in sigs_algname.iter().enumerate() {
        if sigs_doit.get(k).copied().unwrap_or(0) == 0 || !do_sigs {
            continue;
        }
        if first && !st.mr {
            out(&format!(
                "{:31}keygen     signs    verify keygens/s    sign/s  verify/s\n",
                " "
            ));
            first = false;
        }
        let r = res.sigs.get(k).copied().unwrap_or([0.0; 3]);
        out(&kem_sig_row(st.mr, 10, k, name, r));
    }
    o.ret = 0;
    None
}

/// A KEM's or signature algorithm's row of the summary.
fn kem_sig_row(mr: bool, tag: u32, k: usize, name: &str, r: [f64; 3]) -> String {
    if mr {
        format!("+F{tag}:{k}:{}:{}:{}\n", f6(r[0]), f6(r[1]), f6(r[2]))
    } else {
        format!(
            "{name:>27} {}s {}s {}s {} {} {}\n",
            cf(1.0 / r[0], 8, 6),
            cf(1.0 / r[1], 8, 6),
            cf(1.0 / r[2], 8, 6),
            cf(r[0], 9, 1),
            cf(r[1], 9, 1),
            cf(r[2], 9, 1)
        )
    }
}

fn s(c: &std::ffi::CStr) -> &str {
    c.to_str().unwrap_or_default()
}

/// A MAC's runs over every length, stopping at a failure.
fn mac_benchmark(
    st: &mut State,
    mut jobs: Option<&mut Jobs>,
    loopargs: &[RefCell<LoopArgs>],
    alg: usize,
    size_num: usize,
    tm: i32,
    f: LoopFn,
) {
    for t in 0..size_num {
        st.testnum = t;
        let name = st.name(alg);
        st.print_message(&name, st.length(t), tm);
        st.time_start();
        let count = run_benchmark(st, jobs.as_deref_mut(), loopargs, f);
        let d = st.time_stop();
        st.print_result(alg, t, count, d);
        if count < 0 {
            break;
        }
    }
}

/// The per-looparg set-up of an EVP cipher run (`D_EVP`'s loop body).
fn evp_setup(st: &State, cipher: &Cipher, a: &mut LoopArgs, ae_mode: bool) {
    let mode = st.mode_op;
    let len = st.len();
    let Some(ctx) = CipherCtx::new() else {
        eprintf!("\nEVP_CIPHER_CTX_new failure\n");
        crate::exit(1);
    };
    // AE modes encrypt first, for a tag to decrypt with.
    let enc = if ae_mode { 1 } else { i32::from(!st.decrypt) };
    if !ctx.init(Some(cipher), None, None, enc) {
        aead_fail("\nCouldn't init the context\n");
    }
    // No padding.
    ctx.set_padding(false);
    let keylen = usize::try_from(ctx.key_length()).unwrap_or(0);
    a.key = vec![0; keylen];
    ctx.rand_key(&mut a.key);
    let key = a.key.clone();
    let mut ctx = ctx;
    if !ae_mode {
        if !ctx.init(None, Some(&key), Some(&IV), -1) {
            aead_fail("\nFailed to set the key\n");
        }
    } else if mode == EVP_CIPH_SIV_MODE || mode == EVP_CIPH_GCM_SIV_MODE {
        ctx.ctrl(EVP_CTRL_SET_SPEED, 1);
    }
    if ae_mode && st.decrypt {
        if mode != EVP_CIPH_SIV_MODE && ctx.ctrl(EVP_CTRL_AEAD_SET_IVLEN, AEAD_IVLEN_C) == 0 {
            aead_fail("\nFailed to set iv length\n");
        }
        if mode != EVP_CIPH_GCM_MODE
            && mode != EVP_CIPH_SIV_MODE
            && mode != EVP_CIPH_GCM_SIV_MODE
            && ctx.ctrl(EVP_CTRL_AEAD_SET_TAG, TAG_LEN_C) == 0
        {
            aead_fail("\nFailed to set tag length\n");
        }
        if !ctx.init(None, Some(&key), Some(&AEAD_IV), -1) {
            aead_fail("\nFailed to set the key\n");
        }
        if mode == EVP_CIPH_CCM_MODE
            && ctx.update_length(true, i32::try_from(len).unwrap_or(0)) == 0
        {
            aead_fail("\nCouldn't set input text length\n");
        }
        if st.aead && ctx.update_aad(true, &st.aad) == 0 {
            aead_fail("\nCouldn't insert AAD when encrypting\n");
        }
        if ctx.update_in_place(true, a.buf(), len).0 == 0 {
            aead_fail("\nFailed to to encrypt the data\n");
        }
        if ctx.finish(true, a.buf()) == 0 {
            aead_fail("\nFailed finalize the encryption\n");
        }
        if ctx.ctrl_buf(EVP_CTRL_AEAD_GET_TAG, &mut a.tag) <= 0 {
            aead_fail("\nFailed to get the tag\n");
        }
        let Some(c2) = CipherCtx::new() else {
            eprintf!("\nEVP_CIPHER_CTX_new failure\n");
            crate::exit(1);
        };
        ctx = c2;
        if !ctx.init(Some(cipher), None, None, 0) {
            aead_fail("\nFailed initializing the context\n");
        }
        ctx.set_padding(false);
        // GCM-SIV and SIV allow a single update only.
        if mode == EVP_CIPH_SIV_MODE || mode == EVP_CIPH_GCM_SIV_MODE {
            ctx.ctrl(EVP_CTRL_SET_SPEED, 1);
        }
    }
    a.ctx = Some(ctx);
}

/// `multiblock_speed`.
fn multiblock_speed(st: &mut State, cipher: &Cipher, lengths_single: i32, seconds: &Seconds) {
    const MBLENGTHS: [i32; 5] = [
        8 * 1024,
        2 * 8 * 1024,
        4 * 8 * 1024,
        8 * 8 * 1024,
        8 * 16 * 1024,
    ];
    let mblengths: Vec<i32> = if lengths_single != 0 {
        vec![lengths_single]
    } else {
        MBLENGTHS.to_vec()
    };
    let last = usize::try_from(*mblengths.last().unwrap_or(&0)).unwrap_or(0);
    // Upstream's records can read past the input's end; the slack keeps that in bounds.
    let mut inp = vec![0u8; last + 1024];
    let mut outb = vec![0u8; last + 1024];
    let Some(ctx) = CipherCtx::new() else {
        app_bail_out("failed to allocate cipher context\n");
    };
    let no_iv = [0u8; 16];
    let mut no_key = [0u8; 32];
    if !ctx.init(Some(cipher), None, Some(&no_iv), 1) {
        app_bail_out("failed to initialise cipher context\n");
    }
    let keylen = ctx.key_length();
    if keylen < 0 {
        eprintf!("Impossible negative key length: {keylen}\n");
        return;
    }
    let mut key = vec![0u8; usize::try_from(keylen).unwrap_or(0)];
    if ctx.rand_key(&mut key) <= 0 {
        app_bail_out("failed to generate random cipher key\n");
    }
    if !ctx.init(None, Some(&key), None, 1) {
        app_bail_out("failed to set cipher key\n");
    }
    drop(key);
    if ctx.ctrl_buf(EVP_CTRL_AEAD_SET_MAC_KEY, &mut no_key) <= 0 {
        app_bail_out("failed to set AEAD key\n");
    }
    let Some(alg_name) = cipher.name() else {
        app_bail_out("failed to get cipher name\n");
    };
    let mut ciph_success = 1;
    for (j, &mbl) in mblengths.iter().enumerate() {
        st.print_message(&alg_name, mbl, seconds.sym);
        st.time_start();
        let mut count = 0;
        while os::running() && st.cond(count) {
            let mut len = usize::try_from(mbl).unwrap_or(0);
            let aad = &mut st.aad;
            aad.iter_mut().take(8).for_each(|b| *b = 0);
            aad[8] = 23; // SSL3_RT_APPLICATION_DATA
            aad[9] = 3; // version
            aad[10] = 2;
            aad[11] = 0; // length
            aad[12] = 0;
            let packlen = ctx.multiblock_aad(aad, len, 8);
            if packlen > 0 {
                ctx.multiblock_encrypt(&mut outb, &inp, len, 8);
            } else {
                if rand::bytes(inp.get_mut(..16).unwrap_or_default()) <= 0 {
                    app_bail_out("error setting random bytes\n");
                }
                len += 16;
                let [.., hi, lo] = len.to_be_bytes();
                aad[11] = hi;
                aad[12] = lo;
                let pad = ctx.ctrl_buf(EVP_CTRL_AEAD_TLS1_AAD, aad);
                let total =
                    usize::try_from(i64::try_from(len).unwrap_or(0) + i64::from(pad)).unwrap_or(0);
                ciph_success = ctx.cipher(&mut outb, &inp, total);
            }
            count += 1;
        }
        let d = st.time_stop();
        if st.mr {
            eprintf!("+R:{count}:evp:{}\n", f6(d));
        } else {
            eprintf!("{count} evp ops in {}s\n", cf(d, 0, 2));
        }
        if ciph_success <= 0 && !st.mr {
            eprintf!("Error performing cipher op\n");
        }
        set2(
            &mut st.results,
            D_EVP,
            j,
            f64::from(count) / d * f64::from(mbl),
        );
    }
    let mut t = String::new();
    if st.mr {
        t.push_str("+H");
        for l in &mblengths {
            t.push_str(&format!(":{l}"));
        }
        t.push('\n');
        t.push_str(&format!("+F:{D_EVP}:{alg_name}"));
        for r in st
            .results
            .get(D_EVP)
            .into_iter()
            .flatten()
            .take(mblengths.len())
        {
            t.push_str(&format!(":{}", cf(*r, 0, 2)));
        }
        t.push('\n');
    } else {
        t.push_str("The 'numbers' are in 1000s of bytes per second processed.\n");
        t.push_str("type                    ");
        for l in &mblengths {
            t.push_str(&format!("{l:7} bytes"));
        }
        t.push('\n');
        t.push_str(&format!("{alg_name:<24}"));
        for &r in st
            .results
            .get(D_EVP)
            .into_iter()
            .flatten()
            .take(mblengths.len())
        {
            if r > 10000.0 {
                t.push_str(&format!(" {}k", cf(r / 1e3, 11, 2)));
            } else {
                t.push_str(&format!(" {} ", cf(r, 11, 2)));
            }
        }
        t.push('\n');
    }
    out(&t);
}

/// What the asymmetric benchmarks share.
struct Asym<'a> {
    loopargs: &'a [RefCell<LoopArgs>],
    res: &'a mut Results,
}

/// One timed asymmetric run: the message, the run, the result line; the count.
#[allow(clippy::too_many_arguments)]
fn timed(
    st: &mut State,
    jobs: &mut Option<Jobs>,
    loopargs: &[RefCell<LoopArgs>],
    f: LoopFn,
    start: impl FnOnce(&State),
    result: impl FnOnce(&State, i32, f64) -> String,
) -> (i32, f64) {
    start(st);
    st.time_start();
    let count = run_benchmark(st, jobs.as_mut(), loopargs, f);
    let d = st.time_stop();
    eprintf!("{}", result(st, count, d));
    (count, d)
}

/// The RSA, DSA, ECDSA, ECDH, EdDSA, SM2, and FFDH benchmarks.
// `op_count` carries over from one kind to the next, as upstream's does.
#[allow(clippy::too_many_arguments, unused_assignments)]
fn asymmetric(
    st: &mut State,
    jobs: &mut Option<Jobs>,
    c: Asym<'_>,
    seconds: &Seconds,
    primes: i32,
    rsa_doit: &mut [u8; 7],
    dsa_doit: &mut [u8; 2],
    ecdsa_doit: &mut [u8; ECDSA_NUM],
    ecdh_doit: &mut [u8; EC_NUM],
    eddsa_doit: &mut [u8; 2],
    sm2_doit: &mut [u8; 1],
    ffdh_doit: &mut [u8; 5],
) {
    let loopargs = c.loopargs;
    let res = c.res;
    let mut op_count: i64 = 1;
    let rsa_keys = c_arrays(TESTRSA_H);

    for t in 0..7 {
        if at(rsa_doit.as_slice(), t) == 0 {
            continue;
        }
        st.testnum = t;
        let bits = at(&RSA_BITS, t);
        let rsa_key = if primes > RSA_DEFAULT_PRIME_NUM {
            // Multi-prime keys, generated.
            {
                let mut genctx = None;
                keygen::init_gen_str(&mut genctx, "RSA", None, false, None, None);
                genctx
            }
            .and_then(|genctx| {
                if genctx.set_rsa_keygen_bits(i32::try_from(bits).unwrap_or(i32::MAX)) > 0
                    && genctx
                        .set1_rsa_keygen_pubexp_word(
                            core::ffi::c_ulong::try_from(RSA_F4).unwrap_or(0x10001),
                        )
                        .is_some_and(|r| r > 0)
                    && genctx.set_rsa_keygen_primes(primes) > 0
                {
                    match genctx.keygen_into(None) {
                        (r, Some(k)) if r > 0 => Some(k),
                        _ => None,
                    }
                } else {
                    None
                }
            })
        } else {
            Pkey::private_from_der(EVP_PKEY_RSA, &array(&rsa_keys, &format!("test{bits}")))
        };
        let mut ok = rsa_key.is_some();
        // Sign.
        for l in loopargs {
            if !ok {
                break;
            }
            let mut l = l.borrow_mut();
            let ctx = rsa_key.as_ref().and_then(|k| PkeyCtx::new(k, None));
            l.sigsize = l.buflen;
            let n = l.buflen;
            let good = ctx.as_ref().is_some_and(|ctx| {
                let (buf, buf2) = l.bufs();
                ctx.sign_init() > 0 && {
                    let (r, len) = ctx.sign_into(
                        buf2.get_mut(..n).unwrap_or_default(),
                        buf.get(..36).unwrap_or_default(),
                    );
                    l.sigsize = len;
                    r > 0
                }
            });
            set(&mut l.rsa_sign_ctx, t, ctx);
            ok = good;
        }
        if !ok {
            eprintf!("RSA sign setup failure.  No RSA sign will be done.\n");
            st.dofail();
            op_count = 1;
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                rsa_sign_loop,
                |st| st.pkey_print_message("private", "rsa sign", bits, seconds.rsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R1:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!(
                            "{count} {bits} bits private RSA sign ops in {}s\n",
                            cf(d, 0, 2)
                        )
                    }
                },
            );
            set2(&mut res.rsa, t, 0, f64::from(count) / d);
            op_count = i64::from(count);
        }
        // Verify.
        for l in loopargs {
            if !ok {
                break;
            }
            let mut l = l.borrow_mut();
            let ctx = rsa_key.as_ref().and_then(|k| PkeyCtx::new(k, None));
            let n = l.sigsize;
            let good = ctx.as_ref().is_some_and(|ctx| {
                let (buf, buf2) = l.bufs();
                ctx.verify_init() > 0
                    && ctx.verify(
                        buf2.get(..n).unwrap_or_default(),
                        buf.get(..36).unwrap_or_default(),
                    ) > 0
            });
            set(&mut l.rsa_verify_ctx, t, ctx);
            ok = good;
        }
        if !ok {
            eprintf!("RSA verify setup failure.  No RSA verify will be done.\n");
            st.dofail();
            set(rsa_doit.as_mut_slice(), t, 0);
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                rsa_verify_loop,
                |st| st.pkey_print_message("public", "rsa verify", bits, seconds.rsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R2:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!(
                            "{count} {bits} bits public RSA verify ops in {}s\n",
                            cf(d, 0, 2)
                        )
                    }
                },
            );
            set2(&mut res.rsa, t, 1, f64::from(count) / d);
        }
        // Encrypt.
        for l in loopargs {
            if !ok {
                break;
            }
            let mut l = l.borrow_mut();
            let ctx = rsa_key.as_ref().and_then(|k| PkeyCtx::new(k, None));
            l.encsize = l.buflen;
            let n = l.buflen;
            let good = ctx.as_ref().is_some_and(|ctx| {
                let (buf, buf2) = l.bufs();
                ctx.encrypt_init() > 0 && {
                    let (r, len) = ctx.encrypt_into(
                        buf2.get_mut(..n).unwrap_or_default(),
                        buf.get(..36).unwrap_or_default(),
                    );
                    l.encsize = len;
                    r > 0
                }
            });
            set(&mut l.rsa_encrypt_ctx, t, ctx);
            ok = good;
        }
        if !ok {
            eprintf!("RSA encrypt setup failure.  No RSA encrypt will be done.\n");
            st.dofail();
            op_count = 1;
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                rsa_encrypt_loop,
                |st| st.pkey_print_message("public", "rsa encrypt", bits, seconds.rsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R3:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!(
                            "{count} {bits} bits public RSA encrypt ops in {}s\n",
                            cf(d, 0, 2)
                        )
                    }
                },
            );
            set2(&mut res.rsa, t, 2, f64::from(count) / d);
            op_count = i64::from(count);
        }
        // Decrypt.
        for l in loopargs {
            if !ok {
                break;
            }
            let mut l = l.borrow_mut();
            let ctx = rsa_key.as_ref().and_then(|k| PkeyCtx::new(k, None));
            let (n, e) = (l.buflen, l.encsize);
            let good = ctx.as_ref().is_some_and(|ctx| {
                let (buf, buf2) = l.bufs();
                ctx.decrypt_init() > 0
                    && ctx
                        .decrypt_into(
                            buf.get_mut(..n).unwrap_or_default(),
                            buf2.get(..e).unwrap_or_default(),
                        )
                        .0
                        > 0
            });
            set(&mut l.rsa_decrypt_ctx, t, ctx);
            ok = good;
        }
        if !ok {
            eprintf!("RSA decrypt setup failure.  No RSA decrypt will be done.\n");
            st.dofail();
            op_count = 1;
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                rsa_decrypt_loop,
                |st| st.pkey_print_message("private", "rsa decrypt", bits, seconds.rsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R4:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!(
                            "{count} {bits} bits private RSA decrypt ops in {}s\n",
                            cf(d, 0, 2)
                        )
                    }
                },
            );
            set2(&mut res.rsa, t, 3, f64::from(count) / d);
            op_count = i64::from(count);
        }
        if op_count <= 1 {
            // Longer than the time given: no more.
            stop_it(rsa_doit, t);
        }
    }

    for t in 0..2 {
        if at(dsa_doit.as_slice(), t) == 0 {
            continue;
        }
        st.testnum = t;
        let bits = at(&DSA_BITS, t);
        let dsa_key = get_dsa(bits);
        let mut ok = dsa_key.is_some();
        for l in loopargs {
            if !ok {
                break;
            }
            let mut l = l.borrow_mut();
            let ctx = dsa_key.as_ref().and_then(|k| PkeyCtx::new(k, None));
            l.sigsize = l.buflen;
            let n = l.buflen;
            let good = ctx.as_ref().is_some_and(|ctx| {
                let (buf, buf2) = l.bufs();
                ctx.sign_init() > 0 && {
                    let (r, len) = ctx.sign_into(
                        buf2.get_mut(..n).unwrap_or_default(),
                        buf.get(..20).unwrap_or_default(),
                    );
                    l.sigsize = len;
                    r > 0
                }
            });
            set(&mut l.dsa_sign_ctx, t, ctx);
            ok = good;
        }
        if !ok {
            eprintf!("DSA sign setup failure.  No DSA sign will be done.\n");
            st.dofail();
            op_count = 1;
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                dsa_sign_loop,
                |st| st.pkey_print_message("sign", "dsa", bits, seconds.dsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R5:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!("{count} {bits} bits DSA sign ops in {}s\n", cf(d, 0, 2))
                    }
                },
            );
            set2(&mut res.dsa, t, 0, f64::from(count) / d);
            op_count = i64::from(count);
        }
        for l in loopargs {
            if !ok {
                break;
            }
            let mut l = l.borrow_mut();
            let ctx = dsa_key.as_ref().and_then(|k| PkeyCtx::new(k, None));
            let n = l.sigsize;
            // Upstream verifies 36 bytes here (and signed 20).
            let good = ctx.as_ref().is_some_and(|ctx| {
                let (buf, buf2) = l.bufs();
                ctx.verify_init() > 0
                    && ctx.verify(
                        buf2.get(..n).unwrap_or_default(),
                        buf.get(..36).unwrap_or_default(),
                    ) > 0
            });
            set(&mut l.dsa_verify_ctx, t, ctx);
            ok = good;
        }
        if !ok {
            eprintf!("DSA verify setup failure.  No DSA verify will be done.\n");
            st.dofail();
            set(dsa_doit.as_mut_slice(), t, 0);
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                dsa_verify_loop,
                |st| st.pkey_print_message("verify", "dsa", bits, seconds.dsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R6:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!("{count} {bits} bits DSA verify ops in {}s\n", cf(d, 0, 2))
                    }
                },
            );
            set2(&mut res.dsa, t, 1, f64::from(count) / d);
        }
        if op_count <= 1 {
            stop_it(dsa_doit, t);
        }
    }

    for t in 0..ECDSA_NUM {
        if at(ecdsa_doit.as_slice(), t) == 0 {
            continue;
        }
        st.testnum = t;
        let Some(curve) = EC_CURVES.get(t) else {
            continue;
        };
        let bits = curve.bits;
        let key = get_ecdsa(st, curve);
        let mut ok = key.is_some();
        for l in loopargs {
            if !ok {
                break;
            }
            let mut l = l.borrow_mut();
            let ctx = key.as_ref().and_then(|k| PkeyCtx::new(k, None));
            l.sigsize = l.buflen;
            let n = l.buflen;
            let good = ctx.as_ref().is_some_and(|ctx| {
                let (buf, buf2) = l.bufs();
                ctx.sign_init() > 0 && {
                    let (r, len) = ctx.sign_into(
                        buf2.get_mut(..n).unwrap_or_default(),
                        buf.get(..20).unwrap_or_default(),
                    );
                    l.sigsize = len;
                    r > 0
                }
            });
            set(&mut l.ecdsa_sign_ctx, t, ctx);
            ok = good;
        }
        if !ok {
            eprintf!("ECDSA sign setup failure.  No ECDSA sign will be done.\n");
            st.dofail();
            op_count = 1;
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                ecdsa_sign_loop,
                |st| st.pkey_print_message("sign", "ecdsa", bits, seconds.ecdsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R7:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!("{count} {bits} bits ECDSA sign ops in {}s\n", cf(d, 0, 2))
                    }
                },
            );
            set2(&mut res.ecdsa, t, 0, f64::from(count) / d);
            op_count = i64::from(count);
        }
        for l in loopargs {
            if !ok {
                break;
            }
            let mut l = l.borrow_mut();
            let ctx = key.as_ref().and_then(|k| PkeyCtx::new(k, None));
            let n = l.sigsize;
            let good = ctx.as_ref().is_some_and(|ctx| {
                let (buf, buf2) = l.bufs();
                ctx.verify_init() > 0
                    && ctx.verify(
                        buf2.get(..n).unwrap_or_default(),
                        buf.get(..20).unwrap_or_default(),
                    ) > 0
            });
            set(&mut l.ecdsa_verify_ctx, t, ctx);
            ok = good;
        }
        if !ok {
            eprintf!("ECDSA verify setup failure.  No ECDSA verify will be done.\n");
            st.dofail();
            set(ecdsa_doit.as_mut_slice(), t, 0);
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                ecdsa_verify_loop,
                |st| st.pkey_print_message("verify", "ecdsa", bits, seconds.ecdsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R8:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!("{count} {bits} bits ECDSA verify ops in {}s\n", cf(d, 0, 2))
                    }
                },
            );
            set2(&mut res.ecdsa, t, 1, f64::from(count) / d);
        }
        if op_count <= 1 {
            stop_it(ecdsa_doit, t);
        }
    }

    for t in 0..EC_NUM {
        if at(ecdh_doit.as_slice(), t) == 0 {
            continue;
        }
        st.testnum = t;
        let Some(curve) = EC_CURVES.get(t) else {
            continue;
        };
        let mut checks = true;
        for l in loopargs {
            let key_a = get_ecdsa(st, curve);
            let key_b = key_a.as_ref().and_then(|_| get_ecdsa(st, curve));
            let (Some(key_a), Some(key_b)) = (key_a, key_b) else {
                eprintf!("ECDH key generation failure.\n");
                st.dofail();
                op_count = 1;
                checks = false;
                break;
            };
            let ctx = PkeyCtx::new(&key_a, None)
                .filter(|c| c.derive_init() > 0 && c.derive_set_peer(&key_b) > 0);
            let outlen = ctx.as_ref().map(PkeyCtx::derive_length);
            let (Some(ctx), Some((r, outlen))) = (ctx, outlen) else {
                eprintf!("ECDH key generation failure.\n");
                st.dofail();
                op_count = 1;
                checks = false;
                break;
            };
            if r <= 0 || outlen == 0 || outlen > MAX_ECDH_SIZE {
                eprintf!("ECDH key generation failure.\n");
                st.dofail();
                op_count = 1;
                checks = false;
                break;
            }
            // a*B and b*A, compared: the benchmarked derivations need no checks then.
            let mut l = l.borrow_mut();
            let test_ctx = PkeyCtx::new(&key_b, None)
                .filter(|c| c.derive_init() > 0 && c.derive_set_peer(&key_a) > 0);
            let computed = test_ctx.as_ref().and_then(|tc| {
                let (r, test_outlen) = tc.derive_length();
                if r <= 0 {
                    return None;
                }
                let (r1, outlen) = ctx.derive_into(&mut l.secret_a, outlen);
                if r1 <= 0 {
                    return None;
                }
                let (r2, test_outlen) = tc.derive_into(&mut l.secret_b, test_outlen);
                (r2 > 0 && test_outlen == outlen).then_some(outlen)
            });
            let Some(outlen) = computed else {
                eprintf!("ECDH computation failure.\n");
                st.dofail();
                op_count = 1;
                checks = false;
                break;
            };
            if l.secret_a.get(..outlen) != l.secret_b.get(..outlen) {
                eprintf!("ECDH computations don't match.\n");
                st.dofail();
                op_count = 1;
                checks = false;
                break;
            }
            set(&mut l.ecdh_ctx, t, Some(ctx));
            set(&mut l.outlen, t, outlen);
        }
        if checks {
            let bits = curve.bits;
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                ecdh_derive_loop,
                |st| st.pkey_print_message("", "ecdh", bits, seconds.ecdh),
                |st, count, d| {
                    if st.mr {
                        format!("+R9:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!("{count} {bits}-bits ECDH ops in {}s\n", cf(d, 0, 2))
                    }
                },
            );
            set(&mut res.ecdh, t, f64::from(count) / d);
            op_count = i64::from(count);
        }
        if op_count <= 1 {
            stop_it(ecdh_doit, t);
        }
    }

    for t in 0..2 {
        if at(eddsa_doit.as_slice(), t) == 0 {
            continue;
        }
        st.testnum = t;
        let Some(curve) = ED_CURVES.get(t) else {
            continue;
        };
        let mut ok = true;
        for l in loopargs {
            let mut l = l.borrow_mut();
            let (Some(c1), Some(c2)) = (MdCtx::new(), MdCtx::new()) else {
                ok = false;
                break;
            };
            let key = PkeyCtx::new_id(curve.nid, None).and_then(|pctx| {
                if pctx.keygen_init() <= 0 {
                    return None;
                }
                match pctx.keygen_into(None) {
                    (r, Some(k)) if r > 0 => Some(k),
                    _ => None,
                }
            });
            let Some(key) = key else {
                set(&mut l.eddsa_ctx, t, Some(c1));
                set(&mut l.eddsa_ctx2, t, Some(c2));
                ok = false;
                break;
            };
            let good = c1.sign_init(false, &key) != 0 && c2.verify_init(false, &key) != 0;
            set(&mut l.eddsa_ctx, t, Some(c1));
            set(&mut l.eddsa_ctx2, t, Some(c2));
            if !good {
                ok = false;
                break;
            }
        }
        if !ok {
            eprintf!("EdDSA failure.\n");
            st.dofail();
            op_count = 1;
            continue;
        }
        let mut signed = true;
        for l in loopargs {
            let mut l = l.borrow_mut();
            l.sigsize = curve.sigsize;
            let n = l.sigsize;
            let Some(ctx) = l.eddsa_ctx.get_mut(t).and_then(Option::take) else {
                signed = false;
                break;
            };
            let (buf, buf2) = l.bufs();
            let (r, len) = ctx.sign(buf2, n, buf.get(..20).unwrap_or_default());
            l.sigsize = len;
            set(&mut l.eddsa_ctx, t, Some(ctx));
            if r == 0 {
                signed = false;
                break;
            }
        }
        let name = curve.name;
        let bits = curve.bits;
        if !signed {
            eprintf!("EdDSA sign failure.  No EdDSA sign will be done.\n");
            st.dofail();
            op_count = 1;
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                eddsa_sign_loop,
                |st| st.pkey_print_message("sign", name, bits, seconds.eddsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R10:{count}:{bits}:{name}:{}\n", cf(d, 0, 2))
                    } else {
                        format!("{count} {bits} bits {name} sign ops in {}s \n", cf(d, 0, 2))
                    }
                },
            );
            set2(&mut res.eddsa, t, 0, f64::from(count) / d);
            op_count = i64::from(count);
        }
        let mut verified = true;
        for l in loopargs {
            let mut l = l.borrow_mut();
            let n = l.sigsize;
            let Some(ctx) = l.eddsa_ctx2.get_mut(t).and_then(Option::take) else {
                verified = false;
                break;
            };
            let (buf, buf2) = l.bufs();
            let r = ctx.verify(
                buf2.get(..n).unwrap_or_default(),
                buf.get(..20).unwrap_or_default(),
            );
            set(&mut l.eddsa_ctx2, t, Some(ctx));
            if r != 1 {
                verified = false;
                break;
            }
        }
        if !verified {
            eprintf!("EdDSA verify failure.  No EdDSA verify will be done.\n");
            st.dofail();
            set(eddsa_doit.as_mut_slice(), t, 0);
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                eddsa_verify_loop,
                |st| st.pkey_print_message("verify", name, bits, seconds.eddsa),
                |st, count, d| {
                    if st.mr {
                        format!("+R11:{count}:{bits}:{name}:{}\n", cf(d, 0, 2))
                    } else {
                        format!(
                            "{count} {bits} bits {name} verify ops in {}s\n",
                            cf(d, 0, 2)
                        )
                    }
                },
            );
            set2(&mut res.eddsa, t, 1, f64::from(count) / d);
        }
        if op_count <= 1 {
            stop_it(eddsa_doit, t);
        }
    }

    for t in 0..1 {
        if at(sm2_doit.as_slice(), t) == 0 {
            continue;
        }
        st.testnum = t;
        let Some(curve) = SM2_CURVES.get(t) else {
            continue;
        };
        let mut ok = false;
        for l in loopargs {
            ok = false;
            let mut l = l.borrow_mut();
            let (Some(ctx), Some(vfy_ctx)) = (MdCtx::new(), MdCtx::new()) else {
                break;
            };
            let key = PkeyCtx::new_id(EVP_PKEY_SM2, None).and_then(|pctx| {
                if pctx.keygen_init() <= 0 || pctx.set_ec_paramgen_curve_nid(curve.nid) <= 0 {
                    return None;
                }
                match pctx.keygen_into(None) {
                    (r, Some(k)) if r > 0 => Some(k),
                    _ => None,
                }
            });
            let Some(pkey) = key else { break };
            l.sigsize = usize::try_from(pkey.size()).unwrap_or(0);
            let (Some(pctx), Some(vfy_pctx)) =
                (PkeyCtx::new(&pkey, None), PkeyCtx::new(&pkey, None))
            else {
                break;
            };
            // The digest contexts use these key contexts directly.
            ctx.set_pkey_ctx(&pctx);
            vfy_ctx.set_pkey_ctx(&vfy_pctx);
            let sm2 = Sm2 {
                ctx,
                vfy_ctx,
                pctx,
                vfy_pctx,
                pkey,
            };
            // The ID of draft-yang-tls-tl13-sm-suites; not one the user chooses.
            let good = sm2.pctx.set1_id(SM2_ID) == 1
                && sm2.vfy_pctx.set1_id(SM2_ID) == 1
                && sm2.ctx.sign_init(true, &sm2.pkey) != 0
                && sm2.vfy_ctx.verify_init(true, &sm2.pkey) != 0;
            set(&mut l.sm2, t, Some(sm2));
            if !good {
                break;
            }
            ok = true;
        }
        if !ok {
            eprintf!("SM2 init failure.\n");
            st.dofail();
            op_count = 1;
            continue;
        }
        let mut signed = true;
        for l in loopargs {
            let mut l = l.borrow_mut();
            let n = l.sigsize;
            let Some(sm2) = l.sm2.get_mut(t).and_then(Option::take) else {
                signed = false;
                break;
            };
            let (buf, buf2) = l.bufs();
            let (r, len) = sm2.ctx.sign(buf2, n, buf.get(..20).unwrap_or_default());
            l.sigsize = len;
            set(&mut l.sm2, t, Some(sm2));
            if r == 0 {
                signed = false;
                break;
            }
        }
        let (name, bits) = (curve.name, curve.bits);
        if !signed {
            eprintf!("SM2 sign failure.  No SM2 sign will be done.\n");
            st.dofail();
            op_count = 1;
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                sm2_sign_loop,
                |st| st.pkey_print_message("sign", name, bits, seconds.sm2),
                |st, count, d| {
                    if st.mr {
                        format!("+R12:{count}:{bits}:{name}:{}\n", cf(d, 0, 2))
                    } else {
                        format!("{count} {bits} bits {name} sign ops in {}s \n", cf(d, 0, 2))
                    }
                },
            );
            set2(&mut res.sm2, t, 0, f64::from(count) / d);
            op_count = i64::from(count);
        }
        let mut verified = true;
        for l in loopargs {
            let mut l = l.borrow_mut();
            let n = l.sigsize;
            let Some(sm2) = l.sm2.get_mut(t).and_then(Option::take) else {
                verified = false;
                break;
            };
            let (buf, buf2) = l.bufs();
            let r = sm2.vfy_ctx.verify(
                buf2.get(..n).unwrap_or_default(),
                buf.get(..20).unwrap_or_default(),
            );
            set(&mut l.sm2, t, Some(sm2));
            if r != 1 {
                verified = false;
                break;
            }
        }
        if !verified {
            eprintf!("SM2 verify failure.  No SM2 verify will be done.\n");
            st.dofail();
            set(sm2_doit.as_mut_slice(), t, 0);
        } else {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                sm2_verify_loop,
                |st| st.pkey_print_message("verify", name, bits, seconds.sm2),
                |st, count, d| {
                    if st.mr {
                        format!("+R13:{count}:{bits}:{name}:{}\n", cf(d, 0, 2))
                    } else {
                        format!(
                            "{count} {bits} bits {name} verify ops in {}s\n",
                            cf(d, 0, 2)
                        )
                    }
                },
            );
            set2(&mut res.sm2, t, 1, f64::from(count) / d);
        }
        if op_count <= 1 {
            stop_it(sm2_doit, t + 1);
        }
    }

    for t in 0..5 {
        if at(ffdh_doit.as_slice(), t) == 0 {
            continue;
        }
        st.testnum = t;
        let Some(&(_, nid, bits)) = FFDH_PARAMS.get(t) else {
            continue;
        };
        let mut checks = true;
        for l in loopargs {
            if err::peek_error() != 0 {
                eprintf!("WARNING: the error queue contains previous unhandled errors.\n");
                st.dofail();
            }
            let mut l = l.borrow_mut();
            match ffdh_setup(st, nid, &mut l) {
                Ok(ctx) => set(&mut l.ffdh_ctx, t, Some(ctx)),
                Err(()) => {
                    op_count = 1;
                    checks = false;
                    break;
                }
            }
        }
        if checks {
            let (count, d) = timed(
                st,
                jobs,
                loopargs,
                ffdh_derive_loop,
                |st| st.pkey_print_message("", "ffdh", bits, seconds.ffdh),
                |st, count, d| {
                    if st.mr {
                        format!("+R14:{count}:{bits}:{}\n", cf(d, 0, 2))
                    } else {
                        format!("{count} {bits}-bits FFDH ops in {}s\n", cf(d, 0, 2))
                    }
                },
            );
            set(&mut res.ffdh, t, f64::from(count) / d);
            op_count = i64::from(count);
        }
        if op_count <= 1 {
            stop_it(ffdh_doit, t);
        }
    }
}

/// The FFDH set-up of one looparg: two keys, the derivation both ways, compared.
fn ffdh_setup(st: &mut State, nid: i32, l: &mut LoopArgs) -> Result<PkeyCtx, ()> {
    let fail = |st: &mut State, message: &str, dofail: bool| {
        eprintf!("{message}");
        if dofail {
            st.dofail();
        }
        Err(())
    };
    let (Some(pkey_a), Some(pkey_b)) = (Pkey::new(), Pkey::new()) else {
        return fail(
            st,
            "Error while initialising EVP_PKEY (out of memory?).\n",
            true,
        );
    };
    let Some(genctx) = PkeyCtx::new_id(EVP_PKEY_DH, None) else {
        return fail(st, "Error while allocating EVP_PKEY_CTX.\n", true);
    };
    if genctx.keygen_init() <= 0 {
        return fail(st, "Error while initialising EVP_PKEY_CTX.\n", true);
    }
    if genctx.set_dh_nid(nid) <= 0 {
        return fail(st, "Error setting DH key size for keygen.\n", true);
    }
    let (ra, pkey_a) = genctx.keygen_into(Some(pkey_a));
    let generated = if ra > 0 {
        let (rb, pkey_b) = genctx.keygen_into(Some(pkey_b));
        (rb > 0).then_some(()).and(pkey_a.zip(pkey_b))
    } else {
        None
    };
    let Some((pkey_a, pkey_b)) = generated else {
        return fail(st, "FFDH key generation failure.\n", true);
    };
    drop(genctx);
    let Some(ctx) = PkeyCtx::new(&pkey_a, None) else {
        return fail(st, "Error while allocating EVP_PKEY_CTX.\n", true);
    };
    if ctx.derive_init() <= 0 {
        return fail(st, "FFDH derivation context init failure.\n", true);
    }
    if ctx.derive_set_peer(&pkey_b) <= 0 {
        return fail(st, "Assigning peer key for derivation failed.\n", true);
    }
    let (r, secret_size) = ctx.derive_length();
    if r <= 0 {
        return fail(st, "Checking size of shared secret failed.\n", true);
    }
    if secret_size > MAX_FFDH_SIZE {
        return fail(st, "Assertion failure: shared secret too large.\n", false);
    }
    let (r, secret_size) = ctx.derive_into(&mut l.secret_ff_a, secret_size);
    if r <= 0 {
        return fail(st, "Shared secret derive failure.\n", true);
    }
    // Now from side B.
    let Some(test_ctx) = PkeyCtx::new(&pkey_b, None) else {
        return fail(st, "Error while allocating EVP_PKEY_CTX.\n", true);
    };
    let ok = test_ctx.derive_init() > 0 && test_ctx.derive_set_peer(&pkey_a) > 0 && {
        let (r, test_out) = test_ctx.derive_length();
        r > 0 && {
            let (r, test_out) = test_ctx.derive_into(&mut l.secret_ff_b, test_out);
            r > 0 && test_out == secret_size
        }
    };
    if !ok {
        return fail(st, "FFDH computation failure.\n", false);
    }
    if l.secret_ff_a.get(..secret_size) != l.secret_ff_b.get(..secret_size) {
        return fail(st, "FFDH computations don't match.\n", true);
    }
    Ok(ctx)
}

/// The KEM and signature benchmarks.
#[allow(clippy::too_many_arguments)]
fn kems_and_sigs(
    st: &mut State,
    jobs: &mut Option<Jobs>,
    loopargs: &[RefCell<LoopArgs>],
    res: &mut Results,
    seconds: &Seconds,
    kems_algname: &[String],
    kems_doit: &mut [u8; MAX_KEM_NUM],
    do_kems: bool,
    sigs_algname: &[String],
    sigs_doit: &mut [u8; MAX_SIG_NUM],
    do_sigs: bool,
) {
    let lc = app_libctx::libctx();
    let pq = app_libctx::propq();
    let mut op_count: i64 = 1;
    for (t, kem_name) in kems_algname.iter().enumerate() {
        if at(kems_doit.as_slice(), t) == 0 || !do_kems {
            continue;
        }
        st.testnum = t;
        let mut checks = true;
        for l in loopargs {
            if let Err(message) = kem_setup(
                st,
                lc.as_deref(),
                pq.as_deref(),
                kem_name,
                t,
                &mut l.borrow_mut(),
            ) {
                eprintf!("{message}");
                st.dofail();
                op_count = 1;
                checks = false;
                break;
            }
        }
        if checks {
            let name = kem_name.as_str();
            for (i, (what, f, tag)) in [
                ("keygen", kem_keygen_loop as LoopFn, 15),
                ("encaps", kem_encaps_loop, 16),
                ("decaps", kem_decaps_loop, 17),
            ]
            .into_iter()
            .enumerate()
            {
                let (count, d) = timed(
                    st,
                    jobs,
                    loopargs,
                    f,
                    |st| st.kskey_print_message(name, what, seconds.kem),
                    |st, count, d| {
                        if st.mr {
                            format!("+R{tag}:{count}:{name}:{}\n", cf(d, 0, 2))
                        } else {
                            format!("{count} {name} KEM {what} ops in {}s\n", cf(d, 0, 2))
                        }
                    },
                );
                set2(&mut res.kems, t, i, f64::from(count) / d);
                op_count = i64::from(count);
            }
        }
        if op_count <= 1 {
            stop_it(kems_doit, t);
        }
    }

    for (t, sig_name) in sigs_algname.iter().enumerate() {
        if at(sigs_doit.as_slice(), t) == 0 || !do_sigs {
            continue;
        }
        st.testnum = t;
        let mut checks = true;
        for l in loopargs {
            if err::peek_error() != 0 {
                eprintf!("WARNING: the error queue contains previous unhandled errors.\n");
                st.dofail();
            }
            if let Err(message) = sig_setup(
                lc.as_deref(),
                pq.as_deref(),
                sig_name,
                t,
                &mut l.borrow_mut(),
            ) {
                eprintf!("{message}");
                st.dofail();
                op_count = 1;
                checks = false;
                break;
            }
        }
        if checks {
            let name = sig_name.as_str();
            for (i, (what, f, tag, label)) in [
                ("keygen", sig_keygen_loop as LoopFn, 18, "keygen"),
                ("signs", sig_sign_loop, 19, "sign"),
                ("verify", sig_verify_loop, 20, "verify"),
            ]
            .into_iter()
            .enumerate()
            {
                let (count, d) = timed(
                    st,
                    jobs,
                    loopargs,
                    f,
                    |st| st.kskey_print_message(name, what, seconds.sig),
                    |st, count, d| {
                        if st.mr {
                            format!("+R{tag}:{count}:{name}:{}\n", cf(d, 0, 2))
                        } else {
                            format!("{count} {name} signature {label} ops in {}s\n", cf(d, 0, 2))
                        }
                    },
                );
                set2(&mut res.sigs, t, i, f64::from(count) / d);
                op_count = i64::from(count);
            }
        }
        if op_count <= 1 {
            stop_it(sigs_doit, t);
        }
    }
}

/// One looparg's KEM contexts and buffers; the failure's message.
fn kem_setup(
    st: &mut State,
    lc: Option<&rustyssl_ossl::provider::LibCtx>,
    pq: Option<&str>,
    kem_name: &str,
    t: usize,
    l: &mut LoopArgs,
) -> Result<(), String> {
    #[derive(PartialEq)]
    enum Kind {
        Rsa(u32),
        Ec,
        X25519,
        X448,
        Other,
    }
    let kind = if let Some(bits) = rsa_bits(kem_name) {
        Kind::Rsa(bits)
    } else if kem_name.starts_with("EC") {
        Kind::Ec
    } else if kem_name == "X25519" {
        Kind::X25519
    } else if kem_name == "X448" {
        Kind::X448
    } else {
        Kind::Other
    };
    if err::peek_error() != 0 {
        eprintf!("WARNING: the error queue contains previous unhandled errors.\n");
        st.dofail();
    }
    let params = match &kind {
        Kind::Rsa(bits) => Some(ParamValues::new().uint(s(OSSL_PKEY_PARAM_RSA_BITS), *bits)),
        Kind::Ec => Some(ParamValues::new().utf8(
            s(OSSL_PKEY_PARAM_GROUP_NAME),
            kem_name.get(2..).unwrap_or_default(),
        )),
        _ => None,
    };
    let alg = match &kind {
        Kind::Rsa(_) => "RSA",
        Kind::Ec => "EC",
        _ => kem_name,
    };
    let genctx = PkeyCtx::from_name(lc, alg, pq);
    let genctx = match genctx {
        Some(g) if g.keygen_init() > 0 && params.as_ref().is_none_or(|p| g.set_params(p) > 0) => g,
        _ => return Err(format!("Error initializing keygen ctx for {kem_name}.\n")),
    };
    let pkey = match genctx.keygen_into(None) {
        (r, Some(k)) if r > 0 => k,
        _ => return Err("Error while generating KEM EVP_PKEY.\n".to_owned()),
    };
    let op = match kind {
        Kind::Rsa(_) => Some("RSASVE"),
        Kind::Ec | Kind::X25519 | Kind::X448 => Some("DHKEM"),
        Kind::Other => None,
    };
    let encaps = PkeyCtx::from_pkey(lc, Some(&pkey), pq)
        .filter(|c| c.encapsulate_init() > 0 && op.is_none_or(|op| c.set_kem_op(op) > 0));
    let lengths = encaps.as_ref().map(PkeyCtx::encapsulate_lengths);
    let (Some(encaps), Some((r, out_len, secret_len))) = (encaps, lengths) else {
        return Err(format!(
            "Error while initializing encaps data structs for {kem_name}.\n"
        ));
    };
    if r <= 0 {
        return Err(format!(
            "Error while initializing encaps data structs for {kem_name}.\n"
        ));
    }
    let mut out = vec![0u8; out_len];
    let mut send_secret = vec![0u8; secret_len];
    let (r, out_len, secret_len) = encaps.encapsulate_into(&mut out, &mut send_secret);
    if r <= 0 {
        return Err(format!("Encaps error for {kem_name}.\n"));
    }
    let decaps = PkeyCtx::from_pkey(lc, Some(&pkey), pq)
        .filter(|c| c.decapsulate_init() > 0 && op.is_none_or(|op| c.set_kem_op(op) > 0));
    let rcv = decaps
        .as_ref()
        .map(|c| c.decapsulate_length(out.get(..out_len).unwrap_or_default()));
    let (Some(decaps), Some((r, rcv_len))) = (decaps, rcv) else {
        return Err(format!(
            "Error while initializing decaps data structs for {kem_name}.\n"
        ));
    };
    if r <= 0 {
        return Err(format!(
            "Error while initializing decaps data structs for {kem_name}.\n"
        ));
    }
    let mut rcv_secret = vec![0u8; rcv_len];
    let (r, rcv_len) =
        decaps.decapsulate_into(&mut rcv_secret, out.get(..out_len).unwrap_or_default());
    if r <= 0 || rcv_len != secret_len || send_secret.get(..secret_len) != rcv_secret.get(..rcv_len)
    {
        return Err(format!("Decaps error for {kem_name}.\n"));
    }
    set(&mut l.kem_gen_ctx, t, Some(genctx));
    set(&mut l.kem_encaps_ctx, t, Some(encaps));
    set(&mut l.kem_decaps_ctx, t, Some(decaps));
    set(&mut l.kem_out_len, t, out_len);
    set(&mut l.kem_secret_len, t, secret_len);
    set(&mut l.kem_out, t, out);
    set(&mut l.kem_send_secret, t, send_secret);
    set(&mut l.kem_rcv_secret, t, rcv_secret);
    Ok(())
}

/// One looparg's signature contexts and signature; the failure's message.
fn sig_setup(
    lc: Option<&rustyssl_ossl::provider::LibCtx>,
    pq: Option<&str>,
    sig_name: &str,
    t: usize,
    l: &mut LoopArgs,
) -> Result<(), String> {
    // Little data, so as not to measure the digest.
    let md = [0u8; SHA256_DIGEST_LENGTH];
    let rsa = rsa_bits(sig_name);
    let params = rsa.map(|bits| ParamValues::new().uint(s(OSSL_PKEY_PARAM_RSA_BITS), bits));
    let mut genctx = None;
    if sig_name.starts_with("dsa") {
        let classic = PkeyCtx::new_id(EVP_PKEY_DSA, None).and_then(|pctx| {
            if pctx.paramgen_init() <= 0
                || pctx.set_dsa_paramgen_bits(atoi(sig_name.get(3..).unwrap_or_default())) <= 0
            {
                return None;
            }
            let (r, params) = pctx.paramgen();
            let params = params.filter(|_| r > 0)?;
            PkeyCtx::new(&params, None).filter(|g| g.keygen_init() > 0)
        });
        let Some(classic) = classic else {
            return Err(format!(
                "Error initializing classic keygen ctx for {sig_name}.\n"
            ));
        };
        genctx = Some(classic);
    }
    let genctx = match genctx {
        Some(g) => Some(g),
        None => PkeyCtx::from_name(lc, if params.is_some() { "RSA" } else { sig_name }, pq),
    };
    let genctx = match genctx {
        Some(g) if g.keygen_init() > 0 && params.as_ref().is_none_or(|p| g.set_params(p) > 0) => g,
        _ => return Err(format!("Error initializing keygen ctx for {sig_name}.\n")),
    };
    let pkey = match genctx.keygen_into(None) {
        (r, Some(k)) if r > 0 => k,
        _ => {
            return Err(format!(
                "Error while generating signature EVP_PKEY for {sig_name}.\n"
            ));
        }
    };
    // The algorithm fetched explicitly, for one without EVP_PKEY_sign_init.
    err::set_mark();
    let alg = Signature::fetch(lc, sig_name, pq);
    err::pop_to_mark();

    let Some(sign) = PkeyCtx::from_pkey(lc, Some(&pkey), pq) else {
        return Err(format!(
            "Error while initializing signing ctx for {sig_name}.\n"
        ));
    };
    err::set_mark();
    if sign.sign_init() <= 0 && alg.as_ref().is_none_or(|a| sign.sign_message_init(a) <= 0) {
        err::clear_last_mark();
        return Err(format!(
            "Error while initializing signing data structs for {sig_name}.\n"
        ));
    }
    err::pop_to_mark();
    if rsa.is_some() && sign.set_rsa_padding(RSA_PKCS1_PADDING) <= 0 {
        return Err(format!(
            "Error while initializing padding for {sig_name}.\n"
        ));
    }
    let (r, max_sig_len) = sign.sign_length(&md);
    if r <= 0 {
        return Err(format!(
            "Error while obtaining signature buffer length for {sig_name}.\n"
        ));
    }
    let mut sig = vec![0u8; max_sig_len];
    let (r, sig_len) = sign.sign_into(&mut sig, &md);
    if r <= 0 {
        return Err(format!("Signing error for {sig_name}.\n"));
    }
    let Some(verify) = PkeyCtx::from_pkey(lc, Some(&pkey), pq) else {
        return Err(format!(
            "Error while initializing verify ctx for {sig_name}.\n"
        ));
    };
    err::set_mark();
    if verify.verify_init() <= 0
        && alg
            .as_ref()
            .is_none_or(|a| verify.verify_message_init(a) <= 0)
    {
        err::clear_last_mark();
        return Err(format!(
            "Error while initializing verify data structs for {sig_name}.\n"
        ));
    }
    err::pop_to_mark();
    let signature = sig.get(..sig_len).unwrap_or_default();
    if verify.verify(signature, &md) <= 0 {
        return Err(format!("Verify error for {sig_name}.\n"));
    }
    if verify.verify(signature, &md) <= 0 {
        return Err(format!("Verify 2 error for {sig_name}.\n"));
    }
    set(&mut l.sig_gen_ctx, t, Some(genctx));
    set(&mut l.sig_sign_ctx, t, Some(sign));
    set(&mut l.sig_verify_ctx, t, Some(verify));
    set(&mut l.sig_max_sig_len, t, max_sig_len);
    set(&mut l.sig_act_sig_len, t, sig_len);
    set(&mut l.sig_sig, t, sig);
    Ok(())
}

/// The summary of the asymmetric benchmarks.
#[allow(clippy::too_many_arguments)]
fn print_asymmetric(
    st: &State,
    res: &Results,
    rsa_doit: &[u8; 7],
    dsa_doit: &[u8; 2],
    ecdsa_doit: &[u8; ECDSA_NUM],
    ecdh_doit: &[u8; EC_NUM],
    eddsa_doit: &[u8; 2],
    sm2_doit: &[u8; 1],
    ffdh_doit: &[u8; 5],
) {
    let mr = st.mr;
    let mut t = String::new();
    let mut first = true;
    for k in 0..7 {
        if at(rsa_doit.as_slice(), k) == 0 {
            continue;
        }
        if first && !mr {
            t.push_str(&format!(
                "{:19}sign    verify    encrypt   decrypt   sign/s verify/s  encr./s  decr./s\n",
                " "
            ));
            first = false;
        }
        let r = res.rsa.get(k).copied().unwrap_or_default();
        if mr {
            t.push_str(&format!(
                "+F2:{k}:{}:{}:{}:{}:{}\n",
                at(&RSA_BITS, k),
                f6(r[0]),
                f6(r[1]),
                f6(r[2]),
                f6(r[3])
            ));
        } else {
            t.push_str(&format!(
                "rsa {:5} bits {}s {}s {}s {}s {} {} {} {}\n",
                at(&RSA_BITS, k),
                cf(1.0 / r[0], 8, 6),
                cf(1.0 / r[1], 8, 6),
                cf(1.0 / r[2], 8, 6),
                cf(1.0 / r[3], 8, 6),
                cf(r[0], 8, 1),
                cf(r[1], 8, 1),
                cf(r[2], 8, 1),
                cf(r[3], 8, 1)
            ));
        }
    }
    let mut first = true;
    for k in 0..2 {
        if at(dsa_doit.as_slice(), k) == 0 {
            continue;
        }
        if first && !mr {
            t.push_str(&format!("{:18}sign    verify    sign/s verify/s\n", " "));
            first = false;
        }
        let r = res.dsa.get(k).copied().unwrap_or_default();
        if mr {
            t.push_str(&format!(
                "+F3:{k}:{}:{}:{}\n",
                at(&DSA_BITS, k),
                f6(r[0]),
                f6(r[1])
            ));
        } else {
            t.push_str(&format!(
                "dsa {:4} bits {}s {}s {} {}\n",
                at(&DSA_BITS, k),
                cf(1.0 / r[0], 8, 6),
                cf(1.0 / r[1], 8, 6),
                cf(r[0], 8, 1),
                cf(r[1], 8, 1)
            ));
        }
    }
    let mut first = true;
    for k in 0..ECDSA_NUM {
        if at(ecdsa_doit.as_slice(), k) == 0 {
            continue;
        }
        if first && !mr {
            t.push_str(&format!("{:30}sign    verify    sign/s verify/s\n", " "));
            first = false;
        }
        let r = res.ecdsa.get(k).copied().unwrap_or_default();
        let Some(c) = EC_CURVES.get(k) else {
            continue;
        };
        if mr {
            t.push_str(&format!("+F4:{k}:{}:{}:{}\n", c.bits, f6(r[0]), f6(r[1])));
        } else {
            t.push_str(&format!(
                "{:4} bits ecdsa ({}) {}s {}s {} {}\n",
                c.bits,
                c.name,
                cf(1.0 / r[0], 8, 4),
                cf(1.0 / r[1], 8, 4),
                cf(r[0], 8, 1),
                cf(r[1], 8, 1)
            ));
        }
    }
    let mut first = true;
    for k in 0..EC_NUM {
        if at(ecdh_doit.as_slice(), k) == 0 {
            continue;
        }
        if first && !mr {
            t.push_str(&format!("{:30}op      op/s\n", " "));
            first = false;
        }
        let r = at(&res.ecdh, k);
        let Some(c) = EC_CURVES.get(k) else {
            continue;
        };
        if mr {
            t.push_str(&format!("+F5:{k}:{}:{}:{}\n", c.bits, f6(r), f6(1.0 / r)));
        } else {
            t.push_str(&format!(
                "{:4} bits ecdh ({}) {}s {}\n",
                c.bits,
                c.name,
                cf(1.0 / r, 8, 4),
                cf(r, 8, 1)
            ));
        }
    }
    let mut first = true;
    for k in 0..2 {
        if at(eddsa_doit.as_slice(), k) == 0 {
            continue;
        }
        if first && !mr {
            t.push_str(&format!("{:30}sign    verify    sign/s verify/s\n", " "));
            first = false;
        }
        let r = res.eddsa.get(k).copied().unwrap_or_default();
        let Some(c) = ED_CURVES.get(k) else {
            continue;
        };
        if mr {
            t.push_str(&format!(
                "+F6:{k}:{}:{}:{}:{}\n",
                c.bits,
                c.name,
                f6(r[0]),
                f6(r[1])
            ));
        } else {
            t.push_str(&format!(
                "{:4} bits EdDSA ({}) {}s {}s {} {}\n",
                c.bits,
                c.name,
                cf(1.0 / r[0], 8, 4),
                cf(1.0 / r[1], 8, 4),
                cf(r[0], 8, 1),
                cf(r[1], 8, 1)
            ));
        }
    }
    let mut first = true;
    for k in 0..1 {
        if at(sm2_doit.as_slice(), k) == 0 {
            continue;
        }
        if first && !mr {
            t.push_str(&format!("{:30}sign    verify    sign/s verify/s\n", " "));
            first = false;
        }
        let r = res.sm2.get(k).copied().unwrap_or_default();
        let Some(c) = SM2_CURVES.get(k) else {
            continue;
        };
        if mr {
            t.push_str(&format!(
                "+F7:{k}:{}:{}:{}:{}\n",
                c.bits,
                c.name,
                f6(r[0]),
                f6(r[1])
            ));
        } else {
            t.push_str(&format!(
                "{:4} bits SM2 ({}) {}s {}s {} {}\n",
                c.bits,
                c.name,
                cf(1.0 / r[0], 8, 4),
                cf(1.0 / r[1], 8, 4),
                cf(r[0], 8, 1),
                cf(r[1], 8, 1)
            ));
        }
    }
    let mut first = true;
    for k in 0..5 {
        if at(ffdh_doit.as_slice(), k) == 0 {
            continue;
        }
        if first && !mr {
            t.push_str(&format!("{:23}op     op/s\n", " "));
            first = false;
        }
        let r = at(&res.ffdh, k);
        let bits = FFDH_PARAMS.get(k).map_or(0, |p| p.2);
        if mr {
            t.push_str(&format!("+F8:{k}:{bits}:{}:{}\n", f6(r), f6(1.0 / r)));
        } else {
            t.push_str(&format!(
                "{bits:4} bits ffdh {}s {}\n",
                cf(1.0 / r, 8, 4),
                cf(r, 8, 1)
            ));
        }
    }
    out(&t);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_parse() {
        let rsa = c_arrays(TESTRSA_H);
        assert_eq!(rsa.len(), 7);
        for (name, bytes) in &rsa {
            assert!(name.starts_with("test"), "{name}");
            // A DER SEQUENCE.
            assert_eq!(bytes.first(), Some(&0x30), "{name}");
        }
        let dsa = c_arrays(TESTDSA_H);
        assert_eq!(dsa.len(), 15);
        assert!(!array(&dsa, "dsa2048_p").is_empty());
    }

    #[test]
    fn c_formats() {
        assert_eq!(cf(1.5, 11, 2), "       1.50");
        assert_eq!(cf(f64::INFINITY, 11, 2), "        inf");
        assert_eq!(cf(f64::NEG_INFINITY, 0, 2), "-inf");
        assert_eq!(cf(-f64::NAN, 8, 1), "    -nan");
        assert_eq!(f6(0.0), "0.000000");
    }

    #[test]
    fn multi_parsing() {
        assert_eq!(strtoint("12", 0, 31), Some(12));
        assert_eq!(strtoint("31", 0, 31), None);
        assert_eq!(strtoint("x", 0, 31), None);
        assert_eq!(strtoint("+3", 0, 31), Some(3));
        assert_eq!(strtoint("", 0, 31), None);
        assert_eq!(atof("1.25"), 1.25);
        assert_eq!(atof("2e3x"), 2000.0);
        assert_eq!(atof("inf"), f64::INFINITY);
        assert_eq!(atof(""), 0.0);
        assert_eq!(atof("abc"), 0.0);
    }

    #[test]
    fn rsa_names() {
        assert_eq!(rsa_bits("rsa2048"), Some(2048));
        assert_eq!(rsa_bits("rsa2048x"), None);
        assert_eq!(rsa_bits("rsa"), None);
        assert_eq!(rsa_bits("RSA"), None);
        assert_eq!(rsa_bits("rsa512 "), Some(512));
    }

    #[test]
    fn multi_merge() {
        let mut r = Results {
            sym: [[0.0; 6]; ALGOR_NUM],
            rsa: [[0.0; 4]; 7],
            dsa: [[0.0; 2]; 2],
            ecdsa: [[0.0; 2]; ECDSA_NUM],
            ecdh: [0.0; EC_NUM],
            eddsa: [[0.0; 2]; 2],
            sm2: [[0.0; 2]; 1],
            ffdh: [0.0; 5],
            kems: vec![[0.0; 3]; MAX_KEM_NUM],
            sigs: vec![[0.0; 3]; MAX_SIG_NUM],
        };
        r.merge("+F:6:sha256:1.00:2.00", 0, 2);
        r.merge("+F:6:sha256:1.00:2.00", 1, 2);
        assert_eq!(r.sym[6][..2], [2.0, 4.0]);
        r.merge("+F2:2:2048:1:2:3:4", 0, 1);
        assert_eq!(r.rsa[2], [1.0, 2.0, 3.0, 4.0]);
        r.merge("+F6:0:253:Ed25519:5:6", 0, 1);
        assert_eq!(r.eddsa[0], [5.0, 6.0]);
        r.merge("+F9:3:1:2:3", 0, 1);
        assert_eq!(r.kems[3], [1.0, 2.0, 3.0]);
    }
}
