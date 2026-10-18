//! SRP (RFC 2945, RFC 5054; `crypto/srp`, deprecated since 3.0 but in the default build): the
//! protocol's computations (`SRP_Calc_*`), the known groups, verifiers, and the verifier base
//! that `SRP_VBASE_init` reads from a TXT_DB file.
//!
//! The structures are public in `srp.h` (`SRP_gN`, `SRP_user_pwd`, `SRP_VBASE`, `SRP_gN_cache`)
//! and keep OpenSSL's layouts and ownership: a user's `g` and `N` are borrowed from the verifier
//! base's cache or the static groups, which outlive it (as in OpenSSL, the cache isn't freed
//! with its base, so users copied out of it stay valid).

#![allow(
    non_snake_case,
    reason = "RFC 5054's and the header's parameter names: N, g, A, B"
)]

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::size_of;
use core::ptr;
use std::sync::OnceLock;

use rustyssl_abi::{
    BIGNUM, BIO_C_SET_FILENAME, BIO_CLOSE, BIO_FP_READ, BN_CTX, BN_FLG_CONSTTIME, DB_NUMBER,
    DB_SRP_INDEX, DB_SRP_VALID, DB_srpgN, DB_srpid, DB_srpinfo, DB_srpsalt, DB_srptype,
    DB_srpverifier, ERR_LIB_CRYPTO, ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, OPENSSL_STACK,
    OSSL_LIB_CTX, SHA_DIGEST_LENGTH, SN_sha1, SRP_ERR_MEMORY, SRP_ERR_OPEN_FILE,
    SRP_ERR_VBASE_BN_LIB, SRP_ERR_VBASE_INCOMPLETE_FILE, SRP_NO_ERROR, SRP_VBASE, SRP_gN,
    SRP_gN_cache, SRP_user_pwd,
};
use rustyssl_asn1::base64;
use rustyssl_crypto::bn::{BigNum, Limb, rfc_primes};

use crate::bio::file::BIO_s_file;
use crate::bio::{BIO_ctrl, BIO_free_all, BIO_new};
use crate::bn::arith::{BN_add, BN_mul, BN_nnmod};
use crate::bn::conv::{BN_bin2bn, BN_bn2bin, BN_bn2binpad};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new, BN_CTX_new_ex};
use crate::bn::modular::{BN_mod_add, BN_mod_exp, BN_mod_mul, BN_mod_sub};
use crate::bn::{
    BN_clear_free, BN_cmp, BN_dup, BN_free, BN_is_zero, BN_new, BN_num_bits, BN_set_flags, BN_ucmp,
    BN_with_flags, new_static,
};
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::md_ctx::{
    EVP_Digest, EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new,
};
use crate::ffi::ffi_export;
use crate::mem;
use crate::rand_lib::{RAND_bytes_ex, RAND_priv_bytes};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_insert, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::string::CRYPTO_strdup;
use crate::txt_db::{TXT_DB_free, TXT_DB_read};

/// `SRP_RANDOM_SALT_LEN`.
const SRP_RANDOM_SALT_LEN: usize = 20;
/// `MAX_LEN`: the room OpenSSL decodes base64 numbers into.
const MAX_LEN: usize = 2500;
/// `SHA_DIGEST_LENGTH` as a length.
const SHA_LEN: usize = SHA_DIGEST_LENGTH as usize;

/// The 1024-bit group of RFC 5054, appendix A (generator 2).
const SRP_1024: &str = concat!(
    "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576",
    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1",
    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC",
    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
);

/// The 1536-bit group of RFC 5054, appendix A (generator 2).
const SRP_1536: &str = concat!(
    "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D",
    "5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DC",
    "DF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC",
    "764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C486",
    "65772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E",
    "5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
);

/// The 2048-bit group of RFC 5054, appendix A (generator 2).
const SRP_2048: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050",
    "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50",
    "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8",
    "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B",
    "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748",
    "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6",
    "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6",
    "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
);

/// The known groups, in OpenSSL's order (`knowngN`): their ids, generators, and primes (the
/// three largest are RFC 3526's, by bits).
const KNOWN: [(&CStr, Limb, KnownPrime); 7] = [
    (c"8192", 19, KnownPrime::Rfc3526(8192)),
    (c"6144", 5, KnownPrime::Rfc3526(6144)),
    (c"4096", 5, KnownPrime::Rfc3526(4096)),
    (c"3072", 5, KnownPrime::Rfc3526(3072)),
    (c"2048", 2, KnownPrime::Hex(SRP_2048)),
    (c"1536", 2, KnownPrime::Hex(SRP_1536)),
    (c"1024", 2, KnownPrime::Hex(SRP_1024)),
];

/// Where a known group's prime comes from.
#[derive(Clone, Copy)]
enum KnownPrime {
    /// RFC 3526's MODP prime of these bits (the same as RFC 5054's).
    Rfc3526(usize),
    /// RFC 5054's own prime.
    Hex(&'static str),
}

impl KnownPrime {
    fn value(self) -> Option<BigNum> {
        let hex = match self {
            KnownPrime::Rfc3526(bits) => rfc_primes::RFC3526.iter().find(|(b, _)| *b == bits)?.1,
            KnownPrime::Hex(h) => h,
        };
        BigNum::from_hex_digits(hex.as_bytes()).ok()
    }
}

/// The table of known groups: `KNOWN.len()` `SRP_gN`s in a C block, never freed, as OpenSSL's
/// static `knowngN` (applications get pointers into it).
struct Table(*mut SRP_gN);
// SAFETY: built once, then only read (by C code too, which may hold pointers into it).
unsafe impl Send for Table {}
// SAFETY: as above.
unsafe impl Sync for Table {}

static TABLE: OnceLock<Table> = OnceLock::new();

/// Builds the table, or NULL.
fn build_table() -> *mut SRP_gN {
    let block: *mut SRP_gN = mem::alloc(KNOWN.len().saturating_mul(size_of::<SRP_gN>())).cast();
    if block.is_null() {
        return ptr::null_mut();
    }
    for (i, &(id, g, prime)) in KNOWN.iter().enumerate() {
        let Some(n) = prime.value() else {
            // SAFETY: made here, holding no numbers yet that matter (static ones aren't freed).
            unsafe { mem::release(block.cast()) };
            return ptr::null_mut();
        };
        let entry = SRP_gN {
            id: id.as_ptr().cast_mut(),
            g: new_static(BigNum::from_word(g)),
            N: new_static(n),
        };
        // SAFETY: slot `i` of the `KNOWN.len()` the block holds.
        let slot = unsafe { block.add(i) };
        // SAFETY: as above.
        unsafe { slot.write(entry) };
    }
    block
}

/// The known groups' table (`knowngN`), or NULL if it couldn't be made.
fn known() -> *mut SRP_gN {
    if let Some(t) = TABLE.get() {
        return t.0;
    }
    let t = build_table();
    if t.is_null() {
        return ptr::null_mut();
    }
    // A thread that lost the race leaks its table (its numbers are static anyway).
    TABLE.get_or_init(|| Table(t)).0
}

/// The known groups as a slice.
fn known_slice<'a>() -> &'a [SRP_gN] {
    let t = known();
    if t.is_null() {
        return &[];
    }
    // SAFETY: the table holds `KNOWN.len()` entries and is never freed.
    unsafe { core::slice::from_raw_parts(t, KNOWN.len()) }
}

/// `BN_num_bytes`.
///
/// # Safety
/// `a` is a live number.
unsafe fn num_bytes(a: *const BIGNUM) -> c_int {
    // SAFETY: the caller's guarantee.
    let bits = unsafe { BN_num_bits(a) };
    bits.saturating_add(7) / 8
}

/// SHA-1 fetched from `libctx`, or NULL.
///
/// # Safety
/// `libctx` is NULL or live; `propq` NULL or a string.
unsafe fn sha1(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut rustyssl_abi::EVP_MD {
    // SAFETY: the caller's guarantee; a static name.
    unsafe { EVP_MD_fetch(libctx, c"SHA1".as_ptr(), propq) }
}

/// `srp_Calc_xy`: SHA1(PAD(x) || PAD(y)) with both padded to N's length, or NULL (also if x or
/// y, other than N itself, isn't below N).
///
/// # Safety
/// The numbers are live; `libctx` and `propq` as for [`sha1`].
unsafe fn calc_xy(
    x: *const BIGNUM,
    y: *const BIGNUM,
    n: *const BIGNUM,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> *mut BIGNUM {
    // SAFETY: the caller's guarantee.
    let num_n = unsafe { num_bytes(n) };
    // SAFETY: as above.
    let md = unsafe { sha1(libctx, propq) };
    if md.is_null() {
        return ptr::null_mut();
    }
    let res = 'r: {
        // SAFETY: the caller's numbers.
        if x != n && unsafe { BN_ucmp(x, n) } >= 0 {
            break 'r ptr::null_mut();
        }
        // SAFETY: as above.
        if y != n && unsafe { BN_ucmp(y, n) } >= 0 {
            break 'r ptr::null_mut();
        }
        // OpenSSL's zero-size allocation fails.
        let Some(len) = usize::try_from(num_n).ok().filter(|&l| l > 0) else {
            break 'r ptr::null_mut();
        };
        let mut tmp = vec![0u8; len.saturating_mul(2)];
        let (left, right) = tmp.split_at_mut(len);
        let mut digest = [0u8; SHA_LEN];
        // SAFETY: the numbers; each half holds `num_n` octets.
        let ok = unsafe { BN_bn2binpad(x, left.as_mut_ptr(), num_n) } >= 0
            // SAFETY: as above.
            && unsafe { BN_bn2binpad(y, right.as_mut_ptr(), num_n) } >= 0
            // SAFETY: the buffer; the digest's room; the fetched SHA-1.
            && unsafe { EVP_Digest(tmp.as_ptr().cast(), tmp.len(), digest.as_mut_ptr(), ptr::null_mut(), md, ptr::null_mut()) } != 0;
        if !ok {
            break 'r ptr::null_mut();
        }
        // SAFETY: the digest's octets.
        unsafe { BN_bin2bn(digest.as_ptr(), SHA_DIGEST_LENGTH, ptr::null_mut()) }
    };
    // SAFETY: fetched here.
    unsafe { EVP_MD_free(md) };
    res
}

ffi_export! {
    /// u = SHA1(PAD(A) || PAD(B)) (RFC 5054), with SHA-1 fetched from `libctx`; NULL if A or B
    /// isn't below N.
    ///
    /// # Safety
    /// The numbers are live (as in OpenSSL, NULL crashes); `libctx` NULL or live; `propq` NULL
    /// or a string.
    pub unsafe extern "C" fn SRP_Calc_u_ex(A: *const BIGNUM, B: *const BIGNUM, N: *const BIGNUM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if A.is_null() || B.is_null() || N.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        unsafe { calc_xy(A, B, N, libctx, propq) }
    }
}

ffi_export! {
    /// `SRP_Calc_u_ex` in the default library context.
    ///
    /// # Safety
    /// As for `SRP_Calc_u_ex`.
    pub unsafe extern "C" fn SRP_Calc_u(A: *const BIGNUM, B: *const BIGNUM, N: *const BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SRP_Calc_u_ex(A, B, N, ptr::null_mut(), ptr::null()) }
    }
}

/// A new number and a new `BN_CTX` (of `libctx`, or the default one), freed together.
struct Scratch {
    ctx: *mut BN_CTX,
    nums: Vec<*mut BIGNUM>,
}

impl Scratch {
    /// The context, or None.
    fn new(libctx: Option<*mut OSSL_LIB_CTX>) -> Option<Self> {
        let ctx = match libctx {
            // SAFETY: the caller's context, NULL or live.
            Some(l) => unsafe { BN_CTX_new_ex(l) },
            // SAFETY: no preconditions.
            None => unsafe { BN_CTX_new() },
        };
        (!ctx.is_null()).then(|| Self {
            ctx,
            nums: Vec::new(),
        })
    }

    /// A new number freed (cleared) with the scratch, or None.
    fn num(&mut self) -> Option<*mut BIGNUM> {
        // SAFETY: no preconditions.
        let b = unsafe { BN_new() };
        if b.is_null() {
            return None;
        }
        self.nums.push(b);
        Some(b)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        // SAFETY: made here.
        unsafe { BN_CTX_free(self.ctx) };
        for &b in &self.nums {
            // SAFETY: made here; cleared, as they may hold secrets.
            unsafe { BN_clear_free(b) };
        }
    }
}

/// A new number `f(r)` computes, or NULL (freed) if it fails.
fn computed(f: impl FnOnce(*mut BIGNUM) -> bool) -> *mut BIGNUM {
    // SAFETY: no preconditions.
    let r = unsafe { BN_new() };
    if r.is_null() {
        return ptr::null_mut();
    }
    if f(r) {
        return r;
    }
    // SAFETY: made here.
    unsafe { BN_free(r) };
    ptr::null_mut()
}

ffi_export! {
    /// The server's premaster secret S = (A * v^u)^b mod N, or NULL.
    ///
    /// # Safety
    /// Each number is NULL or live.
    pub unsafe extern "C" fn SRP_Calc_server_key(A: *const BIGNUM, v: *const BIGNUM, u: *const BIGNUM, b: *const BIGNUM, N: *const BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if u.is_null() || A.is_null() || v.is_null() || b.is_null() || N.is_null() {
            return ptr::null_mut();
        }
        let Some(mut s) = Scratch::new(None) else { return ptr::null_mut() };
        let Some(tmp) = s.num() else { return ptr::null_mut() };
        // SAFETY: the caller's numbers; the scratch's.
        if unsafe { BN_mod_exp(tmp, v, u, N, s.ctx) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        if unsafe { BN_mod_mul(tmp, A, tmp, N, s.ctx) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        computed(|r| unsafe { BN_mod_exp(r, tmp, b, N, s.ctx) } != 0)
    }
}

ffi_export! {
    /// The server's public value B = g^b + k*v mod N (k = SHA1(N | PAD(g))), with SHA-1 fetched
    /// from `libctx`; or NULL.
    ///
    /// # Safety
    /// Each number is NULL or live; `libctx` NULL or live; `propq` NULL or a string.
    pub unsafe extern "C" fn SRP_Calc_B_ex(b: *const BIGNUM, N: *const BIGNUM, g: *const BIGNUM, v: *const BIGNUM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if b.is_null() || N.is_null() || g.is_null() || v.is_null() {
            return ptr::null_mut();
        }
        let Some(mut s) = Scratch::new(Some(libctx)) else { return ptr::null_mut() };
        let (Some(kv), Some(gb)) = (s.num(), s.num()) else { return ptr::null_mut() };
        // SAFETY: the caller's numbers; the scratch's.
        if unsafe { BN_mod_exp(gb, g, b, N, s.ctx) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let k = unsafe { calc_xy(N, g, N, libctx, propq) };
        if k.is_null() {
            return ptr::null_mut();
        }
        let r = computed(|r| {
            // SAFETY: as above; `k` made here.
            (unsafe { BN_mod_mul(kv, v, k, N, s.ctx) }) != 0
                // SAFETY: as above.
                && unsafe { BN_mod_add(r, gb, kv, N, s.ctx) } != 0
        });
        // SAFETY: made here.
        unsafe { BN_free(k) };
        r
    }
}

ffi_export! {
    /// `SRP_Calc_B_ex` in the default library context.
    ///
    /// # Safety
    /// As for `SRP_Calc_B_ex`.
    pub unsafe extern "C" fn SRP_Calc_B(b: *const BIGNUM, N: *const BIGNUM, g: *const BIGNUM, v: *const BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SRP_Calc_B_ex(b, N, g, v, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The private value x = SHA1(s | SHA1(user | ":" | pass)), with SHA-1 fetched from
    /// `libctx`; or NULL (also for a zero salt, as OpenSSL's zero-size allocation fails).
    ///
    /// # Safety
    /// `s` is NULL or live; `user` and `pass` NULL or strings; `libctx` NULL or live; `propq`
    /// NULL or a string.
    pub unsafe extern "C" fn SRP_Calc_x_ex(s: *const BIGNUM, user: *const c_char, pass: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if s.is_null() || user.is_null() || pass.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let ctxt = unsafe { EVP_MD_CTX_new() };
        if ctxt.is_null() {
            return ptr::null_mut();
        }
        let mut md = ptr::null_mut();
        let res = 'r: {
            // SAFETY: the caller's salt.
            let Some(slen) = usize::try_from(unsafe { num_bytes(s) }).ok().filter(|&l| l > 0) else { break 'r ptr::null_mut() };
            let mut cs = vec![0u8; slen];
            // SAFETY: as for `sha1`.
            md = unsafe { sha1(libctx, propq) };
            if md.is_null() {
                break 'r ptr::null_mut();
            }
            // SAFETY: the caller's string.
            let u = unsafe { CStr::from_ptr(user) }.to_bytes();
            // SAFETY: as above.
            let p = unsafe { CStr::from_ptr(pass) }.to_bytes();
            let mut dig = [0u8; SHA_LEN];
            // SAFETY: the context; the digest; the strings and the room.
            let ok = unsafe { EVP_DigestInit_ex(ctxt, md, ptr::null_mut()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(ctxt, u.as_ptr().cast(), u.len()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(ctxt, c":".as_ptr().cast(), 1) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(ctxt, p.as_ptr().cast(), p.len()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestFinal_ex(ctxt, dig.as_mut_ptr(), ptr::null_mut()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestInit_ex(ctxt, md, ptr::null_mut()) } != 0
                // SAFETY: the salt; its `slen` octets of room.
                && unsafe { BN_bn2bin(s, cs.as_mut_ptr()) } >= 0
                // SAFETY: the context; the salt's octets.
                && unsafe { EVP_DigestUpdate(ctxt, cs.as_ptr().cast(), cs.len()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestUpdate(ctxt, dig.as_ptr().cast(), dig.len()) } != 0
                // SAFETY: as above.
                && unsafe { EVP_DigestFinal_ex(ctxt, dig.as_mut_ptr(), ptr::null_mut()) } != 0;
            if !ok {
                break 'r ptr::null_mut();
            }
            // SAFETY: the digest's octets.
            unsafe { BN_bin2bn(dig.as_ptr(), SHA_DIGEST_LENGTH, ptr::null_mut()) }
        };
        // SAFETY: fetched here, or NULL.
        unsafe { EVP_MD_free(md) };
        // SAFETY: made here.
        unsafe { EVP_MD_CTX_free(ctxt) };
        res
    }
}

ffi_export! {
    /// `SRP_Calc_x_ex` in the default library context.
    ///
    /// # Safety
    /// As for `SRP_Calc_x_ex`.
    pub unsafe extern "C" fn SRP_Calc_x(s: *const BIGNUM, user: *const c_char, pass: *const c_char) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SRP_Calc_x_ex(s, user, pass, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The client's public value A = g^a mod N, or NULL.
    ///
    /// # Safety
    /// Each number is NULL or live.
    pub unsafe extern "C" fn SRP_Calc_A(a: *const BIGNUM, N: *const BIGNUM, g: *const BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if a.is_null() || N.is_null() || g.is_null() {
            return ptr::null_mut();
        }
        let Some(s) = Scratch::new(None) else { return ptr::null_mut() };
        // SAFETY: the caller's numbers; the scratch's context.
        computed(|r| unsafe { BN_mod_exp(r, g, a, N, s.ctx) } != 0)
    }
}

ffi_export! {
    /// The client's premaster secret K = (B - k*g^x)^(a + u*x) mod N, with x used in constant
    /// time and SHA-1 fetched from `libctx`; or NULL.
    ///
    /// # Safety
    /// Each number is NULL or live; `libctx` NULL or live; `propq` NULL or a string.
    pub unsafe extern "C" fn SRP_Calc_client_key_ex(N: *const BIGNUM, B: *const BIGNUM, g: *const BIGNUM, x: *const BIGNUM, a: *const BIGNUM, u: *const BIGNUM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if u.is_null() || B.is_null() || N.is_null() || g.is_null() || x.is_null() || a.is_null() {
            return ptr::null_mut();
        }
        let Some(mut s) = Scratch::new(Some(libctx)) else { return ptr::null_mut() };
        let (Some(tmp), Some(tmp2), Some(tmp3), Some(xtmp)) = (s.num(), s.num(), s.num(), s.num()) else {
            return ptr::null_mut();
        };
        // SAFETY: the scratch's numbers; the caller's x, borrowed with the constant-time flag.
        unsafe { BN_with_flags(xtmp, x, BN_FLG_CONSTTIME) };
        // SAFETY: as above.
        unsafe { BN_set_flags(tmp, BN_FLG_CONSTTIME) };
        // SAFETY: as above; the caller's numbers.
        if unsafe { BN_mod_exp(tmp, g, xtmp, N, s.ctx) } == 0 {
            return ptr::null_mut();
        }
        // SAFETY: as for `calc_xy`.
        let k = unsafe { calc_xy(N, g, N, libctx, propq) };
        if k.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: as above; `k` made here.
        let ok = unsafe { BN_mod_mul(tmp2, tmp, k, N, s.ctx) } != 0
            // SAFETY: as above.
            && unsafe { BN_mod_sub(tmp, B, tmp2, N, s.ctx) } != 0
            // SAFETY: as above.
            && unsafe { BN_mul(tmp3, u, xtmp, s.ctx) } != 0
            // SAFETY: as above.
            && unsafe { BN_add(tmp2, a, tmp3) } != 0;
        // SAFETY: made here.
        unsafe { BN_free(k) };
        if !ok {
            return ptr::null_mut();
        }
        // SAFETY: as above.
        computed(|r| unsafe { BN_mod_exp(r, tmp, tmp2, N, s.ctx) } != 0)
    }
}

ffi_export! {
    /// `SRP_Calc_client_key_ex` in the default library context.
    ///
    /// # Safety
    /// As for `SRP_Calc_client_key_ex`.
    pub unsafe extern "C" fn SRP_Calc_client_key(N: *const BIGNUM, B: *const BIGNUM, g: *const BIGNUM, x: *const BIGNUM, a: *const BIGNUM, u: *const BIGNUM) -> *mut BIGNUM
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SRP_Calc_client_key_ex(N, B, g, x, a, u, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Whether B mod N isn't zero (the check of the server's value): 1, or 0 (also on NULL).
    ///
    /// # Safety
    /// Each number is NULL or live.
    pub unsafe extern "C" fn SRP_Verify_B_mod_N(B: *const BIGNUM, N: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        if B.is_null() || N.is_null() {
            return 0;
        }
        let Some(mut s) = Scratch::new(None) else { return 0 };
        let Some(r) = s.num() else { return 0 };
        // SAFETY: the scratch's number and context; the caller's numbers.
        if unsafe { BN_nnmod(r, B, N, s.ctx) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        c_int::from(unsafe { BN_is_zero(r) } == 0)
    }
}

ffi_export! {
    /// Whether A mod N isn't zero (the check of the client's value).
    ///
    /// # Safety
    /// As for `SRP_Verify_B_mod_N`.
    pub unsafe extern "C" fn SRP_Verify_A_mod_N(A: *const BIGNUM, N: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SRP_Verify_B_mod_N(A, N) }
    }
}

ffi_export! {
    /// The id of the known group with generator `g` and prime `N`, or NULL.
    ///
    /// # Safety
    /// Each number is NULL or live.
    pub unsafe extern "C" fn SRP_check_known_gN_param(g: *const BIGNUM, N: *const BIGNUM) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if g.is_null() || N.is_null() {
            return ptr::null_mut();
        }
        known_slice()
            .iter()
            .find(|e| {
                // SAFETY: the static number; the caller's.
                let same_g = unsafe { BN_cmp(e.g, g) } == 0;
                // SAFETY: as above.
                same_g && unsafe { BN_cmp(e.N, N) } == 0
            })
            .map_or(ptr::null_mut(), |e| e.id)
    }
}

ffi_export! {
    /// The known group of id `id` ("8192", ..., "1024"), the first (8192) for NULL, or NULL.
    ///
    /// # Safety
    /// `id` is NULL or a string.
    pub unsafe extern "C" fn SRP_get_default_gN(id: *const c_char) -> *mut SRP_gN
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let t = known();
        if id.is_null() || t.is_null() {
            return t;
        }
        // SAFETY: the caller's string.
        let want = unsafe { CStr::from_ptr(id) };
        (0..KNOWN.len())
            .zip(known_slice())
            // SAFETY: the static ids.
            .find(|(_, e)| unsafe { CStr::from_ptr(e.id) } == want)
            // SAFETY: an index within the table.
            .map_or(ptr::null_mut(), |(i, _)| unsafe { t.add(i) })
    }
}

/// `t_fromb64`: the octets of an SRP-alphabet base64 string (after leading blanks), padded at
/// the front to whole blocks as OpenSSL does, if they fit `alen`; None for OpenSSL's -1.
///
/// When OpenSSL's final decoding step fails, it counts the octets of the step before again,
/// returning that many unwritten (uninitialized) octets; that is refused here instead.
fn t_fromb64(alen: usize, src: &[u8]) -> Option<Vec<u8>> {
    let start = src
        .iter()
        .position(|&c| !matches!(c, b' ' | b'\t' | b'\n'))
        .unwrap_or(src.len());
    let src = src.get(start..).unwrap_or(&[]);
    let size = src.len();
    let padsize = (4usize.wrapping_sub(size & 3)) & 3;
    if c_int::try_from(size).is_err() || (size.saturating_add(padsize) / 4).saturating_mul(3) > alen
    {
        return None;
    }
    if padsize == 3 {
        return None;
    }
    let mut ctx = base64::Ctx::default();
    ctx.decode_init();
    ctx.flags = base64::USE_SRP_ALPHABET;
    let mut out = Vec::new();
    if padsize != 0 {
        let d = ctx.decode_update(Some(b"00".get(..padsize).unwrap_or(&[])));
        if d.ret < 0 {
            return None;
        }
        out.extend(d.out);
    }
    let d = ctx.decode_update(Some(src));
    if d.ret < 0 {
        return None;
    }
    out.extend(d.out);
    out.extend(ctx.decode_final()?);
    if padsize != 0 {
        if padsize >= out.len() {
            return None;
        }
        out.drain(..padsize);
    }
    Some(out)
}

/// `t_tob64`: the SRP-alphabet base64 of `src` with no padding characters (front-padded with
/// zero octets to whole blocks, whose characters are then dropped); None for no input.
fn t_tob64(src: &[u8]) -> Option<Vec<u8>> {
    let mut ctx = base64::Ctx::default();
    ctx.encode_init();
    ctx.flags = base64::NO_NEWLINES | base64::USE_SRP_ALPHABET;
    let leadz = 3 - src.len() % 3;
    let mut out = Vec::new();
    if leadz != 3 {
        let pad = [0u8; 2];
        out.extend(ctx.encode_update(pad.get(..leadz).unwrap_or(&[]))?.out);
    }
    out.extend(ctx.encode_update(src)?.out);
    if let Some(f) = ctx.encode_final() {
        out.extend(f);
    }
    if leadz != 3 {
        out.drain(..leadz.min(out.len()));
    }
    Some(out)
}

/// A NUL-terminated `CRYPTO_malloc` copy of `text` in at least `room` octets, or NULL.
fn c_string(text: &[u8], room: usize) -> *mut c_char {
    // The room OpenSSL allocates can be short of a tiny number's text; the copy always fits.
    let size = room.max(text.len().saturating_add(1));
    let p: *mut u8 = mem::alloc(size).cast();
    if p.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: `text.len()` octets into the block of at least `text.len() + 1`.
    unsafe { ptr::copy_nonoverlapping(text.as_ptr(), p, text.len()) };
    // SAFETY: the octet after them.
    let end = unsafe { p.add(text.len()) };
    // SAFETY: as above.
    unsafe { end.write(0) };
    p.cast()
}

/// A `CRYPTO_strdup` of a string, or NULL.
///
/// # Safety
/// `s` is a string.
unsafe fn strdup(s: *const c_char) -> *mut c_char {
    // SAFETY: the caller's guarantee.
    unsafe { CRYPTO_strdup(s, ptr::null(), 0) }
}

/// A number from octets, or NULL.
fn bn_of(octets: &[u8]) -> *mut BIGNUM {
    let Ok(len) = c_int::try_from(octets.len()) else {
        return ptr::null_mut();
    };
    // SAFETY: the octets.
    unsafe { BN_bin2bn(octets.as_ptr(), len, ptr::null_mut()) }
}

/// A number from an SRP base64 string, or NULL.
///
/// # Safety
/// `s` is a string.
unsafe fn bn_of_b64(s: *const c_char) -> *mut BIGNUM {
    // SAFETY: the caller's guarantee.
    let text = unsafe { CStr::from_ptr(s) }.to_bytes();
    t_fromb64(MAX_LEN, text).map_or(ptr::null_mut(), |o| bn_of(&o))
}

ffi_export! {
    /// Frees a user (its salt, its verifier cleared, its id and info; not its group).
    ///
    /// # Safety
    /// `user_pwd` is NULL or a live user, not used after.
    pub unsafe extern "C" fn SRP_user_pwd_free(user_pwd: *mut SRP_user_pwd)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { user_pwd.as_mut() }) else { return };
        // SAFETY: its numbers and strings, or NULL.
        unsafe { BN_free(u.s) };
        // SAFETY: as above.
        unsafe { BN_clear_free(u.v) };
        // SAFETY: as above.
        unsafe { mem::release(u.id.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(u.info.cast()) };
        // SAFETY: the user itself.
        unsafe { mem::release(user_pwd.cast()) };
    }
}

ffi_export! {
    /// A new empty user, or NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn SRP_user_pwd_new() -> *mut SRP_user_pwd
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let p: *mut SRP_user_pwd = mem::alloc(size_of::<SRP_user_pwd>()).cast();
        if !p.is_null() {
            // SAFETY: the block made for it.
            unsafe {
                p.write(SRP_user_pwd {
                    id: ptr::null_mut(),
                    s: ptr::null_mut(),
                    v: ptr::null_mut(),
                    g: ptr::null(),
                    N: ptr::null(),
                    info: ptr::null_mut(),
                })
            };
        }
        p
    }
}

ffi_export! {
    /// Sets the user's group (borrowed: it must outlive the user).
    ///
    /// # Safety
    /// `vinfo` is a live user (as in OpenSSL, NULL crashes); the numbers NULL or live.
    pub unsafe extern "C" fn SRP_user_pwd_set_gN(vinfo: *mut SRP_user_pwd, g: *const BIGNUM, N: *const BIGNUM)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        if let Some(u) = unsafe { vinfo.as_mut() } {
            u.N = N;
            u.g = g;
        }
    }
}

ffi_export! {
    /// Replaces the user's id and info with copies (NULL clears them): 1, or 0.
    ///
    /// # Safety
    /// `vinfo` is a live user (as in OpenSSL, NULL crashes); `id` and `info` NULL or strings.
    pub unsafe extern "C" fn SRP_user_pwd_set1_ids(vinfo: *mut SRP_user_pwd, id: *const c_char, info: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { vinfo.as_mut() }) else { return 0 };
        // SAFETY: its strings, or NULL.
        unsafe { mem::release(u.id.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(u.info.cast()) };
        u.id = ptr::null_mut();
        u.info = ptr::null_mut();
        if !id.is_null() {
            // SAFETY: the caller's string.
            u.id = unsafe { strdup(id) };
            if u.id.is_null() {
                return 0;
            }
        }
        if info.is_null() {
            return 1;
        }
        // SAFETY: as above.
        u.info = unsafe { strdup(info) };
        c_int::from(!u.info.is_null())
    }
}

/// `SRP_user_pwd_set_sv`: the user's salt and verifier from SRP base64 strings: true, or false
/// (with neither set).
///
/// # Safety
/// `u` is a live user; `s` and `v` strings.
unsafe fn set_sv(u: &mut SRP_user_pwd, s: *const c_char, v: *const c_char) -> bool {
    u.v = ptr::null_mut();
    u.s = ptr::null_mut();
    // SAFETY: the caller's string.
    u.v = unsafe { bn_of_b64(v) };
    if u.v.is_null() {
        return false;
    }
    // SAFETY: as above.
    u.s = unsafe { bn_of_b64(s) };
    if u.s.is_null() {
        // SAFETY: made here.
        unsafe { BN_free(u.v) };
        u.v = ptr::null_mut();
        return false;
    }
    true
}

ffi_export! {
    /// Replaces the user's salt and verifier with `s` and `v` (taken): 1 if both are set, else
    /// 0 (they are taken anyway).
    ///
    /// # Safety
    /// `vinfo` is a live user (as in OpenSSL, NULL crashes); `s` and `v` NULL or live.
    pub unsafe extern "C" fn SRP_user_pwd_set0_sv(vinfo: *mut SRP_user_pwd, s: *mut BIGNUM, v: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(u) = (unsafe { vinfo.as_mut() }) else { return 0 };
        // SAFETY: its numbers, or NULL.
        unsafe { BN_free(u.s) };
        // SAFETY: as above.
        unsafe { BN_clear_free(u.v) };
        u.v = v;
        u.s = s;
        c_int::from(!s.is_null() && !v.is_null())
    }
}

/// `srp_user_pwd_dup`: a copy of the user (sharing its group), or NULL.
///
/// # Safety
/// `src` is NULL or a live user.
unsafe fn user_dup(src: *const SRP_user_pwd) -> *mut SRP_user_pwd {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { src.as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: no preconditions.
    let ret = unsafe { SRP_user_pwd_new() };
    if ret.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: made here; the source's group.
    unsafe { SRP_user_pwd_set_gN(ret, s.g, s.N) };
    // SAFETY: as above; its strings.
    let ok = unsafe { SRP_user_pwd_set1_ids(ret, s.id, s.info) } != 0 && {
        // SAFETY: its salt, or NULL.
        let salt = unsafe { BN_dup(s.s) };
        // SAFETY: its verifier, or NULL.
        let verifier = unsafe { BN_dup(s.v) };
        // SAFETY: as above; the copies, taken.
        (unsafe { SRP_user_pwd_set0_sv(ret, salt, verifier) }) != 0
    };
    if !ok {
        // SAFETY: made here.
        unsafe { SRP_user_pwd_free(ret) };
        return ptr::null_mut();
    }
    ret
}

ffi_export! {
    /// A new, empty verifier base with a copy of `seed_key` (which, if set, makes up users not
    /// in it), or NULL.
    ///
    /// # Safety
    /// `seed_key` is NULL or a string.
    pub unsafe extern "C" fn SRP_VBASE_new(seed_key: *mut c_char) -> *mut SRP_VBASE
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        let vb: *mut SRP_VBASE = mem::alloc(size_of::<SRP_VBASE>()).cast();
        if vb.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let users = unsafe { OPENSSL_sk_new_null() };
        // SAFETY: as above.
        let cache = unsafe { OPENSSL_sk_new_null() };
        let key = if seed_key.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the caller's string.
            unsafe { strdup(seed_key) }
        };
        if users.is_null() || cache.is_null() || (!seed_key.is_null() && key.is_null()) {
            // SAFETY: made here, or NULL.
            unsafe { OPENSSL_sk_free(users) };
            // SAFETY: as above.
            unsafe { OPENSSL_sk_free(cache) };
            // SAFETY: as above.
            unsafe { mem::release(key.cast()) };
            // SAFETY: as above.
            unsafe { mem::release(vb.cast()) };
            return ptr::null_mut();
        }
        // SAFETY: the block made for it.
        unsafe {
            vb.write(SRP_VBASE {
                users_pwd: users.cast(),
                gN_cache: cache.cast(),
                seed_key: key,
                default_g: ptr::null(),
                default_N: ptr::null(),
            })
        };
        vb
    }
}

/// `SRP_user_pwd_free` as a stack's free function.
unsafe extern "C" fn user_free(p: *mut c_void) {
    // SAFETY: a user of the stack, which the stack owned.
    unsafe { SRP_user_pwd_free(p.cast()) };
}

ffi_export! {
    /// Frees the verifier base and its users. As in OpenSSL, its cache of group numbers is
    /// kept (users copied out of it borrow those numbers).
    ///
    /// # Safety
    /// `vb` is NULL or a live verifier base, not used after.
    pub unsafe extern "C" fn SRP_VBASE_free(vb: *mut SRP_VBASE)
    where failure = (), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { vb.as_ref() }) else { return };
        // SAFETY: its users.
        unsafe { OPENSSL_sk_pop_free(v.users_pwd.cast(), Some(user_free)) };
        // SAFETY: its cache's list (not the entries, which users may borrow).
        unsafe { OPENSSL_sk_free(v.gN_cache.cast()) };
        // SAFETY: its key, or NULL.
        unsafe { mem::release(v.seed_key.cast()) };
        // SAFETY: the base itself.
        unsafe { mem::release(vb.cast()) };
    }
}

/// `SRP_gN_place_bn`: the cached number of SRP base64 string `ch`, decoded and cached (first)
/// if new; NULL on failure.
///
/// # Safety
/// `cache` is NULL or a live list of cache entries; `ch` a string.
unsafe fn place_bn(cache: *mut OPENSSL_STACK, ch: *const c_char) -> *const BIGNUM {
    if cache.is_null() {
        return ptr::null();
    }
    // SAFETY: the caller's string.
    let want = unsafe { CStr::from_ptr(ch) };
    // SAFETY: the list.
    let n = unsafe { OPENSSL_sk_num(cache) };
    for i in 0..n {
        // SAFETY: an index in range.
        let e: *const SRP_gN_cache = unsafe { OPENSSL_sk_value(cache, i) }.cast();
        // SAFETY: an entry of the list.
        if let Some(e) = unsafe { e.as_ref() }
            // SAFETY: its string.
            && unsafe { CStr::from_ptr(e.b64_bn) } == want
        {
            return e.bn;
        }
    }
    let Some(octets) = t_fromb64(MAX_LEN, want.to_bytes()) else {
        return ptr::null();
    };
    let entry: *mut SRP_gN_cache = mem::alloc(size_of::<SRP_gN_cache>()).cast();
    if entry.is_null() {
        return ptr::null();
    }
    // SAFETY: the caller's string.
    let b64 = unsafe { strdup(ch) };
    let bn = if b64.is_null() {
        ptr::null_mut()
    } else {
        bn_of(&octets)
    };
    if bn.is_null() {
        // SAFETY: made here, or NULL.
        unsafe { mem::release(b64.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(entry.cast()) };
        return ptr::null();
    }
    // SAFETY: the block made for it.
    unsafe { entry.write(SRP_gN_cache { b64_bn: b64, bn }) };
    // SAFETY: the list; the entry, taken.
    if unsafe { OPENSSL_sk_insert(cache, entry.cast(), 0) } > 0 {
        return bn;
    }
    // SAFETY: made here.
    unsafe { BN_free(bn) };
    // SAFETY: as above.
    unsafe { mem::release(b64.cast()) };
    // SAFETY: as above.
    unsafe { mem::release(entry.cast()) };
    ptr::null()
}

/// A group the verifier file defines: its id and numbers (from the base's cache).
struct FileGroup {
    id: Vec<u8>,
    g: *const BIGNUM,
    n: *const BIGNUM,
}

/// `SRP_get_gN_by_id`: the file's group of id `id` (the latest defined for NULL), else the
/// known group: its generator and prime.
///
/// # Safety
/// `id` is NULL or a string.
unsafe fn group_by_id(
    id: *const c_char,
    tab: &[FileGroup],
) -> Option<(*const BIGNUM, *const BIGNUM)> {
    // SAFETY: the caller's guarantee.
    let want = (!id.is_null()).then(|| unsafe { CStr::from_ptr(id) }.to_bytes());
    if let Some(f) = tab
        .iter()
        .find(|f| want.is_none_or(|w| w == f.id.as_slice()))
    {
        return Some((f.g, f.n));
    }
    // SAFETY: the caller's string, or NULL.
    let k = unsafe { SRP_get_default_gN(id) };
    // SAFETY: an entry of the static table, or NULL.
    unsafe { k.as_ref() }.map(|k| (k.g, k.N))
}

/// Field `f` of a TXT_DB row.
///
/// # Safety
/// `pp` is a row of at least `f + 1` fields.
unsafe fn field(pp: *mut *mut c_char, f: c_int) -> *mut c_char {
    let Ok(i) = usize::try_from(f) else {
        return ptr::null_mut();
    };
    // SAFETY: the caller's guarantee.
    let slot = unsafe { pp.add(i) };
    // SAFETY: as above.
    unsafe { slot.read() }
}

ffi_export! {
    /// Reads the verifier file into the base: `I` rows define groups (id, prime in the verifier
    /// field, generator in the salt field), `V` rows users of a group defined before them or
    /// known; with a seed key, the last group defined (else the largest known) becomes the
    /// default for made-up users. `SRP_NO_ERROR`, or an `SRP_ERR_*` code.
    ///
    /// # Safety
    /// `vb` is a live verifier base (as in OpenSSL, NULL crashes); `verifier_file` NULL or a
    /// path.
    pub unsafe extern "C" fn SRP_VBASE_init(vb: *mut SRP_VBASE, verifier_file: *mut c_char) -> c_int
    where failure = SRP_ERR_MEMORY, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { vb.as_mut() }) else { return SRP_ERR_MEMORY };
        // SAFETY: no preconditions.
        let meth = unsafe { BIO_s_file() };
        // SAFETY: the built-in method.
        let bio = unsafe { BIO_new(meth) };
        let mut tab: Vec<FileGroup> = Vec::new();
        let mut tmpdb = ptr::null_mut();
        let mut user_pwd: *mut SRP_user_pwd = ptr::null_mut();
        let code = 'e: {
            if verifier_file.is_null() {
                err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "SRP_VBASE_init");
                break 'e SRP_ERR_OPEN_FILE;
            }
            // `BIO_read_filename`.
            if bio.is_null()
                // SAFETY: the file BIO; the caller's path.
                || unsafe { BIO_ctrl(bio, BIO_C_SET_FILENAME, (BIO_CLOSE | BIO_FP_READ).into(), verifier_file.cast()) } <= 0
            {
                break 'e SRP_ERR_OPEN_FILE;
            }
            // SAFETY: the BIO.
            tmpdb = unsafe { TXT_DB_read(bio, DB_NUMBER) };
            // SAFETY: the database read, or NULL.
            let Some(db) = (unsafe { tmpdb.as_ref() }) else { break 'e SRP_ERR_VBASE_INCOMPLETE_FILE };
            let mut code = SRP_ERR_MEMORY;
            let mut last_index: Option<Vec<u8>> = None;
            if !v.seed_key.is_null() {
                // SAFETY: no preconditions.
                let d = unsafe { SRP_get_default_gN(ptr::null()) };
                // SAFETY: the first static entry, or NULL.
                if let Some(d) = unsafe { d.as_ref() } {
                    // SAFETY: its static id.
                    last_index = Some(unsafe { CStr::from_ptr(d.id) }.to_bytes().to_vec());
                }
            }
            let list: *mut OPENSSL_STACK = db.data.cast();
            // SAFETY: the database's rows.
            let n = unsafe { OPENSSL_sk_num(list) };
            for i in 0..n {
                // SAFETY: an index in range.
                let pp: *mut *mut c_char = unsafe { OPENSSL_sk_value(list, i) }.cast();
                // SAFETY: a row of `DB_NUMBER` fields.
                let t = unsafe { field(pp, DB_srptype) };
                // SAFETY: the type field's first octet.
                let kind = unsafe { t.read() }.to_ne_bytes();
                let kind = c_int::from(kind.first().copied().unwrap_or(0));
                if kind == DB_SRP_INDEX {
                    // SAFETY: the row's fields.
                    let id = unsafe { field(pp, DB_srpid) };
                    // SAFETY: as above.
                    let verifier = unsafe { field(pp, DB_srpverifier) };
                    // SAFETY: as above.
                    let salt = unsafe { field(pp, DB_srpsalt) };
                    // SAFETY: the base's cache; the fields' strings.
                    let nn = unsafe { place_bn(v.gN_cache.cast(), verifier) };
                    if nn.is_null() {
                        break 'e code;
                    }
                    // SAFETY: as above.
                    let g = unsafe { place_bn(v.gN_cache.cast(), salt) };
                    if g.is_null() {
                        break 'e code;
                    }
                    // SAFETY: the id field's string.
                    let id = unsafe { CStr::from_ptr(id) }.to_bytes().to_vec();
                    if !v.seed_key.is_null() {
                        last_index = Some(id.clone());
                    }
                    tab.insert(0, FileGroup { id, g, n: nn });
                } else if kind == DB_SRP_VALID {
                    // SAFETY: the row's field.
                    let gn = unsafe { field(pp, DB_srpgN) };
                    // SAFETY: the group field's string.
                    let Some((g, nn)) = (unsafe { group_by_id(gn, &tab) }) else { continue };
                    code = SRP_ERR_MEMORY;
                    // SAFETY: no preconditions.
                    user_pwd = unsafe { SRP_user_pwd_new() };
                    // SAFETY: made here, or NULL.
                    let Some(u) = (unsafe { user_pwd.as_mut() }) else { break 'e code };
                    u.g = g;
                    u.N = nn;
                    // SAFETY: the row's fields.
                    let id = unsafe { field(pp, DB_srpid) };
                    // SAFETY: as above.
                    let info = unsafe { field(pp, DB_srpinfo) };
                    // SAFETY: the user; the row's strings.
                    if unsafe { SRP_user_pwd_set1_ids(user_pwd, id, info) } == 0 {
                        break 'e code;
                    }
                    code = SRP_ERR_VBASE_BN_LIB;
                    // SAFETY: the user, again; the row's strings.
                    let Some(u) = (unsafe { user_pwd.as_mut() }) else { break 'e code };
                    // SAFETY: the row's fields.
                    let salt = unsafe { field(pp, DB_srpsalt) };
                    // SAFETY: as above.
                    let verifier = unsafe { field(pp, DB_srpverifier) };
                    // SAFETY: the user; the row's strings.
                    if !unsafe { set_sv(u, salt, verifier) } {
                        break 'e code;
                    }
                    // SAFETY: the base's users; the user, taken.
                    if unsafe { OPENSSL_sk_insert(v.users_pwd.cast(), user_pwd.cast(), 0) } == 0 {
                        break 'e code;
                    }
                    user_pwd = ptr::null_mut();
                }
            }
            if let Some(last) = last_index {
                let mut id = last;
                id.push(0);
                // SAFETY: a NUL-terminated id.
                let Some((g, nn)) = (unsafe { group_by_id(id.as_ptr().cast(), &tab) }) else { break 'e SRP_ERR_VBASE_BN_LIB };
                v.default_g = g;
                v.default_N = nn;
            }
            SRP_NO_ERROR
        };
        // SAFETY: made here, or NULL (a user not taken by the base).
        unsafe { SRP_user_pwd_free(user_pwd) };
        // SAFETY: as above.
        unsafe { TXT_DB_free(tmpdb) };
        // SAFETY: as above.
        unsafe { BIO_free_all(bio) };
        code
    }
}

/// `find_user`: the base's user named `username`, or NULL.
///
/// # Safety
/// `vb` is NULL or a live base; `username` a string.
unsafe fn find_user(vb: *const SRP_VBASE, username: *const c_char) -> *mut SRP_user_pwd {
    // SAFETY: the caller's guarantee.
    let Some(v) = (unsafe { vb.as_ref() }) else {
        return ptr::null_mut();
    };
    // SAFETY: as above.
    let want = unsafe { CStr::from_ptr(username) };
    let list: *mut OPENSSL_STACK = v.users_pwd.cast();
    // SAFETY: its users.
    let n = unsafe { OPENSSL_sk_num(list) };
    for i in 0..n {
        // SAFETY: an index in range.
        let u: *mut SRP_user_pwd = unsafe { OPENSSL_sk_value(list, i) }.cast();
        // SAFETY: a user of the list; a user without an id matches nothing (OpenSSL crashes).
        if let Some(r) = unsafe { u.as_ref() }
            && !r.id.is_null()
            // SAFETY: its id.
            && unsafe { CStr::from_ptr(r.id) } == want
        {
            return u;
        }
    }
    ptr::null_mut()
}

ffi_export! {
    /// Adds a user (taken) to the base: 1, or 0.
    ///
    /// # Safety
    /// `vb` is a live base (as in OpenSSL, NULL crashes); `user_pwd` a live user.
    pub unsafe extern "C" fn SRP_VBASE_add0_user(vb: *mut SRP_VBASE, user_pwd: *mut SRP_user_pwd) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { vb.as_ref() }) else { return 0 };
        // SAFETY: its users; the user, taken.
        c_int::from(unsafe { OPENSSL_sk_push(v.users_pwd.cast(), user_pwd.cast()) } > 0)
    }
}

ffi_export! {
    /// The base's user named `username` (borrowed), or NULL.
    ///
    /// # Safety
    /// `vb` is NULL or a live base; `username` a string.
    pub unsafe extern "C" fn SRP_VBASE_get_by_user(vb: *mut SRP_VBASE, username: *mut c_char) -> *mut SRP_user_pwd
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { find_user(vb, username) }
    }
}

ffi_export! {
    /// A copy of the base's user named `username`; or, with a seed key and a default group, a
    /// made-up one (salt SHA1(seed key | username), random verifier) so that unknown users look
    /// like known ones; or NULL.
    ///
    /// # Safety
    /// `vb` is NULL or a live base; `username` a string.
    pub unsafe extern "C" fn SRP_VBASE_get1_by_user(vb: *mut SRP_VBASE, username: *mut c_char) -> *mut SRP_user_pwd
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        let Some(v) = (unsafe { vb.as_ref() }) else { return ptr::null_mut() };
        // SAFETY: as above.
        let found = unsafe { find_user(vb, username) };
        if !found.is_null() {
            // SAFETY: the base's user.
            return unsafe { user_dup(found) };
        }
        if v.seed_key.is_null() || v.default_g.is_null() || v.default_N.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let user = unsafe { SRP_user_pwd_new() };
        if user.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: made here; the base's default group.
        unsafe { SRP_user_pwd_set_gN(user, v.default_g, v.default_N) };
        let mut md = ptr::null_mut();
        let mut ctxt = ptr::null_mut();
        let ok = 'm: {
            // SAFETY: the user; the caller's string.
            if unsafe { SRP_user_pwd_set1_ids(user, username, ptr::null()) } == 0 {
                break 'm false;
            }
            let mut digv = [0u8; SHA_LEN];
            let mut digs = [0u8; SHA_LEN];
            // SAFETY: the room.
            if unsafe { RAND_priv_bytes(digv.as_mut_ptr(), SHA_DIGEST_LENGTH) } <= 0 {
                break 'm false;
            }
            // SAFETY: a static name.
            md = unsafe { EVP_MD_fetch(ptr::null_mut(), SN_sha1.as_ptr(), ptr::null()) };
            if md.is_null() {
                break 'm false;
            }
            // SAFETY: no preconditions.
            ctxt = unsafe { EVP_MD_CTX_new() };
            // SAFETY: the base's key, a string.
            let key = unsafe { CStr::from_ptr(v.seed_key) }.to_bytes();
            // SAFETY: the caller's name, a string.
            let name = unsafe { CStr::from_ptr(username) }.to_bytes();
            let hashed = !ctxt.is_null()
                // SAFETY: the context; the digest.
                && unsafe { EVP_DigestInit_ex(ctxt, md, ptr::null_mut()) } != 0
                // SAFETY: as above; the key.
                && unsafe { EVP_DigestUpdate(ctxt, key.as_ptr().cast(), key.len()) } != 0
                // SAFETY: as above; the name.
                && unsafe { EVP_DigestUpdate(ctxt, name.as_ptr().cast(), name.len()) } != 0
                // SAFETY: as above; the room.
                && unsafe { EVP_DigestFinal_ex(ctxt, digs.as_mut_ptr(), ptr::null_mut()) } != 0;
            if !hashed {
                break 'm false;
            }
            // SAFETY: the user; new numbers, taken.
            (unsafe { SRP_user_pwd_set0_sv(user, bn_of(&digs), bn_of(&digv)) }) != 0
        };
        // SAFETY: made here, or NULL.
        unsafe { EVP_MD_free(md) };
        // SAFETY: as above.
        unsafe { EVP_MD_CTX_free(ctxt) };
        if ok {
            return user;
        }
        // SAFETY: made here.
        unsafe { SRP_user_pwd_free(user) };
        ptr::null_mut()
    }
}

ffi_export! {
    /// A verifier for `user` and `pass` in group (`N`, `g`) given as SRP base64 strings, or the
    /// known group of id `g` when `N` is NULL: `*verifier` (and `*salt`, random, if it was NULL)
    /// as new SRP base64 strings; returns "*" or the known group's id, or NULL on failure.
    ///
    /// # Safety
    /// `user` and `pass` NULL or strings; `salt` and `verifier` NULL or slots (`*salt` NULL or a
    /// string); `N` and `g` NULL or strings; `libctx` NULL or live; `propq` NULL or a string.
    pub unsafe extern "C" fn SRP_create_verifier_ex(user: *const c_char, pass: *const c_char, salt: *mut *mut c_char, verifier: *mut *mut c_char, N: *const c_char, g: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        if user.is_null() || pass.is_null() || salt.is_null() || verifier.is_null() {
            return ptr::null_mut();
        }
        let mut n_alloc: *mut BIGNUM = ptr::null_mut();
        let mut g_alloc: *mut BIGNUM = ptr::null_mut();
        let mut s: *mut BIGNUM = ptr::null_mut();
        let mut v: *mut BIGNUM = ptr::null_mut();
        let result = 'r: {
            let (n_bn, g_bn, id): (*const BIGNUM, *const BIGNUM, *mut c_char) = if N.is_null() {
                // SAFETY: the caller's string, or NULL.
                let k = unsafe { SRP_get_default_gN(g) };
                // SAFETY: a static entry, or NULL.
                let Some(k) = (unsafe { k.as_ref() }) else { break 'r ptr::null_mut() };
                (k.N, k.g, k.id)
            } else {
                // SAFETY: the caller's string.
                let nt = unsafe { CStr::from_ptr(N) }.to_bytes();
                let Some(o) = t_fromb64(MAX_LEN, nt).filter(|o| !o.is_empty()) else { break 'r ptr::null_mut() };
                n_alloc = bn_of(&o);
                if n_alloc.is_null() || g.is_null() {
                    break 'r ptr::null_mut();
                }
                // SAFETY: as above.
                let gt = unsafe { CStr::from_ptr(g) }.to_bytes();
                let Some(o) = t_fromb64(MAX_LEN, gt).filter(|o| !o.is_empty()) else { break 'r ptr::null_mut() };
                g_alloc = bn_of(&o);
                if g_alloc.is_null() {
                    break 'r ptr::null_mut();
                }
                (n_alloc, g_alloc, c"*".as_ptr().cast_mut())
            };
            // SAFETY: the caller's slot.
            let given = unsafe { salt.read() };
            let mut tmp2 = [0u8; SRP_RANDOM_SALT_LEN];
            s = if given.is_null() {
                // SAFETY: the room.
                if unsafe { RAND_bytes_ex(libctx, tmp2.as_mut_ptr(), SRP_RANDOM_SALT_LEN, 0) } <= 0 {
                    break 'r ptr::null_mut();
                }
                bn_of(&tmp2)
            } else {
                // SAFETY: the caller's string.
                let st = unsafe { CStr::from_ptr(given) }.to_bytes();
                let Some(o) = t_fromb64(MAX_LEN, st).filter(|o| !o.is_empty()) else { break 'r ptr::null_mut() };
                bn_of(&o)
            };
            if s.is_null() {
                break 'r ptr::null_mut();
            }
            // SAFETY: the strings; the slots for the salt and verifier; the group.
            if unsafe { SRP_create_verifier_BN_ex(user, pass, &raw mut s, &raw mut v, n_bn, g_bn, libctx, propq) } == 0 {
                break 'r ptr::null_mut();
            }
            // SAFETY: the verifier made.
            let vlen = usize::try_from(unsafe { num_bytes(v) }).unwrap_or(0);
            let mut tmp = vec![0u8; vlen];
            // SAFETY: as above; its room.
            if unsafe { BN_bn2bin(v, tmp.as_mut_ptr()) } < 0 {
                break 'r ptr::null_mut();
            }
            let Some(text) = t_tob64(&tmp) else { break 'r ptr::null_mut() };
            let vf = c_string(&text, vlen.saturating_mul(2));
            if vf.is_null() {
                break 'r ptr::null_mut();
            }
            if given.is_null() {
                let Some(st) = t_tob64(&tmp2) else {
                    // SAFETY: made here.
                    unsafe { mem::release_clean(vf.cast(), text.len()) };
                    break 'r ptr::null_mut();
                };
                let ts = c_string(&st, SRP_RANDOM_SALT_LEN * 2);
                if ts.is_null() {
                    // SAFETY: as above.
                    unsafe { mem::release_clean(vf.cast(), text.len()) };
                    break 'r ptr::null_mut();
                }
                // SAFETY: the caller's slot.
                unsafe { salt.write(ts) };
            }
            // SAFETY: as above.
            unsafe { verifier.write(vf) };
            id
        };
        // SAFETY: made here, or NULL.
        unsafe { BN_free(n_alloc) };
        // SAFETY: as above.
        unsafe { BN_free(g_alloc) };
        // SAFETY: as above.
        unsafe { BN_clear_free(s) };
        // SAFETY: as above.
        unsafe { BN_clear_free(v) };
        result
    }
}

ffi_export! {
    /// `SRP_create_verifier_ex` in the default library context.
    ///
    /// # Safety
    /// As for `SRP_create_verifier_ex`.
    pub unsafe extern "C" fn SRP_create_verifier(user: *const c_char, pass: *const c_char, salt: *mut *mut c_char, verifier: *mut *mut c_char, N: *const c_char, g: *const c_char) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SRP_create_verifier_ex(user, pass, salt, verifier, N, g, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The verifier v = g^x mod N for `user` and `pass` with `*salt` (a random one, set in
    /// `*salt`, if NULL), set in `*verifier`: 1, or 0.
    ///
    /// # Safety
    /// `user` and `pass` NULL or strings; `salt` and `verifier` NULL or slots (`*salt` NULL or
    /// live); `N` and `g` NULL or live; `libctx` NULL or live; `propq` NULL or a string.
    pub unsafe extern "C" fn SRP_create_verifier_BN_ex(user: *const c_char, pass: *const c_char, salt: *mut *mut BIGNUM, verifier: *mut *mut BIGNUM, N: *const BIGNUM, g: *const BIGNUM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's context, NULL or live.
        let bn_ctx = unsafe { BN_CTX_new_ex(libctx) };
        let mut x: *mut BIGNUM = ptr::null_mut();
        let mut salttmp: *mut BIGNUM = ptr::null_mut();
        let result = 'r: {
            if user.is_null() || pass.is_null() || salt.is_null() || verifier.is_null() || N.is_null() || g.is_null() || bn_ctx.is_null() {
                break 'r 0;
            }
            // SAFETY: the caller's slot.
            let given = unsafe { salt.read() };
            if given.is_null() {
                let mut tmp2 = [0u8; SRP_RANDOM_SALT_LEN];
                // SAFETY: the room.
                if unsafe { RAND_bytes_ex(libctx, tmp2.as_mut_ptr(), SRP_RANDOM_SALT_LEN, 0) } <= 0 {
                    break 'r 0;
                }
                salttmp = bn_of(&tmp2);
                if salttmp.is_null() {
                    break 'r 0;
                }
            } else {
                salttmp = given;
            }
            // SAFETY: the salt; the caller's strings and context.
            x = unsafe { SRP_Calc_x_ex(salttmp, user, pass, libctx, propq) };
            if x.is_null() {
                break 'r 0;
            }
            // SAFETY: the context; the caller's group.
            let verif = computed(|r| unsafe { BN_mod_exp(r, g, x, N, bn_ctx) } != 0);
            if verif.is_null() {
                break 'r 0;
            }
            // SAFETY: the caller's slots.
            unsafe { salt.write(salttmp) };
            // SAFETY: as above.
            unsafe { verifier.write(verif) };
            1
        };
        // SAFETY: a salt made here and not handed out is freed (not the caller's own).
        if !salt.is_null() && unsafe { salt.read() } != salttmp {
            // SAFETY: made here.
            unsafe { BN_clear_free(salttmp) };
        }
        // SAFETY: made here, or NULL.
        unsafe { BN_clear_free(x) };
        // SAFETY: as above.
        unsafe { BN_CTX_free(bn_ctx) };
        result
    }
}

ffi_export! {
    /// `SRP_create_verifier_BN_ex` in the default library context.
    ///
    /// # Safety
    /// As for `SRP_create_verifier_BN_ex`.
    pub unsafe extern "C" fn SRP_create_verifier_BN(user: *const c_char, pass: *const c_char, salt: *mut *mut BIGNUM, verifier: *mut *mut BIGNUM, N: *const BIGNUM, g: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_CRYPTO
    {
        // SAFETY: the caller's guarantee.
        unsafe { SRP_create_verifier_BN_ex(user, pass, salt, verifier, N, g, ptr::null_mut(), ptr::null()) }
    }
}

#[cfg(test)]
mod tests {
    use super::{t_fromb64, t_tob64};

    #[test]
    fn base64_round_trips_without_padding() {
        for n in 1..10u8 {
            let data: Vec<u8> = (1..=n).collect();
            let text = t_tob64(&data).unwrap_or_default();
            assert!(!text.contains(&b'='));
            assert_eq!(t_fromb64(2500, &text), Some(data));
        }
        assert_eq!(t_tob64(&[]), None);
    }

    #[test]
    fn decoding_refuses_what_doesnt_fit() {
        assert_eq!(t_fromb64(2, b"AAAA"), None);
        assert_eq!(t_fromb64(10, b"A"), None);
    }
}
