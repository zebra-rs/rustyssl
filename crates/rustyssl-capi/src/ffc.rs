//! Finite-field cryptography's domain parameters (`FFC_PARAMS`; `crypto/ffc/`), shared by DH
//! and DSA: `p`, `q`, `g` and their generation record (seed, counter, `h`, the canonical
//! generator's index), the named group they are (cached), and the validation flags.
//!
//! Generation and verification follow FIPS 186-4 (A.1.1.2 and A.1.1.3 for `p` and `q`, A.2.1
//! and A.2.3 for `g`) and, for legacy parameters, FIPS 186-2, as `ffc_params_generate.c` runs
//! them: the same digests (named, or chosen by `N`), seeds drawn from the public generator, the
//! same primality tests, and the same progress callbacks, so a given seed gives the reference's
//! parameters. The results and check bits are OpenSSL's (`FFC_CHECK_*`, `FFC_ERROR_*`).

use core::ffi::{CStr, c_int, c_uint};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    DH_R_BAD_FFC_PARAMETERS, DH_R_NOT_SUITABLE_GENERATOR, DSA_R_BAD_FFC_PARAMETERS,
    DSA_R_P_NOT_PRIME, DSA_R_Q_NOT_PRIME, ERR_LIB_DH, ERR_LIB_DSA, OSSL_LIB_CTX,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian};
use rustyssl_crypto::ffc::{self, NamedGroup};

use crate::err;
use crate::rand_lib::RAND_bytes_ex;
use crate::rsa::Md;
use crate::rsa_gen::Env;
use rustyssl_crypto::rsa::Hash;

/// `FFC_UNVERIFIABLE_GINDEX`.
pub(crate) const UNVERIFIABLE_GINDEX: c_int = -1;

/// `FFC_PARAM_TYPE_*`: whose parameters, for the errors and the `L`, `N` rules.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Type {
    Dsa,
    Dh,
}

/// `FFC_PARAM_FLAG_*`.
pub(crate) const VALIDATE_PQ: c_uint = 0x01;
pub(crate) const VALIDATE_G: c_uint = 0x02;
pub(crate) const VALIDATE_PQG: c_uint = VALIDATE_PQ | VALIDATE_G;
pub(crate) const VALIDATE_LEGACY: c_uint = 0x04;

/// `FFC_CHECK_*` (`internal/ffc.h`; the low bits are `DH_CHECK_*`'s).
pub(crate) const CHECK_P_NOT_PRIME: c_int = 0x00001;
pub(crate) const CHECK_P_NOT_SAFE_PRIME: c_int = 0x00002;
pub(crate) const CHECK_UNKNOWN_GENERATOR: c_int = 0x00004;
pub(crate) const CHECK_NOT_SUITABLE_GENERATOR: c_int = 0x00008;
pub(crate) const CHECK_Q_NOT_PRIME: c_int = 0x00010;
pub(crate) const CHECK_INVALID_Q_VALUE: c_int = 0x00020;
pub(crate) const CHECK_INVALID_J_VALUE: c_int = 0x00040;
pub(crate) const CHECK_MISSING_SEED_OR_COUNTER: c_int = 0x00200;
pub(crate) const CHECK_INVALID_G: c_int = 0x00400;
pub(crate) const CHECK_INVALID_PQ: c_int = 0x00800;
pub(crate) const CHECK_INVALID_COUNTER: c_int = 0x01000;
pub(crate) const CHECK_P_MISMATCH: c_int = 0x02000;
pub(crate) const CHECK_Q_MISMATCH: c_int = 0x04000;
pub(crate) const CHECK_G_MISMATCH: c_int = 0x08000;
pub(crate) const CHECK_COUNTER_MISMATCH: c_int = 0x10000;
pub(crate) const CHECK_BAD_LN_PAIR: c_int = 0x20000;
pub(crate) const CHECK_INVALID_SEED_SIZE: c_int = 0x40000;

/// `FFC_ERROR_*` (public and private key checks; `FFC_ERROR_NOT_SUITABLE_GENERATOR` is
/// `FFC_CHECK_NOT_SUITABLE_GENERATOR`).
pub(crate) const ERROR_PUBKEY_TOO_SMALL: c_int = 0x01;
pub(crate) const ERROR_PUBKEY_TOO_LARGE: c_int = 0x02;
pub(crate) const ERROR_PUBKEY_INVALID: c_int = 0x04;
pub(crate) const ERROR_NOT_SUITABLE_GENERATOR: c_int = 0x08;
pub(crate) const ERROR_PRIVKEY_TOO_SMALL: c_int = 0x10;
pub(crate) const ERROR_PRIVKEY_TOO_LARGE: c_int = 0x20;
pub(crate) const ERROR_PASSED_NULL_PARAM: c_int = 0x40;

/// `FFC_PARAM_RET_STATUS_*`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Status {
    Failed,
    Success,
    UnverifiableG,
}

/// `FFC_PARAMS`.
#[derive(Clone, Debug)]
pub(crate) struct Params {
    pub(crate) p: Option<BigNum>,
    pub(crate) q: Option<BigNum>,
    pub(crate) g: Option<BigNum>,
    /// The cofactor `j`, kept for X9.42's encoding.
    pub(crate) j: Option<BigNum>,
    pub(crate) seed: Option<Vec<u8>>,
    /// The canonical generator's index, or [`UNVERIFIABLE_GINDEX`].
    pub(crate) gindex: c_int,
    /// The counter `p` was found at, or -1.
    pub(crate) pcounter: c_int,
    /// The `h` an unverifiable `g` was made from.
    pub(crate) h: c_int,
    pub(crate) flags: c_uint,
    /// The named group's NID (or RFC 5114's 1 to 3), cached; `NID_undef` for none.
    pub(crate) nid: c_int,
    /// The default private key length (a named group's).
    pub(crate) keylength: c_int,
    pub(crate) mdname: Option<CString>,
    pub(crate) mdprops: Option<CString>,
}

impl Default for Params {
    /// `ossl_ffc_params_init`.
    fn default() -> Self {
        Self {
            p: None,
            q: None,
            g: None,
            j: None,
            seed: None,
            gindex: UNVERIFIABLE_GINDEX,
            pcounter: -1,
            h: 0,
            flags: VALIDATE_PQG,
            nid: 0,
            keylength: 0,
            mdname: None,
            mdprops: None,
        }
    }
}

impl Params {
    /// `ossl_ffc_named_group_set`: the group's numbers and key length (the NID flushed; the
    /// caller caches it).
    pub(crate) fn set_named_group(&mut self, group: &NamedGroup) {
        self.p = Some(group.p.clone());
        self.q = Some(group.q.clone());
        self.g = Some(group.g.clone());
        self.keylength = group.keylength;
        self.nid = 0;
    }

    /// `ossl_ffc_params_cmp`: `p`, `g`, and (unless ignored) `q` equal (missing ones equal
    /// only each other).
    pub(crate) fn cmp(&self, other: &Self, ignore_q: bool) -> bool {
        let eq = |a: &Option<BigNum>, b: &Option<BigNum>| match (a, b) {
            (Some(a), Some(b)) => core_bn::cmp(a, b).is_eq(),
            (None, None) => true,
            _ => false,
        };
        eq(&self.p, &other.p) && eq(&self.g, &other.g) && (ignore_q || eq(&self.q, &other.q))
    }

    /// `ossl_ffc_params_set_validate_params`.
    pub(crate) fn set_validate_params(&mut self, seed: Option<&[u8]>, counter: c_int) {
        self.seed = seed.filter(|s| !s.is_empty()).map(<[u8]>::to_vec);
        self.pcounter = counter;
    }
}

/// The named group of these numbers (`ossl_ffc_numbers_to_dh_named_group`).
pub(crate) fn named_group(
    p: &BigNum,
    q: Option<&BigNum>,
    g: &BigNum,
) -> Option<&'static NamedGroup> {
    ffc::by_numbers(p, q, g)
}

/// Raises `reason` in the type's library.
fn raise(ty: Type, dh: c_int, dsa: c_int, f: &str) {
    match ty {
        Type::Dh => err::raise(ERR_LIB_DH, dh, f),
        Type::Dsa => err::raise(ERR_LIB_DSA, dsa, f),
    }
}

/// `ffc_validate_LN` (outside the FIPS module): the security strength of `L`, `N`, or 0 with
/// the type's error.
fn validate_ln(l: usize, n: usize, ty: Type) -> u32 {
    const F: &str = "ffc_validate_LN";
    match ty {
        Type::Dh => {
            if l == 1024 && n == 160 {
                return 80;
            }
            if l == 2048 && (n == 224 || n == 256) {
                return 112;
            }
            err::raise(ERR_LIB_DH, DH_R_BAD_FFC_PARAMETERS, F);
        }
        Type::Dsa => {
            if n > 512 {
                err::raise_with_text(
                    ERR_LIB_DSA,
                    DSA_R_BAD_FFC_PARAMETERS,
                    F,
                    &format!("N is {n}, but the maximum supported N is 512"),
                );
                return 0;
            }
            if l >= 3072 && n >= 256 {
                return 128;
            }
            if l >= 2048 && n >= 224 {
                return 112;
            }
            if l >= 1024 && n >= 160 {
                return 80;
            }
            err::raise(ERR_LIB_DSA, DSA_R_BAD_FFC_PARAMETERS, F);
        }
    }
    0
}

/// `default_mdname`.
fn default_mdname(n: usize) -> Option<&'static CStr> {
    match n {
        160 => Some(c"SHA1"),
        224 => Some(c"SHA-224"),
        256 => Some(c"SHA-256"),
        _ => None,
    }
}

/// The digest of the parts.
fn digest(md: &Md, parts: &[&[u8]]) -> Option<Vec<u8>> {
    md.digest(parts)
}

/// `a ^ e mod m`.
fn mod_exp(a: &BigNum, e: &BigNum, m: &BigNum) -> Option<BigNum> {
    core_bn::modular::exp_mod(a, e, m).ok()
}

/// `generate_unverifiable_g` (FIPS 186-4 A.2.1): `h^e mod p` for the first `h` from 2 giving
/// more than 1; `g` and `h`.
fn unverifiable_g(p: &BigNum, e: &BigNum, pm1: &BigNum) -> Option<(BigNum, c_int)> {
    let mut h = BigNum::from_word(2);
    let mut hret: c_int = 2;
    loop {
        let g = mod_exp(&h, e, p)?;
        if core_bn::cmp(&g, &BigNum::one()).is_gt() {
            return Some((g, hret));
        }
        h.add_word(1).ok()?;
        if core_bn::cmp(&h, pm1).is_ge() {
            return None;
        }
        hret = hret.saturating_add(1);
    }
}

/// `generate_canonical_g` (FIPS 186-4 A.2.3): `Hash(seed || "ggen" || index || counter)^e mod p`
/// for the first counter giving more than 1.
fn canonical_g(md: &Md, p: &BigNum, e: &BigNum, gindex: c_int, seed: &[u8]) -> Option<BigNum> {
    let index = (gindex & 0xff).to_be_bytes();
    let index = index.last().copied().unwrap_or(0);
    for counter in 1u16..=0xFFFF {
        let [hi, lo] = counter.to_be_bytes();
        let w = digest(md, &[seed, b"ggen", &[index, hi, lo]])?;
        let w = BigNum::from_bin(&w, Endian::Big, false).ok()?;
        let g = mod_exp(&w, e, p)?;
        if core_bn::cmp(&g, &BigNum::one()).is_gt() {
            return Some(g);
        }
    }
    None
}

/// `ossl_ffc_params_validate_unverifiable_g` (FIPS 186-4 A.2.2): `2 <= g <= p - 1` and
/// `g^q mod p = 1`, else `FFC_ERROR_NOT_SUITABLE_GENERATOR`.
pub(crate) fn validate_unverifiable_g(p: &BigNum, q: &BigNum, g: &BigNum, res: &mut c_int) -> bool {
    if core_bn::cmp(g, &BigNum::one()).is_le() || core_bn::cmp(g, p).is_ge() {
        *res |= ERROR_NOT_SUITABLE_GENERATOR;
        return false;
    }
    let Some(t) = mod_exp(g, q, p) else {
        return false;
    };
    if !t.is_one() {
        *res |= ERROR_NOT_SUITABLE_GENERATOR;
        return false;
    }
    true
}

/// Increments a big-endian number in place, wrapping.
fn increment(buf: &mut [u8]) {
    for b in buf.iter_mut().rev() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

/// What `generate_p` found: `p` and its counter, none within the counter (`res` noted), or a
/// failure.
enum PResult {
    Found(BigNum, c_int),
    NotFound,
    Failed,
}

/// `generate_p` (FIPS 186-4 A.1.1.2 steps 10-11, and FIPS 186-2): from `buf` (`seed + offset
/// - 1`), the first prime `p = X - (X mod 2q - 1)` within `max_counter`.
#[expect(
    clippy::too_many_arguments,
    reason = "the generation's state, as OpenSSL passes it"
)]
fn generate_p(
    env: &Env,
    md: &Md,
    max_counter: c_int,
    n: usize,
    buf: &mut [u8],
    q: &BigNum,
    l: usize,
    res: &mut c_int,
) -> PResult {
    let Ok(test) = core_bn::lshift(&BigNum::one(), l.saturating_sub(1)) else {
        return PResult::Failed;
    };
    let mdbits = md.size().saturating_mul(8);
    let Ok(twoq) = core_bn::lshift1(q) else {
        return PResult::Failed;
    };
    for i in 0..=max_counter {
        if i != 0 && !env.call(0, i) {
            return PResult::Failed;
        }
        let mut w = BigNum::zero();
        for j in 0..=n {
            increment(buf);
            let Some(v) = digest(md, &[buf]) else {
                return PResult::Failed;
            };
            let Ok(v) = BigNum::from_bin(&v, Endian::Big, false) else {
                return PResult::Failed;
            };
            let Ok(v) = core_bn::lshift(&v, mdbits.saturating_mul(j)) else {
                return PResult::Failed;
            };
            let Ok(sum) = core_bn::add(&w, &v) else {
                return PResult::Failed;
            };
            w = sum;
        }
        w.mask_bits(l.saturating_sub(1));
        let Ok(x) = core_bn::add(&w, &test) else {
            return PResult::Failed;
        };
        let Ok((_, c)) = core_bn::div_rem(&x, &twoq) else {
            return PResult::Failed;
        };
        let mut cm1 = c;
        if cm1.sub_word(1).is_err() {
            return PResult::Failed;
        }
        let Ok(p) = core_bn::sub(&x, &cm1) else {
            return PResult::Failed;
        };
        if core_bn::cmp(&p, &test).is_ge() {
            match env.check_prime_cb(&p) {
                r if r > 0 => return PResult::Found(p, i),
                0 => {}
                _ => return PResult::Failed,
            }
        }
    }
    *res |= CHECK_P_NOT_PRIME;
    PResult::NotFound
}

/// `generate_q_fips186_4` (A.1.1.2 steps 5-9): `q` from `Hash(seed)`, drawing new seeds until
/// it's prime (or failing with a given seed); `m` counts the attempts.
#[expect(
    clippy::too_many_arguments,
    reason = "the generation's state, as OpenSSL passes it"
)]
fn generate_q_186_4(
    env: &Env,
    libctx: *mut OSSL_LIB_CTX,
    md: &Md,
    qsize: usize,
    seed: &mut [u8],
    generate_seed: bool,
    m: &mut c_int,
    res: &mut c_int,
) -> Option<BigNum> {
    let mdsize = md.size();
    loop {
        let go = env.call(0, *m);
        *m = m.saturating_add(1);
        if !go {
            return None;
        }
        // SAFETY: the library context; room for the seed.
        if generate_seed && unsafe { RAND_bytes_ex(libctx, seed.as_mut_ptr(), seed.len(), 0) } <= 0
        {
            return None;
        }
        let h = digest(md, &[seed])?;
        let mut u = vec![0u8; qsize.max(mdsize)];
        if mdsize > qsize {
            u.copy_from_slice(&h);
            u.drain(..mdsize.saturating_sub(qsize));
        } else if let Some(dst) = u.get_mut(..mdsize) {
            dst.copy_from_slice(&h);
        }
        u.truncate(qsize);
        if let Some(b) = u.first_mut() {
            *b |= 0x80;
        }
        if let Some(b) = u.last_mut() {
            *b |= 0x01;
        }
        let q = BigNum::from_bin(&u, Endian::Big, false).ok()?;
        let r = env.check_prime_cb(&q);
        if r > 0 {
            return Some(q);
        }
        if !generate_seed {
            *res |= CHECK_Q_NOT_PRIME;
            return None;
        }
        if r != 0 {
            return None;
        }
    }
}

/// `generate_q_fips186_2`: `q` from `Hash(seed) ^ Hash(seed + 1)`, with `buf` left as
/// `seed + 1` for `p`'s generation.
fn generate_q_186_2(
    env: &Env,
    libctx: *mut OSSL_LIB_CTX,
    md: &Md,
    buf: &mut [u8],
    seed: &mut [u8],
    mut generate_seed: bool,
    m: &mut c_int,
) -> Option<BigNum> {
    loop {
        let go = env.call(0, *m);
        *m = m.saturating_add(1);
        if !go {
            return None;
        }
        // SAFETY: the library context; room for the seed.
        if generate_seed && unsafe { RAND_bytes_ex(libctx, seed.as_mut_ptr(), seed.len(), 0) } <= 0
        {
            return None;
        }
        buf.copy_from_slice(seed);
        increment(buf);
        let a = digest(md, &[seed])?;
        let b = digest(md, &[buf])?;
        let mut u: Vec<u8> = a
            .iter()
            .zip(&b)
            .map(|(x, y)| x ^ y)
            .take(seed.len())
            .collect();
        if let Some(b) = u.first_mut() {
            *b |= 0x80;
        }
        if let Some(b) = u.last_mut() {
            *b |= 0x01;
        }
        let q = BigNum::from_bin(&u, Endian::Big, false).ok()?;
        let r = env.check_prime_cb(&q);
        if r > 0 {
            return Some(q);
        }
        if r != 0 {
            return None;
        }
        generate_seed = true;
    }
}

/// The digest for generation or verification: the parameters' named one, else the default
/// for `N` (or, with no `N`, for `L`); `N` filled in from it.
///
/// # Safety
/// `libctx` is NULL or a live library context.
unsafe fn choose_md(
    libctx: *mut OSSL_LIB_CTX,
    params: &Params,
    l: usize,
    n: &mut usize,
    res: &mut c_int,
) -> Option<Md> {
    let props = params.mdprops.as_deref().map_or(ptr::null(), CStr::as_ptr);
    let md = if let Some(name) = params.mdname.as_deref() {
        // SAFETY: the caller's guarantee; strings.
        unsafe { Md::fetch(libctx, name, props) }
    } else {
        if *n == 0 {
            *n = if l >= 2048 { 256 } else { 160 };
        }
        let Some(name) = default_mdname(*n) else {
            *res = CHECK_INVALID_Q_VALUE;
            return None;
        };
        // SAFETY: as above.
        unsafe { Md::fetch(libctx, name, props) }
    }?;
    if md.size() == 0 {
        return None;
    }
    if *n == 0 {
        *n = md.size().saturating_mul(8);
    }
    Some(md)
}

/// `ossl_ffc_params_FIPS186_4_gen_verify`: generates parameters into `params` (`verify`
/// false), or verifies them against their seed, counter, and index (as `params.flags` say).
///
/// # Safety
/// `libctx` is NULL or a live library context; `env` reports to a live callback.
#[expect(
    clippy::too_many_arguments,
    reason = "the generation's inputs, as OpenSSL passes them"
)]
pub(crate) unsafe fn gen_verify_186_4(
    libctx: *mut OSSL_LIB_CTX,
    env: &Env,
    params: &mut Params,
    verify: bool,
    ty: Type,
    l: usize,
    n: usize,
    res: &mut c_int,
) -> Status {
    *res = 0;
    let flags = if verify { params.flags } else { 0 };
    let mut n = n;
    // SAFETY: the caller's guarantee.
    let Some(md) = (unsafe { choose_md(libctx, params, l, &mut n, res) }) else {
        return Status::Failed;
    };
    let mdsize = md.size();
    let qsize = n / 8;
    if l <= n || validate_ln(l, n, ty) == 0 {
        *res = CHECK_BAD_LN_PAIR;
        return Status::Failed;
    }
    let mut seedlen = params.seed.as_ref().map_or(0, Vec::len);
    if seedlen == 0 {
        seedlen = mdsize;
    }
    let given_seed = params.seed.is_some();
    if !verify {
        if params.p.is_none() != params.q.is_none() {
            *res = CHECK_INVALID_PQ;
            return Status::Failed;
        }
    } else {
        if flags & VALIDATE_PQ != 0 && (!given_seed || params.pcounter < 0) {
            *res = CHECK_MISSING_SEED_OR_COUNTER;
            return Status::Failed;
        }
        if flags & VALIDATE_G != 0 && params.g.is_none() {
            *res = CHECK_INVALID_G;
            return Status::Failed;
        }
    }

    let mut seed: Option<Vec<u8>> = params.seed.clone();
    let mut found_pcounter = 0;
    let (p, q) = match (&params.p, &params.q) {
        (Some(p), Some(q)) if flags & VALIDATE_PQ == 0 => (p.clone(), q.clone()),
        _ => {
            if seedlen.saturating_mul(8) < n {
                *res = CHECK_INVALID_SEED_SIZE;
                return Status::Failed;
            }
            if seed.is_none() {
                if verify {
                    *res = CHECK_MISSING_SEED_OR_COUNTER;
                    return Status::Failed;
                }
                seed = Some(vec![0u8; seedlen]);
            }
            let Some(seed) = seed.as_mut() else {
                return Status::Failed;
            };
            let mut counter =
                c_int::try_from(l.saturating_mul(4).saturating_sub(1)).unwrap_or(c_int::MAX);
            if verify {
                if params.pcounter > counter {
                    *res = CHECK_INVALID_COUNTER;
                    return Status::Failed;
                }
                counter = params.pcounter;
            }
            let nn = l.saturating_sub(1) / mdsize.saturating_mul(8).max(1);
            let mut m = 0;
            let found = loop {
                let Some(q) =
                    generate_q_186_4(env, libctx, &md, qsize, seed, !given_seed, &mut m, res)
                else {
                    return Status::Failed;
                };
                if verify
                    && params
                        .q
                        .as_ref()
                        .is_none_or(|pq| !core_bn::cmp(&q, pq).is_eq())
                {
                    *res = CHECK_Q_MISMATCH;
                    return Status::Failed;
                }
                if !env.call(2, 0) || !env.call(3, 0) {
                    return Status::Failed;
                }
                let mut tmp = seed.clone();
                match generate_p(env, &md, counter, nn, &mut tmp, &q, l, res) {
                    PResult::Found(p, i) => break (p, q, i),
                    PResult::Failed => return Status::Failed,
                    PResult::NotFound => {
                        if given_seed {
                            *res = CHECK_P_NOT_PRIME;
                            return Status::Failed;
                        }
                    }
                }
            };
            if !env.call(2, 1) {
                return Status::Failed;
            }
            let (p, q, pcounter) = found;
            if verify
                && (pcounter != counter
                    || params
                        .p
                        .as_ref()
                        .is_none_or(|pp| !core_bn::cmp(&p, pp).is_eq()))
            {
                return Status::Failed;
            }
            found_pcounter = pcounter;
            if flags & VALIDATE_PQG == VALIDATE_PQ {
                return finish(flags, false);
            }
            (p, q)
        }
    };

    // g.
    if flags & VALIDATE_G != 0 {
        let Some(g) = params.g.as_ref() else {
            return Status::Failed;
        };
        if !validate_unverifiable_g(&p, &q, g, res) {
            return Status::Failed;
        }
    }
    let mut pm1 = p.clone();
    if pm1.sub_word(1).is_err() {
        return Status::Failed;
    }
    let Some((e, _)) = env.div(&pm1, &q) else {
        return Status::Failed;
    };
    let mut canonical = false;
    let mut g_out = None;
    let mut hret = 0;
    if let Some(s) = seed
        .as_ref()
        .filter(|_| params.gindex != UNVERIFIABLE_GINDEX)
    {
        canonical = true;
        let Some(g) = canonical_g(&md, &p, &e, params.gindex, s) else {
            *res = CHECK_INVALID_G;
            return Status::Failed;
        };
        if verify
            && params
                .g
                .as_ref()
                .is_none_or(|pg| !core_bn::cmp(&g, pg).is_eq())
        {
            *res = CHECK_G_MISMATCH;
            return Status::Failed;
        }
        g_out = Some(g);
    } else if !verify {
        let Some((g, h)) = unverifiable_g(&p, &e, &pm1) else {
            return Status::Failed;
        };
        g_out = Some(g);
        hret = h;
    }
    if !env.call(3, 1) {
        return Status::Failed;
    }
    if !verify {
        params.p = Some(p);
        params.q = Some(q);
        params.g = g_out;
        params.set_validate_params(seed.as_deref(), found_pcounter);
        params.h = hret;
    }
    finish(flags, canonical)
}

/// The result of a generation or verification that got through.
fn finish(flags: c_uint, canonical: bool) -> Status {
    if flags & VALIDATE_G != 0 && !canonical {
        Status::UnverifiableG
    } else {
        Status::Success
    }
}

/// `ossl_ffc_params_FIPS186_2_gen_verify`.
///
/// # Safety
/// As for [`gen_verify_186_4`].
#[expect(
    clippy::too_many_arguments,
    reason = "the generation's inputs, as OpenSSL passes them"
)]
pub(crate) unsafe fn gen_verify_186_2(
    libctx: *mut OSSL_LIB_CTX,
    env: &Env,
    params: &mut Params,
    verify: bool,
    _ty: Type,
    l: usize,
    n: usize,
    res: &mut c_int,
) -> Status {
    *res = 0;
    let flags = if verify { params.flags } else { 0 };
    let mut n = n;
    // SAFETY: the caller's guarantee.
    let Some(md) = (unsafe { choose_md(libctx, params, l, &mut n, res) }) else {
        return Status::Failed;
    };
    let qsize = n / 8;
    if l < 512 {
        *res = CHECK_BAD_LN_PAIR;
        return Status::Failed;
    }
    if qsize != 20 && qsize != 28 && qsize != 32 {
        *res = CHECK_INVALID_Q_VALUE;
        return Status::Failed;
    }
    let l = l.div_ceil(64).saturating_mul(64);
    let mut seed = vec![0u8; qsize];
    let seed_in = params.seed.clone();
    if let Some(s) = seed_in.as_ref() {
        if s.len() < qsize {
            *res = CHECK_INVALID_SEED_SIZE;
            return Status::Failed;
        }
        seed.copy_from_slice(s.get(..qsize).unwrap_or_default());
    }
    if !verify {
        if params.p.is_some() != params.q.is_some() {
            *res = CHECK_INVALID_PQ;
            return Status::Failed;
        }
    } else {
        if flags & VALIDATE_PQ != 0 && (seed_in.is_none() || params.pcounter < 0) {
            *res = CHECK_MISSING_SEED_OR_COUNTER;
            return Status::Failed;
        }
        if flags & VALIDATE_G != 0 && params.g.is_none() {
            *res = CHECK_INVALID_G;
            return Status::Failed;
        }
    }
    let mut pcounter = 0;
    let (p, q) = match (&params.p, &params.q) {
        (Some(p), Some(q)) if flags & VALIDATE_PQ == 0 => (p.clone(), q.clone()),
        _ => {
            let mut use_random_seed = seed_in.is_none();
            let mut buf = vec![0u8; qsize];
            let mut m = 0;
            let (p, q, counter) = loop {
                let Some(q) = generate_q_186_2(
                    env,
                    libctx,
                    &md,
                    &mut buf,
                    &mut seed,
                    use_random_seed,
                    &mut m,
                ) else {
                    return Status::Failed;
                };
                if !env.call(2, 0) || !env.call(3, 0) {
                    return Status::Failed;
                }
                let nn = l.saturating_sub(1) / 160;
                let mut counter =
                    c_int::try_from(l.saturating_mul(4).saturating_sub(1)).unwrap_or(c_int::MAX);
                if verify {
                    if params.pcounter > counter {
                        *res = CHECK_INVALID_COUNTER;
                        return Status::Failed;
                    }
                    counter = params.pcounter;
                }
                match generate_p(env, &md, counter, nn, &mut buf, &q, l, res) {
                    PResult::Found(p, i) => {
                        pcounter = i;
                        break (p, q, counter);
                    }
                    PResult::Failed => return Status::Failed,
                    PResult::NotFound => use_random_seed = true,
                }
            };
            if !env.call(2, 1) {
                return Status::Failed;
            }
            if verify {
                if pcounter != counter {
                    *res = CHECK_COUNTER_MISMATCH;
                    return Status::Failed;
                }
                if params
                    .p
                    .as_ref()
                    .is_none_or(|pp| !core_bn::cmp(&p, pp).is_eq())
                {
                    *res = CHECK_P_MISMATCH;
                    return Status::Failed;
                }
            }
            if flags & VALIDATE_PQG == VALIDATE_PQ {
                return if flags & VALIDATE_G != 0 {
                    Status::UnverifiableG
                } else {
                    Status::Success
                };
            }
            (p, q)
        }
    };
    let mut g_out = None;
    let mut hret = -1;
    if !verify {
        let mut pm1 = p.clone();
        if pm1.sub_word(1).is_err() {
            return Status::Failed;
        }
        let Some((r0, _)) = env.div(&pm1, &q) else {
            return Status::Failed;
        };
        let Some((g, h)) = unverifiable_g(&p, &r0, &pm1) else {
            return Status::Failed;
        };
        g_out = Some(g);
        hret = h;
    } else if flags & VALIDATE_G != 0 {
        let Some(g) = params.g.as_ref() else {
            return Status::Failed;
        };
        if !validate_unverifiable_g(&p, &q, g, res) {
            return Status::Failed;
        }
    }
    if !env.call(3, 1) {
        return Status::Failed;
    }
    if !verify {
        params.p = Some(p);
        params.q = Some(q);
        params.g = g_out;
        params.set_validate_params(Some(&seed), pcounter);
        params.h = hret;
    }
    if flags & VALIDATE_G != 0 {
        Status::UnverifiableG
    } else {
        Status::Success
    }
}

/// `ossl_ffc_params_FIPS186_4_generate`: 1 (2 for an unverifiable generator), or 0.
///
/// # Safety
/// As for [`gen_verify_186_4`].
pub(crate) unsafe fn generate_186_4(
    libctx: *mut OSSL_LIB_CTX,
    env: &Env,
    params: &mut Params,
    ty: Type,
    l: usize,
    n: usize,
    res: &mut c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    match unsafe { gen_verify_186_4(libctx, env, params, false, ty, l, n, res) } {
        Status::Failed => 0,
        Status::Success => 1,
        Status::UnverifiableG => 2,
    }
}

/// `ossl_ffc_params_FIPS186_2_generate`: 1, the parameters marked for legacy validation, or 0.
///
/// # Safety
/// As for [`gen_verify_186_4`].
pub(crate) unsafe fn generate_186_2(
    libctx: *mut OSSL_LIB_CTX,
    env: &Env,
    params: &mut Params,
    ty: Type,
    l: usize,
    n: usize,
    res: &mut c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if unsafe { gen_verify_186_2(libctx, env, params, false, ty, l, n, res) } == Status::Failed {
        return 0;
    }
    params.flags |= VALIDATE_LEGACY;
    1
}

/// `ossl_ffc_params_FIPS186_4_validate` / `_FIPS186_2_validate`: verification of `p` and `q`
/// as they are (`L` and `N` their sizes).
///
/// # Safety
/// As for [`gen_verify_186_4`].
pub(crate) unsafe fn validate(
    libctx: *mut OSSL_LIB_CTX,
    env: &Env,
    params: &Params,
    ty: Type,
    legacy: bool,
    res: &mut c_int,
) -> Status {
    let (Some(p), Some(q)) = (&params.p, &params.q) else {
        if legacy {
            *res = CHECK_INVALID_PQ;
        }
        return Status::Failed;
    };
    let (l, n) = (p.num_bits(), q.num_bits());
    let mut copy = params.clone();
    if legacy {
        // SAFETY: the caller's guarantee.
        unsafe { gen_verify_186_2(libctx, env, &mut copy, true, ty, l, n, res) }
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { gen_verify_186_4(libctx, env, &mut copy, true, ty, l, n, res) }
    }
}

/// `ossl_ffc_params_simple_validate`: `g` checked against `p` and `q` (with the verifier's
/// digest and `L`, `N` rules), a DH generator that isn't suitable raising its error.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn simple_validate(
    libctx: *mut OSSL_LIB_CTX,
    params: &Params,
    ty: Type,
    res: &mut c_int,
) -> bool {
    // SAFETY: the caller's guarantee; no callback.
    let Some(env) = (unsafe { Env::new(libctx, ptr::null_mut()) }) else {
        return false;
    };
    let mut tmp = params.clone();
    tmp.flags = VALIDATE_G;
    tmp.gindex = UNVERIFIABLE_GINDEX;
    // SAFETY: as above.
    let ret = unsafe {
        validate(
            libctx,
            &env,
            &tmp,
            ty,
            params.flags & VALIDATE_LEGACY != 0,
            res,
        )
    };
    if ret == Status::Failed && *res & ERROR_NOT_SUITABLE_GENERATOR != 0 {
        err::raise(
            ERR_LIB_DH,
            DH_R_NOT_SUITABLE_GENERATOR,
            "ossl_ffc_params_simple_validate",
        );
    }
    ret != Status::Failed
}

/// `ossl_ffc_params_full_validate`: with a seed, the verification it allows; without one, the
/// simple validation and `q` and `p` prime.
///
/// # Safety
/// `libctx` is NULL or a live library context.
pub(crate) unsafe fn full_validate(
    libctx: *mut OSSL_LIB_CTX,
    params: &Params,
    ty: Type,
    res: &mut c_int,
) -> bool {
    // SAFETY: the caller's guarantee; no callback.
    let Some(env) = (unsafe { Env::new(libctx, ptr::null_mut()) }) else {
        return false;
    };
    if params.seed.is_some() {
        // SAFETY: as above.
        return unsafe {
            validate(
                libctx,
                &env,
                params,
                ty,
                params.flags & VALIDATE_LEGACY != 0,
                res,
            )
        } != Status::Failed;
    }
    // SAFETY: as above.
    if !unsafe { simple_validate(libctx, params, ty, res) } {
        return false;
    }
    let (Some(p), Some(q)) = (&params.p, &params.q) else {
        return false;
    };
    if env.check_prime(q) != 1 {
        err::raise(
            ERR_LIB_DSA,
            DSA_R_Q_NOT_PRIME,
            "ossl_ffc_params_full_validate",
        );
        return false;
    }
    if env.check_prime(p) != 1 {
        err::raise(
            ERR_LIB_DSA,
            DSA_R_P_NOT_PRIME,
            "ossl_ffc_params_full_validate",
        );
        return false;
    }
    true
}

/// `ossl_ffc_generate_private_key` (SP 800-56A 5.6.1.1.4): `1 + random[0, 2^N)` below
/// `min(2^N, q)`, `N` the key length given (else the parameters', else `2s`), at least `2s`
/// and at most `q`'s length; `None` if they don't allow it.
pub(crate) fn generate_private_key(
    env: &Env,
    params: &Params,
    n: usize,
    s: usize,
) -> Option<BigNum> {
    let q = params.q.as_ref()?;
    if s == 0 {
        return None;
    }
    let n = if n == 0 {
        usize::try_from(params.keylength)
            .ok()
            .filter(|&k| k != 0)
            .unwrap_or(s.saturating_mul(2))
    } else {
        n
    };
    if n < s.saturating_mul(2) || n > q.num_bits() {
        return None;
    }
    let two_n = core_bn::lshift(&BigNum::one(), n).ok()?;
    let m = if core_bn::cmp(&two_n, q).is_gt() {
        q
    } else {
        &two_n
    };
    loop {
        let mut priv_key = env.rand_range(&two_n)?;
        priv_key.add_word(1).ok()?;
        if core_bn::cmp(&priv_key, m).is_lt() {
            return Some(priv_key);
        }
    }
}

/// `ossl_ffc_validate_public_key_partial`: `2 <= pub <= p - 2` (SP 800-56A 5.6.2.3.1 step 1).
pub(crate) fn validate_public_key_partial(
    params: &Params,
    pub_key: &BigNum,
    res: &mut c_int,
) -> bool {
    *res = 0;
    let Some(p) = params.p.as_ref() else {
        *res = ERROR_PASSED_NULL_PARAM;
        return true;
    };
    if core_bn::cmp(pub_key, &BigNum::one()).is_le() {
        *res |= ERROR_PUBKEY_TOO_SMALL;
    }
    let mut pm1 = p.clone();
    if pm1.sub_word(1).is_err() {
        return false;
    }
    if core_bn::cmp(pub_key, &pm1).is_ge() {
        *res |= ERROR_PUBKEY_TOO_LARGE;
    }
    true
}

/// `ossl_ffc_validate_public_key`: the partial checks, then `pub^q mod p = 1` if `q` is known.
pub(crate) fn validate_public_key(params: &Params, pub_key: &BigNum, res: &mut c_int) -> bool {
    if !validate_public_key_partial(params, pub_key, res) {
        return false;
    }
    if *res == 0
        && let (Some(p), Some(q)) = (&params.p, &params.q)
    {
        let Some(t) = mod_exp(pub_key, q, p) else {
            return false;
        };
        if !t.is_one() {
            *res |= ERROR_PUBKEY_INVALID;
        }
    }
    true
}

/// `ossl_ffc_validate_private_key`: `1 <= priv < upper`.
pub(crate) fn validate_private_key(upper: &BigNum, priv_key: &BigNum, res: &mut c_int) -> bool {
    *res = 0;
    if core_bn::cmp(priv_key, &BigNum::one()).is_lt() {
        *res |= ERROR_PRIVKEY_TOO_SMALL;
        return false;
    }
    if core_bn::cmp(priv_key, upper).is_ge() {
        *res |= ERROR_PRIVKEY_TOO_LARGE;
        return false;
    }
    true
}

/// `ossl_ifc_ffc_compute_security_bits`: the strength of an `n`-bit modulus.
pub(crate) fn ifc_ffc_security_bits(n: usize) -> usize {
    usize::from(rustyssl_crypto::rsa::ifc_ffc_security_bits(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increments_wrap() {
        let mut b = [0x00, 0xff, 0xff];
        increment(&mut b);
        assert_eq!(b, [0x01, 0x00, 0x00]);
        let mut b = [0xff];
        increment(&mut b);
        assert_eq!(b, [0x00]);
    }

    #[test]
    fn ln_pairs() {
        assert_eq!(validate_ln(2048, 256, Type::Dh), 112);
        assert_eq!(validate_ln(1024, 160, Type::Dh), 80);
        assert_eq!(validate_ln(3072, 256, Type::Dsa), 128);
        assert_eq!(validate_ln(1024, 160, Type::Dsa), 80);
        assert_eq!(validate_ln(3072, 256, Type::Dh), 0);
        assert_eq!(validate_ln(512, 160, Type::Dsa), 0);
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
