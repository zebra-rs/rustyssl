//! DH parameter generation, the checks, and the X9.42 KDF (`dh_gen.c`, `dh_check.c`,
//! `dh_kdf.c`, `dh_depr.c`).
//!
//! Generation (outside the FIPS module) is the key's method's, else OpenSSL's built-in one: a
//! safe prime `p` of the bits asked for with `p mod 24 = 23` (generator 2), `p mod 60 = 59`
//! (5), or `p mod 12 = 11` (any other), the generator as given, and RFC 7919's private key
//! length for the prime's strength. The checks follow `dh_check.c` with its flags and errors;
//! a named group's parameters pass `DH_check` unchecked, as in OpenSSL.

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, BIGNUM, BN_GENCB, DH, DH_CHECK_INVALID_J_VALUE, DH_CHECK_INVALID_Q_VALUE,
    DH_CHECK_P_NOT_PRIME, DH_CHECK_P_NOT_SAFE_PRIME, DH_CHECK_PUBKEY_INVALID,
    DH_CHECK_PUBKEY_TOO_LARGE, DH_CHECK_PUBKEY_TOO_SMALL, DH_CHECK_Q_NOT_PRIME, DH_GENERATOR_2,
    DH_GENERATOR_5, DH_MODULUS_TOO_LARGE, DH_MODULUS_TOO_SMALL, DH_NOT_SUITABLE_GENERATOR,
    DH_R_BAD_GENERATOR, DH_R_CHECK_INVALID_J_VALUE, DH_R_CHECK_INVALID_Q_VALUE,
    DH_R_CHECK_P_NOT_PRIME, DH_R_CHECK_P_NOT_SAFE_PRIME, DH_R_CHECK_PUBKEY_INVALID,
    DH_R_CHECK_PUBKEY_TOO_LARGE, DH_R_CHECK_PUBKEY_TOO_SMALL, DH_R_CHECK_Q_NOT_PRIME,
    DH_R_MODULUS_TOO_LARGE, DH_R_MODULUS_TOO_SMALL, DH_R_NOT_SUITABLE_GENERATOR,
    DH_R_UNABLE_TO_CHECK_GENERATOR, DH_UNABLE_TO_CHECK_GENERATOR, ERR_LIB_DH, ERR_R_BN_LIB, EVP_MD,
    OPENSSL_DH_CHECK_MAX_MODULUS_BITS, OPENSSL_DH_MAX_MODULUS_BITS, OSSL_KDF_NAME_X942KDF_ASN1,
    OSSL_KDF_PARAM_CEK_ALG, OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_KEY, OSSL_KDF_PARAM_UKM,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum};

use crate::bn::prime::{BN_GENCB_free, BN_GENCB_new, BN_GENCB_set_old, OldCb};
use crate::bn::value;
use crate::dh::{Dh, dh};
use crate::dh_meth::fns_of;
use crate::err;
use crate::evp::digest::{EVP_MD_get0_name, EVP_MD_get0_provider};
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
};
use crate::ffc;
use crate::ffi::ffi_export;
use crate::objects::OBJ_obj2txt;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
};
use crate::provider::libctx_of;
use crate::rsa_gen::Env;

/// `DH_MIN_MODULUS_BITS`.
const MIN_MODULUS_BITS: usize = 512;

/// `dh_builtin_genparams`.
///
/// # Safety
/// `ret` is a live key; `cb` is NULL or a live `BN_GENCB`.
unsafe fn builtin_genparams(
    ret: *mut DH,
    prime_len: c_int,
    generator: c_int,
    cb: *mut BN_GENCB,
) -> c_int {
    const F: &str = "dh_builtin_genparams";
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { dh(ret) }) else {
        return 0;
    };
    if prime_len > OPENSSL_DH_MAX_MODULUS_BITS {
        err::raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE, F);
        return 0;
    }
    if usize::try_from(prime_len).is_ok_and(|l| l < MIN_MODULUS_BITS) || prime_len < 0 {
        err::raise(ERR_LIB_DH, DH_R_MODULUS_TOO_SMALL, F);
        return 0;
    }
    let mut st = k.snapshot();
    // The key gets its p and g (zero) before anything can fail, as OpenSSL's does.
    if st.params.p.is_none() {
        st.params.p = Some(BigNum::zero());
    }
    if st.params.g.is_none() {
        st.params.g = Some(BigNum::zero());
    }
    k.replace(st.clone());
    let ok = (|| {
        if generator <= 1 {
            err::raise(ERR_LIB_DH, DH_R_BAD_GENERATOR, F);
            return None;
        }
        let (add, rem, g) = match generator {
            DH_GENERATOR_2 => (24, 23, 2),
            DH_GENERATOR_5 => (60, 59, 5),
            g => (12, 11, g),
        };
        // SAFETY: the key's library context; the caller's callback.
        let env = unsafe { Env::new(k.libctx.0, cb) }?;
        let p = env.generate_prime_with(
            usize::try_from(prime_len).ok()?,
            true,
            &BigNum::from_word(add),
            &BigNum::from_word(rem),
        )?;
        if !env.call(3, 0) {
            return None;
        }
        st.params.p = Some(p);
        st.params.g = Some(BigNum::from_word(u64::try_from(g).ok()?));
        let secbits = ffc::ifc_ffc_security_bits(usize::try_from(prime_len).ok()?);
        st.length = i32::try_from(secbits.saturating_mul(2).saturating_add(24) / 25 * 25).ok()?;
        Some(())
    })();
    if ok.is_none() {
        err::raise(ERR_LIB_DH, ERR_R_BN_LIB, F);
        return 0;
    }
    k.replace(st);
    1
}

ffi_export! {
    /// Generates parameters into `ret` with its method's `generate_params`, else OpenSSL's
    /// safe-prime generation. 1, or 0.
    ///
    /// # Safety
    /// `ret` is a live key; `cb` is NULL or a live `BN_GENCB`.
    pub unsafe extern "C" fn DH_generate_parameters_ex(ret: *mut DH, prime_len: c_int, generator: c_int, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dh(ret) }) else { return 0 };
        // SAFETY: the key's method, live.
        if let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.generate_params) {
            // SAFETY: the method's function with the caller's arguments; no lock is held.
            return unsafe { f(ret, prime_len, generator, cb) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { builtin_genparams(ret, prime_len, generator, cb) }
    }
}

ffi_export! {
    /// `DH_generate_parameters_ex` into a new key with an old-style callback (deprecated): the
    /// key, or NULL.
    ///
    /// # Safety
    /// `callback` is called with `cb_arg`.
    pub unsafe extern "C" fn DH_generate_parameters(prime_len: c_int, generator: c_int, callback: Option<OldCb>, cb_arg: *mut c_void) -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        let ret = Dh::new_handle_in(ptr::null_mut());
        if ret.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let cb = unsafe { BN_GENCB_new() };
        if cb.is_null() {
            // SAFETY: made above.
            unsafe { crate::dh::free(ret) };
            return ptr::null_mut();
        }
        // SAFETY: the callback just made; the caller's function and argument.
        unsafe { BN_GENCB_set_old(cb, callback, cb_arg) };
        // SAFETY: the key and callback made above.
        let ok = unsafe { DH_generate_parameters_ex(ret, prime_len, generator, cb) } != 0;
        // SAFETY: made above.
        unsafe { BN_GENCB_free(cb) };
        if ok {
            return ret;
        }
        // SAFETY: as above.
        unsafe { crate::dh::free(ret) };
        ptr::null_mut()
    }
}

/// Writes `v` where `ret` points.
///
/// # Safety
/// `ret` is NULL or writable.
unsafe fn set(ret: *mut c_int, v: c_int) {
    if !ret.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { ret.write(v) };
    }
}

/// The key's state with its numbers, or `None` for NULL.
///
/// # Safety
/// `d` is NULL or a live key.
unsafe fn state(d: *const DH) -> Option<(crate::dh::DhState, *mut rustyssl_abi::OSSL_LIB_CTX)> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { dh(d) }?;
    Some((k.snapshot(), k.libctx.0))
}

/// `DH_check_params` (outside the FIPS module): p odd, `1 < g < p - 1`, and p's size.
fn check_params(st: &crate::dh::DhState) -> c_int {
    let (Some(p), Some(g)) = (&st.params.p, &st.params.g) else {
        return DH_NOT_SUITABLE_GENERATOR | DH_CHECK_P_NOT_PRIME;
    };
    let mut ret = 0;
    if !p.is_odd() {
        ret |= DH_CHECK_P_NOT_PRIME;
    }
    if g.is_negative() || g.is_zero() || g.is_one() {
        ret |= DH_NOT_SUITABLE_GENERATOR;
    }
    let mut pm1 = p.clone();
    let _ = pm1.sub_word(1);
    if core_bn::cmp(g, &pm1).is_ge() {
        ret |= DH_NOT_SUITABLE_GENERATOR;
    }
    let max = usize::try_from(OPENSSL_DH_MAX_MODULUS_BITS).unwrap_or(10000);
    if p.num_bits() < MIN_MODULUS_BITS {
        ret |= DH_MODULUS_TOO_SMALL;
    }
    if p.num_bits() > max {
        ret |= DH_MODULUS_TOO_LARGE;
    }
    ret
}

ffi_export! {
    /// The parameters' basic checks into `*ret` (`DH_CHECK_P_NOT_PRIME`,
    /// `DH_NOT_SUITABLE_GENERATOR`, `DH_MODULUS_TOO_*`). 1.
    ///
    /// # Safety
    /// `dh` is a live key; `ret` is writable.
    pub unsafe extern "C" fn DH_check_params(dh: *const DH, ret: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some((st, _)) = (unsafe { state(dh) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set(ret, check_params(&st)) };
        1
    }
}

/// Raises each flag's error, as `DH_check_params_ex` and `DH_check_ex` do (`table` in their
/// order).
fn raise_flags(flags: c_int, table: &[(c_int, c_int)], f: &str) {
    for &(flag, reason) in table {
        if flags & flag != 0 {
            err::raise(ERR_LIB_DH, reason, f);
        }
    }
}

ffi_export! {
    /// `DH_check_params` with each problem raised as an error. 1 if none.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_check_params_ex(dh: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        let mut flags = 0;
        // SAFETY: the caller's guarantee; a local.
        if unsafe { DH_check_params(dh, &raw mut flags) } == 0 {
            return 0;
        }
        raise_flags(
            flags,
            &[
                (DH_CHECK_P_NOT_PRIME, DH_R_CHECK_P_NOT_PRIME),
                (DH_NOT_SUITABLE_GENERATOR, DH_R_NOT_SUITABLE_GENERATOR),
                (DH_MODULUS_TOO_SMALL, DH_R_MODULUS_TOO_SMALL),
                (DH_MODULUS_TOO_LARGE, DH_R_MODULUS_TOO_LARGE),
            ],
            "DH_check_params_ex",
        );
        c_int::from(flags == 0)
    }
}

ffi_export! {
    /// The parameters' checks into `*ret`: a named group's pass; otherwise the basic checks,
    /// q (if any) below p, prime, dividing `p - 1` (and j its cofactor), g of order q, and p
    /// prime (and safe, without q). 1, or 0 on a failure (or a modulus too large to check).
    ///
    /// # Safety
    /// `dh` is a live key; `ret` is writable.
    pub unsafe extern "C" fn DH_check(dh: *const DH, ret: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some((st, libctx)) = (unsafe { state(dh) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set(ret, 0) };
        let (Some(p), Some(g)) = (&st.params.p, &st.params.g) else {
            // SAFETY: as above.
            unsafe { set(ret, DH_NOT_SUITABLE_GENERATOR | DH_CHECK_P_NOT_PRIME) };
            return 1;
        };
        if st.params.nid != 0 {
            return 1;
        }
        if p.num_bits() > usize::try_from(OPENSSL_DH_CHECK_MAX_MODULUS_BITS).unwrap_or(32768) {
            err::raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE, "DH_check");
            // SAFETY: as above.
            unsafe { set(ret, DH_MODULUS_TOO_LARGE | DH_CHECK_P_NOT_PRIME) };
            return 0;
        }
        let mut flags = check_params(&st);
        // SAFETY: the key's library context; no callback.
        let Some(env) = (unsafe { Env::new(libctx, ptr::null_mut()) }) else { return 0 };
        let result = (|| {
            if let Some(q) = &st.params.q {
                if core_bn::ucmp(p, q).is_gt() {
                    if core_bn::cmp(g, &BigNum::one()).is_le() || core_bn::cmp(g, p).is_ge() {
                        flags |= DH_NOT_SUITABLE_GENERATOR;
                    } else {
                        let t = core_bn::modular::exp_mod(g, q, p).ok()?;
                        if !t.is_one() {
                            flags |= DH_NOT_SUITABLE_GENERATOR;
                        }
                    }
                    match env.check_prime(q) {
                        r if r < 0 => return None,
                        0 => flags |= DH_CHECK_Q_NOT_PRIME,
                        _ => {}
                    }
                    let (t1, t2) = env.div(p, q)?;
                    if !t2.is_one() {
                        flags |= DH_CHECK_INVALID_Q_VALUE;
                    }
                    if st.params.j.as_ref().is_some_and(|j| !core_bn::cmp(j, &t1).is_eq()) {
                        flags |= DH_CHECK_INVALID_J_VALUE;
                    }
                } else {
                    flags |= DH_CHECK_INVALID_Q_VALUE;
                }
            }
            match env.check_prime(p) {
                r if r < 0 => return None,
                0 => flags |= DH_CHECK_P_NOT_PRIME,
                _ => {
                    if st.params.q.is_none() {
                        match env.check_prime(&core_bn::rshift1(p)) {
                            r if r < 0 => return None,
                            0 => flags |= DH_CHECK_P_NOT_SAFE_PRIME,
                            _ => {}
                        }
                    }
                }
            }
            Some(())
        })();
        // SAFETY: as above.
        unsafe { set(ret, flags) };
        c_int::from(result.is_some())
    }
}

ffi_export! {
    /// `DH_check` with each problem raised as an error. 1 if none.
    ///
    /// # Safety
    /// `dh` is a live key.
    pub unsafe extern "C" fn DH_check_ex(dh: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        let mut flags = 0;
        // SAFETY: the caller's guarantee; a local.
        if unsafe { DH_check(dh, &raw mut flags) } == 0 {
            return 0;
        }
        raise_flags(
            flags,
            &[
                (DH_NOT_SUITABLE_GENERATOR, DH_R_NOT_SUITABLE_GENERATOR),
                (DH_CHECK_Q_NOT_PRIME, DH_R_CHECK_Q_NOT_PRIME),
                (DH_CHECK_INVALID_Q_VALUE, DH_R_CHECK_INVALID_Q_VALUE),
                (DH_CHECK_INVALID_J_VALUE, DH_R_CHECK_INVALID_J_VALUE),
                (DH_UNABLE_TO_CHECK_GENERATOR, DH_R_UNABLE_TO_CHECK_GENERATOR),
                (DH_CHECK_P_NOT_PRIME, DH_R_CHECK_P_NOT_PRIME),
                (DH_CHECK_P_NOT_SAFE_PRIME, DH_R_CHECK_P_NOT_SAFE_PRIME),
                (DH_MODULUS_TOO_SMALL, DH_R_MODULUS_TOO_SMALL),
                (DH_MODULUS_TOO_LARGE, DH_R_MODULUS_TOO_LARGE),
            ],
            "DH_check_ex",
        );
        c_int::from(flags == 0)
    }
}

ffi_export! {
    /// The public key's checks into `*ret` (SP 800-56A 5.6.2.3.1: `2 <= y <= p - 2`, and
    /// `y^q = 1` with q). 1, or 0 for a modulus too large to check.
    ///
    /// # Safety
    /// `dh` is a live key; `pub_key` is a live `BIGNUM`; `ret` is writable.
    pub unsafe extern "C" fn DH_check_pub_key(dh: *const DH, pub_key: *const BIGNUM, ret: *mut c_int) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some((st, _)) = (unsafe { state(dh) }) else { return 0 };
        // SAFETY: as above.
        unsafe { set(ret, 0) };
        let Some(p) = &st.params.p else {
            // SAFETY: as above.
            unsafe { set(ret, DH_CHECK_PUBKEY_INVALID) };
            return 1;
        };
        if p.num_bits() > usize::try_from(OPENSSL_DH_CHECK_MAX_MODULUS_BITS).unwrap_or(32768) {
            err::raise(ERR_LIB_DH, DH_R_MODULUS_TOO_LARGE, "DH_check_pub_key");
            // SAFETY: as above.
            unsafe { set(ret, DH_MODULUS_TOO_LARGE | DH_CHECK_PUBKEY_INVALID) };
            return 0;
        }
        if st.params.q.as_ref().is_some_and(|q| core_bn::ucmp(p, q).is_lt()) {
            // SAFETY: as above.
            unsafe { set(ret, DH_CHECK_INVALID_Q_VALUE | DH_CHECK_PUBKEY_INVALID) };
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let Some(y) = (unsafe { value(pub_key) }) else { return 0 };
        let mut flags = 0;
        let ok = ffc::validate_public_key(&st.params, &y, &mut flags);
        // SAFETY: as above.
        unsafe { set(ret, flags) };
        c_int::from(ok)
    }
}

ffi_export! {
    /// `DH_check_pub_key` with each problem raised as an error. 1 if none.
    ///
    /// # Safety
    /// `dh` is a live key; `pub_key` is a live `BIGNUM`.
    pub unsafe extern "C" fn DH_check_pub_key_ex(dh: *const DH, pub_key: *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        let mut flags = 0;
        // SAFETY: the caller's guarantee; a local.
        if unsafe { DH_check_pub_key(dh, pub_key, &raw mut flags) } == 0 {
            return 0;
        }
        raise_flags(
            flags,
            &[
                (DH_CHECK_PUBKEY_TOO_SMALL, DH_R_CHECK_PUBKEY_TOO_SMALL),
                (DH_CHECK_PUBKEY_TOO_LARGE, DH_R_CHECK_PUBKEY_TOO_LARGE),
                (DH_CHECK_PUBKEY_INVALID, DH_R_CHECK_PUBKEY_INVALID),
            ],
            "DH_check_pub_key_ex",
        );
        c_int::from(flags == 0)
    }
}

/// `ossl_dh_kdf_X9_42_asn1`: the X9.42 KDF (`X942KDF-ASN1`, fetched from `libctx`) of the
/// shared secret `z`, `outlen` octets into `out`, for the key-wrap algorithm `cek_alg` (by
/// name; NULL fails in the KDF), with the keying material if any, by the digest `md` (NULL
/// fails in the KDF). True on success.
///
/// # Safety
/// `out` has room for `outlen` octets; `cek_alg` is NULL or a string; `md` is NULL or a live
/// digest; `libctx` is NULL or a live library context.
pub(crate) unsafe fn kdf_x9_42_asn1(
    out: *mut c_uchar,
    outlen: usize,
    z: &[u8],
    cek_alg: *const c_char,
    ukm: Option<&[u8]>,
    md: *const EVP_MD,
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
) -> bool {
    let mdname = if md.is_null() {
        ptr::null()
    } else {
        // SAFETY: the caller's digest.
        unsafe { EVP_MD_get0_name(md) }
    };
    // SAFETY: the library context; a static name.
    let kdf = unsafe { EVP_KDF_fetch(libctx, OSSL_KDF_NAME_X942KDF_ASN1.as_ptr(), ptr::null()) };
    if kdf.is_null() {
        return false;
    }
    // SAFETY: the KDF fetched above.
    let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
    let mut ret = false;
    if !kctx.is_null() {
        let mut params = Vec::with_capacity(5);
        // SAFETY: a static name; the digest's name, or NULL, which outlives the array.
        params.push(unsafe {
            OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST.as_ptr(), mdname.cast_mut(), 0)
        });
        // SAFETY: a static name; the caller's secret, which outlives the array.
        params.push(unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_KEY.as_ptr(),
                z.as_ptr().cast_mut().cast(),
                z.len(),
            )
        });
        if let Some(u) = ukm {
            // SAFETY: a static name; the caller's ukm, which outlives the array.
            params.push(unsafe {
                OSSL_PARAM_construct_octet_string(
                    OSSL_KDF_PARAM_UKM.as_ptr(),
                    u.as_ptr().cast_mut().cast(),
                    u.len(),
                )
            });
        }
        // SAFETY: a static name; the caller's name, or NULL, which outlives the array.
        params.push(unsafe {
            OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CEK_ALG.as_ptr(), cek_alg.cast_mut(), 0)
        });
        // SAFETY: no preconditions.
        params.push(unsafe { OSSL_PARAM_construct_end() });
        // SAFETY: the context; the caller's room; the array.
        ret = unsafe { EVP_KDF_derive(kctx, out, outlen, params.as_ptr()) } > 0;
    }
    // SAFETY: made above.
    unsafe { EVP_KDF_CTX_free(kctx) };
    // SAFETY: as above.
    unsafe { EVP_KDF_free(kdf) };
    ret
}

ffi_export! {
    /// The X9.42 KDF (the ASN.1 variant, `X942KDF-ASN1`) of the shared secret `Z`: `outlen`
    /// octets for the key-wrap algorithm `key_oid`, with the `ukm` if given, the digest `md`
    /// fetched from its provider's library context. 1, or 0.
    ///
    /// # Safety
    /// `out` has room for `outlen` octets; `Z` holds `Zlen`; `key_oid` is a live object; `ukm`
    /// is NULL or holds `ukmlen`; `md` is a live digest.
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn DH_KDF_X9_42(out: *mut c_uchar, outlen: usize, Z: *const c_uchar, Zlen: usize, key_oid: *mut ASN1_OBJECT, ukm: *const c_uchar, ukmlen: usize, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        let mut key_alg = [0 as c_char; 50];
        let len = c_int::try_from(key_alg.len()).unwrap_or(0);
        // SAFETY: the room; the caller's object.
        if unsafe { OBJ_obj2txt(key_alg.as_mut_ptr(), len, key_oid, 0) } <= 0 {
            return 0;
        }
        let libctx = if md.is_null() {
            ptr::null_mut()
        } else {
            // SAFETY: the caller's digest.
            let prov = unsafe { EVP_MD_get0_provider(md) };
            // SAFETY: the digest's provider, or NULL.
            unsafe { libctx_of(prov) }
        };
        // SAFETY: the caller's secret.
        let Some(z) = (unsafe { crate::ffi::bytes(Z, Zlen) }) else { return 0 };
        // SAFETY: the caller's keying material, if any.
        let u = if ukm.is_null() { None } else { unsafe { crate::ffi::bytes(ukm, ukmlen) } };
        // SAFETY: the caller's room; the name above; the caller's digest; its library context.
        c_int::from(unsafe { kdf_x9_42_asn1(out, outlen, z, key_alg.as_ptr(), u, md, libctx) })
    }
}
