//! SM2 signatures (`sm2_sign.c`): the Z value of a key and an ID, signing a digest-sized number
//! `e` with a random nonce (the private-key arithmetic in constant time,
//! `rustyssl_crypto::ec::sm2::sign_s`), verifying, and the DER signatures the provider signs
//! and verifies (`ossl_sm2_internal_sign`, `ossl_sm2_internal_verify`).
//!
//! As in OpenSSL, the nonce is drawn with `BN_priv_rand_range_ex` and drawn again while r is 0,
//! r + k is the order, or s is 0. A private key of n - 1, whose `1 + d` has no inverse, makes
//! every s zero and OpenSSL's loop endless; this one refuses it (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_FLG_CONSTTIME, EC_KEY, ERR_LIB_SM2, ERR_R_BN_LIB, ERR_R_EC_LIB, ERR_R_EVP_LIB,
    ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER, EVP_MD,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum, Endian};
use rustyssl_crypto::ec::ecdsa::{Decoded, decode_sig, encode_sig};
use rustyssl_crypto::ec::sm2::{self as sm2_core, SignError, ZError};

use super::group::{EC_GROUP_get_curve, EC_GROUP_get0_generator, EC_GROUP_get0_order};
use super::key::{EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key, key};
use super::point::{EC_POINT_free, EC_POINT_get_affine_coordinates, EC_POINT_mul, EC_POINT_new};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::bn::{BN_clear_free, BN_free, BN_new, BN_secure_new, BN_set_flags, new_bignum, value};
use crate::err;
use crate::evp::md_ctx::{
    EVP_DigestFinal, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
};
use crate::generated::err_strings::{
    SM2_R_BAD_SIGNATURE, SM2_R_ID_TOO_LARGE, SM2_R_INVALID_ENCODING, SM2_R_INVALID_PRIVATE_KEY,
};
use crate::mem::CRYPTO_memcmp;

fn raise(reason: c_int, func: &str) {
    err::raise(ERR_LIB_SM2, reason, func);
}

/// Numbers made with `BN_new`, freed on drop.
struct Nums<const N: usize>([*mut BIGNUM; N]);

impl<const N: usize> Nums<N> {
    fn new() -> Self {
        // SAFETY: no preconditions.
        Self(core::array::from_fn(|_| unsafe { BN_new() }))
    }

    fn ok(&self) -> bool {
        self.0.iter().all(|b| !b.is_null())
    }

    /// The `i`th number's value.
    fn get(&self, i: usize) -> Option<BigNum> {
        // SAFETY: a number made here, or NULL.
        unsafe { value(*self.0.get(i)?) }
    }
}

impl<const N: usize> Drop for Nums<N> {
    fn drop(&mut self) {
        for b in self.0 {
            // SAFETY: made here, or NULL; freed once.
            unsafe { BN_clear_free(b) };
        }
    }
}

/// `ossl_sm2_compute_z_digest`: `Z = H(ENTL || ID || a || b || xG || yG || xA || yA)` into
/// `out`, which has room for the digest.
///
/// # Safety
/// `digest` is a live digest; `eckey` is a live key; `out` has room for the digest's size.
pub(crate) unsafe fn compute_z_digest(
    out: *mut u8,
    digest: *const EVP_MD,
    id: &[u8],
    eckey: *const EC_KEY,
) -> bool {
    const F: &str = "ossl_sm2_compute_z_digest";
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(eckey) };
    // SAFETY: as above.
    let pubkey = unsafe { EC_KEY_get0_public_key(eckey) };
    if pubkey.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, F);
        return false;
    }
    // SAFETY: no preconditions.
    let hash = unsafe { EVP_MD_CTX_new() };
    if hash.is_null() {
        raise(ERR_R_EVP_LIB, F);
        return false;
    }
    // SAFETY: the key.
    let libctx = unsafe { key(eckey) }.map_or(ptr::null_mut(), |k| k.get().libctx.0);
    // SAFETY: the key's library context, or NULL.
    let ctx = unsafe { BN_CTX_new_ex(libctx) };
    let nums = Nums::<7>::new();
    let ok = (|| {
        if ctx.is_null() || !nums.ok() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        // SAFETY: the context; the caller's digest.
        if unsafe { EVP_DigestInit_ex(hash, digest, ptr::null_mut()) } == 0 {
            raise(ERR_R_EVP_LIB, F);
            return false;
        }
        if id.len() >= usize::from(u16::MAX / 8) {
            raise(SM2_R_ID_TOO_LARGE, F);
            return false;
        }
        let [p, a, b, xg, yg, xa, ya] = nums.0;
        // SAFETY: the key's group; numbers made here; the context.
        if unsafe { EC_GROUP_get_curve(group, p, a, b, ctx) } == 0 {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        // SAFETY: as above.
        let g = unsafe { EC_GROUP_get0_generator(group) };
        // SAFETY: the group, its generator, numbers made here, the context.
        let have_g = unsafe { EC_POINT_get_affine_coordinates(group, g, xg, yg, ctx) } != 0;
        // SAFETY: as above, with the key's point.
        let have_a =
            have_g && unsafe { EC_POINT_get_affine_coordinates(group, pubkey, xa, ya, ctx) } != 0;
        let values: Option<Vec<BigNum>> = (0..7).map(|i| nums.get(i)).collect();
        let pre = match (have_a, values) {
            (true, Some(v)) => match v.as_slice() {
                [p, a, b, xg, yg, xa, ya] => {
                    sm2_core::z_preimage(id, p.num_bytes(), [a, b, xg, yg, xa, ya])
                }
                _ => Err(ZError::TooLong),
            },
            _ => Err(ZError::TooLong),
        };
        let Ok(pre) = pre else {
            raise(ERR_R_INTERNAL_ERROR, F);
            return false;
        };
        // SAFETY: the context; the octets; the caller's room.
        let done = unsafe { EVP_DigestUpdate(hash, pre.as_ptr().cast(), pre.len()) } != 0
            // SAFETY: as above.
            && unsafe { EVP_DigestFinal(hash, out, ptr::null_mut()) } != 0;
        if !done {
            raise(ERR_R_INTERNAL_ERROR, F);
        }
        done
    })();
    // SAFETY: made above, or NULL.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: made above.
    unsafe { EVP_MD_CTX_free(hash) };
    ok
}

/// `sm2_sig_gen`: `(r, s)` for `e` with a random nonce, or `None` with the error raised.
///
/// # Safety
/// `eckey` is a live key.
unsafe fn sig_gen(eckey: *const EC_KEY, e: &BigNum) -> Option<(BigNum, BigNum)> {
    const F: &str = "sm2_sig_gen";
    // SAFETY: the caller's key.
    let d_p = unsafe { EC_KEY_get0_private_key(eckey) };
    // SAFETY: as above.
    let group = unsafe { EC_KEY_get0_group(eckey) };
    // SAFETY: the key's number, or NULL.
    let Some(d) = (unsafe { value(d_p) }) else {
        raise(SM2_R_INVALID_PRIVATE_KEY, F);
        return None;
    };
    // SAFETY: the key's group.
    let order_p = unsafe { EC_GROUP_get0_order(group) };
    // SAFETY: the group's number.
    let order = unsafe { value(order_p) }?;
    // `EC_GROUP_get_mont_data`: an order without Montgomery arithmetic (an even one).
    if rustyssl_crypto::ec::fe::Fp::new(&order).is_none() {
        raise(ERR_R_EC_LIB, F);
        return None;
    }
    // SAFETY: the key's group.
    let kg = unsafe { EC_POINT_new(group) };
    if kg.is_null() {
        raise(ERR_R_EC_LIB, F);
        return None;
    }
    // SAFETY: the key.
    let libctx = unsafe { key(eckey) }.map_or(ptr::null_mut(), |k| k.get().libctx.0);
    // SAFETY: the key's library context, or NULL.
    let ctx = unsafe { BN_CTX_new_ex(libctx) };
    // SAFETY: no preconditions.
    let k = unsafe { BN_secure_new() };
    // SAFETY: as above.
    let x1 = unsafe { BN_new() };
    let out = (|| {
        if ctx.is_null() || k.is_null() || x1.is_null() {
            raise(ERR_R_BN_LIB, F);
            return None;
        }
        loop {
            // SAFETY: a number; the group's order; the context.
            if unsafe { BN_priv_rand_range_ex(k, order_p, 0, ctx) } == 0 {
                raise(ERR_R_INTERNAL_ERROR, F);
                return None;
            }
            // SAFETY: the number.
            unsafe { BN_set_flags(k, BN_FLG_CONSTTIME) };
            // SAFETY: the group, point, nonce, and context.
            let mul = unsafe { EC_POINT_mul(group, kg, k, ptr::null(), ptr::null(), ctx) } != 0;
            let got = mul && {
                // SAFETY: as above.
                (unsafe { EC_POINT_get_affine_coordinates(group, kg, x1, ptr::null_mut(), ctx) })
                    != 0
            };
            if !got {
                raise(ERR_R_INTERNAL_ERROR, F);
                return None;
            }
            // SAFETY: numbers made here.
            let (Some(kv), Some(x1v)) = (unsafe { value(k) }, unsafe { value(x1) }) else {
                return None;
            };
            let Ok(r) = core_bn::add(e, &x1v).and_then(|t| core_bn::nnmod(&t, &order)) else {
                raise(ERR_R_INTERNAL_ERROR, F);
                return None;
            };
            if r.is_zero() {
                continue;
            }
            // r + k = n is k = n - r: n - r is public, compared with k in constant time over
            // the order's width.
            let Ok(nr) = core_bn::sub(&order, &r) else {
                raise(ERR_R_BN_LIB, F);
                return None;
            };
            let width = order.num_bytes();
            let (Some(a), Some(b)) = (
                kv.to_bin(Some(width), Endian::Big, false),
                nr.to_bin(Some(width), Endian::Big, false),
            ) else {
                raise(ERR_R_BN_LIB, F);
                return None;
            };
            // SAFETY: two buffers of `width` octets.
            if unsafe { CRYPTO_memcmp(a.as_ptr().cast::<c_void>(), b.as_ptr().cast(), width) } == 0
            {
                continue;
            }
            match sm2_core::sign_s(&order, &d, &kv, &r) {
                Ok(s) => return Some((r, s)),
                Err(SignError::ZeroS) => {}
                Err(SignError::Bn) => {
                    raise(ERR_R_BN_LIB, F);
                    return None;
                }
                Err(SignError::PrivateKey) => {
                    raise(SM2_R_INVALID_PRIVATE_KEY, F);
                    return None;
                }
            }
        }
    })();
    // SAFETY: made above, or NULL.
    unsafe { BN_clear_free(k) };
    // SAFETY: as above.
    unsafe { BN_clear_free(x1) };
    // SAFETY: as above.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: made above.
    unsafe { EC_POINT_free(kg) };
    out
}

/// `sm2_sig_verify`: 1 if `(r, s)` signs `e`, 0 if not (`SM2_R_BAD_SIGNATURE` for values out of
/// range).
///
/// # Safety
/// `eckey` is a live key.
unsafe fn sig_verify(eckey: *const EC_KEY, r: &BigNum, s: &BigNum, e: &BigNum) -> c_int {
    const F: &str = "sm2_sig_verify";
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(eckey) };
    // SAFETY: the key's group.
    let order_p = unsafe { EC_GROUP_get0_order(group) };
    // SAFETY: the group's number.
    let Some(order) = (unsafe { value(order_p) }) else {
        return 0;
    };
    let one = BigNum::one();
    if core_bn::cmp(r, &one).is_lt()
        || core_bn::cmp(s, &one).is_lt()
        || core_bn::cmp(&order, r).is_le()
        || core_bn::cmp(&order, s).is_le()
    {
        raise(SM2_R_BAD_SIGNATURE, F);
        return 0;
    }
    let Ok(t) = core_bn::add(r, s).and_then(|v| core_bn::nnmod(&v, &order)) else {
        raise(ERR_R_BN_LIB, F);
        return 0;
    };
    if t.is_zero() {
        raise(SM2_R_BAD_SIGNATURE, F);
        return 0;
    }
    // SAFETY: the key.
    let libctx = unsafe { key(eckey) }.map_or(ptr::null_mut(), |k| k.get().libctx.0);
    // SAFETY: the key's library context, or NULL.
    let ctx = unsafe { BN_CTX_new_ex(libctx) };
    // SAFETY: the group.
    let pt = unsafe { EC_POINT_new(group) };
    let sb = new_bignum(s.clone(), false);
    let tb = new_bignum(t, false);
    // SAFETY: no preconditions.
    let x1 = unsafe { BN_new() };
    let ret = (|| {
        if ctx.is_null() || pt.is_null() || x1.is_null() {
            raise(ERR_R_EC_LIB, F);
            return 0;
        }
        // SAFETY: the key.
        let pubkey = unsafe { EC_KEY_get0_public_key(eckey) };
        // SAFETY: the group, point, numbers, key's point, and context.
        let mul = unsafe { EC_POINT_mul(group, pt, sb, pubkey, tb, ctx) } != 0;
        let got = mul && {
            // SAFETY: as above.
            (unsafe { EC_POINT_get_affine_coordinates(group, pt, x1, ptr::null_mut(), ctx) }) != 0
        };
        if !got {
            raise(ERR_R_EC_LIB, F);
            return 0;
        }
        // SAFETY: a number made here.
        let Some(x1v) = (unsafe { value(x1) }) else {
            return 0;
        };
        let Ok(rr) = core_bn::add(e, &x1v).and_then(|v| core_bn::nnmod(&v, &order)) else {
            raise(ERR_R_BN_LIB, F);
            return 0;
        };
        c_int::from(core_bn::cmp(r, &rr).is_eq())
    })();
    // SAFETY: made above, or NULL; each freed once.
    unsafe { EC_POINT_free(pt) };
    // SAFETY: as above.
    unsafe { BN_free(sb) };
    // SAFETY: as above.
    unsafe { BN_free(tb) };
    // SAFETY: as above.
    unsafe { BN_free(x1) };
    // SAFETY: as above.
    unsafe { BN_CTX_free(ctx) };
    ret
}

/// `ossl_sm2_internal_sign`: the DER signature of the number `dgst` into `sig`; its length, or
/// `None` (OpenSSL's -1) with the error raised.
///
/// # Safety
/// `sig` is NULL or has room for `ECDSA_size(eckey)` octets; `eckey` is a live key.
pub(crate) unsafe fn internal_sign(
    dgst: &[u8],
    sig: *mut c_uchar,
    eckey: *const EC_KEY,
) -> Option<c_uint> {
    const F: &str = "ossl_sm2_internal_sign";
    if sig.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, F);
        return None;
    }
    let Ok(e) = BigNum::from_bin(dgst, Endian::Big, false) else {
        raise(ERR_R_BN_LIB, F);
        return None;
    };
    // SAFETY: the caller's key.
    let Some((r, s)) = (unsafe { sig_gen(eckey, &e) }) else {
        raise(ERR_R_INTERNAL_ERROR, F);
        return None;
    };
    let Some(der) = encode_sig(&r, &s) else {
        raise(ERR_R_INTERNAL_ERROR, F);
        return None;
    };
    let n = c_uint::try_from(der.len()).ok()?;
    // SAFETY: the caller's room for the key's largest signature, which this is at most.
    unsafe { ptr::copy_nonoverlapping(der.as_ptr(), sig, der.len()) };
    Some(n)
}

/// `ossl_sm2_internal_verify`: 1 if the DER signature (exactly DER, nothing after it) signs the
/// number `dgst`, 0 if not, -1 for a malformed one.
///
/// # Safety
/// `eckey` is a live key.
pub(crate) unsafe fn internal_verify(dgst: &[u8], sig: &[u8], eckey: *const EC_KEY) -> c_int {
    const F: &str = "ossl_sm2_internal_verify";
    let Decoded::Sig { r, s, .. } = decode_sig(sig) else {
        raise(SM2_R_INVALID_ENCODING, F);
        return -1;
    };
    if encode_sig(&r, &s).as_deref() != Some(sig) {
        raise(SM2_R_INVALID_ENCODING, F);
        return -1;
    }
    let Ok(e) = BigNum::from_bin(dgst, Endian::Big, false) else {
        raise(ERR_R_BN_LIB, F);
        return -1;
    };
    // SAFETY: the caller's key.
    unsafe { sig_verify(eckey, &r, &s, &e) }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::NID_sm2;

    use super::*;
    use crate::ec::key::{
        EC_KEY_free, EC_KEY_new_by_curve_name, EC_KEY_set_private_key, EC_KEY_set_public_key,
    };

    /// docs/DEVIATIONS.md: a private key of n - 1, whose `1 + d` has no inverse, makes every s
    /// zero; OpenSSL draws nonces forever, this refuses the key.
    #[test]
    #[cfg_attr(miri, ignore = "draws from the DRBG, which loads the configuration")]
    fn a_private_key_of_n_minus_1_is_refused() {
        // SAFETY: no preconditions.
        let k = unsafe { EC_KEY_new_by_curve_name(NID_sm2) };
        // SAFETY: a live key.
        let group = unsafe { EC_KEY_get0_group(k) };
        // SAFETY: the key's group.
        let order_p = unsafe { EC_GROUP_get0_order(group) };
        // SAFETY: the group's number.
        let order = unsafe { value(order_p) }.unwrap_or_default();
        let mut nm1 = order.clone();
        assert!(nm1.sub_word(1).is_ok());
        let d = new_bignum(nm1, false);
        // SAFETY: the key and the number.
        assert_eq!(unsafe { EC_KEY_set_private_key(k, d) }, 1);
        // The public key of n - 1 is -G; any point will do for signing.
        // SAFETY: the key's group.
        let g = unsafe { EC_GROUP_get0_generator(group) };
        // SAFETY: the key and point.
        assert_eq!(unsafe { EC_KEY_set_public_key(k, g) }, 1);
        let mut sig = [0u8; 80];
        // SAFETY: a digest's octets; room for a signature; the key.
        let r = unsafe { internal_sign(&[0x5a; 32], sig.as_mut_ptr(), k) };
        assert!(r.is_none());
        // SAFETY: no preconditions.
        let first = unsafe { crate::err::ERR_get_error() };
        let reason =
            first & core::ffi::c_ulong::from(rustyssl_abi::ERR_REASON_MASK.cast_unsigned());
        assert_eq!(
            reason,
            core::ffi::c_ulong::from(SM2_R_INVALID_PRIVATE_KEY.cast_unsigned())
        );
        // SAFETY: made above, freed once each.
        unsafe { BN_free(d) };
        // SAFETY: as above.
        unsafe { EC_KEY_free(k) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
