//! ECDSA and ECDH (`ecdsa_ossl.c`, `ecdsa_sign.c`, `ecdsa_vrf.c`, `ecdh_ossl.c`,
//! `ec_kmeth.c`, `ecdh_kdf.c`, and `ECDSA_SIG` in `ec_asn1.c`): the library method's
//! functions (`ossl_ecdsa_*`, `ossl_ecdh_compute_key`, which every built-in group method
//! implements the simple way), the public functions that call a key's method, and `ECDSA_SIG`
//! with its DER.
//!
//! A signature's nonce comes as OpenSSL's does: from `BN_generate_dsa_nonce` (the private key,
//! the digest, and the private generator through SHA-512) when signing, or as the order's bits
//! plus one, cut down, for `ECDSA_sign_setup`. The secret arithmetic (`k^-1` and
//! `s = k^-1 (m + r d)`) runs in constant time (`rustyssl_crypto::ec::ecdsa`); verification,
//! on public values, uses the ordinary functions.

use core::ffi::{c_int, c_long, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_CTX, BN_FLG_CONSTTIME, EC_FLAG_COFACTOR_ECDH, EC_KEY, EC_POINT, EC_R_BAD_SIGNATURE,
    EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING, EC_R_INVALID_OUTPUT_LENGTH, EC_R_MISSING_PARAMETERS,
    EC_R_MISSING_PRIVATE_KEY, EC_R_NEED_NEW_SETUP_VALUES, EC_R_OPERATION_NOT_SUPPORTED,
    EC_R_POINT_ARITHMETIC_FAILURE, EC_R_RANDOM_NUMBER_GENERATION_FAILED, EC_R_TOO_MANY_RETRIES,
    ECDSA_SIG, ERR_LIB_EC, ERR_R_BN_LIB, ERR_R_EC_LIB, ERR_R_ECDSA_LIB, ERR_R_INTERNAL_ERROR,
    ERR_R_PASSED_NULL_PARAMETER, EVP_MD, OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_INFO,
    OSSL_KDF_PARAM_KEY,
};
use rustyssl_crypto::bn::{BigNum, rand::rand_range_fixed_top};
use rustyssl_crypto::ec::ecdsa::{self as ecdsa_core, Decoded, SignError};

use super::group::{EC_GROUP_get_cofactor, EC_GROUP_get_degree, EC_GROUP_get0_order};
use super::key::{
    EC_KEY_can_sign, EC_KEY_get_flags, EC_KEY_get0_group, EC_KEY_get0_private_key,
    EC_KEY_get0_public_key, EcKey, key, method,
};
use super::point::{
    EC_POINT_clear_free, EC_POINT_free, EC_POINT_get_affine_coordinates, EC_POINT_mul, EC_POINT_new,
};
use super::random;
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::modular::BN_generate_dsa_nonce;
use crate::bn::{BN_clear_free, BN_new, BN_secure_new, BN_set_flags, new_bignum, store, value};
use crate::err;
use crate::evp::digest::EVP_MD_get0_name;
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::params::{
    OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
};

/// Raises an EC error from `func`.
fn raise(reason: c_int, func: &'static str) {
    err::raise(ERR_LIB_EC, reason, func);
}

/// `MIN_ECDSA_SIGN_ORDERBITS`: an order this short can't be signed with (its nonce loop could
/// spin).
const MIN_SIGN_ORDER_BITS: usize = 64;

/// `MAX_ECDSA_SIGN_RETRIES`.
const MAX_SIGN_RETRIES: u32 = 8;

/// `ECDSA_SIG` (`struct ECDSA_SIG_st`), which applications see only through pointers.
#[repr(C)]
struct Sig {
    r: *mut BIGNUM,
    s: *mut BIGNUM,
}

/// The signature behind a pointer.
///
/// # Safety
/// `s` is NULL or a live signature.
unsafe fn sig<'a>(s: *const ECDSA_SIG) -> Option<&'a mut Sig> {
    // SAFETY: the caller's guarantee.
    unsafe { s.cast::<Sig>().cast_mut().as_mut() }
}

ffi_export! {
    /// A new, empty signature.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn ECDSA_SIG_new() -> *mut ECDSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        mem::zalloc(size_of::<Sig>(), ptr::null(), 0).cast()
    }
}

ffi_export! {
    /// Frees a signature and its numbers. NULL does nothing.
    ///
    /// # Safety
    /// `sig` is NULL or a live signature.
    pub unsafe extern "C" fn ECDSA_SIG_free(sig: *mut ECDSA_SIG)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::sig(sig) }) else { return };
        // SAFETY: the signature's own numbers, or NULL.
        unsafe { BN_clear_free(s.r) };
        // SAFETY: as above.
        unsafe { BN_clear_free(s.s) };
        // SAFETY: the signature, freed once.
        unsafe { mem::release(sig.cast()) };
    }
}

ffi_export! {
    /// The signature's numbers, each through a pointer that isn't NULL.
    ///
    /// # Safety
    /// `sig` is a live signature; `pr` and `ps` are NULL or writable.
    pub unsafe extern "C" fn ECDSA_SIG_get0(sig: *const ECDSA_SIG, pr: *mut *const BIGNUM, ps: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::sig(sig) }) else { return };
        if !pr.is_null() {
            // SAFETY: as above.
            unsafe { *pr = s.r };
        }
        if !ps.is_null() {
            // SAFETY: as above.
            unsafe { *ps = s.s };
        }
    }
}

ffi_export! {
    /// The signature's r.
    ///
    /// # Safety
    /// `sig` is a live signature.
    pub unsafe extern "C" fn ECDSA_SIG_get0_r(sig: *const ECDSA_SIG) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::sig(sig) }.map_or(ptr::null(), |s| s.r.cast_const())
    }
}

ffi_export! {
    /// The signature's s.
    ///
    /// # Safety
    /// `sig` is a live signature.
    pub unsafe extern "C" fn ECDSA_SIG_get0_s(sig: *const ECDSA_SIG) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { self::sig(sig) }.map_or(ptr::null(), |s| s.s.cast_const())
    }
}

ffi_export! {
    /// Gives the signature `r` and `s` (both needed), freeing its old ones. 1, or 0.
    ///
    /// # Safety
    /// `sig` is a live signature; `r` and `s` are NULL or live numbers it takes.
    pub unsafe extern "C" fn ECDSA_SIG_set0(sig: *mut ECDSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        if r.is_null() || s.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some(sg) = (unsafe { self::sig(sig) }) else { return 0 };
        // SAFETY: the old numbers, or NULL, freed once.
        unsafe { BN_clear_free(sg.r) };
        // SAFETY: as above.
        unsafe { BN_clear_free(sg.s) };
        sg.r = r;
        sg.s = s;
        1
    }
}

/// A signature's DER, or `None` (without an error) for a missing or negative number.
///
/// # Safety
/// `s` is a live signature.
unsafe fn sig_der(s: &Sig) -> Option<Vec<u8>> {
    // SAFETY: the signature's numbers, or NULL.
    let (r, sv) = (unsafe { value(s.r) }?, unsafe { value(s.s) }?);
    ecdsa_core::encode_sig(&r, &sv)
}

ffi_export! {
    /// The signature's DER (`i2d` conventions); -1 for a signature that can't be encoded.
    ///
    /// # Safety
    /// `sig` is a live signature; `ppout` is NULL or holds NULL or room for the encoding.
    pub unsafe extern "C" fn i2d_ECDSA_SIG(sig: *const ECDSA_SIG, ppout: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(s) = (unsafe { self::sig(sig) }) else { return -1 };
        // SAFETY: as above.
        let Some(der) = (unsafe { sig_der(s) }) else { return -1 };
        let Ok(len) = c_int::try_from(der.len()) else { return -1 };
        if ppout.is_null() {
            return len;
        }
        // SAFETY: the caller's pointer.
        let out = unsafe { *ppout };
        if out.is_null() {
            let buf: *mut c_uchar = mem::malloc(der.len(), ptr::null(), 0).cast();
            if buf.is_null() {
                return -1;
            }
            // SAFETY: room for the encoding.
            unsafe { ptr::copy_nonoverlapping(der.as_ptr(), buf, der.len()) };
            // SAFETY: the caller's pointer.
            unsafe { *ppout = buf };
        } else {
            // SAFETY: the caller's room for the encoding.
            unsafe { ptr::copy_nonoverlapping(der.as_ptr(), out, der.len()) };
            // SAFETY: the caller's pointer, past the encoding.
            unsafe { *ppout = out.wrapping_add(der.len()) };
        }
        len
    }
}

ffi_export! {
    /// Decodes a signature's DER (only what OpenSSL's DER reader accepts) into `*psig` if
    /// given, else a new signature; advances `*ppin` past it. On failure into a given
    /// signature, its r is the one read if the failure came after it, as in OpenSSL.
    ///
    /// # Safety
    /// `psig` is NULL or holds NULL or a live signature; `ppin` holds `len` readable octets.
    pub unsafe extern "C" fn d2i_ECDSA_SIG(psig: *mut *mut ECDSA_SIG, ppin: *mut *const c_uchar, len: c_long) -> *mut ECDSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        let Ok(n) = usize::try_from(len) else { return ptr::null_mut() };
        // SAFETY: the caller's guarantee.
        let given = if psig.is_null() { ptr::null_mut() } else { unsafe { *psig } };
        let sigp = if given.is_null() {
            // SAFETY: no preconditions.
            let s = unsafe { ECDSA_SIG_new() };
            if s.is_null() {
                return ptr::null_mut();
            }
            s
        } else {
            given
        };
        // SAFETY: a live signature.
        let Some(s) = (unsafe { sig(sigp) }) else { return ptr::null_mut() };
        if s.r.is_null() {
            // SAFETY: no preconditions.
            s.r = unsafe { BN_new() };
        }
        if s.s.is_null() {
            // SAFETY: no preconditions.
            s.s = unsafe { BN_new() };
        }
        // SAFETY: the caller's pointer.
        let start = if ppin.is_null() { ptr::null() } else { unsafe { *ppin } };
        let input: &[u8] = if n == 0 || start.is_null() {
            &[]
        } else {
            // SAFETY: the caller's `len` octets.
            unsafe { core::slice::from_raw_parts(start, n) }
        };
        let ok = !s.r.is_null() && !s.s.is_null() && match ecdsa_core::decode_sig(input) {
            Decoded::Sig { r, s: sv, consumed } => {
                // SAFETY: the signature's numbers.
                let stored = unsafe { store(s.r, r) } && unsafe { store(s.s, sv) };
                // SAFETY: the caller's pointer, past the signature.
                unsafe { *ppin = start.wrapping_add(consumed) };
                stored
            }
            Decoded::Failed { r } => {
                if let Some(r) = r {
                    // SAFETY: the signature's number.
                    unsafe { store(s.r, r) };
                }
                false
            }
        };
        if !ok {
            if given.is_null() {
                // SAFETY: the signature made above.
                unsafe { ECDSA_SIG_free(sigp) };
            }
            return ptr::null_mut();
        }
        if !psig.is_null() && given.is_null() {
            // SAFETY: the caller's pointer.
            unsafe { *psig = sigp };
        }
        sigp
    }
}

ffi_export! {
    /// The longest DER signature the key can make (r and s the size of the order), or 0.
    ///
    /// # Safety
    /// `ec` is NULL or a live key.
    pub unsafe extern "C" fn ECDSA_size(ec: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        if ec.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let g = unsafe { EC_KEY_get0_group(ec) };
        if g.is_null() {
            return 0;
        }
        // SAFETY: the key's group.
        let order_p = unsafe { EC_GROUP_get0_order(g) };
        // SAFETY: the group's number.
        let Some(order) = (unsafe { value(order_p) }) else { return 0 };
        ecdsa_core::encode_sig(&order, &order).and_then(|d| c_int::try_from(d.len()).ok()).unwrap_or(0)
    }
}

/// Swaps in a new number at `*p`, freeing the old.
///
/// # Safety
/// `p` is writable and holds NULL or a live number the caller owns.
unsafe fn replace(p: *mut *mut BIGNUM, v: *mut BIGNUM) {
    // SAFETY: the caller's guarantee.
    let old = unsafe { *p };
    // SAFETY: as above.
    unsafe { BN_clear_free(old) };
    // SAFETY: as above.
    unsafe { *p = v };
}

/// `ecdsa_sign_setup`: a nonce (`BN_generate_dsa_nonce` over `dgst`, or the setup's own draw
/// without one), `r = (kG).x mod n` (again while zero), and `k^-1`, into `*kinvp` and `*rp`.
///
/// # Safety
/// `eckey` is NULL or a live key; `ctx_in` is NULL or a live context; `kinvp` and `rp` are
/// writable and hold NULL or numbers the caller owns.
unsafe fn sign_setup(
    eckey: *mut EC_KEY,
    ctx_in: *mut BN_CTX,
    kinvp: *mut *mut BIGNUM,
    rp: *mut *mut BIGNUM,
    dgst: Option<&[u8]>,
) -> bool {
    const F: &str = "ecdsa_sign_setup";
    // SAFETY: the caller's guarantee.
    let group = if eckey.is_null() {
        ptr::null()
    } else {
        // SAFETY: the caller\'s key.
        unsafe { EC_KEY_get0_group(eckey) }
    };
    if group.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, F);
        return false;
    }
    // SAFETY: as above.
    let priv_key = unsafe { EC_KEY_get0_private_key(eckey) };
    if priv_key.is_null() {
        raise(EC_R_MISSING_PRIVATE_KEY, F);
        return false;
    }
    // SAFETY: as above.
    if unsafe { EC_KEY_can_sign(eckey) } == 0 {
        raise(EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING, F);
        return false;
    }
    // SAFETY: as above.
    let libctx = unsafe { key(eckey) }.map_or(ptr::null_mut(), |k| k.get().libctx.0);
    let ctx = if ctx_in.is_null() {
        // SAFETY: the key's context.
        let c = unsafe { BN_CTX_new_ex(libctx) };
        if c.is_null() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        c
    } else {
        ctx_in
    };
    // SAFETY: no preconditions.
    let k = unsafe { BN_secure_new() };
    // SAFETY: the group.
    let tmp = unsafe { EC_POINT_new(group) };
    // SAFETY: no preconditions.
    let x = unsafe { BN_new() };
    let mut kinv: *mut BIGNUM = ptr::null_mut();
    let mut r: *mut BIGNUM = ptr::null_mut();
    let ok = (|| {
        if k.is_null() || x.is_null() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        if tmp.is_null() {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        // SAFETY: the group.
        let order_p = unsafe { EC_GROUP_get0_order(group) };
        // SAFETY: the group's number.
        let Some(order) = (unsafe { value(order_p) }) else {
            raise(ERR_R_EC_LIB, F);
            return false;
        };
        if order.num_bits() < MIN_SIGN_ORDER_BITS {
            return false;
        }
        // SAFETY: the number.
        unsafe { BN_set_flags(k, BN_FLG_CONSTTIME) };
        let mut rv;
        loop {
            loop {
                let drawn = match dgst {
                    Some(d) => {
                        // SAFETY: live numbers; the digest; the context.
                        (unsafe {
                            BN_generate_dsa_nonce(k, order_p, priv_key, d.as_ptr(), d.len(), ctx)
                        }) != 0
                    }
                    None => {
                        // SAFETY: the context.
                        let mut rng = unsafe { random(ctx, libctx) };
                        match rand_range_fixed_top(&order, &mut rng) {
                            // SAFETY: the number.
                            Some(v) => unsafe { store(k, v) },
                            None => false,
                        }
                    }
                };
                if !drawn {
                    raise(EC_R_RANDOM_NUMBER_GENERATION_FAILED, F);
                    return false;
                }
                // SAFETY: the number.
                if unsafe { value(k) }.is_some_and(|v| !v.is_zero()) {
                    break;
                }
            }
            // SAFETY: the group, the point, the nonce, and the context.
            if unsafe { EC_POINT_mul(group, tmp, k, ptr::null(), ptr::null(), ctx) } == 0 {
                raise(ERR_R_EC_LIB, F);
                return false;
            }
            // SAFETY: as above.
            if unsafe { EC_POINT_get_affine_coordinates(group, tmp, x, ptr::null_mut(), ctx) } == 0
            {
                raise(ERR_R_EC_LIB, F);
                return false;
            }
            // SAFETY: the number.
            let Some(xv) = (unsafe { value(x) }) else {
                return false;
            };
            let Ok(v) = rustyssl_crypto::bn::nnmod(&xv, &order) else {
                raise(ERR_R_BN_LIB, F);
                return false;
            };
            rv = v;
            if !rv.is_zero() {
                break;
            }
        }
        // SAFETY: the nonce.
        let Some(kv) = (unsafe { value(k) }) else {
            return false;
        };
        let Some(inv) = ecdsa_core::inverse_mod_order(&order, &kv) else {
            raise(ERR_R_BN_LIB, F);
            return false;
        };
        kinv = new_bignum(inv, true);
        r = new_bignum(rv, false);
        if kinv.is_null() || r.is_null() {
            return false;
        }
        // SAFETY: the number.
        unsafe { BN_set_flags(kinv, BN_FLG_CONSTTIME) };
        true
    })();
    if ok {
        // SAFETY: the caller's pointers.
        unsafe { replace(rp, r) };
        // SAFETY: as above.
        unsafe { replace(kinvp, kinv) };
    } else {
        // SAFETY: NULL or made above.
        unsafe { BN_clear_free(kinv) };
        // SAFETY: as above.
        unsafe { BN_clear_free(r) };
    }
    if ctx != ctx_in {
        // SAFETY: made above.
        unsafe { BN_CTX_free(ctx) };
    }
    // SAFETY: made above, or NULL.
    unsafe { EC_POINT_free(tmp) };
    // SAFETY: as above.
    unsafe { BN_clear_free(x) };
    // SAFETY: as above.
    unsafe { BN_clear_free(k) };
    ok
}

/// The digest's octets.
///
/// # Safety
/// `dgst` holds `dlen` octets (or is NULL for none).
unsafe fn digest<'a>(dgst: *const c_uchar, dlen: c_int) -> Option<&'a [u8]> {
    let n = usize::try_from(dlen).ok()?;
    if n == 0 || dgst.is_null() {
        return Some(&[]);
    }
    // SAFETY: the caller's guarantee.
    Some(unsafe { core::slice::from_raw_parts(dgst, n) })
}

ffi_callback! {
    /// `ossl_ecdsa_sign_setup`: a nonce's inverse and r, drawn without a digest.
    ///
    /// # Safety
    /// As for `ECDSA_sign_setup`.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_sign_setup(eckey: *mut EC_KEY, ctx_in: *mut BN_CTX, kinvp: *mut *mut BIGNUM, rp: *mut *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        if kinvp.is_null() || rp.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, "ecdsa_sign_setup");
            return 0;
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { sign_setup(eckey, ctx_in, kinvp, rp, None) })
    }
}

ffi_callback! {
    /// `ossl_ecdsa_simple_sign_sig`: a signature of the digest, with the given kinv and r or a
    /// fresh nonce (again, up to eight times, while s is zero).
    ///
    /// # Safety
    /// As for `ECDSA_do_sign_ex`.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_sign_sig(dgst: *const c_uchar, dgst_len: c_int, in_kinv: *const BIGNUM, in_r: *const BIGNUM, eckey: *mut EC_KEY) -> *mut ECDSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        const F: &str = "ossl_ecdsa_simple_sign_sig";
        // SAFETY: the caller's guarantee.
        let group = if eckey.is_null() { ptr::null() } else { unsafe { EC_KEY_get0_group(eckey) } };
        // SAFETY: as above.
        let priv_key = if eckey.is_null() { ptr::null() } else { unsafe { EC_KEY_get0_private_key(eckey) } };
        if group.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        if priv_key.is_null() {
            raise(EC_R_MISSING_PRIVATE_KEY, F);
            return ptr::null_mut();
        }
        // SAFETY: as above.
        if unsafe { EC_KEY_can_sign(eckey) } == 0 {
            raise(EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING, F);
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let ret = unsafe { ECDSA_SIG_new() };
        // SAFETY: just made.
        let Some(sg) = (unsafe { sig(ret) }) else {
            raise(ERR_R_ECDSA_LIB, F);
            return ptr::null_mut();
        };
        // SAFETY: no preconditions.
        sg.r = unsafe { BN_new() };
        // SAFETY: as above.
        sg.s = unsafe { BN_new() };
        let mut kinv: *mut BIGNUM = ptr::null_mut();
        let ok = (|| {
            if sg.r.is_null() || sg.s.is_null() {
                raise(ERR_R_BN_LIB, F);
                return false;
            }
            // SAFETY: the group.
            let order_p = unsafe { EC_GROUP_get0_order(group) };
            // SAFETY: the group's number.
            let Some(order) = (unsafe { value(order_p) }) else {
                raise(ERR_R_EC_LIB, F);
                return false;
            };
            // SAFETY: the caller's digest.
            let Some(d) = (unsafe { digest(dgst, dgst_len) }) else {
                raise(ERR_R_BN_LIB, F);
                return false;
            };
            let bits = order.num_bits();
            // The setup sees the digest cut to whole octets, as OpenSSL passes it.
            let d = d.get(..bits.div_ceil(8)).unwrap_or(d);
            let m = ecdsa_core::digest_to_int(d, bits);
            // SAFETY: the key's number.
            let Some(dv) = (unsafe { value(priv_key) }) else { return false };
            let given = !in_kinv.is_null() && !in_r.is_null();
            let mut retries = 0;
            loop {
                let (kv, rv) = if given {
                    // SAFETY: the caller's numbers.
                    let (Some(kv), Some(rv)) = (unsafe { value(in_kinv) }, unsafe { value(in_r) }) else {
                        raise(ERR_R_BN_LIB, F);
                        return false;
                    };
                    (kv, rv)
                } else {
                    // SAFETY: the key; the signature's r and a local, each a number or NULL.
                    if !unsafe { sign_setup(eckey, ptr::null_mut(), &raw mut kinv, &raw mut sg.r, Some(d)) } {
                        raise(ERR_R_ECDSA_LIB, F);
                        return false;
                    }
                    // SAFETY: the numbers the setup made.
                    let (Some(kv), Some(rv)) = (unsafe { value(kinv) }, unsafe { value(sg.r) }) else {
                        return false;
                    };
                    (kv, rv)
                };
                match ecdsa_core::sign_s(&order, &dv, &m, &kv, &rv) {
                    Ok(s) => {
                        // SAFETY: the signature's numbers.
                        let stored = unsafe { store(sg.s, s) } && (!given || unsafe { store(sg.r, rv) });
                        return stored;
                    }
                    Err(SignError::Bn) => {
                        raise(ERR_R_BN_LIB, F);
                        return false;
                    }
                    Err(SignError::ZeroS) => {
                        if given {
                            raise(EC_R_NEED_NEW_SETUP_VALUES, F);
                            return false;
                        }
                        retries += 1;
                        if retries > MAX_SIGN_RETRIES {
                            raise(EC_R_TOO_MANY_RETRIES, F);
                            return false;
                        }
                    }
                }
            }
        })();
        // SAFETY: NULL or the setup's number.
        unsafe { BN_clear_free(kinv) };
        if ok {
            return ret;
        }
        // SAFETY: the signature made above.
        unsafe { ECDSA_SIG_free(ret) };
        ptr::null_mut()
    }
}

ffi_callback! {
    /// `ossl_ecdsa_sign`: the DER signature into `sig` (its length into `*siglen`), or just
    /// the size for no buffer and no given setup values.
    ///
    /// # Safety
    /// As for `ECDSA_sign_ex`.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_sign(type_: c_int, dgst: *const c_uchar, dlen: c_int, sig: *mut c_uchar, siglen: *mut c_uint, kinv: *const BIGNUM, r: *const BIGNUM, eckey: *mut EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let _ = type_;
        if siglen.is_null() {
            return 0;
        }
        if sig.is_null() && (kinv.is_null() || r.is_null()) {
            // SAFETY: the caller's key.
            let size = unsafe { ECDSA_size(eckey) };
            // SAFETY: the caller's pointer.
            unsafe { *siglen = c_uint::try_from(size).unwrap_or(0) };
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let s = unsafe { ECDSA_do_sign_ex(dgst, dlen, kinv, r, eckey) };
        if s.is_null() {
            // SAFETY: the caller's pointer.
            unsafe { *siglen = 0 };
            return 0;
        }
        let mut out = sig;
        // SAFETY: the signature; the caller's buffer, or none.
        let n = unsafe { i2d_ECDSA_SIG(s, if sig.is_null() { ptr::null_mut() } else { &raw mut out }) };
        // SAFETY: the caller's pointer; OpenSSL stores the length (-1 too) as unsigned.
        unsafe { *siglen = n.cast_unsigned() };
        // SAFETY: the signature made above.
        unsafe { ECDSA_SIG_free(s) };
        1
    }
}

ffi_callback! {
    /// `ossl_ecdsa_verify`: 1 for a valid DER signature (exactly DER, nothing after it), 0 for
    /// an invalid one, -1 on error.
    ///
    /// # Safety
    /// As for `ECDSA_verify`.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_verify(type_: c_int, dgst: *const c_uchar, dgst_len: c_int, sigbuf: *const c_uchar, sig_len: c_int, eckey: *mut EC_KEY) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        let _ = type_;
        // SAFETY: no preconditions.
        let mut s = unsafe { ECDSA_SIG_new() };
        if s.is_null() {
            return -1;
        }
        let mut p = sigbuf;
        let ret = (|| {
            // SAFETY: the signature; the caller's octets.
            if unsafe { d2i_ECDSA_SIG(&raw mut s, &raw mut p, c_long::from(sig_len)) }.is_null() {
                return -1;
            }
            // SAFETY: the signature decoded.
            let Some(der) = (unsafe { sig(s) }).and_then(|sg| unsafe { sig_der(sg) }) else {
                return -1;
            };
            let Ok(n) = usize::try_from(sig_len) else { return -1 };
            // SAFETY: the caller's `sig_len` octets.
            let given = unsafe { core::slice::from_raw_parts(sigbuf, n) };
            if der != given {
                return -1;
            }
            // SAFETY: the caller's digest and key; the signature.
            unsafe { ECDSA_do_verify(dgst, dgst_len, s, eckey) }
        })();
        // SAFETY: the signature made above.
        unsafe { ECDSA_SIG_free(s) };
        ret
    }
}

ffi_callback! {
    /// `ossl_ecdsa_simple_verify_sig`: 1 for a valid signature, 0 for an invalid one, -1 on
    /// error.
    ///
    /// # Safety
    /// As for `ECDSA_do_verify`.
    pub(crate) unsafe extern "C" fn ossl_ecdsa_verify_sig(dgst: *const c_uchar, dgst_len: c_int, sig: *const ECDSA_SIG, eckey: *mut EC_KEY) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        const F: &str = "ossl_ecdsa_simple_verify_sig";
        // SAFETY: the caller's guarantee.
        let group = if eckey.is_null() { ptr::null() } else { unsafe { EC_KEY_get0_group(eckey) } };
        // SAFETY: as above.
        let pub_key = if group.is_null() { ptr::null() } else { unsafe { EC_KEY_get0_public_key(eckey) } };
        // SAFETY: as above.
        let sg = unsafe { self::sig(sig) };
        let Some(sg) = sg.filter(|_| !pub_key.is_null()) else {
            raise(EC_R_MISSING_PARAMETERS, F);
            return -1;
        };
        // SAFETY: as above.
        if unsafe { EC_KEY_can_sign(eckey) } == 0 {
            raise(EC_R_CURVE_DOES_NOT_SUPPORT_SIGNING, F);
            return -1;
        }
        // SAFETY: the key's group.
        let order_p = unsafe { EC_GROUP_get0_order(group) };
        // SAFETY: the group's number.
        let Some(order) = (unsafe { value(order_p) }) else {
            raise(ERR_R_EC_LIB, F);
            return -1;
        };
        // SAFETY: the signature's numbers, or NULL.
        let (r, s) = (unsafe { value(sg.r) }, unsafe { value(sg.s) });
        let in_range = |v: &Option<BigNum>| {
            v.as_ref().is_some_and(|v| !v.is_zero() && !v.is_negative() && rustyssl_crypto::bn::ucmp(v, &order).is_lt())
        };
        if !in_range(&r) || !in_range(&s) {
            raise(EC_R_BAD_SIGNATURE, F);
            return 0;
        }
        let (Some(r), Some(s)) = (r, s) else { return 0 };
        let Some(w) = ecdsa_core::inverse_mod_order(&order, &s) else {
            raise(ERR_R_BN_LIB, F);
            return -1;
        };
        // SAFETY: the caller's digest.
        let Some(d) = (unsafe { digest(dgst, dgst_len) }) else {
            raise(ERR_R_BN_LIB, F);
            return -1;
        };
        let m = ecdsa_core::digest_to_int(d, order.num_bits());
        let mulmod = |a: &BigNum, b: &BigNum| {
            rustyssl_crypto::bn::mul(a, b).and_then(|p| rustyssl_crypto::bn::nnmod(&p, &order)).ok()
        };
        let (Some(u1), Some(u2)) = (mulmod(&m, &w), mulmod(&r, &w)) else {
            raise(ERR_R_BN_LIB, F);
            return -1;
        };
        let (bu1, bu2) = (new_bignum(u1, false), new_bignum(u2, false));
        // SAFETY: the group.
        let point = unsafe { EC_POINT_new(group) };
        // SAFETY: no preconditions.
        let x = unsafe { BN_new() };
        // SAFETY: the key's context.
        let libctx = unsafe { key(eckey) }.map_or(ptr::null_mut(), |k| k.get().libctx.0);
        // SAFETY: as above.
        let ctx = unsafe { BN_CTX_new_ex(libctx) };
        let ret = (|| {
            if ctx.is_null() || bu1.is_null() || bu2.is_null() || x.is_null() {
                raise(ERR_R_BN_LIB, F);
                return -1;
            }
            if point.is_null() {
                raise(ERR_R_EC_LIB, F);
                return -1;
            }
            // SAFETY: the group, the point, the numbers, the key, and the context.
            if unsafe { EC_POINT_mul(group, point, bu1, pub_key, bu2, ctx) } == 0 {
                raise(ERR_R_EC_LIB, F);
                return -1;
            }
            // SAFETY: as above.
            if unsafe { EC_POINT_get_affine_coordinates(group, point, x, ptr::null_mut(), ctx) } == 0 {
                raise(ERR_R_EC_LIB, F);
                return -1;
            }
            // SAFETY: the number.
            let Some(xv) = (unsafe { value(x) }) else { return -1 };
            let Ok(v) = rustyssl_crypto::bn::nnmod(&xv, &order) else {
                raise(ERR_R_BN_LIB, F);
                return -1;
            };
            c_int::from(rustyssl_crypto::bn::ucmp(&v, &r).is_eq())
        })();
        for b in [bu1, bu2, x] {
            // SAFETY: made above, or NULL.
            unsafe { BN_clear_free(b) };
        }
        // SAFETY: as above.
        unsafe { EC_POINT_free(point) };
        // SAFETY: as above.
        unsafe { BN_CTX_free(ctx) };
        ret
    }
}

ffi_callback! {
    /// `ossl_ecdh_simple_compute_key`: the x coordinate of `priv * pub` (times the cofactor
    /// with `EC_FLAG_COFACTOR_ECDH`) in the field's length, in a new buffer.
    ///
    /// # Safety
    /// As for `ECDH_compute_key`.
    pub(crate) unsafe extern "C" fn ossl_ecdh_compute_key(psec: *mut *mut c_uchar, pseclen: *mut usize, pub_key: *const EC_POINT, ecdh: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "ossl_ecdh_simple_compute_key";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(ecdh) }) else { return 0 };
        let f = k.get();
        // SAFETY: the key's context.
        let ctx = unsafe { BN_CTX_new_ex(f.libctx.0) };
        if ctx.is_null() {
            return 0;
        }
        // SAFETY: no preconditions.
        let x = unsafe { BN_secure_new() };
        let mut tmp: *mut EC_POINT = ptr::null_mut();
        let ok = (|| {
            if x.is_null() {
                raise(ERR_R_BN_LIB, F);
                return false;
            }
            let mut priv_key = f.priv_key.0.cast_const();
            if priv_key.is_null() {
                raise(EC_R_MISSING_PRIVATE_KEY, F);
                return false;
            }
            let group = f.group.0;
            // SAFETY: the key.
            if unsafe { EC_KEY_get_flags(ecdh) } & EC_FLAG_COFACTOR_ECDH != 0 {
                // SAFETY: the group; the number.
                if unsafe { EC_GROUP_get_cofactor(group, x, ptr::null_mut()) } == 0 {
                    raise(ERR_R_EC_LIB, F);
                    return false;
                }
                // SAFETY: live numbers.
                let (Some(h), Some(d)) = (unsafe { value(x) }, unsafe { value(priv_key) }) else { return false };
                // SAFETY: the number.
                if !rustyssl_crypto::bn::mul(&h, &d).is_ok_and(|v| unsafe { store(x, v) }) {
                    raise(ERR_R_BN_LIB, F);
                    return false;
                }
                priv_key = x;
            }
            // SAFETY: the group.
            tmp = unsafe { EC_POINT_new(group) };
            if tmp.is_null() {
                raise(ERR_R_EC_LIB, F);
                return false;
            }
            // SAFETY: the group, the point, the peer's point, the number, and the context.
            if unsafe { EC_POINT_mul(group, tmp, ptr::null(), pub_key, priv_key, ctx) } == 0 {
                raise(EC_R_POINT_ARITHMETIC_FAILURE, F);
                return false;
            }
            // SAFETY: as above.
            if unsafe { EC_POINT_get_affine_coordinates(group, tmp, x, ptr::null_mut(), ctx) } == 0 {
                raise(EC_R_POINT_ARITHMETIC_FAILURE, F);
                return false;
            }
            // SAFETY: the group.
            let degree = usize::try_from(unsafe { EC_GROUP_get_degree(group) }).unwrap_or(0);
            let buflen = degree.saturating_add(7) / 8;
            // SAFETY: the number.
            let Some(xv) = (unsafe { value(x) }) else { return false };
            if xv.num_bytes() > buflen {
                raise(ERR_R_INTERNAL_ERROR, F);
                return false;
            }
            let Some(bytes) = xv.to_bin(Some(buflen), rustyssl_crypto::bn::Endian::Big, false) else {
                raise(ERR_R_BN_LIB, F);
                return false;
            };
            let buf: *mut c_uchar = mem::malloc(buflen, ptr::null(), 0).cast();
            if buf.is_null() {
                return false;
            }
            // SAFETY: room for `buflen` octets.
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buf, buflen) };
            // SAFETY: the caller's pointers.
            unsafe { *psec = buf };
            // SAFETY: as above.
            unsafe { *pseclen = buflen };
            true
        })();
        // SAFETY: made above.
        unsafe { BN_clear_free(x) };
        // SAFETY: made above, or NULL.
        unsafe { EC_POINT_clear_free(tmp) };
        // SAFETY: as above.
        unsafe { BN_CTX_free(ctx) };
        c_int::from(ok)
    }
}

/// The key's method, or `None` (with no key).
///
/// # Safety
/// `k` is NULL or a live key.
unsafe fn meth(k: *const EC_KEY) -> Option<super::key::Method> {
    // SAFETY: the caller's guarantee.
    let key = unsafe { key(k) }?;
    // SAFETY: the key's method.
    unsafe { method(EcKey::get(key).meth.0) }
}

ffi_export! {
    /// Signs the digest with the key's method; the signature, or NULL.
    ///
    /// # Safety
    /// `dgst` holds `dlen` octets; `eckey` is a live key.
    pub unsafe extern "C" fn ECDSA_do_sign(dgst: *const c_uchar, dlen: c_int, eckey: *mut EC_KEY) -> *mut ECDSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { ECDSA_do_sign_ex(dgst, dlen, ptr::null(), ptr::null(), eckey) }
    }
}

ffi_export! {
    /// Signs the digest with the key's method, with the given setup values if both are given.
    ///
    /// # Safety
    /// `dgst` holds `dlen` octets; `kinv` and `rp` are NULL or live numbers; `eckey` is a live
    /// key.
    pub unsafe extern "C" fn ECDSA_do_sign_ex(dgst: *const c_uchar, dlen: c_int, kinv: *const BIGNUM, rp: *const BIGNUM, eckey: *mut EC_KEY) -> *mut ECDSA_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        match unsafe { meth(eckey) }.and_then(|m| m.sign_sig) {
            // SAFETY: the method's function takes these.
            Some(f) => unsafe { f(dgst, dlen, kinv, rp, eckey) },
            None => {
                raise(EC_R_OPERATION_NOT_SUPPORTED, "ECDSA_do_sign_ex");
                ptr::null_mut()
            }
        }
    }
}

ffi_export! {
    /// Signs the digest into `sig` as DER, with the key's method. 1, or 0.
    ///
    /// # Safety
    /// As for `ECDSA_sign_ex`.
    pub unsafe extern "C" fn ECDSA_sign(type_: c_int, dgst: *const c_uchar, dlen: c_int, sig: *mut c_uchar, siglen: *mut c_uint, eckey: *mut EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { ECDSA_sign_ex(type_, dgst, dlen, sig, siglen, ptr::null(), ptr::null(), eckey) }
    }
}

ffi_export! {
    /// Signs the digest into `sig` as DER (with the given setup values if both are given),
    /// with the key's method. 1, or 0.
    ///
    /// # Safety
    /// `dgst` holds `dlen` octets; `sig` is NULL or has room for `ECDSA_size` octets;
    /// `siglen` is writable; `kinv` and `r` are NULL or live numbers; `eckey` is a live key.
    pub unsafe extern "C" fn ECDSA_sign_ex(type_: c_int, dgst: *const c_uchar, dlen: c_int, sig: *mut c_uchar, siglen: *mut c_uint, kinv: *const BIGNUM, rp: *const BIGNUM, eckey: *mut EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        match unsafe { meth(eckey) }.and_then(|m| m.sign) {
            // SAFETY: the method's function takes these.
            Some(f) => unsafe { f(type_, dgst, dlen, sig, siglen, kinv, rp, eckey) },
            None => {
                raise(EC_R_OPERATION_NOT_SUPPORTED, "ECDSA_sign_ex");
                0
            }
        }
    }
}

ffi_export! {
    /// Makes a nonce's inverse and r for a later signature, with the key's method. 1, or 0.
    ///
    /// # Safety
    /// `eckey` is a live key; `ctx_in` is NULL or a live context; `kinvp` and `rp` are
    /// writable and hold NULL or numbers the caller owns.
    pub unsafe extern "C" fn ECDSA_sign_setup(eckey: *mut EC_KEY, ctx_in: *mut BN_CTX, kinvp: *mut *mut BIGNUM, rp: *mut *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        match unsafe { meth(eckey) }.and_then(|m| m.sign_setup) {
            // SAFETY: the method's function takes these.
            Some(f) => unsafe { f(eckey, ctx_in, kinvp, rp) },
            None => {
                raise(EC_R_OPERATION_NOT_SUPPORTED, "ECDSA_sign_setup");
                0
            }
        }
    }
}

ffi_export! {
    /// Verifies a signature with the key's method: 1, 0, or -1 on error.
    ///
    /// # Safety
    /// `dgst` holds `dgst_len` octets; `sig` is NULL or a live signature; `eckey` is a live
    /// key.
    pub unsafe extern "C" fn ECDSA_do_verify(dgst: *const c_uchar, dgst_len: c_int, sig: *const ECDSA_SIG, eckey: *mut EC_KEY) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        match unsafe { meth(eckey) }.and_then(|m| m.verify_sig) {
            // SAFETY: the method's function takes these.
            Some(f) => unsafe { f(dgst, dgst_len, sig, eckey) },
            None => {
                raise(EC_R_OPERATION_NOT_SUPPORTED, "ECDSA_do_verify");
                -1
            }
        }
    }
}

ffi_export! {
    /// Verifies a DER signature with the key's method: 1, 0, or -1 on error.
    ///
    /// # Safety
    /// `dgst` holds `dgst_len` octets; `sigbuf` holds `sig_len` octets; `eckey` is a live key.
    pub unsafe extern "C" fn ECDSA_verify(type_: c_int, dgst: *const c_uchar, dgst_len: c_int, sigbuf: *const c_uchar, sig_len: c_int, eckey: *mut EC_KEY) -> c_int
    where failure = -1, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        match unsafe { meth(eckey) }.and_then(|m| m.verify) {
            // SAFETY: the method's function takes these.
            Some(f) => unsafe { f(type_, dgst, dgst_len, sigbuf, sig_len, eckey) },
            None => {
                raise(EC_R_OPERATION_NOT_SUPPORTED, "ECDSA_verify");
                -1
            }
        }
    }
}

/// An application's KDF for `ECDH_compute_key`.
type Kdf = unsafe extern "C" fn(
    in_: *const c_void,
    inlen: usize,
    out: *mut c_void,
    outlen: *mut usize,
) -> *mut c_void;

ffi_export! {
    /// The shared secret with `pub_key` (the key's method's), through `kdf_fn` if given, else cut
    /// to `outlen`, into `out`. Its length, or 0.
    ///
    /// # Safety
    /// `out` has room for `outlen` octets; `pub_key` is a live point of the key's group;
    /// `eckey` is a live key.
    pub unsafe extern "C" fn ECDH_compute_key(out: *mut c_void, outlen: usize, pub_key: *const EC_POINT, eckey: *const EC_KEY, kdf_fn: Option<Kdf>) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "ECDH_compute_key";
        // SAFETY: the caller's guarantee.
        let Some(ck) = (unsafe { meth(eckey) }).and_then(|m| m.compute_key) else {
            raise(EC_R_OPERATION_NOT_SUPPORTED, F);
            return 0;
        };
        if c_int::try_from(outlen).is_err() {
            raise(EC_R_INVALID_OUTPUT_LENGTH, F);
            return 0;
        }
        let mut sec: *mut c_uchar = ptr::null_mut();
        let mut seclen = 0usize;
        // SAFETY: the method's function; locals.
        if unsafe { ck(&raw mut sec, &raw mut seclen, pub_key, eckey) } == 0 {
            return 0;
        }
        let mut n = outlen;
        match kdf_fn {
            Some(kdf) => {
                // SAFETY: the application's function, with the secret and the caller's buffer.
                unsafe { kdf(sec.cast(), seclen, out, &raw mut n) };
            }
            None => {
                n = n.min(seclen);
                // SAFETY: the secret; the caller's room.
                unsafe { ptr::copy_nonoverlapping(sec, out.cast(), n) };
            }
        }
        // SAFETY: the secret from the method, freed once.
        unsafe { mem::release_clean(sec.cast(), seclen) };
        c_int::try_from(n).unwrap_or(0)
    }
}

ffi_export! {
    /// X9.63's KDF of `z` and `sinfo` with `md` (the X963KDF of the default library
    /// context). 1, or 0.
    ///
    /// # Safety
    /// `out` has room for `outlen` octets; `z` and `sinfo` hold their lengths; `md` is a live
    /// digest.
    pub unsafe extern "C" fn ECDH_KDF_X9_62(out: *mut c_uchar, outlen: usize, z: *const c_uchar, z_len: usize, sinfo: *const c_uchar, sinfolen: usize, md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's digest.
        let mdname = unsafe { EVP_MD_get0_name(md) };
        if mdname.is_null() {
            return 0;
        }
        // SAFETY: a name.
        let kdf = unsafe { EVP_KDF_fetch(ptr::null_mut(), c"X963KDF".as_ptr(), ptr::null()) };
        // SAFETY: the KDF, or NULL.
        let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
        let mut ret = 0;
        if !kctx.is_null() {
            // SAFETY: a static key; the digest's name, read only.
            let p0 = unsafe { OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST.as_ptr(), mdname.cast_mut(), 0) };
            // SAFETY: as above; the caller's octets, read only.
            let p1 = unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY.as_ptr(), z.cast_mut().cast(), z_len) };
            // SAFETY: as above.
            let p2 = unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO.as_ptr(), sinfo.cast_mut().cast(), sinfolen) };
            // SAFETY: no preconditions.
            let params = [p0, p1, p2, unsafe { OSSL_PARAM_construct_end() }];
            // SAFETY: the context; the caller's room; the parameters.
            ret = c_int::from(unsafe { EVP_KDF_derive(kctx, out, outlen, params.as_ptr()) } > 0);
            // SAFETY: made above.
            unsafe { EVP_KDF_CTX_free(kctx) };
        }
        // SAFETY: made above, or NULL.
        unsafe { EVP_KDF_free(kdf) };
        ret
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::NID_X9_62_prime256v1;

    use super::*;
    use crate::ec::key::{EC_KEY_free, EC_KEY_generate_key, EC_KEY_new_by_curve_name};

    /// docs/DEVIATIONS.md: OpenSSL's dereference NULL keys, signatures, and outputs, and the
    /// missing numbers of an empty signature.
    #[test]
    fn null_and_empty_arguments_fail() {
        let d = [0u8; 32];
        // SAFETY: no preconditions.
        let empty = unsafe { ECDSA_SIG_new() };
        // SAFETY: no preconditions.
        let k = unsafe { EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) };
        // SAFETY: a live key.
        assert_eq!(unsafe { EC_KEY_generate_key(k) }, 1);
        // SAFETY: an empty signature.
        assert_eq!(unsafe { i2d_ECDSA_SIG(empty, ptr::null_mut()) }, -1);
        // SAFETY: a digest, an empty signature, and a key.
        assert_eq!(unsafe { ECDSA_do_verify(d.as_ptr(), 32, empty, k) }, 0);
        // SAFETY: a digest; NULL.
        assert!(unsafe { ECDSA_do_sign(d.as_ptr(), 32, ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        let v = unsafe { ECDSA_verify(0, d.as_ptr(), 32, d.as_ptr(), 8, ptr::null_mut()) };
        assert_eq!(v, -1);
        // SAFETY: NULL.
        assert!(unsafe { ECDSA_SIG_get0_r(ptr::null()) }.is_null());
        // SAFETY: a buffer; NULL.
        let n = unsafe {
            ECDH_compute_key(
                d.as_ptr().cast_mut().cast(),
                32,
                ptr::null(),
                ptr::null(),
                None,
            )
        };
        assert_eq!(n, 0);
        // SAFETY: a key; NULL outputs.
        let r = unsafe { ECDSA_sign_setup(k, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(r, 0);
        let mut sig = [0u8; 80];
        // SAFETY: a digest, a buffer, a key; a NULL length.
        let r = unsafe { ECDSA_sign(0, d.as_ptr(), 32, sig.as_mut_ptr(), ptr::null_mut(), k) };
        assert_eq!(r, 0);
        // SAFETY: made above, freed once.
        unsafe { ECDSA_SIG_free(empty) };
        // SAFETY: as above.
        unsafe { EC_KEY_free(k) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
