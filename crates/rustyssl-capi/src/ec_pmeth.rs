//! The built-in EC `EVP_PKEY_METHOD`'s functions (`ec_pmeth.c`). A key whose `EC_KEY` has an
//! application's method (a "foreign" key) stays a legacy key, and its contexts use these
//! instead of a provider; an application that copies or wraps the built-in method
//! (`EVP_PKEY_meth_find`, `EVP_PKEY_meth_copy`) calls them too.
//!
//! As in OpenSSL, each operation is made of the `EC_KEY` functions, so it goes through the key's
//! method: signing is `ECDSA_sign` with the digest's type (SHA-1's without one), verifying
//! `ECDSA_verify`, deriving `ECDH_compute_key` (with a copy of the key flagged for the
//! cofactor mode the context sets), then X9.63's KDF when one is set. Parameter and key
//! generation take the context's curve, or the parameters of its key.
//!
//! OpenSSL's ctrl writes through NULL pointers where its own `EVP_PKEY_CTX_get_ecdh_kdf_outlen`
//! passes one, dereferences a context without a key, and takes keying material of a negative
//! length; this one answers, refuses, or keeps it safe instead (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    EC_FLAG_COFACTOR_ECDH, EC_GROUP, EC_KEY, EC_R_BUFFER_TOO_SMALL, EC_R_INVALID_CURVE,
    EC_R_INVALID_DIGEST, EC_R_INVALID_DIGEST_TYPE, EC_R_KEYS_NOT_SET, EC_R_NO_PARAMETERS_SET,
    ERR_LIB_EC, ERR_R_UNSUPPORTED, EVP_MD, EVP_PKEY, EVP_PKEY_CTRL_CMS_SIGN,
    EVP_PKEY_CTRL_DIGESTINIT, EVP_PKEY_CTRL_EC_ECDH_COFACTOR, EVP_PKEY_CTRL_EC_KDF_MD,
    EVP_PKEY_CTRL_EC_KDF_OUTLEN, EVP_PKEY_CTRL_EC_KDF_TYPE, EVP_PKEY_CTRL_EC_KDF_UKM,
    EVP_PKEY_CTRL_EC_PARAM_ENC, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, EVP_PKEY_CTRL_GET_EC_KDF_MD,
    EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, EVP_PKEY_CTRL_GET_EC_KDF_UKM, EVP_PKEY_CTRL_GET_MD,
    EVP_PKEY_CTRL_MD, EVP_PKEY_CTRL_PEER_KEY, EVP_PKEY_CTRL_PKCS7_SIGN, EVP_PKEY_CTX, EVP_PKEY_EC,
    EVP_PKEY_ECDH_KDF_NONE, EVP_PKEY_ECDH_KDF_X9_63, NID_ecdsa_with_SHA1, NID_sha1, NID_sha3_224,
    NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha224, NID_sha256, NID_sha384, NID_sha512,
    NID_sm3, NID_undef, OPENSSL_EC_NAMED_CURVE,
};

use crate::bn::BN_is_one;
use crate::ec::curves::EC_curve_nist2nid;
use crate::ec::ecdsa::{ECDH_compute_key, ECDSA_sign, ECDSA_size, ECDSA_verify, kdf_x9_63};
use crate::ec::group::{
    EC_GROUP_dup, EC_GROUP_free, EC_GROUP_get_degree, EC_GROUP_get0_cofactor,
    EC_GROUP_new_by_curve_name, EC_GROUP_set_asn1_flag,
};
use crate::ec::key::{
    EC_KEY_clear_flags, EC_KEY_dup, EC_KEY_free, EC_KEY_generate_key, EC_KEY_get_flags,
    EC_KEY_get0_group, EC_KEY_get0_public_key, EC_KEY_new, EC_KEY_set_flags, EC_KEY_set_group,
};
use crate::err;
use crate::evp::digest::EVP_MD_get_type;
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::pkey::ec::EVP_PKEY_get0_EC_KEY;
use crate::evp::pkey::{EVP_PKEY_assign, EVP_PKEY_copy_parameters};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get_data, EVP_PKEY_CTX_get0_libctx, EVP_PKEY_CTX_get0_peerkey,
    EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_get0_propq, EVP_PKEY_CTX_set_data,
};
use crate::evp::setters::{
    EVP_PKEY_CTX_set_ec_param_enc, EVP_PKEY_CTX_set_ec_paramgen_curve_nid,
    EVP_PKEY_CTX_set_ecdh_cofactor_mode, EVP_PKEY_CTX_set_ecdh_kdf_md,
};
use crate::ffi::{bytes, ffi_callback};
use crate::mem;
use crate::objects::{OBJ_ln2nid, OBJ_sn2nid};

/// The digests a signature may name (`EVP_PKEY_CTRL_MD`).
const SIGN_DIGESTS: [c_int; 11] = [
    NID_sha1,
    NID_ecdsa_with_SHA1,
    NID_sha224,
    NID_sha256,
    NID_sha384,
    NID_sha512,
    NID_sha3_224,
    NID_sha3_256,
    NID_sha3_384,
    NID_sha3_512,
    NID_sm3,
];

/// `EC_PKEY_CTX`.
struct EcPkeyCtx {
    /// The parameter generation's group (owned), or NULL.
    gen_group: *mut EC_GROUP,
    md: *const EVP_MD,
    /// A copy of the key flagged for the cofactor mode (owned), or NULL.
    co_key: *mut EC_KEY,
    cofactor_mode: c_int,
    kdf_type: c_int,
    kdf_md: *const EVP_MD,
    /// Owned, from the C allocator (`EVP_PKEY_CTX_set0_ecdh_kdf_ukm`'s).
    kdf_ukm: *mut c_uchar,
    kdf_ukmlen: usize,
    kdf_outlen: usize,
}

impl Drop for EcPkeyCtx {
    fn drop(&mut self) {
        // SAFETY: the context's own group, or NULL.
        unsafe { EC_GROUP_free(self.gen_group) };
        // SAFETY: the context's own key, or NULL.
        unsafe { EC_KEY_free(self.co_key) };
        // SAFETY: the context's own octets, or NULL, from the C allocator.
        unsafe { mem::release(self.kdf_ukm.cast()) };
    }
}

/// The context's settings.
///
/// # Safety
/// `ctx` is NULL or a live context whose data is NULL or an `EcPkeyCtx`; nothing else uses the
/// settings while the reference lives.
unsafe fn settings<'a>(ctx: *const EVP_PKEY_CTX) -> Option<&'a mut EcPkeyCtx> {
    // SAFETY: the caller's guarantee.
    let data = unsafe { EVP_PKEY_CTX_get_data(ctx) };
    // SAFETY: as above.
    unsafe { data.cast::<EcPkeyCtx>().as_mut() }
}

/// The `EC_KEY` of a key (`EVP_PKEY_get0_EC_KEY`), or NULL.
///
/// # Safety
/// `pkey` is NULL or a live key.
unsafe fn ec_of(pkey: *const EVP_PKEY) -> *mut EC_KEY {
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's key.
    unsafe { EVP_PKEY_get0_EC_KEY(pkey) }.cast_mut()
}

/// The context's key's `EC_KEY`, or NULL.
///
/// # Safety
/// `ctx` is NULL or a live context.
unsafe fn key(ctx: *mut EVP_PKEY_CTX) -> *mut EC_KEY {
    // SAFETY: the caller's guarantee.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
    // SAFETY: the context's key, or NULL.
    unsafe { ec_of(pkey) }
}

/// The digest's NID, SHA-1's for none.
///
/// # Safety
/// `md` is NULL or a live digest.
unsafe fn md_type(md: *const EVP_MD) -> c_int {
    if md.is_null() {
        NID_sha1
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { EVP_MD_get_type(md) }
    }
}

fn raise(reason: c_int, func: &str) {
    err::raise(ERR_LIB_EC, reason, func);
}

ffi_callback! {
    /// `pkey_ec_init`: no cofactor mode set, no KDF.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub(crate) unsafe extern "C" fn pkey_ec_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        let data = Box::into_raw(Box::new(EcPkeyCtx {
            gen_group: ptr::null_mut(),
            md: ptr::null(),
            co_key: ptr::null_mut(),
            cofactor_mode: -1,
            kdf_type: EVP_PKEY_ECDH_KDF_NONE,
            kdf_md: ptr::null(),
            kdf_ukm: ptr::null_mut(),
            kdf_ukmlen: 0,
            kdf_outlen: 0,
        }));
        // SAFETY: the context; the settings it owns until `pkey_ec_cleanup`.
        unsafe { EVP_PKEY_CTX_set_data(ctx, data.cast()) };
        1
    }
}

ffi_callback! {
    /// `pkey_ec_copy`: `dst`'s settings from `src`'s, with copies of the group, the cofactor
    /// key, and the keying material (not the cofactor mode, as in OpenSSL).
    ///
    /// # Safety
    /// `dst` and `src` are live contexts; `src`'s data is its settings.
    pub(crate) unsafe extern "C" fn pkey_ec_copy(dst: *mut EVP_PKEY_CTX, src: *const EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        if unsafe { pkey_ec_init(dst) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let (Some(s), Some(d)) = (unsafe { settings(src) }, unsafe { settings(dst) }) else {
            return 0;
        };
        if !s.gen_group.is_null() {
            // SAFETY: the source's group.
            d.gen_group = unsafe { EC_GROUP_dup(s.gen_group) };
            if d.gen_group.is_null() {
                return 0;
            }
        }
        d.md = s.md;
        if !s.co_key.is_null() {
            // SAFETY: the source's key.
            d.co_key = unsafe { EC_KEY_dup(s.co_key) };
            if d.co_key.is_null() {
                return 0;
            }
        }
        d.kdf_type = s.kdf_type;
        d.kdf_md = s.kdf_md;
        d.kdf_outlen = s.kdf_outlen;
        if !s.kdf_ukm.is_null() {
            let copy: *mut c_uchar = mem::alloc(s.kdf_ukmlen.max(1)).cast();
            if copy.is_null() {
                return 0;
            }
            // SAFETY: the source's `kdf_ukmlen` octets; a block that size.
            unsafe { ptr::copy_nonoverlapping(s.kdf_ukm, copy, s.kdf_ukmlen) };
            d.kdf_ukm = copy;
        }
        d.kdf_ukmlen = s.kdf_ukmlen;
        1
    }
}

ffi_callback! {
    /// `pkey_ec_cleanup`: frees the settings.
    ///
    /// # Safety
    /// `ctx` is a live context whose data is NULL or its settings.
    pub(crate) unsafe extern "C" fn pkey_ec_cleanup(ctx: *mut EVP_PKEY_CTX)
    where failure = (), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let data = unsafe { EVP_PKEY_CTX_get_data(ctx) };
        if !data.is_null() {
            // SAFETY: the context; its data is gone.
            unsafe { EVP_PKEY_CTX_set_data(ctx, ptr::null_mut()) };
            // SAFETY: the settings `pkey_ec_init` made, freed once.
            drop(unsafe { Box::from_raw(data.cast::<EcPkeyCtx>()) });
        }
    }
}

ffi_callback! {
    /// `pkey_ec_sign`: `ECDSA_sign` with the digest's type (SHA-1's without one), or the
    /// signature's size for NULL `sig`.
    ///
    /// # Safety
    /// `ctx` is a live context; `sig` is NULL or has room for `*siglen` octets; `siglen` is
    /// readable and writable; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn pkey_ec_sign(ctx: *mut EVP_PKEY_CTX, sig: *mut c_uchar, siglen: *mut usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        // SAFETY: as above.
        let ec = unsafe { key(ctx) };
        // SAFETY: the key, or NULL.
        let Some(sig_sz) = usize::try_from(unsafe { ECDSA_size(ec) }).ok().filter(|&s| s > 0) else {
            return 0;
        };
        if sig.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { siglen.write(sig_sz) };
            return 1;
        }
        // SAFETY: as above.
        if unsafe { siglen.read() } < sig_sz {
            raise(EC_R_BUFFER_TOO_SMALL, "pkey_ec_sign");
            return 0;
        }
        // OpenSSL passes the length as an int, cut short past INT_MAX; this fails instead.
        let Ok(dlen) = c_int::try_from(tbslen) else { return 0 };
        let mut sltmp = 0;
        // SAFETY: the context's digest, or NULL.
        let type_ = unsafe { md_type(d.md) };
        // SAFETY: the caller's input and room; a local; the key.
        let ret = unsafe { ECDSA_sign(type_, tbs, dlen, sig, &raw mut sltmp, ec) };
        if ret <= 0 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        unsafe { siglen.write(sltmp as usize) };
        1
    }
}

ffi_callback! {
    /// `pkey_ec_verify`: `ECDSA_verify` with the digest's type (SHA-1's without one).
    ///
    /// # Safety
    /// `ctx` is a live context; `sig` holds `siglen` octets; `tbs` holds `tbslen`.
    pub(crate) unsafe extern "C" fn pkey_ec_verify(ctx: *mut EVP_PKEY_CTX, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        // OpenSSL passes the lengths as ints, cut short past INT_MAX; this fails instead.
        let (Ok(dlen), Ok(slen)) = (c_int::try_from(tbslen), c_int::try_from(siglen)) else {
            return 0;
        };
        // SAFETY: the context's digest, or NULL.
        let type_ = unsafe { md_type(d.md) };
        // SAFETY: the caller's guarantee.
        let ec = unsafe { key(ctx) };
        // SAFETY: the caller's input; the key.
        unsafe { ECDSA_verify(type_, tbs, dlen, sig, slen, ec) }
    }
}

/// `pkey_ec_derive`: the shared secret, cut to `*keylen`, or its size for NULL `out`.
///
/// # Safety
/// `ctx` is a live context with settings `d`; `out` is NULL or has room for `*keylen` octets;
/// `keylen` is readable and writable.
unsafe fn plain_derive(
    ctx: *mut EVP_PKEY_CTX,
    d: &EcPkeyCtx,
    out: *mut c_uchar,
    keylen: *mut usize,
) -> c_int {
    const F: &str = "pkey_ec_derive";
    // SAFETY: the caller's guarantee.
    let (pkey, peer) = (unsafe { EVP_PKEY_CTX_get0_pkey(ctx) }, unsafe {
        EVP_PKEY_CTX_get0_peerkey(ctx)
    });
    if pkey.is_null() || peer.is_null() {
        raise(EC_R_KEYS_NOT_SET, F);
        return 0;
    }
    // SAFETY: the context's peer key.
    let eckeypub = unsafe { ec_of(peer) };
    if eckeypub.is_null() {
        raise(EC_R_KEYS_NOT_SET, F);
        return 0;
    }
    let eckey = if d.co_key.is_null() {
        // SAFETY: the context's key.
        unsafe { ec_of(pkey) }
    } else {
        d.co_key
    };
    if out.is_null() {
        let group = if eckey.is_null() {
            ptr::null()
        } else {
            // SAFETY: the key.
            unsafe { EC_KEY_get0_group(eckey) }
        };
        if group.is_null() {
            return 0;
        }
        // SAFETY: the key's group.
        let degree = usize::try_from(unsafe { EC_GROUP_get_degree(group) }).unwrap_or(0);
        // SAFETY: the caller's guarantee.
        unsafe { keylen.write(degree.div_ceil(8)) };
        return 1;
    }
    // SAFETY: the peer's key.
    let pubkey = unsafe { EC_KEY_get0_public_key(eckeypub) };
    // SAFETY: the caller's guarantee.
    let room = unsafe { keylen.read() };
    // SAFETY: the caller's room for `room` octets; the point; the key.
    let ret = unsafe { ECDH_compute_key(out.cast(), room, pubkey, eckey, None) };
    let Some(n) = usize::try_from(ret).ok().filter(|&n| n > 0) else {
        return 0;
    };
    // SAFETY: the caller's guarantee.
    unsafe { keylen.write(n) };
    1
}

ffi_callback! {
    /// `pkey_ec_kdf_derive`: the shared secret, or X9.63's KDF of it into exactly the KDF's
    /// length.
    ///
    /// # Safety
    /// `ctx` is a live context; `key` is NULL or has room for `*keylen` octets; `keylen` is
    /// readable and writable.
    pub(crate) unsafe extern "C" fn pkey_ec_kdf_derive(ctx: *mut EVP_PKEY_CTX, key: *mut c_uchar, keylen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        if d.kdf_type == EVP_PKEY_ECDH_KDF_NONE {
            // SAFETY: the caller's guarantee.
            return unsafe { plain_derive(ctx, d, key, keylen) };
        }
        if key.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { keylen.write(d.kdf_outlen) };
            return 1;
        }
        // SAFETY: as above.
        if unsafe { keylen.read() } != d.kdf_outlen {
            return 0;
        }
        let mut zlen = 0;
        // SAFETY: the context; a local.
        if unsafe { plain_derive(ctx, d, ptr::null_mut(), &raw mut zlen) } == 0 {
            return 0;
        }
        let mut z = vec![0u8; zlen];
        // SAFETY: room for `zlen` octets; a local.
        let mut ok = unsafe { plain_derive(ctx, d, z.as_mut_ptr(), &raw mut zlen) } == 1;
        if ok {
            // SAFETY: the context's keying material.
            let ukm = unsafe { bytes(d.kdf_ukm, d.kdf_ukmlen) }.unwrap_or_default();
            // SAFETY: the caller's guarantee.
            let (libctx, propq) = (unsafe { EVP_PKEY_CTX_get0_libctx(ctx) }, unsafe {
                EVP_PKEY_CTX_get0_propq(ctx)
            });
            let secret = z.get(..zlen).unwrap_or(&z);
            // SAFETY: the caller's room for `kdf_outlen` octets; the digest, or NULL; the
            // context's library context and query.
            ok = unsafe { kdf_x9_63(key, d.kdf_outlen, secret, ukm, d.kdf_md, libctx, propq) };
        }
        crate::provider::macs::wipe(&mut z);
        c_int::from(ok)
    }
}

ffi_callback! {
    /// `pkey_ec_ctrl`: the curve and its encoding for generation, the cofactor mode, the KDF's
    /// type, digest, length, and keying material, the signature's digest; 1 for the ctrls it
    /// accepts as they are, -2 for others.
    ///
    /// # Safety
    /// `ctx` is a live context; `p2` is what `type_` takes (NULL is refused or answered where
    /// it would be written through).
    pub(crate) unsafe extern "C" fn pkey_ec_ctrl(ctx: *mut EVP_PKEY_CTX, type_: c_int, p1: c_int, p2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "pkey_ec_ctrl";
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        match type_ {
            EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID => {
                // SAFETY: a NID.
                let group = unsafe { EC_GROUP_new_by_curve_name(p1) };
                if group.is_null() {
                    raise(EC_R_INVALID_CURVE, F);
                    return 0;
                }
                // SAFETY: the context's group, or NULL.
                unsafe { EC_GROUP_free(d.gen_group) };
                d.gen_group = group;
                1
            }
            EVP_PKEY_CTRL_EC_PARAM_ENC => {
                if d.gen_group.is_null() {
                    raise(EC_R_NO_PARAMETERS_SET, F);
                    return 0;
                }
                // SAFETY: the context's group.
                unsafe { EC_GROUP_set_asn1_flag(d.gen_group, p1) };
                1
            }
            EVP_PKEY_CTRL_EC_ECDH_COFACTOR => {
                // SAFETY: the caller's guarantee.
                let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
                // SAFETY: the context's key, or NULL.
                let ec = unsafe { ec_of(pkey) };
                if p1 == -2 {
                    if d.cofactor_mode != -1 {
                        return d.cofactor_mode;
                    }
                    // SAFETY: the key, or NULL.
                    return c_int::from(unsafe { EC_KEY_get_flags(ec) } & EC_FLAG_COFACTOR_ECDH != 0);
                }
                if !(-1..=1).contains(&p1) {
                    return -2;
                }
                d.cofactor_mode = p1;
                if p1 == -1 {
                    // SAFETY: the context's key copy, or NULL.
                    unsafe { EC_KEY_free(d.co_key) };
                    d.co_key = ptr::null_mut();
                    return 1;
                }
                // SAFETY: the context's key, or NULL.
                if unsafe { crate::evp::pkey::pkey(pkey) }.is_some_and(|k| k.provided().0.is_some()) {
                    raise(ERR_R_UNSUPPORTED, F);
                    return 0;
                }
                // Without a key, OpenSSL reads its group from NULL; this answers as for a key
                // without a group.
                // SAFETY: the key, or NULL.
                let group = if ec.is_null() { ptr::null() } else { unsafe { EC_KEY_get0_group(ec) } };
                if group.is_null() {
                    return -2;
                }
                // SAFETY: the group.
                let cofactor = unsafe { EC_GROUP_get0_cofactor(group) };
                // SAFETY: the group's number.
                if unsafe { BN_is_one(cofactor) } != 0 {
                    return 1;
                }
                if d.co_key.is_null() {
                    // SAFETY: the context's key.
                    d.co_key = unsafe { EC_KEY_dup(ec) };
                    if d.co_key.is_null() {
                        return 0;
                    }
                }
                if p1 == 1 {
                    // SAFETY: the context's key copy.
                    unsafe { EC_KEY_set_flags(d.co_key, EC_FLAG_COFACTOR_ECDH) };
                } else {
                    // SAFETY: as above.
                    unsafe { EC_KEY_clear_flags(d.co_key, EC_FLAG_COFACTOR_ECDH) };
                }
                1
            }
            EVP_PKEY_CTRL_EC_KDF_TYPE => {
                if p1 == -2 {
                    return d.kdf_type;
                }
                if p1 != EVP_PKEY_ECDH_KDF_NONE && p1 != EVP_PKEY_ECDH_KDF_X9_63 {
                    return -2;
                }
                d.kdf_type = p1;
                1
            }
            EVP_PKEY_CTRL_EC_KDF_MD => {
                d.kdf_md = p2.cast_const().cast();
                1
            }
            EVP_PKEY_CTRL_GET_EC_KDF_MD => {
                if !p2.is_null() {
                    // SAFETY: the caller's place for a digest.
                    unsafe { p2.cast::<*const EVP_MD>().write(d.kdf_md) };
                }
                1
            }
            EVP_PKEY_CTRL_EC_KDF_OUTLEN => {
                let Some(n) = usize::try_from(p1).ok().filter(|&n| n > 0) else { return -2 };
                d.kdf_outlen = n;
                1
            }
            EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN => {
                // Set from a positive int, so it fits.
                let len = c_int::try_from(d.kdf_outlen).unwrap_or(c_int::MAX);
                if p2.is_null() {
                    // `EVP_PKEY_CTX_get_ecdh_kdf_outlen` asks with no place for the length,
                    // which OpenSSL writes through; this returns it, as DH's method does.
                    return len;
                }
                // SAFETY: the caller's place for an int.
                unsafe { p2.cast::<c_int>().write(len) };
                1
            }
            EVP_PKEY_CTRL_EC_KDF_UKM => {
                // A negative length, which OpenSSL takes as a huge one, is refused (the octets
                // stay the caller's).
                let Ok(len) = usize::try_from(p1) else { return 0 };
                // SAFETY: the context's octets, or NULL.
                unsafe { mem::release(d.kdf_ukm.cast()) };
                d.kdf_ukm = p2.cast();
                d.kdf_ukmlen = if p2.is_null() { 0 } else { len };
                1
            }
            EVP_PKEY_CTRL_GET_EC_KDF_UKM => {
                if !p2.is_null() {
                    // SAFETY: the caller's place for a pointer.
                    unsafe { p2.cast::<*mut c_uchar>().write(d.kdf_ukm) };
                }
                // Set from an int, so it fits.
                c_int::try_from(d.kdf_ukmlen).unwrap_or(c_int::MAX)
            }
            EVP_PKEY_CTRL_MD => {
                // SAFETY: the caller's digest, or NULL (whose type is 0).
                let t = unsafe { EVP_MD_get_type(p2.cast_const().cast()) };
                if !SIGN_DIGESTS.contains(&t) {
                    raise(EC_R_INVALID_DIGEST_TYPE, F);
                    return 0;
                }
                d.md = p2.cast_const().cast();
                1
            }
            EVP_PKEY_CTRL_GET_MD => {
                if !p2.is_null() {
                    // SAFETY: the caller's place for a digest.
                    unsafe { p2.cast::<*const EVP_MD>().write(d.md) };
                }
                1
            }
            EVP_PKEY_CTRL_PEER_KEY
            | EVP_PKEY_CTRL_DIGESTINIT
            | EVP_PKEY_CTRL_PKCS7_SIGN
            | EVP_PKEY_CTRL_CMS_SIGN => 1,
            _ => -2,
        }
    }
}

/// C's `atoi`: leading white space, a sign, digits; 0 for none (a value past an int saturates,
/// where C's is undefined).
fn atoi(s: &[u8]) -> c_int {
    let mut it = s
        .iter()
        .copied()
        .skip_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r'))
        .peekable();
    let neg = match it.peek() {
        Some(b'-') => {
            it.next();
            true
        }
        Some(b'+') => {
            it.next();
            false
        }
        _ => false,
    };
    let mut v: i64 = 0;
    for c in it.take_while(u8::is_ascii_digit) {
        v = v.saturating_mul(10).saturating_add(i64::from(c - b'0'));
    }
    let v = if neg { -v } else { v };
    c_int::try_from(v).unwrap_or(if neg { c_int::MIN } else { c_int::MAX })
}

ffi_callback! {
    /// `pkey_ec_ctrl_str`: `ec_paramgen_curve` (a NIST name, short name, or long name),
    /// `ec_param_enc` (`explicit` or `named_curve`), `ecdh_kdf_md`, and `ecdh_cofactor_mode`,
    /// through their EVP setters; -2 for others.
    ///
    /// # Safety
    /// `ctx` is a live context; `type_` and `value` are strings.
    pub(crate) unsafe extern "C" fn pkey_ec_ctrl_str(ctx: *mut EVP_PKEY_CTX, type_: *const c_char, value: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "pkey_ec_ctrl_str";
        if type_.is_null() || value.is_null() {
            return -2;
        }
        // SAFETY: the caller's strings.
        let (t, v) = (unsafe { CStr::from_ptr(type_) }, unsafe { CStr::from_ptr(value) });
        match t.to_bytes() {
            b"ec_paramgen_curve" => {
                // SAFETY: a string.
                let mut nid = unsafe { EC_curve_nist2nid(value) };
                if nid == NID_undef {
                    // SAFETY: as above.
                    nid = unsafe { OBJ_sn2nid(value) };
                }
                if nid == NID_undef {
                    // SAFETY: as above.
                    nid = unsafe { OBJ_ln2nid(value) };
                }
                if nid == NID_undef {
                    raise(EC_R_INVALID_CURVE, F);
                    return 0;
                }
                // SAFETY: the caller's context.
                unsafe { EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) }
            }
            b"ec_param_enc" => {
                let enc = match v.to_bytes() {
                    b"explicit" => 0,
                    b"named_curve" => OPENSSL_EC_NAMED_CURVE,
                    _ => return -2,
                };
                // SAFETY: the caller's context.
                unsafe { EVP_PKEY_CTX_set_ec_param_enc(ctx, enc) }
            }
            b"ecdh_kdf_md" => {
                // SAFETY: a string.
                let md = unsafe { EVP_get_digestbyname(value) };
                if md.is_null() {
                    raise(EC_R_INVALID_DIGEST, F);
                    return 0;
                }
                // SAFETY: the caller's context; the digest.
                unsafe { EVP_PKEY_CTX_set_ecdh_kdf_md(ctx, md) }
            }
            b"ecdh_cofactor_mode" => {
                // SAFETY: the caller's context.
                unsafe { EVP_PKEY_CTX_set_ecdh_cofactor_mode(ctx, atoi(v.to_bytes())) }
            }
            _ => -2,
        }
    }
}

ffi_callback! {
    /// `pkey_ec_paramgen`: an `EC_KEY` of the context's curve, assigned to `pkey`.
    ///
    /// # Safety
    /// `ctx` is a live context; `pkey` is a live key.
    pub(crate) unsafe extern "C" fn pkey_ec_paramgen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        if d.gen_group.is_null() {
            raise(EC_R_NO_PARAMETERS_SET, "pkey_ec_paramgen");
            return 0;
        }
        // SAFETY: no preconditions.
        let ec = unsafe { EC_KEY_new() };
        if ec.is_null() {
            return 0;
        }
        // SAFETY: the new key; the context's group.
        let mut ret = unsafe { EC_KEY_set_group(ec, d.gen_group) };
        if ret != 0 {
            // SAFETY: the caller's key takes the new one.
            ret = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast()) };
        }
        if ret == 0 {
            // SAFETY: the key made above, not taken.
            unsafe { EC_KEY_free(ec) };
        }
        ret
    }
}

ffi_callback! {
    /// `pkey_ec_keygen`: a key of the context's key's parameters, or of its curve.
    ///
    /// # Safety
    /// `ctx` is a live context; `pkey` is a live key.
    pub(crate) unsafe extern "C" fn pkey_ec_keygen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        // SAFETY: as above.
        let template = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
        if template.is_null() && d.gen_group.is_null() {
            raise(EC_R_NO_PARAMETERS_SET, "pkey_ec_keygen");
            return 0;
        }
        // SAFETY: no preconditions.
        let ec = unsafe { EC_KEY_new() };
        if ec.is_null() {
            return 0;
        }
        // SAFETY: the caller's key takes the new one.
        if unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_EC, ec.cast()) } == 0 {
            // SAFETY: the key made above, not taken.
            unsafe { EC_KEY_free(ec) };
            return 0;
        }
        let ret = if template.is_null() {
            // SAFETY: the key; the context's group.
            unsafe { EC_KEY_set_group(ec, d.gen_group) }
        } else {
            // SAFETY: the caller's key; the context's.
            unsafe { EVP_PKEY_copy_parameters(pkey, template) }
        };
        if ret == 0 {
            return 0;
        }
        // SAFETY: the key, now the caller's key's.
        unsafe { EC_KEY_generate_key(ec) }
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::{EVP_PKEY_OP_DERIVE, NID_X9_62_prime256v1};
    use rustyssl_crypto::bn::BigNum;

    use super::*;
    use crate::bn::{BN_clear_free, new_bignum};
    use crate::ec::group::EC_GROUP_get0_generator;
    use crate::ec::key::{
        EC_KEY_METHOD_free, EC_KEY_METHOD_new, EC_KEY_OpenSSL, EC_KEY_new_by_curve_name,
        EC_KEY_set_method, EC_KEY_set_private_key, EC_KEY_set_public_key,
    };
    use crate::evp::ctrl::EVP_PKEY_CTX_ctrl;
    use crate::evp::exchange::EVP_PKEY_derive_init;
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new};
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new};
    use crate::evp::setters::{EVP_PKEY_CTX_get_ecdh_kdf_outlen, EVP_PKEY_CTX_set_ecdh_kdf_outlen};

    /// docs/DEVIATIONS.md: the built-in EC method's ctrl with NULL where OpenSSL writes through
    /// it or reads a key from it, and keying material of a negative length. A foreign key (an
    /// application's copy of OpenSSL's `EC_KEY_METHOD`) keeps its contexts on the method.
    #[test]
    fn ctrl_null_pointers_and_negative_lengths_are_safe() {
        // SAFETY: no preconditions.
        let openssl = unsafe { EC_KEY_OpenSSL() };
        // SAFETY: OpenSSL's method.
        let meth = unsafe { EC_KEY_METHOD_new(openssl) };
        // SAFETY: as above.
        let ec = unsafe { EC_KEY_new_by_curve_name(NID_X9_62_prime256v1) };
        // A key without randomness (which Miri can't draw): private key 1, public key G.
        let one = new_bignum(BigNum::one(), false);
        // SAFETY: a live key and number.
        assert_eq!(unsafe { EC_KEY_set_private_key(ec, one) }, 1);
        // SAFETY: a live key.
        let group = unsafe { EC_KEY_get0_group(ec) };
        // SAFETY: the key's group.
        let g = unsafe { EC_GROUP_get0_generator(group) };
        // SAFETY: a live key and point.
        assert_eq!(unsafe { EC_KEY_set_public_key(ec, g) }, 1);
        // SAFETY: a live key and method.
        assert_eq!(unsafe { EC_KEY_set_method(ec, meth) }, 1);
        // SAFETY: no preconditions.
        let pk = unsafe { EVP_PKEY_new() };
        // SAFETY: the key takes the EC key.
        assert_eq!(unsafe { EVP_PKEY_assign(pk, EVP_PKEY_EC, ec.cast()) }, 1);
        // SAFETY: a live key.
        let ctx = unsafe { EVP_PKEY_CTX_new(pk, ptr::null_mut()) };
        // SAFETY: a live context.
        assert_eq!(unsafe { EVP_PKEY_derive_init(ctx) }, 1);

        // OpenSSL's own getter hands the ctrl NULL for the length.
        // SAFETY: a live context.
        assert_eq!(unsafe { EVP_PKEY_CTX_set_ecdh_kdf_outlen(ctx, 40) }, 1);
        let mut len: c_int = 0;
        // SAFETY: a live context; a local.
        let r = unsafe { EVP_PKEY_CTX_get_ecdh_kdf_outlen(ctx, &raw mut len) };
        assert_eq!(r, 1);
        assert_eq!(len, 40);
        let ctrl = |type_: c_int, p1: c_int, p2: *mut c_void| {
            // SAFETY: a live context.
            unsafe { EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_EC, EVP_PKEY_OP_DERIVE, type_, p1, p2) }
        };
        assert_eq!(
            ctrl(EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, 0, ptr::null_mut()),
            40
        );
        assert_eq!(ctrl(EVP_PKEY_CTRL_GET_EC_KDF_MD, 0, ptr::null_mut()), 1);
        assert_eq!(ctrl(EVP_PKEY_CTRL_GET_EC_KDF_UKM, 0, ptr::null_mut()), 0);
        // Keying material of a negative length is refused and stays the caller's.
        let ukm = mem::alloc(4);
        assert_eq!(ctrl(EVP_PKEY_CTRL_EC_KDF_UKM, -1, ukm), 0);
        // SAFETY: still the test's, freed once.
        unsafe { mem::release(ukm) };
        // SAFETY: a live context.
        let r = unsafe { pkey_ec_ctrl(ctx, EVP_PKEY_CTRL_GET_MD, 0, ptr::null_mut()) };
        assert_eq!(r, 1);
        // SAFETY: as above; NULL is no digest.
        let r = unsafe { pkey_ec_ctrl(ctx, EVP_PKEY_CTRL_MD, 0, ptr::null_mut()) };
        assert_eq!(r, 0);

        // SAFETY: made above, freed once each.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(pk) };
        // SAFETY: as above.
        unsafe { BN_clear_free(one) };
        // SAFETY: as above.
        unsafe { EC_KEY_METHOD_free(meth) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    /// docs/DEVIATIONS.md: the cofactor mode on a context without a key, whose key OpenSSL
    /// reads from NULL: asked, it's the (absent) key's flag, 0; set, -2 as for a key without a
    /// group.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn cofactor_mode_without_a_key_is_answered() {
        // SAFETY: no preconditions.
        let ctx =
            unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ptr::null_mut()) };
        assert!(!ctx.is_null());
        // SAFETY: a live context without data; settings for it.
        assert_eq!(unsafe { pkey_ec_init(ctx) }, 1);
        // SAFETY: as above.
        let r = unsafe { pkey_ec_ctrl(ctx, EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -2, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { pkey_ec_ctrl(ctx, EVP_PKEY_CTRL_EC_ECDH_COFACTOR, 1, ptr::null_mut()) };
        assert_eq!(r, -2);
        // SAFETY: as above.
        let r = unsafe { pkey_ec_ctrl(ctx, EVP_PKEY_CTRL_EC_ECDH_COFACTOR, -2, ptr::null_mut()) };
        assert_eq!(r, 1);
        // SAFETY: the settings made above, freed once.
        unsafe { pkey_ec_cleanup(ctx) };
        // SAFETY: made above, freed once.
        unsafe { EVP_PKEY_CTX_free(ctx) };
    }
}
