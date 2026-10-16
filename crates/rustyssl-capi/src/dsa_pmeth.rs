//! The built-in DSA `EVP_PKEY_METHOD`'s functions (`dsa_pmeth.c`). A key whose `DSA` has an
//! application's method (a "foreign" key) stays a legacy key, and its contexts use these
//! instead of a provider; an application that copies or wraps the built-in method
//! (`EVP_PKEY_meth_find`, `EVP_PKEY_meth_copy`) calls them too.
//!
//! As in OpenSSL, signing and verifying are `DSA_sign` and `DSA_verify` (through the key's
//! method), of a digest of the digest's size when one is set; parameter generation is FIPS
//! 186-4's, of the context's sizes, with the signature's digest (not the one
//! `EVP_PKEY_CTX_set_dsa_paramgen_md` sets, which OpenSSL keeps but never uses); key generation
//! takes the context key's parameters.
//!
//! OpenSSL passes lengths past `INT_MAX` cut short to `DSA_sign` and `DSA_verify`; this fails
//! instead. Its digest getter writes through NULL; this one doesn't.

use core::ffi::{CStr, c_char, c_int, c_uchar, c_uint, c_void};
use core::ptr;

use rustyssl_abi::{
    BN_GENCB, DSA_R_INVALID_DIGEST_TYPE, DSA_R_NO_PARAMETERS_SET, ERR_LIB_DSA, EVP_MD, EVP_PKEY,
    EVP_PKEY_CTRL_CMS_SIGN, EVP_PKEY_CTRL_DIGESTINIT, EVP_PKEY_CTRL_DSA_PARAMGEN_BITS,
    EVP_PKEY_CTRL_DSA_PARAMGEN_MD, EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, EVP_PKEY_CTRL_GET_MD,
    EVP_PKEY_CTRL_MD, EVP_PKEY_CTRL_PEER_KEY, EVP_PKEY_CTRL_PKCS7_SIGN, EVP_PKEY_CTX, EVP_PKEY_DSA,
    EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, NID_dsa, NID_dsaWithSHA, NID_sha1,
    NID_sha3_224, NID_sha3_256, NID_sha3_384, NID_sha3_512, NID_sha224, NID_sha256, NID_sha384,
    NID_sha512,
};

use crate::bn::prime::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set};
use crate::dsa::{DSA_free, DSA_new, dsa};
use crate::dsa_ops::{DSA_generate_key, DSA_sign, DSA_verify};
use crate::ec_pmeth::atoi;
use crate::err;
use crate::evp::digest::{EVP_MD_get_size, EVP_MD_get_type, EVP_MD_get0_name};
use crate::evp::legacy_md::EVP_get_digestbyname;
use crate::evp::pkey::dsa::EVP_PKEY_get0_DSA;
use crate::evp::pkey::{EVP_PKEY_assign, EVP_PKEY_copy_parameters};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get_cb, EVP_PKEY_CTX_get_data, EVP_PKEY_CTX_get0_pkey, EVP_PKEY_CTX_set_data,
    EVP_PKEY_CTX_set0_keygen_info, legacy_gen_progress,
};
use crate::evp::setters::{
    EVP_PKEY_CTX_set_dsa_paramgen_bits, EVP_PKEY_CTX_set_dsa_paramgen_md,
    EVP_PKEY_CTX_set_dsa_paramgen_q_bits,
};
use crate::ffc::{self, Type};
use crate::ffi::ffi_callback;
use crate::rsa_gen::Env;

/// The digests a signature may name (`EVP_PKEY_CTRL_MD`).
const SIGN_DIGESTS: [c_int; 11] = [
    NID_sha1,
    NID_dsa,
    NID_dsaWithSHA,
    NID_sha224,
    NID_sha256,
    NID_sha384,
    NID_sha512,
    NID_sha3_224,
    NID_sha3_256,
    NID_sha3_384,
    NID_sha3_512,
];

/// The digests parameter generation may name (`EVP_PKEY_CTRL_DSA_PARAMGEN_MD`).
const PARAMGEN_DIGESTS: [c_int; 3] = [NID_sha1, NID_sha224, NID_sha256];

/// `DSA_PKEY_CTX`.
struct DsaPkeyCtx {
    /// p's size in bits.
    nbits: c_int,
    /// q's size in bits.
    qbits: c_int,
    /// The parameter generation's digest, or NULL (kept, never used).
    pmd: *const EVP_MD,
    /// What `EVP_PKEY_CTX_get_keygen_info` reads.
    gentmp: [c_int; 2],
    /// The signature's digest, or NULL.
    md: *const EVP_MD,
}

/// The context's settings.
///
/// # Safety
/// `ctx` is NULL or a live context whose data is NULL or a `DsaPkeyCtx`; nothing else uses the
/// settings while the reference lives.
unsafe fn settings<'a>(ctx: *const EVP_PKEY_CTX) -> Option<&'a mut DsaPkeyCtx> {
    // SAFETY: the caller's guarantee.
    let data = unsafe { EVP_PKEY_CTX_get_data(ctx) };
    // SAFETY: as above.
    unsafe { data.cast::<DsaPkeyCtx>().as_mut() }
}

/// The `DSA` of the context's key, or NULL.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn key(ctx: *mut EVP_PKEY_CTX) -> *mut rustyssl_abi::DSA {
    // SAFETY: the caller's guarantee.
    let pkey = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the context's key.
    unsafe { EVP_PKEY_get0_DSA(pkey) }.cast_mut()
}

/// Whether `tbs` fits the context's digest: true without one; false for a digest without a
/// size.
///
/// # Safety
/// `d`'s digest is NULL or live.
unsafe fn fits(d: &DsaPkeyCtx, tbslen: usize) -> bool {
    if d.md.is_null() {
        return true;
    }
    // SAFETY: the context's digest.
    let size = unsafe { EVP_MD_get_size(d.md) };
    usize::try_from(size).is_ok_and(|s| s > 0 && s == tbslen)
}

ffi_callback! {
    /// `pkey_dsa_init`: 2048-bit p and 224-bit q, no digests.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub(crate) unsafe extern "C" fn pkey_dsa_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        let data = Box::into_raw(Box::new(DsaPkeyCtx {
            nbits: 2048,
            qbits: 224,
            pmd: ptr::null(),
            gentmp: [0; 2],
            md: ptr::null(),
        }));
        // SAFETY: the context; the settings it owns until `pkey_dsa_cleanup`.
        unsafe { EVP_PKEY_CTX_set_data(ctx, data.cast()) };
        // SAFETY: the settings just made, at a fixed address until they're freed.
        let gentmp = unsafe { (&raw mut (*data).gentmp).cast::<c_int>() };
        // SAFETY: the context; the two values, which live as long as its data.
        unsafe { EVP_PKEY_CTX_set0_keygen_info(ctx, gentmp, 2) };
        1
    }
}

ffi_callback! {
    /// `pkey_dsa_copy`: `dst`'s settings from `src`'s.
    ///
    /// # Safety
    /// `dst` and `src` are live contexts; `src`'s data is its settings.
    pub(crate) unsafe extern "C" fn pkey_dsa_copy(dst: *mut EVP_PKEY_CTX, src: *const EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        if unsafe { pkey_dsa_init(dst) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let (Some(s), Some(d)) = (unsafe { settings(src) }, unsafe { settings(dst) }) else {
            return 0;
        };
        d.nbits = s.nbits;
        d.qbits = s.qbits;
        d.pmd = s.pmd;
        d.md = s.md;
        1
    }
}

ffi_callback! {
    /// `pkey_dsa_cleanup`: frees the settings.
    ///
    /// # Safety
    /// `ctx` is a live context whose data is NULL or its settings.
    pub(crate) unsafe extern "C" fn pkey_dsa_cleanup(ctx: *mut EVP_PKEY_CTX)
    where failure = (), library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let data = unsafe { EVP_PKEY_CTX_get_data(ctx) };
        if !data.is_null() {
            // SAFETY: the context; its data is gone.
            unsafe { EVP_PKEY_CTX_set_data(ctx, ptr::null_mut()) };
            // SAFETY: the settings `pkey_dsa_init` made, freed once.
            drop(unsafe { Box::from_raw(data.cast::<DsaPkeyCtx>()) });
        }
    }
}

ffi_callback! {
    /// `pkey_dsa_sign`: `DSA_sign` of a digest of the digest's size when one is set.
    ///
    /// # Safety
    /// `ctx` is a live context; `sig` is NULL or has room for the key's signature; `siglen` is
    /// writable; `tbs` holds `tbslen` octets.
    pub(crate) unsafe extern "C" fn pkey_dsa_sign(ctx: *mut EVP_PKEY_CTX, sig: *mut c_uchar, siglen: *mut usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        // SAFETY: the context's digest, or NULL.
        if !unsafe { fits(d, tbslen) } {
            return 0;
        }
        // OpenSSL passes the length as an int, cut short past INT_MAX; this fails instead.
        let Ok(dlen) = c_int::try_from(tbslen) else { return 0 };
        let mut sltmp: c_uint = 0;
        // SAFETY: the caller's guarantee.
        let dsa = unsafe { key(ctx) };
        // SAFETY: the caller's input and room; a local; the key, or NULL.
        let ret = unsafe { DSA_sign(0, tbs, dlen, sig, &raw mut sltmp, dsa) };
        if ret <= 0 {
            return ret;
        }
        // SAFETY: the caller's guarantee.
        unsafe { siglen.write(sltmp as usize) };
        1
    }
}

ffi_callback! {
    /// `pkey_dsa_verify`: `DSA_verify` of a digest of the digest's size when one is set.
    ///
    /// # Safety
    /// `ctx` is a live context; `sig` holds `siglen` octets; `tbs` holds `tbslen`.
    pub(crate) unsafe extern "C" fn pkey_dsa_verify(ctx: *mut EVP_PKEY_CTX, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        // SAFETY: the context's digest, or NULL.
        if !unsafe { fits(d, tbslen) } {
            return 0;
        }
        // OpenSSL passes the lengths as ints, cut short past INT_MAX; this fails instead.
        let (Ok(dlen), Ok(slen)) = (c_int::try_from(tbslen), c_int::try_from(siglen)) else {
            return 0;
        };
        // SAFETY: the caller's guarantee.
        let dsa = unsafe { key(ctx) };
        // SAFETY: the caller's input; the key, or NULL.
        unsafe { DSA_verify(0, tbs, dlen, sig, slen, dsa) }
    }
}

ffi_callback! {
    /// `pkey_dsa_ctrl`: the generation's sizes and digest, the signature's digest; 1 for the
    /// digest init and PKCS#7 and CMS signing; -2 for a peer key, others, or values out of
    /// range.
    ///
    /// # Safety
    /// `ctx` is a live context; `p2` is what `type_` takes (NULL isn't written through).
    pub(crate) unsafe extern "C" fn pkey_dsa_ctrl(ctx: *mut EVP_PKEY_CTX, type_: c_int, p1: c_int, p2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        const F: &str = "pkey_dsa_ctrl";
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        match type_ {
            EVP_PKEY_CTRL_DSA_PARAMGEN_BITS => {
                if p1 < 256 {
                    return -2;
                }
                d.nbits = p1;
                1
            }
            EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS => {
                // OpenSSL's test lets 0 through.
                if !matches!(p1, 0 | 160 | 224 | 256) {
                    return -2;
                }
                d.qbits = p1;
                1
            }
            EVP_PKEY_CTRL_DSA_PARAMGEN_MD => {
                // SAFETY: the caller's digest, or NULL (whose type is 0).
                let t = unsafe { EVP_MD_get_type(p2.cast_const().cast()) };
                if !PARAMGEN_DIGESTS.contains(&t) {
                    err::raise(ERR_LIB_DSA, DSA_R_INVALID_DIGEST_TYPE, F);
                    return 0;
                }
                d.pmd = p2.cast_const().cast();
                1
            }
            EVP_PKEY_CTRL_MD => {
                // SAFETY: as above.
                let t = unsafe { EVP_MD_get_type(p2.cast_const().cast()) };
                if !SIGN_DIGESTS.contains(&t) {
                    err::raise(ERR_LIB_DSA, DSA_R_INVALID_DIGEST_TYPE, F);
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
            EVP_PKEY_CTRL_DIGESTINIT | EVP_PKEY_CTRL_PKCS7_SIGN | EVP_PKEY_CTRL_CMS_SIGN => 1,
            EVP_PKEY_CTRL_PEER_KEY => {
                err::raise(ERR_LIB_DSA, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE, F);
                -2
            }
            _ => -2,
        }
    }
}

ffi_callback! {
    /// `pkey_dsa_ctrl_str`: `dsa_paramgen_bits`, `dsa_paramgen_q_bits` (numbers, as `atoi`
    /// reads them), and `dsa_paramgen_md` (a digest's name); -2 for others.
    ///
    /// # Safety
    /// `ctx` is a live context; `type_` and `value` are NULL or strings.
    pub(crate) unsafe extern "C" fn pkey_dsa_ctrl_str(ctx: *mut EVP_PKEY_CTX, type_: *const c_char, value: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        if type_.is_null() || value.is_null() {
            return -2;
        }
        // SAFETY: the caller's strings.
        let (t, v) = (unsafe { CStr::from_ptr(type_) }, unsafe { CStr::from_ptr(value) });
        match t.to_bytes() {
            // SAFETY: the caller's context.
            b"dsa_paramgen_bits" => unsafe { EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, atoi(v.to_bytes())) },
            // SAFETY: as above.
            b"dsa_paramgen_q_bits" => unsafe { EVP_PKEY_CTX_set_dsa_paramgen_q_bits(ctx, atoi(v.to_bytes())) },
            b"dsa_paramgen_md" => {
                // SAFETY: a string.
                let md = unsafe { EVP_get_digestbyname(value) };
                if md.is_null() {
                    err::raise(ERR_LIB_DSA, DSA_R_INVALID_DIGEST_TYPE, "pkey_dsa_ctrl_str");
                    return 0;
                }
                // SAFETY: the caller's context; the digest.
                unsafe { EVP_PKEY_CTX_set_dsa_paramgen_md(ctx, md) }
            }
            _ => -2,
        }
    }
}

/// `trans_cb`: the generator's progress to the context's callback.
///
/// # Safety
/// `cb` is a live `BN_GENCB` whose argument is a live context.
unsafe extern "C" fn trans_cb(a: c_int, b: c_int, cb: *mut BN_GENCB) -> c_int {
    // SAFETY: the caller's guarantee.
    let ctx: *mut EVP_PKEY_CTX = unsafe { BN_GENCB_get_arg(cb) }.cast();
    // SAFETY: as above.
    unsafe { legacy_gen_progress(ctx, a, b) }
}

/// FIPS 186-4 parameters of `nbits` and `qbits` with `md`'s digest (if any) in a new `DSA`, or
/// NULL.
///
/// # Safety
/// `md` is NULL or live; `pcb` is NULL or a live `BN_GENCB`.
unsafe fn generate_params(
    nbits: c_int,
    qbits: c_int,
    md: *const EVP_MD,
    pcb: *mut BN_GENCB,
) -> *mut rustyssl_abi::DSA {
    // SAFETY: no preconditions.
    let ret = unsafe { DSA_new() };
    // SAFETY: just made, or NULL.
    let Some(k) = (unsafe { dsa(ret) }) else {
        return ptr::null_mut();
    };
    let mut st = k.snapshot();
    if !md.is_null() {
        // SAFETY: the caller's digest.
        let name = unsafe { EVP_MD_get0_name(md) };
        if !name.is_null() {
            // SAFETY: the digest's name.
            st.params.mdname = Some(unsafe { CStr::from_ptr(name) }.to_owned());
        }
    }
    let ok = (|| {
        let l = usize::try_from(nbits).ok()?;
        let n = usize::try_from(qbits).ok()?;
        // SAFETY: the default library context; the caller's callback.
        let env = unsafe { Env::new(ptr::null_mut(), pcb) }?;
        let mut res = 0;
        // SAFETY: as above.
        let rv = unsafe {
            ffc::generate_186_4(
                ptr::null_mut(),
                &env,
                &mut st.params,
                Type::Dsa,
                l,
                n,
                &mut res,
            )
        };
        (rv > 0).then_some(())
    })();
    if ok.is_none() {
        // SAFETY: the key made above.
        unsafe { DSA_free(ret) };
        return ptr::null_mut();
    }
    k.replace(st);
    ret
}

ffi_callback! {
    /// `pkey_dsa_paramgen`: FIPS 186-4 parameters of the context's sizes, assigned to `pkey`.
    ///
    /// # Safety
    /// `ctx` is a live context; `pkey` is a live key.
    pub(crate) unsafe extern "C" fn pkey_dsa_paramgen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        let (nbits, qbits, md) = {
            // SAFETY: the caller's guarantee.
            let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
            (d.nbits, d.qbits, d.md)
        };
        // SAFETY: the caller's context.
        let pcb = if unsafe { EVP_PKEY_CTX_get_cb(ctx) }.is_some() {
            // SAFETY: no preconditions.
            let pcb = unsafe { BN_GENCB_new() };
            if pcb.is_null() {
                return 0;
            }
            // SAFETY: the new callback, reporting to the context.
            unsafe { BN_GENCB_set(pcb, Some(trans_cb), ctx.cast()) };
            pcb
        } else {
            ptr::null_mut()
        };
        // SAFETY: the context's digest, or NULL; the callback, or NULL.
        let h = unsafe { generate_params(nbits, qbits, md, pcb) };
        // SAFETY: NULL or the callback made above.
        unsafe { BN_GENCB_free(pcb) };
        if h.is_null() {
            return 0;
        }
        // SAFETY: the caller's key; the `DSA`, which it takes.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, h.cast()) };
        1
    }
}

ffi_callback! {
    /// `pkey_dsa_keygen`: a `DSA` of the context key's parameters, assigned to `pkey`, and its
    /// key pair.
    ///
    /// # Safety
    /// `ctx` is a live context; `pkey` is a live key.
    pub(crate) unsafe extern "C" fn pkey_dsa_keygen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_DSA
    {
        // SAFETY: the caller's guarantee.
        let ctx_pkey = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
        if ctx_pkey.is_null() {
            err::raise(ERR_LIB_DSA, DSA_R_NO_PARAMETERS_SET, "pkey_dsa_keygen");
            return 0;
        }
        // SAFETY: no preconditions.
        let h = unsafe { DSA_new() };
        if h.is_null() {
            return 0;
        }
        // SAFETY: the caller's key; the `DSA`, which it takes.
        unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DSA, h.cast()) };
        // SAFETY: the keys.
        if unsafe { EVP_PKEY_copy_parameters(pkey, ctx_pkey) } == 0 {
            return 0;
        }
        // SAFETY: the caller's key.
        let d = unsafe { EVP_PKEY_get0_DSA(pkey) }.cast_mut();
        // SAFETY: its `DSA`, or NULL; no lock is held.
        unsafe { DSA_generate_key(d) }
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::EVP_PKEY_CTX;

    use super::*;
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new_id};

    /// docs/DEVIATIONS.md: the signature digest's getter with NULL, which OpenSSL writes
    /// through, writes nothing; a NULL digest, whose type OpenSSL reads, is refused as no
    /// digest.
    #[test]
    #[cfg_attr(miri, ignore = "fetches, which loads the configuration")]
    fn ctrl_null_pointers_are_safe() {
        // SAFETY: no preconditions.
        let ctx: *mut EVP_PKEY_CTX = unsafe { EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, ptr::null_mut()) };
        assert!(!ctx.is_null());
        // SAFETY: a live context without data; settings for it.
        assert_eq!(unsafe { pkey_dsa_init(ctx) }, 1);
        // SAFETY: as above.
        let r = unsafe { pkey_dsa_ctrl(ctx, EVP_PKEY_CTRL_GET_MD, 0, ptr::null_mut()) };
        assert_eq!(r, 1);
        // SAFETY: as above; NULL is no digest.
        let r = unsafe { pkey_dsa_ctrl(ctx, EVP_PKEY_CTRL_MD, 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { pkey_dsa_ctrl(ctx, EVP_PKEY_CTRL_DSA_PARAMGEN_MD, 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: the settings made above, freed once.
        unsafe { pkey_dsa_cleanup(ctx) };
        // SAFETY: made above, freed once.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
