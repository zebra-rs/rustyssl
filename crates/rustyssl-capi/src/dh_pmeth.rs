//! The built-in DH and DHX `EVP_PKEY_METHOD`s' functions (`dh_pmeth.c`). A key whose `DH` has
//! an application's method (a "foreign" key) stays a legacy key, and its contexts use these
//! instead of a provider; an application that copies or wraps the built-in methods
//! (`EVP_PKEY_meth_find`, `EVP_PKEY_meth_copy`) calls them too.
//!
//! As in OpenSSL, each operation is made of the `DH` functions, so it goes through the key's
//! method: deriving is `DH_compute_key` (padded with `EVP_PKEY_CTRL_DH_PAD`), or X9.42's KDF of
//! the padded secret into exactly the KDF's length; parameter generation takes a named group
//! (by NID, or RFC 5114's 1 to 3, typed DHX), FIPS 186-4 or 186-2 parameters (DHX), or a safe
//! prime with a generator; key generation takes the named group, or the context key's
//! parameters. A context with no KDF object can't be copied, as in OpenSSL.
//!
//! OpenSSL's derive writes the whole secret whatever room `*keylen` gives, its getters write
//! through NULL, and it takes keying material of a negative length; this one refuses, answers,
//! or keeps it safe instead (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_OBJECT, BN_GENCB, DH, DH_PARAMGEN_TYPE_FIPS_186_2, DH_PARAMGEN_TYPE_FIPS_186_4,
    DH_PARAMGEN_TYPE_GENERATOR, DH_R_INVALID_PARAMETER_NAME, DH_R_INVALID_SIZE, DH_R_KEYS_NOT_SET,
    DH_R_NO_PARAMETERS_SET, ERR_LIB_DH, EVP_MD, EVP_PKEY, EVP_PKEY_CTRL_DH_KDF_MD,
    EVP_PKEY_CTRL_DH_KDF_OID, EVP_PKEY_CTRL_DH_KDF_OUTLEN, EVP_PKEY_CTRL_DH_KDF_TYPE,
    EVP_PKEY_CTRL_DH_KDF_UKM, EVP_PKEY_CTRL_DH_NID, EVP_PKEY_CTRL_DH_PAD,
    EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN,
    EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, EVP_PKEY_CTRL_DH_PARAMGEN_TYPE,
    EVP_PKEY_CTRL_DH_RFC5114, EVP_PKEY_CTRL_GET_DH_KDF_MD, EVP_PKEY_CTRL_GET_DH_KDF_OID,
    EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, EVP_PKEY_CTRL_GET_DH_KDF_UKM, EVP_PKEY_CTRL_PEER_KEY,
    EVP_PKEY_CTX, EVP_PKEY_DH, EVP_PKEY_DH_KDF_NONE, EVP_PKEY_DH_KDF_X9_42, EVP_PKEY_DHX,
    NID_undef,
};

use crate::bn::prime::{BN_GENCB_free, BN_GENCB_get_arg, BN_GENCB_new, BN_GENCB_set};
use crate::dh::{DH_free, DH_get0_pub_key, DH_new, DH_new_by_nid, DH_size, dh};
use crate::dh_meth::{DH_compute_key, DH_compute_key_padded, DH_generate_key};
use crate::dh_ops::{DH_KDF_X9_42, DH_generate_parameters_ex};
use crate::ec_pmeth::atoi;
use crate::err;
use crate::evp::digest::EVP_MD_get0_name;
use crate::evp::pkey::dh::EVP_PKEY_get0_DH;
use crate::evp::pkey::{EVP_PKEY_assign, EVP_PKEY_copy_parameters};
use crate::evp::pkey_ctx::{
    EVP_PKEY_CTX_get_cb, EVP_PKEY_CTX_get_data, EVP_PKEY_CTX_get0_peerkey, EVP_PKEY_CTX_get0_pkey,
    EVP_PKEY_CTX_set_data, EVP_PKEY_CTX_set0_keygen_info, legacy_gen_progress,
};
use crate::evp::setters::{
    EVP_PKEY_CTX_set_dh_pad, EVP_PKEY_CTX_set_dh_paramgen_generator,
    EVP_PKEY_CTX_set_dh_paramgen_prime_len, EVP_PKEY_CTX_set_dh_paramgen_subprime_len,
    EVP_PKEY_CTX_set_dh_paramgen_type,
};
use crate::ffc::{self, Type};
use crate::ffi::ffi_callback;
use crate::mem;
use crate::objects::{ASN1_OBJECT_free, OBJ_dup, OBJ_sn2nid};
use crate::rsa_gen::Env;

/// `DH_PKEY_CTX`.
struct DhPkeyCtx {
    prime_len: c_int,
    generator: c_int,
    paramgen_type: c_int,
    subprime_len: c_int,
    pad: c_int,
    /// The digest for FIPS 186 parameter generation, or NULL.
    md: *const EVP_MD,
    param_nid: c_int,
    /// What `EVP_PKEY_CTX_get_keygen_info` reads.
    gentmp: [c_int; 2],
    kdf_type: c_int,
    /// Owned, or NULL.
    kdf_oid: *mut ASN1_OBJECT,
    kdf_md: *const EVP_MD,
    /// Owned, from the C allocator (`EVP_PKEY_CTX_set0_dh_kdf_ukm`'s).
    kdf_ukm: *mut c_uchar,
    kdf_ukmlen: usize,
    kdf_outlen: usize,
}

impl Drop for DhPkeyCtx {
    fn drop(&mut self) {
        // SAFETY: the context's own octets, or NULL, from the C allocator.
        unsafe { mem::release(self.kdf_ukm.cast()) };
        // SAFETY: the context's own object, or NULL.
        unsafe { ASN1_OBJECT_free(self.kdf_oid) };
    }
}

/// The context's settings.
///
/// # Safety
/// `ctx` is NULL or a live context whose data is NULL or a `DhPkeyCtx`; nothing else uses the
/// settings while the reference lives.
unsafe fn settings<'a>(ctx: *const EVP_PKEY_CTX) -> Option<&'a mut DhPkeyCtx> {
    // SAFETY: the caller's guarantee.
    let data = unsafe { EVP_PKEY_CTX_get_data(ctx) };
    // SAFETY: as above.
    unsafe { data.cast::<DhPkeyCtx>().as_mut() }
}

/// The `DH` of a key, or NULL.
///
/// # Safety
/// `pkey` is NULL or a live key.
unsafe fn dh_of(pkey: *const EVP_PKEY) -> *mut DH {
    if pkey.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's key.
    unsafe { EVP_PKEY_get0_DH(pkey) }.cast_mut()
}

ffi_callback! {
    /// `pkey_dh_init`: 2048-bit safe primes with generator 2, no KDF.
    ///
    /// # Safety
    /// `ctx` is a live context.
    pub(crate) unsafe extern "C" fn pkey_dh_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        let data = Box::into_raw(Box::new(DhPkeyCtx {
            prime_len: 2048,
            generator: 2,
            paramgen_type: DH_PARAMGEN_TYPE_GENERATOR,
            subprime_len: -1,
            pad: 0,
            md: ptr::null(),
            param_nid: NID_undef,
            gentmp: [0; 2],
            kdf_type: EVP_PKEY_DH_KDF_NONE,
            kdf_oid: ptr::null_mut(),
            kdf_md: ptr::null(),
            kdf_ukm: ptr::null_mut(),
            kdf_ukmlen: 0,
            kdf_outlen: 0,
        }));
        // SAFETY: the context; the settings it owns until `pkey_dh_cleanup`.
        unsafe { EVP_PKEY_CTX_set_data(ctx, data.cast()) };
        // SAFETY: the settings just made, at a fixed address until they're freed.
        let gentmp = unsafe { (&raw mut (*data).gentmp).cast::<c_int>() };
        // SAFETY: the context; the two values, which live as long as its data.
        unsafe { EVP_PKEY_CTX_set0_keygen_info(ctx, gentmp, 2) };
        1
    }
}

ffi_callback! {
    /// `pkey_dh_copy`: `dst`'s settings from `src`'s, with copies of the KDF object and keying
    /// material. Fails for a context without a KDF object, as OpenSSL's does (its `OBJ_dup`
    /// of NULL is NULL).
    ///
    /// # Safety
    /// `dst` and `src` are live contexts; `src`'s data is its settings.
    pub(crate) unsafe extern "C" fn pkey_dh_copy(dst: *mut EVP_PKEY_CTX, src: *const EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        if unsafe { pkey_dh_init(dst) } == 0 {
            return 0;
        }
        // SAFETY: as above.
        let (Some(s), Some(d)) = (unsafe { settings(src) }, unsafe { settings(dst) }) else {
            return 0;
        };
        d.prime_len = s.prime_len;
        d.subprime_len = s.subprime_len;
        d.generator = s.generator;
        d.paramgen_type = s.paramgen_type;
        d.pad = s.pad;
        d.md = s.md;
        d.param_nid = s.param_nid;
        d.kdf_type = s.kdf_type;
        // SAFETY: the source's object, or NULL.
        d.kdf_oid = unsafe { OBJ_dup(s.kdf_oid) };
        if d.kdf_oid.is_null() {
            return 0;
        }
        d.kdf_md = s.kdf_md;
        if !s.kdf_ukm.is_null() {
            let copy: *mut c_uchar = mem::alloc(s.kdf_ukmlen.max(1)).cast();
            if copy.is_null() {
                return 0;
            }
            // SAFETY: the source's `kdf_ukmlen` octets; a block that size.
            unsafe { ptr::copy_nonoverlapping(s.kdf_ukm, copy, s.kdf_ukmlen) };
            d.kdf_ukm = copy;
            d.kdf_ukmlen = s.kdf_ukmlen;
        }
        d.kdf_outlen = s.kdf_outlen;
        1
    }
}

ffi_callback! {
    /// `pkey_dh_cleanup`: frees the settings.
    ///
    /// # Safety
    /// `ctx` is a live context whose data is NULL or its settings.
    pub(crate) unsafe extern "C" fn pkey_dh_cleanup(ctx: *mut EVP_PKEY_CTX)
    where failure = (), library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let data = unsafe { EVP_PKEY_CTX_get_data(ctx) };
        if !data.is_null() {
            // SAFETY: the context; its data is gone.
            unsafe { EVP_PKEY_CTX_set_data(ctx, ptr::null_mut()) };
            // SAFETY: the settings `pkey_dh_init` made, freed once.
            drop(unsafe { Box::from_raw(data.cast::<DhPkeyCtx>()) });
        }
    }
}

/// Writes `v` where `p` points, if it does.
///
/// # Safety
/// `p` is NULL or room for a `T`.
unsafe fn put<T>(p: *mut c_void, v: T) {
    if !p.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { p.cast::<T>().write(v) };
    }
}

ffi_callback! {
    /// `pkey_dh_ctrl`: the generation's prime and subprime sizes, generator, type, and named
    /// group; padding; the KDF's type, digest, length, keying material, and object; 1 for a
    /// peer key; -2 for others or values out of range.
    ///
    /// # Safety
    /// `ctx` is a live context; `p2` is what `type_` takes (NULL isn't written through).
    pub(crate) unsafe extern "C" fn pkey_dh_ctrl(ctx: *mut EVP_PKEY_CTX, type_: c_int, p1: c_int, p2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        match type_ {
            EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN => {
                if p1 < 256 {
                    return -2;
                }
                d.prime_len = p1;
                1
            }
            EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN => {
                if d.paramgen_type == DH_PARAMGEN_TYPE_GENERATOR {
                    return -2;
                }
                d.subprime_len = p1;
                1
            }
            EVP_PKEY_CTRL_DH_PAD => {
                d.pad = p1;
                1
            }
            EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR => {
                if d.paramgen_type != DH_PARAMGEN_TYPE_GENERATOR {
                    return -2;
                }
                d.generator = p1;
                1
            }
            EVP_PKEY_CTRL_DH_PARAMGEN_TYPE => {
                if !(0..=2).contains(&p1) {
                    return -2;
                }
                d.paramgen_type = p1;
                1
            }
            EVP_PKEY_CTRL_DH_RFC5114 => {
                if !(1..=3).contains(&p1) || d.param_nid != NID_undef {
                    return -2;
                }
                d.param_nid = p1;
                1
            }
            EVP_PKEY_CTRL_DH_NID => {
                if p1 <= 0 || d.param_nid != NID_undef {
                    return -2;
                }
                d.param_nid = p1;
                1
            }
            EVP_PKEY_CTRL_PEER_KEY => 1,
            EVP_PKEY_CTRL_DH_KDF_TYPE => {
                if p1 == -2 {
                    return d.kdf_type;
                }
                if p1 != EVP_PKEY_DH_KDF_NONE && p1 != EVP_PKEY_DH_KDF_X9_42 {
                    return -2;
                }
                d.kdf_type = p1;
                1
            }
            EVP_PKEY_CTRL_DH_KDF_MD => {
                d.kdf_md = p2.cast_const().cast();
                1
            }
            EVP_PKEY_CTRL_GET_DH_KDF_MD => {
                // SAFETY: the caller's place for a digest, or NULL.
                unsafe { put(p2, d.kdf_md) };
                1
            }
            EVP_PKEY_CTRL_DH_KDF_OUTLEN => {
                let Some(n) = usize::try_from(p1).ok().filter(|&n| n > 0) else { return -2 };
                d.kdf_outlen = n;
                1
            }
            EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN => {
                // Set from a positive int, so it fits.
                let len = c_int::try_from(d.kdf_outlen).unwrap_or(c_int::MAX);
                // SAFETY: the caller's place for an int, or NULL.
                unsafe { put(p2, len) };
                1
            }
            EVP_PKEY_CTRL_DH_KDF_UKM => {
                // A negative length, which OpenSSL takes as a huge one, is refused (the octets
                // stay the caller's).
                let Ok(len) = usize::try_from(p1) else { return 0 };
                // SAFETY: the context's octets, or NULL.
                unsafe { mem::release(d.kdf_ukm.cast()) };
                d.kdf_ukm = p2.cast();
                d.kdf_ukmlen = if p2.is_null() { 0 } else { len };
                1
            }
            EVP_PKEY_CTRL_GET_DH_KDF_UKM => {
                // SAFETY: the caller's place for a pointer, or NULL.
                unsafe { put(p2, d.kdf_ukm) };
                // Set from an int, so it fits.
                c_int::try_from(d.kdf_ukmlen).unwrap_or(c_int::MAX)
            }
            EVP_PKEY_CTRL_DH_KDF_OID => {
                // SAFETY: the context's object, or NULL.
                unsafe { ASN1_OBJECT_free(d.kdf_oid) };
                d.kdf_oid = p2.cast();
                1
            }
            EVP_PKEY_CTRL_GET_DH_KDF_OID => {
                // SAFETY: the caller's place for an object, or NULL.
                unsafe { put(p2, d.kdf_oid) };
                1
            }
            _ => -2,
        }
    }
}

ffi_callback! {
    /// `pkey_dh_ctrl_str`: the generation's sizes, generator, and type and the padding through
    /// their EVP setters, a named group (`dh_param`, a short name) or RFC 5114's (`dh_rfc5114`,
    /// 0 to 3) set as they are; -2 for others.
    ///
    /// # Safety
    /// `ctx` is a live context; `type_` and `value` are strings.
    pub(crate) unsafe extern "C" fn pkey_dh_ctrl_str(ctx: *mut EVP_PKEY_CTX, type_: *const c_char, value: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        if type_.is_null() || value.is_null() {
            return -2;
        }
        // SAFETY: the caller's strings.
        let (t, v) = (unsafe { CStr::from_ptr(type_) }, unsafe { CStr::from_ptr(value) });
        let n = atoi(v.to_bytes());
        match t.to_bytes() {
            // SAFETY: the caller's context (for each setter below).
            b"dh_paramgen_prime_len" => unsafe { EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, n) },
            b"dh_rfc5114" => {
                // SAFETY: the caller's guarantee.
                let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
                if !(0..=3).contains(&n) {
                    return -2;
                }
                d.param_nid = n;
                1
            }
            b"dh_param" => {
                // SAFETY: the caller's guarantee.
                let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
                // SAFETY: a string.
                let nid = unsafe { OBJ_sn2nid(value) };
                if nid == NID_undef {
                    err::raise(ERR_LIB_DH, DH_R_INVALID_PARAMETER_NAME, "pkey_dh_ctrl_str");
                    return -2;
                }
                d.param_nid = nid;
                1
            }
            // SAFETY: as above.
            b"dh_paramgen_generator" => unsafe { EVP_PKEY_CTX_set_dh_paramgen_generator(ctx, n) },
            // SAFETY: as above.
            b"dh_paramgen_subprime_len" => unsafe { EVP_PKEY_CTX_set_dh_paramgen_subprime_len(ctx, n) },
            // SAFETY: as above.
            b"dh_paramgen_type" => unsafe { EVP_PKEY_CTX_set_dh_paramgen_type(ctx, n) },
            // SAFETY: as above.
            b"dh_pad" => unsafe { EVP_PKEY_CTX_set_dh_pad(ctx, n) },
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

/// `ffc_params_generate`: FIPS 186-2 or 186-4 parameters of the context's sizes (q's 256 bits
/// for primes of 2048 bits or more, else 160, unless set) and digest, in a new `DH`, or NULL.
///
/// # Safety
/// `d`'s digest is NULL or live; `pcb` is NULL or a live `BN_GENCB`.
unsafe fn ffc_params_generate(d: &DhPkeyCtx, pcb: *mut BN_GENCB) -> *mut DH {
    if d.paramgen_type > DH_PARAMGEN_TYPE_FIPS_186_4 {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let ret = unsafe { DH_new() };
    // SAFETY: just made, or NULL.
    let Some(k) = (unsafe { dh(ret) }) else {
        return ptr::null_mut();
    };
    let subprime_len = match d.subprime_len {
        -1 if d.prime_len >= 2048 => 256,
        -1 => 160,
        n => n,
    };
    let mut st = k.snapshot();
    if !d.md.is_null() {
        // SAFETY: the context's digest.
        let name = unsafe { EVP_MD_get0_name(d.md) };
        if !name.is_null() {
            // SAFETY: the digest's name.
            st.params.mdname = Some(unsafe { CStr::from_ptr(name) }.to_owned());
        }
    }
    let ok = (|| {
        let l = usize::try_from(d.prime_len).ok()?;
        let n = usize::try_from(subprime_len).ok()?;
        // SAFETY: the default library context; the caller's callback.
        let env = unsafe { Env::new(ptr::null_mut(), pcb) }?;
        let mut res = 0;
        let rv = if d.paramgen_type == DH_PARAMGEN_TYPE_FIPS_186_2 {
            // SAFETY: as above.
            unsafe {
                ffc::generate_186_2(
                    ptr::null_mut(),
                    &env,
                    &mut st.params,
                    Type::Dh,
                    l,
                    n,
                    &mut res,
                )
            }
        } else {
            // SAFETY: as above.
            unsafe {
                ffc::generate_186_4(
                    ptr::null_mut(),
                    &env,
                    &mut st.params,
                    Type::Dh,
                    l,
                    n,
                    &mut res,
                )
            }
        };
        (rv > 0).then_some(())
    })();
    if ok.is_none() {
        // SAFETY: the key made above.
        unsafe { DH_free(ret) };
        return ptr::null_mut();
    }
    k.replace(st);
    ret
}

ffi_callback! {
    /// `pkey_dh_paramgen`: the named group (typed DHX for RFC 5114's), FIPS 186 parameters
    /// (DHX), or a safe prime with the generator (DH), assigned to `pkey`.
    ///
    /// # Safety
    /// `ctx` is a live context; `pkey` is a live key.
    pub(crate) unsafe extern "C" fn pkey_dh_paramgen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        let (param_nid, paramgen_type, prime_len, generator) = {
            // SAFETY: the caller's guarantee.
            let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
            (d.param_nid, d.paramgen_type, d.prime_len, d.generator)
        };
        if param_nid != NID_undef {
            let type_ = if param_nid <= 3 { EVP_PKEY_DHX } else { EVP_PKEY_DH };
            // SAFETY: no preconditions.
            let h = unsafe { DH_new_by_nid(param_nid) };
            if h.is_null() {
                return 0;
            }
            // SAFETY: the caller's key; the `DH`, which it takes.
            unsafe { EVP_PKEY_assign(pkey, type_, h.cast()) };
            return 1;
        }
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
        if paramgen_type >= DH_PARAMGEN_TYPE_FIPS_186_2 {
            // SAFETY: the caller's guarantee (read again: the callback may have used the
            // context).
            let h = match unsafe { settings(ctx) } {
                // SAFETY: the settings; the callback, or NULL.
                Some(d) => unsafe { ffc_params_generate(d, pcb) },
                None => ptr::null_mut(),
            };
            // SAFETY: NULL or the callback made above.
            unsafe { BN_GENCB_free(pcb) };
            if h.is_null() {
                return 0;
            }
            // SAFETY: the caller's key; the `DH`, which it takes.
            unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DHX, h.cast()) };
            return 1;
        }
        // SAFETY: no preconditions.
        let h = unsafe { DH_new() };
        if h.is_null() {
            // SAFETY: NULL or the callback made above.
            unsafe { BN_GENCB_free(pcb) };
            return 0;
        }
        // SAFETY: the new key; the callback, or NULL.
        let ret = unsafe { DH_generate_parameters_ex(h, prime_len, generator, pcb) };
        // SAFETY: NULL or the callback made above.
        unsafe { BN_GENCB_free(pcb) };
        if ret != 0 {
            // SAFETY: the caller's key; the `DH`, which it takes.
            unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_DH, h.cast()) };
        } else {
            // SAFETY: the key made above.
            unsafe { DH_free(h) };
        }
        ret
    }
}

/// `pkey_dh_keygen` for a method of `type_`: a `DH` of the named group or the context key's
/// parameters, assigned to `pkey`, and its key pair.
///
/// # Safety
/// `ctx` is a live context; `pkey` is a live key.
unsafe fn keygen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY, type_: c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(param_nid) = (unsafe { settings(ctx) }).map(|d| d.param_nid) else {
        return 0;
    };
    // SAFETY: as above.
    let ctx_pkey = unsafe { EVP_PKEY_CTX_get0_pkey(ctx) };
    if ctx_pkey.is_null() && param_nid == NID_undef {
        err::raise(ERR_LIB_DH, DH_R_NO_PARAMETERS_SET, "pkey_dh_keygen");
        return 0;
    }
    let h = if param_nid != NID_undef {
        // SAFETY: no preconditions.
        unsafe { DH_new_by_nid(param_nid) }
    } else {
        // SAFETY: as above.
        unsafe { DH_new() }
    };
    if h.is_null() {
        return 0;
    }
    // SAFETY: the caller's key; the `DH`, which it takes.
    unsafe { EVP_PKEY_assign(pkey, type_, h.cast()) };
    // SAFETY: the keys.
    if !ctx_pkey.is_null() && unsafe { EVP_PKEY_copy_parameters(pkey, ctx_pkey) } == 0 {
        return 0;
    }
    // SAFETY: the caller's key.
    let d = unsafe { dh_of(pkey) };
    // SAFETY: its `DH`, or NULL; no lock is held.
    unsafe { DH_generate_key(d) }
}

ffi_callback! {
    /// `pkey_dh_keygen` of the DH method.
    ///
    /// # Safety
    /// `ctx` is a live context; `pkey` is a live key.
    pub(crate) unsafe extern "C" fn pkey_dh_keygen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { keygen(ctx, pkey, EVP_PKEY_DH) }
    }
}

ffi_callback! {
    /// `pkey_dh_keygen` of the DHX method.
    ///
    /// # Safety
    /// `ctx` is a live context; `pkey` is a live key.
    pub(crate) unsafe extern "C" fn pkey_dhx_keygen(ctx: *mut EVP_PKEY_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        unsafe { keygen(ctx, pkey, EVP_PKEY_DHX) }
    }
}

ffi_callback! {
    /// `pkey_dh_derive`: the shared secret (padded if set), or X9.42's KDF of the padded secret
    /// into exactly the KDF's length (which needs the KDF's length and object); the size for
    /// NULL `key`.
    ///
    /// # Safety
    /// `ctx` is a live context; `key` is NULL or has room for `*keylen` octets; `keylen` is
    /// readable and writable.
    pub(crate) unsafe extern "C" fn pkey_dh_derive(ctx: *mut EVP_PKEY_CTX, key: *mut c_uchar, keylen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        const F: &str = "pkey_dh_derive";
        // SAFETY: the caller's guarantee.
        let Some(d) = (unsafe { settings(ctx) }) else { return 0 };
        // SAFETY: as above.
        let (pkey, peer) = (unsafe { EVP_PKEY_CTX_get0_pkey(ctx) }, unsafe { EVP_PKEY_CTX_get0_peerkey(ctx) });
        if pkey.is_null() || peer.is_null() {
            err::raise(ERR_LIB_DH, DH_R_KEYS_NOT_SET, F);
            return 0;
        }
        // SAFETY: the context's keys.
        let (h, hpub) = (unsafe { dh_of(pkey) }, unsafe { dh_of(peer) });
        if h.is_null() || hpub.is_null() {
            err::raise(ERR_LIB_DH, DH_R_KEYS_NOT_SET, F);
            return 0;
        }
        // SAFETY: the peer's `DH`.
        let pub_key = unsafe { DH_get0_pub_key(hpub) };
        // SAFETY: the key's `DH`.
        let size = unsafe { DH_size(h) };
        if d.kdf_type == EVP_PKEY_DH_KDF_NONE {
            if key.is_null() {
                // `(size_t)DH_size(dh)`.
                // SAFETY: the caller's guarantee.
                unsafe { keylen.write(usize::try_from(size).unwrap_or(usize::MAX)) };
                return 1;
            }
            // OpenSSL writes the whole secret whatever room there is; this refuses less.
            // SAFETY: the caller's guarantee.
            if usize::try_from(size).is_ok_and(|n| unsafe { keylen.read() } < n) {
                err::raise(ERR_LIB_DH, DH_R_INVALID_SIZE, F);
                return 0;
            }
            let ret = if d.pad != 0 {
                // SAFETY: the caller's room for the prime's length; the peer's number, or
                // NULL; the key.
                unsafe { DH_compute_key_padded(key, pub_key, h) }
            } else {
                // SAFETY: as above.
                unsafe { DH_compute_key(key, pub_key, h) }
            };
            let Some(n) = usize::try_from(ret).ok().filter(|&n| n > 0) else { return ret };
            // SAFETY: the caller's guarantee.
            unsafe { keylen.write(n) };
            return 1;
        }
        if d.kdf_type != EVP_PKEY_DH_KDF_X9_42 {
            return 0;
        }
        if d.kdf_outlen == 0 || d.kdf_oid.is_null() {
            return 0;
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
        let Some(zlen) = usize::try_from(size).ok().filter(|&n| n > 0) else { return 0 };
        let mut z = vec![0u8; zlen];
        // SAFETY: room for the prime's length; the peer's number, or NULL; the key.
        let mut ok = unsafe { DH_compute_key_padded(z.as_mut_ptr(), pub_key, h) } > 0;
        if ok {
            // SAFETY: the caller's room for the KDF's length; the secret; the context's object,
            // keying material (or NULL), and digest.
            ok = unsafe { DH_KDF_X9_42(key, d.kdf_outlen, z.as_ptr(), zlen, d.kdf_oid, d.kdf_ukm, d.kdf_ukmlen, d.kdf_md) } != 0;
        }
        crate::provider::macs::wipe(&mut z);
        if ok {
            // SAFETY: the caller's guarantee.
            unsafe { keylen.write(d.kdf_outlen) };
        }
        c_int::from(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dh::DH_set_method;
    use crate::dh_meth::{DH_OpenSSL, DH_meth_dup, DH_meth_free};
    use crate::evp::exchange::{EVP_PKEY_derive, EVP_PKEY_derive_init, EVP_PKEY_derive_set_peer};
    use crate::evp::pkey::dh::EVP_PKEY_set1_DH;
    use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new};
    use crate::evp::pkey_ctx::{EVP_PKEY_CTX_free, EVP_PKEY_CTX_new};
    use rustyssl_abi::NID_ffdhe2048;

    /// A key of ffdhe2048 with a key pair and an application's method (so it stays legacy).
    fn legacy_key(meth: *const rustyssl_abi::DH_METHOD) -> *mut EVP_PKEY {
        // SAFETY: no preconditions.
        let h = unsafe { DH_new_by_nid(NID_ffdhe2048) };
        // SAFETY: the key just made; a live method.
        assert_eq!(unsafe { DH_set_method(h, meth) }, 1);
        // SAFETY: the key.
        assert_eq!(unsafe { DH_generate_key(h) }, 1);
        // SAFETY: no preconditions.
        let k = unsafe { EVP_PKEY_new() };
        // SAFETY: live objects; the key takes a reference.
        assert_eq!(unsafe { EVP_PKEY_set1_DH(k, h) }, 1);
        // SAFETY: the reference made above.
        unsafe { DH_free(h) };
        k
    }

    /// docs/DEVIATIONS.md: OpenSSL's derive writes the whole secret into less room, its getters
    /// write through NULL, and it takes keying material of a negative length.
    #[test]
    #[cfg_attr(miri, ignore = "generates DH keys")]
    fn less_room_null_getters_and_negative_lengths_are_safe() {
        // SAFETY: no preconditions.
        let builtin = unsafe { DH_OpenSSL() };
        // SAFETY: the built-in method.
        let meth = unsafe { DH_meth_dup(builtin) };
        let (a, b) = (legacy_key(meth), legacy_key(meth));
        // SAFETY: a live key; no engine.
        let ctx = unsafe { EVP_PKEY_CTX_new(a, ptr::null_mut()) };
        // SAFETY: the context.
        let r = unsafe { EVP_PKEY_derive_init(ctx) };
        assert_eq!(r, 1);
        // SAFETY: the context and the peer.
        let r = unsafe { EVP_PKEY_derive_set_peer(ctx, b) };
        assert_eq!(r, 1);
        let mut out = [0u8; 256];
        let mut n = 255;
        // SAFETY: room for 256 octets, of which 255 are offered.
        let r = unsafe { EVP_PKEY_derive(ctx, out.as_mut_ptr(), &raw mut n) };
        assert_eq!((r, out[255]), (0, 0));
        n = 256;
        // SAFETY: as above, all offered.
        let r = unsafe { EVP_PKEY_derive(ctx, out.as_mut_ptr(), &raw mut n) };
        assert_eq!(r, 1);
        for cmd in [
            EVP_PKEY_CTRL_GET_DH_KDF_MD,
            EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN,
            EVP_PKEY_CTRL_GET_DH_KDF_OID,
        ] {
            // SAFETY: the legacy context; NULL for the place.
            let r = unsafe { pkey_dh_ctrl(ctx, cmd, 0, ptr::null_mut()) };
            assert_eq!(r, 1);
        }
        // SAFETY: as above.
        let r = unsafe { pkey_dh_ctrl(ctx, EVP_PKEY_CTRL_GET_DH_KDF_UKM, 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        let mut ukm = [1u8; 4];
        let p2 = ukm.as_mut_ptr().cast();
        // SAFETY: the context; octets it refuses to take.
        let r = unsafe { pkey_dh_ctrl(ctx, EVP_PKEY_CTRL_DH_KDF_UKM, -1, p2) };
        assert_eq!(r, 0);
        // SAFETY: made above, each freed once.
        unsafe { EVP_PKEY_CTX_free(ctx) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(a) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(b) };
        // SAFETY: as above.
        unsafe { DH_meth_free(meth) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
