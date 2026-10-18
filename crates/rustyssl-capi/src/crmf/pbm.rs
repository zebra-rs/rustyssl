//! The password-based MAC of RFC 4211 section 4.4 (`crmf_pbm.c`): its parameters (a random
//! salt, the one-way function, the iteration count, the MAC), and the MAC: the OWF iterated
//! over the secret and salt gives the key, and HMAC with the MAC's digest the value.

use core::ffi::{c_char, c_int, c_uint};
use core::ptr;

use rustyssl_abi::{
    CRMF_R_BAD_PBM_ITERATIONCOUNT, CRMF_R_CRMFERROR, CRMF_R_FAILURE_OBTAINING_RANDOM,
    CRMF_R_ITERATIONCOUNT_BELOW_100, CRMF_R_NULL_ARGUMENT, CRMF_R_SETTING_MAC_ALGOR_FAILURE,
    CRMF_R_SETTING_OWF_ALGOR_FAILURE, CRMF_R_UNSUPPORTED_ALGORITHM, ERR_LIB_CRMF, EVP_MAX_MD_SIZE,
    EVP_PBE_TYPE_PRF, NID_undef, OSSL_CRMF_PBMPARAMETER, OSSL_LIB_CTX, V_ASN1_UNDEF,
};

use super::asn::{OSSL_CRMF_PBMPARAMETER_free, OSSL_CRMF_PBMPARAMETER_new, PbmParameter, of};
use crate::asn1::integer::{ASN1_INTEGER_get_int64, ASN1_INTEGER_set};
use crate::asn1::string::ASN1_OCTET_STRING_set;
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::mac::EVP_Q_mac;
use crate::evp::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
};
use crate::evp::pbe::EVP_PBE_find;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_nid2obj, OBJ_obj2nid, OBJ_obj2txt};
use crate::rand_lib::RAND_bytes_ex;
use crate::x509::algor::X509_ALGOR_set0;

fn raise(reason: c_int, f: &str) {
    err::raise(ERR_LIB_CRMF, reason, f);
}

/// `OSSL_CRMF_PBM_MAX_ITERATION_COUNT` (`crmf_local.h`): more allows a denial of service.
const OSSL_CRMF_PBM_MAX_ITERATION_COUNT: usize = 100_000;

ffi_export! {
    /// New parameters: `slen` random salt octets, the OWF `owfnid`, `itercnt` iterations (100
    /// to `OSSL_CRMF_PBM_MAX_ITERATION_COUNT`), and the MAC `macnid`; or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context.
    pub unsafe extern "C" fn OSSL_CRMF_pbmp_new(libctx: *mut OSSL_LIB_CTX, slen: usize, owfnid: c_int, itercnt: usize, macnid: c_int) -> *mut OSSL_CRMF_PBMPARAMETER
    where failure = ptr::null_mut(), library = ERR_LIB_CRMF
    {
        const F: &str = "OSSL_CRMF_pbmp_new";
        // SAFETY: no preconditions.
        let pbm = unsafe { OSSL_CRMF_PBMPARAMETER_new() };
        // SAFETY: made here, or NULL.
        let ok = unsafe { of::<PbmParameter, _>(pbm) }.is_some_and(|p| {
            let mut salt = vec![0u8; slen];
            // SAFETY: the library context; the room.
            if unsafe { RAND_bytes_ex(libctx, salt.as_mut_ptr(), slen, 0) } <= 0 {
                raise(CRMF_R_FAILURE_OBTAINING_RANDOM, F);
                return false;
            }
            let Ok(n) = c_int::try_from(slen) else { return false };
            // SAFETY: its salt; the octets.
            if unsafe { ASN1_OCTET_STRING_set(p.salt, salt.as_ptr(), n) } == 0 {
                return false;
            }
            // SAFETY: a NID; NULL if unknown.
            let owf = unsafe { OBJ_nid2obj(owfnid) };
            // SAFETY: its OWF; a static object.
            if unsafe { X509_ALGOR_set0(p.owf, owf, V_ASN1_UNDEF, ptr::null_mut()) } == 0 {
                raise(CRMF_R_SETTING_OWF_ALGOR_FAILURE, F);
                return false;
            }
            if itercnt < 100 {
                raise(CRMF_R_ITERATIONCOUNT_BELOW_100, F);
                return false;
            }
            if itercnt > OSSL_CRMF_PBM_MAX_ITERATION_COUNT {
                raise(CRMF_R_BAD_PBM_ITERATIONCOUNT, F);
                return false;
            }
            // SAFETY: its count.
            if unsafe { ASN1_INTEGER_set(p.iteration_count, core::ffi::c_long::try_from(itercnt).unwrap_or(0)) } == 0 {
                raise(CRMF_R_CRMFERROR, F);
                return false;
            }
            // SAFETY: a NID; NULL if unknown.
            let mac = unsafe { OBJ_nid2obj(macnid) };
            // SAFETY: its MAC; a static object.
            if unsafe { X509_ALGOR_set0(p.mac, mac, V_ASN1_UNDEF, ptr::null_mut()) } == 0 {
                raise(CRMF_R_SETTING_MAC_ALGOR_FAILURE, F);
                return false;
            }
            true
        });
        if !ok {
            // SAFETY: made here, or NULL.
            unsafe { OSSL_CRMF_PBMPARAMETER_free(pbm) };
            return ptr::null_mut();
        }
        pbm
    }
}

/// The OWF iterated over the secret and salt: the base key into `basekey`, its length.
///
/// # Safety
/// `p`'s members are live.
unsafe fn base_key(
    p: &PbmParameter,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    sec: &[u8],
    basekey: &mut [u8; EVP_MAX_MD_SIZE as usize],
) -> Option<c_uint> {
    const F: &str = "OSSL_CRMF_pbm_new";
    let mut mdname = [0 as c_char; super::NAME_LEN];
    let len = c_int::try_from(super::NAME_LEN).unwrap_or(0);
    // SAFETY: its OWF, checked by the caller.
    let owf = unsafe { (*p.owf).algorithm };
    // SAFETY: the room; its OWF's object.
    unsafe { OBJ_obj2txt(mdname.as_mut_ptr(), len, owf, 0) };
    // SAFETY: the library context; a NUL-terminated name; the properties.
    let owf = unsafe { EVP_MD_fetch(libctx, mdname.as_ptr(), propq) };
    if owf.is_null() {
        raise(CRMF_R_UNSUPPORTED_ALGORITHM, F);
        return None;
    }
    // SAFETY: no preconditions.
    let ctx = unsafe { EVP_MD_CTX_new() };
    let mut bklen = EVP_MAX_MD_SIZE as c_uint;
    let out = 'b: {
        if ctx.is_null() {
            break 'b None;
        }
        // SAFETY: its salt.
        let salt = unsafe { &*p.salt };
        let salt_len = usize::try_from(salt.length).unwrap_or(0);
        // SAFETY: the context; the digest; the secret and the salt; the room.
        if unsafe { EVP_DigestInit_ex(ctx, owf, ptr::null_mut()) } == 0
            // SAFETY: as above.
            || unsafe { EVP_DigestUpdate(ctx, sec.as_ptr().cast(), sec.len()) } == 0
            // SAFETY: as above.
            || unsafe { EVP_DigestUpdate(ctx, salt.data.cast(), salt_len) } == 0
            // SAFETY: as above.
            || unsafe { EVP_DigestFinal_ex(ctx, basekey.as_mut_ptr(), &raw mut bklen) } == 0
        {
            break 'b None;
        }
        let mut iterations: i64 = 0;
        // SAFETY: room for the count; its count.
        if unsafe { ASN1_INTEGER_get_int64(&raw mut iterations, p.iteration_count) } == 0
            || !(100..=i64::try_from(OSSL_CRMF_PBM_MAX_ITERATION_COUNT).unwrap_or(0))
                .contains(&iterations)
        {
            raise(CRMF_R_BAD_PBM_ITERATIONCOUNT, F);
            break 'b None;
        }
        for _ in 1..iterations {
            let n = bklen as usize;
            // SAFETY: as above, the base key as input and output.
            if unsafe { EVP_DigestInit_ex(ctx, owf, ptr::null_mut()) } == 0
                // SAFETY: as above.
                || unsafe { EVP_DigestUpdate(ctx, basekey.as_ptr().cast(), n) } == 0
                // SAFETY: as above.
                || unsafe { EVP_DigestFinal_ex(ctx, basekey.as_mut_ptr(), &raw mut bklen) } == 0
            {
                break 'b None;
            }
        }
        Some(bklen)
    };
    // SAFETY: fetched here.
    unsafe { EVP_MD_free(owf) };
    // SAFETY: made here, or NULL.
    unsafe { EVP_MD_CTX_free(ctx) };
    out
}

ffi_export! {
    /// The MAC of `msg` under the secret with the parameters: 1 with the value
    /// (`CRYPTO_malloc`) in `*out` and its length in `*outlen`, or 0.
    ///
    /// # Safety
    /// `pbmp` is NULL or live; `msg` and `sec` point to their lengths' octets; `out` and
    /// `outlen` are NULL or writable.
    pub unsafe extern "C" fn OSSL_CRMF_pbm_new(libctx: *mut OSSL_LIB_CTX, propq: *const c_char, pbmp: *const OSSL_CRMF_PBMPARAMETER, msg: *const u8, msglen: usize, sec: *const u8, seclen: usize, out: *mut *mut u8, outlen: *mut usize) -> c_int
    where failure = 0, library = ERR_LIB_CRMF
    {
        const F: &str = "OSSL_CRMF_pbm_new";
        // SAFETY: the caller's guarantee.
        let p = unsafe { of::<PbmParameter, _>(pbmp) };
        // SAFETY: its MAC, or NULL.
        let mac_ok = p.as_ref().is_some_and(|p| unsafe { p.mac.as_ref() }.is_some_and(|m| !m.algorithm.is_null()));
        let (Some(p), true, false, false, false) = (p, mac_ok, out.is_null(), msg.is_null(), sec.is_null()) else {
            raise(CRMF_R_NULL_ARGUMENT, F);
            return 0;
        };
        let ok = 'm: {
            // SAFETY: the caller's `seclen` octets.
            let secret = unsafe { core::slice::from_raw_parts(sec, seclen) };
            let mut basekey = [0u8; EVP_MAX_MD_SIZE as usize];
            // SAFETY: the parameters' members.
            let bklen = unsafe { base_key(p, libctx, propq, secret, &mut basekey) };
            let Some(bklen) = bklen else {
                wipe(&mut basekey);
                break 'm None;
            };
            // SAFETY: its MAC, checked above.
            let mac_alg = unsafe { (*p.mac).algorithm };
            // SAFETY: its MAC's object.
            let mac_nid = unsafe { OBJ_obj2nid(mac_alg) };
            let mut hmac_md_nid = NID_undef;
            let mut hmac_mdname = [0 as c_char; super::NAME_LEN];
            let len = c_int::try_from(super::NAME_LEN).unwrap_or(0);
            // SAFETY: rooms for what it finds.
            let found = unsafe { EVP_PBE_find(EVP_PBE_TYPE_PRF, mac_nid, ptr::null_mut(), &raw mut hmac_md_nid, ptr::null_mut()) } != 0
                // SAFETY: the room; a known NID's object.
                && unsafe { OBJ_obj2txt(hmac_mdname.as_mut_ptr(), len, nid_obj(hmac_md_nid), 0) } > 0;
            if !found {
                wipe(&mut basekey);
                raise(CRMF_R_UNSUPPORTED_ALGORITHM, F);
                break 'm None;
            }
            let mac_res: *mut u8 = mem::alloc(EVP_MAX_MD_SIZE as usize).cast();
            if mac_res.is_null() {
                wipe(&mut basekey);
                break 'm None;
            }
            let mut n = 0usize;
            // SAFETY: the library context; static and NUL-terminated names; the base key; the
            // caller's message; the room for the value.
            let r = unsafe { EVP_Q_mac(libctx, c"HMAC".as_ptr(), propq, hmac_mdname.as_ptr(), ptr::null(), basekey.as_ptr().cast(), bklen as usize, msg, msglen, mac_res, EVP_MAX_MD_SIZE as usize, &raw mut n) };
            wipe(&mut basekey);
            if r.is_null() {
                // SAFETY: allocated above.
                unsafe { mem::release(mac_res.cast()) };
                break 'm None;
            }
            Some((mac_res, n))
        };
        match ok {
            Some((v, n)) => {
                // SAFETY: the caller's rooms.
                unsafe { *out = v };
                // SAFETY: as above, or NULL.
                if let Some(l) = unsafe { outlen.as_mut() } {
                    *l = n;
                }
                1
            }
            None => {
                let mut buf = [0 as c_char; 128];
                // SAFETY: its MAC, checked above.
                let mac_alg = unsafe { (*p.mac).algorithm };
                // SAFETY: the room; its MAC's object.
                if unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 128, mac_alg, 0) } > 0 {
                    // SAFETY: NUL-terminated by the call.
                    let t = unsafe { core::ffi::CStr::from_ptr(buf.as_ptr()) };
                    err::add_error_data([Some(t.to_bytes())]);
                }
                0
            }
        }
    }
}

/// Zeroes a base key.
fn wipe(key: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { mem::cleanse(key.as_mut_ptr().cast(), key.len()) };
}

/// The object of a NID, or NULL.
fn nid_obj(nid: c_int) -> *const rustyssl_abi::ASN1_OBJECT {
    // SAFETY: no preconditions.
    unsafe { OBJ_nid2obj(nid) }
}
