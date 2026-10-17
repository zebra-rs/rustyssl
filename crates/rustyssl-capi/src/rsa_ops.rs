//! What the four RSA operations are built into (`rsa_sign.c`, `rsa_saos.c`, `rsa_pk1.c`,
//! `rsa_oaep.c`, `rsa_none.c`, `rsa_x931.c`, `rsa_pss.c`, `rsa_x931g.c`, `rsa_gen.c`,
//! `rsa_chk.c`, `rsa_depr.c`): the padding functions, PSS, `RSA_sign` and `RSA_verify` (and
//! their OCTET STRING forms), X9.31 keys, key generation, and the key check.
//!
//! As in OpenSSL, signing and verifying go through the key's method: its `rsa_sign` or
//! `rsa_verify` if it has them, else its private encryption or public decryption, which the
//! providers' operations use too (`method_op`). Key generation goes through the method's
//! `rsa_keygen` or `rsa_multi_prime_keygen` when it has them.
//!
//! The padding functions take OpenSSL's buffers and lengths; negative lengths and NULL
//! buffers, which OpenSSL's would write through, fail (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_long, c_uchar, c_uint, c_ulong, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_GENCB, ERR_LIB_RSA, EVP_MD, RSA, RSA_PKCS1_PADDING, RSA_R_BAD_SIGNATURE,
    RSA_R_WRONG_SIGNATURE_LENGTH,
};
use rustyssl_crypto::bn::{self as core_bn, BigNum};
use rustyssl_crypto::rsa::{
    self as core_rsa, Hash, Key, add_none, add_oaep, add_pkcs1_type1, add_pkcs1_type2, add_pss,
    add_x931, check_decrypted, check_none, check_oaep, check_pkcs1_type1, check_pkcs1_type2,
    check_x931, octet_string_encoding, sign_encoding, verify_pss, x931_hash_id,
};

use crate::asn1::string::ASN1_OCTET_STRING_free;
use crate::asn1::tpl::items::d2i_ASN1_OCTET_STRING;
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::modular::BN_mod_inverse;
use crate::bn::prime::{
    BN_GENCB_free, BN_GENCB_new, BN_GENCB_set_old, BN_X931_derive_prime_ex, BN_X931_generate_Xpq,
    BN_X931_generate_prime_ex,
};
use crate::bn::{BN_free, new_bignum, value};
use crate::err;
use crate::ffi::{bytes, ffi_export};
use crate::rsa::{Md, public_random, raise_all, rsa};
use crate::rsa_gen::{generate_key, validate_keypair};
use crate::rsa_lib::{
    RSA_free, RSA_new, RSA_private_decrypt, RSA_private_encrypt, RSA_public_decrypt,
    RSA_public_encrypt,
};
use crate::rsa_meth::fns_of;

/// One of the four operations.
#[derive(Clone, Copy)]
pub(crate) enum Op {
    PublicEncrypt,
    PublicDecrypt,
    PrivateEncrypt,
    PrivateDecrypt,
}

/// The key's size in octets (0 without a modulus or a key).
///
/// # Safety
/// `r` is NULL or a live key.
pub(crate) unsafe fn size(r: *const RSA) -> usize {
    // SAFETY: the caller's guarantee.
    unsafe { rsa(r) }.map_or(0, |k| k.snapshot().key.size())
}

/// `op` through the key's method: `from` into `to`, which receives at most its own length of
/// what the method writes (the method writes into a buffer of the key's size). The length, or
/// `Err` (the method's errors raised).
///
/// # Safety
/// `r` is NULL or a live key.
pub(crate) unsafe fn method_op(
    r: *mut RSA,
    op: Op,
    from: &[u8],
    to: &mut [u8],
    padding: c_int,
) -> Result<usize, ()> {
    // SAFETY: the caller's guarantee.
    let num = unsafe { size(r) };
    let flen = c_int::try_from(from.len()).map_err(|_| ())?;
    let mut buf = vec![0u8; num.max(to.len()).max(1)];
    let f = match op {
        Op::PublicEncrypt => RSA_public_encrypt,
        Op::PublicDecrypt => RSA_public_decrypt,
        Op::PrivateEncrypt => RSA_private_encrypt,
        Op::PrivateDecrypt => RSA_private_decrypt,
    };
    // SAFETY: the key; `from` holds `flen` octets; the buffer has room for the key's size.
    let n = unsafe { f(flen, from.as_ptr(), buf.as_mut_ptr(), r, padding) };
    let n = usize::try_from(n).map_err(|_| ())?;
    let take = n.min(to.len()).min(buf.len());
    to.get_mut(..take)
        .ok_or(())?
        .copy_from_slice(buf.get(..take).ok_or(())?);
    Ok(n)
}

/// `RSA_sign`'s work: the method's `rsa_sign`, or the DigestInfo through its private
/// encryption. The signature's length.
///
/// # Safety
/// `r` is NULL or a live key; `sig` has room for the key's size.
pub(crate) unsafe fn sign(r: *mut RSA, nid: c_int, m: &[u8], sig: &mut [u8]) -> Option<usize> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { rsa(r) }?;
    // SAFETY: the key's method, live.
    if let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.sign) {
        let mut len: c_uint = 0;
        let mlen = c_uint::try_from(m.len()).ok()?;
        // SAFETY: the method's function takes these; no lock is held.
        let ok = unsafe { f(nid, m.as_ptr(), mlen, sig.as_mut_ptr(), &raw mut len, r) } > 0;
        return ok.then(|| usize::try_from(len).unwrap_or(0));
    }
    // SAFETY: as above.
    let num = unsafe { size(r) };
    let encoded = match sign_encoding(nid, m, num) {
        Ok(e) => e,
        Err(raised) => {
            raise_all(&raised);
            return None;
        }
    };
    // SAFETY: as above.
    let n = unsafe { method_op(r, Op::PrivateEncrypt, &encoded, sig, RSA_PKCS1_PADDING) }.ok()?;
    (n > 0).then_some(n)
}

/// `ossl_rsa_verify`: whether `sig` signs the digest `m` of `nid` (through the key's public
/// decryption), or, with no `m`, the digest it recovers. The digest.
///
/// # Safety
/// `r` is NULL or a live key.
pub(crate) unsafe fn ossl_verify(
    r: *mut RSA,
    nid: c_int,
    m: Option<&[u8]>,
    sig: &[u8],
) -> Option<Vec<u8>> {
    // SAFETY: the caller's guarantee.
    let num = unsafe { size(r) };
    if sig.len() != num {
        err::raise(ERR_LIB_RSA, RSA_R_WRONG_SIGNATURE_LENGTH, "ossl_rsa_verify");
        return None;
    }
    let mut buf = vec![0u8; num];
    // SAFETY: as above.
    let n = unsafe { method_op(r, Op::PublicDecrypt, sig, &mut buf, RSA_PKCS1_PADDING) }.ok()?;
    if n == 0 {
        return None;
    }
    let (res, raised) = check_decrypted(nid, m, buf.get(..n)?);
    raise_all(&raised);
    res.ok()
}

/// `RSA_verify`'s work: the method's `rsa_verify`, or `ossl_rsa_verify`. 1, 0, or what the
/// method returns.
///
/// # Safety
/// `r` is NULL or a live key.
pub(crate) unsafe fn verify(r: *mut RSA, nid: c_int, m: &[u8], sig: &[u8]) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { rsa(r) }) else {
        return 0;
    };
    // SAFETY: the key's method, live.
    if let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.verify) {
        let (Ok(mlen), Ok(slen)) = (c_uint::try_from(m.len()), c_uint::try_from(sig.len())) else {
            return 0;
        };
        // SAFETY: the method's function takes these; no lock is held.
        return unsafe { f(nid, m.as_ptr(), mlen, sig.as_ptr(), slen, r) };
    }
    // SAFETY: as above.
    c_int::from(unsafe { ossl_verify(r, nid, Some(m), sig) }.is_some())
}

/// `RSA_sign_ASN1_OCTET_STRING`'s work: `m` as a DER OCTET STRING through the key's private
/// encryption. The signature's length.
///
/// # Safety
/// `r` is NULL or a live key; `sig` has room for the key's size.
pub(crate) unsafe fn sign_octet_string(r: *mut RSA, m: &[u8], sig: &mut [u8]) -> Option<usize> {
    // SAFETY: the caller's guarantee.
    let num = unsafe { size(r) };
    let der = match octet_string_encoding(m, num) {
        Ok(d) => d,
        Err(raised) => {
            raise_all(&raised);
            return None;
        }
    };
    // SAFETY: as above.
    let n = unsafe { method_op(r, Op::PrivateEncrypt, &der, sig, RSA_PKCS1_PADDING) }.ok()?;
    (n > 0).then_some(n)
}

/// `to` (`tlen` octets) and `from` (`flen`) as slices, or `None` for a negative length or a
/// NULL buffer with a length.
///
/// # Safety
/// `to` has room for `tlen` octets; `from` holds `flen`.
unsafe fn bufs<'a>(
    to: *mut c_uchar,
    tlen: c_int,
    from: *const c_uchar,
    flen: c_int,
) -> Option<(&'a mut [u8], &'a [u8])> {
    let (tlen, flen) = (usize::try_from(tlen).ok()?, usize::try_from(flen).ok()?);
    // SAFETY: the caller's guarantee.
    let from = unsafe { bytes(from, flen) }?;
    if to.is_null() && tlen > 0 {
        return None;
    }
    let to = if tlen == 0 {
        &mut []
    } else {
        // SAFETY: the caller's room for `tlen` octets.
        unsafe { core::slice::from_raw_parts_mut(to, tlen) }
    };
    Some((to, from))
}

/// An add function's result: 1, or 0 with its errors raised.
fn added(r: core_rsa::Outcome<()>) -> c_int {
    raise_all(&r.1);
    c_int::from(r.0.is_ok())
}

/// A check function's result: the length, or -1 with its errors raised.
fn checked(r: core_rsa::Outcome<usize>) -> c_int {
    raise_all(&r.1);
    r.0.ok().and_then(|n| c_int::try_from(n).ok()).unwrap_or(-1)
}

/// A constant-time check's result.
fn checked_ct(r: (isize, core_rsa::Raised)) -> c_int {
    raise_all(&r.1);
    c_int::try_from(r.0).unwrap_or(-1)
}

/// The digest `md`, or SHA-1 (OAEP's default) from the default context.
///
/// # Safety
/// `md` is NULL or a live digest.
unsafe fn md_or_sha1(md: *const EVP_MD) -> Option<Md> {
    if md.is_null() {
        // SAFETY: the default context; a name; no properties.
        unsafe { Md::fetch(ptr::null_mut(), c"SHA1", ptr::null()) }
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { Md::of(md) }
    }
}

ffi_export! {
    /// `00 01 FF.. 00 || from` into `to` (`tlen` octets). 1, or 0.
    ///
    /// # Safety
    /// `to` has room for `tlen` octets; `from` holds `flen`.
    pub unsafe extern "C" fn RSA_padding_add_PKCS1_type_1(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return 0 };
        added(add_pkcs1_type1(to, from))
    }
}

ffi_export! {
    /// The data of a PKCS #1 v1.5 type 1 block (with or without its leading zero) for a key of
    /// `num` octets, into `to`. The length, or -1.
    ///
    /// # Safety
    /// `to` has room for `tlen` octets; `from` holds `flen`.
    pub unsafe extern "C" fn RSA_padding_check_PKCS1_type_1(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int, num: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return -1 };
        let Ok(num) = usize::try_from(num) else { return -1 };
        checked(check_pkcs1_type1(to, from, num))
    }
}

ffi_export! {
    /// `00 02 PS 00 || from` with random nonzero padding (from the default context's public
    /// generator). 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_padding_add_PKCS1_type_1`.
    pub unsafe extern "C" fn RSA_padding_add_PKCS1_type_2(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return 0 };
        let mut rng = public_random(ptr::null_mut());
        added(add_pkcs1_type2(to, from, &mut rng))
    }
}

ffi_export! {
    /// The data of a PKCS #1 v1.5 type 2 block, in constant time (no implicit rejection). The
    /// length, or -1.
    ///
    /// # Safety
    /// As for `RSA_padding_check_PKCS1_type_1`.
    pub unsafe extern "C" fn RSA_padding_check_PKCS1_type_2(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int, num: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return -1 };
        let Ok(num) = usize::try_from(num) else { return -1 };
        checked_ct(check_pkcs1_type2(to, from, num))
    }
}

ffi_export! {
    /// OAEP with SHA-1 and the label `param`. 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_padding_add_PKCS1_type_1`; `param` holds `plen` octets.
    pub unsafe extern "C" fn RSA_padding_add_PKCS1_OAEP(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int, param: *const c_uchar, plen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { RSA_padding_add_PKCS1_OAEP_mgf1(to, tlen, from, flen, param, plen, ptr::null(), ptr::null()) }
    }
}

ffi_export! {
    /// OAEP with the digest `md` (SHA-1 for NULL), MGF1 with `mgf1md` (`md` for NULL), and the
    /// label `param`. 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_padding_add_PKCS1_OAEP`; each digest is NULL or live.
    pub unsafe extern "C" fn RSA_padding_add_PKCS1_OAEP_mgf1(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int, param: *const c_uchar, plen: c_int, md: *const EVP_MD, mgf1md: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return 0 };
        let Ok(plen) = usize::try_from(plen) else { return 0 };
        // SAFETY: as above.
        let Some(label) = (unsafe { bytes(param, plen) }) else { return 0 };
        // SAFETY: as above.
        let Some(md) = (unsafe { md_or_sha1(md) }) else { return 0 };
        // SAFETY: as above.
        let mgf1 = if mgf1md.is_null() { md.clone() } else { match unsafe { Md::of(mgf1md) } {
            Some(m) => m,
            None => return 0,
        } };
        let mut rng = public_random(ptr::null_mut());
        added(add_oaep(to, from, label, &md, &mgf1, &mut rng))
    }
}

ffi_export! {
    /// The data of an OAEP block (SHA-1, the label `param`), in constant time. The length, or
    /// -1.
    ///
    /// # Safety
    /// As for `RSA_padding_check_PKCS1_type_1`; `param` holds `plen` octets.
    pub unsafe extern "C" fn RSA_padding_check_PKCS1_OAEP(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int, num: c_int, param: *const c_uchar, plen: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { RSA_padding_check_PKCS1_OAEP_mgf1(to, tlen, from, flen, num, param, plen, ptr::null(), ptr::null()) }
    }
}

ffi_export! {
    /// The data of an OAEP block with `md` (SHA-1 for NULL) and `mgf1md` (`md` for NULL), in
    /// constant time. The length, or -1.
    ///
    /// # Safety
    /// As for `RSA_padding_check_PKCS1_OAEP`; each digest is NULL or live.
    pub unsafe extern "C" fn RSA_padding_check_PKCS1_OAEP_mgf1(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int, num: c_int, param: *const c_uchar, plen: c_int, md: *const EVP_MD, mgf1md: *const EVP_MD) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return -1 };
        let (Ok(num), Ok(plen)) = (usize::try_from(num), usize::try_from(plen)) else { return -1 };
        // SAFETY: as above.
        let Some(label) = (unsafe { bytes(param, plen) }) else { return -1 };
        // SAFETY: as above.
        let Some(md) = (unsafe { md_or_sha1(md) }) else { return -1 };
        // SAFETY: as above.
        let mgf1 = if mgf1md.is_null() { md.clone() } else { match unsafe { Md::of(mgf1md) } {
            Some(m) => m,
            None => return -1,
        } };
        checked_ct(check_oaep(to, from, num, label, &md, &mgf1))
    }
}

ffi_export! {
    /// `from` as it is, which must be exactly `tlen` octets. 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_padding_add_PKCS1_type_1`.
    pub unsafe extern "C" fn RSA_padding_add_none(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return 0 };
        added(add_none(to, from))
    }
}

ffi_export! {
    /// `from` right-aligned in `to` (`tlen` octets, zeros before). `tlen`, or -1.
    ///
    /// # Safety
    /// As for `RSA_padding_check_PKCS1_type_1`.
    pub unsafe extern "C" fn RSA_padding_check_none(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int, _num: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return -1 };
        checked(check_none(to, from))
    }
}

ffi_export! {
    /// `6A || from || CC`, or `6B BB.. BA || from || CC`. 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_padding_add_PKCS1_type_1`.
    pub unsafe extern "C" fn RSA_padding_add_X931(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return 0 };
        added(add_x931(to, from))
    }
}

ffi_export! {
    /// The data of an X9.31 block of `num` octets. The length, or -1.
    ///
    /// # Safety
    /// As for `RSA_padding_check_PKCS1_type_1`.
    pub unsafe extern "C" fn RSA_padding_check_X931(to: *mut c_uchar, tlen: c_int, from: *const c_uchar, flen: c_int, num: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((to, from)) = (unsafe { bufs(to, tlen, from, flen) }) else { return -1 };
        let Ok(num) = usize::try_from(num) else { return -1 };
        checked(check_x931(to, from, num))
    }
}

ffi_export! {
    /// The X9.31 hash identifier of the digest `nid`, or -1.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RSA_X931_hash_id(nid: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        x931_hash_id(nid)
    }
}

/// The key's size and bits, for the PSS functions (none without a modulus).
///
/// # Safety
/// `r` is NULL or a live key.
unsafe fn key_dims(r: *const RSA) -> Option<(usize, usize, *mut rustyssl_abi::OSSL_LIB_CTX)> {
    // SAFETY: the caller's guarantee.
    let k = unsafe { rsa(r) }?;
    let st = k.snapshot();
    st.key.n.as_ref()?;
    Some((st.key.size(), st.key.bits(), k.libctx.get()))
}

ffi_export! {
    /// The digest `m_hash` PSS-encoded into `em` (the key's size) with `hash` for both. 1, or 0.
    ///
    /// # Safety
    /// `rsa` is a live key; `em` has room for its size; `m_hash` holds `hash`'s size.
    pub unsafe extern "C" fn RSA_padding_add_PKCS1_PSS(rsa: *mut RSA, em: *mut c_uchar, m_hash: *const c_uchar, hash: *const EVP_MD, s_len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, m_hash, hash, ptr::null(), s_len) }
    }
}

ffi_export! {
    /// The digest `m_hash` PSS-encoded into `em` with `hash`, MGF1 with `mgf1_hash` (`hash` for
    /// NULL), and a salt of `s_len` (or a special length) from the key's context. 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_padding_add_PKCS1_PSS`; `mgf1_hash` is NULL or live.
    pub unsafe extern "C" fn RSA_padding_add_PKCS1_PSS_mgf1(rsa: *mut RSA, em: *mut c_uchar, m_hash: *const c_uchar, hash: *const EVP_MD, mgf1_hash: *const EVP_MD, s_len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((num, bits, libctx)) = (unsafe { key_dims(rsa) }) else { return 0 };
        // SAFETY: as above.
        let Some(md) = (unsafe { Md::of(hash) }) else { return 0 };
        // SAFETY: as above.
        let mgf1 = if mgf1_hash.is_null() { md.clone() } else { match unsafe { Md::of(mgf1_hash) } {
            Some(m) => m,
            None => return 0,
        } };
        // SAFETY: the caller's digest of the hash's size.
        let Some(mhash) = (unsafe { bytes(m_hash, md.size()) }) else { return 0 };
        if em.is_null() {
            return 0;
        }
        // SAFETY: the caller's room for the key's size.
        let em = unsafe { core::slice::from_raw_parts_mut(em, num) };
        let mut rng = public_random(libctx);
        let (r, raised) = add_pss(em, bits, mhash, &md, &mgf1, s_len, &mut rng);
        raise_all(&raised);
        c_int::from(r.is_ok())
    }
}

ffi_export! {
    /// Whether `em` (the key's size) PSS-encodes `m_hash` with `hash` for both. 1, or 0.
    ///
    /// # Safety
    /// `rsa` is a live key; `em` holds its size; `m_hash` holds `hash`'s size.
    pub unsafe extern "C" fn RSA_verify_PKCS1_PSS(rsa: *mut RSA, m_hash: *const c_uchar, hash: *const EVP_MD, em: *const c_uchar, s_len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { RSA_verify_PKCS1_PSS_mgf1(rsa, m_hash, hash, ptr::null(), em, s_len) }
    }
}

ffi_export! {
    /// Whether `em` PSS-encodes `m_hash` with `hash`, MGF1 with `mgf1_hash` (`hash` for NULL),
    /// and a salt of `s_len` (or one detected). 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_verify_PKCS1_PSS`; `mgf1_hash` is NULL or live.
    pub unsafe extern "C" fn RSA_verify_PKCS1_PSS_mgf1(rsa: *mut RSA, m_hash: *const c_uchar, hash: *const EVP_MD, mgf1_hash: *const EVP_MD, em: *const c_uchar, s_len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some((num, bits, _)) = (unsafe { key_dims(rsa) }) else { return 0 };
        // SAFETY: as above.
        let Some(md) = (unsafe { Md::of(hash) }) else { return 0 };
        // SAFETY: as above.
        let mgf1 = if mgf1_hash.is_null() { md.clone() } else { match unsafe { Md::of(mgf1_hash) } {
            Some(m) => m,
            None => return 0,
        } };
        // SAFETY: the caller's digest and block.
        let (Some(mhash), Some(em)) = (unsafe { bytes(m_hash, md.size()) }, unsafe { bytes(em, num) }) else {
            return 0;
        };
        let (r, raised) = verify_pss(mhash, &md, &mgf1, em, bits, s_len);
        raise_all(&raised);
        c_int::from(r.is_ok())
    }
}

ffi_export! {
    /// The digest `m` of `type_` signed into `sigret` (the key's size), its length into
    /// `siglen`: through the method's `rsa_sign`, or its private encryption. 1, or 0.
    ///
    /// # Safety
    /// `rsa` is a live key; `m` holds `m_len` octets; `sigret` has room for the key's size;
    /// `siglen` is writable.
    pub unsafe extern "C" fn RSA_sign(type_: c_int, m: *const c_uchar, m_len: c_uint, sigret: *mut c_uchar, siglen: *mut c_uint, rsa: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        let Ok(mlen) = usize::try_from(m_len) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { bytes(m, mlen) }) else { return 0 };
        if sigret.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let num = unsafe { size(rsa) };
        // SAFETY: the caller's room for the key's size.
        let sig = unsafe { core::slice::from_raw_parts_mut(sigret, num.max(1)) };
        // SAFETY: as above.
        match unsafe { sign(rsa, type_, m, sig) } {
            Some(n) => {
                if !siglen.is_null() {
                    // SAFETY: the caller's guarantee.
                    unsafe { siglen.write(c_uint::try_from(n).unwrap_or(0)) };
                }
                1
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// Whether `sigbuf` signs the digest `m` of `type_`: through the method's `rsa_verify`, or
    /// its public decryption. 1, or 0.
    ///
    /// # Safety
    /// `rsa` is a live key; `m` holds `m_len` octets; `sigbuf` holds `siglen`.
    pub unsafe extern "C" fn RSA_verify(type_: c_int, m: *const c_uchar, m_len: c_uint, sigbuf: *const c_uchar, siglen: c_uint, rsa: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        let (Ok(mlen), Ok(slen)) = (usize::try_from(m_len), usize::try_from(siglen)) else { return 0 };
        // SAFETY: the caller's guarantee.
        let (Some(m), Some(sig)) = (unsafe { bytes(m, mlen) }, unsafe { bytes(sigbuf, slen) }) else { return 0 };
        // SAFETY: as above.
        unsafe { verify(rsa, type_, m, sig) }
    }
}

ffi_export! {
    /// `m` signed as a DER OCTET STRING (MDC2's form). 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_sign`.
    pub unsafe extern "C" fn RSA_sign_ASN1_OCTET_STRING(_type_: c_int, m: *const c_uchar, m_len: c_uint, sigret: *mut c_uchar, siglen: *mut c_uint, rsa: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        let Ok(mlen) = usize::try_from(m_len) else { return 0 };
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { bytes(m, mlen) }) else { return 0 };
        if sigret.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let num = unsafe { size(rsa) };
        // SAFETY: the caller's room for the key's size.
        let sig = unsafe { core::slice::from_raw_parts_mut(sigret, num.max(1)) };
        // SAFETY: as above.
        match unsafe { sign_octet_string(rsa, m, sig) } {
            Some(n) => {
                if !siglen.is_null() {
                    // SAFETY: the caller's guarantee.
                    unsafe { siglen.write(c_uint::try_from(n).unwrap_or(0)) };
                }
                1
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// Whether `sigbuf` signs `m` as a DER OCTET STRING. 1, or 0.
    ///
    /// # Safety
    /// `rsa` is a live key; `m` holds `m_len` octets; `sigbuf` holds `siglen`.
    pub unsafe extern "C" fn RSA_verify_ASN1_OCTET_STRING(_dtype: c_int, m: *const c_uchar, m_len: c_uint, sigbuf: *mut c_uchar, siglen: c_uint, rsa: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        const F: &str = "RSA_verify_ASN1_OCTET_STRING";
        let (Ok(mlen), Ok(slen)) = (usize::try_from(m_len), usize::try_from(siglen)) else { return 0 };
        // SAFETY: the caller's guarantee.
        let (Some(m), Some(sig)) = (unsafe { bytes(m, mlen) }, unsafe { bytes(sigbuf, slen) }) else { return 0 };
        // SAFETY: as above.
        let num = unsafe { size(rsa) };
        if slen != num {
            err::raise(ERR_LIB_RSA, RSA_R_WRONG_SIGNATURE_LENGTH, F);
            return 0;
        }
        let mut buf = vec![0u8; num];
        // SAFETY: as above.
        let Ok(n) = (unsafe { method_op(rsa, Op::PublicDecrypt, sig, &mut buf, RSA_PKCS1_PADDING) }) else { return 0 };
        if n == 0 {
            return 0;
        }
        let mut p = buf.as_ptr();
        let Ok(len) = c_long::try_from(n) else { return 0 };
        // SAFETY: the decrypted block of `n` octets.
        let os = unsafe { d2i_ASN1_OCTET_STRING(ptr::null_mut(), &raw mut p, len) };
        if os.is_null() {
            return 0;
        }
        // SAFETY: the string just decoded.
        let decoded = unsafe { &*os };
        let (data, dlen) = (decoded.data, decoded.length);
        // SAFETY: the string's data.
        let got = usize::try_from(dlen).ok().and_then(|l| unsafe { bytes(data, l) });
        let ok = got.is_some_and(|g| g == m);
        // SAFETY: decoded above, freed once.
        unsafe { ASN1_OCTET_STRING_free(os) };
        if !ok {
            err::raise(ERR_LIB_RSA, RSA_R_BAD_SIGNATURE, F);
        }
        c_int::from(ok)
    }
}

/// A number as a temporary `BIGNUM`, freed when dropped.
struct Bn(*mut BIGNUM);

impl Bn {
    fn of(v: Option<&BigNum>) -> Self {
        Bn(v.map_or(ptr::null_mut(), |v| new_bignum(v.clone(), false)))
    }

    fn get(&self) -> Option<BigNum> {
        // SAFETY: ours, or NULL.
        unsafe { value(self.0) }
    }
}

impl Drop for Bn {
    fn drop(&mut self) {
        // SAFETY: ours to free, or NULL.
        unsafe { BN_free(self.0) };
    }
}

/// `RSA_X931_derive_ex`'s work on `key`: e if it has none; p from `xp` and q from `xq` if
/// it lacks them (2 when either is still missing); then n, d, and the CRT numbers. Changes
/// the key as far as it gets, as OpenSSL's does.
///
/// # Safety
/// The numbers are NULL or live `BIGNUM`s; `cb` is NULL or a live `BN_GENCB`.
#[allow(
    clippy::too_many_arguments,
    reason = "RSA_X931_derive_ex's own arguments"
)]
unsafe fn x931_derive(
    libctx: *mut rustyssl_abi::OSSL_LIB_CTX,
    key: &mut Key,
    pq: [[*mut BIGNUM; 2]; 2],
    xs: [[*const BIGNUM; 3]; 2],
    e: *const BIGNUM,
    cb: *mut BN_GENCB,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let ctx = unsafe { BN_CTX_new_ex(libctx) };
    if ctx.is_null() {
        return 0;
    }
    let ret = (|| -> Option<c_int> {
        if key.e.is_none() {
            // `BN_dup(e)`: fails for NULL.
            // SAFETY: the caller's guarantee.
            key.e = Some(unsafe { value(e) }?);
        }
        let eb = Bn::of(key.e.as_ref());
        for (i, ((p1p2, [x1, x2, x]), slot)) in pq.iter().zip(xs).zip([0, 1]).enumerate() {
            let _ = slot;
            let have = if i == 0 {
                key.p.is_some()
            } else {
                key.q.is_some()
            };
            if x.is_null() || have {
                continue;
            }
            let out = Bn::of(Some(&BigNum::zero()));
            if i == 0 {
                key.p = Some(BigNum::zero())
            } else {
                key.q = Some(BigNum::zero())
            };
            // SAFETY: ours; the caller's numbers; the context and callback.
            if unsafe { BN_X931_derive_prime_ex(out.0, p1p2[0], p1p2[1], x, x1, x2, eb.0, ctx, cb) }
                == 0
            {
                return None;
            }
            let v = out.get()?;
            if i == 0 {
                key.p = Some(v)
            } else {
                key.q = Some(v)
            };
        }
        let (Some(p), Some(q)) = (key.p.clone(), key.q.clone()) else {
            return Some(2);
        };
        key.n = Some(core_bn::mul(&p, &q).ok()?);
        let (mut r1, mut r2) = (p.clone(), q.clone());
        r1.sub_word(1).ok()?;
        r2.sub_word(1).ok()?;
        let r0 = core_bn::mul(&r1, &r2).ok()?;
        let g = if r1.is_zero() || r2.is_zero() {
            core_bn::add(&r1, &r2).ok()?.abs()
        } else {
            core_bn::ct::gcd(&r1, &r2).0
        };
        let lcm = core_bn::div_rem(&r0, &g).ok()?.0;
        let inverse = |a: &BigNum, m: &BigNum| -> Option<BigNum> {
            let (ab, mb, out) = (
                Bn::of(Some(a)),
                Bn::of(Some(m)),
                Bn::of(Some(&BigNum::zero())),
            );
            // SAFETY: ours; the default context's (OpenSSL uses a new `BN_CTX`).
            (!unsafe { BN_mod_inverse(out.0, ab.0, mb.0, ptr::null_mut()) }.is_null())
                .then(|| out.get())
                .flatten()
        };
        let d = inverse(key.e.as_ref()?, &lcm)?;
        key.dmp1 = Some(core_bn::nnmod(&d, &r1).ok()?);
        key.dmq1 = Some(core_bn::nnmod(&d, &r2).ok()?);
        key.d = Some(d);
        key.iqmp = Some(inverse(&q, &p)?);
        Some(1)
    })();
    // SAFETY: made above.
    unsafe { BN_CTX_free(ctx) };
    ret.unwrap_or(0)
}

ffi_export! {
    /// An X9.31 key from the given values (the primes derived from `xp_` and `xq_` with their
    /// auxiliary values, when the key lacks them). 1, 2 when p or q is still missing, or 0.
    ///
    /// # Safety
    /// `rsa` is NULL or a live key; each number is NULL or a live `BIGNUM`; `cb` is NULL or a
    /// live `BN_GENCB`.
    pub unsafe extern "C" fn RSA_X931_derive_ex(rsa: *mut RSA, p1: *mut BIGNUM, p2: *mut BIGNUM, q1: *mut BIGNUM, q2: *mut BIGNUM, xp1: *const BIGNUM, xp2: *const BIGNUM, xp_: *const BIGNUM, xq1: *const BIGNUM, xq2: *const BIGNUM, xq_: *const BIGNUM, e: *const BIGNUM, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { crate::rsa::rsa(rsa) }) else { return 0 };
        let mut key = k.snapshot().key;
        // SAFETY: as above.
        let r = unsafe { x931_derive(k.libctx.get(), &mut key, [[p1, p2], [q1, q2]], [[xp1, xp2, xp_], [xq1, xq2, xq_]], e, cb) };
        k.update_key(|kk| set_numbers(kk, &key));
        r
    }
}

/// The key's numbers set to `from`'s (the blinding made again for them).
fn set_numbers(key: &mut Key, from: &Key) {
    key.n.clone_from(&from.n);
    key.e.clone_from(&from.e);
    key.d.clone_from(&from.d);
    key.p.clone_from(&from.p);
    key.q.clone_from(&from.q);
    key.dmp1.clone_from(&from.dmp1);
    key.dmq1.clone_from(&from.dmq1);
    key.iqmp.clone_from(&from.iqmp);
    key.extra.clone_from(&from.extra);
    key.multi = from.multi;
    key.drop_blinding();
}

ffi_export! {
    /// An X9.31 key of `bits` bits with the public exponent `e`: xp_ and xq_, then the primes
    /// from them, then the rest. 1, or 0.
    ///
    /// # Safety
    /// `rsa` is NULL or a live key; `e` is NULL or a live `BIGNUM`; `cb` is NULL or a live
    /// `BN_GENCB`.
    pub unsafe extern "C" fn RSA_X931_generate_key_ex(rsa: *mut RSA, bits: c_int, e: *const BIGNUM, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { crate::rsa::rsa(rsa) }) else { return 0 };
        let libctx = k.libctx.get();
        // SAFETY: the key's library context.
        let ctx = unsafe { BN_CTX_new_ex(libctx) };
        if ctx.is_null() {
            return 0;
        }
        let zero = BigNum::zero();
        let (xp, xq, p, q) = (Bn::of(Some(&zero)), Bn::of(Some(&zero)), Bn::of(Some(&zero)), Bn::of(Some(&zero)));
        let mut key = k.snapshot().key;
        let ok = (|| -> Option<c_int> {
            // SAFETY: ours; the context.
            if unsafe { BN_X931_generate_Xpq(xp.0, xq.0, bits, ctx) } == 0 {
                return Some(0);
            }
            key.p = Some(BigNum::zero());
            key.q = Some(BigNum::zero());
            for (out, x, which) in [(&p, &xp, 0), (&q, &xq, 1)] {
                let n = ptr::null_mut();
                // SAFETY: ours; the caller's exponent; the context and callback.
                if unsafe { BN_X931_generate_prime_ex(out.0, n, n, n, n, x.0, e, ctx, cb) } == 0 {
                    return Some(0);
                }
                if which == 0 { key.p = out.get() } else { key.q = out.get() }
            }
            let nul = ptr::null();
            let nm = ptr::null_mut();
            // SAFETY: the key's context; NULLs; the caller's exponent and callback.
            Some(c_int::from(unsafe { x931_derive(libctx, &mut key, [[nm, nm], [nm, nm]], [[nul, nul, nul], [nul, nul, nul]], e, cb) } == 1))
        })()
        .unwrap_or(0);
        // SAFETY: made above.
        unsafe { BN_CTX_free(ctx) };
        k.update_key(|kk| set_numbers(kk, &key));
        ok
    }
}

ffi_export! {
    /// A two-prime key of `bits` bits: the method's `rsa_keygen`, or the built-in generator
    /// (`RSA_generate_multi_prime_key`). 1, or 0.
    ///
    /// # Safety
    /// `rsa` is a live key; `e_value` is NULL or a live `BIGNUM`; `cb` is NULL or a live
    /// `BN_GENCB`.
    pub unsafe extern "C" fn RSA_generate_key_ex(rsa: *mut RSA, bits: c_int, e_value: *mut BIGNUM, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { crate::rsa::rsa(rsa) }) else { return 0 };
        // SAFETY: the key's method, live.
        if let Some(f) = unsafe { fns_of(k.meth()) }.and_then(|f| f.keygen) {
            // SAFETY: the method's function takes these; no lock is held.
            return unsafe { f(rsa, bits, e_value, cb) };
        }
        // SAFETY: the caller's guarantee.
        unsafe { RSA_generate_multi_prime_key(rsa, bits, 2, e_value, cb) }
    }
}

ffi_export! {
    /// A key of `bits` bits and `primes` primes: the method's `rsa_multi_prime_keygen` (or its
    /// `rsa_keygen` for two primes; a method with only that can't make more), or the built-in
    /// generator. 1, or 0.
    ///
    /// # Safety
    /// As for `RSA_generate_key_ex`.
    pub unsafe extern "C" fn RSA_generate_multi_prime_key(rsa: *mut RSA, bits: c_int, primes: c_int, e_value: *mut BIGNUM, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { crate::rsa::rsa(rsa) }) else { return 0 };
        // SAFETY: the key's method, live.
        let fns = unsafe { fns_of(k.meth()) };
        if let Some(f) = fns.as_ref().and_then(|f| f.mp_keygen) {
            // SAFETY: the method's function takes these; no lock is held.
            return unsafe { f(rsa, bits, primes, e_value, cb) };
        }
        if let Some(f) = fns.as_ref().and_then(|f| f.keygen) {
            // SAFETY: as above.
            return if primes == 2 { unsafe { f(rsa, bits, e_value, cb) } } else { 0 };
        }
        // SAFETY: the caller's guarantee.
        let e = unsafe { value(e_value) };
        // SAFETY: the key's library context; the caller's callback.
        match unsafe { generate_key(k.libctx.get(), bits, primes, e.as_ref(), cb) } {
            Some(key) => {
                k.update_key(|kk| set_numbers(kk, &key));
                1
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// A new two-prime key (deprecated): `bits` bits, the public exponent `e_value`, progress
    /// to an old-style `callback`. NULL on failure.
    ///
    /// # Safety
    /// `callback` is NULL or a function taking `cb_arg`.
    pub unsafe extern "C" fn RSA_generate_key(bits: c_int, e_value: c_ulong, callback: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void)>, cb_arg: *mut c_void) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: no preconditions.
        let cb = unsafe { BN_GENCB_new() };
        // SAFETY: as above.
        let r = unsafe { RSA_new() };
        if cb.is_null() || r.is_null() {
            // SAFETY: made above, or NULL.
            unsafe { BN_GENCB_free(cb) };
            // SAFETY: as above.
            unsafe { RSA_free(r) };
            return ptr::null_mut();
        }
        let e = Bn::of(Some(&BigNum::from_word(e_value)));
        // SAFETY: the holder just made; the caller's callback.
        unsafe { BN_GENCB_set_old(cb, callback, cb_arg) };
        // SAFETY: the key and holder just made; the exponent.
        let ok = unsafe { RSA_generate_key_ex(r, bits, e.0, cb) } != 0;
        // SAFETY: made above.
        unsafe { BN_GENCB_free(cb) };
        if ok {
            r
        } else {
            // SAFETY: made above.
            unsafe { RSA_free(r) };
            ptr::null_mut()
        }
    }
}

ffi_export! {
    /// `RSA_check_key_ex` without a callback.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_check_key(r: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { RSA_check_key_ex(r, ptr::null_mut()) }
    }
}

ffi_export! {
    /// The key's consistency (each problem raised): 1 valid, 0 invalid, -1 on a failure.
    ///
    /// # Safety
    /// `r` is NULL or a live key; `cb` is NULL or a live `BN_GENCB`.
    pub unsafe extern "C" fn RSA_check_key_ex(r: *const RSA, cb: *mut BN_GENCB) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { rsa(r) }) else { return 0 };
        let st = k.snapshot();
        // SAFETY: the key's library context; the caller's callback.
        unsafe { validate_keypair(k.libctx.get(), &st.key, cb) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: OpenSSL's copy or write through negative lengths and NULL buffers.
    #[test]
    fn negative_lengths_and_null_buffers_fail() {
        let mut to = [0u8; 64];
        let from = [1u8; 8];
        let (t, f) = (to.as_mut_ptr(), from.as_ptr());
        // SAFETY: buffers of the lengths given, or lengths refused before any use.
        assert_eq!(unsafe { RSA_padding_add_PKCS1_type_1(t, -1, f, 8) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_padding_add_none(t, 64, f, -8) }, 0);
        let null_to = ptr::null_mut();
        // SAFETY: as above.
        let r = unsafe { RSA_padding_check_none(null_to, 64, f, 8, 64) };
        assert_eq!(r, -1);
        // SAFETY: as above.
        let r = unsafe { RSA_padding_check_PKCS1_type_2(t, 64, ptr::null(), 8, 64) };
        assert_eq!(r, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_padding_check_X931(t, 64, f, 8, -1) }, -1);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_padding_add_PKCS1_OAEP(t, 64, f, 8, f, -1) }, 0);
    }
}
