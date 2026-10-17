//! Microsoft's key blobs and PVK files (`pvkfmt.c`): `b2i_PrivateKey` and the other blob readers
//! and writers (PUBLICKEYBLOB and PRIVATEKEYBLOB of RSA and DSS keys), and the PVK reader and
//! writer (`b2i_PVK_bio`, `i2b_PVK_bio`), which encrypt with RC4 under a key from PVKKDF.
//!
//! As OpenSSL's: lengths are 32-bit (a blob's size computed from its bit length, wrapping as
//! C's `unsigned int` does), little-endian numbers are read at the sizes the header gives, and
//! RC4 and PVKKDF are the legacy provider's (9.1), so an encrypted PVK fails without it. The
//! input is read through a bounds-checked cursor: a length that says more than there is fails
//! where the reference would read past it (docs/DEVIATIONS.md, for `b2i_PrivateKey`'s negative
//! lengths).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BIO, DSA, ERR_LIB_PEM, ERR_R_BN_LIB, ERR_R_DSA_LIB, ERR_R_EVP_LIB, ERR_R_RSA_LIB,
    EVP_PKEY, EVP_PKEY_RSA, OSSL_LIB_CTX, PEM_BUFSIZE, PEM_R_BAD_DECRYPT, PEM_R_BAD_MAGIC_NUMBER,
    PEM_R_BAD_PASSWORD_READ, PEM_R_BAD_VERSION_NUMBER, PEM_R_BIO_WRITE_FAILURE,
    PEM_R_EXPECTING_DSS_KEY_BLOB, PEM_R_EXPECTING_PRIVATE_KEY_BLOB,
    PEM_R_EXPECTING_PUBLIC_KEY_BLOB, PEM_R_EXPECTING_RSA_KEY_BLOB, PEM_R_HEADER_TOO_LONG,
    PEM_R_INCONSISTENT_HEADER, PEM_R_KEYBLOB_HEADER_PARSE_ERROR, PEM_R_KEYBLOB_TOO_SHORT,
    PEM_R_PVK_DATA_TOO_SHORT, PEM_R_PVK_TOO_SHORT, PEM_R_UNSUPPORTED_KEY_COMPONENTS,
    PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE, PEM_R_UNSUPPORTED_PVK_KEY_TYPE, RSA, pem_password_cb,
};

use crate::err;
use crate::ffi::ffi_export;

const MS_PUBLICKEYBLOB: u8 = 0x6;
const MS_PRIVATEKEYBLOB: u8 = 0x7;
const MS_RSA1MAGIC: u32 = 0x3141_5352;
const MS_RSA2MAGIC: u32 = 0x3241_5352;
const MS_DSS1MAGIC: u32 = 0x3153_5344;
const MS_DSS2MAGIC: u32 = 0x3253_5344;
const MS_KEYALG_RSA_KEYX: u32 = 0xa400;
const MS_KEYALG_DSS_SIGN: u32 = 0x2200;
const MS_KEYTYPE_KEYX: u32 = 0x1;
const MS_KEYTYPE_SIGN: u32 = 0x2;
const MS_PVKMAGIC: u32 = 0xb0b5_f11e;
const PVK_SALTLEN: u32 = 0x10;
const PVK_MAX_KEYLEN: u32 = 102_400;
const PVK_MAX_SALTLEN: u32 = 10_240;
/// `BLOB_MAX_LENGTH` (`crypto/pem.h`).
pub(crate) const BLOB_MAX_LENGTH: u32 = 102_400;

/// A bounds-checked reader over a blob.
pub(crate) struct Cursor<'a>(pub(crate) &'a [u8]);

impl<'a> Cursor<'a> {
    /// `read_ledword`, or `None` past the end.
    fn ledword(&mut self) -> Option<u32> {
        let (b, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_le_bytes(*b))
    }

    /// The next `n` octets, or `None` past the end.
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(a)
    }

    fn byte(&mut self) -> Option<u8> {
        let (&b, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(b)
    }
}

/// `read_lebn`: `nbyte` little-endian octets as a new BIGNUM, or NULL.
fn read_lebn(c: &mut Cursor<'_>, nbyte: u32) -> *mut BIGNUM {
    let Some(b) = usize::try_from(nbyte).ok().and_then(|n| c.take(n)) else {
        return ptr::null_mut();
    };
    let Ok(len) = c_int::try_from(b.len()) else {
        return ptr::null_mut();
    };
    // SAFETY: the octets.
    unsafe { crate::bn::conv::BN_lebin2bn(b.as_ptr(), len, ptr::null_mut()) }
}

/// The header's parts: the bit length, whether DSS, whether public.
pub(crate) struct Header {
    pub(crate) bitlen: u32,
    pub(crate) isdss: bool,
    pub(crate) ispub: bool,
}

/// `ossl_do_blob_header`: 1 (and the header, the cursor past it), 0, or -1 for a bad magic,
/// each with OpenSSL's errors. `isdss` and `ispub` are -1 for either, else what's expected.
pub(crate) fn blob_header(
    c: &mut Cursor<'_>,
    length: u32,
    isdss: c_int,
    ispub: c_int,
) -> (c_int, Option<Header>) {
    const F: &str = "ossl_do_blob_header";
    let mut p = Cursor(c.0);
    if length < 16 || p.0.len() < 16 {
        return (0, None);
    }
    let ispub = match p.byte() {
        Some(MS_PUBLICKEYBLOB) => {
            if ispub == 0 {
                err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_PRIVATE_KEY_BLOB, F);
                return (0, None);
            }
            true
        }
        Some(MS_PRIVATEKEYBLOB) => {
            if ispub == 1 {
                err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_PUBLIC_KEY_BLOB, F);
                return (0, None);
            }
            false
        }
        _ => return (0, None),
    };
    if p.byte() != Some(0x2) {
        err::raise(ERR_LIB_PEM, PEM_R_BAD_VERSION_NUMBER, F);
        return (0, None);
    }
    let (Some(_), Some(magic), Some(bitlen)) = (p.take(6), p.ledword(), p.ledword()) else {
        return (0, None);
    };
    match magic {
        MS_DSS1MAGIC | MS_RSA1MAGIC if !ispub => {
            err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_PRIVATE_KEY_BLOB, F);
            return (0, None);
        }
        MS_DSS2MAGIC | MS_RSA2MAGIC if ispub => {
            err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_PUBLIC_KEY_BLOB, F);
            return (0, None);
        }
        MS_DSS1MAGIC | MS_RSA1MAGIC | MS_DSS2MAGIC | MS_RSA2MAGIC => {}
        _ => {
            err::raise(ERR_LIB_PEM, PEM_R_BAD_MAGIC_NUMBER, F);
            return (-1, None);
        }
    }
    let dss = matches!(magic, MS_DSS1MAGIC | MS_DSS2MAGIC);
    if dss && isdss == 0 {
        err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_DSS_KEY_BLOB, F);
        return (0, None);
    }
    if !dss && isdss == 1 {
        err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_RSA_KEY_BLOB, F);
        return (0, None);
    }
    c.0 = p.0;
    (
        1,
        Some(Header {
            bitlen,
            isdss: dss,
            ispub,
        }),
    )
}

/// `ossl_blob_length`: the body's length for a key of `bitlen` bits, wrapping as C's `unsigned
/// int` does.
pub(crate) fn blob_length(bitlen: u32, isdss: bool, ispub: bool) -> u32 {
    let nbyte = bitlen.wrapping_add(7) >> 3;
    let hnbyte = bitlen.wrapping_add(15) >> 4;
    match (isdss, ispub) {
        (true, true) => 44u32.wrapping_add(nbyte.wrapping_mul(3)),
        (true, false) => 64u32.wrapping_add(nbyte.wrapping_mul(2)),
        (false, true) => 4u32.wrapping_add(nbyte),
        (false, false) => 4u32
            .wrapping_add(nbyte.wrapping_mul(2))
            .wrapping_add(hnbyte.wrapping_mul(5)),
    }
}

/// Frees the BIGNUMs.
fn free_bns(bns: &[*mut BIGNUM]) {
    for &b in bns {
        // SAFETY: made here, or NULL.
        unsafe { crate::bn::BN_free(b) };
    }
}

/// `ossl_b2i_DSA_after_header`: a DSA key from the body (its public key computed from a private
/// one), or NULL.
pub(crate) fn b2i_dsa_after_header(c: &mut Cursor<'_>, bitlen: u32, ispub: bool) -> *mut DSA {
    use crate::dsa::{DSA_free, DSA_new, DSA_set0_key, DSA_set0_pqg};
    let nbyte = bitlen.wrapping_add(7) >> 3;
    // SAFETY: no preconditions.
    let dsa = unsafe { DSA_new() };
    let mut bns = [ptr::null_mut::<BIGNUM>(); 5];
    let [pbn, qbn, gbn, priv_key, pub_key] = &mut bns;
    let fail = |reason: c_int, dsa: *mut DSA, bns: &[*mut BIGNUM]| {
        err::raise(ERR_LIB_PEM, reason, "ossl_b2i_DSA_after_header");
        // SAFETY: made here, or NULL.
        unsafe { DSA_free(dsa) };
        free_bns(bns);
        ptr::null_mut()
    };
    if dsa.is_null() {
        return fail(ERR_R_DSA_LIB, dsa, &[]);
    }
    *pbn = read_lebn(c, nbyte);
    if pbn.is_null() {
        return fail(ERR_R_BN_LIB, dsa, &bns);
    }
    *qbn = read_lebn(c, 20);
    if qbn.is_null() {
        return fail(ERR_R_BN_LIB, dsa, &bns);
    }
    *gbn = read_lebn(c, nbyte);
    if gbn.is_null() {
        return fail(ERR_R_BN_LIB, dsa, &bns);
    }
    if ispub {
        *pub_key = read_lebn(c, nbyte);
        if pub_key.is_null() {
            return fail(ERR_R_BN_LIB, dsa, &bns);
        }
    } else {
        *priv_key = read_lebn(c, 20);
        if priv_key.is_null() {
            return fail(ERR_R_BN_LIB, dsa, &bns);
        }
        // SAFETY: the new number.
        unsafe { crate::bn::BN_set_flags(*priv_key, rustyssl_abi::BN_FLG_CONSTTIME) };
        // SAFETY: no preconditions.
        *pub_key = unsafe { crate::bn::BN_new() };
        // SAFETY: as above.
        let ctx = unsafe { crate::bn::ctx::BN_CTX_new() };
        // SAFETY: the numbers; the context.
        let ok = !pub_key.is_null()
            && !ctx.is_null()
            && unsafe { crate::bn::modular::BN_mod_exp(*pub_key, *gbn, *priv_key, *pbn, ctx) } != 0;
        // SAFETY: made above, or NULL.
        unsafe { crate::bn::ctx::BN_CTX_free(ctx) };
        if !ok {
            return fail(ERR_R_BN_LIB, dsa, &bns);
        }
    }
    // SAFETY: the new key takes the numbers.
    if unsafe { DSA_set0_pqg(dsa, *pbn, *qbn, *gbn) } == 0 {
        return fail(ERR_R_DSA_LIB, dsa, &bns);
    }
    (*pbn, *qbn, *gbn) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    // SAFETY: as above.
    if unsafe { DSA_set0_key(dsa, *pub_key, *priv_key) } == 0 {
        return fail(ERR_R_DSA_LIB, dsa, &bns);
    }
    dsa
}

/// `ossl_b2i_RSA_after_header`: an RSA key from the body, or NULL.
pub(crate) fn b2i_rsa_after_header(c: &mut Cursor<'_>, bitlen: u32, ispub: bool) -> *mut RSA {
    use crate::rsa_lib::{RSA_free, RSA_new, RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key};
    let nbyte = bitlen.wrapping_add(7) >> 3;
    let hnbyte = bitlen.wrapping_add(15) >> 4;
    // SAFETY: no preconditions.
    let rsa = unsafe { RSA_new() };
    // e, n, p, q, dmp1, dmq1, iqmp, d
    let mut bns = [ptr::null_mut::<BIGNUM>(); 8];
    let fail = |reason: c_int, rsa: *mut RSA, bns: &[*mut BIGNUM]| {
        err::raise(ERR_LIB_PEM, reason, "ossl_b2i_RSA_after_header");
        free_bns(bns);
        // SAFETY: made here, or NULL.
        unsafe { RSA_free(rsa) };
        ptr::null_mut()
    };
    if rsa.is_null() {
        return fail(ERR_R_RSA_LIB, rsa, &[]);
    }
    // SAFETY: no preconditions.
    bns[0] = unsafe { crate::bn::BN_new() };
    let Some(w) = c.ledword() else {
        return fail(ERR_R_BN_LIB, rsa, &bns);
    };
    // SAFETY: the new number, or NULL.
    if bns[0].is_null() || unsafe { crate::bn::BN_set_word(bns[0], w.into()) } == 0 {
        return fail(ERR_R_BN_LIB, rsa, &bns);
    }
    bns[1] = read_lebn(c, nbyte);
    if bns[1].is_null() {
        return fail(ERR_R_BN_LIB, rsa, &bns);
    }
    if !ispub {
        for (i, n) in [
            (2, hnbyte),
            (3, hnbyte),
            (4, hnbyte),
            (5, hnbyte),
            (6, hnbyte),
            (7, nbyte),
        ] {
            let b = read_lebn(c, n);
            if b.is_null() {
                return fail(ERR_R_BN_LIB, rsa, &bns);
            }
            if let Some(slot) = bns.get_mut(i) {
                *slot = b;
            }
        }
        let [_, _, p, q, dmp1, dmq1, iqmp, _] = bns;
        // SAFETY: the new key takes the factors.
        if unsafe { RSA_set0_factors(rsa, p, q) } == 0 {
            return fail(ERR_R_RSA_LIB, rsa, &bns);
        }
        bns[2] = ptr::null_mut();
        bns[3] = ptr::null_mut();
        // SAFETY: as above, the CRT parameters.
        if unsafe { RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) } == 0 {
            return fail(ERR_R_RSA_LIB, rsa, &bns);
        }
        bns[4] = ptr::null_mut();
        bns[5] = ptr::null_mut();
        bns[6] = ptr::null_mut();
    }
    let [e, n, _, _, _, _, _, d] = bns;
    // SAFETY: as above, the key's numbers.
    if unsafe { RSA_set0_key(rsa, n, e, d) } == 0 {
        return fail(ERR_R_RSA_LIB, rsa, &bns);
    }
    rsa
}

/// `evp_pkey_new0_key`: an `EVP_PKEY` holding the RSA (DSS for `isdss`) key, which it frees;
/// NULL for none.
fn new0_key(key: *mut c_void, isdss: bool) -> *mut EVP_PKEY {
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let pkey = unsafe { crate::evp::pkey::EVP_PKEY_new() };
    if pkey.is_null() {
        err::raise(ERR_LIB_PEM, ERR_R_EVP_LIB, "evp_pkey_new0_key");
    } else {
        let set = if isdss {
            // SAFETY: the new key; the DSA.
            unsafe { crate::evp::pkey::dsa::EVP_PKEY_set1_DSA(pkey, key.cast()) }
        } else {
            // SAFETY: as above, the RSA.
            unsafe { crate::evp::pkey::rsa::EVP_PKEY_set1_RSA(pkey, key.cast()) }
        };
        if set == 0 {
            err::raise(ERR_LIB_PEM, ERR_R_EVP_LIB, "evp_pkey_new0_key");
            // SAFETY: made above.
            unsafe { crate::evp::pkey::EVP_PKEY_free(pkey) };
            free_key(key, isdss);
            return ptr::null_mut();
        }
    }
    free_key(key, isdss);
    pkey
}

/// Frees an RSA (or DSA) key.
fn free_key(key: *mut c_void, isdss: bool) {
    if isdss {
        // SAFETY: a DSA made here, or NULL.
        unsafe { crate::dsa::DSA_free(key.cast()) };
    } else {
        // SAFETY: an RSA made here, or NULL.
        unsafe { crate::rsa_lib::RSA_free(key.cast()) };
    }
}

/// `do_b2i_key`: the key of a whole blob (header and body), or NULL with
/// `PEM_R_KEYBLOB_HEADER_PARSE_ERROR` or `_TOO_SHORT`.
fn do_b2i_key(
    c: &mut Cursor<'_>,
    length: u32,
    isdss: c_int,
    ispub: c_int,
) -> (*mut c_void, Option<Header>) {
    const F: &str = "do_b2i_key";
    let mut p = Cursor(c.0);
    let (r, h) = blob_header(&mut p, length, isdss, ispub);
    let Some(h) = h.filter(|_| r > 0) else {
        err::raise(ERR_LIB_PEM, PEM_R_KEYBLOB_HEADER_PARSE_ERROR, F);
        return (ptr::null_mut(), None);
    };
    if length.wrapping_sub(16) < blob_length(h.bitlen, h.isdss, h.ispub) {
        err::raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT, F);
        return (ptr::null_mut(), Some(h));
    }
    let key: *mut c_void = if h.isdss {
        b2i_dsa_after_header(&mut p, h.bitlen, h.ispub).cast()
    } else {
        b2i_rsa_after_header(&mut p, h.bitlen, h.ispub).cast()
    };
    if key.is_null() {
        err::raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE, F);
    }
    (key, Some(h))
}

/// `ossl_b2i`: the blob's key as an `EVP_PKEY`.
///
/// # Safety
/// `in_` holds a pointer to `length` octets (truncated to 32 bits, as OpenSSL takes them).
unsafe fn b2i(in_: *mut *const c_uchar, length: c_long, ispub: c_int) -> *mut EVP_PKEY {
    // A negative length is a huge `unsigned int` in OpenSSL, which reads past the buffer
    // (docs/DEVIATIONS.md).
    let Ok(length) = u64::try_from(length) else {
        err::raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT, "ossl_b2i");
        return ptr::null_mut();
    };
    let length = u32::try_from(length & 0xffff_ffff).unwrap_or(0);
    // SAFETY: the caller's guarantee.
    let p = unsafe { in_.as_ref() }.map_or(ptr::null(), |p| *p);
    // SAFETY: as above: `length` octets.
    let Some(bytes) = (unsafe { crate::ffi::bytes(p, usize::try_from(length).unwrap_or(0)) })
    else {
        return ptr::null_mut();
    };
    let mut c = Cursor(bytes);
    let (key, h) = do_b2i_key(&mut c, length, -1, ispub);
    new0_key(key, h.is_some_and(|h| h.isdss))
}

ffi_export! {
    /// The private key of a PRIVATEKEYBLOB (RSA or DSS), or NULL. `*in` isn't moved, as
    /// OpenSSL's isn't.
    ///
    /// # Safety
    /// `in_` holds a pointer to `length` octets.
    pub unsafe extern "C" fn b2i_PrivateKey(in_: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { b2i(in_, length, 0) }
    }
}

ffi_export! {
    /// The public key of a PUBLICKEYBLOB (RSA or DSS), or NULL.
    ///
    /// # Safety
    /// As for `b2i_PrivateKey`.
    pub unsafe extern "C" fn b2i_PublicKey(in_: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { b2i(in_, length, 1) }
    }
}

/// Reads exactly `n` octets from the BIO, or `None`.
///
/// # Safety
/// `bp` is a live BIO.
pub(crate) unsafe fn read_exact(bp: *mut BIO, n: usize) -> Option<Vec<u8>> {
    let len = c_int::try_from(n).ok()?;
    let mut buf = vec![0u8; n];
    // SAFETY: the caller's BIO; room for `n`.
    let got = unsafe { crate::bio::BIO_read(bp, buf.as_mut_ptr().cast(), len) };
    (got == len).then_some(buf)
}

/// `ossl_b2i_bio`: a blob's key read from a BIO (its header, then the body it gives the length
/// of), or NULL.
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn b2i_bio(bp: *mut BIO, ispub: c_int) -> *mut EVP_PKEY {
    const F: &str = "ossl_b2i_bio";
    // SAFETY: the caller's guarantee.
    let Some(hdr) = (unsafe { read_exact(bp, 16) }) else {
        err::raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT, F);
        return ptr::null_mut();
    };
    let mut c = Cursor(&hdr);
    let (r, h) = blob_header(&mut c, 16, -1, ispub);
    let Some(h) = h.filter(|_| r > 0) else {
        return ptr::null_mut();
    };
    let length = blob_length(h.bitlen, h.isdss, h.ispub);
    if length > BLOB_MAX_LENGTH {
        err::raise(ERR_LIB_PEM, PEM_R_HEADER_TOO_LONG, F);
        return ptr::null_mut();
    }
    // SAFETY: as above.
    let Some(body) = (unsafe { read_exact(bp, usize::try_from(length).unwrap_or(0)) }) else {
        err::raise(ERR_LIB_PEM, PEM_R_KEYBLOB_TOO_SHORT, F);
        return ptr::null_mut();
    };
    let body = rustyssl_crypto::bn::Zeroizing::new(body);
    let mut c = Cursor(&body);
    let key: *mut c_void = if h.isdss {
        b2i_dsa_after_header(&mut c, h.bitlen, h.ispub).cast()
    } else {
        b2i_rsa_after_header(&mut c, h.bitlen, h.ispub).cast()
    };
    if key.is_null() {
        err::raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE, F);
        return ptr::null_mut();
    }
    new0_key(key, h.isdss)
}

ffi_export! {
    /// The private key of a PRIVATEKEYBLOB read from the BIO, or NULL.
    ///
    /// # Safety
    /// `in_` is a live BIO.
    pub unsafe extern "C" fn b2i_PrivateKey_bio(in_: *mut BIO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { b2i_bio(in_, 0) }
    }
}

ffi_export! {
    /// The public key of a PUBLICKEYBLOB read from the BIO, or NULL.
    ///
    /// # Safety
    /// `in_` is a live BIO.
    pub unsafe extern "C" fn b2i_PublicKey_bio(in_: *mut BIO) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { b2i_bio(in_, 1) }
    }
}

/// `BN_num_bytes`.
///
/// # Safety
/// `b` is NULL or a live BIGNUM.
unsafe fn num_bytes(b: *const BIGNUM) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { crate::bn::BN_num_bits(b) }.saturating_add(7) / 8
}

/// `write_lebn`: the number in `len` little-endian octets.
///
/// # Safety
/// `b` is a live BIGNUM.
unsafe fn write_lebn(out: &mut Vec<u8>, b: *const BIGNUM, len: c_int) {
    let n = usize::try_from(len).unwrap_or(0);
    let mut buf = vec![0u8; n];
    // SAFETY: the caller's number; room for `len`.
    unsafe { crate::bn::conv::BN_bn2lebinpad(b, buf.as_mut_ptr(), len) };
    out.extend_from_slice(&buf);
    buf.fill(0);
}

/// `check_bitlen_rsa`: the key's bits and magic, or 0 (with
/// `PEM_R_UNSUPPORTED_KEY_COMPONENTS`) for numbers that don't fit the blob.
///
/// # Safety
/// `rsa` is a live RSA key.
unsafe fn check_bitlen_rsa(rsa: *const RSA, ispub: bool) -> (u32, u32) {
    use crate::rsa_lib::{RSA_bits, RSA_get0_crt_params, RSA_get0_factors, RSA_get0_key, RSA_size};
    let bad = || {
        err::raise(
            ERR_LIB_PEM,
            PEM_R_UNSUPPORTED_KEY_COMPONENTS,
            "check_bitlen_rsa",
        );
        (0, 0)
    };
    let (mut n, mut e, mut d) = (ptr::null(), ptr::null(), ptr::null());
    // SAFETY: the caller's key; locals.
    unsafe { RSA_get0_key(rsa, &raw mut n, &raw mut e, &raw mut d) };
    // SAFETY: the key's number, or NULL.
    if unsafe { crate::bn::BN_num_bits(e) } > 32 {
        return bad();
    }
    // SAFETY: the caller's key.
    let bitlen = unsafe { RSA_bits(rsa) };
    // SAFETY: as above.
    let nbyte = unsafe { RSA_size(rsa) };
    let hnbyte = bitlen.saturating_add(15) >> 4;
    let bits = u32::try_from(bitlen).unwrap_or(0);
    if ispub {
        return (bits, MS_RSA1MAGIC);
    }
    // SAFETY: the key's number, or NULL.
    if unsafe { num_bytes(d) } > nbyte {
        return bad();
    }
    let (mut p, mut q, mut dmp1, mut dmq1, mut iqmp) = (
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
    );
    // SAFETY: the caller's key; locals.
    unsafe { RSA_get0_factors(rsa, &raw mut p, &raw mut q) };
    // SAFETY: as above.
    unsafe { RSA_get0_crt_params(rsa, &raw mut dmp1, &raw mut dmq1, &raw mut iqmp) };
    for b in [iqmp, p, q, dmp1, dmq1] {
        // SAFETY: the key's numbers, or NULL.
        if unsafe { num_bytes(b) } > hnbyte {
            return bad();
        }
    }
    (bits, MS_RSA2MAGIC)
}

/// `write_rsa`.
///
/// # Safety
/// `rsa` is a live RSA key that passed `check_bitlen_rsa`.
unsafe fn write_rsa(out: &mut Vec<u8>, rsa: *const RSA, ispub: bool) {
    use crate::rsa_lib::{RSA_bits, RSA_get0_crt_params, RSA_get0_factors, RSA_get0_key, RSA_size};
    // SAFETY: the caller's key.
    let nbyte = unsafe { RSA_size(rsa) };
    // SAFETY: as above.
    let hnbyte = unsafe { RSA_bits(rsa) }.saturating_add(15) >> 4;
    let (mut n, mut e, mut d) = (ptr::null(), ptr::null(), ptr::null());
    // SAFETY: the caller's key; locals.
    unsafe { RSA_get0_key(rsa, &raw mut n, &raw mut e, &raw mut d) };
    // SAFETY: the key's numbers.
    unsafe { write_lebn(out, e, 4) };
    // SAFETY: as above.
    unsafe { write_lebn(out, n, nbyte) };
    if ispub {
        return;
    }
    let (mut p, mut q, mut dmp1, mut dmq1, mut iqmp) = (
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
    );
    // SAFETY: the caller's key; locals.
    unsafe { RSA_get0_factors(rsa, &raw mut p, &raw mut q) };
    // SAFETY: as above.
    unsafe { RSA_get0_crt_params(rsa, &raw mut dmp1, &raw mut dmq1, &raw mut iqmp) };
    for b in [p, q, dmp1, dmq1, iqmp] {
        // SAFETY: the key's numbers.
        unsafe { write_lebn(out, b, hnbyte) };
    }
    // SAFETY: as above.
    unsafe { write_lebn(out, d, nbyte) };
}

/// `check_bitlen_dsa`: the key's bits and magic, or 0 (with
/// `PEM_R_UNSUPPORTED_KEY_COMPONENTS`) for a key that isn't DSS's (160-bit q, whole octets).
///
/// # Safety
/// `dsa` is a live DSA key.
unsafe fn check_bitlen_dsa(dsa: *const DSA, ispub: bool) -> (u32, u32) {
    use crate::bn::BN_num_bits;
    let bad = || {
        err::raise(
            ERR_LIB_PEM,
            PEM_R_UNSUPPORTED_KEY_COMPONENTS,
            "check_bitlen_dsa",
        );
        (0, 0)
    };
    let (mut p, mut q, mut g, mut pub_key, mut priv_key) = (
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
    );
    // SAFETY: the caller's key; locals.
    unsafe { crate::dsa::DSA_get0_pqg(dsa, &raw mut p, &raw mut q, &raw mut g) };
    // SAFETY: as above.
    unsafe { crate::dsa::DSA_get0_key(dsa, &raw mut pub_key, &raw mut priv_key) };
    // SAFETY: the key's numbers, or NULL (here and below).
    let bitlen = unsafe { BN_num_bits(p) };
    // SAFETY: as above.
    if bitlen & 7 != 0 || unsafe { BN_num_bits(q) } != 160 || unsafe { BN_num_bits(g) } > bitlen {
        return bad();
    }
    let magic = if ispub {
        // SAFETY: as above.
        if unsafe { BN_num_bits(pub_key) } > bitlen {
            return bad();
        }
        MS_DSS1MAGIC
    } else {
        // SAFETY: as above.
        if unsafe { BN_num_bits(priv_key) } > 160 {
            return bad();
        }
        MS_DSS2MAGIC
    };
    (u32::try_from(bitlen).unwrap_or(0), magic)
}

/// `write_dsa`: p, q, g, and the key, then 24 octets of 0xff (no DSSSEED).
///
/// # Safety
/// `dsa` is a live DSA key that passed `check_bitlen_dsa`.
unsafe fn write_dsa(out: &mut Vec<u8>, dsa: *const DSA, ispub: bool) {
    let (mut p, mut q, mut g, mut pub_key, mut priv_key) = (
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
        ptr::null(),
    );
    // SAFETY: the caller's key; locals.
    unsafe { crate::dsa::DSA_get0_pqg(dsa, &raw mut p, &raw mut q, &raw mut g) };
    // SAFETY: as above.
    unsafe { crate::dsa::DSA_get0_key(dsa, &raw mut pub_key, &raw mut priv_key) };
    // SAFETY: the key's number.
    let nbyte = unsafe { num_bytes(p) };
    // SAFETY: the key's numbers (here and below).
    unsafe { write_lebn(out, p, nbyte) };
    // SAFETY: as above.
    unsafe { write_lebn(out, q, 20) };
    // SAFETY: as above.
    unsafe { write_lebn(out, g, nbyte) };
    if ispub {
        // SAFETY: as above.
        unsafe { write_lebn(out, pub_key, nbyte) };
    } else {
        // SAFETY: as above.
        unsafe { write_lebn(out, priv_key, 20) };
    }
    out.extend_from_slice(&[0xff; 24]);
}

/// `do_i2b`: the key's blob (RSA's or DSS's), or `None` (with an error for a key that doesn't
/// fit).
///
/// # Safety
/// `pk` is a live key.
pub(crate) unsafe fn do_i2b(
    pk: *const EVP_PKEY,
    ispub: bool,
) -> Option<rustyssl_crypto::bn::Zeroizing<Vec<u8>>> {
    use crate::evp::pkey::EVP_PKEY_is_a;
    // SAFETY: the caller's key; static names.
    let (bitlen, magic, keyalg) = if unsafe { EVP_PKEY_is_a(pk, c"RSA".as_ptr()) } != 0 {
        // SAFETY: as above.
        let rsa = unsafe { crate::evp::pkey::rsa::EVP_PKEY_get0_RSA(pk) };
        // SAFETY: the key's RSA.
        let (b, m) = unsafe { check_bitlen_rsa(rsa, ispub) };
        (b, m, MS_KEYALG_RSA_KEYX)
    // SAFETY: as above.
    } else if unsafe { EVP_PKEY_is_a(pk, c"DSA".as_ptr()) } != 0 {
        // SAFETY: as above.
        let dsa = unsafe { crate::evp::pkey::dsa::EVP_PKEY_get0_DSA(pk) };
        // SAFETY: the key's DSA.
        let (b, m) = unsafe { check_bitlen_dsa(dsa, ispub) };
        (b, m, MS_KEYALG_DSS_SIGN)
    } else {
        (0, 0, 0)
    };
    if bitlen == 0 {
        return None;
    }
    let dss = keyalg == MS_KEYALG_DSS_SIGN;
    let outlen = 16u32.wrapping_add(blob_length(bitlen, dss, ispub));
    let mut out = rustyssl_crypto::bn::Zeroizing::new(Vec::with_capacity(
        usize::try_from(outlen).unwrap_or(0),
    ));
    out.push(if ispub {
        MS_PUBLICKEYBLOB
    } else {
        MS_PRIVATEKEYBLOB
    });
    out.extend_from_slice(&[0x2, 0, 0]);
    out.extend_from_slice(&keyalg.to_le_bytes());
    out.extend_from_slice(&magic.to_le_bytes());
    out.extend_from_slice(&bitlen.to_le_bytes());
    if dss {
        // SAFETY: as above.
        let dsa = unsafe { crate::evp::pkey::dsa::EVP_PKEY_get0_DSA(pk) };
        // SAFETY: the key's DSA, checked above.
        unsafe { write_dsa(&mut out, dsa, ispub) };
    } else {
        // SAFETY: as above.
        let rsa = unsafe { crate::evp::pkey::rsa::EVP_PKEY_get0_RSA(pk) };
        // SAFETY: the key's RSA, checked above.
        unsafe { write_rsa(&mut out, rsa, ispub) };
    }
    Some(out)
}

/// `do_i2b_bio`: the blob written to the BIO: its length, or -1.
///
/// # Safety
/// `bp` is a live BIO; `pk` is a live key.
unsafe fn i2b_bio(bp: *mut BIO, pk: *const EVP_PKEY, ispub: bool) -> c_int {
    // SAFETY: the caller's key.
    let Some(blob) = (unsafe { do_i2b(pk, ispub) }) else {
        return -1;
    };
    let Ok(len) = c_int::try_from(blob.len()) else {
        return -1;
    };
    // SAFETY: the caller's BIO; the blob.
    let wrlen = unsafe { crate::bio::BIO_write(bp, blob.as_ptr().cast(), len) };
    if wrlen == len { len } else { -1 }
}

ffi_export! {
    /// Writes the key's PRIVATEKEYBLOB: its length, or -1.
    ///
    /// # Safety
    /// `out` is a live BIO; `pk` is a live key.
    pub unsafe extern "C" fn i2b_PrivateKey_bio(out: *mut BIO, pk: *const EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2b_bio(out, pk, false) }
    }
}

ffi_export! {
    /// Writes the key's PUBLICKEYBLOB: its length, or -1.
    ///
    /// # Safety
    /// As for `i2b_PrivateKey_bio`.
    pub unsafe extern "C" fn i2b_PublicKey_bio(out: *mut BIO, pk: *const EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2b_bio(out, pk, true) }
    }
}

/// A PVK header's parts: whether DSS, the salt's and key blob's lengths.
pub(crate) struct PvkHeader {
    pub(crate) isdss: bool,
    pub(crate) saltlen: u32,
    pub(crate) keylen: u32,
}

/// `ossl_do_PVK_header`: the header (the cursor past it), or `None` with OpenSSL's errors.
pub(crate) fn pvk_header(
    c: &mut Cursor<'_>,
    length: u32,
    skip_magic: bool,
    isdss: c_int,
) -> Option<PvkHeader> {
    const F: &str = "ossl_do_PVK_header";
    let mut p = Cursor(c.0);
    if length < if skip_magic { 20 } else { 24 } {
        err::raise(ERR_LIB_PEM, PEM_R_PVK_TOO_SHORT, F);
        return None;
    }
    if !skip_magic && p.ledword()? != MS_PVKMAGIC {
        err::raise(ERR_LIB_PEM, PEM_R_BAD_MAGIC_NUMBER, F);
        return None;
    }
    p.take(4)?;
    let dss = match p.ledword()? {
        MS_KEYTYPE_KEYX => {
            if isdss == 1 {
                err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_RSA_KEY_BLOB, F);
                return None;
            }
            false
        }
        MS_KEYTYPE_SIGN => {
            if isdss == 0 {
                err::raise(ERR_LIB_PEM, PEM_R_EXPECTING_DSS_KEY_BLOB, F);
                return None;
            }
            true
        }
        _ => {
            err::raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_PVK_KEY_TYPE, F);
            return None;
        }
    };
    let is_encrypted = p.ledword()?;
    let saltlen = p.ledword()?;
    let keylen = p.ledword()?;
    if keylen > PVK_MAX_KEYLEN || saltlen > PVK_MAX_SALTLEN {
        return None;
    }
    if is_encrypted != 0 && saltlen == 0 {
        err::raise(ERR_LIB_PEM, PEM_R_INCONSISTENT_HEADER, F);
        return None;
    }
    c.0 = p.0;
    Some(PvkHeader {
        isdss: dss,
        saltlen,
        keylen,
    })
}

/// `derive_pvk_key`: PVKKDF (the legacy provider's) over the salt and password, into `key`.
///
/// # Safety
/// `libctx` is NULL or live; `propq` is NULL or a C string.
unsafe fn derive_pvk_key(
    key: &mut [u8; 20],
    salt: &[u8],
    pass: &[u8],
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    use crate::evp::kdf::{
        EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
    };
    use crate::params::{
        OSSL_PARAM_construct_end, OSSL_PARAM_construct_octet_string,
        OSSL_PARAM_construct_utf8_string,
    };
    use rustyssl_abi::{
        OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_PASSWORD, OSSL_KDF_PARAM_PROPERTIES,
        OSSL_KDF_PARAM_SALT,
    };
    // SAFETY: the caller's library context and properties; a static name.
    let kdf = unsafe { EVP_KDF_fetch(libctx, c"PVKKDF".as_ptr(), propq) };
    if kdf.is_null() {
        return false;
    }
    // SAFETY: the method fetched.
    let ctx = unsafe { EVP_KDF_CTX_new(kdf) };
    // SAFETY: as above.
    unsafe { EVP_KDF_free(kdf) };
    if ctx.is_null() {
        return false;
    }
    let params = [
        // SAFETY: the salt, password, and names, read during the derivation.
        unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_SALT.as_ptr(),
                salt.as_ptr().cast_mut().cast(),
                salt.len(),
            )
        },
        // SAFETY: as above.
        unsafe {
            OSSL_PARAM_construct_octet_string(
                OSSL_KDF_PARAM_PASSWORD.as_ptr(),
                pass.as_ptr().cast_mut().cast(),
                pass.len(),
            )
        },
        // SAFETY: as above.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_DIGEST.as_ptr(),
                c"SHA1".as_ptr().cast_mut(),
                0,
            )
        },
        // SAFETY: as above.
        unsafe {
            OSSL_PARAM_construct_utf8_string(
                OSSL_KDF_PARAM_PROPERTIES.as_ptr(),
                propq.cast_mut(),
                0,
            )
        },
        // SAFETY: no preconditions.
        unsafe { OSSL_PARAM_construct_end() },
    ];
    // SAFETY: the context; room for 20; the parameters.
    let rv = unsafe { EVP_KDF_derive(ctx, key.as_mut_ptr(), key.len(), params.as_ptr()) };
    // SAFETY: made above.
    unsafe { EVP_KDF_CTX_free(ctx) };
    rv == 1
}

/// The password `cb` (or `PEM_def_callback`) gives into `buf`: its length, or -1.
///
/// # Safety
/// `cb` is NULL or a callback taking `u`.
unsafe fn password(
    buf: &mut [c_char; PEM_BUFSIZE as usize],
    rwflag: c_int,
    cb: pem_password_cb,
    u: *mut c_void,
) -> c_int {
    let f = cb.unwrap_or(crate::pem_cipher::PEM_def_callback);
    // SAFETY: the callback with room for `PEM_BUFSIZE`.
    unsafe { f(buf.as_mut_ptr(), PEM_BUFSIZE, rwflag, u) }
}

/// RC4 over `data` (in place) with `key`, the legacy provider's cipher.
///
/// # Safety
/// `libctx` and `propq` as for the fetch.
unsafe fn rc4(
    key: &[u8; 20],
    data: &mut [u8],
    encrypt: bool,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> bool {
    use crate::evp::cipher_ctx::{
        EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_CipherFinal_ex, EVP_CipherInit_ex,
        EVP_CipherUpdate,
    };
    // SAFETY: the caller's library context and properties; a static name.
    let cipher = unsafe { crate::evp::cipher::EVP_CIPHER_fetch(libctx, c"RC4".as_ptr(), propq) };
    if cipher.is_null() {
        return false;
    }
    // SAFETY: no preconditions.
    let cctx = unsafe { EVP_CIPHER_CTX_new() };
    let Ok(len) = c_int::try_from(data.len()) else {
        return false;
    };
    let mut n = 0;
    let ok = !cctx.is_null()
        // SAFETY: the context; the cipher; the key.
        && unsafe { EVP_CipherInit_ex(cctx, cipher, ptr::null_mut(), key.as_ptr(), ptr::null(), c_int::from(encrypt)) } != 0
        // SAFETY: the data, in place.
        && unsafe { EVP_CipherUpdate(cctx, data.as_mut_ptr(), &raw mut n, data.as_ptr(), len) } != 0
        // SAFETY: as above, past what was written (a stream cipher writes nothing more).
        && unsafe { EVP_CipherFinal_ex(cctx, data.as_mut_ptr().wrapping_add(usize::try_from(n).unwrap_or(0)), &raw mut n) } != 0;
    // SAFETY: made above, or NULL.
    unsafe { EVP_CIPHER_CTX_free(cctx) };
    // SAFETY: fetched above.
    unsafe { crate::evp::cipher::EVP_CIPHER_free(cipher) };
    ok
}

/// `do_PVK_body_key`: the key of a PVK body (the salt, then the blob, encrypted after its first
/// 8 octets when there's a salt), or NULL.
///
/// # Safety
/// `cb` is NULL or a callback taking `u`; `libctx` and `propq` as for the fetches.
#[allow(clippy::too_many_arguments, reason = "do_PVK_body_key's")]
pub(crate) unsafe fn pvk_body_key(
    body: &[u8],
    saltlen: u32,
    keylen: u32,
    cb: pem_password_cb,
    u: *mut c_void,
    isdss: c_int,
    ispub: c_int,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> (*mut c_void, Option<Header>) {
    const F: &str = "do_PVK_body_key";
    let mut c = Cursor(body);
    let mut plain: rustyssl_crypto::bn::Zeroizing<Vec<u8>>;
    let blob: &[u8] = if saltlen != 0 {
        let mut psbuf = rustyssl_crypto::bn::Zeroizing::new([0 as c_char; PEM_BUFSIZE as usize]);
        // SAFETY: the caller's callback.
        let inlen = unsafe { password(&mut psbuf, 0, cb, u) };
        let Ok(plen) = usize::try_from(inlen) else {
            err::raise(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, F);
            return (ptr::null_mut(), None);
        };
        // SAFETY: a `c_char` buffer as its octets.
        let pass = unsafe {
            core::slice::from_raw_parts(psbuf.as_ptr().cast::<u8>(), plen.min(psbuf.len()))
        };
        let Some(salt) = c.take(usize::try_from(saltlen).unwrap_or(0)) else {
            return (ptr::null_mut(), None);
        };
        let mut keybuf = rustyssl_crypto::bn::Zeroizing::new([0u8; 20]);
        // SAFETY: the caller's library context and properties.
        if !unsafe { derive_pvk_key(&mut keybuf, salt, pass, libctx, propq) } {
            return (ptr::null_mut(), None);
        }
        if keylen < 8 {
            err::raise(ERR_LIB_PEM, PEM_R_PVK_TOO_SHORT, F);
            return (ptr::null_mut(), None);
        }
        let Some(enc) = c.take(usize::try_from(keylen).unwrap_or(0)) else {
            return (ptr::null_mut(), None);
        };
        let try_key = |k: &[u8; 20]| {
            let mut buf = rustyssl_crypto::bn::Zeroizing::new(enc.to_vec());
            let (_, rest) = buf.split_at_mut(8);
            // SAFETY: the caller's library context and properties.
            let ok = unsafe { rc4(k, rest, false, libctx, propq) };
            let magic = rest.first_chunk::<4>().map(|m| u32::from_le_bytes(*m));
            (ok, magic, buf)
        };
        let (ok, magic, buf) = try_key(&keybuf);
        if !ok {
            return (ptr::null_mut(), None);
        }
        plain = buf;
        if magic != Some(MS_RSA2MAGIC) && magic != Some(MS_DSS2MAGIC) {
            if let Some(tail) = keybuf.get_mut(5..16) {
                tail.fill(0);
            }
            let (ok, magic, buf) = try_key(&keybuf);
            if !ok {
                return (ptr::null_mut(), None);
            }
            if magic != Some(MS_RSA2MAGIC) && magic != Some(MS_DSS2MAGIC) {
                err::raise(ERR_LIB_PEM, PEM_R_BAD_DECRYPT, F);
                return (ptr::null_mut(), None);
            }
            plain = buf;
        }
        &plain
    } else {
        c.0
    };
    let mut bc = Cursor(blob);
    do_b2i_key(&mut bc, keylen, isdss, ispub)
}

/// `do_PVK_key_bio`: a PVK read from the BIO (its header, then the salt and blob it gives the
/// lengths of), or NULL. `isdss` and `ispub` are -1 for either, else what's expected.
///
/// # Safety
/// `bp` is a live BIO; otherwise as for `pvk_body_key`.
pub(crate) unsafe fn pvk_key_bio(
    bp: *mut BIO,
    cb: pem_password_cb,
    u: *mut c_void,
    isdss: c_int,
    ispub: c_int,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> (*mut c_void, Option<Header>) {
    // SAFETY: the caller's guarantee.
    let Some(hdr) = (unsafe { read_exact(bp, 24) }) else {
        err::raise(ERR_LIB_PEM, PEM_R_PVK_DATA_TOO_SHORT, "do_PVK_key_bio");
        return (ptr::null_mut(), None);
    };
    let mut c = Cursor(&hdr);
    let Some(h) = pvk_header(&mut c, 24, false, isdss) else {
        return (ptr::null_mut(), None);
    };
    let buflen = h.keylen.saturating_add(h.saltlen);
    // SAFETY: as above.
    let Some(buf) = (unsafe { read_exact(bp, usize::try_from(buflen).unwrap_or(0)) }) else {
        err::raise(ERR_LIB_PEM, PEM_R_PVK_DATA_TOO_SHORT, "do_PVK_key_bio");
        return (ptr::null_mut(), None);
    };
    let buf = rustyssl_crypto::bn::Zeroizing::new(buf);
    // SAFETY: the caller's guarantee.
    unsafe {
        pvk_body_key(
            &buf,
            h.saltlen,
            h.keylen,
            cb,
            u,
            c_int::from(h.isdss),
            ispub,
            libctx,
            propq,
        )
    }
}

ffi_export! {
    /// The key of a PVK read from the BIO (decrypted with the password `cb`, else
    /// `PEM_def_callback`, gives, when it's encrypted), or NULL. The library context isn't
    /// passed on, as OpenSSL's isn't.
    ///
    /// # Safety
    /// `in_` is a live BIO; `cb` is NULL or a callback taking `u`.
    pub unsafe extern "C" fn b2i_PVK_bio_ex(in_: *mut BIO, cb: pem_password_cb, u: *mut c_void, _libctx: *mut OSSL_LIB_CTX, _propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let (key, h) = unsafe { pvk_key_bio(in_, cb, u, -1, -1, ptr::null_mut(), ptr::null()) };
        new0_key(key, h.is_some_and(|h| h.isdss))
    }
}

ffi_export! {
    /// `b2i_PVK_bio_ex` with the default library context.
    ///
    /// # Safety
    /// As for `b2i_PVK_bio_ex`.
    pub unsafe extern "C" fn b2i_PVK_bio(in_: *mut BIO, cb: pem_password_cb, u: *mut c_void) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { b2i_PVK_bio_ex(in_, cb, u, ptr::null_mut(), ptr::null()) }
    }
}

/// `i2b_PVK`: the key's PVK (its blob after the first 8 octets RC4-encrypted under the
/// password and a random salt, `enclevel` 1 with a 40-bit key, 2 with a 128-bit one), or
/// `None`.
///
/// # Safety
/// `pk` is a live key; `cb` is NULL or a callback taking `u`; `libctx` and `propq` as for the
/// fetches.
pub(crate) unsafe fn i2b_pvk(
    pk: *const EVP_PKEY,
    enclevel: c_int,
    cb: pem_password_cb,
    u: *mut c_void,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> Option<rustyssl_crypto::bn::Zeroizing<Vec<u8>>> {
    const F: &str = "i2b_PVK";
    // SAFETY: the caller's key.
    let mut blob = unsafe { do_i2b(pk, false) }?;
    let pklen = u32::try_from(blob.len()).ok()?;
    let mut out = rustyssl_crypto::bn::Zeroizing::new(Vec::new());
    out.extend_from_slice(&MS_PVKMAGIC.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    // SAFETY: the caller's key.
    let keytype = if unsafe { crate::evp::pkey::EVP_PKEY_get_id(pk) } == EVP_PKEY_RSA {
        MS_KEYTYPE_KEYX
    } else {
        MS_KEYTYPE_SIGN
    };
    out.extend_from_slice(&keytype.to_le_bytes());
    out.extend_from_slice(&u32::from(enclevel != 0).to_le_bytes());
    out.extend_from_slice(&(if enclevel != 0 { PVK_SALTLEN } else { 0 }).to_le_bytes());
    out.extend_from_slice(&pklen.to_le_bytes());
    if enclevel != 0 {
        let mut salt = [0u8; PVK_SALTLEN as usize];
        // SAFETY: the caller's library context; room for the salt.
        if unsafe { crate::rand_lib::RAND_bytes_ex(libctx, salt.as_mut_ptr(), salt.len(), 0) } <= 0
        {
            return None;
        }
        let mut psbuf = rustyssl_crypto::bn::Zeroizing::new([0 as c_char; PEM_BUFSIZE as usize]);
        // SAFETY: the caller's callback.
        let inlen = unsafe { password(&mut psbuf, 1, cb, u) };
        let Some(plen) = usize::try_from(inlen).ok().filter(|&n| n > 0) else {
            err::raise(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, F);
            return None;
        };
        // SAFETY: a `c_char` buffer as its octets.
        let pass = unsafe {
            core::slice::from_raw_parts(psbuf.as_ptr().cast::<u8>(), plen.min(psbuf.len()))
        };
        let mut keybuf = rustyssl_crypto::bn::Zeroizing::new([0u8; 20]);
        // SAFETY: the caller's library context and properties.
        if !unsafe { derive_pvk_key(&mut keybuf, &salt, pass, libctx, propq) } {
            return None;
        }
        if enclevel == 1
            && let Some(tail) = keybuf.get_mut(5..16)
        {
            tail.fill(0);
        }
        let rest = blob.get_mut(8..)?;
        // SAFETY: as above.
        if !unsafe { rc4(&keybuf, rest, true, libctx, propq) } {
            return None;
        }
        out.extend_from_slice(&salt);
    }
    out.extend_from_slice(&blob);
    Some(out)
}

ffi_export! {
    /// Writes the key's PVK (encrypted for `enclevel` 1 or 2, with the password `cb`, else
    /// `PEM_def_callback`, gives): its length, or -1.
    ///
    /// # Safety
    /// `out` is a live BIO; `pk` is a live key; `cb` is NULL or a callback taking `u`; `libctx`
    /// is NULL or live; `propq` is NULL or a C string.
    pub unsafe extern "C" fn i2b_PVK_bio_ex(out: *mut BIO, pk: *const EVP_PKEY, enclevel: c_int, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = -1, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let Some(pvk) = (unsafe { i2b_pvk(pk, enclevel, cb, u, libctx, propq) }) else { return -1 };
        let Ok(len) = c_int::try_from(pvk.len()) else { return -1 };
        // SAFETY: the caller's BIO; the PVK.
        if unsafe { crate::bio::BIO_write(out, pvk.as_ptr().cast(), len) } == len {
            return len;
        }
        err::raise(ERR_LIB_PEM, PEM_R_BIO_WRITE_FAILURE, "i2b_PVK_bio_ex");
        -1
    }
}

ffi_export! {
    /// `i2b_PVK_bio_ex` with the default library context.
    ///
    /// # Safety
    /// As for `i2b_PVK_bio_ex`.
    pub unsafe extern "C" fn i2b_PVK_bio(out: *mut BIO, pk: *const EVP_PKEY, enclevel: c_int, cb: pem_password_cb, u: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2b_PVK_bio_ex(out, pk, enclevel, cb, u, ptr::null_mut(), ptr::null()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_lengths_wrap_as_unsigned_int() {
        assert_eq!(blob_length(1024, false, false), 4 + 128 * 2 + 64 * 5);
        assert_eq!(blob_length(1024, true, true), 44 + 128 * 3);
        // (bitlen + 7) wraps to 0, so the body is just e's four octets.
        assert_eq!(blob_length(0xffff_fff9, false, false), 4);
        assert_eq!(blob_length(0xffff_fff9, false, true), 4);
    }

    #[test]
    fn headers_are_checked() {
        let mut h = [0u8; 16];
        h[0] = MS_PRIVATEKEYBLOB;
        h[1] = 2;
        h[8..12].copy_from_slice(&MS_RSA2MAGIC.to_le_bytes());
        h[12..16].copy_from_slice(&512u32.to_le_bytes());
        let mut c = Cursor(&h);
        let (r, hd) = blob_header(&mut c, 16, -1, -1);
        assert_eq!(r, 1);
        assert!(hd.is_some_and(|hd| !hd.isdss && !hd.ispub && hd.bitlen == 512));
        assert!(c.0.is_empty());
        // A private blob where a public one is expected, then a bad magic.
        assert_eq!(blob_header(&mut Cursor(&h), 16, -1, 1).0, 0);
        h[8] = 0;
        assert_eq!(blob_header(&mut Cursor(&h), 16, -1, -1).0, -1);
        // Too short, even when the length says otherwise.
        assert_eq!(blob_header(&mut Cursor(&h[..10]), 16, -1, -1).0, 0);
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    /// docs/DEVIATIONS.md: OpenSSL takes a negative length as a huge `unsigned int` and reads
    /// past the buffer.
    #[test]
    fn a_negative_length_is_refused() {
        let mut h = [0u8; 20];
        h[0] = MS_PRIVATEKEYBLOB;
        h[1] = 2;
        h[8..12].copy_from_slice(&MS_RSA2MAGIC.to_le_bytes());
        h[12..16].copy_from_slice(&1024u32.to_le_bytes());
        let mut p = h.as_ptr();
        // SAFETY: the buffer; a negative length.
        let k = unsafe { b2i_PrivateKey(&raw mut p, -1) };
        assert!(k.is_null());
        // SAFETY: as above.
        let k = unsafe { b2i_PublicKey(&raw mut p, c_long::MIN) };
        assert!(k.is_null());
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
