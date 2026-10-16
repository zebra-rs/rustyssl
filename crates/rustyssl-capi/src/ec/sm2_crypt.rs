//! SM2 encryption (`sm2_crypt.c`): the ciphertext `SEQUENCE { C1x INTEGER, C1y INTEGER,
//! C3 OCTET STRING, C2 OCTET STRING }` (decoded and encoded by the template engine, as
//! OpenSSL's `SM2_Ciphertext` item is), its size for a message and a message's size in it, and
//! encrypting and decrypting: `C1 = kG`, a mask from X9.63's KDF over `kP`'s coordinates (`dC1`
//! when decrypting), `C2 = M ^ mask`, `C3 = H(x2 || M || y2)`.
//!
//! As in OpenSSL, an empty message fails without an error (its allocation of no octets fails),
//! a decryption writes the message before its check and clears the whole buffer if the check
//! fails, and the check compares in constant time.

use core::ffi::{c_int, c_long, c_uchar};
use core::mem::offset_of;
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_OCTET_STRING, ASN1_VALUE, BIGNUM, EC_KEY, ERR_LIB_SM2, ERR_R_ASN1_LIB,
    ERR_R_BN_LIB, ERR_R_EC_LIB, ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR, EVP_MD, V_ASN1_INTEGER,
    V_ASN1_OCTET_STRING, V_ASN1_SEQUENCE,
};

use super::ecdsa::kdf_x9_63;
use super::group::{EC_GROUP_get0_field, EC_GROUP_get0_order};
use super::key::{EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key, key};
use super::point::{
    EC_POINT_free, EC_POINT_get_affine_coordinates, EC_POINT_mul, EC_POINT_new,
    EC_POINT_set_affine_coordinates,
};
use crate::asn1::ASN1_object_size;
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new, ASN1_OCTET_STRING_set};
use crate::asn1::tpl::bignum::BIGNUM_it;
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::items::ASN1_OCTET_STRING_it;
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{Item, template_at};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::rand::BN_priv_rand_range_ex;
use crate::bn::{BN_clear_free, BN_new, value};
use crate::err;
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free, EVP_MD_get_size, EVP_MD_get0_name};
use crate::evp::md_ctx::{
    EVP_DigestFinal, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
};
use crate::generated::err_strings::{
    SM2_R_ASN1_ERROR, SM2_R_BUFFER_TOO_SMALL, SM2_R_INVALID_DIGEST, SM2_R_INVALID_ENCODING,
};
use crate::mem::CRYPTO_memcmp;
use crate::provider::macs::wipe;

fn raise(reason: c_int, func: &str) {
    err::raise(ERR_LIB_SM2, reason, func);
}

/// `struct SM2_Ciphertext_st`.
#[repr(C)]
struct Ciphertext {
    c1x: *mut BIGNUM,
    c1y: *mut BIGNUM,
    c3: *mut ASN1_OCTET_STRING,
    c2: *mut ASN1_OCTET_STRING,
}

static CIPHERTEXT_TT: Templates<4> = Templates([
    template_at(0, 0, offset_of!(Ciphertext, c1x), c"C1x", BIGNUM_it),
    template_at(0, 0, offset_of!(Ciphertext, c1y), c"C1y", BIGNUM_it),
    template_at(
        0,
        0,
        offset_of!(Ciphertext, c3),
        c"C3",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        0,
        0,
        offset_of!(Ciphertext, c2),
        c"C2",
        ASN1_OCTET_STRING_it,
    ),
]);
static CIPHERTEXT: Item = sequence::<Ciphertext, 4>(&CIPHERTEXT_TT, None, c"SM2_Ciphertext");

fn ciphertext_it() -> *const ASN1_ITEM {
    &raw const CIPHERTEXT.0
}

/// A decoded ciphertext, freed on drop.
struct Decoded(*mut Ciphertext);

impl Decoded {
    /// `d2i_SM2_Ciphertext` (what follows it is ignored), or `None` with the errors raised.
    fn new(ct: &[u8]) -> Option<Self> {
        let len = c_long::try_from(ct.len()).ok()?;
        let mut p = ct.as_ptr();
        // SAFETY: `len` readable octets; the item.
        let v = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, len, ciphertext_it()) };
        (!v.is_null()).then(|| Self(v.cast()))
    }

    fn get(&self) -> &Ciphertext {
        // SAFETY: a decoded structure, alive until dropped.
        unsafe { &*self.0 }
    }
}

impl Drop for Decoded {
    fn drop(&mut self) {
        // SAFETY: the structure the item decoded, freed once.
        unsafe { ASN1_item_free(self.0.cast::<ASN1_VALUE>(), ciphertext_it()) };
    }
}

/// An octet string's octets.
///
/// # Safety
/// `s` is a live string.
unsafe fn string_octets<'a>(s: *const ASN1_OCTET_STRING) -> &'a [u8] {
    // SAFETY: the caller's guarantee.
    let s = unsafe { &*s };
    let n = usize::try_from(s.length).unwrap_or(0);
    if s.data.is_null() || n == 0 {
        return &[];
    }
    // SAFETY: the string's `length` octets.
    unsafe { core::slice::from_raw_parts(s.data, n) }
}

/// `ec_field_size`: the field's octets (0 without a group).
///
/// # Safety
/// `eckey` is a live key.
unsafe fn field_size(eckey: *const EC_KEY) -> usize {
    // SAFETY: the caller's key.
    let g = unsafe { EC_KEY_get0_group(eckey) };
    if g.is_null() {
        return 0;
    }
    // SAFETY: the key's group.
    let p = unsafe { EC_GROUP_get0_field(g) };
    // SAFETY: the group's number, or NULL.
    unsafe { value(p) }.map_or(0, |v| v.num_bytes())
}

/// The digest's size, or `None` for none or an invalid one.
///
/// # Safety
/// `md` is NULL or a live digest.
unsafe fn md_size(md: *const EVP_MD) -> Option<usize> {
    // SAFETY: the caller's guarantee.
    usize::try_from(unsafe { EVP_MD_get_size(md) })
        .ok()
        .filter(|&n| n > 0)
}

/// `ossl_sm2_plaintext_size`: the length of the message a ciphertext holds.
pub(crate) fn plaintext_size(ct: &[u8]) -> Option<usize> {
    let Some(d) = Decoded::new(ct) else {
        raise(SM2_R_INVALID_ENCODING, "ossl_sm2_plaintext_size");
        return None;
    };
    // SAFETY: the decoded string.
    Some(unsafe { string_octets(d.get().c2) }.len())
}

/// `ossl_sm2_ciphertext_size`: a ciphertext's largest size for a message of `msg_len` octets.
///
/// # Safety
/// `eckey` is a live key; `digest` is NULL or a live digest.
pub(crate) unsafe fn ciphertext_size(
    eckey: *const EC_KEY,
    digest: *const EVP_MD,
    msg_len: usize,
) -> Option<usize> {
    // SAFETY: the caller's guarantee.
    let fs = unsafe { field_size(eckey) };
    // SAFETY: as above.
    let md = unsafe { md_size(digest) }?;
    if fs == 0 {
        return None;
    }
    let size = |constructed, len: usize, tag| {
        let l = c_int::try_from(len).ok()?;
        // SAFETY: no preconditions.
        usize::try_from(unsafe { ASN1_object_size(constructed, l, tag) }).ok()
    };
    let int = size(0, fs.checked_add(1)?, V_ASN1_INTEGER)?;
    let sz = int
        .checked_mul(2)?
        .checked_add(size(0, md, V_ASN1_OCTET_STRING)?)?
        .checked_add(size(0, msg_len, V_ASN1_OCTET_STRING)?)?;
    size(1, sz, V_ASN1_SEQUENCE)
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
}

impl<const N: usize> Drop for Nums<N> {
    fn drop(&mut self) {
        for b in self.0 {
            // SAFETY: made here, or NULL; freed once.
            unsafe { BN_clear_free(b) };
        }
    }
}

/// The coordinates padded to the field's octets and joined (`x2 || y2`), or `None`.
fn join(
    x: &rustyssl_crypto::bn::BigNum,
    y: &rustyssl_crypto::bn::BigNum,
    fs: usize,
) -> Option<Vec<u8>> {
    use rustyssl_crypto::bn::Endian;
    let mut v = x.to_bin(Some(fs), Endian::Big, false)?.to_vec();
    v.extend_from_slice(&y.to_bin(Some(fs), Endian::Big, false)?);
    Some(v)
}

/// `H(x2 || msg || y2)` into `out` with `digest`.
///
/// # Safety
/// `digest` is a live digest; `out` has room for its size.
unsafe fn c3_hash(digest: *const EVP_MD, x2y2: &[u8], fs: usize, msg: &[u8], out: *mut u8) -> bool {
    let (x2, y2) = x2y2.split_at(fs.min(x2y2.len()));
    // SAFETY: no preconditions.
    let h = unsafe { EVP_MD_CTX_new() };
    if h.is_null() {
        return false;
    }
    // SAFETY: the context; the caller's digest; octets; room for the hash.
    let ok = unsafe { EVP_DigestInit_ex(h, digest, ptr::null_mut()) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestUpdate(h, x2.as_ptr().cast(), x2.len()) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestUpdate(h, msg.as_ptr().cast(), msg.len()) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestUpdate(h, y2.as_ptr().cast(), y2.len()) } != 0
        // SAFETY: as above.
        && unsafe { EVP_DigestFinal(h, out, ptr::null_mut()) } != 0;
    // SAFETY: made above.
    unsafe { EVP_MD_CTX_free(h) };
    ok
}

/// `ossl_sm2_encrypt`: the ciphertext of `msg` into `out`, whose room is `*out_len` (cleared
/// first), and its length into `*out_len`.
///
/// # Safety
/// `eckey` is a live key; `digest` is a live digest; `out` has room for `*out_len` octets;
/// `out_len` is readable and writable.
pub(crate) unsafe fn encrypt(
    eckey: *const EC_KEY,
    digest: *const EVP_MD,
    msg: &[u8],
    out: *mut c_uchar,
    out_len: *mut usize,
) -> bool {
    const F: &str = "ossl_sm2_encrypt";
    // SAFETY: the caller's guarantee.
    let Some(c3_size) = (unsafe { md_size(digest) }) else {
        raise(ERR_R_INTERNAL_ERROR, F);
        return false;
    };
    // SAFETY: as above.
    let fs = unsafe { field_size(eckey) };
    if fs == 0 {
        raise(ERR_R_INTERNAL_ERROR, F);
        return false;
    }
    // SAFETY: as above.
    let group = unsafe { EC_KEY_get0_group(eckey) };
    // SAFETY: the key's group.
    let order = unsafe { EC_GROUP_get0_order(group) };
    // SAFETY: as above.
    let p = unsafe { EC_KEY_get0_public_key(eckey) };
    // SAFETY: the group.
    let kg = unsafe { EC_POINT_new(group) };
    // SAFETY: as above.
    let kp = unsafe { EC_POINT_new(group) };
    // SAFETY: the caller's key.
    let (libctx, propq) = unsafe { key(eckey) }.map_or((ptr::null_mut(), ptr::null()), |k| {
        (k.get().libctx.0, k.propq())
    });
    // SAFETY: the key's library context, or NULL.
    let ctx = unsafe { BN_CTX_new_ex(libctx) };
    let nums = Nums::<5>::new();
    let ok = (|| {
        if kg.is_null() || kp.is_null() {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        if ctx.is_null() || !nums.ok() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        let [k, x1, x2, y1, y2] = nums.0;
        // SAFETY: the caller's guarantee.
        let room = unsafe { out_len.read() };
        // SAFETY: the caller's room.
        unsafe { ptr::write_bytes(out, 0, room) };
        // OpenSSL's allocation of an empty message's mask fails, silently.
        if msg.is_empty() {
            return false;
        }
        let mut mask = vec![0u8; msg.len()];
        let mut x2y2;
        loop {
            // SAFETY: a number; the order; the context.
            if unsafe { BN_priv_rand_range_ex(k, order, 0, ctx) } == 0 {
                raise(ERR_R_INTERNAL_ERROR, F);
                return false;
            }
            // SAFETY: the group, points, numbers, and context.
            let points = unsafe { EC_POINT_mul(group, kg, k, ptr::null(), ptr::null(), ctx) } != 0
                // SAFETY: as above.
                && unsafe { EC_POINT_get_affine_coordinates(group, kg, x1, y1, ctx) } != 0
                // SAFETY: as above.
                && unsafe { EC_POINT_mul(group, kp, ptr::null(), p, k, ctx) } != 0
                // SAFETY: as above.
                && unsafe { EC_POINT_get_affine_coordinates(group, kp, x2, y2, ctx) } != 0;
            if !points {
                raise(ERR_R_EC_LIB, F);
                return false;
            }
            // SAFETY: numbers made here.
            let joined = match (unsafe { value(x2) }, unsafe { value(y2) }) {
                (Some(a), Some(b)) => join(&a, &b, fs),
                _ => None,
            };
            let Some(j) = joined else {
                raise(ERR_R_INTERNAL_ERROR, F);
                return false;
            };
            x2y2 = j;
            // X9.63's KDF without shared info is SM2's.
            // SAFETY: room for the mask; the digest; the key's library context and query.
            if !unsafe {
                kdf_x9_63(
                    mask.as_mut_ptr(),
                    mask.len(),
                    &x2y2,
                    &[],
                    digest,
                    libctx,
                    propq,
                )
            } {
                raise(ERR_R_EVP_LIB, F);
                return false;
            }
            if mask.iter().any(|&b| b != 0) {
                break;
            }
            wipe(&mut x2y2);
        }
        for (m, b) in mask.iter_mut().zip(msg) {
            *m ^= b;
        }
        // SAFETY: the caller's digest.
        let name = unsafe { EVP_MD_get0_name(digest) };
        // SAFETY: the digest's name; the key's library context and query.
        let fetched = unsafe { EVP_MD_fetch(libctx, name, propq) };
        if fetched.is_null() {
            raise(ERR_R_INTERNAL_ERROR, F);
            wipe(&mut x2y2);
            return false;
        }
        let mut c3 = vec![0u8; c3_size];
        // SAFETY: the digest; room for its size.
        let hashed = unsafe { c3_hash(fetched, &x2y2, fs, msg, c3.as_mut_ptr()) };
        // SAFETY: the reference fetched above.
        unsafe { EVP_MD_free(fetched) };
        wipe(&mut x2y2);
        if !hashed {
            raise(ERR_R_EVP_LIB, F);
            return false;
        }
        // SAFETY: no preconditions.
        let s3 = unsafe { ASN1_OCTET_STRING_new() };
        // SAFETY: as above.
        let s2 = unsafe { ASN1_OCTET_STRING_new() };
        let written = (|| {
            if s3.is_null() || s2.is_null() {
                raise(ERR_R_ASN1_LIB, F);
                return false;
            }
            let (Ok(l3), Ok(l2)) = (c_int::try_from(c3.len()), c_int::try_from(mask.len())) else {
                raise(ERR_R_INTERNAL_ERROR, F);
                return false;
            };
            // SAFETY: the strings; the octets.
            if unsafe { ASN1_OCTET_STRING_set(s3, c3.as_ptr(), l3) } == 0
                // SAFETY: as above.
                || unsafe { ASN1_OCTET_STRING_set(s2, mask.as_ptr(), l2) } == 0
            {
                raise(ERR_R_INTERNAL_ERROR, F);
                return false;
            }
            let st = Ciphertext {
                c1x: x1,
                c1y: y1,
                c3: s3,
                c2: s2,
            };
            let v = (&raw const st).cast::<ASN1_VALUE>();
            // SAFETY: the structure; the item.
            let need = unsafe { ASN1_item_i2d(v, ptr::null_mut(), ciphertext_it()) };
            let Ok(need) = usize::try_from(need) else {
                raise(ERR_R_INTERNAL_ERROR, F);
                return false;
            };
            if room < need {
                raise(SM2_R_BUFFER_TOO_SMALL, F);
                return false;
            }
            let mut o = out;
            // SAFETY: the structure; the caller's room for `need` octets; the item.
            let n = unsafe { ASN1_item_i2d(v, &raw mut o, ciphertext_it()) };
            let Ok(n) = usize::try_from(n) else {
                raise(ERR_R_INTERNAL_ERROR, F);
                return false;
            };
            // SAFETY: the caller's guarantee.
            unsafe { out_len.write(n) };
            true
        })();
        // SAFETY: made above, or NULL.
        unsafe { ASN1_OCTET_STRING_free(s3) };
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_free(s2) };
        wipe(&mut mask);
        written
    })();
    // SAFETY: made above, or NULL.
    unsafe { BN_CTX_free(ctx) };
    // SAFETY: as above.
    unsafe { EC_POINT_free(kg) };
    // SAFETY: as above.
    unsafe { EC_POINT_free(kp) };
    ok
}

/// `ossl_sm2_decrypt`: the message of `ct` into `out`, whose room is `*out_len` (filled with
/// 0xFF first, cleared on failure), and its length into `*out_len`.
///
/// # Safety
/// `eckey` is a live key; `digest` is a live digest; `out` has room for `*out_len` octets;
/// `out_len` is readable and writable.
pub(crate) unsafe fn decrypt(
    eckey: *const EC_KEY,
    digest: *const EVP_MD,
    ct: &[u8],
    out: *mut c_uchar,
    out_len: *mut usize,
) -> bool {
    const F: &str = "ossl_sm2_decrypt";
    // SAFETY: the caller's guarantee.
    let fs = unsafe { field_size(eckey) };
    // SAFETY: as above.
    let hash_size = unsafe { md_size(digest) };
    // SAFETY: as above.
    let room = unsafe { out_len.read() };
    let Some(hash_size) = hash_size.filter(|_| fs != 0) else {
        // OpenSSL's early exit still clears the buffer.
        // SAFETY: the caller's room.
        unsafe { ptr::write_bytes(out, 0, room) };
        return false;
    };
    // SAFETY: the caller's room.
    unsafe { ptr::write_bytes(out, 0xFF, room) };
    // SAFETY: the caller's key.
    let group = unsafe { EC_KEY_get0_group(eckey) };
    // SAFETY: as above.
    let (libctx, propq) = unsafe { key(eckey) }.map_or((ptr::null_mut(), ptr::null()), |k| {
        (k.get().libctx.0, k.propq())
    });
    let mut ctx = ptr::null_mut();
    let mut c1 = ptr::null_mut();
    let nums = Nums::<2>::new();
    let ok = (|| {
        let Some(d) = Decoded::new(ct) else {
            raise(SM2_R_ASN1_ERROR, F);
            return false;
        };
        let s = d.get();
        // SAFETY: a decoded string.
        let c3 = unsafe { string_octets(s.c3) };
        // SAFETY: as above.
        let c2 = unsafe { string_octets(s.c2) };
        if c3.len() != hash_size {
            raise(SM2_R_INVALID_ENCODING, F);
            return false;
        }
        let msg_len = c2.len();
        if room < msg_len {
            raise(SM2_R_BUFFER_TOO_SMALL, F);
            return false;
        }
        // SAFETY: the key's library context, or NULL.
        ctx = unsafe { BN_CTX_new_ex(libctx) };
        if ctx.is_null() || !nums.ok() {
            raise(ERR_R_BN_LIB, F);
            return false;
        }
        // OpenSSL's allocation of an empty message's mask fails, silently.
        if msg_len == 0 {
            return false;
        }
        let mut mask = vec![0u8; msg_len];
        // SAFETY: the group.
        c1 = unsafe { EC_POINT_new(group) };
        if c1.is_null() {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        let [x2, y2] = nums.0;
        // SAFETY: the key.
        let d_priv = unsafe { EC_KEY_get0_private_key(eckey) };
        // SAFETY: the group, point, the decoded numbers, the context.
        let points = unsafe { EC_POINT_set_affine_coordinates(group, c1, s.c1x, s.c1y, ctx) } != 0
            // SAFETY: as above, with the key's number.
            && unsafe { EC_POINT_mul(group, c1, ptr::null(), c1, d_priv, ctx) } != 0
            // SAFETY: as above.
            && unsafe { EC_POINT_get_affine_coordinates(group, c1, x2, y2, ctx) } != 0;
        if !points {
            raise(ERR_R_EC_LIB, F);
            return false;
        }
        // SAFETY: numbers made here.
        let joined = match (unsafe { value(x2) }, unsafe { value(y2) }) {
            (Some(a), Some(b)) => join(&a, &b, fs),
            _ => None,
        };
        let Some(mut x2y2) = joined else {
            raise(ERR_R_INTERNAL_ERROR, F);
            return false;
        };
        // SAFETY: room for the mask; the digest; the key's library context and query.
        if !unsafe {
            kdf_x9_63(
                mask.as_mut_ptr(),
                mask.len(),
                &x2y2,
                &[],
                digest,
                libctx,
                propq,
            )
        } {
            raise(ERR_R_INTERNAL_ERROR, F);
            wipe(&mut x2y2);
            return false;
        }
        if mask.iter().all(|&b| b == 0) {
            raise(SM2_R_INVALID_ENCODING, F);
            wipe(&mut x2y2);
            return false;
        }
        // SAFETY: the caller's room, at least `msg_len` octets.
        let pt = unsafe { core::slice::from_raw_parts_mut(out, msg_len) };
        for ((o, c), m) in pt.iter_mut().zip(c2).zip(&mask) {
            *o = c ^ m;
        }
        wipe(&mut mask);
        let mut computed = vec![0u8; hash_size];
        // SAFETY: the caller's digest; room for its size.
        let hashed = unsafe { c3_hash(digest, &x2y2, fs, pt, computed.as_mut_ptr()) };
        wipe(&mut x2y2);
        if !hashed {
            raise(ERR_R_EVP_LIB, F);
            return false;
        }
        // SAFETY: two buffers of `hash_size` octets.
        if unsafe { CRYPTO_memcmp(computed.as_ptr().cast(), c3.as_ptr().cast(), hash_size) } != 0 {
            raise(SM2_R_INVALID_DIGEST, F);
            return false;
        }
        // SAFETY: the caller's guarantee.
        unsafe { out_len.write(msg_len) };
        true
    })();
    if !ok {
        // SAFETY: the caller's room (its length unchanged on failure).
        unsafe { ptr::write_bytes(out, 0, room) };
    }
    // SAFETY: made above, or NULL.
    unsafe { EC_POINT_free(c1) };
    // SAFETY: as above.
    unsafe { BN_CTX_free(ctx) };
    ok
}
