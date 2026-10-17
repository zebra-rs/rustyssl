//! SubjectPublicKeyInfo (`x_pubkey.c`, with `x_all.c`'s BIO and FILE forms): `X509_PUBKEY`, an
//! AlgorithmIdentifier and the key's BIT STRING, with the key it holds decoded, and the
//! functions that make, read, compare, and copy one; `i2d_PUBKEY`; and the typed
//! `d2i_RSA_PUBKEY`, `i2d_RSA_PUBKEY`, and the DSA and EC ones.
//!
//! As OpenSSL's, `X509_PUBKEY` is an extern item over its own structure (which the headers keep
//! opaque), whose private SEQUENCE item `X509_PUBKEY_INTERNAL` the engine walks. Decoding one
//! also decodes its key: with the key type's ASN.1 method for the typed functions (which force
//! the legacy route), else with a decoder (step 4.7b; until then that aborts). A key made by a
//! provider is encoded by an encoder (step 4.7c; until then that aborts too).

use core::ffi::{c_char, c_int, c_long, c_uchar, c_uint, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_EXTERN_FUNCS, ASN1_ITEM, ASN1_ITYPE_EXTERN, ASN1_OBJECT, ASN1_PCTX,
    ASN1_STRING_FLAG_BITS_LEFT, ASN1_TLC, ASN1_VALUE, BIO, DSA, EC_KEY, ERR_LIB_ASN1, ERR_LIB_EVP,
    ERR_LIB_X509, ERR_R_ASN1_LIB, ERR_R_EVP_LIB, ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER,
    ERR_R_X509_LIB, EVP_PKEY, EVP_PKEY_DSA, EVP_PKEY_EC, EVP_PKEY_RSA, EVP_PKEY_SM2,
    EVP_R_DECODE_ERROR, OSSL_LIB_CTX, RSA, V_ASN1_SEQUENCE, X509_ALGOR, X509_PUBKEY,
    X509_R_METHOD_NOT_SUPPORTED, X509_R_PUBLIC_KEY_ENCODE_ERROR, X509_R_UNSUPPORTED_ALGORITHM,
};

use super::algor::{X509_ALGOR_cmp, X509_ALGOR_dup, set0};
use crate::asn1::bit_string::ASN1_BIT_STRING_set;
use crate::asn1::string::ASN1_STRING_set0;
use crate::asn1::string::{ASN1_BIT_STRING_free, ASN1_BIT_STRING_new};
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::decode::ASN1_item_ex_d2i;
use crate::asn1::tpl::encode::ASN1_item_ex_i2d;
use crate::asn1::tpl::io::{
    ASN1_d2i_bio, ASN1_d2i_fp, ASN1_i2d_bio, ASN1_i2d_fp, ASN1_item_d2i_bio, ASN1_item_d2i_fp,
    ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_BIT_STRING_it, X509_ALGOR_free, X509_ALGOR_it, X509_ALGOR_new, d2i, i2d, new_free,
};
use crate::asn1::tpl::new::ASN1_item_new_ex;
use crate::asn1::tpl::print::ASN1_item_print;
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{Item, item, template_at};
use crate::dsa::{DSA_free, DSA_new};
use crate::ec::key::{EC_KEY_free, EC_KEY_new};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::pkey::dsa::EVP_PKEY_get1_DSA;
use crate::evp::pkey::ec::EVP_PKEY_get1_EC_KEY;
use crate::evp::pkey::rsa::EVP_PKEY_get1_RSA;
use crate::evp::pkey::{
    EVP_PKEY_assign, EVP_PKEY_dup, EVP_PKEY_eq, EVP_PKEY_free, EVP_PKEY_get_id, EVP_PKEY_new,
    EVP_PKEY_set_type, EVP_PKEY_up_ref, pkey,
};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::objects::OBJ_obj2nid;
use crate::rsa_lib::{RSA_free, RSA_new};

/// `X509_PUBKEY` (`X509_pubkey_st`).
#[repr(C)]
pub(crate) struct Pubkey {
    pub(crate) algor: *mut X509_ALGOR,
    pub(crate) public_key: *mut ASN1_BIT_STRING,
    /// The key decoded (or set), with a reference this holds, or NULL.
    pub(crate) pkey: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
    /// From the C allocator, or NULL.
    propq: *mut c_char,
    /// Decode the key only with its ASN.1 method.
    flag_force_legacy: c_uint,
}

static INTERNAL_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(Pubkey, algor), c"algor", X509_ALGOR_it),
    template_at(
        0,
        0,
        offset_of!(Pubkey, public_key),
        c"public_key",
        ASN1_BIT_STRING_it,
    ),
]);

/// `X509_PUBKEY_INTERNAL`: the SEQUENCE the extern item's functions walk.
static INTERNAL: Item = sequence::<Pubkey, 2>(&INTERNAL_TT, None, c"X509_PUBKEY");

extern "C" fn internal_it() -> *const ASN1_ITEM {
    &raw const INTERNAL.0
}

/// The extern functions (`x509_pubkey_ff`).
struct Funcs(ASN1_EXTERN_FUNCS);
// SAFETY: immutable, with no pointers but functions.
unsafe impl Sync for Funcs {}

static FUNCS: Funcs = Funcs(ASN1_EXTERN_FUNCS {
    app_data: ptr::null_mut(),
    asn1_ex_new: None,
    asn1_ex_free: Some(ex_free),
    asn1_ex_clear: None,
    asn1_ex_d2i: None,
    asn1_ex_i2d: Some(ex_i2d),
    asn1_ex_print: Some(ex_print),
    asn1_ex_new_ex: Some(ex_new_ex),
    asn1_ex_d2i_ex: Some(ex_d2i_ex),
});

static PUBKEY: Item = item(
    ASN1_ITYPE_EXTERN,
    V_ASN1_SEQUENCE,
    ptr::null(),
    0,
    (&raw const FUNCS.0).cast(),
    0,
    c"X509_PUBKEY",
);

ffi_export! {
    /// SubjectPublicKeyInfo: SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT
    /// STRING }, with the key decoded.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn X509_PUBKEY_it() -> *const ASN1_ITEM
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        &raw const PUBKEY.0
    }
}

new_free! {
    pub unsafe extern "C" fn X509_PUBKEY_new, pub unsafe extern "C" fn X509_PUBKEY_free(X509_PUBKEY) = X509_PUBKEY_it;
}

i2d! {
    /// Encodes a SubjectPublicKeyInfo.
    pub unsafe extern "C" fn i2d_X509_PUBKEY(X509_PUBKEY) = X509_PUBKEY_it;
}

d2i! {
    /// Decodes a SubjectPublicKeyInfo and its key (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_X509_PUBKEY(X509_PUBKEY) = X509_PUBKEY_it;
}

ffi_export! {
    /// Reads a SubjectPublicKeyInfo from a BIO.
    ///
    /// # Safety
    /// `bp` is a live BIO; `xpk` is NULL or holds NULL or a live structure.
    pub unsafe extern "C" fn d2i_X509_PUBKEY_bio(bp: *mut BIO, xpk: *mut *mut X509_PUBKEY) -> *mut X509_PUBKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_PUBKEY_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_d2i_bio(it, bp, xpk.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a SubjectPublicKeyInfo to a BIO. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `xpk` is a live structure.
    pub unsafe extern "C" fn i2d_X509_PUBKEY_bio(bp: *mut BIO, xpk: *const X509_PUBKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_PUBKEY_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d_bio(it, bp, xpk.cast()) }
    }
}

ffi_export! {
    /// Reads a SubjectPublicKeyInfo from a file.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `xpk` is NULL or holds NULL or a live structure.
    pub unsafe extern "C" fn d2i_X509_PUBKEY_fp(fp: *mut FILE, xpk: *mut *mut X509_PUBKEY) -> *mut X509_PUBKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_PUBKEY_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_d2i_fp(it, fp, xpk.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a SubjectPublicKeyInfo to a file. 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `xpk` is a live structure.
    pub unsafe extern "C" fn i2d_X509_PUBKEY_fp(fp: *mut FILE, xpk: *const X509_PUBKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_PUBKEY_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d_fp(it, fp, xpk.cast()) }
    }
}

/// The structure behind a pointer.
///
/// # Safety
/// `p` is NULL or a live `X509_PUBKEY`, which nothing else changes while the reference lives.
pub(crate) unsafe fn pubkey_of<'a>(p: *const X509_PUBKEY) -> Option<&'a mut Pubkey> {
    // SAFETY: the caller's guarantee; an `X509_PUBKEY` is a `Pubkey`.
    unsafe { p.cast::<Pubkey>().cast_mut().as_mut() }
}

/// `x509_pubkey_set0_libctx`: the library context and a copy of the query. False when memory
/// runs out.
fn set0_libctx(x: &mut Pubkey, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> bool {
    x.libctx = libctx;
    // SAFETY: the structure's own string, or NULL.
    unsafe { mem::release(x.propq.cast()) };
    x.propq = ptr::null_mut();
    if !propq.is_null() {
        // SAFETY: the caller's string.
        x.propq = unsafe { crate::string::CRYPTO_strdup(propq, ptr::null(), 0) };
        if x.propq.is_null() {
            return false;
        }
    }
    true
}

/// `x509_pubkey_ex_free` of a structure.
///
/// # Safety
/// `p` is NULL or a live structure from `alloc`, which the caller gives up.
unsafe fn free_struct(p: *mut Pubkey) {
    // SAFETY: the caller's guarantee.
    let Some(x) = (unsafe { p.as_mut() }) else {
        return;
    };
    // SAFETY: its fields, each NULL or its own.
    unsafe {
        X509_ALGOR_free(x.algor);
    }
    // SAFETY: as above.
    unsafe { ASN1_BIT_STRING_free(x.public_key) };
    // SAFETY: as above.
    unsafe { EVP_PKEY_free(x.pkey) };
    // SAFETY: as above.
    unsafe { mem::release(x.propq.cast()) };
    // SAFETY: the structure, from the C allocator.
    unsafe { mem::release(p.cast()) };
}

/// `x509_pubkey_ex_populate`: an AlgorithmIdentifier and a BIT STRING where it has none.
fn populate(x: &mut Pubkey) -> bool {
    if x.algor.is_null() {
        // SAFETY: no preconditions.
        x.algor = unsafe { X509_ALGOR_new() };
    }
    if x.public_key.is_null() {
        // SAFETY: no preconditions.
        x.public_key = unsafe { ASN1_BIT_STRING_new() };
    }
    !x.algor.is_null() && !x.public_key.is_null()
}

/// A new, zeroed structure from the C allocator, or NULL.
fn alloc() -> *mut Pubkey {
    mem::zalloc(size_of::<Pubkey>(), ptr::null(), 0).cast()
}

ffi_callback! {
    /// `x509_pubkey_ex_free`.
    ///
    /// # Safety
    /// `pval` is NULL or holds NULL or a live structure.
    pub(crate) unsafe extern "C" fn ex_free(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM)
    where failure = (), library = ERR_LIB_ASN1
    {
        if pval.is_null() {
            return;
        }
        // SAFETY: the caller's guarantee.
        let p = unsafe { pval.read() };
        if !p.is_null() {
            // SAFETY: the slot's structure.
            unsafe { free_struct(p.cast()) };
            // SAFETY: the caller's slot.
            unsafe { pval.write(ptr::null_mut()) };
        }
    }
}

ffi_callback! {
    /// `x509_pubkey_ex_new_ex`: a structure with its two fields and the library context.
    ///
    /// # Safety
    /// `pval` is writable; `propq` is NULL or a string.
    pub(crate) unsafe extern "C" fn ex_new_ex(pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        let p = alloc();
        // SAFETY: just made, or NULL.
        let Some(x) = (unsafe { p.as_mut() }) else { return 0 };
        if !populate(x) || !set0_libctx(x, libctx, propq) {
            // SAFETY: made above.
            unsafe { free_struct(p) };
            err::raise(ERR_LIB_ASN1, ERR_R_X509_LIB, "x509_pubkey_ex_new_ex");
            return 0;
        }
        // SAFETY: the caller's slot.
        unsafe { pval.write(p.cast()) };
        1
    }
}

ffi_callback! {
    /// `x509_pubkey_ex_i2d`: the internal SEQUENCE.
    ///
    /// # Safety
    /// As for `ASN1_item_ex_i2d`.
    pub(crate) unsafe extern "C" fn ex_i2d(pval: *mut *const ASN1_VALUE, out: *mut *mut c_uchar, _it: *const ASN1_ITEM, tag: c_int, aclass: c_int) -> c_int
    where failure = -1, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee; the internal item.
        unsafe { ASN1_item_ex_i2d(pval, out, internal_it(), tag, aclass) }
    }
}

ffi_callback! {
    /// `x509_pubkey_ex_print`: the internal SEQUENCE.
    ///
    /// # Safety
    /// As for `ASN1_item_print`, with `pval` holding a live structure.
    pub(crate) unsafe extern "C" fn ex_print(out: *mut BIO, pval: *mut *const ASN1_VALUE, indent: c_int, _fname: *const c_char, pctx: *const ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        // SAFETY: as above; the internal item.
        unsafe { ASN1_item_print(out, v, indent, internal_it(), pctx) }
    }
}

/// `x509_pubkey_decode`: the key, through its type's ASN.1 method (only when legacy decoding is
/// forced; rustyssl has no engines). 1, 0 for a failure, or -1 for a fatal one.
///
/// # Safety
/// `x` is a live structure.
unsafe fn decode_legacy(x: &Pubkey) -> (c_int, *mut EVP_PKEY) {
    if x.flag_force_legacy == 0 {
        return (0, ptr::null_mut());
    }
    // SAFETY: its AlgorithmIdentifier.
    let nid = unsafe { x.algor.as_ref() }.map_or(0, |a| {
        // SAFETY: its object.
        unsafe { OBJ_obj2nid(a.algorithm) }
    });
    // SAFETY: no preconditions.
    let pk = unsafe { EVP_PKEY_new() };
    if pk.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_EVP_LIB, "x509_pubkey_decode");
        return (-1, ptr::null_mut());
    }
    let fail = || {
        // SAFETY: made above.
        unsafe { EVP_PKEY_free(pk) };
        (0, ptr::null_mut())
    };
    // SAFETY: the new key.
    if unsafe { EVP_PKEY_set_type(pk, nid) } == 0 {
        err::raise(
            ERR_LIB_X509,
            X509_R_UNSUPPORTED_ALGORITHM,
            "x509_pubkey_decode",
        );
        return fail();
    }
    // SAFETY: the new key.
    let decode = unsafe { pkey(pk) }
        .and_then(|k| k.ameth_funcs())
        .and_then(|f| f.pub_decode);
    let Some(decode) = decode else {
        err::raise(
            ERR_LIB_X509,
            X509_R_METHOD_NOT_SUPPORTED,
            "x509_pubkey_decode",
        );
        return fail();
    };
    // SAFETY: the method's function with the new key and the structure.
    if unsafe { decode(pk, (&raw const *x).cast()) } == 0 {
        return fail();
    }
    (1, pk)
}

ffi_callback! {
    /// `x509_pubkey_ex_d2i_ex`: the internal SEQUENCE, then (with any errors dropped) the key:
    /// with its ASN.1 method when that's forced, else with a decoder.
    ///
    /// # Safety
    /// As for `ASN1_item_ex_d2i`, with `pval` holding NULL or a live structure.
    pub(crate) unsafe extern "C" fn ex_d2i_ex(pval: *mut *mut ASN1_VALUE, in_: *mut *const c_uchar, len: c_long, it: *const ASN1_ITEM, tag: c_int, aclass: c_int, opt: c_char, ctx: *mut ASN1_TLC, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let in_saved = unsafe { in_.read() };
        // SAFETY: as above.
        if unsafe { pval.read() }.is_null() && unsafe { ex_new_ex(pval, it, libctx, propq) } == 0 {
            return 0;
        }
        // SAFETY: the caller's slot.
        let v = unsafe { pval.read() };
        // SAFETY: the slot's structure.
        let Some(x) = (unsafe { v.cast::<Pubkey>().as_mut() }) else { return 0 };
        if !populate(x) {
            err::raise(ERR_LIB_ASN1, ERR_R_X509_LIB, "x509_pubkey_ex_d2i_ex");
            return 0;
        }
        // SAFETY: the caller's input into the structure, through the internal item.
        let ret = unsafe { ASN1_item_ex_d2i(pval, in_, len, internal_it(), tag, aclass, opt, ctx) };
        if ret <= 0 {
            // SAFETY: the slot (the engine may have freed and emptied it already).
            unsafe { ex_free(pval, it) };
            return ret;
        }
        // SAFETY: as above.
        let publen = unsafe { in_.read() } as usize - in_saved as usize;
        if publen == 0 {
            err::raise(ERR_LIB_ASN1, ERR_R_INTERNAL_ERROR, "x509_pubkey_ex_d2i_ex");
            return 0;
        }
        // SAFETY: the caller's slot.
        let v = unsafe { pval.read() };
        // SAFETY: the slot's structure.
        let Some(x) = (unsafe { v.cast::<Pubkey>().as_mut() }) else { return 0 };
        // SAFETY: its key, or NULL.
        unsafe { EVP_PKEY_free(x.pkey) };
        x.pkey = ptr::null_mut();
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the structure.
        let (r, pk) = unsafe { decode_legacy(x) };
        if r == -1 {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_last_mark() };
            return -1;
        }
        x.pkey = pk;
        if r <= 0 && x.flag_force_legacy == 0 {
            // SAFETY: the structure just decoded from the caller's `publen` octets.
            if !unsafe { decode_with_decoder(x, in_saved, publen, aclass) } {
                return 0;
            }
        }
        // SAFETY: no preconditions.
        unsafe { ERR_pop_to_mark() };
        1
    }
}

/// `x509_pubkey_ex_d2i_ex`'s decoding of the key with the decoders of its algorithm's type
/// (from the SubjectPublicKeyInfo's octets, retagged as a SEQUENCE when implicitly tagged),
/// into the structure. False, with the error mark cleared, when the algorithm has no text or
/// the decoders leave octets over; true otherwise, key or not.
///
/// # Safety
/// `x` is a live structure; `der` holds its `publen` octets as decoded.
unsafe fn decode_with_decoder(
    x: &mut Pubkey,
    der: *const c_uchar,
    publen: usize,
    aclass: c_int,
) -> bool {
    use rustyssl_abi::{
        ASN1_R_DECODE_ERROR, EVP_PKEY_PUBLIC_KEY, V_ASN1_CONSTRUCTED, V_ASN1_SEQUENCE,
        V_ASN1_UNIVERSAL,
    };
    // SAFETY: the caller's guarantee.
    let mut octets = unsafe { core::slice::from_raw_parts(der, publen) }.to_vec();
    if aclass != V_ASN1_UNIVERSAL
        && let Some(first) = octets.first_mut()
    {
        *first = u8::try_from(V_ASN1_CONSTRUCTED | V_ASN1_SEQUENCE).unwrap_or(0x30);
    }
    let mut name = [0 as c_char; 50];
    // SAFETY: its AlgorithmIdentifier.
    let obj = unsafe { x.algor.as_ref() }.map_or(ptr::null(), |a| a.algorithm.cast_const());
    // SAFETY: the object; the buffer's size.
    if unsafe { crate::objects::OBJ_obj2txt(name.as_mut_ptr(), 50, obj, 0) } <= 0 {
        // SAFETY: the caller's mark.
        unsafe { ERR_clear_last_mark() };
        return false;
    }
    // SAFETY: the structure's key slot, live while the context is; static strings; the name;
    // the structure's library context and properties.
    let dctx = unsafe {
        crate::decoder::pkey::OSSL_DECODER_CTX_new_for_pkey(
            &raw mut x.pkey,
            c"DER".as_ptr(),
            c"SubjectPublicKeyInfo".as_ptr(),
            name.as_ptr(),
            EVP_PKEY_PUBLIC_KEY,
            x.libctx,
            x.propq,
        )
    };
    let mut ok = true;
    if !dctx.is_null() {
        let mut p = octets.as_ptr();
        let mut slen = octets.len();
        // SAFETY: the context; the octets.
        if unsafe { crate::decoder::ctx::OSSL_DECODER_from_data(dctx, &raw mut p, &raw mut slen) }
            != 0
            && slen != 0
        {
            // SAFETY: the caller's mark.
            unsafe { ERR_clear_last_mark() };
            err::raise(ERR_LIB_ASN1, ASN1_R_DECODE_ERROR, "x509_pubkey_ex_d2i_ex");
            ok = false;
        }
        // SAFETY: made above.
        unsafe { crate::decoder::ctx::OSSL_DECODER_CTX_free(dctx) };
    }
    ok
}

ffi_export! {
    /// A new SubjectPublicKeyInfo in a library context (`ASN1_item_new_ex`), or NULL.
    ///
    /// # Safety
    /// `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn X509_PUBKEY_new_ex(libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509_PUBKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: no preconditions.
        let it = unsafe { X509_PUBKEY_it() };
        // SAFETY: the item; the caller's guarantee.
        let p: *mut X509_PUBKEY = unsafe { ASN1_item_new_ex(it, libctx, propq) }.cast();
        // SAFETY: just made, or NULL.
        if let Some(x) = unsafe { pubkey_of(p) }
            && !set0_libctx(x, libctx, propq)
        {
            // SAFETY: made above.
            unsafe { X509_PUBKEY_free(p) };
            return ptr::null_mut();
        }
        p
    }
}

ffi_export! {
    /// A copy of a SubjectPublicKeyInfo: its library context, AlgorithmIdentifier, BIT STRING,
    /// and a copy of its key (decoded again through its ASN.1 method if it can't be copied), or
    /// NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live SubjectPublicKeyInfo.
    pub unsafe extern "C" fn X509_PUBKEY_dup(a: *const X509_PUBKEY) -> *mut X509_PUBKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(src) = (unsafe { pubkey_of(a) }) else { return ptr::null_mut() };
        let p = alloc();
        // SAFETY: just made, or NULL.
        let Some(x) = (unsafe { p.as_mut() }) else { return ptr::null_mut() };
        if !set0_libctx(x, src.libctx, src.propq) {
            err::raise(ERR_LIB_X509, ERR_R_X509_LIB, "X509_PUBKEY_dup");
            // SAFETY: made above.
            unsafe { free_struct(p) };
            return ptr::null_mut();
        }
        // SAFETY: the source's AlgorithmIdentifier.
        x.algor = unsafe { X509_ALGOR_dup(src.algor) };
        // SAFETY: no preconditions.
        x.public_key = unsafe { ASN1_BIT_STRING_new() };
        // SAFETY: the source's BIT STRING.
        let bits = unsafe { src.public_key.as_ref() };
        let copied = !x.algor.is_null()
            && !x.public_key.is_null()
            && bits.is_some_and(|b| {
                // SAFETY: the new string; the source's `length` octets.
                (unsafe { ASN1_BIT_STRING_set(x.public_key, b.data, b.length) }) != 0
            });
        if !copied {
            // SAFETY: made above.
            unsafe { free_struct(p) };
            err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, "X509_PUBKEY_dup");
            return ptr::null_mut();
        }
        if !src.pkey.is_null() {
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
            // SAFETY: the source's key.
            x.pkey = unsafe { EVP_PKEY_dup(src.pkey) };
            if x.pkey.is_null() {
                x.flag_force_legacy = 1;
                // SAFETY: the copy.
                let (r, pk) = unsafe { decode_legacy(x) };
                if r <= 0 {
                    // SAFETY: made above.
                    unsafe { free_struct(p) };
                    // SAFETY: no preconditions.
                    unsafe { ERR_clear_last_mark() };
                    return ptr::null_mut();
                }
                x.pkey = pk;
            }
            // SAFETY: no preconditions.
            unsafe { ERR_pop_to_mark() };
        }
        p.cast()
    }
}

ffi_export! {
    /// Sets `*x` to a new SubjectPublicKeyInfo of the key (through its ASN.1 method's
    /// `pub_encode`, or an encoder for a provided key), holding a reference to the key; the
    /// old one is freed. 1, or 0.
    ///
    /// # Safety
    /// `x` is NULL or holds NULL or a live SubjectPublicKeyInfo; `pkey` is NULL or a live key.
    pub unsafe extern "C" fn X509_PUBKEY_set(x: *mut *mut X509_PUBKEY, pkey_: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        const F: &str = "X509_PUBKEY_set";
        if x.is_null() || pkey_.is_null() {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        }
        // SAFETY: the caller's live key.
        let Some(k) = (unsafe { pkey(pkey_) }) else { return 0 };
        let mut pk: *mut X509_PUBKEY = ptr::null_mut();
        let fail = |pk: *mut X509_PUBKEY| {
            // SAFETY: made here, or NULL.
            unsafe { X509_PUBKEY_free(pk) };
            0
        };
        if let Some(f) = k.ameth_funcs() {
            // SAFETY: no preconditions.
            pk = unsafe { X509_PUBKEY_new() };
            if pk.is_null() {
                err::raise(ERR_LIB_X509, ERR_R_ASN1_LIB, F);
                return fail(pk);
            }
            let Some(encode) = f.pub_encode else {
                err::raise(ERR_LIB_X509, X509_R_METHOD_NOT_SUPPORTED, F);
                return fail(pk);
            };
            // SAFETY: the method's function with the new structure and the caller's key.
            if unsafe { encode(pk, pkey_) } == 0 {
                err::raise(ERR_LIB_X509, X509_R_PUBLIC_KEY_ENCODE_ERROR, F);
                return fail(pk);
            }
        } else if k.is_provided() {
            crate::stub::unimplemented("X509_PUBKEY_set of a provided key (an encoder, step 4.7c)");
        }
        if pk.is_null() {
            err::raise(ERR_LIB_X509, X509_R_UNSUPPORTED_ALGORITHM, F);
            return fail(pk);
        }
        // SAFETY: the caller's slot.
        let old = unsafe { x.read() };
        // SAFETY: its old structure, or NULL.
        unsafe { X509_PUBKEY_free(old) };
        // SAFETY: the caller's key.
        if unsafe { EVP_PKEY_up_ref(pkey_) } == 0 {
            err::raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR, F);
            return fail(pk);
        }
        // SAFETY: as above.
        unsafe { x.write(pk) };
        // SAFETY: the new structure.
        if let Some(s) = unsafe { pubkey_of(pk) } {
            // SAFETY: its key, or NULL.
            unsafe { EVP_PKEY_free(s.pkey) };
            s.pkey = pkey_;
        }
        1
    }
}

ffi_export! {
    /// The SubjectPublicKeyInfo's key, or NULL (`EVP_R_DECODE_ERROR` when it has none).
    ///
    /// # Safety
    /// `key` is NULL or a live SubjectPublicKeyInfo.
    pub unsafe extern "C" fn X509_PUBKEY_get0(key: *const X509_PUBKEY) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { pubkey_of(key) }) else {
            err::raise(ERR_LIB_X509, ERR_R_PASSED_NULL_PARAMETER, "X509_PUBKEY_get0");
            return ptr::null_mut();
        };
        if x.pkey.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_DECODE_ERROR, "X509_PUBKEY_get0");
            return ptr::null_mut();
        }
        x.pkey
    }
}

ffi_export! {
    /// As `X509_PUBKEY_get0`, with a reference for the caller.
    ///
    /// # Safety
    /// `key` is NULL or a live SubjectPublicKeyInfo.
    pub unsafe extern "C" fn X509_PUBKEY_get(key: *const X509_PUBKEY) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let ret = unsafe { X509_PUBKEY_get0(key) };
        // SAFETY: its key.
        if !ret.is_null() && unsafe { EVP_PKEY_up_ref(ret) } == 0 {
            err::raise(ERR_LIB_X509, ERR_R_INTERNAL_ERROR, "X509_PUBKEY_get");
            return ptr::null_mut();
        }
        ret
    }
}

ffi_export! {
    /// Sets the key's BIT STRING to `penclen` octets (taken), with no unused bits.
    ///
    /// # Safety
    /// `pub_` is NULL or a live SubjectPublicKeyInfo; `penc` is NULL or `penclen` octets from
    /// the C allocator.
    pub unsafe extern "C" fn X509_PUBKEY_set0_public_key(pub_: *mut X509_PUBKEY, penc: *mut c_uchar, penclen: c_int)
    where failure = (), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { pubkey_of(pub_) }) else { return };
        // SAFETY: its BIT STRING takes the caller's octets.
        unsafe { ASN1_STRING_set0(x.public_key, penc.cast(), penclen) };
        // SAFETY: its BIT STRING.
        if let Some(b) = unsafe { x.public_key.as_mut() } {
            b.flags &= !0x07;
            b.flags |= c_long::from(ASN1_STRING_FLAG_BITS_LEFT);
        }
    }
}

ffi_export! {
    /// Sets the AlgorithmIdentifier's object and parameter (as `X509_ALGOR_set0`, taken) and,
    /// unless `penc` is NULL, the key's octets (taken). 1, or 0.
    ///
    /// # Safety
    /// `pub_` is NULL or a live SubjectPublicKeyInfo; `aobj` and `pval` are what
    /// `X509_ALGOR_set0` takes; `penc` is NULL or `penclen` octets from the C allocator.
    pub unsafe extern "C" fn X509_PUBKEY_set0_param(pub_: *mut X509_PUBKEY, aobj: *mut ASN1_OBJECT, ptype: c_int, pval: *mut c_void, penc: *mut c_uchar, penclen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { pubkey_of(pub_) }) else { return 0 };
        // SAFETY: its AlgorithmIdentifier; the caller's object and value.
        if unsafe { set0(x.algor, aobj, ptype, pval) } == 0 {
            return 0;
        }
        if !penc.is_null() {
            // SAFETY: the caller's guarantee.
            unsafe { X509_PUBKEY_set0_public_key(pub_, penc, penclen) };
        }
        1
    }
}

ffi_export! {
    /// The algorithm's object, the key's octets and their length, and the AlgorithmIdentifier,
    /// each where asked for. 1.
    ///
    /// # Safety
    /// `pub_` is a live SubjectPublicKeyInfo; the out pointers are NULL or writable (`ppklen`
    /// too when `pk` is given).
    pub unsafe extern "C" fn X509_PUBKEY_get0_param(ppkalg: *mut *mut ASN1_OBJECT, pk: *mut *const c_uchar, ppklen: *mut c_int, pa: *mut *mut X509_ALGOR, pub_: *const X509_PUBKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { pubkey_of(pub_) }) else { return 0 };
        if !ppkalg.is_null() {
            // SAFETY: its AlgorithmIdentifier.
            let obj = unsafe { x.algor.as_ref() }.map_or(ptr::null_mut(), |a| a.algorithm);
            // SAFETY: the caller's guarantee.
            unsafe { ppkalg.write(obj) };
        }
        if !pk.is_null() {
            // SAFETY: its BIT STRING.
            let (data, len) = unsafe { x.public_key.as_ref() }.map_or((ptr::null(), 0), |b| (b.data.cast_const(), b.length));
            // SAFETY: the caller's guarantee.
            unsafe { pk.write(data) };
            if !ppklen.is_null() {
                // SAFETY: as above.
                unsafe { ppklen.write(len) };
            }
        }
        if !pa.is_null() {
            // SAFETY: as above.
            unsafe { pa.write(x.algor) };
        }
        1
    }
}

ffi_export! {
    /// 1 if two SubjectPublicKeyInfos are the same object or have equal AlgorithmIdentifiers
    /// and equal keys, 0 if not (or one is NULL), and a negative number for one without a key.
    ///
    /// # Safety
    /// `a` and `b` are NULL or live SubjectPublicKeyInfos.
    pub unsafe extern "C" fn X509_PUBKEY_eq(a: *const X509_PUBKEY, b: *const X509_PUBKEY) -> c_int
    where failure = -2, library = ERR_LIB_X509
    {
        if a == b {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let (Some(x), Some(y)) = (unsafe { pubkey_of(a) }, unsafe { pubkey_of(b) }) else { return 0 };
        if x.algor.is_null() || y.algor.is_null() {
            return -2;
        }
        // SAFETY: their AlgorithmIdentifiers.
        if unsafe { X509_ALGOR_cmp(x.algor, y.algor) } != 0 {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let pa = unsafe { X509_PUBKEY_get0(a) };
        // SAFETY: as above.
        let pb = if pa.is_null() { ptr::null_mut() } else { unsafe { X509_PUBKEY_get0(b) } };
        if pa.is_null() || pb.is_null() {
            return -2;
        }
        // SAFETY: their keys.
        unsafe { EVP_PKEY_eq(pa, pb) }
    }
}

/// `d2i_PUBKEY_int`: a key from a SubjectPublicKeyInfo decoded in a library context (or only
/// through its type's ASN.1 method, `force_legacy`), replacing `*a`; `*pp` moves past it.
///
/// # Safety
/// `pp` holds a pointer to `length` octets; `a` is NULL or holds NULL or a live key; `libctx`
/// is NULL or a live library context; `propq` is NULL or a string.
pub(crate) unsafe fn d2i_pubkey_int(
    a: *mut *mut EVP_PKEY,
    pp: *mut *const c_uchar,
    length: c_long,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    force_legacy: bool,
) -> *mut EVP_PKEY {
    let mut slot: *mut ASN1_VALUE = ptr::null_mut();
    if !libctx.is_null() || !propq.is_null() || force_legacy {
        let p = alloc();
        // SAFETY: just made, or NULL.
        let Some(x) = (unsafe { p.as_mut() }) else {
            return ptr::null_mut();
        };
        if !set0_libctx(x, libctx, propq) {
            // SAFETY: made above.
            unsafe { free_struct(p) };
            return ptr::null_mut();
        }
        x.flag_force_legacy = c_uint::from(force_legacy);
        slot = p.cast();
    }
    // SAFETY: the caller's guarantee.
    let mut q = unsafe { pp.read() };
    // SAFETY: no preconditions.
    let it = unsafe { X509_PUBKEY_it() };
    let pslot = if slot.is_null() {
        ptr::null_mut()
    } else {
        &raw mut slot
    };
    // SAFETY: the structure to decode into, or none; the caller's octets; the item.
    let xpk = unsafe { ASN1_item_d2i(pslot, &raw mut q, length, it) };
    if xpk.is_null() {
        // SAFETY: the engine freed the structure and emptied the slot, or left it.
        unsafe { free_struct(slot.cast()) };
        return ptr::null_mut();
    }
    // SAFETY: the decoded structure.
    let pktmp = unsafe { X509_PUBKEY_get(xpk.cast()) };
    // SAFETY: as above, freed once.
    unsafe { X509_PUBKEY_free(xpk.cast()) };
    if pktmp.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    unsafe { pp.write(q) };
    if !a.is_null() {
        // SAFETY: as above.
        let old = unsafe { a.read() };
        // SAFETY: the caller's old key, or NULL.
        unsafe { EVP_PKEY_free(old) };
        // SAFETY: as above.
        unsafe { a.write(pktmp) };
    }
    pktmp
}

/// `ossl_d2i_PUBKEY_legacy`: `d2i_PUBKEY_int` through the type's ASN.1 method only.
///
/// # Safety
/// `pp` holds a pointer to `length` octets.
pub(crate) unsafe fn d2i_pubkey_legacy(pp: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY {
    // SAFETY: the caller's guarantee.
    unsafe {
        d2i_pubkey_int(
            ptr::null_mut(),
            pp,
            length,
            ptr::null_mut(),
            ptr::null(),
            true,
        )
    }
}

ffi_export! {
    /// A key from a SubjectPublicKeyInfo in a library context, replacing `*a`; `*pp` moves
    /// past it. NULL on failure.
    ///
    /// # Safety
    /// `pp` holds a pointer to `length` octets; `a` is NULL or holds NULL or a live key;
    /// `libctx` is NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn d2i_PUBKEY_ex(a: *mut *mut EVP_PKEY, pp: *mut *const c_uchar, length: c_long, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_pubkey_int(a, pp, length, libctx, propq, false) }
    }
}

ffi_export! {
    /// `d2i_PUBKEY_ex` in the default library context.
    ///
    /// # Safety
    /// As for `d2i_PUBKEY_ex`.
    pub unsafe extern "C" fn d2i_PUBKEY(a: *mut *mut EVP_PKEY, pp: *mut *const c_uchar, length: c_long) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_pubkey_int(a, pp, length, ptr::null_mut(), ptr::null(), false) }
    }
}

ffi_export! {
    /// Reads a key's SubjectPublicKeyInfo from a BIO.
    ///
    /// # Safety
    /// `bp` is a live BIO; `a` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_PUBKEY_bio(bp: *mut BIO, a: *mut *mut EVP_PKEY) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { crate::evp::pkey::d2i::d2i_bio_of(bp, a, d2i_PUBKEY) }
    }
}

ffi_export! {
    /// Reads a key's SubjectPublicKeyInfo from a BIO in a library context.
    ///
    /// # Safety
    /// As for `d2i_PUBKEY_bio`; `libctx` is NULL or a live library context; `propq` is NULL or
    /// a string.
    pub unsafe extern "C" fn d2i_PUBKEY_ex_bio(bp: *mut BIO, a: *mut *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(der) = (unsafe { crate::asn1::tpl::io::read_element_octets(bp) }) else {
            return ptr::null_mut();
        };
        let Ok(len) = c_long::try_from(der.len()) else { return ptr::null_mut() };
        let mut p = der.as_ptr();
        // SAFETY: the element's octets; the caller's guarantee.
        unsafe { d2i_PUBKEY_ex(a, &raw mut p, len, libctx, propq) }
    }
}

ffi_export! {
    /// Reads a key's SubjectPublicKeyInfo from a file.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `a` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_PUBKEY_fp(fp: *mut FILE, a: *mut *mut EVP_PKEY) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let f = |b| {
            // SAFETY: the file's BIO; the caller's guarantee.
            unsafe { crate::evp::pkey::d2i::d2i_bio_of(b, a, d2i_PUBKEY) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { crate::evp::pkey::d2i::with_file(fp, f) }
    }
}

ffi_export! {
    /// Reads a key's SubjectPublicKeyInfo from a file in a library context.
    ///
    /// # Safety
    /// As for `d2i_PUBKEY_fp`; `libctx` is NULL or a live library context; `propq` is NULL or
    /// a string.
    pub unsafe extern "C" fn d2i_PUBKEY_ex_fp(fp: *mut FILE, a: *mut *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_X509
    {
        let f = |b| {
            // SAFETY: the file's BIO; the caller's guarantee.
            unsafe { d2i_PUBKEY_ex_bio(b, a, libctx, propq) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { crate::evp::pkey::d2i::with_file(fp, f) }
    }
}

/// A typed key from a SubjectPublicKeyInfo: the key of a type `accept` takes, made by `get1`
/// (NULL otherwise), replacing `*a` (freed with `free`); `*pp` moves past it.
///
/// # Safety
/// `pp` holds a pointer to `length` octets; `a` is NULL or holds NULL or a live key of the
/// type.
unsafe fn d2i_typed<T>(
    a: *mut *mut T,
    pp: *mut *const c_uchar,
    length: c_long,
    accept: fn(c_int) -> bool,
    get1: unsafe extern "C" fn(*mut EVP_PKEY) -> *mut T,
    free: unsafe extern "C" fn(*mut T),
) -> *mut T {
    // SAFETY: the caller's guarantee.
    let mut q = unsafe { pp.read() };
    // SAFETY: as above.
    let pk = unsafe { d2i_pubkey_legacy(&raw mut q, length) };
    if pk.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the key decoded.
    let key = if accept(unsafe { EVP_PKEY_get_id(pk) }) {
        // SAFETY: as above.
        unsafe { get1(pk) }
    } else {
        ptr::null_mut()
    };
    // SAFETY: made above, freed once.
    unsafe { EVP_PKEY_free(pk) };
    if key.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's guarantee.
    unsafe { pp.write(q) };
    if !a.is_null() {
        // SAFETY: as above.
        let old = unsafe { a.read() };
        // SAFETY: the caller's old key, or NULL.
        unsafe { free(old) };
        // SAFETY: as above.
        unsafe { a.write(key) };
    }
    key
}

/// A typed key's SubjectPublicKeyInfo (`i2d_PUBKEY` of a key assigned the data), or 0 for NULL.
///
/// # Safety
/// `a` is NULL or a live key of `type_`; `pp` is as `i2d_PUBKEY` takes it.
unsafe fn i2d_typed(
    a: *const c_void,
    type_: c_int,
    up_ref: unsafe extern "C" fn(*mut c_void) -> c_int,
    pp: *mut *mut c_uchar,
) -> c_int {
    if a.is_null() {
        return 0;
    }
    // SAFETY: no preconditions.
    let pktmp = unsafe { EVP_PKEY_new() };
    if pktmp.is_null() {
        err::raise(ERR_LIB_ASN1, ERR_R_EVP_LIB, "i2d_PUBKEY");
        return -1;
    }
    // A reference for the temporary key, whose freeing gives it back; OpenSSL's borrows the data.
    // SAFETY: the caller's key.
    unsafe { up_ref(a.cast_mut()) };
    // SAFETY: the new key takes the reference.
    unsafe { EVP_PKEY_assign(pktmp, type_, a.cast_mut()) };
    // SAFETY: the temporary key; the caller's output.
    let ret = unsafe { i2d_PUBKEY(pktmp, pp) };
    // SAFETY: made above.
    unsafe { EVP_PKEY_free(pktmp) };
    ret
}

ffi_export! {
    /// The key's SubjectPublicKeyInfo through its ASN.1 method (an encoder for a provided key):
    /// its length, -1 on failure, 0 for NULL.
    ///
    /// # Safety
    /// `a` is NULL or a live key; `pp` is NULL, or holds NULL (for a new buffer) or room for the
    /// encoding, which it moves past.
    pub unsafe extern "C" fn i2d_PUBKEY(a: *const EVP_PKEY, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(a) }) else { return 0 };
        if let Some(f) = k.ameth_funcs() {
            // SAFETY: no preconditions.
            let xpk = unsafe { X509_PUBKEY_new() };
            if xpk.is_null() {
                return -1;
            }
            let mut ret = -1;
            // SAFETY: the new structure, which the encoding fills.
            if let (Some(encode), Some(x)) = (f.pub_encode, unsafe { pubkey_of(xpk) })
                // SAFETY: the method's function with the structure and the caller's key.
                && unsafe { encode(xpk, a) } != 0
            {
                x.pkey = a.cast_mut();
                // SAFETY: the structure; the caller's output.
                ret = unsafe { i2d_X509_PUBKEY(xpk, pp) };
                x.pkey = ptr::null_mut();
            }
            // SAFETY: made above (its key is the caller's, not freed).
            unsafe { X509_PUBKEY_free(xpk) };
            return ret;
        }
        if k.is_provided() {
            crate::stub::unimplemented("i2d_PUBKEY of a provided key (an encoder, step 4.7c)");
        }
        -1
    }
}

ffi_export! {
    /// Writes the key's SubjectPublicKeyInfo to a BIO. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `pkey` is a live key.
    pub unsafe extern "C" fn i2d_PUBKEY_bio(bp: *mut BIO, pkey_: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the encoder of the type, as OpenSSL's `ASN1_i2d_bio_of` casts it.
        let i2d = unsafe { core::mem::transmute::<I2dPubkey, I2dVoid>(i2d_PUBKEY) };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_i2d_bio(Some(i2d), bp, pkey_.cast()) }
    }
}

ffi_export! {
    /// Writes the key's SubjectPublicKeyInfo to a file. 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live file; `pkey` is a live key.
    pub unsafe extern "C" fn i2d_PUBKEY_fp(fp: *mut FILE, pkey_: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: as above.
        let i2d = unsafe { core::mem::transmute::<I2dPubkey, I2dVoid>(i2d_PUBKEY) };
        // SAFETY: the caller's guarantee.
        unsafe { ASN1_i2d_fp(Some(i2d), fp, pkey_.cast()) }
    }
}

type I2dPubkey = unsafe extern "C" fn(*const EVP_PKEY, *mut *mut c_uchar) -> c_int;
type I2dVoid = unsafe extern "C" fn(*const c_void, *mut *mut c_uchar) -> c_int;
pub(crate) type D2iVoid =
    unsafe extern "C" fn(*mut *mut c_void, *mut *const c_uchar, c_long) -> *mut c_void;

/// The typed functions of one key type: `d2i_`/`i2d_` of its SubjectPublicKeyInfo and their
/// BIO and FILE forms.
macro_rules! typed_pubkey {
    (
        $ty:ty, $id:expr, $accept:expr, $get1:path, $free:path, $new:path, $up_ref:path;
        pub unsafe extern "C" fn $d2i:ident();
        pub unsafe extern "C" fn $i2d:ident();
        pub unsafe extern "C" fn $d2i_bio:ident();
        pub unsafe extern "C" fn $i2d_bio:ident();
        pub unsafe extern "C" fn $d2i_fp:ident();
        pub unsafe extern "C" fn $i2d_fp:ident();
    ) => {
        ffi_export! {
            /// The key of a SubjectPublicKeyInfo of the type, through the type's ASN.1 method,
            /// replacing `*a`; `*pp` moves past it. NULL for a failure or another type.
            ///
            /// # Safety
            /// `pp` holds a pointer to `length` octets; `a` is NULL or holds NULL or a live key.
            pub unsafe extern "C" fn $d2i(a: *mut *mut $ty, pp: *mut *const c_uchar, length: c_long) -> *mut $ty
            where failure = ptr::null_mut(), library = ERR_LIB_X509
            {
                // SAFETY: the caller's guarantee.
                unsafe { d2i_typed(a, pp, length, $accept, $get1, $free) }
            }
        }

        ffi_export! {
            /// The key's SubjectPublicKeyInfo: its length, -1 on failure, 0 for NULL.
            ///
            /// # Safety
            /// `a` is NULL or a live key; `pp` is as `i2d_PUBKEY` takes it.
            pub unsafe extern "C" fn $i2d(a: *const $ty, pp: *mut *mut c_uchar) -> c_int
            where failure = -1, library = ERR_LIB_X509
            {
                /// The type's `up_ref` over an untyped pointer.
                unsafe extern "C" fn up(p: *mut c_void) -> c_int {
                    // SAFETY: the caller's live key of the type.
                    unsafe { $up_ref(p.cast()) }
                }
                // SAFETY: the caller's guarantee.
                unsafe { i2d_typed(a.cast(), $id, up, pp) }
            }
        }

        ffi_export! {
            /// Reads a key's SubjectPublicKeyInfo from a BIO.
            ///
            /// # Safety
            /// `bp` is a live BIO; `a` is NULL or holds NULL or a live key.
            pub unsafe extern "C" fn $d2i_bio(bp: *mut BIO, a: *mut *mut $ty) -> *mut $ty
            where failure = ptr::null_mut(), library = ERR_LIB_X509
            {
                /// The type's constructor over an untyped pointer.
                unsafe extern "C" fn make() -> *mut c_void {
                    // SAFETY: no preconditions.
                    unsafe { $new() }.cast()
                }
                // SAFETY: the type's decoder, as OpenSSL's `ASN1_d2i_bio_of` casts it.
                let d2i = unsafe { core::mem::transmute::<unsafe extern "C" fn(*mut *mut $ty, *mut *const c_uchar, c_long) -> *mut $ty, D2iVoid>($d2i) };
                // SAFETY: the caller's guarantee.
                unsafe { ASN1_d2i_bio(Some(make), Some(d2i), bp, a.cast()) }.cast()
            }
        }

        ffi_export! {
            /// Writes a key's SubjectPublicKeyInfo to a BIO. 1, or 0.
            ///
            /// # Safety
            /// `bp` is a live BIO; `a` is a live key.
            pub unsafe extern "C" fn $i2d_bio(bp: *mut BIO, a: *const $ty) -> c_int
            where failure = 0, library = ERR_LIB_X509
            {
                // SAFETY: the type's encoder, as OpenSSL's `ASN1_i2d_bio_of` casts it.
                let i2d = unsafe { core::mem::transmute::<unsafe extern "C" fn(*const $ty, *mut *mut c_uchar) -> c_int, I2dVoid>($i2d) };
                // SAFETY: the caller's guarantee.
                unsafe { ASN1_i2d_bio(Some(i2d), bp, a.cast()) }
            }
        }

        ffi_export! {
            /// Reads a key's SubjectPublicKeyInfo from a file.
            ///
            /// # Safety
            /// `fp` is a live file; `a` is NULL or holds NULL or a live key.
            pub unsafe extern "C" fn $d2i_fp(fp: *mut FILE, a: *mut *mut $ty) -> *mut $ty
            where failure = ptr::null_mut(), library = ERR_LIB_X509
            {
                /// The type's constructor over an untyped pointer.
                unsafe extern "C" fn make() -> *mut c_void {
                    // SAFETY: no preconditions.
                    unsafe { $new() }.cast()
                }
                // SAFETY: as for the BIO form.
                let d2i = unsafe { core::mem::transmute::<unsafe extern "C" fn(*mut *mut $ty, *mut *const c_uchar, c_long) -> *mut $ty, D2iVoid>($d2i) };
                // SAFETY: the caller's guarantee.
                unsafe { ASN1_d2i_fp(Some(make), Some(d2i), fp, a.cast()) }.cast()
            }
        }

        ffi_export! {
            /// Writes a key's SubjectPublicKeyInfo to a file. 1, or 0.
            ///
            /// # Safety
            /// `fp` is a live file; `a` is a live key.
            pub unsafe extern "C" fn $i2d_fp(fp: *mut FILE, a: *const $ty) -> c_int
            where failure = 0, library = ERR_LIB_X509
            {
                // SAFETY: as for the BIO form.
                let i2d = unsafe { core::mem::transmute::<unsafe extern "C" fn(*const $ty, *mut *mut c_uchar) -> c_int, I2dVoid>($i2d) };
                // SAFETY: the caller's guarantee.
                unsafe { ASN1_i2d_fp(Some(i2d), fp, a.cast()) }
            }
        }
    };
}

typed_pubkey! {
    RSA, EVP_PKEY_RSA, |_| true, EVP_PKEY_get1_RSA, RSA_free, RSA_new, crate::rsa_lib::RSA_up_ref;
    pub unsafe extern "C" fn d2i_RSA_PUBKEY();
    pub unsafe extern "C" fn i2d_RSA_PUBKEY();
    pub unsafe extern "C" fn d2i_RSA_PUBKEY_bio();
    pub unsafe extern "C" fn i2d_RSA_PUBKEY_bio();
    pub unsafe extern "C" fn d2i_RSA_PUBKEY_fp();
    pub unsafe extern "C" fn i2d_RSA_PUBKEY_fp();
}

typed_pubkey! {
    DSA, EVP_PKEY_DSA, |_| true, EVP_PKEY_get1_DSA, DSA_free, DSA_new, crate::dsa::DSA_up_ref;
    pub unsafe extern "C" fn d2i_DSA_PUBKEY();
    pub unsafe extern "C" fn i2d_DSA_PUBKEY();
    pub unsafe extern "C" fn d2i_DSA_PUBKEY_bio();
    pub unsafe extern "C" fn i2d_DSA_PUBKEY_bio();
    pub unsafe extern "C" fn d2i_DSA_PUBKEY_fp();
    pub unsafe extern "C" fn i2d_DSA_PUBKEY_fp();
}

typed_pubkey! {
    EC_KEY, EVP_PKEY_EC, |t| t == EVP_PKEY_EC || t == EVP_PKEY_SM2, EVP_PKEY_get1_EC_KEY,
    EC_KEY_free, EC_KEY_new, crate::ec::key::EC_KEY_up_ref;
    pub unsafe extern "C" fn d2i_EC_PUBKEY();
    pub unsafe extern "C" fn i2d_EC_PUBKEY();
    pub unsafe extern "C" fn d2i_EC_PUBKEY_bio();
    pub unsafe extern "C" fn i2d_EC_PUBKEY_bio();
    pub unsafe extern "C" fn d2i_EC_PUBKEY_fp();
    pub unsafe extern "C" fn i2d_EC_PUBKEY_fp();
}

/// `ossl_x509_PUBKEY_get0_libctx`: the structure's library context and query.
///
/// # Safety
/// `key` is a live structure.
pub(crate) unsafe fn libctx_of(key: *const X509_PUBKEY) -> (*mut OSSL_LIB_CTX, *const c_char) {
    // SAFETY: the caller's guarantee.
    unsafe { pubkey_of(key) }.map_or((ptr::null_mut(), ptr::null()), |x| {
        (x.libctx, x.propq.cast_const())
    })
}

/// The octets and length of an AlgorithmIdentifier's SEQUENCE parameter (an `ASN1_STRING`).
///
/// # Safety
/// `pval` is a live `ASN1_STRING`.
pub(crate) unsafe fn sequence_octets(pval: *const c_void) -> (*const c_uchar, c_long) {
    // SAFETY: the caller's guarantee.
    let s = unsafe { &*pval.cast::<rustyssl_abi::ASN1_STRING>() };
    (s.data.cast_const(), c_long::from(s.length))
}

/// Why `int_decode` failed.
pub(crate) enum IntError {
    /// The octets aren't an INTEGER.
    Decode,
    /// It isn't a number.
    Bn,
}

/// A key's INTEGER (a DSA or DH public or private key) as a new number.
///
/// # Safety
/// `p` holds `len` octets.
pub(crate) unsafe fn int_decode(
    p: *const c_uchar,
    len: c_long,
    secure: bool,
) -> Result<*mut rustyssl_abi::BIGNUM, IntError> {
    let mut q = p;
    // SAFETY: the caller's guarantee.
    let ai = unsafe { crate::asn1::tpl::items::d2i_ASN1_INTEGER(ptr::null_mut(), &raw mut q, len) };
    if ai.is_null() {
        return Err(IntError::Decode);
    }
    let into = if secure {
        // SAFETY: no preconditions.
        unsafe { crate::bn::BN_secure_new() }
    } else {
        ptr::null_mut()
    };
    // SAFETY: the INTEGER; the secure number, or NULL for a new one.
    let bn = unsafe { crate::bn::conv::ASN1_INTEGER_to_BN(ai, into) };
    // SAFETY: decoded above, wiped and freed once.
    unsafe { crate::asn1::string::ASN1_STRING_clear_free(ai) };
    if bn.is_null() {
        // SAFETY: made above, or NULL.
        unsafe { crate::bn::BN_clear_free(into) };
        return Err(IntError::Bn);
    }
    Ok(bn)
}

/// A number's DER INTEGER, in a new buffer from the C allocator: its octets and length, or
/// `None` (with the INTEGER that couldn't be made or encoded named by the `bool`: true when
/// the number couldn't become an INTEGER).
///
/// # Safety
/// `bn` is a live number.
pub(crate) unsafe fn int_encode(
    bn: *const rustyssl_abi::BIGNUM,
) -> Result<(*mut c_uchar, c_int), bool> {
    // SAFETY: the caller's guarantee; a new INTEGER.
    let ai = unsafe { crate::bn::conv::BN_to_ASN1_INTEGER(bn, ptr::null_mut()) };
    if ai.is_null() {
        return Err(true);
    }
    let mut penc = ptr::null_mut();
    // SAFETY: the INTEGER; a place for a new encoding.
    let n = unsafe { crate::asn1::tpl::items::i2d_ASN1_INTEGER(ai, &raw mut penc) };
    // SAFETY: made above, wiped and freed once.
    unsafe { crate::asn1::string::ASN1_STRING_clear_free(ai) };
    if n <= 0 {
        return Err(false);
    }
    Ok((penc, n))
}

/// A new SEQUENCE parameter (an `ASN1_STRING` of `type_`) holding what `i2d` writes, or `None`
/// (any string made freed).
///
/// # Safety
/// `i2d` writes a new buffer from the C allocator through its argument, returning its length.
pub(crate) unsafe fn sequence_param(
    type_: c_int,
    i2d: impl FnOnce(*mut *mut c_uchar) -> c_int,
) -> Option<*mut rustyssl_abi::ASN1_STRING> {
    // SAFETY: no preconditions.
    let s = unsafe { crate::asn1::string::ASN1_STRING_new() };
    // SAFETY: just made, or NULL.
    let st = unsafe { s.as_mut() }?;
    let mut data = ptr::null_mut();
    let n = i2d(&raw mut data);
    if n <= 0 {
        // SAFETY: made above.
        unsafe { crate::asn1::string::ASN1_STRING_free(s) };
        return None;
    }
    st.data = data;
    st.length = n;
    st.type_ = type_;
    Some(s)
}

/// `ossl_d2i_X509_PUBKEY_INTERNAL`: a SubjectPublicKeyInfo decoded without its key (through the
/// internal SEQUENCE), or NULL; free it with `free_internal`.
///
/// # Safety
/// `pp` holds a pointer to `len` octets.
pub(crate) unsafe fn d2i_internal(pp: *mut *const c_uchar, len: c_long) -> *mut X509_PUBKEY {
    let p = alloc();
    if p.is_null() {
        return ptr::null_mut();
    }
    let mut slot: *mut ASN1_VALUE = p.cast();
    // SAFETY: the structure to decode into; the caller's octets; the internal item.
    let r = unsafe { ASN1_item_d2i(&raw mut slot, pp, len, internal_it()) };
    if r.is_null() {
        // SAFETY: the engine freed the structure and emptied the slot, or left it.
        unsafe { free_struct(slot.cast()) };
    }
    r.cast()
}

/// `ossl_X509_PUBKEY_INTERNAL_free`.
///
/// # Safety
/// `x` is NULL or from `d2i_internal`.
pub(crate) unsafe fn free_internal(x: *mut X509_PUBKEY) {
    // SAFETY: the caller's guarantee; its key is NULL.
    unsafe { free_struct(x.cast()) };
}

/// The NID of a SubjectPublicKeyInfo's algorithm (`NID_undef` for NULL).
///
/// # Safety
/// `x` is NULL or a live structure.
pub(crate) unsafe fn algorithm_nid(x: *const X509_PUBKEY) -> c_int {
    // SAFETY: the caller's guarantee.
    let algor = unsafe { x.cast::<Pubkey>().as_ref() }.map_or(ptr::null_mut(), |p| p.algor);
    // SAFETY: its AlgorithmIdentifier, or NULL.
    unsafe { algor.as_ref() }.map_or(0, |a| {
        // SAFETY: its object.
        unsafe { OBJ_obj2nid(a.algorithm) }
    })
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use rustyssl_abi::{EVP_PKEY_X25519, NID_X25519, V_ASN1_UNDEF};

    use super::*;
    use crate::evp::pkey::ecx::{ecx_pub_decode, ecx_pub_encode};
    use crate::objects::OBJ_nid2obj;

    /// docs/DEVIATIONS.md: NULL where OpenSSL dereferences it fails or does nothing.
    #[test]
    fn null_arguments_are_safe() {
        // SAFETY: NULL where OpenSSL dereferences it (here and below).
        assert!(unsafe { X509_PUBKEY_dup(ptr::null()) }.is_null());
        let none = ptr::null_mut();
        // SAFETY: as above.
        let r = unsafe {
            X509_PUBKEY_get0_param(
                none,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe {
            X509_PUBKEY_set0_param(
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
            )
        };
        assert_eq!(r, 0);
        // SAFETY: as above.
        unsafe { X509_PUBKEY_set0_public_key(ptr::null_mut(), ptr::null_mut(), 0) };
        // A key's octets without a place for their length: only the octets are written.
        // SAFETY: no preconditions.
        let x = unsafe { X509_PUBKEY_new() };
        let mut pk: *const c_uchar = ptr::dangling();
        // SAFETY: a live structure; a local; NULL for the length.
        let r = unsafe {
            X509_PUBKEY_get0_param(none, &raw mut pk, ptr::null_mut(), ptr::null_mut(), x)
        };
        assert_eq!(r, 1);
        // SAFETY: made above.
        unsafe { X509_PUBKEY_free(x) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }

    /// An X25519 key's SubjectPublicKeyInfo through the legacy method (no API reaches a legacy
    /// ECX key until the decoders).
    #[test]
    #[cfg_attr(miri, ignore = "X25519 arithmetic is slow under Miri")]
    fn ecx_public_keys_round_trip() {
        let raw: [u8; 32] = core::array::from_fn(|i| u8::try_from(i).unwrap_or(0) + 1);
        // SAFETY: no preconditions.
        let x = unsafe { X509_PUBKEY_new() };
        let penc: *mut c_uchar = mem::alloc(32).cast();
        // SAFETY: a block of 32 octets.
        unsafe { ptr::copy_nonoverlapping(raw.as_ptr(), penc, 32) };
        // SAFETY: no preconditions.
        let obj = unsafe { OBJ_nid2obj(NID_X25519) };
        // SAFETY: the structure takes the object and octets.
        let r = unsafe { X509_PUBKEY_set0_param(x, obj, V_ASN1_UNDEF, ptr::null_mut(), penc, 32) };
        assert_eq!(r, 1);
        // SAFETY: no preconditions.
        let k = unsafe { EVP_PKEY_new() };
        // SAFETY: the new key.
        assert_eq!(unsafe { EVP_PKEY_set_type(k, EVP_PKEY_X25519) }, 1);
        // SAFETY: the key; the structure.
        assert_eq!(unsafe { ecx_pub_decode(k, x) }, 1);
        // SAFETY: no preconditions.
        let y = unsafe { X509_PUBKEY_new() };
        // SAFETY: the new structure; the key.
        assert_eq!(unsafe { ecx_pub_encode(y, k) }, 1);
        let (mut p, mut n) = (ptr::null(), 0);
        // SAFETY: the structure; locals.
        unsafe {
            X509_PUBKEY_get0_param(ptr::null_mut(), &raw mut p, &raw mut n, ptr::null_mut(), y)
        };
        // SAFETY: its `n` octets.
        let got = unsafe { core::slice::from_raw_parts(p, usize::try_from(n).unwrap_or(0)) };
        assert_eq!(got, &raw);
        // A key of the wrong length is refused.
        let short: *mut c_uchar = mem::alloc(31).cast();
        // SAFETY: the structure takes the octets (31 of the 32 written above's length).
        unsafe { X509_PUBKEY_set0_public_key(x, short, 31) };
        // SAFETY: a new key of the type.
        let k2 = unsafe { EVP_PKEY_new() };
        // SAFETY: as above.
        unsafe { EVP_PKEY_set_type(k2, EVP_PKEY_X25519) };
        // SAFETY: the key; the structure.
        assert_eq!(unsafe { ecx_pub_decode(k2, x) }, 0);
        // SAFETY: made above, freed once each.
        unsafe {
            X509_PUBKEY_free(x);
        }
        // SAFETY: as above.
        unsafe { X509_PUBKEY_free(y) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k2) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
