//! An EC key's encodings and printing (`ec_asn1.c`, `ec_ameth.c`, `eck_prn.c`, `x_all.c`):
//! SEC 1's `ECPrivateKey` (OpenSSL's private `EC_PRIVATEKEY` item) and its BIO and FILE
//! forms, `ECParameters`, the public key's octets (`o2i`/`i2o_ECPublicKey`), and
//! `EC_KEY_print` and `ECParameters_print`. Each goes through the key, group, and point
//! functions in OpenSSL's order, so the errors are the reference's.

use core::ffi::{c_int, c_long, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_ITEM, ASN1_OCTET_STRING, ASN1_STRING_FLAG_BITS_LEFT, ASN1_TFLG_EMBED,
    ASN1_TFLG_EXPLICIT, ASN1_TFLG_OPTIONAL, BIO, BIO_NOCLOSE, EC_FLAG_SM2_RANGE, EC_KEY,
    EC_PKEY_NO_PARAMETERS, EC_PKEY_NO_PUBKEY, EC_R_MISSING_PRIVATE_KEY, ERR_LIB_EC, ERR_R_ASN1_LIB,
    ERR_R_BIO_LIB, ERR_R_EC_LIB, ERR_R_PASSED_NULL_PARAMETER, NID_sm2,
};

use super::asn1::{
    EC_GROUP_get_ecpkparameters, EC_GROUP_new_from_ecpkparameters, ECPKPARAMETERS_it,
    ECPKParameters_print, PkParams, TYPE_EXPLICIT, d2i_ECPKParameters, i2d_ECPKParameters,
};
use super::group::{
    EC_GROUP_free, EC_GROUP_get_curve_name, EC_GROUP_order_bits, set_decoded_from_explicit,
};
use super::key::{
    EC_KEY_get_conv_form, EC_KEY_get0_group, EC_KEY_get0_private_key, EC_KEY_get0_public_key,
    EC_KEY_key2buf, EC_KEY_new, EC_KEY_oct2key, EC_KEY_oct2priv, EC_KEY_priv2buf, EC_KEY_set_flags,
    free, key,
};
use super::point::{EC_POINT_clear_free, EC_POINT_mul, EC_POINT_new, EC_POINT_point2oct};
use crate::asn1::hex::ASN1_buf_print;
use crate::asn1::string::{ASN1_BIT_STRING_new, ASN1_STRING_set0};
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::ints::INT32_it;
use crate::asn1::tpl::io::{ASN1_d2i_bio, ASN1_d2i_fp, ASN1_i2d_bio, ASN1_i2d_fp};
use crate::asn1::tpl::items::{ASN1_BIT_STRING_it, ASN1_OCTET_STRING_it};
use crate::asn1::tpl::new::ASN1_item_new;
use crate::asn1::tpl::statics::{Templates, sequence};
use crate::asn1::tpl::{Item, template_at};
use crate::bio::print::BIO_printf;
use crate::bio::{BIO_free, BIO_indent};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::provider::Ptr;

/// The encoding flags, as the key holds them.
const NO_PARAMETERS: u32 = EC_PKEY_NO_PARAMETERS.cast_unsigned();
const NO_PUBKEY: u32 = EC_PKEY_NO_PUBKEY.cast_unsigned();

/// Raises an EC error from `func`.
fn raise(reason: c_int, func: &'static str) {
    err::raise(ERR_LIB_EC, reason, func);
}

/// `EC_PRIVATEKEY`: SEC 1's ECPrivateKey.
#[repr(C)]
struct PrivateKey {
    version: i32,
    private_key: *mut ASN1_OCTET_STRING,
    parameters: *mut PkParams,
    public_key: *mut ASN1_BIT_STRING,
}

/// `ECPKPARAMETERS_it` as a template's item.
unsafe extern "C" fn pk_it() -> *const ASN1_ITEM {
    // SAFETY: no preconditions.
    unsafe { ECPKPARAMETERS_it() }
}

static PRIVATE_KEY_TT: Templates<4> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(PrivateKey, version),
        c"version",
        INT32_it,
    ),
    template_at(
        0,
        0,
        offset_of!(PrivateKey, private_key),
        c"privateKey",
        ASN1_OCTET_STRING_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(PrivateKey, parameters),
        c"parameters",
        pk_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(PrivateKey, public_key),
        c"publicKey",
        ASN1_BIT_STRING_it,
    ),
]);
static PRIVATE_KEY: Item = sequence::<PrivateKey, 4>(&PRIVATE_KEY_TT, None, c"EC_PRIVATEKEY");

/// The item.
fn private_key_it() -> *const ASN1_ITEM {
    &raw const PRIVATE_KEY.0
}

ffi_export! {
    /// Decodes SEC 1's ECPrivateKey into a key (the one at `*a` if given, which must have the
    /// group when the encoding has no parameters), computing the public key if it's absent
    /// (and remembering that with `NO_PUBKEY`). Advances `*in` past it.
    ///
    /// # Safety
    /// `a` is NULL or holds NULL or a live key; `in` holds `len` readable octets.
    pub unsafe extern "C" fn d2i_ECPrivateKey(a: *mut *mut EC_KEY, r#in: *mut *const c_uchar, len: c_long) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        const F: &str = "d2i_ECPrivateKey";
        if r#in.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee.
        let mut p = unsafe { *r#in };
        // SAFETY: as above; the item.
        let pk: *mut PrivateKey = unsafe { ASN1_item_d2i(ptr::null_mut(), &raw mut p, len, private_key_it()) }.cast();
        if pk.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the structure just decoded.
        let s = unsafe { &*pk };
        // SAFETY: NULL or the caller's pointer.
        let given = if a.is_null() { ptr::null_mut() } else { unsafe { *a } };
        let ret = if given.is_null() {
            // SAFETY: no preconditions.
            let r = unsafe { EC_KEY_new() };
            if r.is_null() {
                raise(ERR_R_EC_LIB, F);
            }
            r
        } else {
            given
        };
        let ok = (|| {
            // SAFETY: a live key.
            let Some(k) = (unsafe { key(ret) }) else { return false };
            if !s.parameters.is_null() {
                let old = k.update(|f| core::mem::replace(&mut f.group, Ptr(ptr::null_mut())));
                // SAFETY: the key's old group, freed once.
                unsafe { EC_GROUP_free(old.0) };
                // SAFETY: the decoded parameters.
                let g = unsafe { EC_GROUP_new_from_ecpkparameters(s.parameters.cast()) };
                k.update(|f| f.group = Ptr(g));
                // SAFETY: as above.
                if !g.is_null() && unsafe { (*s.parameters).kind } == TYPE_EXPLICIT {
                    // SAFETY: the new group.
                    unsafe { set_decoded_from_explicit(g, true) };
                }
            }
            let g = k.get().group.0;
            if g.is_null() {
                raise(ERR_R_EC_LIB, F);
                return false;
            }
            k.update(|f| f.version = s.version);
            if s.private_key.is_null() {
                raise(EC_R_MISSING_PRIVATE_KEY, F);
                return false;
            }
            // SAFETY: the decoded string.
            let pkey = unsafe { &*s.private_key };
            let n = usize::try_from(pkey.length).unwrap_or(0);
            // SAFETY: the key; the string's octets.
            if unsafe { EC_KEY_oct2priv(ret, pkey.data, n) } == 0 {
                return false;
            }
            // SAFETY: the key's group.
            if unsafe { EC_GROUP_get_curve_name(g) } == NID_sm2 {
                // SAFETY: the key.
                unsafe { EC_KEY_set_flags(ret, EC_FLAG_SM2_RANGE) };
            }
            let old = k.update(|f| core::mem::replace(&mut f.pub_key, Ptr(ptr::null_mut())));
            // SAFETY: the key's old point, freed once.
            unsafe { EC_POINT_clear_free(old.0) };
            // SAFETY: the group.
            let pt = unsafe { EC_POINT_new(g) };
            if pt.is_null() {
                raise(ERR_R_EC_LIB, F);
                return false;
            }
            k.update(|f| f.pub_key = Ptr(pt));
            if s.public_key.is_null() {
                // `ossl_ec_key_simple_generate_public_key`.
                let f = k.get();
                // SAFETY: the key's context.
                let ctx = unsafe { BN_CTX_new_ex(f.libctx.0) };
                if ctx.is_null() {
                    return false;
                }
                // SAFETY: the key's objects; the context.
                let r = unsafe { EC_POINT_mul(g, pt, f.priv_key.0, ptr::null(), ptr::null(), ctx) };
                // SAFETY: made above.
                unsafe { BN_CTX_free(ctx) };
                if r != 1 {
                    return false;
                }
                k.touch();
                k.update(|f| f.enc_flag |= NO_PUBKEY);
            } else {
                // SAFETY: the decoded string.
                let pubs = unsafe { &*s.public_key };
                let n = usize::try_from(pubs.length).unwrap_or(0);
                // SAFETY: the key; the string's octets.
                if unsafe { EC_KEY_oct2key(ret, pubs.data, n, ptr::null_mut()) } == 0 {
                    raise(ERR_R_EC_LIB, F);
                    return false;
                }
            }
            k.touch();
            true
        })();
        // SAFETY: the structure decoded above.
        unsafe { ASN1_item_free(pk.cast(), private_key_it()) };
        if !ok {
            if given.is_null() {
                // SAFETY: the key made above.
                unsafe { free(ret) };
            }
            return ptr::null_mut();
        }
        if !a.is_null() {
            // SAFETY: the caller's pointer.
            unsafe { *a = ret };
        }
        // SAFETY: as above.
        unsafe { *r#in = p };
        ret
    }
}

/// `ossl_asn1_string_set_bits_left(s, 0)`.
///
/// # Safety
/// `s` is a live string.
unsafe fn no_bits_left(s: *mut ASN1_BIT_STRING) {
    // SAFETY: the caller's guarantee.
    let st = unsafe { &mut *s };
    st.flags &= !0x07;
    st.flags |= c_long::from(ASN1_STRING_FLAG_BITS_LEFT);
}

ffi_export! {
    /// Encodes the key as SEC 1's ECPrivateKey (without the parameters or the public key as
    /// its encoding flags say), `i2d` conventions; 0 on failure.
    ///
    /// # Safety
    /// `a` is NULL or a live key; `out` is NULL or holds NULL or room for the encoding.
    pub unsafe extern "C" fn i2d_ECPrivateKey(a: *const EC_KEY, out: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "i2d_ECPrivateKey";
        // SAFETY: the caller's guarantee.
        let f = unsafe { key(a) }.map(super::key::EcKey::get);
        let Some(f) = f.filter(|f| {
            !f.group.0.is_null() && (f.enc_flag & NO_PUBKEY != 0 || !f.pub_key.0.is_null())
        }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        // SAFETY: the item.
        let pk: *mut PrivateKey = unsafe { ASN1_item_new(private_key_it()) }.cast();
        if pk.is_null() {
            raise(ERR_R_EC_LIB, F);
            return 0;
        }
        let mut priv_buf: *mut c_uchar = ptr::null_mut();
        let mut priv_len = 0;
        let mut pub_buf: *mut c_uchar = ptr::null_mut();
        let ret = (|| {
            // SAFETY: the structure made above.
            let s = unsafe { &mut *pk };
            s.version = f.version;
            // SAFETY: the caller's key; a local.
            priv_len = unsafe { EC_KEY_priv2buf(a, &raw mut priv_buf) };
            if priv_len == 0 {
                raise(ERR_R_EC_LIB, F);
                return 0;
            }
            let Ok(n) = c_int::try_from(priv_len) else { return 0 };
            // SAFETY: the structure's string, taking the octets.
            unsafe { ASN1_STRING_set0(s.private_key, priv_buf.cast(), n) };
            priv_buf = ptr::null_mut();
            if f.enc_flag & NO_PARAMETERS == 0 {
                // SAFETY: the key's group; the structure's field, NULL.
                s.parameters = unsafe { EC_GROUP_get_ecpkparameters(f.group.0, s.parameters.cast()) }.cast();
                if s.parameters.is_null() {
                    raise(ERR_R_EC_LIB, F);
                    return 0;
                }
            }
            if f.enc_flag & NO_PUBKEY == 0 {
                // SAFETY: no preconditions.
                s.public_key = unsafe { ASN1_BIT_STRING_new() };
                if s.public_key.is_null() {
                    raise(ERR_R_ASN1_LIB, F);
                    return 0;
                }
                // SAFETY: the caller's key; a local.
                let publen = unsafe { EC_KEY_key2buf(a, f.conv_form, &raw mut pub_buf, ptr::null_mut()) };
                if publen == 0 {
                    raise(ERR_R_EC_LIB, F);
                    return 0;
                }
                // SAFETY: the structure's string.
                unsafe { no_bits_left(s.public_key) };
                let Ok(n) = c_int::try_from(publen) else { return 0 };
                // SAFETY: as above, taking the octets.
                unsafe { ASN1_STRING_set0(s.public_key, pub_buf.cast(), n) };
                pub_buf = ptr::null_mut();
            }
            // SAFETY: the structure; the caller's buffer.
            let r = unsafe { ASN1_item_i2d(pk.cast(), out, private_key_it()) };
            if r == 0 {
                raise(ERR_R_EC_LIB, F);
            }
            r
        })();
        // SAFETY: NULL or octets not taken by the structure.
        unsafe { mem::release_clean(priv_buf.cast(), priv_len) };
        // SAFETY: as above.
        unsafe { mem::release(pub_buf.cast()) };
        // SAFETY: the structure made above.
        unsafe { ASN1_item_free(pk.cast(), private_key_it()) };
        ret
    }
}

ffi_export! {
    /// Encodes the key's group as ECPKParameters; 0 on failure.
    ///
    /// # Safety
    /// `a` is NULL or a live key; `out` as for `i2d_ECPKParameters`.
    pub unsafe extern "C" fn i2d_ECParameters(a: *const EC_KEY, out: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(a) }) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, "i2d_ECParameters");
            return 0;
        };
        // SAFETY: the key's group; the caller's buffer.
        unsafe { i2d_ECPKParameters(k.get().group.0, out) }
    }
}

ffi_export! {
    /// Decodes ECPKParameters as the group of a key (the one at `*a` if given).
    ///
    /// # Safety
    /// `a` is NULL or holds NULL or a live key; `in` holds `len` readable octets.
    pub unsafe extern "C" fn d2i_ECParameters(a: *mut *mut EC_KEY, r#in: *mut *const c_uchar, len: c_long) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        const F: &str = "d2i_ECParameters";
        // SAFETY: the caller's guarantee.
        if r#in.is_null() || unsafe { *r#in }.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        // SAFETY: as above.
        let given = if a.is_null() { ptr::null_mut() } else { unsafe { *a } };
        let ret = if given.is_null() {
            // SAFETY: no preconditions.
            let r = unsafe { EC_KEY_new() };
            if r.is_null() {
                raise(ERR_R_EC_LIB, F);
                return ptr::null_mut();
            }
            r
        } else {
            given
        };
        // SAFETY: a live key.
        let Some(k) = (unsafe { key(ret) }) else { return ptr::null_mut() };
        let mut g = k.get().group.0;
        // SAFETY: the key's group pointer, replaced on success; the caller's octets.
        let decoded = unsafe { d2i_ECPKParameters(&raw mut g, r#in, len) };
        k.update(|f| f.group = Ptr(g));
        if decoded.is_null() {
            if given.is_null() {
                // SAFETY: the key made above.
                unsafe { free(ret) };
            } else {
                k.touch();
            }
            return ptr::null_mut();
        }
        // SAFETY: the new group.
        if unsafe { EC_GROUP_get_curve_name(g) } == NID_sm2 {
            // SAFETY: the key.
            unsafe { EC_KEY_set_flags(ret, EC_FLAG_SM2_RANGE) };
        }
        k.touch();
        if !a.is_null() {
            // SAFETY: the caller's pointer.
            unsafe { *a = ret };
        }
        ret
    }
}

ffi_export! {
    /// Sets the public key of `*a` (which must have a group) from its octets, and advances
    /// `*in` by `len`.
    ///
    /// # Safety
    /// `a` is NULL or holds NULL or a live key; `in` holds `len` readable octets.
    pub unsafe extern "C" fn o2i_ECPublicKey(a: *mut *mut EC_KEY, r#in: *mut *const c_uchar, len: c_long) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        const F: &str = "o2i_ECPublicKey";
        // SAFETY: the caller's guarantee.
        let ret = if a.is_null() { ptr::null_mut() } else { unsafe { *a } };
        // SAFETY: as above.
        if unsafe { key(ret) }.is_none_or(|k| k.get().group.0.is_null()) || r#in.is_null() {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        }
        // A negative length is OpenSSL's huge `size_t`, which no encoding has.
        let n = usize::try_from(len).unwrap_or(usize::MAX);
        // SAFETY: the caller's pointer.
        let start = unsafe { *r#in };
        // SAFETY: the key; the caller's octets.
        if unsafe { EC_KEY_oct2key(ret, start, n, ptr::null_mut()) } == 0 {
            raise(ERR_R_EC_LIB, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's pointer, past the octets.
        unsafe { *r#in = start.wrapping_add(n) };
        ret
    }
}

ffi_export! {
    /// The public key's octets in the key's form: their length (for NULL `out`), into a new
    /// buffer at `*out` if it's NULL, or into `*out`, advancing it. 0 on failure.
    ///
    /// # Safety
    /// `a` is NULL or a live key; `out` is NULL or holds NULL or room for the octets.
    pub unsafe extern "C" fn i2o_ECPublicKey(a: *const EC_KEY, out: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        const F: &str = "i2o_ECPublicKey";
        // SAFETY: the caller's guarantee.
        let f = unsafe { key(a) }.map(super::key::EcKey::get);
        let Some(f) = f.filter(|f| !f.pub_key.0.is_null()) else {
            raise(ERR_R_PASSED_NULL_PARAMETER, F);
            return 0;
        };
        // SAFETY: the key's objects.
        let len = unsafe { EC_POINT_point2oct(f.group.0, f.pub_key.0, f.conv_form, ptr::null_mut(), 0, ptr::null_mut()) };
        let ret = c_int::try_from(len).unwrap_or(0);
        if out.is_null() || len == 0 {
            return ret;
        }
        // SAFETY: the caller's pointer.
        let mut buf = unsafe { *out };
        let new_buffer = buf.is_null();
        if new_buffer {
            buf = mem::malloc(len, ptr::null(), 0).cast();
            if buf.is_null() {
                return 0;
            }
        }
        // SAFETY: the key's objects; room for `len` octets.
        if unsafe { EC_POINT_point2oct(f.group.0, f.pub_key.0, f.conv_form, buf, len, ptr::null_mut()) } == 0 {
            raise(ERR_R_EC_LIB, F);
            if new_buffer {
                // SAFETY: the buffer made above.
                unsafe { mem::release(buf.cast()) };
            }
            return 0;
        }
        // SAFETY: the caller's pointer: the new buffer, or past the octets.
        unsafe { *out = if new_buffer { buf } else { buf.wrapping_add(len) } };
        ret
    }
}

ffi_callback! {
    /// `EC_KEY_new` as `ASN1_d2i_bio`'s constructor.
    ///
    /// # Safety
    /// No preconditions.
    pub(crate) unsafe extern "C" fn new_void() -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: no preconditions.
        unsafe { EC_KEY_new() }.cast()
    }
}

ffi_callback! {
    /// `d2i_ECPrivateKey` as `ASN1_d2i_bio`'s decoder.
    ///
    /// # Safety
    /// As for `d2i_ECPrivateKey`.
    pub(crate) unsafe extern "C" fn d2i_void(a: *mut *mut c_void, r#in: *mut *const c_uchar, len: c_long) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { d2i_ECPrivateKey(a.cast(), r#in, len) }.cast()
    }
}

ffi_callback! {
    /// `i2d_ECPrivateKey` as `ASN1_i2d_bio`'s encoder.
    ///
    /// # Safety
    /// As for `i2d_ECPrivateKey`.
    pub(crate) unsafe extern "C" fn i2d_void(a: *const c_void, out: *mut *mut c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { i2d_ECPrivateKey(a.cast(), out) }
    }
}

ffi_export! {
    /// Reads an ECPrivateKey from a BIO (`ASN1_d2i_bio_of`).
    ///
    /// # Safety
    /// `bp` is a live BIO; `eckey` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_ECPrivateKey_bio(bp: *mut BIO, eckey: *mut *mut EC_KEY) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee; the adapters.
        unsafe { ASN1_d2i_bio(Some(new_void), Some(d2i_void), bp, eckey.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a key's ECPrivateKey to a BIO (`ASN1_i2d_bio_of`). 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `eckey` is NULL or a live key.
    pub unsafe extern "C" fn i2d_ECPrivateKey_bio(bp: *mut BIO, eckey: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee; the adapter.
        unsafe { ASN1_i2d_bio(Some(i2d_void), bp, eckey.cast()) }
    }
}

ffi_export! {
    /// Reads an ECPrivateKey from a file (`ASN1_d2i_fp_of`).
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `eckey` is NULL or holds NULL or a live key.
    pub unsafe extern "C" fn d2i_ECPrivateKey_fp(fp: *mut FILE, eckey: *mut *mut EC_KEY) -> *mut EC_KEY
    where failure = ptr::null_mut(), library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee; the adapters.
        unsafe { ASN1_d2i_fp(Some(new_void), Some(d2i_void), fp, eckey.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a key's ECPrivateKey to a file (`ASN1_i2d_fp_of`). 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `eckey` is NULL or a live key.
    pub unsafe extern "C" fn i2d_ECPrivateKey_fp(fp: *mut FILE, eckey: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee; the adapter.
        unsafe { ASN1_i2d_fp(Some(i2d_void), fp, eckey.cast()) }
    }
}

/// What `do_EC_KEY_print` prints.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Print {
    Param,
    Public,
    Private,
}

/// `do_EC_KEY_print`: a heading with the order's size, the private and public keys' octets,
/// and the group's parameters.
///
/// # Safety
/// `bp` is a live BIO; `x` is NULL or a live key.
pub(crate) unsafe fn print_key(bp: *mut BIO, x: *const EC_KEY, off: c_int, ktype: Print) -> c_int {
    const F: &str = "do_EC_KEY_print";
    // SAFETY: the caller's guarantee.
    let group = if x.is_null() {
        ptr::null()
    } else {
        // SAFETY: the caller's key.
        unsafe { EC_KEY_get0_group(x) }
    };
    if group.is_null() {
        raise(ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    }
    let mut pub_buf: *mut c_uchar = ptr::null_mut();
    let mut priv_buf: *mut c_uchar = ptr::null_mut();
    let (mut publen, mut privlen) = (0, 0);
    let ok = (|| {
        // SAFETY: the caller's key, here and below.
        if ktype != Print::Param && !unsafe { EC_KEY_get0_public_key(x) }.is_null() {
            // SAFETY: as above.
            let form = unsafe { EC_KEY_get_conv_form(x) };
            // SAFETY: as above; a local.
            publen = unsafe { EC_KEY_key2buf(x, form, &raw mut pub_buf, ptr::null_mut()) };
            if publen == 0 {
                return false;
            }
        }
        // SAFETY: as above.
        if ktype == Print::Private && !unsafe { EC_KEY_get0_private_key(x) }.is_null() {
            // SAFETY: as above; a local.
            privlen = unsafe { EC_KEY_priv2buf(x, &raw mut priv_buf) };
            if privlen == 0 {
                return false;
            }
        }
        let ecstr = match ktype {
            Print::Private => c"Private-Key",
            Print::Public => c"Public-Key",
            Print::Param => c"ECDSA-Parameters",
        };
        // SAFETY: the caller's BIO; the key's group.
        let bits = unsafe { EC_GROUP_order_bits(group) };
        // SAFETY: as above.
        if unsafe { BIO_indent(bp, off, 128) } == 0
            // SAFETY: a format with matching arguments.
            || unsafe { BIO_printf(bp, c"%s: (%d bit)\n".as_ptr(), ecstr.as_ptr(), bits) } <= 0
        {
            return false;
        }
        let sub = off.saturating_add(4);
        if privlen != 0 {
            // SAFETY: as above.
            if unsafe { BIO_printf(bp, c"%*spriv:\n".as_ptr(), off, c"".as_ptr()) } <= 0
                // SAFETY: the octets.
                || unsafe { ASN1_buf_print(bp, priv_buf, privlen, sub) } == 0
            {
                return false;
            }
        }
        if publen != 0 {
            // SAFETY: as above.
            if unsafe { BIO_printf(bp, c"%*spub:\n".as_ptr(), off, c"".as_ptr()) } <= 0
                // SAFETY: the octets.
                || unsafe { ASN1_buf_print(bp, pub_buf, publen, sub) } == 0
            {
                return false;
            }
        }
        // SAFETY: as above.
        (unsafe { ECPKParameters_print(bp, group, off) }) != 0
    })();
    if !ok {
        raise(ERR_R_EC_LIB, F);
    }
    // SAFETY: NULL or the octets made above.
    unsafe { mem::release_clean(priv_buf.cast(), privlen) };
    // SAFETY: as above.
    unsafe { mem::release(pub_buf.cast()) };
    c_int::from(ok)
}

ffi_export! {
    /// Prints the key (its private key too if it has one), each line indented by `off`. 1, or
    /// 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or a live key.
    pub unsafe extern "C" fn EC_KEY_print(bp: *mut BIO, x: *const EC_KEY, off: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        let private = !x.is_null() && !unsafe { EC_KEY_get0_private_key(x) }.is_null();
        let ktype = if private { Print::Private } else { Print::Public };
        // SAFETY: as above.
        unsafe { print_key(bp, x, off, ktype) }
    }
}

ffi_export! {
    /// Prints the key's parameters, indented by 4. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or a live key.
    pub unsafe extern "C" fn ECParameters_print(bp: *mut BIO, x: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: the caller's guarantee.
        unsafe { print_key(bp, x, 4, Print::Param) }
    }
}

/// Runs `f` on a BIO over `fp`.
///
/// # Safety
/// `fp` is a live `FILE`.
unsafe fn with_fp(fp: *mut FILE, func: &'static str, f: impl FnOnce(*mut BIO) -> c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let b = unsafe { crate::bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
    if b.is_null() {
        raise(ERR_R_BIO_LIB, func);
        return 0;
    }
    let ret = f(b);
    // SAFETY: the BIO made above.
    unsafe { BIO_free(b) };
    ret
}

ffi_export! {
    /// `EC_KEY_print` to a `FILE`.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `x` is NULL or a live key.
    pub unsafe extern "C" fn EC_KEY_print_fp(fp: *mut FILE, x: *const EC_KEY, off: c_int) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: a BIO over the caller's file; the caller's key.
        let print = |b| unsafe { EC_KEY_print(b, x, off) };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "EC_KEY_print_fp", print) }
    }
}

ffi_export! {
    /// `ECParameters_print` to a `FILE`.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `x` is NULL or a live key.
    pub unsafe extern "C" fn ECParameters_print_fp(fp: *mut FILE, x: *const EC_KEY) -> c_int
    where failure = 0, library = ERR_LIB_EC
    {
        // SAFETY: a BIO over the caller's file; the caller's key.
        let print = |b| unsafe { ECParameters_print(b, x) };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "ECParameters_print_fp", print) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::key::{
        EC_KEY_METHOD_free, EC_KEY_OpenSSL, EC_KEY_can_sign, EC_KEY_get_flags, EC_KEY_priv2oct,
        EC_KEY_set_conv_form, EC_KEY_set_method, EC_KEY_set_private_key, EC_KEY_up_ref,
    };

    /// docs/DEVIATIONS.md: OpenSSL's dereference a NULL key.
    #[test]
    fn a_null_key_fails() {
        let none: *mut EC_KEY = ptr::null_mut();
        // SAFETY: no preconditions.
        let m = unsafe { crate::bio::mem::BIO_s_mem() };
        // SAFETY: a method.
        let bio = unsafe { crate::bio::BIO_new(m) };
        // SAFETY: a live BIO; NULL.
        assert_eq!(unsafe { EC_KEY_print(bio, none, 0) }, 0);
        // SAFETY: NULL, here and below.
        assert!(unsafe { EC_KEY_get0_group(none) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EC_KEY_set_private_key(none, ptr::null()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_KEY_up_ref(none) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_KEY_get_flags(none) }, 0);
        // SAFETY: as above.
        let m = unsafe { EC_KEY_OpenSSL() };
        // SAFETY: as above.
        assert_eq!(unsafe { EC_KEY_set_method(none, m) }, 0);
        // SAFETY: as above.
        unsafe { EC_KEY_METHOD_free(ptr::null_mut()) };
        // SAFETY: as above.
        assert_eq!(unsafe { EC_KEY_priv2oct(none, ptr::null_mut(), 0) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { EC_KEY_can_sign(none) }, 0);
        // SAFETY: as above.
        unsafe { EC_KEY_set_conv_form(none, rustyssl_abi::POINT_CONVERSION_COMPRESSED) };
        // SAFETY: the BIO made above.
        unsafe { BIO_free(bio) };
        // SAFETY: no preconditions.
        unsafe { crate::err::ERR_clear_error() };
    }
}
