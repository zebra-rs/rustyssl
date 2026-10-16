//! DH's ASN.1, PEM, and printing (`dh_asn1.c`, `pem_all.c`, `dh_ameth.c`'s `do_dh_print`,
//! `dh_prn.c`): PKCS #3's DHparameter (`DHparams`, a shadowed item over the `DH` handle, as
//! `RSAPublicKey` is) and X9.42's DomainParameters (`DHxparams`, through OpenSSL's private
//! items `int_dhx942_dh` and `int_dhvparams`), their PEM forms, and the parameters' text.
//!
//! As in OpenSSL, decoding `DHparams` reuses the key's p and g and caches the named group they
//! are; a decoded key is typed DH, and one from `DHxparams` DHX; reading PEM takes either kind;
//! and the printed text is `do_dh_print`'s with `ossl_ffc_params_print`'s fields.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_EXTERN, ASN1_OP_FREE_PRE, ASN1_STRING, ASN1_STRING_FLAG_BITS_LEFT,
    ASN1_TFLG_EMBED, ASN1_TFLG_OPTIONAL, ASN1_VALUE, BIGNUM, BIO, DH, ERR_LIB_ASN1, ERR_LIB_DH,
    ERR_LIB_PEM, ERR_R_ASN1_LIB, ERR_R_BUF_LIB, ERR_R_PASSED_NULL_PARAMETER, PEM_STRING_DHPARAMS,
    PEM_STRING_DHXPARAMS, V_ASN1_SEQUENCE, pem_password_cb,
};

use crate::asn1::string::{ASN1_STRING_free, ASN1_STRING_set, ASN1_STRING_type_new};
use crate::asn1::tpl::bignum::BIGNUM_it;
use crate::asn1::tpl::decode::ASN1_item_d2i;
use crate::asn1::tpl::encode::ASN1_item_i2d;
use crate::asn1::tpl::free::ASN1_item_free;
use crate::asn1::tpl::ints::ZINT32_it;
use crate::asn1::tpl::items::{ASN1_BIT_STRING_it, d2i, i2d};
use crate::asn1::tpl::shadow::{self, Lend, Shadowed};
use crate::asn1::tpl::statics::{Aux, Templates, aux, sequence};
use crate::asn1::tpl::{Item, item, item_fns, template_at};
use crate::bio::print::BIO_printf;
use crate::bio::{BIO_free, BIO_indent, BIO_puts};
use crate::bn::conv::ASN1_bn_print;
use crate::bn::{BN_free, new_bignum, value};
use crate::dh::{
    DH_free, DH_get_length, DH_get0_g, DH_get0_p, DH_get0_q, DH_new, DH_set0_pqg, Dh, Field, dh,
};
use crate::err;
use crate::ffc;
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::pem_cipher::{PEM_ASN1_write, PEM_ASN1_write_bio};
use crate::pem_read::PEM_bytes_read_bio;

/// The shadow of a `DH` for `DHparams`: the fields of OpenSSL's that its templates name.
#[repr(C)]
struct Shadow {
    p: *mut BIGNUM,
    g: *mut BIGNUM,
    length: i32,
    /// The key's own numbers the fields were lent, which freeing the shadow leaves alone.
    lent: [*mut BIGNUM; 2],
}

static DHPARAMS_TT: Templates<3> = Templates([
    template_at(0, 0, offset_of!(Shadow, p), c"params.p", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, g), c"params.g", BIGNUM_it),
    template_at(
        ASN1_TFLG_EMBED | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Shadow, length),
        c"length",
        ZINT32_it,
    ),
]);

static SHADOW_AUX: Aux = aux(shadow_cb);

static SHADOW: Item = sequence::<Shadow, 3>(&DHPARAMS_TT, Some(&SHADOW_AUX), c"DHparams");

/// The shadow's item.
unsafe extern "C" fn shadow_it() -> *const ASN1_ITEM {
    &raw const SHADOW.0
}

ffi_callback! {
    /// The shadow's callback: freeing leaves the key's own numbers.
    ///
    /// # Safety
    /// `pval` holds NULL or a live shadow.
    pub(crate) unsafe extern "C" fn shadow_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if operation != ASN1_OP_FREE_PRE {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let s: *mut Shadow = unsafe { pval.read() }.cast();
        // SAFETY: as above.
        let Some(s) = (unsafe { s.as_mut() }) else { return 1 };
        let [lp, lg] = s.lent;
        if !lp.is_null() && s.p == lp {
            s.p = ptr::null_mut();
        }
        if !lg.is_null() && s.g == lg {
            s.g = ptr::null_mut();
        }
        1
    }
}

/// `DH_new` as a handle.
unsafe fn new_key() -> *mut ASN1_VALUE {
    // SAFETY: no preconditions.
    unsafe { DH_new() }.cast()
}

/// `DH_free` of a handle.
///
/// # Safety
/// `h` is a live `DH` whose reference the caller gives up.
unsafe fn free_key(h: *mut ASN1_VALUE) {
    // SAFETY: the caller's guarantee.
    unsafe { DH_free(h.cast()) };
}

/// A shadow lending the key's p and g (and, for encoding, its private key length).
///
/// # Safety
/// `h` is NULL or a live `DH`.
unsafe fn lend(h: *const ASN1_VALUE, how: Lend) -> *mut ASN1_VALUE {
    let s: *mut Shadow = mem::alloc_zeroed(size_of::<Shadow>()).cast();
    // SAFETY: a new block, or NULL.
    let Some(sh) = (unsafe { s.as_mut() }) else {
        return ptr::null_mut();
    };
    let d: *const DH = h.cast();
    if d.is_null() {
        return s.cast();
    }
    // SAFETY: the caller's key.
    sh.p = unsafe { DH_get0_p(d) }.cast_mut();
    // SAFETY: as above.
    sh.g = unsafe { DH_get0_g(d) }.cast_mut();
    sh.lent = [sh.p, sh.g];
    if how == Lend::Encode {
        // SAFETY: as above.
        let length = unsafe { DH_get_length(d) };
        sh.length = i32::try_from(length).unwrap_or_default();
    }
    s.cast()
}

/// Frees a shadow's own memory.
///
/// # Safety
/// `s` is a shadow from [`lend`] or the engine, whose numbers are lent or taken.
unsafe fn release(s: *mut ASN1_VALUE) {
    // SAFETY: the caller's guarantee.
    unsafe { mem::release(s.cast()) };
}

/// Moves a decoded `DHparams` into the key (`dh_cb`'s `ASN1_OP_D2I_POST`): p, g, and the
/// length; typed DH; the named group cached.
///
/// # Safety
/// `h` is a live `DH`; `s` a shadow decoded for it, whose numbers it takes.
unsafe fn commit(h: *mut ASN1_VALUE, s: *mut ASN1_VALUE) {
    // SAFETY: the caller's guarantee.
    let (Some(k), Some(sh)) = (unsafe { dh(h.cast()) }, unsafe {
        s.cast::<Shadow>().as_ref()
    }) else {
        return;
    };
    // SAFETY: the numbers decoded, each now the key's.
    unsafe { k.adopt(&[(Field::P, sh.p), (Field::G, sh.g)]) };
    let mut st = k.snapshot();
    st.length = sh.length;
    Dh::cache_named_group(&mut st);
    k.replace(st);
    k.set_type(false);
}

static FUNCS: Shadowed = Shadowed {
    funcs: shadow::FUNCS,
    item: shadow_it,
    new: new_key,
    free: free_key,
    lend,
    commit,
    release,
};

item_fns! {
    /// PKCS #3's DHparameter: SEQUENCE { prime, base, privateValueLength OPTIONAL }, over a
    /// `DH`.
    pub unsafe extern "C" fn DHparams_it = item(ASN1_ITYPE_EXTERN, V_ASN1_SEQUENCE, ptr::null(), 0, (&raw const FUNCS.funcs).cast(), 0, c"DHparams");
}

i2d! {
    /// Encodes DH parameters as PKCS #3's DHparameter.
    pub unsafe extern "C" fn i2d_DHparams(DH) = DHparams_it;
}

d2i! {
    /// Decodes PKCS #3's DHparameter (`ASN1_item_d2i`), into the key given if any.
    pub unsafe extern "C" fn d2i_DHparams(DH) = DHparams_it;
}

/// `int_dhvparams`: X9.42's ValidationParms.
#[repr(C)]
struct Vparams {
    seed: *mut ASN1_STRING,
    counter: *mut BIGNUM,
}

/// `int_dhx942_dh`: X9.42's DomainParameters.
#[repr(C)]
struct Dhx {
    p: *mut BIGNUM,
    g: *mut BIGNUM,
    q: *mut BIGNUM,
    j: *mut BIGNUM,
    vparams: *mut Vparams,
}

static VPARAMS_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(Vparams, seed), c"seed", ASN1_BIT_STRING_it),
    template_at(0, 0, offset_of!(Vparams, counter), c"counter", BIGNUM_it),
]);

static VPARAMS: Item = sequence::<Vparams, 2>(&VPARAMS_TT, None, c"int_dhvparams");

/// `DHvparams_it`, which OpenSSL keeps private.
unsafe extern "C" fn vparams_it() -> *const ASN1_ITEM {
    &raw const VPARAMS.0
}

static DHX_TT: Templates<5> = Templates([
    template_at(0, 0, offset_of!(Dhx, p), c"p", BIGNUM_it),
    template_at(0, 0, offset_of!(Dhx, g), c"g", BIGNUM_it),
    template_at(0, 0, offset_of!(Dhx, q), c"q", BIGNUM_it),
    template_at(ASN1_TFLG_OPTIONAL, 0, offset_of!(Dhx, j), c"j", BIGNUM_it),
    template_at(
        ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Dhx, vparams),
        c"vparams",
        vparams_it,
    ),
]);

static DHX: Item = sequence::<Dhx, 5>(&DHX_TT, None, c"int_dhx942_dh");

/// `DHxparams_it`, which OpenSSL keeps private.
unsafe extern "C" fn dhx_it() -> *const ASN1_ITEM {
    &raw const DHX.0
}

/// The low 32 bits of `BN_get_word(b)` as `int`, as OpenSSL's `(size_t)` then `int` takes it.
fn counter_of(b: &rustyssl_crypto::bn::BigNum) -> c_int {
    let w = if b.num_bits() > 64 {
        u64::MAX
    } else {
        b.get_word()
    };
    let low = u32::try_from(w & 0xffff_ffff).unwrap_or(0);
    c_int::from_ne_bytes(low.to_ne_bytes())
}

ffi_export! {
    /// Decodes X9.42's DomainParameters into a new key (typed DHX): p, g, q, j, and the
    /// validation parameters' seed and counter; the key given, if any, is freed and replaced.
    ///
    /// # Safety
    /// `a` is NULL or holds NULL or a live key; `*pp` holds `length` octets.
    pub unsafe extern "C" fn d2i_DHxparams(a: *mut *mut DH, pp: *mut *const c_uchar, length: c_long) -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_DH
    {
        // SAFETY: no preconditions.
        let d = unsafe { DH_new() };
        if d.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: no preconditions.
        let it = unsafe { dhx_it() };
        // SAFETY: the caller's input; the private item.
        let x: *mut Dhx = unsafe { ASN1_item_d2i(ptr::null_mut(), pp, length, it) }.cast();
        // SAFETY: the decoded structure, or NULL.
        let Some(dx) = (unsafe { x.as_mut() }) else {
            // SAFETY: made above.
            unsafe { DH_free(d) };
            return ptr::null_mut();
        };
        if !a.is_null() {
            // SAFETY: the caller's guarantee.
            let old = unsafe { a.read() };
            // SAFETY: as above.
            unsafe { DH_free(old) };
            // SAFETY: as above.
            unsafe { a.write(d) };
        }
        // SAFETY: the key made above; the decoded numbers, which it takes.
        unsafe { DH_set0_pqg(d, dx.p, dx.q, dx.g) };
        dx.p = ptr::null_mut();
        dx.q = ptr::null_mut();
        dx.g = ptr::null_mut();
        // SAFETY: the key made above.
        if let Some(k) = unsafe { dh(d) } {
            let mut st = k.snapshot();
            // SAFETY: the decoded j, or NULL.
            st.params.j = unsafe { value(dx.j) };
            // SAFETY: the decoded validation parameters, or NULL.
            if let Some(v) = unsafe { dx.vparams.as_ref() } {
                // SAFETY: the decoded counter.
                let counter = unsafe { value(v.counter) }.map_or(0, |c| counter_of(&c));
                // SAFETY: the decoded seed.
                let seed = unsafe { v.seed.as_ref() }.and_then(|s| {
                    // SAFETY: the string's own octets.
                    unsafe { crate::ffi::bytes(s.data, usize::try_from(s.length).unwrap_or(0)) }
                });
                st.params.set_validate_params(seed, counter);
            }
            k.replace(st);
            k.set_type(true);
        }
        // SAFETY: the decoded structure, without the numbers the key took.
        unsafe { ASN1_item_free(x.cast(), it) };
        d
    }
}

ffi_export! {
    /// Encodes the key's parameters as X9.42's DomainParameters: p, g, q, j if any, and the
    /// validation parameters if it has a seed and counter. The length, or -1 (without q).
    ///
    /// # Safety
    /// `dh` is a live key; `pp` is NULL or as `i2d_*`'s.
    pub unsafe extern "C" fn i2d_DHxparams(dh: *const DH, pp: *mut *mut c_uchar) -> c_int
    where failure = -1, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { self::dh(dh) }) else { return -1 };
        let st = k.snapshot();
        let j = st.params.j.as_ref().map_or(ptr::null_mut(), |j| new_bignum(j.clone(), false));
        let seed = st.params.seed.as_deref().filter(|s| !s.is_empty() && st.params.pcounter != -1);
        let mut v = Vparams { seed: ptr::null_mut(), counter: ptr::null_mut() };
        if let Some(seed) = seed {
            // SAFETY: no preconditions.
            v.seed = unsafe { ASN1_STRING_type_new(rustyssl_abi::V_ASN1_BIT_STRING) };
            let len = c_int::try_from(seed.len()).unwrap_or(0);
            // SAFETY: the string made above (or NULL, checked by the call); the seed.
            unsafe { ASN1_STRING_set(v.seed, seed.as_ptr().cast(), len) };
            // SAFETY: as above.
            if let Some(s) = unsafe { v.seed.as_mut() } {
                s.flags = c_long::from(ASN1_STRING_FLAG_BITS_LEFT);
            }
            let counter = u64::try_from(st.params.pcounter).unwrap_or(0);
            v.counter = new_bignum(rustyssl_crypto::bn::BigNum::from_word(counter), false);
        }
        let x = Dhx {
            // SAFETY: the caller's key.
            p: unsafe { DH_get0_p(dh) }.cast_mut(),
            // SAFETY: as above.
            g: unsafe { DH_get0_g(dh) }.cast_mut(),
            // SAFETY: as above.
            q: unsafe { DH_get0_q(dh) }.cast_mut(),
            j,
            vparams: if seed.is_some() { &raw mut v } else { ptr::null_mut() },
        };
        // SAFETY: no preconditions.
        let it = unsafe { dhx_it() };
        // SAFETY: the structure, which outlives the call; the private item.
        let ret = unsafe { ASN1_item_i2d((&raw const x).cast(), pp, it) };
        // SAFETY: ours, or NULL.
        unsafe { BN_free(j) };
        // SAFETY: as above.
        unsafe { BN_free(v.counter) };
        // SAFETY: as above.
        unsafe { ASN1_STRING_free(v.seed) };
        ret
    }
}

/// `BIO_indent(bp, n, 128)` as a success.
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn indent(bp: *mut BIO, n: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { BIO_indent(bp, n, 128) }) != 0
}

/// `ASN1_bn_print(bp, label, v, NULL, off)` of a number (nothing for none).
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn bn_print(
    bp: *mut BIO,
    label: &CStr,
    v: Option<&rustyssl_crypto::bn::BigNum>,
    off: c_int,
) -> bool {
    let b = v.map_or(ptr::null_mut(), |v| new_bignum(v.clone(), false));
    // SAFETY: the caller's BIO; a label; ours, or NULL.
    let ok = unsafe { ASN1_bn_print(bp, label.as_ptr(), b, ptr::null_mut(), off) } != 0;
    // SAFETY: ours, or NULL.
    unsafe { BN_free(b) };
    ok
}

/// `ossl_ffc_params_print`: p, g, q, j, the seed (15 octets a line), and the counter.
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn ffc_print(bp: *mut BIO, params: &ffc::Params, off: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    let ok = unsafe { bn_print(bp, c"prime P:", params.p.as_ref(), off) }
        // SAFETY: as above.
        && unsafe { bn_print(bp, c"generator G:", params.g.as_ref(), off) }
        // SAFETY: as above.
        && (params.q.is_none() || unsafe { bn_print(bp, c"subgroup order Q:", params.q.as_ref(), off) })
        // SAFETY: as above.
        && (params.j.is_none() || unsafe { bn_print(bp, c"subgroup factor:", params.j.as_ref(), off) });
    if !ok {
        return false;
    }
    if let Some(seed) = params.seed.as_deref() {
        // SAFETY: as above.
        if !unsafe { indent(bp, off) } || unsafe { BIO_puts(bp, c"seed:".as_ptr()) } <= 0 {
            return false;
        }
        for (i, b) in seed.iter().enumerate() {
            if i % 15 == 0 {
                // SAFETY: as above.
                if unsafe { BIO_puts(bp, c"\n".as_ptr()) } <= 0
                    // SAFETY: as above.
                    || !unsafe { indent(bp, off.saturating_add(4)) }
                {
                    return false;
                }
            }
            let sep: &CStr = if i.saturating_add(1) == seed.len() {
                c""
            } else {
                c":"
            };
            // SAFETY: as above; a format and its arguments.
            if unsafe { BIO_printf(bp, c"%02x%s".as_ptr(), c_int::from(*b), sep.as_ptr()) } <= 0 {
                return false;
            }
        }
        // SAFETY: as above.
        if unsafe { BIO_puts(bp, c"\n".as_ptr()) } <= 0 {
            return false;
        }
    }
    if params.pcounter != -1 {
        // SAFETY: as above.
        if !unsafe { indent(bp, off) }
            // SAFETY: as above; a format and its argument.
            || unsafe { BIO_printf(bp, c"counter: %d\n".as_ptr(), params.pcounter) } <= 0
        {
            return false;
        }
    }
    true
}

/// What `do_print` prints: the parameters, or the public key, or the private key too.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Part {
    Params,
    Public,
    Private,
}

/// `do_dh_print`: the kind and the prime's bits, the private and public keys (as `part`
/// asks), the FFC fields, and the private key length if set, indented `off`. 1, or 0 (without
/// a prime or a key asked for, or when writing fails) with the error raised.
///
/// # Safety
/// `bp` is a live BIO.
pub(crate) unsafe fn do_print(
    bp: *mut BIO,
    st: &crate::dh::DhState,
    off: c_int,
    part: Part,
) -> c_int {
    const F: &str = "do_dh_print";
    let priv_key = if part == Part::Private {
        st.priv_key.as_ref()
    } else {
        None
    };
    let pub_key = if part == Part::Params {
        None
    } else {
        st.pub_key.as_ref()
    };
    let Some(p) = st.params.p.as_ref() else {
        err::raise(ERR_LIB_DH, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    };
    if (part == Part::Private && priv_key.is_none()) || (part != Part::Params && pub_key.is_none())
    {
        err::raise(ERR_LIB_DH, ERR_R_PASSED_NULL_PARAMETER, F);
        return 0;
    }
    let ktype = match part {
        Part::Private => c"DH Private-Key",
        Part::Public => c"DH Public-Key",
        Part::Params => c"DH Parameters",
    };
    let bits = c_int::try_from(p.num_bits()).unwrap_or(c_int::MAX);
    let inner = off.saturating_add(4);
    // SAFETY: the caller's BIO; a format and its arguments.
    let ok = unsafe { indent(bp, off) }
        // SAFETY: as above.
        && unsafe { BIO_printf(bp, c"%s: (%d bit)\n".as_ptr(), ktype.as_ptr(), bits) } > 0
        // SAFETY: as above.
        && unsafe { bn_print(bp, c"private-key:", priv_key, inner) }
        // SAFETY: as above.
        && unsafe { bn_print(bp, c"public-key:", pub_key, inner) }
        // SAFETY: as above.
        && unsafe { ffc_print(bp, &st.params, inner) }
        && (st.length == 0
            // SAFETY: as above.
            || (unsafe { indent(bp, inner) }
                // SAFETY: as above; a format and its argument.
                && unsafe { BIO_printf(bp, c"recommended-private-length: %d bits\n".as_ptr(), st.length) } > 0));
    if !ok {
        err::raise(ERR_LIB_DH, ERR_R_BUF_LIB, F);
        return 0;
    }
    1
}

ffi_export! {
    /// The parameters' text (`do_dh_print` of parameters, indented 4): "DH Parameters", the
    /// prime's bits, the FFC fields, and the private key length if set. 1, or 0 (without a
    /// prime, or when writing fails) with the error raised.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` a live key.
    pub unsafe extern "C" fn DHparams_print(bp: *mut BIO, x: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { dh(x) }) else { return 0 };
        // SAFETY: the caller's BIO.
        unsafe { do_print(bp, &k.snapshot(), 4, Part::Params) }
    }
}

ffi_export! {
    /// `DHparams_print` to a FILE.
    ///
    /// # Safety
    /// `fp` is a live FILE; `x` a live key.
    pub unsafe extern "C" fn DHparams_print_fp(fp: *mut FILE, x: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_DH
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { crate::bio::file::BIO_new_fp(fp, rustyssl_abi::BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_DH, ERR_R_BUF_LIB, "DHparams_print_fp");
            return 0;
        }
        // SAFETY: the BIO; the caller's key.
        let ret = unsafe { DHparams_print(b, x) };
        // SAFETY: the BIO made above.
        unsafe { BIO_free(b) };
        ret
    }
}

type I2dOfVoid = unsafe extern "C" fn(*const c_void, *mut *mut c_uchar) -> c_int;

/// `i2d_DHparams` as `i2d_of_void`.
unsafe extern "C" fn i2d_dhparams_void(x: *const c_void, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { i2d_DHparams(x.cast(), pp) }
}

/// `i2d_DHxparams` as `i2d_of_void`.
unsafe extern "C" fn i2d_dhxparams_void(x: *const c_void, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { i2d_DHxparams(x.cast(), pp) }
}

/// `PEM_ASN1_write_bio` of a key with `i2d` under `name`.
///
/// # Safety
/// `bp` is a live BIO; `x` a live key.
unsafe fn write_bio(i2d: I2dOfVoid, name: &CStr, bp: *mut BIO, x: *const DH) -> c_int {
    // SAFETY: the caller's guarantee; no encryption.
    unsafe {
        PEM_ASN1_write_bio(
            Some(i2d),
            name.as_ptr(),
            bp,
            x.cast(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

/// `PEM_ASN1_write` of a key with `i2d` under `name`.
///
/// # Safety
/// `fp` is a live FILE; `x` a live key.
unsafe fn write_fp(i2d: I2dOfVoid, name: &CStr, fp: *mut FILE, x: *const DH) -> c_int {
    // SAFETY: the caller's guarantee; no encryption.
    unsafe {
        PEM_ASN1_write(
            Some(i2d),
            name.as_ptr(),
            fp,
            x.cast(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

ffi_export! {
    /// Writes PKCS #3 DH parameters as PEM ("DH PARAMETERS").
    ///
    /// # Safety
    /// `out` is a live BIO; `x` a live key.
    pub unsafe extern "C" fn PEM_write_bio_DHparams(out: *mut BIO, x: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_bio(i2d_dhparams_void, PEM_STRING_DHPARAMS, out, x) }
    }
}

ffi_export! {
    /// Writes X9.42 DH parameters as PEM ("X9.42 DH PARAMETERS").
    ///
    /// # Safety
    /// `out` is a live BIO; `x` a live key.
    pub unsafe extern "C" fn PEM_write_bio_DHxparams(out: *mut BIO, x: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_bio(i2d_dhxparams_void, PEM_STRING_DHXPARAMS, out, x) }
    }
}

ffi_export! {
    /// `PEM_write_bio_DHparams` to a FILE.
    ///
    /// # Safety
    /// `out` is a live FILE; `x` a live key.
    pub unsafe extern "C" fn PEM_write_DHparams(out: *mut FILE, x: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_fp(i2d_dhparams_void, PEM_STRING_DHPARAMS, out, x) }
    }
}

ffi_export! {
    /// `PEM_write_bio_DHxparams` to a FILE.
    ///
    /// # Safety
    /// `out` is a live FILE; `x` a live key.
    pub unsafe extern "C" fn PEM_write_DHxparams(out: *mut FILE, x: *const DH) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_fp(i2d_dhxparams_void, PEM_STRING_DHXPARAMS, out, x) }
    }
}

ffi_export! {
    /// Reads PKCS #3 or X9.42 DH parameters from PEM, into the key given if any.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or holds NULL or a live key; `cb` is called with `u`.
    pub unsafe extern "C" fn PEM_read_bio_DHparams(bp: *mut BIO, x: *mut *mut DH, cb: pem_password_cb, u: *mut c_void) -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        let mut data: *mut c_uchar = ptr::null_mut();
        let mut len: c_long = 0;
        let mut nm: *mut c_char = ptr::null_mut();
        // SAFETY: places for the results; the caller's BIO and callback.
        if unsafe { PEM_bytes_read_bio(&raw mut data, &raw mut len, &raw mut nm, PEM_STRING_DHPARAMS.as_ptr(), bp, cb, u) } == 0 {
            return ptr::null_mut();
        }
        let mut p = data.cast_const();
        // SAFETY: the name read.
        let x942 = unsafe { CStr::from_ptr(nm) } == PEM_STRING_DHXPARAMS;
        let ret = if x942 {
            // SAFETY: the caller's key; the octets read.
            unsafe { d2i_DHxparams(x, &raw mut p, len) }
        } else {
            // SAFETY: as above.
            unsafe { d2i_DHparams(x, &raw mut p, len) }
        };
        if ret.is_null() {
            err::raise(ERR_LIB_PEM, ERR_R_ASN1_LIB, "PEM_read_bio_DHparams");
        }
        // SAFETY: the name and octets read, ours to free.
        unsafe { mem::CRYPTO_free(nm.cast(), c"".as_ptr(), 0) };
        // SAFETY: as above.
        unsafe { mem::CRYPTO_free(data.cast(), c"".as_ptr(), 0) };
        ret
    }
}

ffi_export! {
    /// `PEM_read_bio_DHparams` from a FILE.
    ///
    /// # Safety
    /// As for `PEM_read_bio_DHparams`, with a live FILE.
    pub unsafe extern "C" fn PEM_read_DHparams(fp: *mut FILE, x: *mut *mut DH, cb: pem_password_cb, u: *mut c_void) -> *mut DH
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { crate::bio::file::BIO_new_fp(fp, rustyssl_abi::BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_PEM, ERR_R_BUF_LIB, "PEM_read_DHparams");
            return ptr::null_mut();
        }
        // SAFETY: the BIO; the caller's arguments.
        let ret = unsafe { PEM_read_bio_DHparams(b, x, cb, u) };
        // SAFETY: the BIO made above.
        unsafe { BIO_free(b) };
        ret
    }
}
