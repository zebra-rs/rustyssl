//! RSA's ASN.1 items (`rsa_asn1.c`, `x_all.c`): `RSAPublicKey` and `RSAPrivateKey` (PKCS #1)
//! over the `RSA` handle, `RSA_PSS_PARAMS` and `RSA_OAEP_PARAMS` over their public structures,
//! and their `d2i_`/`i2d_`/`_dup`/BIO and FILE functions.
//!
//! The two key items are shadowed extern items ([`crate::asn1::tpl::shadow`]): the shadow has
//! the fields OpenSSL's `RSA` gives its templates (`version`, `n` ... `iqmp`, `prime_infos`),
//! with OpenSSL's field names, items (`INT32`, `BIGNUM`, `CBIGNUM`, `RSA_PRIME_INFO`), and
//! callback: a version-1 (multi-prime) key without the other primes' list fails to decode, as
//! `ossl_rsa_multip_calc_product` makes OpenSSL's fail. Decoding reuses the key's own `BIGNUM`s,
//! keeps the version as decoded (any `int32`, re-encoded as it was), and replaces the other
//! primes with the list decoded (none when it's absent); `RSAPublicKey` touches only n and e.

use core::ffi::{c_int, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_AUX, ASN1_ITEM, ASN1_ITYPE_EXTERN, ASN1_ITYPE_SEQUENCE, ASN1_OP_D2I_POST,
    ASN1_OP_FREE_PRE, ASN1_TEMPLATE, ASN1_TFLG_EMBED, ASN1_TFLG_EXPLICIT, ASN1_TFLG_OPTIONAL,
    ASN1_TFLG_SEQUENCE_OF, ASN1_VALUE, BIGNUM, BIO, ERR_LIB_ASN1, OPENSSL_STACK, RSA,
    RSA_ASN1_VERSION_MULTI, RSA_OAEP_PARAMS, RSA_PSS_PARAMS, V_ASN1_SEQUENCE,
};

use crate::asn1::tpl::bignum::{BIGNUM_it, CBIGNUM_it};
use crate::asn1::tpl::ints::INT32_it;
use crate::asn1::tpl::io::{
    ASN1_item_d2i_bio, ASN1_item_d2i_fp, ASN1_item_i2d_bio, ASN1_item_i2d_fp,
};
use crate::asn1::tpl::items::{
    ASN1_INTEGER_it, X509_ALGOR_free, X509_ALGOR_it, d2i, i2d, new_free,
};
use crate::asn1::tpl::shadow::{self, Lend, Shadowed};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Item, item, item_fns, size_of_long, template_at};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::rsa::{Field, rsa};
use crate::rsa_lib::{
    RSA_free, RSA_get_multi_prime_extra_count, RSA_get_version, RSA_get0_d, RSA_get0_dmp1,
    RSA_get0_dmq1, RSA_get0_e, RSA_get0_iqmp, RSA_get0_multi_prime_crt_params,
    RSA_get0_multi_prime_factors, RSA_get0_n, RSA_get0_p, RSA_get0_q, RSA_new,
};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};

/// A table of templates in a static.
struct Templates<const N: usize>([ASN1_TEMPLATE; N]);
// SAFETY: immutable tables of pointers to static data.
unsafe impl<const N: usize> Sync for Templates<N> {}

/// An aux table in a static.
struct Aux(ASN1_AUX);
// SAFETY: immutable, with no pointers but the callback.
unsafe impl Sync for Aux {}

/// An aux table with callback `cb`, as `ASN1_SEQUENCE_cb` makes.
const fn aux(
    cb: unsafe extern "C" fn(c_int, *mut *mut ASN1_VALUE, *const ASN1_ITEM, *mut c_void) -> c_int,
) -> Aux {
    Aux(ASN1_AUX {
        app_data: ptr::null_mut(),
        flags: 0,
        ref_offset: 0,
        ref_lock: 0,
        asn1_cb: Some(cb),
        enc_offset: 0,
        asn1_const_cb: None,
    })
}

/// A SEQUENCE item over `T` with `templates` and `aux`.
const fn sequence<T, const N: usize>(
    templates: &'static Templates<N>,
    aux: Option<&'static Aux>,
    sname: &'static core::ffi::CStr,
) -> Item {
    let funcs: *const c_void = match aux {
        Some(a) => (&raw const a.0).cast(),
        None => ptr::null(),
    };
    #[expect(clippy::cast_possible_wrap, reason = "a handful of templates")]
    let tcount = N as core::ffi::c_long;
    item(
        ASN1_ITYPE_SEQUENCE,
        V_ASN1_SEQUENCE,
        (&raw const templates.0).cast(),
        tcount,
        funcs,
        size_of_long::<T>(),
        sname,
    )
}

/// The key's numbers in OpenSSL's order, with the fields that hold them.
const FIELDS: [Field; 8] = [
    Field::N,
    Field::E,
    Field::D,
    Field::P,
    Field::Q,
    Field::Dmp1,
    Field::Dmq1,
    Field::Iqmp,
];

/// The shadow of an `RSA`: the fields of OpenSSL's that its templates name.
#[repr(C)]
struct Shadow {
    version: i32,
    n: *mut BIGNUM,
    e: *mut BIGNUM,
    d: *mut BIGNUM,
    p: *mut BIGNUM,
    q: *mut BIGNUM,
    dmp1: *mut BIGNUM,
    dmq1: *mut BIGNUM,
    iqmp: *mut BIGNUM,
    prime_infos: *mut OPENSSL_STACK,
    /// The key's own numbers the fields were lent, which freeing the shadow leaves alone.
    lent: [*mut BIGNUM; 8],
}

impl Shadow {
    /// The number fields, in [`FIELDS`]' order.
    fn numbers(&mut self) -> [&mut *mut BIGNUM; 8] {
        [
            &mut self.n,
            &mut self.e,
            &mut self.d,
            &mut self.p,
            &mut self.q,
            &mut self.dmp1,
            &mut self.dmq1,
            &mut self.iqmp,
        ]
    }
}

/// `RSA_PRIME_INFO`'s encoded fields: an extra prime, its CRT exponent, and its coefficient.
#[repr(C)]
struct PrimeInfo {
    r: *mut BIGNUM,
    d: *mut BIGNUM,
    t: *mut BIGNUM,
}

static PRIME_INFO_TT: Templates<3> = Templates([
    template_at(0, 0, offset_of!(PrimeInfo, r), c"r", CBIGNUM_it),
    template_at(0, 0, offset_of!(PrimeInfo, d), c"d", CBIGNUM_it),
    template_at(0, 0, offset_of!(PrimeInfo, t), c"t", CBIGNUM_it),
]);

static PRIME_INFO: Item = sequence::<PrimeInfo, 3>(&PRIME_INFO_TT, None, c"RSA_PRIME_INFO");

/// `RSA_PRIME_INFO_it`, which OpenSSL doesn't export.
unsafe extern "C" fn prime_info_it() -> *const ASN1_ITEM {
    &raw const PRIME_INFO.0
}

static PRIVATE_TT: Templates<10> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Shadow, version),
        c"version",
        INT32_it,
    ),
    template_at(0, 0, offset_of!(Shadow, n), c"n", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, e), c"e", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, d), c"d", CBIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, p), c"p", CBIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, q), c"q", CBIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, dmp1), c"dmp1", CBIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, dmq1), c"dmq1", CBIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, iqmp), c"iqmp", CBIGNUM_it),
    template_at(
        ASN1_TFLG_SEQUENCE_OF | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(Shadow, prime_infos),
        c"prime_infos",
        prime_info_it,
    ),
]);

static PUBLIC_TT: Templates<2> = Templates([
    template_at(0, 0, offset_of!(Shadow, n), c"n", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, e), c"e", BIGNUM_it),
]);

static SHADOW_AUX: Aux = aux(shadow_cb);

static PRIVATE_SHADOW: Item =
    sequence::<Shadow, 10>(&PRIVATE_TT, Some(&SHADOW_AUX), c"RSAPrivateKey");
static PUBLIC_SHADOW: Item = sequence::<Shadow, 2>(&PUBLIC_TT, Some(&SHADOW_AUX), c"RSAPublicKey");

/// The private key's shadow item.
unsafe extern "C" fn private_shadow_it() -> *const ASN1_ITEM {
    &raw const PRIVATE_SHADOW.0
}

/// The public key's shadow item.
unsafe extern "C" fn public_shadow_it() -> *const ASN1_ITEM {
    &raw const PUBLIC_SHADOW.0
}

ffi_callback! {
    /// The shadows' callback: freeing leaves the key's own numbers (`ASN1_OP_FREE_PRE`), and a
    /// multi-prime version needs the other primes (`ASN1_OP_D2I_POST`, `rsa_cb`'s
    /// `ossl_rsa_multip_calc_product`, which fails without them).
    ///
    /// # Safety
    /// `pval` holds NULL or a live shadow.
    pub(crate) unsafe extern "C" fn shadow_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, _it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let s: *mut Shadow = unsafe { pval.read() }.cast();
        // SAFETY: as above.
        let Some(s) = (unsafe { s.as_mut() }) else { return 1 };
        match operation {
            ASN1_OP_FREE_PRE => {
                let lent = s.lent;
                for (f, l) in s.numbers().into_iter().zip(lent) {
                    if !l.is_null() && *f == l {
                        *f = ptr::null_mut();
                    }
                }
                1
            }
            ASN1_OP_D2I_POST if s.version == RSA_ASN1_VERSION_MULTI => {
                // SAFETY: NULL or the stack decoded.
                c_int::from(!s.prime_infos.is_null() && unsafe { OPENSSL_sk_num(s.prime_infos) } > 0)
            }
            _ => 1,
        }
    }
}

/// `RSA_new` as a handle.
unsafe fn new_key() -> *mut ASN1_VALUE {
    // SAFETY: no preconditions.
    unsafe { RSA_new() }.cast()
}

/// `RSA_free` of a handle.
///
/// # Safety
/// `h` is a live `RSA` whose reference the caller gives up.
unsafe fn free_key(h: *mut ASN1_VALUE) {
    // SAFETY: the caller's guarantee.
    unsafe { RSA_free(h.cast()) };
}

/// The key's other primes as `RSA_PRIME_INFO`s lending its numbers, or NULL when it has none
/// and listed none; `Err` when memory runs out.
///
/// # Safety
/// `r` is a live key.
unsafe fn lend_primes(r: *const RSA) -> Result<*mut OPENSSL_STACK, ()> {
    // SAFETY: the caller's guarantee.
    let count = usize::try_from(unsafe { RSA_get_multi_prime_extra_count(r) }).unwrap_or(0);
    // SAFETY: as above.
    let listed = unsafe { rsa(r) }.is_some_and(|k| k.legacy().listed_primes);
    if count == 0 && !listed {
        return Ok(ptr::null_mut());
    }
    let mut primes = vec![ptr::null::<BIGNUM>(); count];
    let mut exps = vec![ptr::null::<BIGNUM>(); count];
    let mut coeffs = vec![ptr::null::<BIGNUM>(); count];
    // SAFETY: room for each extra prime.
    let got = count == 0 || unsafe { RSA_get0_multi_prime_factors(r, primes.as_mut_ptr()) } != 0;
    // SAFETY: as above.
    let got = got
        && (count == 0
            || unsafe {
                RSA_get0_multi_prime_crt_params(r, exps.as_mut_ptr(), coeffs.as_mut_ptr())
            } != 0);
    if !got {
        return Err(());
    }
    // SAFETY: no preconditions.
    let sk = unsafe { OPENSSL_sk_new_null() };
    if sk.is_null() {
        return Err(());
    }
    for ((&p, &e), &c) in primes.iter().zip(&exps).zip(&coeffs) {
        let info: *mut PrimeInfo = mem::alloc_zeroed(size_of::<PrimeInfo>()).cast();
        // SAFETY: a new block, or NULL.
        let Some(i) = (unsafe { info.as_mut() }) else {
            // SAFETY: the stack and the infos pushed so far, which hold only lent numbers.
            unsafe { release_primes(sk) };
            return Err(());
        };
        i.r = p.cast_mut();
        i.d = e.cast_mut();
        i.t = c.cast_mut();
        // SAFETY: a live stack.
        if unsafe { OPENSSL_sk_push(sk, info.cast_const().cast()) } <= 0 {
            // SAFETY: the info, not on the stack.
            unsafe { mem::release(info.cast()) };
            // SAFETY: as above.
            unsafe { release_primes(sk) };
            return Err(());
        }
    }
    Ok(sk)
}

/// Frees a stack of `PrimeInfo`s and the infos, not their numbers.
///
/// # Safety
/// `sk` is NULL or a live stack of infos from this allocator.
unsafe fn release_primes(sk: *mut OPENSSL_STACK) {
    if sk.is_null() {
        return;
    }
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(sk) };
    for i in 0..n {
        // SAFETY: an element of the stack.
        let info = unsafe { OPENSSL_sk_value(sk, i) };
        // SAFETY: an info from this allocator.
        unsafe { mem::release(info) };
    }
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_free(sk) };
}

/// A shadow lending the key's numbers: for decoding, the ones a decode reuses; for encoding,
/// also its version and other primes.
///
/// # Safety
/// `h` is NULL or a live `RSA`.
unsafe fn lend(h: *const ASN1_VALUE, how: Lend) -> *mut ASN1_VALUE {
    let s: *mut Shadow = mem::alloc_zeroed(size_of::<Shadow>()).cast();
    // SAFETY: a new block, or NULL.
    let Some(sh) = (unsafe { s.as_mut() }) else {
        return ptr::null_mut();
    };
    let r: *const RSA = h.cast();
    if r.is_null() {
        return s.cast();
    }
    let getters: [unsafe extern "C" fn(*const RSA) -> *const BIGNUM; 8] = [
        RSA_get0_n,
        RSA_get0_e,
        RSA_get0_d,
        RSA_get0_p,
        RSA_get0_q,
        RSA_get0_dmp1,
        RSA_get0_dmq1,
        RSA_get0_iqmp,
    ];
    for (i, get) in getters.into_iter().enumerate() {
        // SAFETY: the caller's key.
        let b = unsafe { get(r) }.cast_mut();
        if let Some(l) = sh.lent.get_mut(i) {
            *l = b;
        }
    }
    let lent = sh.lent;
    for (f, l) in sh.numbers().into_iter().zip(lent) {
        *f = l;
    }
    if how == Lend::Encode {
        // SAFETY: as above.
        sh.version = unsafe { RSA_get_version(r.cast_mut()) };
        // SAFETY: as above.
        match unsafe { lend_primes(r) } {
            Ok(sk) => sh.prime_infos = sk,
            Err(()) => {
                // SAFETY: the shadow just made, lending only.
                unsafe { mem::release(s.cast()) };
                return ptr::null_mut();
            }
        }
    }
    s.cast()
}

/// Frees a shadow's own memory: the shadow, its list of other primes, and their infos.
///
/// # Safety
/// `s` is a shadow from [`lend`] or the engine, whose numbers are lent or taken.
unsafe fn release(s: *mut ASN1_VALUE) {
    let s: *mut Shadow = s.cast();
    // SAFETY: the caller's guarantee.
    let sk = unsafe { (*s).prime_infos };
    // SAFETY: its list, of infos from this allocator.
    unsafe { release_primes(sk) };
    // SAFETY: the shadow, from this allocator.
    unsafe { mem::release(s.cast()) };
}

/// Moves a decoded `RSAPrivateKey` into the key: its numbers, version, and other primes.
///
/// # Safety
/// `h` is a live `RSA`; `s` a shadow decoded for it, whose numbers it takes.
unsafe fn commit_private(h: *mut ASN1_VALUE, s: *mut ASN1_VALUE) {
    // SAFETY: the caller's guarantee.
    let (Some(k), Some(sh)) = (unsafe { rsa(h.cast()) }, unsafe {
        s.cast::<Shadow>().as_mut()
    }) else {
        return;
    };
    let numbers: Vec<(Field, *mut BIGNUM)> =
        FIELDS.into_iter().zip(sh.numbers().map(|f| *f)).collect();
    let mut extra = Vec::new();
    if !sh.prime_infos.is_null() {
        // SAFETY: the stack decoded.
        let n = unsafe { OPENSSL_sk_num(sh.prime_infos) };
        for i in 0..n {
            // SAFETY: an element of the stack decoded.
            let info: *const PrimeInfo = unsafe { OPENSSL_sk_value(sh.prime_infos, i) }.cast();
            // SAFETY: an info decoded, with its three numbers.
            let info = unsafe { &*info };
            extra.push([info.r, info.d, info.t]);
        }
    }
    let listed = !sh.prime_infos.is_null();
    // SAFETY: the numbers decoded, each now the key's.
    unsafe { k.adopt(&numbers, Some((extra, listed)), Some(sh.version)) };
}

/// Moves a decoded `RSAPublicKey` into the key: n and e.
///
/// # Safety
/// As for [`commit_private`].
unsafe fn commit_public(h: *mut ASN1_VALUE, s: *mut ASN1_VALUE) {
    // SAFETY: the caller's guarantee.
    let (Some(k), Some(sh)) = (unsafe { rsa(h.cast()) }, unsafe {
        s.cast::<Shadow>().as_ref()
    }) else {
        return;
    };
    // SAFETY: as above.
    unsafe { k.adopt(&[(Field::N, sh.n), (Field::E, sh.e)], None, None) };
}

static PRIVATE_FUNCS: Shadowed = Shadowed {
    funcs: shadow::FUNCS,
    item: private_shadow_it,
    new: new_key,
    free: free_key,
    lend,
    commit: commit_private,
    release,
};

static PUBLIC_FUNCS: Shadowed = Shadowed {
    funcs: shadow::FUNCS,
    item: public_shadow_it,
    new: new_key,
    free: free_key,
    lend,
    commit: commit_public,
    release,
};

/// An extern item through `funcs`.
const fn shadowed(funcs: &'static Shadowed, sname: &'static core::ffi::CStr) -> Item {
    item(
        ASN1_ITYPE_EXTERN,
        V_ASN1_SEQUENCE,
        ptr::null(),
        0,
        (&raw const funcs.funcs).cast(),
        0,
        sname,
    )
}

ffi_callback! {
    /// `rsa_pss_cb` and `rsa_oaep_cb`: freeing frees the decoded mask hash (`maskHash`, the
    /// last field of both).
    ///
    /// # Safety
    /// `pval` holds NULL or a live `RSA_PSS_PARAMS` or `RSA_OAEP_PARAMS`, per the item.
    pub(crate) unsafe extern "C" fn params_cb(operation: c_int, pval: *mut *mut ASN1_VALUE, it: *const ASN1_ITEM, _exarg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        if operation != ASN1_OP_FREE_PRE {
            return 1;
        }
        // SAFETY: the caller's guarantee.
        let v = unsafe { pval.read() };
        if v.is_null() {
            return 1;
        }
        let pss = ptr::eq(it, &raw const PSS.0);
        let mask_hash = if pss {
            // SAFETY: a live `RSA_PSS_PARAMS`.
            unsafe { (*v.cast::<RSA_PSS_PARAMS>()).maskHash }
        } else {
            // SAFETY: a live `RSA_OAEP_PARAMS`.
            unsafe { (*v.cast::<RSA_OAEP_PARAMS>()).maskHash }
        };
        // SAFETY: NULL or the structure's own.
        unsafe { X509_ALGOR_free(mask_hash) };
        1
    }
}

static PARAMS_AUX: Aux = aux(params_cb);

static PSS_TT: Templates<4> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(RSA_PSS_PARAMS, hashAlgorithm),
        c"hashAlgorithm",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(RSA_PSS_PARAMS, maskGenAlgorithm),
        c"maskGenAlgorithm",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(RSA_PSS_PARAMS, saltLength),
        c"saltLength",
        ASN1_INTEGER_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        3,
        offset_of!(RSA_PSS_PARAMS, trailerField),
        c"trailerField",
        ASN1_INTEGER_it,
    ),
]);

static OAEP_TT: Templates<3> = Templates([
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        0,
        offset_of!(RSA_OAEP_PARAMS, hashFunc),
        c"hashFunc",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        1,
        offset_of!(RSA_OAEP_PARAMS, maskGenFunc),
        c"maskGenFunc",
        X509_ALGOR_it,
    ),
    template_at(
        ASN1_TFLG_EXPLICIT | ASN1_TFLG_OPTIONAL,
        2,
        offset_of!(RSA_OAEP_PARAMS, pSourceFunc),
        c"pSourceFunc",
        X509_ALGOR_it,
    ),
]);

/// `RSA_PSS_PARAMS`' item, also for the callback to tell the structures apart.
static PSS: Item = sequence::<RSA_PSS_PARAMS, 4>(&PSS_TT, Some(&PARAMS_AUX), c"RSA_PSS_PARAMS");

item_fns! {
    /// RSAPublicKey: SEQUENCE { modulus INTEGER, publicExponent INTEGER }, over an `RSA`.
    pub unsafe extern "C" fn RSAPublicKey_it = shadowed(&PUBLIC_FUNCS, c"RSAPublicKey");
    /// RSAPrivateKey: SEQUENCE { version, the eight numbers, otherPrimeInfos OPTIONAL }, over
    /// an `RSA`.
    pub unsafe extern "C" fn RSAPrivateKey_it = shadowed(&PRIVATE_FUNCS, c"RSAPrivateKey");
    /// RSAES-OAEP-params: three explicitly tagged, optional fields.
    pub unsafe extern "C" fn RSA_OAEP_PARAMS_it = sequence::<RSA_OAEP_PARAMS, 3>(&OAEP_TT, Some(&PARAMS_AUX), c"RSA_OAEP_PARAMS");
}

ffi_export! {
    /// RSASSA-PSS-params: four explicitly tagged, optional fields.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RSA_PSS_PARAMS_it() -> *const ASN1_ITEM
    where failure = ptr::null(), library = ERR_LIB_ASN1
    {
        &raw const PSS.0
    }
}

i2d! {
    /// Encodes an RSA public key as PKCS #1's RSAPublicKey.
    pub unsafe extern "C" fn i2d_RSAPublicKey(RSA) = RSAPublicKey_it;
    /// Encodes an RSA private key as PKCS #1's RSAPrivateKey.
    pub unsafe extern "C" fn i2d_RSAPrivateKey(RSA) = RSAPrivateKey_it;
    /// Encodes RSASSA-PSS parameters.
    pub unsafe extern "C" fn i2d_RSA_PSS_PARAMS(RSA_PSS_PARAMS) = RSA_PSS_PARAMS_it;
    /// Encodes RSAES-OAEP parameters.
    pub unsafe extern "C" fn i2d_RSA_OAEP_PARAMS(RSA_OAEP_PARAMS) = RSA_OAEP_PARAMS_it;
}

d2i! {
    /// Decodes PKCS #1's RSAPublicKey (`ASN1_item_d2i`): n and e, into the key given if any.
    pub unsafe extern "C" fn d2i_RSAPublicKey(RSA) = RSAPublicKey_it;
    /// Decodes PKCS #1's RSAPrivateKey (`ASN1_item_d2i`), into the key given if any.
    pub unsafe extern "C" fn d2i_RSAPrivateKey(RSA) = RSAPrivateKey_it;
    /// Decodes RSASSA-PSS parameters (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_RSA_PSS_PARAMS(RSA_PSS_PARAMS) = RSA_PSS_PARAMS_it;
    /// Decodes RSAES-OAEP parameters (`ASN1_item_d2i`).
    pub unsafe extern "C" fn d2i_RSA_OAEP_PARAMS(RSA_OAEP_PARAMS) = RSA_OAEP_PARAMS_it;
}

new_free! {
    pub unsafe extern "C" fn RSA_PSS_PARAMS_new, pub unsafe extern "C" fn RSA_PSS_PARAMS_free(RSA_PSS_PARAMS) = RSA_PSS_PARAMS_it;
    pub unsafe extern "C" fn RSA_OAEP_PARAMS_new, pub unsafe extern "C" fn RSA_OAEP_PARAMS_free(RSA_OAEP_PARAMS) = RSA_OAEP_PARAMS_it;
}

ffi_export! {
    /// A copy of RSASSA-PSS parameters (`ASN1_item_dup`); the mask hash isn't encoded, so the
    /// copy has none.
    ///
    /// # Safety
    /// `a` is NULL or live parameters.
    pub unsafe extern "C" fn RSA_PSS_PARAMS_dup(a: *const RSA_PSS_PARAMS) -> *mut RSA_PSS_PARAMS
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSA_PSS_PARAMS_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, a.cast()) }.cast()
    }
}

ffi_export! {
    /// A new key with a copy of the key's n and e (`ASN1_item_dup` through RSAPublicKey).
    ///
    /// # Safety
    /// `rsa` is NULL or a live key.
    pub unsafe extern "C" fn RSAPublicKey_dup(rsa: *const RSA) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPublicKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, rsa.cast()) }.cast()
    }
}

ffi_export! {
    /// A new key with a copy of the key's numbers (`ASN1_item_dup` through RSAPrivateKey).
    ///
    /// # Safety
    /// `rsa` is NULL or a live key.
    pub unsafe extern "C" fn RSAPrivateKey_dup(rsa: *const RSA) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPrivateKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_dup(it, rsa.cast()) }.cast()
    }
}

ffi_export! {
    /// Reads an RSAPrivateKey from a BIO (`ASN1_item_d2i_bio`).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `rsa` is NULL or a slot for a key.
    pub unsafe extern "C" fn d2i_RSAPrivateKey_bio(bp: *mut BIO, rsa: *mut *mut RSA) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPrivateKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_d2i_bio(it, bp, rsa.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a key's RSAPrivateKey to a BIO (`ASN1_item_i2d_bio`). 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `rsa` is NULL or a live key.
    pub unsafe extern "C" fn i2d_RSAPrivateKey_bio(bp: *mut BIO, rsa: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPrivateKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d_bio(it, bp, rsa.cast()) }
    }
}

ffi_export! {
    /// Reads an RSAPublicKey from a BIO (`ASN1_item_d2i_bio`).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `rsa` is NULL or a slot for a key.
    pub unsafe extern "C" fn d2i_RSAPublicKey_bio(bp: *mut BIO, rsa: *mut *mut RSA) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPublicKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_d2i_bio(it, bp, rsa.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a key's RSAPublicKey to a BIO (`ASN1_item_i2d_bio`). 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `rsa` is NULL or a live key.
    pub unsafe extern "C" fn i2d_RSAPublicKey_bio(bp: *mut BIO, rsa: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPublicKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d_bio(it, bp, rsa.cast()) }
    }
}

ffi_export! {
    /// Reads an RSAPrivateKey from a file (`ASN1_item_d2i_fp`).
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `rsa` is NULL or a slot for a key.
    pub unsafe extern "C" fn d2i_RSAPrivateKey_fp(fp: *mut FILE, rsa: *mut *mut RSA) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPrivateKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_d2i_fp(it, fp, rsa.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a key's RSAPrivateKey to a file (`ASN1_item_i2d_fp`). 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `rsa` is NULL or a live key.
    pub unsafe extern "C" fn i2d_RSAPrivateKey_fp(fp: *mut FILE, rsa: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPrivateKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d_fp(it, fp, rsa.cast()) }
    }
}

ffi_export! {
    /// Reads an RSAPublicKey from a file (`ASN1_item_d2i_fp`).
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `rsa` is NULL or a slot for a key.
    pub unsafe extern "C" fn d2i_RSAPublicKey_fp(fp: *mut FILE, rsa: *mut *mut RSA) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPublicKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_d2i_fp(it, fp, rsa.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a key's RSAPublicKey to a file (`ASN1_item_i2d_fp`). 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `rsa` is NULL or a live key.
    pub unsafe extern "C" fn i2d_RSAPublicKey_fp(fp: *mut FILE, rsa: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: no preconditions.
        let it = unsafe { RSAPublicKey_it() };
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { ASN1_item_i2d_fp(it, fp, rsa.cast()) }
    }
}

#[cfg(test)]
mod tests {
    use rustyssl_abi::{ASN1_ITYPE_EXTERN, ASN1_ITYPE_SEQUENCE};

    use super::*;
    use crate::bn::{BN_get_word, BN_new, BN_set_word};
    use crate::err::ERR_clear_error;
    use crate::rsa_lib::{
        RSA_set0_crt_params, RSA_set0_factors, RSA_set0_key, RSA_set0_multi_prime_params,
        RSA_up_ref,
    };

    /// A new `BIGNUM` holding `w`.
    fn word(w: core::ffi::c_ulong) -> *mut BIGNUM {
        // SAFETY: no preconditions.
        let b = unsafe { BN_new() };
        // SAFETY: just made.
        assert_eq!(unsafe { BN_set_word(b, w) }, 1);
        b
    }

    /// A key with every number, and a third prime when `multi`.
    fn key(multi: bool) -> *mut RSA {
        // SAFETY: no preconditions.
        let r = unsafe { RSA_new() };
        // SAFETY: a live key; new numbers it takes.
        unsafe {
            assert_eq!(RSA_set0_key(r, word(0xc3), word(3), word(0x0d)), 1);
        }
        // SAFETY: as above.
        unsafe { assert_eq!(RSA_set0_factors(r, word(0x0b), word(7)), 1) };
        // SAFETY: as above.
        unsafe { assert_eq!(RSA_set0_crt_params(r, word(1), word(1), word(2)), 1) };
        if multi {
            let (mut ps, mut es, mut cs) = ([word(0x11)], [word(5)], [word(9)]);
            // SAFETY: as above; arrays of one number each.
            let set = unsafe {
                RSA_set0_multi_prime_params(r, ps.as_mut_ptr(), es.as_mut_ptr(), cs.as_mut_ptr(), 1)
            };
            assert_eq!(set, 1);
        }
        r
    }

    /// The key's RSAPrivateKey encoding.
    fn encode(r: *const RSA) -> Vec<u8> {
        let mut out: *mut core::ffi::c_uchar = ptr::null_mut();
        // SAFETY: a live key; the encoding is allocated.
        let len = unsafe { i2d_RSAPrivateKey(r, &raw mut out) };
        let len = usize::try_from(len).expect("encoded");
        // SAFETY: the encoding's `len` octets.
        let v = unsafe { core::slice::from_raw_parts(out, len) }.to_vec();
        // SAFETY: allocated by the encoder.
        unsafe { mem::release(out.cast()) };
        v
    }

    /// docs/DEVIATIONS.md: the key items are extern items over the handle, not SEQUENCEs; the
    /// parameter structures, whose layout is public, are SEQUENCEs.
    #[test]
    fn the_key_items_are_extern() {
        for it in [
            // SAFETY: no preconditions.
            unsafe { RSAPublicKey_it() },
            // SAFETY: as above.
            unsafe { RSAPrivateKey_it() },
        ] {
            // SAFETY: a static item.
            assert_eq!(c_int::from(unsafe { (*it).itype }), ASN1_ITYPE_EXTERN);
            // SAFETY: as above.
            assert!(unsafe { shadow::shadowed(it) }.is_some());
        }
        // SAFETY: as above.
        let pss = unsafe { RSA_PSS_PARAMS_it() };
        // SAFETY: a static item.
        assert_eq!(c_int::from(unsafe { (*pss).itype }), ASN1_ITYPE_SEQUENCE);
        // SAFETY: as above.
        assert!(unsafe { shadow::shadowed(pss) }.is_none());
    }

    #[test]
    fn a_three_prime_key_round_trips() {
        let r = key(true);
        let der = encode(r);
        let mut p = der.as_ptr();
        let len = core::ffi::c_long::try_from(der.len()).expect("short");
        // SAFETY: the encoding's octets.
        let back = unsafe { d2i_RSAPrivateKey(ptr::null_mut(), &raw mut p, len) };
        assert!(!back.is_null());
        // SAFETY: the key decoded.
        assert_eq!(unsafe { RSA_get_version(back) }, RSA_ASN1_VERSION_MULTI);
        assert_eq!(encode(back), der);
        // SAFETY: the two keys.
        unsafe { RSA_free(back) };
        // SAFETY: as above.
        unsafe { RSA_free(r) };
    }

    /// A decode that fails after writing into the key's own numbers: the key (still
    /// referenced by the caller) keeps them, and nothing is freed twice.
    #[test]
    fn a_failed_decode_leaves_the_key_its_numbers() {
        let r = key(true);
        // SAFETY: a live key.
        assert_eq!(unsafe { RSA_up_ref(r) }, 1);
        // SAFETY: as above.
        let n = unsafe { RSA_get0_n(r) };
        // version 0, n = 0x22, then an OCTET STRING where e belongs.
        let der = [
            0x30, 0x09, 0x02, 0x01, 0x00, 0x02, 0x01, 0x22, 0x04, 0x01, 0x00,
        ];
        let mut p = der.as_ptr();
        let mut slot = r;
        // SAFETY: the encoding's octets; a slot holding the key's reference.
        let got = unsafe { d2i_RSAPrivateKey(&raw mut slot, &raw mut p, 11) };
        assert!(got.is_null());
        assert!(slot.is_null(), "the slot's reference dropped");
        // SAFETY: the reference kept.
        assert_eq!(unsafe { RSA_get0_n(r) }, n, "the same BIGNUM");
        // SAFETY: the key's number.
        let w = unsafe { BN_get_word(n) };
        assert_eq!(w, 0x22, "decoded in place, as OpenSSL's is");
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_get_multi_prime_extra_count(r) }, 1);
        // SAFETY: the reference kept.
        unsafe { RSA_free(r) };
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
    }

    #[test]
    fn decoding_over_a_key_reuses_its_numbers_and_drops_the_other_primes() {
        let two = key(false);
        let der = encode(two);
        let r = key(true);
        // SAFETY: a live key.
        let d = unsafe { RSA_get0_d(r) };
        let mut p = der.as_ptr();
        let mut slot = r;
        let len = core::ffi::c_long::try_from(der.len()).expect("short");
        // SAFETY: the encoding's octets; a slot holding the key.
        let got = unsafe { d2i_RSAPrivateKey(&raw mut slot, &raw mut p, len) };
        assert_eq!(got, r);
        // SAFETY: the key.
        assert_eq!(unsafe { RSA_get0_d(r) }, d);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_get_multi_prime_extra_count(r) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_get_version(r) }, 0);
        assert_eq!(encode(r), der);
        // SAFETY: the two keys.
        unsafe { RSA_free(r) };
        // SAFETY: as above.
        unsafe { RSA_free(two) };
    }
}
