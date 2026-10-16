//! DSA's ASN.1 and PEM (`dsa_asn1.c`, `x_all.c`, `pem_all.c`): the traditional DSAPrivateKey
//! (version, p, q, g, the public and private keys), DSAparams (p, q, g), and DSAPublicKey (the
//! public key, then p, q, g), each a shadowed item over the `DSA` handle (as `RSAPrivateKey`
//! is) that OpenSSL keeps private, so only their `d2i`/`i2d` functions are exported; the
//! private key's BIO and FILE forms; DSAparams' PEM; and `DSAparams_dup`.
//!
//! As in OpenSSL, decoding into a key reuses its numbers and keeps what the encoding doesn't
//! carry; the private key's version is kept and written back; and all three items are named
//! "DSA" (the type their `ASN1_SEQUENCE_END_cb` names), as their errors say.

use core::ffi::{CStr, c_int, c_uchar, c_void};
use core::mem::offset_of;
use core::ptr;

use libc::FILE;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_ITYPE_EXTERN, ASN1_OP_FREE_PRE, ASN1_TFLG_EMBED, ASN1_VALUE, BIGNUM, BIO, DSA,
    ERR_LIB_ASN1, ERR_LIB_PEM, PEM_STRING_DSAPARAMS, V_ASN1_SEQUENCE, pem_password_cb,
};

use crate::asn1::tpl::bignum::{BIGNUM_it, CBIGNUM_it};
use crate::asn1::tpl::ints::INT32_it;
use crate::asn1::tpl::items::{d2i, i2d};
use crate::asn1::tpl::shadow::{self, Lend, Shadowed};
use crate::asn1::tpl::statics::{Aux, Templates, aux, sequence};
use crate::asn1::tpl::util::ASN1_item_dup;
use crate::asn1::tpl::{Item, item, template_at};
use crate::dsa::{
    DSA_free, DSA_get0_g, DSA_get0_p, DSA_get0_priv_key, DSA_get0_pub_key, DSA_get0_q, DSA_new,
    Field, dsa,
};
use crate::ffi::{ffi_callback, ffi_export};
use crate::mem;
use crate::pem_cipher::{PEM_ASN1_write, PEM_ASN1_write_bio};
use crate::pem_read::{PEM_ASN1_read, PEM_ASN1_read_bio};

/// The shadow of a `DSA`: the fields of OpenSSL's that the three items' templates name.
#[repr(C)]
struct Shadow {
    version: i32,
    p: *mut BIGNUM,
    q: *mut BIGNUM,
    g: *mut BIGNUM,
    pub_key: *mut BIGNUM,
    priv_key: *mut BIGNUM,
    /// The key's own numbers the fields were lent (p, q, g, the public and private keys),
    /// which freeing the shadow leaves alone.
    lent: [*mut BIGNUM; 5],
}

static PRIVATE_TT: Templates<6> = Templates([
    template_at(
        ASN1_TFLG_EMBED,
        0,
        offset_of!(Shadow, version),
        c"version",
        INT32_it,
    ),
    template_at(0, 0, offset_of!(Shadow, p), c"params.p", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, q), c"params.q", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, g), c"params.g", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, pub_key), c"pub_key", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, priv_key), c"priv_key", CBIGNUM_it),
]);

static PARAMS_TT: Templates<3> = Templates([
    template_at(0, 0, offset_of!(Shadow, p), c"params.p", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, q), c"params.q", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, g), c"params.g", BIGNUM_it),
]);

static PUBLIC_TT: Templates<4> = Templates([
    template_at(0, 0, offset_of!(Shadow, pub_key), c"pub_key", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, p), c"params.p", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, q), c"params.q", BIGNUM_it),
    template_at(0, 0, offset_of!(Shadow, g), c"params.g", BIGNUM_it),
]);

static SHADOW_AUX: Aux = aux(shadow_cb);

static PRIVATE_SHADOW: Item = sequence::<Shadow, 6>(&PRIVATE_TT, Some(&SHADOW_AUX), c"DSA");
static PARAMS_SHADOW: Item = sequence::<Shadow, 3>(&PARAMS_TT, Some(&SHADOW_AUX), c"DSA");
static PUBLIC_SHADOW: Item = sequence::<Shadow, 4>(&PUBLIC_TT, Some(&SHADOW_AUX), c"DSA");

extern "C" fn private_shadow_it() -> *const ASN1_ITEM {
    &raw const PRIVATE_SHADOW.0
}

extern "C" fn params_shadow_it() -> *const ASN1_ITEM {
    &raw const PARAMS_SHADOW.0
}

extern "C" fn public_shadow_it() -> *const ASN1_ITEM {
    &raw const PUBLIC_SHADOW.0
}

ffi_callback! {
    /// The shadows' callback: freeing leaves the key's own numbers.
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
        let lent = s.lent;
        for (slot, l) in [&mut s.p, &mut s.q, &mut s.g, &mut s.pub_key, &mut s.priv_key].into_iter().zip(lent) {
            if !l.is_null() && *slot == l {
                *slot = ptr::null_mut();
            }
        }
        1
    }
}

/// `DSA_new` as a handle.
unsafe fn new_key() -> *mut ASN1_VALUE {
    // SAFETY: no preconditions.
    unsafe { DSA_new() }.cast()
}

/// `DSA_free` of a handle.
///
/// # Safety
/// `h` is a live `DSA` whose reference the caller gives up.
unsafe fn free_key(h: *mut ASN1_VALUE) {
    // SAFETY: the caller's guarantee.
    unsafe { DSA_free(h.cast()) };
}

/// A shadow lending the key's numbers (and, for encoding, its version).
///
/// # Safety
/// `h` is NULL or a live `DSA`.
unsafe fn lend(h: *const ASN1_VALUE, how: Lend) -> *mut ASN1_VALUE {
    let s: *mut Shadow = mem::alloc_zeroed(size_of::<Shadow>()).cast();
    // SAFETY: a new block, or NULL.
    let Some(sh) = (unsafe { s.as_mut() }) else {
        return ptr::null_mut();
    };
    let d: *const DSA = h.cast();
    if d.is_null() {
        return s.cast();
    }
    // SAFETY: the caller's key (for each below).
    sh.p = unsafe { DSA_get0_p(d) }.cast_mut();
    // SAFETY: as above.
    sh.q = unsafe { DSA_get0_q(d) }.cast_mut();
    // SAFETY: as above.
    sh.g = unsafe { DSA_get0_g(d) }.cast_mut();
    // SAFETY: as above.
    sh.pub_key = unsafe { DSA_get0_pub_key(d) }.cast_mut();
    // SAFETY: as above.
    sh.priv_key = unsafe { DSA_get0_priv_key(d) }.cast_mut();
    sh.lent = [sh.p, sh.q, sh.g, sh.pub_key, sh.priv_key];
    if how == Lend::Encode {
        // SAFETY: as above.
        sh.version = unsafe { dsa(d) }.map_or(0, |k| k.lock().version);
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

/// Moves a decoded shadow's `fields` (and the version, for the private key) into the key.
///
/// # Safety
/// `h` is a live `DSA`; `s` a shadow decoded for it, whose numbers it takes.
unsafe fn commit_fields(h: *mut ASN1_VALUE, s: *mut ASN1_VALUE, fields: &[Field], version: bool) {
    // SAFETY: the caller's guarantee.
    let (Some(k), Some(sh)) = (unsafe { dsa(h.cast()) }, unsafe {
        s.cast::<Shadow>().as_ref()
    }) else {
        return;
    };
    let of = |f: Field| match f {
        Field::P => sh.p,
        Field::Q => sh.q,
        Field::G => sh.g,
        Field::Pub => sh.pub_key,
        Field::Priv => sh.priv_key,
    };
    let taken: Vec<(Field, *mut BIGNUM)> = fields.iter().map(|&f| (f, of(f))).collect();
    // SAFETY: the numbers decoded, each now the key's.
    unsafe { k.adopt(&taken) };
    if version {
        k.lock().version = sh.version;
    }
}

/// Commits a DSAPrivateKey.
///
/// # Safety
/// As for [`commit_fields`].
unsafe fn commit_private(h: *mut ASN1_VALUE, s: *mut ASN1_VALUE) {
    let all = [Field::P, Field::Q, Field::G, Field::Pub, Field::Priv];
    // SAFETY: the caller's guarantee.
    unsafe { commit_fields(h, s, &all, true) };
}

/// Commits DSAparams.
///
/// # Safety
/// As for [`commit_fields`].
unsafe fn commit_params(h: *mut ASN1_VALUE, s: *mut ASN1_VALUE) {
    // SAFETY: the caller's guarantee.
    unsafe { commit_fields(h, s, &[Field::P, Field::Q, Field::G], false) };
}

/// Commits a DSAPublicKey.
///
/// # Safety
/// As for [`commit_fields`].
unsafe fn commit_public(h: *mut ASN1_VALUE, s: *mut ASN1_VALUE) {
    let fields = [Field::Pub, Field::P, Field::Q, Field::G];
    // SAFETY: the caller's guarantee.
    unsafe { commit_fields(h, s, &fields, false) };
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

static PARAMS_FUNCS: Shadowed = Shadowed {
    funcs: shadow::FUNCS,
    item: params_shadow_it,
    new: new_key,
    free: free_key,
    lend,
    commit: commit_params,
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

static PRIVATE_ITEM: Item = item(
    ASN1_ITYPE_EXTERN,
    V_ASN1_SEQUENCE,
    ptr::null(),
    0,
    (&raw const PRIVATE_FUNCS.funcs).cast(),
    0,
    c"DSA",
);

static PARAMS_ITEM: Item = item(
    ASN1_ITYPE_EXTERN,
    V_ASN1_SEQUENCE,
    ptr::null(),
    0,
    (&raw const PARAMS_FUNCS.funcs).cast(),
    0,
    c"DSA",
);

static PUBLIC_ITEM: Item = item(
    ASN1_ITYPE_EXTERN,
    V_ASN1_SEQUENCE,
    ptr::null(),
    0,
    (&raw const PUBLIC_FUNCS.funcs).cast(),
    0,
    c"DSA",
);

/// `DSAPrivateKey_it` (OpenSSL's is private).
extern "C" fn dsa_private_key_it() -> *const ASN1_ITEM {
    &raw const PRIVATE_ITEM.0
}

/// `DSAparams_it` (OpenSSL's is private).
extern "C" fn dsa_params_it() -> *const ASN1_ITEM {
    &raw const PARAMS_ITEM.0
}

/// `DSAPublicKey_it` (OpenSSL's is private).
extern "C" fn dsa_public_key_it() -> *const ASN1_ITEM {
    &raw const PUBLIC_ITEM.0
}

i2d! {
    /// Encodes a key as the traditional DSAPrivateKey.
    pub unsafe extern "C" fn i2d_DSAPrivateKey(DSA) = dsa_private_key_it;
    /// Encodes a key's parameters as DSAparams.
    pub unsafe extern "C" fn i2d_DSAparams(DSA) = dsa_params_it;
    /// Encodes a key as DSAPublicKey (the public key, then p, q, g).
    pub unsafe extern "C" fn i2d_DSAPublicKey(DSA) = dsa_public_key_it;
}

d2i! {
    /// Decodes the traditional DSAPrivateKey, into the key given if any.
    pub unsafe extern "C" fn d2i_DSAPrivateKey(DSA) = dsa_private_key_it;
    /// Decodes DSAparams, into the key given if any.
    pub unsafe extern "C" fn d2i_DSAparams(DSA) = dsa_params_it;
    /// Decodes DSAPublicKey, into the key given if any.
    pub unsafe extern "C" fn d2i_DSAPublicKey(DSA) = dsa_public_key_it;
}

ffi_export! {
    /// A copy of the key's parameters (through their encoding), or NULL.
    ///
    /// # Safety
    /// `dsa` is NULL or a live key.
    pub unsafe extern "C" fn DSAparams_dup(dsa: *const DSA) -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the item; the caller's key.
        unsafe { ASN1_item_dup(dsa_params_it(), dsa.cast_mut().cast()) }.cast()
    }
}

ffi_export! {
    /// Reads a DSAPrivateKey from a BIO (`ASN1_item_d2i_bio`).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `dsa` is NULL or a slot for a key.
    pub unsafe extern "C" fn d2i_DSAPrivateKey_bio(bp: *mut BIO, dsa: *mut *mut DSA) -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::io::ASN1_item_d2i_bio(dsa_private_key_it(), bp, dsa.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a key's DSAPrivateKey to a BIO (`ASN1_item_i2d_bio`). 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `dsa` is NULL or a live key.
    pub unsafe extern "C" fn i2d_DSAPrivateKey_bio(bp: *mut BIO, dsa: *const DSA) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::io::ASN1_item_i2d_bio(dsa_private_key_it(), bp, dsa.cast()) }
    }
}

ffi_export! {
    /// Reads a DSAPrivateKey from a file (`ASN1_item_d2i_fp`).
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `dsa` is NULL or a slot for a key.
    pub unsafe extern "C" fn d2i_DSAPrivateKey_fp(fp: *mut FILE, dsa: *mut *mut DSA) -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::io::ASN1_item_d2i_fp(dsa_private_key_it(), fp, dsa.cast()) }.cast()
    }
}

ffi_export! {
    /// Writes a key's DSAPrivateKey to a file (`ASN1_item_i2d_fp`). 1, or 0.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; `dsa` is NULL or a live key.
    pub unsafe extern "C" fn i2d_DSAPrivateKey_fp(fp: *mut FILE, dsa: *const DSA) -> c_int
    where failure = 0, library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee; the type's item.
        unsafe { crate::asn1::tpl::io::ASN1_item_i2d_fp(dsa_private_key_it(), fp, dsa.cast()) }
    }
}

type I2dOfVoid = unsafe extern "C" fn(*const c_void, *mut *mut c_uchar) -> c_int;
type D2iOfVoid =
    unsafe extern "C" fn(*mut *mut c_void, *mut *const c_uchar, core::ffi::c_long) -> *mut c_void;

/// `i2d_DSAparams` as `i2d_of_void`.
unsafe extern "C" fn i2d_params_void(x: *const c_void, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { i2d_DSAparams(x.cast(), pp) }
}

/// `d2i_DSAparams` as `d2i_of_void`.
unsafe extern "C" fn d2i_params_void(
    a: *mut *mut c_void,
    pp: *mut *const c_uchar,
    len: core::ffi::c_long,
) -> *mut c_void {
    // SAFETY: the caller's guarantee.
    unsafe { d2i_DSAparams(a.cast(), pp, len) }.cast()
}

/// The PEM name of DSAparams.
const NAME: &CStr = PEM_STRING_DSAPARAMS;

ffi_export! {
    /// Writes a key's parameters as PEM ("DSA PARAMETERS").
    ///
    /// # Safety
    /// `out` is a live BIO; `x` a live key.
    pub unsafe extern "C" fn PEM_write_bio_DSAparams(out: *mut BIO, x: *const DSA) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        let f: I2dOfVoid = i2d_params_void;
        // SAFETY: the caller's guarantee; no encryption.
        unsafe { PEM_ASN1_write_bio(Some(f), NAME.as_ptr(), out, x.cast(), ptr::null(), ptr::null(), 0, None, ptr::null_mut()) }
    }
}

ffi_export! {
    /// `PEM_write_bio_DSAparams` to a FILE.
    ///
    /// # Safety
    /// `out` is a live FILE; `x` a live key.
    pub unsafe extern "C" fn PEM_write_DSAparams(out: *mut FILE, x: *const DSA) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        let f: I2dOfVoid = i2d_params_void;
        // SAFETY: the caller's guarantee; no encryption.
        unsafe { PEM_ASN1_write(Some(f), NAME.as_ptr(), out, x.cast(), ptr::null(), ptr::null(), 0, None, ptr::null_mut()) }
    }
}

ffi_export! {
    /// Reads DSA parameters from PEM, into the key given if any.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or holds NULL or a live key; `cb` is called with `u`.
    pub unsafe extern "C" fn PEM_read_bio_DSAparams(bp: *mut BIO, x: *mut *mut DSA, cb: pem_password_cb, u: *mut c_void) -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        let f: D2iOfVoid = d2i_params_void;
        // SAFETY: the caller's guarantee.
        unsafe { PEM_ASN1_read_bio(Some(f), NAME.as_ptr(), bp, x.cast(), cb, u) }.cast()
    }
}

ffi_export! {
    /// `PEM_read_bio_DSAparams` from a FILE.
    ///
    /// # Safety
    /// As for `PEM_read_bio_DSAparams`, with a live FILE.
    pub unsafe extern "C" fn PEM_read_DSAparams(fp: *mut FILE, x: *mut *mut DSA, cb: pem_password_cb, u: *mut c_void) -> *mut DSA
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        let f: D2iOfVoid = d2i_params_void;
        // SAFETY: the caller's guarantee.
        unsafe { PEM_ASN1_read(Some(f), NAME.as_ptr(), fp, x.cast(), cb, u) }.cast()
    }
}
