//! RSA keys in `EVP_PKEY` (`EVP_PKEY_set1_RSA(3)`; `p_legacy.c`, `rsa_ameth.c`): the built-in
//! RSA and RSA-PSS ASN.1 methods' functions for a key whose legacy data is an `RSA`, and the
//! `RSA` of a key, made from a provided key's data when it has none (cached, as OpenSSL's
//! `legacy_cache_pkey`).
//!
//! As in OpenSSL, a legacy RSA key reaches the providers through a copy of its numbers
//! (`export_to`), remade when the `RSA` changes (`dirty_cnt`), and a provided key's `RSA` is a
//! copy too (`import_from`): the `RSA` and the provider's key are separate objects.

use core::ffi::{CStr, c_int, c_long, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_PCTX, ASN1_PKEY_CTRL_DEFAULT_MD_NID, BIGNUM, BIO, ERR_LIB_EVP, ERR_LIB_RSA, EVP_PKEY,
    EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_R_EXPECTING_AN_RSA_KEY, NID_sha256, OSSL_CALLBACK,
    OSSL_KEYMGMT_SELECT_ALL, OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS, OSSL_KEYMGMT_SELECT_PRIVATE_KEY,
    OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, OSSL_PARAM, RSA, RSA_METHOD_FLAG_NO_CHECK,
};

use super::{EVP_PKEY_assign, get_legacy, legacy_data, pkey};
use crate::bio::BIO_indent;
use crate::bio::print::BIO_printf;
use crate::bn::BN_num_bits;
use crate::bn::conv::ASN1_bn_print;
use crate::err;
use crate::ffi::{ffi_callback, ffi_export};
use crate::provider::rsa_kmgmt::{rsa_dup, rsa_export, rsa_import};
use crate::rsa::{Kind, Rsa, free, rsa, up_ref};
use crate::rsa_lib::{
    RSA_bits, RSA_flags, RSA_get_multi_prime_extra_count, RSA_get0_d, RSA_get0_dmp1, RSA_get0_dmq1,
    RSA_get0_e, RSA_get0_iqmp, RSA_get0_multi_prime_crt_params, RSA_get0_multi_prime_factors,
    RSA_get0_n, RSA_get0_p, RSA_get0_q, RSA_security_bits, RSA_size,
};
use crate::rsa_ops::RSA_check_key_ex;

/// The key's legacy data as an `RSA` (NULL without).
///
/// # Safety
/// `p` is NULL or a live key.
unsafe fn data(p: *const EVP_PKEY) -> *mut RSA {
    // SAFETY: the caller's guarantee.
    unsafe { legacy_data(p) }.cast()
}

/// `rsa_pub_cmp`: the same modulus and public exponent (1), unless a method asks for no check.
pub(crate) unsafe extern "C" fn rsa_pub_cmp(a: *const EVP_PKEY, b: *const EVP_PKEY) -> c_int {
    // SAFETY: the keys the caller compares.
    let ra = unsafe { data(a) };
    // SAFETY: as above.
    let rb = unsafe { data(b) };
    // SAFETY: their `RSA`s, or NULL.
    let no_check = |r: *mut RSA| unsafe { RSA_flags(r) } & RSA_METHOD_FLAG_NO_CHECK != 0;
    if no_check(ra) || no_check(rb) {
        return 1;
    }
    // SAFETY: as above.
    let (Some(ka), Some(kb)) = (unsafe { rsa(ra) }, unsafe { rsa(rb) }) else {
        return 0;
    };
    let (sa, sb) = (ka.snapshot().key, kb.snapshot().key);
    c_int::from(sa.n == sb.n && sa.e == sb.e)
}

/// `int_rsa_size`.
pub(crate) unsafe extern "C" fn int_rsa_size(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { RSA_size(r) }
}

/// `rsa_bits`.
pub(crate) unsafe extern "C" fn rsa_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { RSA_bits(r) }
}

/// `rsa_security_bits`.
pub(crate) unsafe extern "C" fn rsa_security_bits(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { RSA_security_bits(r) }
}

/// `int_rsa_free`: drops the key's reference to its `RSA`.
pub(crate) unsafe extern "C" fn int_rsa_free(p: *mut EVP_PKEY) {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { free(r) };
}

/// `rsa_pkey_ctrl`: the default digest is SHA-256 (decoded RSASSA-PSS parameters, which
/// would name theirs, come with the ASN.1 items); other controls -2.
pub(crate) unsafe extern "C" fn rsa_pkey_ctrl(
    _p: *mut EVP_PKEY,
    op: c_int,
    _arg1: c_long,
    arg2: *mut c_void,
) -> c_int {
    if op != ASN1_PKEY_CTRL_DEFAULT_MD_NID {
        return -2;
    }
    if !arg2.is_null() {
        // SAFETY: the control's `int *`.
        unsafe { arg2.cast::<c_int>().write(NID_sha256) };
    }
    1
}

/// `rsa_pkey_check`: `RSA_check_key_ex`.
pub(crate) unsafe extern "C" fn rsa_pkey_check(p: *const EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { RSA_check_key_ex(r, ptr::null_mut()) }
}

/// `rsa_pkey_copy`: `to` gets a copy of `from`'s `RSA`. 1, or 0.
pub(crate) unsafe extern "C" fn rsa_pkey_copy(to: *mut EVP_PKEY, from: *mut EVP_PKEY) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(from) };
    let dup = if r.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: a live key's data.
        let d = unsafe { rsa_dup(r.cast_const().cast(), OSSL_KEYMGMT_SELECT_ALL as c_int) };
        if d.is_null() {
            return 0;
        }
        d
    };
    // SAFETY: the caller's key.
    let type_ = unsafe { pkey(from) }.map_or(EVP_PKEY_RSA, super::Pkey::type_);
    // SAFETY: as above; the copy, which `to` takes.
    let ret = unsafe { EVP_PKEY_assign(to, type_, dup) };
    if ret == 0 {
        // SAFETY: the copy made above.
        unsafe { free(dup.cast()) };
    }
    ret
}

/// `rsa_pkey_dirty_cnt`.
pub(crate) unsafe fn rsa_pkey_dirty_cnt(p: *const EVP_PKEY) -> usize {
    // SAFETY: the method's key.
    let r = unsafe { data(p) };
    // SAFETY: its `RSA`, or NULL.
    unsafe { rsa(r) }.map_or(0, Rsa::dirty_cnt)
}

/// What `rsa_pkey_export_to`'s callback hands the importer.
struct Exporting<'a> {
    selection: c_int,
    importer: &'a mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int,
}

/// The key manager's export callback: the parameters to the importer.
unsafe extern "C" fn exported(params: *const OSSL_PARAM, arg: *mut c_void) -> c_int {
    // SAFETY: `rsa_pkey_export_to`'s `Exporting`, live for the call.
    let Some(e) = (unsafe { arg.cast::<Exporting<'_>>().as_mut() }) else {
        return 0;
    };
    (e.importer)(e.selection, params)
}

/// `rsa_int_export_to`: the public key (and the private key, and an RSA-PSS key's
/// restrictions, when it has them) to `importer`.
pub(crate) unsafe fn rsa_pkey_export_to(
    from: *const EVP_PKEY,
    importer: &mut dyn FnMut(c_int, *const OSSL_PARAM) -> c_int,
) -> c_int {
    // SAFETY: the method's key.
    let r = unsafe { data(from) };
    // SAFETY: its `RSA`.
    let Some(k) = (unsafe { rsa(r) }) else {
        return 0;
    };
    let st = k.snapshot();
    if st.key.n.is_none() || st.key.e.is_none() {
        return 0;
    }
    let mut selection = OSSL_KEYMGMT_SELECT_PUBLIC_KEY as c_int;
    if st.key.d.is_some() {
        selection |= OSSL_KEYMGMT_SELECT_PRIVATE_KEY as c_int;
    }
    if st.pss.restricted() {
        selection |= OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS as c_int;
    }
    let mut e = Exporting {
        selection,
        importer,
    };
    let cb: OSSL_CALLBACK = Some(exported);
    // SAFETY: the `RSA` as key data; the callback takes `e`, which outlives the call.
    unsafe { rsa_export(r.cast(), selection, cb, (&raw mut e).cast()) }
}

/// `rsa_int_import_from`: a new `RSA` of `kind` in `libctx` from `params`, assigned to `to`.
///
/// # Safety
/// `params` is a parameter array; `to` is a live key.
unsafe fn import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
    kind: Kind,
) -> c_int {
    let r = Rsa::new_handle_in(libctx, kind);
    if r.is_null() {
        return 0;
    }
    // SAFETY: the key just made; the caller's array.
    let mut ok = unsafe { rsa_import(r.cast(), OSSL_KEYMGMT_SELECT_ALL as c_int, params) } != 0;
    if ok {
        let type_ = if kind == Kind::Rsa {
            EVP_PKEY_RSA
        } else {
            EVP_PKEY_RSA_PSS
        };
        // SAFETY: the caller's key; the `RSA`, which it takes.
        ok = unsafe { EVP_PKEY_assign(to, type_, r.cast()) } != 0;
    }
    if !ok {
        // SAFETY: the key made above.
        unsafe { free(r) };
    }
    c_int::from(ok)
}

/// `rsa_pkey_import_from`.
pub(crate) unsafe fn rsa_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { import_from(params, to, libctx, Kind::Rsa) }
}

/// `rsa_pss_pkey_import_from`.
pub(crate) unsafe fn rsa_pss_pkey_import_from(
    params: *const OSSL_PARAM,
    to: *mut EVP_PKEY,
    libctx: *mut OSSL_LIB_CTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { import_from(params, to, libctx, Kind::RsaPss) }
}

/// `evp_pkey_get0_RSA_int`: the key's `RSA` (a provided key's made and cached), or NULL with
/// `EVP_R_EXPECTING_AN_RSA_KEY` for another type.
///
/// # Safety
/// `p` is NULL or a live key.
pub(crate) unsafe fn get0_rsa(p: *const EVP_PKEY) -> *mut RSA {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { pkey(p) }) else {
        return ptr::null_mut();
    };
    let t = k.type_();
    if t != EVP_PKEY_RSA && t != EVP_PKEY_RSA_PSS {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_EXPECTING_AN_RSA_KEY,
            "evp_pkey_get0_RSA_int",
        );
        return ptr::null_mut();
    }
    get_legacy(k).cast()
}

ffi_export! {
    /// Gives the key `key` (with a reference of its own) as RSA legacy data. 1, or 0.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key; `key` is NULL or a live `RSA`.
    pub unsafe extern "C" fn EVP_PKEY_set1_RSA(pkey: *mut EVP_PKEY, key: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        if !unsafe { up_ref(key) } {
            return 0;
        }
        // SAFETY: as above; the reference taken, which the key keeps on success.
        let ret = unsafe { EVP_PKEY_assign(pkey, EVP_PKEY_RSA, key.cast()) };
        if ret == 0 {
            // SAFETY: the reference taken above.
            unsafe { free(key) };
        }
        ret
    }
}

ffi_export! {
    /// The key's `RSA` (made from a provided key's data, and kept with the key), or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get0_RSA(pkey: *const EVP_PKEY) -> *const RSA
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { get0_rsa(pkey) }
    }
}

ffi_export! {
    /// The key's `RSA` with a reference for the caller, or NULL.
    ///
    /// # Safety
    /// `pkey` is NULL or a live key.
    pub unsafe extern "C" fn EVP_PKEY_get1_RSA(pkey: *mut EVP_PKEY) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe { get0_rsa(pkey) };
        // SAFETY: the key's `RSA`, or NULL.
        if r.is_null() || !unsafe { up_ref(r) } {
            return ptr::null_mut();
        }
        r
    }
}

/// `BIO_indent(bp, off, 128)`, as a success.
///
/// # Safety
/// `bp` is NULL or a live BIO.
unsafe fn indent(bp: *mut BIO, off: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { BIO_indent(bp, off, 128) }) != 0
}

/// `ASN1_bn_print(bp, label, bn, NULL, off)`, as a success.
///
/// # Safety
/// `bp` is NULL or a live BIO; `bn` is NULL or a live number.
unsafe fn number(bp: *mut BIO, label: &CStr, bn: *const BIGNUM, off: c_int) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { ASN1_bn_print(bp, label.as_ptr(), bn, ptr::null_mut(), off) }) != 0
}

/// `pkey_rsa_print`: the key's size, its numbers (the private ones too with `private` when it
/// has d), and an RSA-PSS key's parameter restrictions, each line indented by `off`.
///
/// # Safety
/// `bp` is NULL or a live BIO; `p` is a live key whose legacy data is an `RSA`.
unsafe fn pkey_rsa_print(bp: *mut BIO, p: *const EVP_PKEY, off: c_int, private: bool) -> bool {
    // SAFETY: the caller's guarantee.
    let r = unsafe { data(p) }.cast_const();
    if r.is_null() {
        return false;
    }
    // SAFETY: the key's `RSA`.
    let n = unsafe { RSA_get0_n(r) };
    let mod_len = if n.is_null() {
        0
    } else {
        // SAFETY: its modulus.
        unsafe { BN_num_bits(n) }
    };
    // SAFETY: as above.
    let ex_primes = unsafe { RSA_get_multi_prime_extra_count(r) };
    // SAFETY: the caller's key.
    let pss = unsafe { pkey(p) }.is_some_and(|k| k.type_() == EVP_PKEY_RSA_PSS);
    let name = if pss { c"RSA-PSS" } else { c"RSA" };
    // SAFETY: as above.
    if !unsafe { indent(bp, off) }
        // SAFETY: the caller's BIO; the format takes a string.
        || unsafe { BIO_printf(bp, c"%s ".as_ptr(), name.as_ptr()) } <= 0
    {
        return false;
    }
    // SAFETY: as above.
    let d = unsafe { RSA_get0_d(r) };
    let (modulus, exponent) = if private && !d.is_null() {
        let primes = if ex_primes <= 0 {
            2
        } else {
            ex_primes.saturating_add(2)
        };
        let f = c"Private-Key: (%d bit, %d primes)\n";
        // SAFETY: as above; the format takes two ints.
        if unsafe { BIO_printf(bp, f.as_ptr(), mod_len, primes) } <= 0 {
            return false;
        }
        (c"modulus:", c"publicExponent:")
    } else {
        // SAFETY: as above; the format takes an int.
        if unsafe { BIO_printf(bp, c"Public-Key: (%d bit)\n".as_ptr(), mod_len) } <= 0 {
            return false;
        }
        (c"Modulus:", c"Exponent:")
    };
    // SAFETY: as above.
    let e = unsafe { RSA_get0_e(r) };
    // SAFETY: the BIO and the key's numbers.
    if !unsafe { number(bp, modulus, n, off) } || !unsafe { number(bp, exponent, e, off) } {
        return false;
    }
    if private {
        let getters: [(&CStr, unsafe extern "C" fn(*const RSA) -> *const BIGNUM); 6] = [
            (c"privateExponent:", RSA_get0_d),
            (c"prime1:", RSA_get0_p),
            (c"prime2:", RSA_get0_q),
            (c"exponent1:", RSA_get0_dmp1),
            (c"exponent2:", RSA_get0_dmq1),
            (c"coefficient:", RSA_get0_iqmp),
        ];
        for (label, get) in getters {
            // SAFETY: the key's `RSA`.
            let b = unsafe { get(r) };
            // SAFETY: the BIO and the key's number.
            if !unsafe { number(bp, label, b, off) } {
                return false;
            }
        }
        // SAFETY: the extra primes' numbers.
        if !unsafe { print_extra_primes(bp, r, ex_primes, off) } {
            return false;
        }
    }
    if pss {
        // `rsa_pss_param_print` for a key without restrictions: decoding a key's restrictions
        // (`RSA_get0_pss_params`) comes with the key decoders.
        // SAFETY: as above.
        if !unsafe { indent(bp, off) }
            // SAFETY: as above.
            || unsafe { BIO_printf(bp, c"No PSS parameter restrictions\n".as_ptr()) } <= 0
        {
            return false;
        }
    }
    true
}

/// The extra primes, their exponents, and their coefficients (`prime3:` ...).
///
/// # Safety
/// `bp` is NULL or a live BIO; `r` a live key with `count` extra primes.
unsafe fn print_extra_primes(bp: *mut BIO, r: *const RSA, count: c_int, off: c_int) -> bool {
    let Ok(n) = usize::try_from(count) else {
        return true;
    };
    if n == 0 {
        return true;
    }
    let mut primes = vec![ptr::null::<BIGNUM>(); n];
    let mut exps = vec![ptr::null::<BIGNUM>(); n];
    let mut coeffs = vec![ptr::null::<BIGNUM>(); n];
    // SAFETY: room for every extra prime.
    if unsafe { RSA_get0_multi_prime_factors(r, primes.as_mut_ptr()) } == 0 {
        return false;
    }
    // SAFETY: as above.
    if unsafe { RSA_get0_multi_prime_crt_params(r, exps.as_mut_ptr(), coeffs.as_mut_ptr()) } == 0 {
        return false;
    }
    for (i, ((&p, &e), &c)) in primes.iter().zip(&exps).zip(&coeffs).enumerate() {
        let index = c_int::try_from(i).unwrap_or(c_int::MAX).saturating_add(3);
        for (format, b) in [
            (c"prime%d:", p),
            (c"exponent%d:", e),
            (c"coefficient%d:", c),
        ] {
            // SAFETY: as above.
            if !unsafe { indent(bp, off) }
                // SAFETY: as above; the format takes an int.
                || unsafe { BIO_printf(bp, format.as_ptr(), index) } <= 0
                // SAFETY: the BIO and the key's number.
                || !unsafe { number(bp, c"", b, off) }
            {
                return false;
            }
        }
    }
    true
}

ffi_callback! {
    /// `rsa_pub_print`.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `p` a live key whose legacy data is an `RSA`.
    pub(crate) unsafe extern "C" fn rsa_pub_print(bp: *mut BIO, p: *const EVP_PKEY, indent: c_int, _ctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { pkey_rsa_print(bp, p, indent, false) })
    }
}

ffi_callback! {
    /// `rsa_priv_print`.
    ///
    /// # Safety
    /// As for [`rsa_pub_print`].
    pub(crate) unsafe extern "C" fn rsa_priv_print(bp: *mut BIO, p: *const EVP_PKEY, indent: c_int, _ctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { pkey_rsa_print(bp, p, indent, true) })
    }
}

ffi_export! {
    /// Prints a key as `EVP_PKEY_print_private` prints it in an RSA `EVP_PKEY`. 1, or 0.
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `x` is NULL or a live key.
    pub unsafe extern "C" fn RSA_print(bp: *mut BIO, x: *const RSA, off: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: no preconditions.
        let pk = unsafe { super::EVP_PKEY_new() };
        if pk.is_null() {
            return 0;
        }
        // SAFETY: a new key; the caller's `RSA`, which it references.
        let mut ret = unsafe { EVP_PKEY_set1_RSA(pk, x.cast_mut()) };
        if ret != 0 {
            // SAFETY: the caller's BIO; the key.
            ret = unsafe { super::print::EVP_PKEY_print_private(bp, pk, off, ptr::null_mut()) };
        }
        // SAFETY: the key made above.
        unsafe { super::EVP_PKEY_free(pk) };
        ret
    }
}

ffi_export! {
    /// [`RSA_print`] to a `FILE`, which stays open. 1, or 0.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `x` is NULL or a live key.
    pub unsafe extern "C" fn RSA_print_fp(fp: *mut libc::FILE, x: *const RSA, off: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { crate::bio::file::BIO_new_fp(fp, rustyssl_abi::BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_RSA, rustyssl_abi::ERR_R_BUF_LIB, "RSA_print_fp");
            return 0;
        }
        // SAFETY: the BIO; the caller's key.
        let ret = unsafe { RSA_print(b, x, off) };
        // SAFETY: the BIO made above.
        unsafe { crate::bio::BIO_free(b) };
        ret
    }
}
