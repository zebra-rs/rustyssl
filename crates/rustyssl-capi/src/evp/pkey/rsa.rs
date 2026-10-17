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
    RSA_PKCS1_PSS_PADDING, RSA_PSS_SALTLEN_AUTO, RSA_PSS_SALTLEN_AUTO_DIGEST_MAX,
    RSA_PSS_SALTLEN_DIGEST, RSA_PSS_SALTLEN_MAX, RSA_R_DIGEST_DOES_NOT_MATCH,
    RSA_R_INVALID_PSS_PARAMETERS, RSA_R_UNSUPPORTED_SIGNATURE_TYPE, V_ASN1_SEQUENCE,
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
    if ok && kind == Kind::RsaPss {
        // A restricted key's RSASSA-PSS-params too (`rsa->pss`), which its legacy encoding
        // writes.
        // SAFETY: the key just made.
        ok = unsafe { set_legacy_pss(r) };
    }
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

/// `rsa_int_import_from`'s `ossl_rsa_pss_params_create` of a restricted RSA-PSS key's digests
/// and salt length (the digests by their NIDs' names), set as its `RSA_PSS_PARAMS`. False if
/// it can't be made.
///
/// # Safety
/// `r` is a live key.
unsafe fn set_legacy_pss(r: *mut RSA) -> bool {
    use crate::evp::legacy_md::EVP_get_digestbyname;
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { crate::rsa::rsa(r) }) else {
        return false;
    };
    let pss = k.lock().pss;
    if !pss.restricted() {
        return true;
    }
    let digest = |nid: c_int| {
        // SAFETY: a number.
        let sn = unsafe { crate::objects::OBJ_nid2sn(nid) };
        // SAFETY: NULL or a static name.
        unsafe { EVP_get_digestbyname(sn) }
    };
    let (md, mgf1md) = (digest(pss.hash), digest(pss.mask_gen_hash));
    // SAFETY: the digests, or NULL.
    let params = unsafe { crate::rsa_pmeth::pss_params_create(md, mgf1md, pss.salt_len) };
    if params.is_null() {
        return false;
    }
    k.set_pss_params(params);
    true
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
        // SAFETY: the key's `RSA`.
        let params = unsafe { crate::rsa::rsa(r) }.map_or(ptr::null_mut(), |k| k.legacy().pss.0);
        // SAFETY: the BIO; the key's restrictions or NULL.
        if !unsafe { pss_param_print(bp, true, params, off) } {
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

/// `BIO_puts`, as a success.
///
/// # Safety
/// `bp` is NULL or a live BIO.
unsafe fn puts(bp: *mut BIO, text: &CStr) -> bool {
    // SAFETY: the caller's guarantee.
    (unsafe { crate::bio::BIO_puts(bp, text.as_ptr()) }) > 0
}

/// `rsa_pss_param_print`: a key's restrictions (`pss_key`) or a signature's parameters, each
/// field or its default.
///
/// # Safety
/// `bp` is NULL or a live BIO; `pss` is NULL or live parameters.
pub(crate) unsafe fn pss_param_print(
    bp: *mut BIO,
    pss_key: bool,
    pss: *const rustyssl_abi::RSA_PSS_PARAMS,
    off: c_int,
) -> bool {
    use crate::asn1::integer::i2a_ASN1_INTEGER;
    use crate::objects::i2a_ASN1_OBJECT;
    // SAFETY: the caller's guarantee.
    if !unsafe { indent(bp, off) } {
        return false;
    }
    // SAFETY: as above.
    let Some(p) = (unsafe { pss.as_ref() }) else {
        let text = if pss_key {
            c"No PSS parameter restrictions\n"
        } else {
            c"(INVALID PSS PARAMETERS)\n"
        };
        // SAFETY: as above.
        return unsafe { puts(bp, text) };
    };
    // SAFETY: as above.
    if pss_key && !unsafe { puts(bp, c"PSS parameter restrictions:") } {
        return false;
    }
    // SAFETY: as above.
    if !unsafe { puts(bp, c"\n") } {
        return false;
    }
    let off = if pss_key { off.saturating_add(2) } else { off };
    // SAFETY: as above.
    if !unsafe { indent(bp, off) } || !unsafe { puts(bp, c"Hash Algorithm: ") } {
        return false;
    }
    // SAFETY: the parameters' AlgorithmIdentifiers, objects, and INTEGERs, each live.
    let ok = if let Some(h) = unsafe { p.hashAlgorithm.as_ref() } {
        // SAFETY: as above.
        (unsafe { i2a_ASN1_OBJECT(bp, h.algorithm) }) > 0
    } else {
        // SAFETY: as above.
        unsafe { puts(bp, c"sha1 (default)") }
    };
    // SAFETY: as above.
    if !ok || !unsafe { puts(bp, c"\n") } || !unsafe { indent(bp, off) } {
        return false;
    }
    // SAFETY: as above.
    if !unsafe { puts(bp, c"Mask Algorithm: ") } {
        return false;
    }
    // SAFETY: as above.
    let ok = if let Some(m) = unsafe { p.maskGenAlgorithm.as_ref() } {
        // SAFETY: as above.
        if unsafe { i2a_ASN1_OBJECT(bp, m.algorithm) } <= 0 || !unsafe { puts(bp, c" with ") } {
            return false;
        }
        // SAFETY: as above.
        let hash = unsafe { crate::rsa_pmeth::mgf1_decode(m) };
        let ok = if hash.is_null() {
            // SAFETY: as above.
            unsafe { puts(bp, c"INVALID") }
        } else {
            // SAFETY: the decoded AlgorithmIdentifier.
            let obj = unsafe { (*hash).algorithm };
            // SAFETY: its object.
            (unsafe { i2a_ASN1_OBJECT(bp, obj) }) > 0
        };
        // SAFETY: NULL or the decoded AlgorithmIdentifier.
        unsafe { crate::asn1::tpl::items::X509_ALGOR_free(hash) };
        ok
    } else {
        // SAFETY: as above.
        unsafe { puts(bp, c"mgf1 with sha1 (default)") }
    };
    if !ok {
        return false;
    }
    // OpenSSL doesn't check these newlines.
    // SAFETY: as above.
    unsafe { puts(bp, c"\n") };
    // SAFETY: as above.
    if !unsafe { indent(bp, off) } {
        return false;
    }
    let what = if pss_key { c"Minimum" } else { c"" };
    // SAFETY: as above; the format takes a string.
    if unsafe { BIO_printf(bp, c"%s Salt Length: 0x".as_ptr(), what.as_ptr()) } <= 0 {
        return false;
    }
    let ok = if p.saltLength.is_null() {
        // SAFETY: as above.
        unsafe { puts(bp, c"14 (default)") }
    } else {
        // SAFETY: as above.
        (unsafe { i2a_ASN1_INTEGER(bp, p.saltLength) }) > 0
    };
    if !ok {
        return false;
    }
    // SAFETY: as above.
    unsafe { puts(bp, c"\n") };
    // SAFETY: as above.
    if !unsafe { indent(bp, off) } || !unsafe { puts(bp, c"Trailer Field: 0x") } {
        return false;
    }
    let ok = if p.trailerField.is_null() {
        // SAFETY: as above.
        unsafe { puts(bp, c"01 (default)") }
    } else {
        // SAFETY: as above.
        (unsafe { i2a_ASN1_INTEGER(bp, p.trailerField) }) > 0
    };
    if !ok {
        return false;
    }
    // SAFETY: as above.
    unsafe { puts(bp, c"\n") };
    true
}

/// `rsa_param_encode`: the AlgorithmIdentifier's parameter of a key: NULL for RSA; for
/// RSA-PSS, its restrictions as a SEQUENCE, or none without any. `None` if they can't be
/// encoded.
///
/// # Safety
/// `r` is NULL or a live key.
unsafe fn param_encode(r: *mut RSA) -> Option<(c_int, *mut rustyssl_abi::ASN1_STRING)> {
    use rustyssl_abi::{
        RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSASSAPSS, V_ASN1_NULL, V_ASN1_SEQUENCE, V_ASN1_UNDEF,
    };
    // SAFETY: the caller's guarantee.
    if unsafe { crate::rsa_lib::RSA_test_flags(r, RSA_FLAG_TYPE_MASK) } != RSA_FLAG_TYPE_RSASSAPSS {
        return Some((V_ASN1_NULL, ptr::null_mut()));
    }
    // SAFETY: as above.
    let pss = unsafe { crate::rsa_lib::RSA_get0_pss_params(r) };
    if pss.is_null() {
        return Some((V_ASN1_UNDEF, ptr::null_mut()));
    }
    let mut s = ptr::null_mut();
    // SAFETY: no preconditions.
    let it = unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_it() };
    // SAFETY: the key's restrictions, a value of the item; a place for the new string.
    let packed =
        unsafe { crate::asn1::tpl::util::ASN1_item_pack(pss.cast_mut().cast(), it, &raw mut s) };
    if packed.is_null() {
        return None;
    }
    Some((V_ASN1_SEQUENCE, s))
}

/// `ossl_rsa_pss_decode`: an AlgorithmIdentifier's RSA-PSS restrictions, with MGF1's digest
/// decoded, or NULL.
///
/// # Safety
/// `alg` is a live AlgorithmIdentifier.
pub(crate) unsafe fn pss_decode(
    alg: *const rustyssl_abi::X509_ALGOR,
) -> *mut rustyssl_abi::RSA_PSS_PARAMS {
    // SAFETY: no preconditions.
    let it = unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_it() };
    // SAFETY: the caller's guarantee.
    let param = unsafe { (*alg).parameter };
    // SAFETY: its parameter, NULL or a live `ASN1_TYPE`.
    let pss: *mut rustyssl_abi::RSA_PSS_PARAMS =
        unsafe { crate::asn1::tpl::util::ASN1_TYPE_unpack_sequence(it, param) }.cast();
    // SAFETY: just decoded, or NULL.
    let Some(p) = (unsafe { pss.as_mut() }) else {
        return ptr::null_mut();
    };
    if !p.maskGenAlgorithm.is_null() {
        // SAFETY: its MGF's AlgorithmIdentifier.
        p.maskHash = unsafe { crate::rsa_pmeth::mgf1_decode(p.maskGenAlgorithm) };
        if p.maskHash.is_null() {
            // SAFETY: decoded above.
            unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_free(pss) };
            return ptr::null_mut();
        }
    }
    pss
}

/// `ossl_rsa_param_decode`: an RSA-PSS AlgorithmIdentifier's restrictions given to the key
/// (as its `RSA_PSS_PARAMS` and, unverified, as its provider form). False on failure.
///
/// # Safety
/// `r` is a live key; `alg` is a live AlgorithmIdentifier.
pub(crate) unsafe fn param_decode(r: *mut RSA, alg: *const rustyssl_abi::X509_ALGOR) -> bool {
    use rustyssl_abi::{NID_mgf1, RSA_R_INVALID_PSS_PARAMETERS, V_ASN1_SEQUENCE, V_ASN1_UNDEF};
    let (mut algoid, mut ptype, mut pval) = (ptr::null(), 0, ptr::null());
    // SAFETY: the caller's AlgorithmIdentifier; locals.
    unsafe {
        crate::x509::algor::X509_ALGOR_get0(&raw mut algoid, &raw mut ptype, &raw mut pval, alg)
    };
    // SAFETY: its object.
    if unsafe { crate::objects::OBJ_obj2nid(algoid) } != EVP_PKEY_RSA_PSS || ptype == V_ASN1_UNDEF {
        return true;
    }
    if ptype != V_ASN1_SEQUENCE {
        err::raise(
            ERR_LIB_RSA,
            RSA_R_INVALID_PSS_PARAMETERS,
            "ossl_rsa_param_decode",
        );
        return false;
    }
    // SAFETY: the caller's guarantee.
    let pss = unsafe { pss_decode(alg) };
    // SAFETY: as above.
    let Some(k) = (unsafe { rsa(r) }) else {
        // SAFETY: decoded above, or NULL.
        unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_free(pss) };
        return false;
    };
    if pss.is_null() {
        return false;
    }
    k.set_pss_params(pss);
    // `ossl_rsa_sync_to_pss_params_30`, unverified (`ossl_rsa_pss_get_param_unverified`).
    // SAFETY: the key's restrictions now.
    let p = unsafe { &*pss };
    // SAFETY: their AlgorithmIdentifiers.
    let md = unsafe { crate::rsa_pmeth::md_of_algor(p.hashAlgorithm) };
    if md.is_null() {
        return false;
    }
    // SAFETY: as above.
    let mgf1md = unsafe { crate::rsa_pmeth::md_of_algor(p.maskHash) };
    if mgf1md.is_null() {
        return false;
    }
    let int = |i: *const rustyssl_abi::ASN1_INTEGER, default: c_int| {
        if i.is_null() {
            default
        } else {
            // SAFETY: its INTEGER (one past an int reads as -1, as in `pss_get_param`).
            c_int::try_from(unsafe { crate::asn1::integer::ASN1_INTEGER_get(i) }).unwrap_or(-1)
        }
    };
    let (salt_len, trailer) = (int(p.saltLength, 20), int(p.trailerField, 1));
    // SAFETY: the digests.
    let hash = unsafe { crate::evp::digest::EVP_MD_get_type(md) };
    // SAFETY: as above.
    let mask_gen_hash = unsafe { crate::evp::digest::EVP_MD_get_type(mgf1md) };
    k.lock().pss = crate::rsa::Pss30 {
        hash,
        mask_gen: NID_mgf1,
        mask_gen_hash,
        salt_len,
        trailer,
    };
    true
}

ffi_callback! {
    /// `rsa_pub_encode`: the key's RSAPublicKey with its type's object and parameter (none for
    /// RSA-PSS without restrictions).
    ///
    /// # Safety
    /// `pk` is a live SubjectPublicKeyInfo; `pkey` is a live RSA or RSA-PSS key.
    pub(crate) unsafe extern "C" fn rsa_pub_encode(pk: *mut rustyssl_abi::X509_PUBKEY, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe { data(pkey) };
        // SAFETY: as above.
        let Some((strtype, str_)) = (unsafe { param_encode(r) }) else { return 0 };
        let mut penc = ptr::null_mut();
        // SAFETY: the key; a place for a new encoding.
        let penclen = unsafe { crate::rsa_asn1::i2d_RSAPublicKey(r, &raw mut penc) };
        if penclen <= 0 {
            // SAFETY: made above, or NULL.
            unsafe { crate::asn1::string::ASN1_STRING_free(str_) };
            return 0;
        }
        // SAFETY: the caller's key.
        let id = unsafe { super::EVP_PKEY_get_id(pkey) };
        // SAFETY: no preconditions.
        let obj = unsafe { crate::objects::OBJ_nid2obj(id) };
        // SAFETY: the caller's structure takes the object, parameter, and octets.
        if unsafe { crate::x509::pubkey::X509_PUBKEY_set0_param(pk, obj, strtype, str_.cast(), penc, penclen) } != 0 {
            return 1;
        }
        // SAFETY: made above.
        unsafe { crate::mem::release(penc.cast()) };
        // SAFETY: as above.
        unsafe { crate::asn1::string::ASN1_STRING_free(str_) };
        0
    }
}

ffi_callback! {
    /// `rsa_pub_decode`: an RSAPublicKey, its RSA-PSS restrictions, and its kind (the key's
    /// type's), assigned to the key.
    ///
    /// # Safety
    /// `pkey` is a live key typed RSA or RSA-PSS; `pubkey` is a live SubjectPublicKeyInfo.
    pub(crate) unsafe extern "C" fn rsa_pub_decode(pkey: *mut EVP_PKEY, pubkey: *const rustyssl_abi::X509_PUBKEY) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        use rustyssl_abi::{RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA, RSA_FLAG_TYPE_RSASSAPSS};
        let (mut p, mut pklen, mut alg) = (ptr::null(), 0, ptr::null_mut());
        // SAFETY: the caller's structure; locals.
        if unsafe { crate::x509::pubkey::X509_PUBKEY_get0_param(ptr::null_mut(), &raw mut p, &raw mut pklen, &raw mut alg, pubkey) } == 0 {
            return 0;
        }
        // SAFETY: the structure's `pklen` octets.
        let r = unsafe { crate::rsa_asn1::d2i_RSAPublicKey(ptr::null_mut(), &raw mut p, c_long::from(pklen)) };
        if r.is_null() {
            return 0;
        }
        // SAFETY: the new key; the structure's AlgorithmIdentifier.
        let ok = unsafe { param_decode(r, alg) };
        // SAFETY: the new key.
        let Some(k) = (unsafe { rsa(r) }).filter(|_| ok) else {
            // SAFETY: made above.
            unsafe { free(r) };
            return 0;
        };
        // SAFETY: the caller's key.
        let id = unsafe { super::EVP_PKEY_get_id(pkey) };
        let kind = match id {
            EVP_PKEY_RSA => RSA_FLAG_TYPE_RSA,
            EVP_PKEY_RSA_PSS => RSA_FLAG_TYPE_RSASSAPSS,
            _ => 0,
        };
        k.set_flags_to((k.flags() & !RSA_FLAG_TYPE_MASK) | kind);
        // SAFETY: the caller's key takes the new one.
        if unsafe { EVP_PKEY_assign(pkey, id, r.cast()) } == 0 {
            // SAFETY: made above, not taken.
            unsafe { free(r) };
            return 0;
        }
        1
    }
}

/// `ossl_rsa_key_from_pkcs8`: a PrivateKeyInfo's RSAPrivateKey with its RSA-PSS restrictions
/// and the kind its algorithm names, or NULL.
///
/// # Safety
/// `p8` is a live PrivateKeyInfo.
pub(crate) unsafe fn key_from_pkcs8(p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO) -> *mut RSA {
    use rustyssl_abi::{
        ERR_R_RSA_LIB, RSA_FLAG_TYPE_MASK, RSA_FLAG_TYPE_RSA, RSA_FLAG_TYPE_RSASSAPSS,
    };
    let (mut p, mut pklen, mut alg) = (ptr::null(), 0, ptr::null());
    // SAFETY: the caller's structure; locals.
    if unsafe {
        crate::x509::p8::PKCS8_pkey_get0(
            ptr::null_mut(),
            &raw mut p,
            &raw mut pklen,
            &raw mut alg,
            p8,
        )
    } == 0
    {
        return ptr::null_mut();
    }
    // SAFETY: the structure's `pklen` octets.
    let r = unsafe {
        crate::rsa_asn1::d2i_RSAPrivateKey(ptr::null_mut(), &raw mut p, c_long::from(pklen))
    };
    if r.is_null() {
        err::raise(ERR_LIB_RSA, ERR_R_RSA_LIB, "ossl_rsa_key_from_pkcs8");
        return ptr::null_mut();
    }
    // SAFETY: the new key; the structure's AlgorithmIdentifier.
    let ok = unsafe { param_decode(r, alg) };
    // SAFETY: the new key.
    let Some(k) = (unsafe { rsa(r) }).filter(|_| ok) else {
        // SAFETY: made above.
        unsafe { free(r) };
        return ptr::null_mut();
    };
    // SAFETY: the structure's AlgorithmIdentifier.
    let obj = unsafe { (*alg).algorithm };
    // SAFETY: the AlgorithmIdentifier's object.
    let kind = match unsafe { crate::objects::OBJ_obj2nid(obj) } {
        EVP_PKEY_RSA => RSA_FLAG_TYPE_RSA,
        EVP_PKEY_RSA_PSS => RSA_FLAG_TYPE_RSASSAPSS,
        _ => 0,
    };
    k.set_flags_to((k.flags() & !RSA_FLAG_TYPE_MASK) | kind);
    r
}

ffi_callback! {
    /// `rsa_priv_encode`: the key's RSAPrivateKey with its type's object and parameter.
    ///
    /// # Safety
    /// `p8` is a live PrivateKeyInfo; `pkey` is a live RSA or RSA-PSS key.
    pub(crate) unsafe extern "C" fn rsa_priv_encode(p8: *mut rustyssl_abi::PKCS8_PRIV_KEY_INFO, pkey: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        use rustyssl_abi::ERR_R_ASN1_LIB;
        const F: &str = "rsa_priv_encode";
        // SAFETY: the caller's guarantee.
        let r = unsafe { data(pkey) };
        // SAFETY: as above.
        let Some((strtype, str_)) = (unsafe { param_encode(r) }) else { return 0 };
        let mut rk = ptr::null_mut();
        // SAFETY: the key; a place for a new encoding.
        let rklen = unsafe { crate::rsa_asn1::i2d_RSAPrivateKey(r, &raw mut rk) };
        if rklen <= 0 {
            err::raise(ERR_LIB_RSA, ERR_R_ASN1_LIB, F);
            // SAFETY: made above, or NULL.
            unsafe { crate::asn1::string::ASN1_STRING_free(str_) };
            return 0;
        }
        // SAFETY: the caller's key.
        let id = unsafe { super::EVP_PKEY_get_id(pkey) };
        // SAFETY: no preconditions.
        let obj = unsafe { crate::objects::OBJ_nid2obj(id) };
        // SAFETY: the caller's structure takes the object, parameter, and octets.
        if unsafe { crate::x509::p8::PKCS8_pkey_set0(p8, obj, 0, strtype, str_.cast(), rk, rklen) } != 0 {
            return 1;
        }
        err::raise(ERR_LIB_RSA, ERR_R_ASN1_LIB, F);
        // SAFETY: made above.
        unsafe { crate::asn1::string::ASN1_STRING_free(str_) };
        // SAFETY: as above, `rklen` octets.
        unsafe { crate::mem::release_clean(rk.cast(), usize::try_from(rklen).unwrap_or(0)) };
        0
    }
}

ffi_callback! {
    /// `rsa_priv_decode`: a PrivateKeyInfo's key assigned to the key, as its type.
    ///
    /// # Safety
    /// `pkey` is a live key typed RSA or RSA-PSS; `p8` is a live PrivateKeyInfo.
    pub(crate) unsafe extern "C" fn rsa_priv_decode(pkey: *mut EVP_PKEY, p8: *const rustyssl_abi::PKCS8_PRIV_KEY_INFO) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let r = unsafe { key_from_pkcs8(p8) };
        if r.is_null() {
            return 0;
        }
        // SAFETY: the caller's key.
        let id = unsafe { super::EVP_PKEY_get_id(pkey) };
        // SAFETY: the caller's key takes the new one.
        unsafe { EVP_PKEY_assign(pkey, id, r.cast()) };
        1
    }
}

ffi_callback! {
    /// `old_rsa_priv_decode`: a traditional RSAPrivateKey assigned to the key, as its type.
    ///
    /// # Safety
    /// `pkey` is a live key typed RSA or RSA-PSS; `pder` holds `derlen` readable octets.
    pub(crate) unsafe extern "C" fn old_rsa_priv_decode(pkey: *mut EVP_PKEY, pder: *mut *const core::ffi::c_uchar, derlen: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's octets.
        let r = unsafe { crate::rsa_asn1::d2i_RSAPrivateKey(ptr::null_mut(), pder, c_long::from(derlen)) };
        if r.is_null() {
            return 0;
        }
        // SAFETY: the caller's key.
        let id = unsafe { super::EVP_PKEY_get_id(pkey) };
        // SAFETY: the caller's key takes the new one.
        unsafe { EVP_PKEY_assign(pkey, id, r.cast()) };
        1
    }
}

ffi_callback! {
    /// `old_rsa_priv_encode`: the key's RSAPrivateKey.
    ///
    /// # Safety
    /// `p` is NULL or a live key; `pder` as for an `i2d`.
    pub(crate) unsafe extern "C" fn old_rsa_priv_encode(p: *const EVP_PKEY, pder: *mut *mut core::ffi::c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let key = unsafe { data(p) };
        // SAFETY: the key's data (or NULL); the caller's output.
        unsafe { crate::rsa_asn1::i2d_RSAPrivateKey(key, pder) }
    }
}

/// `ossl_rsa_pss_to_ctx`: an RSA-PSS AlgorithmIdentifier's parameters given to a verification:
/// with `pkey`, `ctx` initialised to verify with it and the parameters' digest (and `pkctx` its
/// key context); without, `pkctx` checked to have that digest. Then the context's padding, salt
/// length, and MGF1 digest set from them. 1, or -1.
///
/// # Safety
/// `ctx` is a live digest context; `pkctx` is NULL or a live key context (not NULL without
/// `pkey`); `sigalg` is a live AlgorithmIdentifier; `pkey` is NULL or a live key.
pub(crate) unsafe fn pss_to_ctx(
    ctx: *mut rustyssl_abi::EVP_MD_CTX,
    mut pkctx: *mut rustyssl_abi::EVP_PKEY_CTX,
    sigalg: *const rustyssl_abi::X509_ALGOR,
    pkey: *mut EVP_PKEY,
) -> c_int {
    use crate::evp::setters::{
        EVP_PKEY_CTX_set_rsa_mgf1_md, EVP_PKEY_CTX_set_rsa_padding,
        EVP_PKEY_CTX_set_rsa_pss_saltlen,
    };
    const F: &str = "ossl_rsa_pss_to_ctx";
    // SAFETY: the caller's AlgorithmIdentifier.
    let obj = unsafe { (*sigalg).algorithm };
    // SAFETY: its object.
    if unsafe { crate::objects::OBJ_obj2nid(obj) } != EVP_PKEY_RSA_PSS {
        err::raise(ERR_LIB_RSA, RSA_R_UNSUPPORTED_SIGNATURE_TYPE, F);
        return -1;
    }
    // SAFETY: as above.
    let pss = unsafe { pss_decode(sigalg) };
    let rv = (|| {
        let params = if pss.is_null() {
            None
        } else {
            // SAFETY: just decoded.
            unsafe { crate::rsa_pmeth::pss_get_param(pss) }
        };
        let Some((md, mgf1md, saltlen)) = params else {
            err::raise(ERR_LIB_RSA, RSA_R_INVALID_PSS_PARAMETERS, F);
            return -1;
        };
        if pkey.is_null() {
            let mut checkmd = ptr::null();
            // SAFETY: the caller's key context; a writable digest.
            if unsafe { crate::evp::signature::EVP_PKEY_CTX_get_signature_md(pkctx, &mut checkmd) }
                <= 0
            {
                return -1;
            }
            // SAFETY: the digests.
            let t1 = unsafe { crate::evp::digest::EVP_MD_get_type(md) };
            // SAFETY: as above.
            let t2 = unsafe { crate::evp::digest::EVP_MD_get_type(checkmd) };
            if t1 != t2 {
                err::raise(ERR_LIB_RSA, RSA_R_DIGEST_DOES_NOT_MATCH, F);
                return -1;
            }
        // SAFETY: the caller's context and key; the parameters' digest.
        } else if unsafe {
            crate::evp::sigver::EVP_DigestVerifyInit(ctx, &mut pkctx, md, ptr::null_mut(), pkey)
        } == 0
        {
            return -1;
        }
        // SAFETY: the key context, verifying.
        let ok = unsafe { EVP_PKEY_CTX_set_rsa_padding(pkctx, RSA_PKCS1_PSS_PADDING) } > 0
            // SAFETY: as above.
            && unsafe { EVP_PKEY_CTX_set_rsa_pss_saltlen(pkctx, saltlen) } > 0
            // SAFETY: as above; the parameters' MGF1 digest.
            && unsafe { EVP_PKEY_CTX_set_rsa_mgf1_md(pkctx, mgf1md) } > 0;
        if ok { 1 } else { -1 }
    })();
    // SAFETY: decoded above, or NULL.
    unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_free(pss) };
    rv
}

/// `rsa_ctx_to_pss`: the RSA-PSS parameters a signing context's settings make (its digest,
/// MGF1 digest, and salt length, a special length worked out for the key), or NULL.
///
/// # Safety
/// `pkctx` is a live key context with a key.
unsafe fn ctx_to_pss(pkctx: *mut rustyssl_abi::EVP_PKEY_CTX) -> *mut rustyssl_abi::RSA_PSS_PARAMS {
    use crate::evp::digest::EVP_MD_get_size;
    use crate::evp::setters::{EVP_PKEY_CTX_get_rsa_mgf1_md, EVP_PKEY_CTX_get_rsa_pss_saltlen};
    // SAFETY: the caller's context.
    let pk = unsafe { crate::evp::pkey_ctx::EVP_PKEY_CTX_get0_pkey(pkctx) };
    let (mut sigmd, mut mgf1md) = (ptr::null(), ptr::null());
    // SAFETY: as above; a writable digest.
    if unsafe { crate::evp::signature::EVP_PKEY_CTX_get_signature_md(pkctx, &mut sigmd) } <= 0 {
        return ptr::null_mut();
    }
    // SAFETY: the context's digest.
    let md_size = unsafe { EVP_MD_get_size(sigmd) };
    if md_size <= 0 {
        return ptr::null_mut();
    }
    // SAFETY: as above.
    if unsafe { EVP_PKEY_CTX_get_rsa_mgf1_md(pkctx, &mut mgf1md) } <= 0 {
        return ptr::null_mut();
    }
    let mut saltlen = 0;
    // SAFETY: as above; a writable length.
    if unsafe { EVP_PKEY_CTX_get_rsa_pss_saltlen(pkctx, &mut saltlen) } <= 0 {
        return ptr::null_mut();
    }
    let mut saltlen_max = -1;
    if saltlen == RSA_PSS_SALTLEN_DIGEST {
        saltlen = md_size;
    } else if saltlen == RSA_PSS_SALTLEN_AUTO_DIGEST_MAX {
        saltlen = RSA_PSS_SALTLEN_MAX;
        saltlen_max = md_size;
    }
    if saltlen == RSA_PSS_SALTLEN_MAX || saltlen == RSA_PSS_SALTLEN_AUTO {
        // SAFETY: the context's key.
        let size = unsafe { crate::evp::pkey::EVP_PKEY_get_size(pk) };
        // SAFETY: as above.
        let bits = unsafe { crate::evp::pkey::EVP_PKEY_get_bits(pk) };
        saltlen = size.saturating_sub(md_size).saturating_sub(2);
        if bits & 0x7 == 1 {
            saltlen = saltlen.saturating_sub(1);
        }
        if saltlen < 0 {
            return ptr::null_mut();
        }
        if saltlen_max >= 0 && saltlen > saltlen_max {
            saltlen = saltlen_max;
        }
    }
    // SAFETY: the context's digests.
    unsafe { crate::rsa_pmeth::pss_params_create(sigmd, mgf1md, saltlen) }
}

/// `ossl_rsa_ctx_to_pss_string`: [`ctx_to_pss`]'s parameters encoded as a string, or NULL.
///
/// # Safety
/// As for [`ctx_to_pss`].
pub(crate) unsafe fn ctx_to_pss_string(
    pkctx: *mut rustyssl_abi::EVP_PKEY_CTX,
) -> *mut rustyssl_abi::ASN1_STRING {
    // SAFETY: the caller's guarantee.
    let pss = unsafe { ctx_to_pss(pkctx) };
    if pss.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let it = unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_it() };
    // SAFETY: the parameters, of the item.
    let os = unsafe { crate::asn1::tpl::util::ASN1_item_pack(pss.cast(), it, ptr::null_mut()) };
    // SAFETY: made above.
    unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_free(pss) };
    os
}

ffi_callback! {
    /// `rsa_item_verify`: an RSA-PSS AlgorithmIdentifier's parameters given to the
    /// verification (2), or -1.
    ///
    /// # Safety
    /// `ctx` is a live digest context; `sigalg` a live AlgorithmIdentifier; `pkey` a live key.
    pub(crate) unsafe extern "C" fn rsa_item_verify(ctx: *mut rustyssl_abi::EVP_MD_CTX, _it: *const rustyssl_abi::ASN1_ITEM, _asn: *const c_void, sigalg: *const rustyssl_abi::X509_ALGOR, _sig: *const rustyssl_abi::ASN1_BIT_STRING, pkey: *mut EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's AlgorithmIdentifier.
        let obj = unsafe { (*sigalg).algorithm };
        // SAFETY: its object.
        if unsafe { crate::objects::OBJ_obj2nid(obj) } != EVP_PKEY_RSA_PSS {
            err::raise(ERR_LIB_RSA, RSA_R_UNSUPPORTED_SIGNATURE_TYPE, "rsa_item_verify");
            return -1;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { pss_to_ctx(ctx, ptr::null_mut(), sigalg, pkey) } > 0 { 2 } else { -1 }
    }
}

ffi_callback! {
    /// `rsa_item_sign`: for PSS padding, the AlgorithmIdentifiers set to RSA-PSS with the
    /// context's parameters (3); for other padding, 2 (named from the digest); 0 on failure.
    ///
    /// # Safety
    /// `ctx` is a live digest context initialised to sign; `alg1` and `alg2` are NULL or live
    /// AlgorithmIdentifiers.
    pub(crate) unsafe extern "C" fn rsa_item_sign(ctx: *mut rustyssl_abi::EVP_MD_CTX, _it: *const rustyssl_abi::ASN1_ITEM, _asn: *const c_void, alg1: *mut rustyssl_abi::X509_ALGOR, alg2: *mut rustyssl_abi::X509_ALGOR, _sig: *mut rustyssl_abi::ASN1_BIT_STRING) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        use crate::asn1::string::ASN1_STRING_free;
        use crate::x509::algor::X509_ALGOR_set0;
        // SAFETY: the caller's context.
        let pkctx = unsafe { crate::evp::sigver::EVP_MD_CTX_get_pkey_ctx(ctx) };
        let mut pad_mode = 0;
        // SAFETY: its key context; a writable mode.
        if unsafe { crate::evp::setters::EVP_PKEY_CTX_get_rsa_padding(pkctx, &mut pad_mode) } <= 0 {
            return 0;
        }
        if pad_mode != RSA_PKCS1_PSS_PADDING {
            return 2;
        }
        // SAFETY: the key context.
        let legacy = unsafe { crate::evp::pkey_ctx::context(pkctx) }.is_some_and(|c| c.lock().keymgmt.is_none());
        if !legacy {
            // SAFETY: the key context; the caller's AlgorithmIdentifiers.
            return if unsafe { crate::asn1::sign::algorithm_id(pkctx, alg1, alg2) }.is_ok() { 3 } else { 0 };
        }
        // SAFETY: the key context.
        let os1 = unsafe { ctx_to_pss_string(pkctx) };
        if os1.is_null() {
            return 0;
        }
        // SAFETY: a NID.
        let pss_obj = || unsafe { crate::objects::OBJ_nid2obj(EVP_PKEY_RSA_PSS) };
        if !alg2.is_null() {
            // SAFETY: the parameters' string.
            let os2 = unsafe { crate::asn1::string::ASN1_STRING_dup(os1) };
            // SAFETY: the caller's AlgorithmIdentifier; the copy, which it takes.
            if os2.is_null() || unsafe { X509_ALGOR_set0(alg2, pss_obj(), V_ASN1_SEQUENCE, os2.cast()) } == 0 {
                // SAFETY: made above, or NULL.
                unsafe { ASN1_STRING_free(os1) };
                // SAFETY: as above.
                unsafe { ASN1_STRING_free(os2) };
                return 0;
            }
        }
        // SAFETY: as above.
        if unsafe { X509_ALGOR_set0(alg1, pss_obj(), V_ASN1_SEQUENCE, os1.cast()) } == 0 {
            // SAFETY: made above.
            unsafe { ASN1_STRING_free(os1) };
            return 0;
        }
        3
    }
}

ffi_callback! {
    /// `rsa_sig_info_set`: an RSA-PSS signature's digest and security bits (half the digest's,
    /// SHA-1 and MD5 lower), usable in TLS with SHA-2 for both digests and a salt as long.
    ///
    /// # Safety
    /// `siginf` is a live `X509_SIG_INFO`; `sigalg` is a live AlgorithmIdentifier.
    pub(crate) unsafe extern "C" fn rsa_sig_info_set(siginf: *mut rustyssl_abi::X509_SIG_INFO, sigalg: *const rustyssl_abi::X509_ALGOR, _sig: *const rustyssl_abi::ASN1_STRING) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let obj = unsafe { (*sigalg).algorithm };
        // SAFETY: its object.
        if unsafe { crate::objects::OBJ_obj2nid(obj) } != EVP_PKEY_RSA_PSS {
            return 0;
        }
        // SAFETY: as above.
        let pss = unsafe { pss_decode(sigalg) };
        let rv = (|| {
            if pss.is_null() {
                return 0;
            }
            // SAFETY: just decoded.
            let Some((md, mgf1md, saltlen)) = (unsafe { crate::rsa_pmeth::pss_get_param(pss) }) else { return 0 };
            // SAFETY: a digest.
            let md_size = unsafe { crate::evp::digest::EVP_MD_get_size(md) };
            if md_size <= 0 {
                return 0;
            }
            // SAFETY: as above.
            let mdnid = unsafe { crate::evp::digest::EVP_MD_get_type(md) };
            // SAFETY: as above.
            let mgfnid = unsafe { crate::evp::digest::EVP_MD_get_type(mgf1md) };
            let tls = [NID_sha256, rustyssl_abi::NID_sha384, rustyssl_abi::NID_sha512].contains(&mdnid)
                && mdnid == mgfnid
                && saltlen == md_size;
            let flags = if tls { rustyssl_abi::X509_SIG_INFO_TLS.cast_unsigned() } else { 0 };
            let secbits = match mdnid {
                n if n == rustyssl_abi::NID_sha1 => 64,
                n if n == rustyssl_abi::NID_md5_sha1 => 68,
                n if n == rustyssl_abi::NID_md5 => 39,
                _ => md_size.saturating_mul(4),
            };
            // SAFETY: the caller's information.
            unsafe { crate::x509::purpose::X509_SIG_INFO_set(siginf, mdnid, EVP_PKEY_RSA_PSS, secbits, flags) };
            1
        })();
        // SAFETY: decoded above, or NULL.
        unsafe { crate::rsa_asn1::RSA_PSS_PARAMS_free(pss) };
        rv
    }
}
