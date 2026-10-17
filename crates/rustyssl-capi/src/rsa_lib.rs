//! The `RSA` object's functions (`RSA_new(3)`, `RSA_get0_key(3)`, `RSA_set_method(3)`,
//! `RSA_blinding_on(3)`; `rsa_lib.c`, `rsa_crpt.c`): making and freeing keys, their numbers,
//! flags, method, application data, blinding, and the four operations through the method.
//!
//! A key's numbers are `rustyssl_crypto::rsa::Key`'s; the `BIGNUM`s the application sees or
//! gives are kept as the key's own from then on (`crate::rsa::Numbers`), so `get0` pointers
//! live as long as the key and read (and write) its numbers, as OpenSSL's do.

use core::ffi::{c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    BIGNUM, BN_BLINDING, BN_CTX, BN_FLG_CONSTTIME, ENGINE, ERR_LIB_RSA, ERR_R_BN_LIB, EVP_PKEY_CTX,
    EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, RSA, RSA_ASN1_VERSION_DEFAULT, RSA_ASN1_VERSION_MULTI,
    RSA_FLAG_BLINDING, RSA_FLAG_NO_BLINDING, RSA_METHOD, RSA_PSS_PARAMS, RSA_R_NO_PUBLIC_EXPONENT,
};
use rustyssl_crypto::bn as core_bn;
use rustyssl_crypto::rsa::ExtraPrime;

use crate::bn::blind::{BN_BLINDING_create_param, BN_BLINDING_set_current_thread};
use crate::bn::ctx::{BN_CTX_free, BN_CTX_new_ex};
use crate::bn::{BN_set_flags, new_bignum, value};
use crate::err;
use crate::evp::ctrl::EVP_PKEY_CTX_ctrl;
use crate::ex_data::{CRYPTO_get_ex_data, CRYPTO_set_ex_data};
use crate::ffi::ffi_export;
use crate::provider::Ptr;
use crate::provider::rsa_kmgmt::security_bits;
use crate::rsa::{Field, Kind, Rsa, free, key_field, private_random, read_numbers, rsa, up_ref};
use crate::rsa_meth::fns_of;

/// The key behind `r`.
///
/// # Safety
/// `r` is NULL or a live key.
unsafe fn key<'a>(r: *const RSA) -> Option<&'a Rsa> {
    // SAFETY: the caller's guarantee.
    unsafe { rsa(r) }
}

ffi_export! {
    /// A new key with the default method (NULL if its `init` fails).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RSA_new() -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        Rsa::new_handle_in(ptr::null_mut(), Kind::Rsa)
    }
}

ffi_export! {
    /// `RSA_new` with an engine: NULL only (rustyssl has no engines; another pointer aborts).
    ///
    /// # Safety
    /// `engine` is NULL.
    pub unsafe extern "C" fn RSA_new_method(engine: *mut ENGINE) -> *mut RSA
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        if !engine.is_null() {
            crate::stub::unimplemented("RSA_new_method with an engine (rustyssl has none)");
        }
        Rsa::new_handle_in(ptr::null_mut(), Kind::Rsa)
    }
}

ffi_export! {
    /// Drops a reference; at the last, the method's `finish` runs and the key is freed. NULL
    /// does nothing.
    ///
    /// # Safety
    /// `r` is NULL or a live key whose reference the caller gives up.
    pub unsafe extern "C" fn RSA_free(r: *mut RSA)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { free(r) };
    }
}

ffi_export! {
    /// Adds a reference. 1, or 0 for NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_up_ref(r: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { up_ref(r) })
    }
}

ffi_export! {
    /// The key's method.
    ///
    /// # Safety
    /// `rsa` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get_method(rsa: *const RSA) -> *const RSA_METHOD
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(rsa) }.map_or(ptr::null(), Rsa::meth)
    }
}

ffi_export! {
    /// Gives the key `meth`: the old method's `finish`, then the new one's `init` (their
    /// results ignored, as OpenSSL ignores them). 1, or 0 for a NULL key.
    ///
    /// # Safety
    /// `rsa` is NULL or a live key; `meth` is NULL or a method that outlives the key's use of
    /// it.
    pub unsafe extern "C" fn RSA_set_method(rsa: *mut RSA, meth: *const RSA_METHOD) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(rsa) }) else { return 0 };
        // SAFETY: the key's method, live.
        if let Some(finish) = unsafe { fns_of(k.meth()) }.and_then(|f| f.finish) {
            // SAFETY: the method's function takes the key; no lock is held.
            unsafe { finish(rsa) };
        }
        k.legacy().meth = Ptr(meth.cast_mut());
        // SAFETY: the caller's guarantee.
        if let Some(init) = unsafe { fns_of(meth) }.and_then(|f| f.init) {
            // SAFETY: as above.
            unsafe { init(rsa) };
        }
        1
    }
}

ffi_export! {
    /// Sets the key's application data at `idx`. 1, or 0.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_set_ex_data(r: *mut RSA, idx: c_int, arg: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return 0 };
        // SAFETY: the key's own ex_data.
        unsafe { CRYPTO_set_ex_data(k.ex_data(), idx, arg) }
    }
}

ffi_export! {
    /// The key's application data at `idx`, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get_ex_data(r: *const RSA, idx: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return ptr::null_mut() };
        // SAFETY: the key's own ex_data.
        unsafe { CRYPTO_get_ex_data(k.ex_data(), idx) }
    }
}

ffi_export! {
    /// The modulus's length in octets (0 without one).
    ///
    /// # Safety
    /// `rsa` is NULL or a live key.
    pub unsafe extern "C" fn RSA_size(rsa: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(rsa) }.map_or(0, |k| c_int::try_from(k.snapshot().key.size()).unwrap_or(0))
    }
}

ffi_export! {
    /// The modulus's length in bits (0 without one).
    ///
    /// # Safety
    /// `rsa` is NULL or a live key.
    pub unsafe extern "C" fn RSA_bits(rsa: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(rsa) }.map_or(0, |k| c_int::try_from(k.snapshot().key.bits()).unwrap_or(0))
    }
}

ffi_export! {
    /// The key's security bits (0 for a multi-prime key with too many primes for its size).
    ///
    /// # Safety
    /// `rsa` is NULL or a live key.
    pub unsafe extern "C" fn RSA_security_bits(rsa: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(rsa) }.map_or(0, |k| security_bits(&k.snapshot().key))
    }
}

ffi_export! {
    /// The key's ASN.1 version: `RSA_ASN1_VERSION_MULTI` for a multi-prime key, else the
    /// version an `RSAPrivateKey` was decoded with (0 for other keys).
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get_version(r: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else {
            return RSA_ASN1_VERSION_DEFAULT;
        };
        if k.lock().key.multi {
            return RSA_ASN1_VERSION_MULTI;
        }
        match k.legacy().version {
            RSA_ASN1_VERSION_MULTI => RSA_ASN1_VERSION_DEFAULT,
            v => v,
        }
    }
}

ffi_export! {
    /// An RSA-PSS key's restrictions (from its generation through the legacy method; decoding
    /// keys comes with the key decoders), or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_pss_params(r: *const RSA) -> *const RSA_PSS_PARAMS
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| k.legacy().pss.0.cast_const())
    }
}

ffi_export! {
    /// The key's engine: none.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn RSA_get0_engine(_r: *const RSA) -> *mut ENGINE
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        ptr::null_mut()
    }
}

ffi_export! {
    /// The flags of the key's method (deprecated; not the key's own, as in OpenSSL).
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_flags(r: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(0, |k| unsafe { crate::rsa_meth::flags(k.meth()) })
    }
}

ffi_export! {
    /// The key's flags among `flags`.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_test_flags(r: *const RSA, flags: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(0, |k| k.flags() & flags)
    }
}

ffi_export! {
    /// Sets `flags` (the type bits change the key's type; `RSA_FLAG_NO_BLINDING` stops its
    /// blinding).
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_set_flags(r: *mut RSA, flags: c_int)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { key(r) } {
            k.set_flags_to(k.flags() | flags);
        }
    }
}

ffi_export! {
    /// Clears `flags`.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_clear_flags(r: *mut RSA, flags: c_int)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { key(r) } {
            k.set_flags_to(k.flags() & !flags);
        }
    }
}

/// The key's number `f` as its own `BIGNUM`, made the first time (NULL if the key has none).
fn get0(k: &Rsa, f: Field) -> *const BIGNUM {
    let mut st = k.lock();
    let mut lg = k.legacy();
    read_numbers(&mut lg.numbers, &mut st.key);
    let v = match f {
        Field::Extra(i, j) => st
            .key
            .extra
            .get(i)
            .and_then(|x| [&x.r, &x.d, &x.t].get(j).map(|v| (*v).clone())),
        _ => key_field(&mut st.key, f).and_then(|v| v.clone()),
    };
    let Some(v) = v else { return ptr::null() };
    let extras = st.key.extra.len();
    if lg.numbers.extra.len() < extras {
        lg.numbers.extra.resize(extras, Default::default());
    }
    let Some(slot) = lg.numbers.slot(f) else {
        return ptr::null();
    };
    if slot.0.is_null() {
        let b = new_bignum(v, false);
        if f.secret() {
            // SAFETY: just made.
            unsafe { BN_set_flags(b, BN_FLG_CONSTTIME) };
        }
        *slot = Ptr(b);
    }
    slot.0
}

/// `RSA_set0_*`'s step: the key takes `b` as its number `f` (keeping the old one alive).
///
/// # Safety
/// `b` is a live `BIGNUM` the caller gives up.
unsafe fn set0(k: &Rsa, f: Field, b: *mut BIGNUM) {
    if f.secret() {
        // SAFETY: the caller's guarantee.
        unsafe { BN_set_flags(b, BN_FLG_CONSTTIME) };
    }
    // SAFETY: as above.
    let v = unsafe { value(b) };
    let mut st = k.lock();
    let mut lg = k.legacy();
    read_numbers(&mut lg.numbers, &mut st.key);
    if let Some(dst) = key_field(&mut st.key, f) {
        *dst = v;
    }
    if let Some(slot) = lg.numbers.slot(f) {
        let old = core::mem::replace(slot, Ptr(b));
        if old.0 != b {
            lg.numbers.retire(old);
        }
    }
    k.touch();
}

/// Whether the key has the number `f`.
fn has(k: &Rsa, f: Field) -> bool {
    key_field(&mut k.snapshot().key, f).is_some_and(|v| v.is_some())
}

/// Puts `v` where `out` points, if it does.
///
/// # Safety
/// `out` is NULL or writable.
unsafe fn put(out: *mut *const BIGNUM, v: *const BIGNUM) {
    if !out.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { out.write(v) };
    }
}

ffi_export! {
    /// Sets the modulus, the public exponent, and the private exponent; the key takes each
    /// number that isn't NULL. 0 when the key would lack n or e.
    ///
    /// # Safety
    /// `r` is NULL or a live key; each number is NULL or a live `BIGNUM` the caller gives up.
    pub unsafe extern "C" fn RSA_set0_key(r: *mut RSA, n: *mut BIGNUM, e: *mut BIGNUM, d: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return 0 };
        if (n.is_null() && !has(k, Field::N)) || (e.is_null() && !has(k, Field::E)) {
            return 0;
        }
        for (f, b) in [(Field::N, n), (Field::E, e), (Field::D, d)] {
            if !b.is_null() {
                // SAFETY: the caller's number.
                unsafe { set0(k, f, b) };
            }
        }
        1
    }
}

ffi_export! {
    /// Sets the primes p and q (each that isn't NULL). 0 when the key would lack one.
    ///
    /// # Safety
    /// As for `RSA_set0_key`.
    pub unsafe extern "C" fn RSA_set0_factors(r: *mut RSA, p: *mut BIGNUM, q: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return 0 };
        if (p.is_null() && !has(k, Field::P)) || (q.is_null() && !has(k, Field::Q)) {
            return 0;
        }
        for (f, b) in [(Field::P, p), (Field::Q, q)] {
            if !b.is_null() {
                // SAFETY: the caller's number.
                unsafe { set0(k, f, b) };
            }
        }
        1
    }
}

ffi_export! {
    /// Sets the CRT exponents and coefficient (each that isn't NULL). 0 when the key would
    /// lack one.
    ///
    /// # Safety
    /// As for `RSA_set0_key`.
    pub unsafe extern "C" fn RSA_set0_crt_params(r: *mut RSA, dmp1: *mut BIGNUM, dmq1: *mut BIGNUM, iqmp: *mut BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return 0 };
        let fields = [(Field::Dmp1, dmp1), (Field::Dmq1, dmq1), (Field::Iqmp, iqmp)];
        if fields.iter().any(|&(f, b)| b.is_null() && !has(k, f)) {
            return 0;
        }
        for (f, b) in fields {
            if !b.is_null() {
                // SAFETY: the caller's number.
                unsafe { set0(k, f, b) };
            }
        }
        1
    }
}

ffi_export! {
    /// Sets the key's extra primes (all `pnum` of them become extra primes, as in OpenSSL)
    /// with their exponents and coefficients, making it a multi-prime key. 0 (taking nothing)
    /// for no primes, a missing number, or a key without p and q.
    ///
    /// # Safety
    /// `r` is NULL or a live key; each array is NULL or holds `pnum` numbers, each NULL or a
    /// live `BIGNUM` the caller gives up on success.
    pub unsafe extern "C" fn RSA_set0_multi_prime_params(r: *mut RSA, primes: *mut *mut BIGNUM, exps: *mut *mut BIGNUM, coeffs: *mut *mut BIGNUM, pnum: c_int) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return 0 };
        let Ok(n) = usize::try_from(pnum) else { return 0 };
        if primes.is_null() || exps.is_null() || coeffs.is_null() || n == 0 {
            return 0;
        }
        // SAFETY: the caller's array of `pnum`.
        let ps = unsafe { core::slice::from_raw_parts(primes, n) };
        // SAFETY: as above.
        let es = unsafe { core::slice::from_raw_parts(exps, n) };
        // SAFETY: as above.
        let cs = unsafe { core::slice::from_raw_parts(coeffs, n) };
        let mut extra = Vec::with_capacity(n);
        let mut handles = Vec::with_capacity(n);
        for ((&p, &e), &c) in ps.iter().zip(es).zip(cs) {
            if p.is_null() || e.is_null() || c.is_null() {
                return 0;
            }
            // SAFETY: the caller's numbers.
            let (Some(rv), Some(dv), Some(tv)) = (unsafe { value(p) }, unsafe { value(e) }, unsafe { value(c) }) else {
                return 0;
            };
            extra.push(ExtraPrime { r: rv, d: dv, t: tv });
            handles.push([Ptr(p), Ptr(e), Ptr(c)]);
        }
        // `ossl_rsa_multip_calc_product` needs p and q (OpenSSL's would crash without them).
        if !has(k, Field::P) || !has(k, Field::Q) {
            return 0;
        }
        for h in &handles {
            for b in h {
                // SAFETY: the caller's number, now the key's.
                unsafe { BN_set_flags(b.0, BN_FLG_CONSTTIME) };
            }
        }
        let mut st = k.lock();
        let mut lg = k.legacy();
        read_numbers(&mut lg.numbers, &mut st.key);
        st.key.extra = extra;
        st.key.multi = true;
        k.touch();
        let old = core::mem::replace(&mut lg.numbers.extra, handles);
        for h in old {
            for b in h {
                lg.numbers.retire(b);
            }
        }
        1
    }
}

ffi_export! {
    /// The modulus, public exponent, and private exponent (each where asked, NULL if absent).
    ///
    /// # Safety
    /// `r` is a live key; each output is NULL or writable.
    pub unsafe extern "C" fn RSA_get0_key(r: *const RSA, n: *mut *const BIGNUM, e: *mut *const BIGNUM, d: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return };
        for (out, f) in [(n, Field::N), (e, Field::E), (d, Field::D)] {
            if !out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { put(out, get0(k, f)) };
            }
        }
    }
}

ffi_export! {
    /// The primes p and q (each where asked).
    ///
    /// # Safety
    /// As for `RSA_get0_key`.
    pub unsafe extern "C" fn RSA_get0_factors(r: *const RSA, p: *mut *const BIGNUM, q: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return };
        for (out, f) in [(p, Field::P), (q, Field::Q)] {
            if !out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { put(out, get0(k, f)) };
            }
        }
    }
}

ffi_export! {
    /// The CRT exponents and coefficient (each where asked).
    ///
    /// # Safety
    /// As for `RSA_get0_key`.
    pub unsafe extern "C" fn RSA_get0_crt_params(r: *const RSA, dmp1: *mut *const BIGNUM, dmq1: *mut *const BIGNUM, iqmp: *mut *const BIGNUM)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return };
        for (out, f) in [(dmp1, Field::Dmp1), (dmq1, Field::Dmq1), (iqmp, Field::Iqmp)] {
            if !out.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { put(out, get0(k, f)) };
            }
        }
    }
}

ffi_export! {
    /// The number of extra primes (0 for a two-prime key).
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get_multi_prime_extra_count(r: *const RSA) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(0, |k| c_int::try_from(k.lock().key.extra.len()).unwrap_or(0))
    }
}

ffi_export! {
    /// The extra primes into `primes` (room for the count); 0 for a two-prime key.
    ///
    /// # Safety
    /// `r` is NULL or a live key; `primes` has room for the extra primes.
    pub unsafe extern "C" fn RSA_get0_multi_prime_factors(r: *const RSA, primes: *mut *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return 0 };
        let n = k.lock().key.extra.len();
        if n == 0 || primes.is_null() {
            return 0;
        }
        // SAFETY: the caller's room for the count.
        let out = unsafe { core::slice::from_raw_parts_mut(primes, n) };
        for (i, o) in out.iter_mut().enumerate() {
            *o = get0(k, Field::Extra(i, 0));
        }
        1
    }
}

ffi_export! {
    /// The extra primes' exponents and coefficients (each array where given); 0 for a
    /// two-prime key.
    ///
    /// # Safety
    /// `r` is NULL or a live key; each array is NULL or has room for the extra primes.
    pub unsafe extern "C" fn RSA_get0_multi_prime_crt_params(r: *const RSA, exps: *mut *const BIGNUM, coeffs: *mut *const BIGNUM) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(r) }) else { return 0 };
        let n = k.lock().key.extra.len();
        if n == 0 {
            return 0;
        }
        for (arr, j) in [(exps, 1), (coeffs, 2)] {
            if arr.is_null() {
                continue;
            }
            // SAFETY: the caller's room for the count.
            let out = unsafe { core::slice::from_raw_parts_mut(arr, n) };
            for (i, o) in out.iter_mut().enumerate() {
                *o = get0(k, Field::Extra(i, j));
            }
        }
        1
    }
}

ffi_export! {
    /// The key's modulus, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_n(r: *const RSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| get0(k, Field::N))
    }
}

ffi_export! {
    /// The key's public exponent, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_e(r: *const RSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| get0(k, Field::E))
    }
}

ffi_export! {
    /// The key's private exponent, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_d(r: *const RSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| get0(k, Field::D))
    }
}

ffi_export! {
    /// The key's first prime, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_p(r: *const RSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| get0(k, Field::P))
    }
}

ffi_export! {
    /// The key's second prime, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_q(r: *const RSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| get0(k, Field::Q))
    }
}

ffi_export! {
    /// The key's first CRT exponent, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_dmp1(r: *const RSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| get0(k, Field::Dmp1))
    }
}

ffi_export! {
    /// The key's second CRT exponent, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_dmq1(r: *const RSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| get0(k, Field::Dmq1))
    }
}

ffi_export! {
    /// The key's CRT coefficient, or NULL.
    ///
    /// # Safety
    /// `r` is NULL or a live key.
    pub unsafe extern "C" fn RSA_get0_iqmp(r: *const RSA) -> *const BIGNUM
    where failure = ptr::null(), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { key(r) }.map_or(ptr::null(), |k| get0(k, Field::Iqmp))
    }
}

ffi_export! {
    /// Turns blinding off (`RSA_FLAG_NO_BLINDING`), dropping the key's blinding.
    ///
    /// # Safety
    /// `rsa` is NULL or a live key.
    pub unsafe extern "C" fn RSA_blinding_off(rsa: *mut RSA)
    where failure = (), library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        if let Some(k) = unsafe { key(rsa) } {
            k.lock().key.drop_blinding();
            k.set_flags_to((k.flags() & !RSA_FLAG_BLINDING) | RSA_FLAG_NO_BLINDING);
        }
    }
}

ffi_export! {
    /// Makes the key a fresh blinding now (from the private generator) and turns blinding on.
    /// 1, or 0 (blinding stays as it was set: off if it had a blinding).
    ///
    /// # Safety
    /// `rsa` is NULL or a live key; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn RSA_blinding_on(rsa: *mut RSA, _ctx: *mut BN_CTX) -> c_int
    where failure = 0, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(rsa) }) else { return 0 };
        let st = k.snapshot();
        if st.key.has_blinding() {
            // SAFETY: as above.
            unsafe { RSA_blinding_off(rsa) };
        }
        let mut rng = private_random(k.libctx.get());
        if !st.key.new_blinding(&mut rng) {
            err::raise(ERR_LIB_RSA, ERR_R_BN_LIB, "RSA_setup_blinding");
            return 0;
        }
        k.set_flags_to((k.flags() | RSA_FLAG_BLINDING) & !RSA_FLAG_NO_BLINDING);
        1
    }
}

ffi_export! {
    /// A new blinding for the key (`BN_BLINDING_create_param` with its public exponent, or
    /// one derived from d, p, and q), or NULL.
    ///
    /// # Safety
    /// `rsa` is NULL or a live key; `ctx` is NULL or a live `BN_CTX`.
    pub unsafe extern "C" fn RSA_setup_blinding(rsa: *mut RSA, ctx: *mut BN_CTX) -> *mut BN_BLINDING
    where failure = ptr::null_mut(), library = ERR_LIB_RSA
    {
        const F: &str = "RSA_setup_blinding";
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { key(rsa) }) else { return ptr::null_mut() };
        let st = k.snapshot();
        let Some(n) = st.key.n.clone() else { return ptr::null_mut() };
        let e = st.key.e.clone().or_else(|| {
            let (d, p, q) = (st.key.d.as_ref()?, st.key.p.as_ref()?, st.key.q.as_ref()?);
            let mut p1 = p.clone();
            p1.sub_word(1).ok()?;
            let mut q1 = q.clone();
            q1.sub_word(1).ok()?;
            let phi = core_bn::mul(&p1, &q1).ok()?;
            core_bn::ct::inverse(&core_bn::nnmod(d, &phi).ok()?, &phi)
        });
        let Some(e) = e else {
            err::raise(ERR_LIB_RSA, RSA_R_NO_PUBLIC_EXPONENT, F);
            return ptr::null_mut();
        };
        let own = ctx.is_null();
        // SAFETY: the key's library context.
        let ctx = if own { unsafe { BN_CTX_new_ex(k.libctx.get()) } } else { ctx };
        let (eb, nb) = (new_bignum(e, false), new_bignum(n, false));
        // SAFETY: just made.
        unsafe { BN_set_flags(nb, BN_FLG_CONSTTIME) };
        // SAFETY: the key's method, live.
        let bn_mod_exp = unsafe { fns_of(k.meth()) }.and_then(|f| f.bn_mod_exp);
        // SAFETY: the numbers just made; the context.
        let b = unsafe { BN_BLINDING_create_param(ptr::null_mut(), eb, nb, ctx, bn_mod_exp, ptr::null_mut()) };
        // SAFETY: ours to free.
        unsafe { crate::bn::BN_free(eb) };
        // SAFETY: as above (the blinding keeps its own copy of the modulus).
        unsafe { crate::bn::BN_free(nb) };
        if own {
            // SAFETY: made above.
            unsafe { BN_CTX_free(ctx) };
        }
        if b.is_null() {
            err::raise(ERR_LIB_RSA, ERR_R_BN_LIB, F);
            return ptr::null_mut();
        }
        // SAFETY: the blinding just made.
        unsafe { BN_BLINDING_set_current_thread(b) };
        b
    }
}

ffi_export! {
    /// `EVP_PKEY_CTX_ctrl` for any key type, or -1 if the context's legacy method is for
    /// another type than RSA or RSA-PSS.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `p2` is what the command takes.
    pub unsafe extern "C" fn RSA_pkey_ctx_ctrl(ctx: *mut EVP_PKEY_CTX, optype: c_int, cmd: c_int, p1: c_int, p2: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        let id = unsafe { crate::evp::pkey_ctx::context(ctx) }
            .and_then(|c| c.lock().pmeth.as_ref().map(|m| m.get().pkey_id));
        if id.is_some_and(|id| id != EVP_PKEY_RSA && id != EVP_PKEY_RSA_PSS) {
            return -1;
        }
        // SAFETY: the caller's guarantee.
        unsafe { EVP_PKEY_CTX_ctrl(ctx, -1, optype, cmd, p1, p2) }
    }
}

/// One of the method's four operations on `rsa`, or -1 without one.
///
/// # Safety
/// `rsa` is NULL or a live key; the buffers are what the method's function takes.
unsafe fn dispatch(
    pick: fn(&crate::rsa_meth::Fns) -> Option<crate::rsa_meth::EncFn>,
    flen: c_int,
    from: *const c_uchar,
    to: *mut c_uchar,
    rsa: *mut RSA,
    padding: c_int,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { key(rsa) }) else {
        return -1;
    };
    // SAFETY: the key's method, live.
    let Some(f) = unsafe { fns_of(k.meth()) }.as_ref().and_then(pick) else {
        return -1;
    };
    // SAFETY: the method's function takes these; no lock is held.
    unsafe { f(flen, from, to, rsa, padding) }
}

ffi_export! {
    /// The method's public encryption of `flen` octets into `to` (room for `RSA_size`). The
    /// length, or -1.
    ///
    /// # Safety
    /// `rsa` is NULL or a live key; `from` holds `flen` octets; `to` has room for the key's
    /// size.
    pub unsafe extern "C" fn RSA_public_encrypt(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: *mut RSA, padding: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { dispatch(|f| f.pub_enc, flen, from, to, rsa, padding) }
    }
}

ffi_export! {
    /// The method's private encryption (signing). The length, or -1.
    ///
    /// # Safety
    /// As for `RSA_public_encrypt`.
    pub unsafe extern "C" fn RSA_private_encrypt(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: *mut RSA, padding: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { dispatch(|f| f.priv_enc, flen, from, to, rsa, padding) }
    }
}

ffi_export! {
    /// The method's public decryption (verification). The length, or -1.
    ///
    /// # Safety
    /// As for `RSA_public_encrypt`.
    pub unsafe extern "C" fn RSA_public_decrypt(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: *mut RSA, padding: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { dispatch(|f| f.pub_dec, flen, from, to, rsa, padding) }
    }
}

ffi_export! {
    /// The method's private decryption. The length, or -1.
    ///
    /// # Safety
    /// As for `RSA_public_encrypt`.
    pub unsafe extern "C" fn RSA_private_decrypt(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: *mut RSA, padding: c_int) -> c_int
    where failure = -1, library = ERR_LIB_RSA
    {
        // SAFETY: the caller's guarantee.
        unsafe { dispatch(|f| f.priv_dec, flen, from, to, rsa, padding) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rsa_meth::{RSA_PKCS1_OpenSSL, RSA_get_default_method, RSA_set_default_method};

    /// docs/DEVIATIONS.md: OpenSSL's dereference the missing modulus, or a NULL key.
    #[test]
    fn a_key_without_numbers_or_a_null_key_is_safe() {
        // SAFETY: no preconditions; then a live key, and NULL.
        let r = unsafe { RSA_new() };
        // SAFETY: a live key.
        assert_eq!(unsafe { RSA_size(r) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_bits(r) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_security_bits(r) }, 0);
        // SAFETY: NULL.
        assert_eq!(unsafe { RSA_up_ref(ptr::null_mut()) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_size(ptr::null()) }, 0);
        let mut ps = [new_bignum(core_bn::BigNum::one(), false)];
        let mut es = [new_bignum(core_bn::BigNum::one(), false)];
        let mut cs = [new_bignum(core_bn::BigNum::one(), false)];
        // SAFETY: a live key; arrays of one live number each, kept on failure.
        let set = unsafe {
            RSA_set0_multi_prime_params(r, ps.as_mut_ptr(), es.as_mut_ptr(), cs.as_mut_ptr(), 1)
        };
        assert_eq!(
            set, 0,
            "no p and q: refused, the numbers left to the caller"
        );
        for b in [ps[0], es[0], cs[0]] {
            // SAFETY: ours still.
            unsafe { crate::bn::BN_free(b) };
        }
        // SAFETY: the key made above.
        unsafe { RSA_free(r) };
    }

    /// Each reference `RSA_up_ref` adds is one `RSA_free` drops, and the last frees the key
    /// (Miri reports the key leaked otherwise).
    #[test]
    fn references_balance() {
        // SAFETY: no preconditions.
        let r = unsafe { RSA_new() };
        // SAFETY: a live key.
        assert_eq!(unsafe { RSA_up_ref(r) }, 1);
        // SAFETY: as above.
        assert_eq!(unsafe { RSA_up_ref(r) }, 1);
        for _ in 0..3 {
            // SAFETY: one of the three references.
            unsafe { RSA_free(r) };
        }
    }

    /// docs/DEVIATIONS.md: OpenSSL's `RSA_new` dereferences a NULL default method.
    #[test]
    fn a_null_default_method_gives_new_keys_the_built_in_one() {
        // SAFETY: no preconditions.
        unsafe { RSA_set_default_method(ptr::null()) };
        // SAFETY: as above.
        assert!(unsafe { RSA_get_default_method() }.is_null());
        // SAFETY: as above.
        let r = unsafe { RSA_new() };
        // SAFETY: the key just made; the built-in method is static.
        assert_eq!(unsafe { RSA_get_method(r) }, unsafe { RSA_PKCS1_OpenSSL() });
        // SAFETY: the key made above.
        unsafe { RSA_free(r) };
        // SAFETY: no preconditions.
        let builtin = unsafe { RSA_PKCS1_OpenSSL() };
        // SAFETY: the built-in method.
        unsafe { RSA_set_default_method(builtin) };
    }
}
