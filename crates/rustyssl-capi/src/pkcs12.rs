//! PKCS #12 (step 6.5): its structures ([`asn`]), safe bags ([`bags`]), packing them into
//! contents ([`add`]), the MAC ([`mutl`]), making ([`crt`]) and reading ([`kiss`]) a PFX, and
//! changing its password ([`npas`]); here, its password strings and key derivation
//! (`p12_utl.c`, `p12_key.c`): passwords as the big-endian UTF-16 PKCS #12 hashes (`OPENSSL_asc2uni`,
//! `OPENSSL_utf82uni`) and back (`OPENSSL_uni2asc`, `OPENSSL_uni2utf8`), over
//! `rustyssl_asn1::text`, and `PKCS12_key_gen_*`, the PKCS12KDF of RFC 7292 appendix B through
//! the provider's KDF.
//!
//! Where the reference reads out of bounds (a NULL string with a length, a negative length taken
//! as a huge `size_t`) or overflows an `int`, these fail instead (docs/DEVIATIONS.md).

use core::ffi::{CStr, c_char, c_int, c_uchar};

pub(crate) mod add;
pub(crate) mod asn;
pub(crate) mod bags;
pub(crate) mod crt;
pub(crate) mod kiss;
pub(crate) mod mutl;
pub(crate) mod npas;
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_PKCS12, ERR_R_PKCS12_LIB, EVP_MD, OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_ITER,
    OSSL_KDF_PARAM_PASSWORD, OSSL_KDF_PARAM_PKCS12_ID, OSSL_KDF_PARAM_SALT, OSSL_LIB_CTX,
};
use rustyssl_asn1::text;

use crate::err;
use crate::evp::digest::EVP_MD_get0_name;
use crate::evp::kdf::{
    EVP_KDF_CTX_free, EVP_KDF_CTX_new, EVP_KDF_derive, EVP_KDF_fetch, EVP_KDF_free,
};
use crate::ffi::ffi_export;
use crate::mem;
use crate::params::{
    OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_utf8_string,
    end,
};

/// The `len` octets at `data`, a C string's for -1; `None` for a NULL string with octets or a
/// length below -1.
///
/// # Safety
/// `data` is NULL, a C string (for -1), or holds `len` octets.
unsafe fn string<'a>(data: *const c_char, len: c_int) -> Option<&'a [u8]> {
    if len == -1 {
        if data.is_null() {
            return None;
        }
        // SAFETY: the caller's guarantee: a C string for -1.
        return Some(unsafe { CStr::from_ptr(data) }.to_bytes());
    }
    // SAFETY: the caller's guarantee.
    unsafe { octets(data.cast(), len) }
}

/// The `len` octets at `data`; `None` for a negative length or NULL data with octets.
///
/// # Safety
/// `data` is NULL or holds `len` octets.
unsafe fn octets<'a>(data: *const c_uchar, len: c_int) -> Option<&'a [u8]> {
    match usize::try_from(len).ok()? {
        0 => Some(&[]),
        _ if data.is_null() => None,
        // SAFETY: the caller's guarantee.
        n => Some(unsafe { core::slice::from_raw_parts(data, n) }),
    }
}

/// A copy of `bytes` in `CRYPTO_malloc` memory, or NULL.
fn c_copy(bytes: &[u8]) -> *mut c_uchar {
    let p = mem::alloc(bytes.len()).cast::<c_uchar>();
    if !p.is_null() {
        // SAFETY: a new allocation of `bytes.len()` octets.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len()) };
    }
    p
}

/// Hands `bmp` to the caller as `OPENSSL_asc2uni` does: a copy, also stored through `uni` and
/// its length through `unilen` when they aren't NULL.
///
/// # Safety
/// `uni` and `unilen` are NULL or valid for a write.
unsafe fn give_bmp(bmp: &[u8], uni: *mut *mut c_uchar, unilen: *mut c_int) -> *mut c_uchar {
    let Ok(len) = c_int::try_from(bmp.len()) else {
        return ptr::null_mut();
    };
    let copy = c_copy(bmp);
    if copy.is_null() {
        return copy;
    }
    if !unilen.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { unilen.write(len) };
    }
    if !uni.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { uni.write(copy) };
    }
    copy
}

ffi_export! {
    /// `asclen` octets of `asc` (a C string for -1) as big-endian UTF-16, one unit per octet,
    /// with a zero unit after: a new block (`OPENSSL_free`), also stored through `uni`, its
    /// length through `unilen`. NULL for a length below -1.
    ///
    /// # Safety
    /// `asc` is a C string (for -1) or holds `asclen` octets; `uni` and `unilen` are NULL or
    /// valid for a write.
    pub unsafe extern "C" fn OPENSSL_asc2uni(asc: *const c_char, asclen: c_int, uni: *mut *mut c_uchar, unilen: *mut c_int) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        let Some(asc) = (unsafe { string(asc, asclen) }) else {
            return ptr::null_mut();
        };
        // SAFETY: the caller's guarantee.
        unsafe { give_bmp(&text::asc_to_bmp(asc), uni, unilen) }
    }
}

ffi_export! {
    /// `asclen` octets of UTF-8 `asc` (a C string for -1) as big-endian UTF-16 with a zero unit
    /// after, like `OPENSSL_asc2uni`; input that isn't UTF-8 is converted as that function
    /// does. As in OpenSSL, a length below -1 gives only the zero unit.
    ///
    /// # Safety
    /// As for `OPENSSL_asc2uni`.
    pub unsafe extern "C" fn OPENSSL_utf82uni(asc: *const c_char, asclen: c_int, uni: *mut *mut c_uchar, unilen: *mut c_int) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        let asc = if asclen < -1 {
            Some(&[][..])
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { string(asc, asclen) }
        };
        let Some(asc) = asc else {
            return ptr::null_mut();
        };
        // SAFETY: the caller's guarantee.
        unsafe { give_bmp(&text::utf8_to_bmp(asc), uni, unilen) }
    }
}

ffi_export! {
    /// The low octet of each big-endian UTF-16 unit of `uni` (`unilen` octets) as a C string
    /// (`OPENSSL_free`), or NULL for an odd or negative length.
    ///
    /// # Safety
    /// `uni` holds `unilen` octets.
    pub unsafe extern "C" fn OPENSSL_uni2asc(uni: *const c_uchar, unilen: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        match unsafe { octets(uni, unilen) }.and_then(text::bmp_to_asc) {
            Some(asc) => c_copy(&asc).cast(),
            None => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// Big-endian UTF-16 `uni` (`unilen` octets) as a UTF-8 C string (`OPENSSL_free`); input
    /// that isn't UTF-16 is converted as `OPENSSL_uni2asc` does. NULL for an odd or negative
    /// length.
    ///
    /// # Safety
    /// `uni` holds `unilen` octets.
    pub unsafe extern "C" fn OPENSSL_uni2utf8(uni: *const c_uchar, unilen: c_int) -> *mut c_char
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        match unsafe { octets(uni, unilen) }.and_then(text::bmp_to_utf8) {
            Some(utf8) => c_copy(&utf8).cast(),
            None => ptr::null_mut(),
        }
    }
}

ffi_export! {
    /// The PKCS #12 key derivation (RFC 7292 appendix B) of `ctx`'s PKCS12KDF (with `propq`):
    /// `n` octets into `out` for the purpose `id` (1 key, 2 IV, 3 MAC key) from the UTF-16
    /// password `pass` (`passlen` octets), `saltlen` octets of `salt`, `iter` iterations, and
    /// `md_type`. Returns 1, or 0.
    ///
    /// # Safety
    /// `pass` and `salt` are NULL (for 0) or hold their lengths; `out` has room for `n` octets;
    /// `md_type` is a live digest; `ctx` is NULL or a live library context; `propq` is NULL or
    /// a string.
    pub unsafe extern "C" fn PKCS12_key_gen_uni_ex(pass: *mut c_uchar, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, id: c_int, iter: c_int, n: c_int, out: *mut c_uchar, md_type: *const EVP_MD, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        let Ok(n @ 1..) = usize::try_from(n) else {
            return 0;
        };
        // The lengths the reference would take as huge `size_t`s, or read from NULL.
        // SAFETY: the caller's guarantee.
        let (Some(_), Some(_)) = (unsafe { octets(pass, passlen) }, unsafe { octets(salt, saltlen) }) else {
            return 0;
        };
        let (Ok(passlen), Ok(saltlen)) = (usize::try_from(passlen), usize::try_from(saltlen)) else {
            return 0;
        };
        // SAFETY: the caller's library context and query; a static name.
        let kdf = unsafe { EVP_KDF_fetch(ctx, c"PKCS12KDF".as_ptr(), propq) };
        if kdf.is_null() {
            return 0;
        }
        // SAFETY: the method just fetched.
        let kctx = unsafe { EVP_KDF_CTX_new(kdf) };
        // SAFETY: as above; the context holds its own reference.
        unsafe { EVP_KDF_free(kdf) };
        if kctx.is_null() {
            return 0;
        }
        let (mut id, mut iter) = (id, iter);
        // SAFETY: the caller's digest.
        let mdname = unsafe { EVP_MD_get0_name(md_type) };
        let params = [
            // SAFETY: the caller's buffers and locals, which outlive the derivation.
            unsafe { OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST.as_ptr(), mdname.cast_mut(), 0) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD.as_ptr(), pass.cast(), passlen) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT.as_ptr(), salt.cast(), saltlen) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS12_ID.as_ptr(), &raw mut id) },
            // SAFETY: as above.
            unsafe { OSSL_PARAM_construct_int(OSSL_KDF_PARAM_ITER.as_ptr(), &raw mut iter) },
            end(),
        ];
        // SAFETY: the context made here; the caller's room; the array above.
        let rv = c_int::from(unsafe { EVP_KDF_derive(kctx, out, n, params.as_ptr()) } == 1);
        // SAFETY: the context made here.
        unsafe { EVP_KDF_CTX_free(kctx) };
        rv
    }
}

ffi_export! {
    /// `PKCS12_key_gen_uni_ex` in the default library context.
    ///
    /// # Safety
    /// As for `PKCS12_key_gen_uni_ex`.
    pub unsafe extern "C" fn PKCS12_key_gen_uni(pass: *mut c_uchar, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, id: c_int, iter: c_int, n: c_int, out: *mut c_uchar, md_type: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_key_gen_uni_ex(pass, passlen, salt, saltlen, id, iter, n, out, md_type, ptr::null_mut(), ptr::null()) }
    }
}

/// `PKCS12_key_gen_uni_ex` over the UTF-16 password `bmp` (`None` for a NULL password).
///
/// # Safety
/// As for `PKCS12_key_gen_uni_ex`, but for the password.
#[expect(
    clippy::too_many_arguments,
    reason = "the reference's function, one to one"
)]
unsafe fn key_gen_bmp(
    bmp: Option<&[u8]>,
    salt: *mut c_uchar,
    saltlen: c_int,
    id: c_int,
    iter: c_int,
    n: c_int,
    out: *mut c_uchar,
    md_type: *const EVP_MD,
    ctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> c_int {
    let (pass, passlen) = match bmp {
        Some(bmp) => match c_int::try_from(bmp.len()) {
            Ok(len) => (bmp.as_ptr().cast_mut(), len),
            Err(_) => return 0,
        },
        None => (ptr::null_mut(), 0),
    };
    // SAFETY: the caller's guarantee; `bmp` holds `passlen` octets and is only read.
    let rv = unsafe {
        PKCS12_key_gen_uni_ex(
            pass, passlen, salt, saltlen, id, iter, n, out, md_type, ctx, propq,
        )
    };
    c_int::from(rv > 0)
}

ffi_export! {
    /// `PKCS12_key_gen_uni_ex` with the password `pass` (`passlen` octets, a C string for -1;
    /// none for NULL) converted as `OPENSSL_asc2uni` converts it.
    ///
    /// # Safety
    /// As for `PKCS12_key_gen_uni_ex`, with `pass` NULL, a C string (for -1), or holding
    /// `passlen` octets.
    pub unsafe extern "C" fn PKCS12_key_gen_asc_ex(pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, id: c_int, iter: c_int, n: c_int, out: *mut c_uchar, md_type: *const EVP_MD, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        if pass.is_null() {
            // SAFETY: the caller's guarantee.
            return unsafe { key_gen_bmp(None, salt, saltlen, id, iter, n, out, md_type, ctx, propq) };
        }
        // SAFETY: the caller's guarantee.
        let Some(pass) = (unsafe { string(pass, passlen) }) else {
            err::raise(ERR_LIB_PKCS12, ERR_R_PKCS12_LIB, "PKCS12_key_gen_asc_ex");
            return 0;
        };
        let bmp = text::asc_to_bmp(pass);
        // SAFETY: the caller's guarantee.
        unsafe { key_gen_bmp(Some(&bmp), salt, saltlen, id, iter, n, out, md_type, ctx, propq) }
    }
}

ffi_export! {
    /// `PKCS12_key_gen_asc_ex` in the default library context.
    ///
    /// # Safety
    /// As for `PKCS12_key_gen_asc_ex`.
    pub unsafe extern "C" fn PKCS12_key_gen_asc(pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, id: c_int, iter: c_int, n: c_int, out: *mut c_uchar, md_type: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_key_gen_asc_ex(pass, passlen, salt, saltlen, id, iter, n, out, md_type, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// `PKCS12_key_gen_uni_ex` with the UTF-8 password `pass` (`passlen` octets, a C string for
    /// -1; none for NULL) converted as `OPENSSL_utf82uni` converts it.
    ///
    /// # Safety
    /// As for `PKCS12_key_gen_asc_ex`.
    pub unsafe extern "C" fn PKCS12_key_gen_utf8_ex(pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, id: c_int, iter: c_int, n: c_int, out: *mut c_uchar, md_type: *const EVP_MD, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        if pass.is_null() {
            // SAFETY: the caller's guarantee.
            return unsafe { key_gen_bmp(None, salt, saltlen, id, iter, n, out, md_type, ctx, propq) };
        }
        let pass = if passlen < -1 {
            // As `OPENSSL_utf82uni` takes it: no octets.
            Some(&[][..])
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { string(pass, passlen) }
        };
        let Some(pass) = pass else {
            err::raise(ERR_LIB_PKCS12, ERR_R_PKCS12_LIB, "PKCS12_key_gen_utf8_ex");
            return 0;
        };
        let bmp = text::utf8_to_bmp(pass);
        // SAFETY: the caller's guarantee.
        unsafe { key_gen_bmp(Some(&bmp), salt, saltlen, id, iter, n, out, md_type, ctx, propq) }
    }
}

ffi_export! {
    /// `PKCS12_key_gen_utf8_ex` in the default library context.
    ///
    /// # Safety
    /// As for `PKCS12_key_gen_utf8_ex`.
    pub unsafe extern "C" fn PKCS12_key_gen_utf8(pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, id: c_int, iter: c_int, n: c_int, out: *mut c_uchar, md_type: *const EVP_MD) -> c_int
    where failure = 0, library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_key_gen_utf8_ex(pass, passlen, salt, saltlen, id, iter, n, out, md_type, ptr::null_mut(), ptr::null()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: lengths the reference would read out of bounds with fail.
    #[test]
    fn out_of_bounds_lengths_fail() {
        let null = ptr::null_mut();
        // SAFETY: NULL with a length is the case under test, here and below.
        assert!(unsafe { OPENSSL_asc2uni(ptr::null(), -1, null, ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { OPENSSL_asc2uni(ptr::null(), 3, null, ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { OPENSSL_utf82uni(ptr::null(), 3, null, ptr::null_mut()) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { OPENSSL_uni2asc(ptr::null(), 4) }.is_null());
        // SAFETY: as above.
        assert!(unsafe { OPENSSL_uni2utf8(ptr::null(), 4) }.is_null());
        let mut out = [0u8; 8];
        let mut salt = [1u8; 8];
        let mut pass = [0u8, b'a', 0, 0];
        let (o, s, p) = (out.as_mut_ptr(), salt.as_mut_ptr(), pass.as_mut_ptr());
        for (p, passlen, s, saltlen) in [
            (p, -2, s, 8),
            (p, 4, s, -2),
            (ptr::null_mut(), 4, s, 8),
            (p, 4, ptr::null_mut(), 8),
        ] {
            // SAFETY: the lengths and NULLs under test; `out` has room for 8 octets.
            let r = unsafe { PKCS12_key_gen_uni(p, passlen, s, saltlen, 1, 1, 8, o, ptr::null()) };
            assert_eq!(r, 0);
        }
        assert_eq!(out, [0; 8]);
    }
}
