//! Reading a PEM block by name (`PEM_bytes_read_bio(3)`, `PEM_bytes_read_bio_secmem`,
//! `PEM_ASN1_read(3)`, `PEM_ASN1_read_bio`; `pem_lib.c`, `pem_oth.c`): the first block whose name
//! stands for the one asked for, decrypted if its header says so, and decoded with the caller's
//! `d2i` function.
//!
//! As in OpenSSL (`check_pem`), a name stands for itself and:
//! - "ANY PRIVATE KEY" for PKCS#8's names and "<TYPE> PRIVATE KEY" where the PEM name `<TYPE>`
//!   has an ASN.1 method with a traditional private key decoder (RSA, DSA, EC; applications'
//!   methods can't have one);
//! - "PARAMETERS" for "<TYPE> PARAMETERS" where the method decodes parameters (DH, X9.42 DH,
//!   DSA, EC, and applications' methods given a `param_decode`);
//! - "DH PARAMETERS" for X9.42's; "CERTIFICATE" for "X509 CERTIFICATE"; "CERTIFICATE REQUEST"
//!   for "NEW CERTIFICATE REQUEST"; "TRUSTED CERTIFICATE" for both certificate names; "PKCS7"
//!   for "CERTIFICATE" and "PKCS #7 SIGNED DATA"; "CMS" for "CERTIFICATE" and "PKCS7".
//!
//! Blocks of other names are skipped; running out of blocks adds "Expecting: <name>" to the
//! `PEM_R_NO_START_LINE` error.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    BIO, BIO_NOCLOSE, ERR_LIB_PEM, ERR_R_ASN1_LIB, ERR_R_BUF_LIB, ERR_REASON_MASK, ERR_SYSTEM_FLAG,
    EVP_CIPHER_INFO, PEM_R_NO_START_LINE, PEM_STRING_CMS, PEM_STRING_DHPARAMS,
    PEM_STRING_DHXPARAMS, PEM_STRING_EVP_PKEY, PEM_STRING_PARAMETERS, PEM_STRING_PKCS7,
    PEM_STRING_PKCS7_SIGNED, PEM_STRING_PKCS8, PEM_STRING_PKCS8INF, PEM_STRING_X509,
    PEM_STRING_X509_OLD, PEM_STRING_X509_REQ, PEM_STRING_X509_REQ_OLD, PEM_STRING_X509_TRUSTED,
    d2i_of_void, pem_password_cb,
};
use rustyssl_asn1::pem::{FLAG_EAY_COMPATIBLE, FLAG_SECURE};

use crate::err;
use crate::evp::pkey::ameth;
use crate::ffi::ffi_export;
use crate::pem::PEM_read_bio_ex;
use crate::pem_cipher::{PEM_do_header, PEM_get_EVP_CIPHER_INFO};

/// `ossl_pem_check_suffix`: the length of the part of `pem` before " `suffix`", or `None` if
/// it doesn't end so (or nothing comes before).
pub(crate) fn check_suffix<'a>(pem: &'a [u8], suffix: &[u8]) -> Option<&'a [u8]> {
    if suffix.len() + 1 >= pem.len() {
        return None;
    }
    let (head, tail) = pem.split_at(pem.len() - suffix.len());
    if tail != suffix {
        return None;
    }
    let (name, space) = head.split_at(head.len() - 1);
    (space == b" ").then_some(name)
}

/// `check_pem`: whether the block named `nm` is one `name` asks for.
fn check_pem(nm: &[u8], name: &[u8]) -> bool {
    let is = |s: &CStr, v: &[u8]| s.to_bytes() == v;
    if nm == name {
        return true;
    }
    if is(PEM_STRING_EVP_PKEY, name) {
        if is(PEM_STRING_PKCS8, nm) || is(PEM_STRING_PKCS8INF, nm) {
            return true;
        }
        return check_suffix(nm, b"PRIVATE KEY")
            .and_then(ameth::find_str)
            .is_some_and(|m| m.get().funcs().old_priv_decode.is_some());
    }
    if is(PEM_STRING_PARAMETERS, name) {
        return check_suffix(nm, b"PARAMETERS")
            .and_then(ameth::find_str)
            .is_some_and(|m| m.get().funcs().param_decode.is_some());
    }
    let pairs: [(&CStr, &CStr); 9] = [
        (PEM_STRING_DHXPARAMS, PEM_STRING_DHPARAMS),
        (PEM_STRING_X509_OLD, PEM_STRING_X509),
        (PEM_STRING_X509_REQ_OLD, PEM_STRING_X509_REQ),
        (PEM_STRING_X509, PEM_STRING_X509_TRUSTED),
        (PEM_STRING_X509_OLD, PEM_STRING_X509_TRUSTED),
        (PEM_STRING_X509, PEM_STRING_PKCS7),
        (PEM_STRING_PKCS7_SIGNED, PEM_STRING_PKCS7),
        (PEM_STRING_X509, PEM_STRING_CMS),
        (PEM_STRING_PKCS7, PEM_STRING_CMS),
    ];
    pairs.iter().any(|(a, b)| is(a, nm) && is(b, name))
}

/// `PEM_FREE`.
///
/// # Safety
/// `p` is NULL or a block `PEM_read_bio_ex` made with `flags`, of `num` octets.
unsafe fn pem_free(p: *mut c_void, flags: u32, num: usize) {
    if flags & FLAG_SECURE != 0 {
        // SAFETY: the caller's guarantee.
        unsafe { crate::secure::CRYPTO_secure_clear_free(p, num, ptr::null(), 0) };
    } else {
        // SAFETY: as above.
        unsafe { crate::mem::release(p) };
    }
}

/// Whether the oldest error queued is `PEM_R_NO_START_LINE` (`ERR_GET_REASON(ERR_peek_error())`).
fn no_start_line() -> bool {
    // SAFETY: no preconditions.
    let code: c_ulong = unsafe { err::ERR_peek_error() };
    code & c_ulong::from(ERR_SYSTEM_FLAG) == 0
        && code & c_ulong::from(ERR_REASON_MASK.cast_unsigned())
            == c_ulong::from(PEM_R_NO_START_LINE.cast_unsigned())
}

/// `pem_bytes_read_bio_flags`.
///
/// # Safety
/// `pdata`, `plen` are room for their values; `pnm` is NULL or room for a pointer; `name` is a
/// string; `bp` is a live BIO; `cb` is NULL or a password callback taking `u`.
#[expect(
    clippy::too_many_arguments,
    reason = "OpenSSL's internal function's arguments"
)]
unsafe fn read_flags(
    pdata: *mut *mut c_uchar,
    plen: *mut c_long,
    pnm: *mut *mut c_char,
    name: *const c_char,
    bp: *mut BIO,
    cb: pem_password_cb,
    u: *mut c_void,
    flags: u32,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let wanted = unsafe { CStr::from_ptr(name) }.to_bytes();
    let mut nm: *mut c_char = ptr::null_mut();
    let mut header: *mut c_char = ptr::null_mut();
    let mut data: *mut c_uchar = ptr::null_mut();
    let mut len: c_long = 0;
    loop {
        // SAFETY: the blocks of the previous turn (or NULL), each freed once.
        unsafe { pem_free(nm.cast(), flags, 0) };
        // SAFETY: as above.
        unsafe { pem_free(header.cast(), flags, 0) };
        // SAFETY: as above.
        unsafe { pem_free(data.cast(), flags, usize::try_from(len).unwrap_or(0)) };
        (nm, header, data) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        // SAFETY: the caller's BIO; room for each value.
        let r = unsafe {
            PEM_read_bio_ex(
                bp,
                &raw mut nm,
                &raw mut header,
                &raw mut data,
                &raw mut len,
                flags,
            )
        };
        if r == 0 {
            if no_start_line() {
                err::add_error_data([Some(&b"Expecting: "[..]), Some(wanted)]);
            }
            return 0;
        }
        // SAFETY: the name `PEM_read_bio_ex` made.
        let got = unsafe { CStr::from_ptr(nm) }.to_bytes();
        if check_pem(got, wanted) {
            break;
        }
    }
    let mut cipher = EVP_CIPHER_INFO {
        cipher: ptr::null(),
        iv: [0; 16],
    };
    // SAFETY: the header `PEM_read_bio_ex` made; the local.
    let mut ok = unsafe { PEM_get_EVP_CIPHER_INFO(header, &raw mut cipher) } != 0;
    // SAFETY: as above; the data and its length; the caller's callback.
    ok = ok && unsafe { PEM_do_header(&raw mut cipher, data, &raw mut len, cb, u) } != 0;
    if ok {
        // SAFETY: the caller's guarantee.
        unsafe { pdata.write(data) };
        // SAFETY: as above.
        unsafe { plen.write(len) };
        if !pnm.is_null() {
            // SAFETY: as above.
            unsafe { pnm.write(nm) };
        }
    }
    if !ok || pnm.is_null() {
        // SAFETY: the name, freed once (or given to the caller).
        unsafe { pem_free(nm.cast(), flags, 0) };
    }
    // SAFETY: the header, freed once.
    unsafe { pem_free(header.cast(), flags, 0) };
    if !ok {
        // SAFETY: the data, freed once.
        unsafe { pem_free(data.cast(), flags, usize::try_from(len).unwrap_or(0)) };
    }
    c_int::from(ok)
}

ffi_export! {
    /// Reads the first PEM block from `bp` named `name` (or a name it stands for), decrypted with
    /// `cb`'s password (or `u`, as the default callback takes it) if it's encrypted: its data in
    /// `*pdata` (freed with `OPENSSL_free`), its length in `*plen`, and its name in `*pnm` unless
    /// that's NULL. 1, or 0 with an error.
    ///
    /// # Safety
    /// `pdata` and `plen` are room for their values; `pnm` is NULL or room for a pointer; `name`
    /// is a string; `bp` is a live BIO; `cb` is NULL or a password callback taking `u`.
    pub unsafe extern "C" fn PEM_bytes_read_bio(pdata: *mut *mut c_uchar, plen: *mut c_long, pnm: *mut *mut c_char, name: *const c_char, bp: *mut BIO, cb: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_flags(pdata, plen, pnm, name, bp, cb, u, FLAG_EAY_COMPATIBLE) }
    }
}

ffi_export! {
    /// `PEM_bytes_read_bio` with the data and name from the secure heap (freed with
    /// `OPENSSL_secure_free`).
    ///
    /// # Safety
    /// As for `PEM_bytes_read_bio`.
    pub unsafe extern "C" fn PEM_bytes_read_bio_secmem(pdata: *mut *mut c_uchar, plen: *mut c_long, pnm: *mut *mut c_char, name: *const c_char, bp: *mut BIO, cb: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_flags(pdata, plen, pnm, name, bp, cb, u, FLAG_SECURE | FLAG_EAY_COMPATIBLE) }
    }
}

ffi_export! {
    /// Reads the PEM block `name` from `bp` as `PEM_bytes_read_bio` does and decodes its data with
    /// `d2i` (into `*x` if the function does): what it decodes, or NULL with an error.
    ///
    /// # Safety
    /// `d2i` is a decoding function of OpenSSL's kind; `x` is what it takes; otherwise as for
    /// `PEM_bytes_read_bio`.
    pub unsafe extern "C" fn PEM_ASN1_read_bio(d2i: d2i_of_void, name: *const c_char, bp: *mut BIO, x: *mut *mut c_void, cb: pem_password_cb, u: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        let mut data: *mut c_uchar = ptr::null_mut();
        let mut len: c_long = 0;
        // SAFETY: the caller's guarantee; the locals.
        if unsafe { PEM_bytes_read_bio(&raw mut data, &raw mut len, ptr::null_mut(), name, bp, cb, u) } == 0 {
            return ptr::null_mut();
        }
        let mut p = data.cast_const();
        let ret = match d2i {
            // SAFETY: the caller's function and object; the data and its length.
            Some(f) => unsafe { f(x, &raw mut p, len) },
            // The reference calls through NULL (docs/DEVIATIONS.md).
            None => ptr::null_mut(),
        };
        if ret.is_null() {
            err::raise(ERR_LIB_PEM, ERR_R_ASN1_LIB, "PEM_ASN1_read_bio");
        }
        // SAFETY: the data `PEM_bytes_read_bio` made.
        unsafe { crate::mem::release(data.cast()) };
        ret
    }
}

ffi_export! {
    /// `PEM_ASN1_read_bio` from a `FILE`.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; otherwise as for `PEM_ASN1_read_bio`.
    pub unsafe extern "C" fn PEM_ASN1_read(d2i: d2i_of_void, name: *const c_char, fp: *mut FILE, x: *mut *mut c_void, cb: pem_password_cb, u: *mut c_void) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's file.
        let b = unsafe { crate::bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
        if b.is_null() {
            err::raise(ERR_LIB_PEM, ERR_R_BUF_LIB, "PEM_ASN1_read");
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; the BIO above.
        let ret = unsafe { PEM_ASN1_read_bio(d2i, name, b, x, cb, u) };
        // SAFETY: made above.
        unsafe { crate::bio::BIO_free(b) };
        ret
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixes() {
        assert_eq!(
            check_suffix(b"RSA PRIVATE KEY", b"PRIVATE KEY"),
            Some(&b"RSA"[..])
        );
        assert_eq!(
            check_suffix(b"X9.42 DH PARAMETERS", b"PARAMETERS"),
            Some(&b"X9.42 DH"[..])
        );
        assert_eq!(check_suffix(b" PARAMETERS", b"PARAMETERS"), None);
        assert_eq!(check_suffix(b"XPARAMETERS", b"PARAMETERS"), None);
        assert_eq!(check_suffix(b"PARAMETERS", b"PARAMETERS"), None);
    }

    #[test]
    fn names_stand_for_others() {
        assert!(check_pem(b"RSA PRIVATE KEY", b"ANY PRIVATE KEY"));
        assert!(!check_pem(b"DH PRIVATE KEY", b"ANY PRIVATE KEY"));
        assert!(check_pem(b"DH PARAMETERS", b"PARAMETERS"));
        assert!(!check_pem(b"RSA PARAMETERS", b"PARAMETERS"));
        assert!(check_pem(b"PKCS7", b"CMS"));
        assert!(!check_pem(b"CMS", b"PKCS7"));
    }
}

#[cfg(test)]
mod null_tests {
    use super::*;

    /// docs/DEVIATIONS.md: `PEM_ASN1_read_bio` without a decoding function fails (the reference
    /// calls through NULL).
    #[test]
    fn a_null_decoder_fails() {
        let text = b"-----BEGIN X-----\nAgEB\n-----END X-----\n";
        let len = c_int::try_from(text.len()).unwrap();
        // SAFETY: the text, which outlives the BIO.
        let b = unsafe { crate::bio::mem::BIO_new_mem_buf(text.as_ptr().cast(), len) };
        // SAFETY: the BIO; a static name; no decoder.
        let got = unsafe {
            PEM_ASN1_read_bio(
                None,
                c"X".as_ptr(),
                b,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
            )
        };
        assert!(got.is_null());
        // SAFETY: made above.
        unsafe { crate::bio::BIO_free(b) };
        crate::err::take_all();
    }
}
