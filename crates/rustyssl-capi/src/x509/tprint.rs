//! Printing certificates, CRLs, requests, and attribute certificates (`t_x509.c`, `t_crl.c`,
//! `t_req.c`, `t_acert.c`): `X509_print_ex` and its forms, `X509_signature_print`,
//! `X509_aux_print`, `X509_ocspid_print`, `X509_STORE_CTX_print_verify_cb`,
//! `X509_CRL_print_ex`, `X509_REQ_print_ex`, and `X509_ACERT_print_ex`, byte for byte as
//! OpenSSL prints them. The signature and serial-number printers are in `print.rs`.
//!
//! A NULL object, which OpenSSL reads through, prints nothing and fails (docs/DEVIATIONS.md).

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    ASN1_BIT_STRING, ASN1_DTFLGS_RFC822, ASN1_INTEGER, ASN1_OBJECT, ASN1_STRFLGS_ESC_QUOTE,
    ASN1_STRFLGS_RFC2253, ASN1_STRING, BIO, BIO_NOCLOSE, ERR_LIB_X509, ERR_R_BUF_LIB, GENERAL_NAME,
    V_ASN1_IA5STRING, V_ASN1_NUMERICSTRING, V_ASN1_PRINTABLESTRING, V_ASN1_SEQUENCE,
    V_ASN1_T61STRING, V_ASN1_UTF8STRING, X509, X509_ACERT, X509_ACERT_VERSION_2, X509_ALGOR,
    X509_ATTRIBUTE, X509_CRL, X509_CRL_VERSION_1, X509_CRL_VERSION_2, X509_EXTENSION,
    X509_FLAG_EXTENSIONS_ONLY_KID, X509_FLAG_NO_ATTRIBUTES, X509_FLAG_NO_AUX,
    X509_FLAG_NO_EXTENSIONS, X509_FLAG_NO_HEADER, X509_FLAG_NO_IDS, X509_FLAG_NO_ISSUER,
    X509_FLAG_NO_PUBKEY, X509_FLAG_NO_SERIAL, X509_FLAG_NO_SIGDUMP, X509_FLAG_NO_SIGNAME,
    X509_FLAG_NO_SUBJECT, X509_FLAG_NO_VALIDITY, X509_FLAG_NO_VERSION,
    X509_R_CERTIFICATE_VERIFICATION_FAILED, X509_R_INVALID_ATTRIBUTES, X509_REQ,
    X509_REQ_VERSION_1, X509_REVOKED, X509_STORE, X509_STORE_CTX, X509_V_ERR_CERT_UNTRUSTED,
    X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, X509_V_ERR_EMAIL_MISMATCH,
    X509_V_ERR_HOSTNAME_MISMATCH, X509_V_ERR_IP_ADDRESS_MISMATCH,
    X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN, X509_V_ERR_STORE_LOOKUP,
    X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER, X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
    X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY, X509_V_OK, X509_VERSION_1, X509_VERSION_3,
    XN_FLAG_COMPAT, XN_FLAG_FN_SN, XN_FLAG_SEP_CPLUS_SPC, XN_FLAG_SEP_MASK, XN_FLAG_SEP_MULTILINE,
    stack_st_X509, stack_st_X509_EXTENSION,
};

use super::acert::{
    OSSL_ISSUER_SERIAL_get0_issuer, OSSL_ISSUER_SERIAL_get0_issuerUID,
    OSSL_ISSUER_SERIAL_get0_serial, X509_ACERT_get_attr, X509_ACERT_get_attr_count,
    X509_ACERT_get_version, X509_ACERT_get0_extensions, X509_ACERT_get0_holder_baseCertId,
    X509_ACERT_get0_holder_entityName, X509_ACERT_get0_issuerName, X509_ACERT_get0_notAfter,
    X509_ACERT_get0_notBefore, X509_ACERT_get0_serialNumber, X509_ACERT_get0_signature,
};
use super::attrib::{X509_ATTRIBUTE_count, X509_ATTRIBUTE_get0_object, X509_ATTRIBUTE_get0_type};
use super::cert::{
    OSSL_STACK_OF_X509_free, X509_cmp_current_time, X509_get_X509_PUBKEY, X509_get_issuer_name,
    X509_get_subject_name, X509_get_version, X509_get0_extensions, X509_get0_notAfter,
    X509_get0_notBefore, X509_get0_pubkey, X509_get0_pubkey_bitstr, X509_get0_serialNumber,
    X509_get0_signature, X509_get0_tbs_sigalg, X509_get0_uids, cert_of,
};
use super::crl::{
    X509_CRL_get_REVOKED, X509_CRL_get_issuer, X509_CRL_get_version, X509_CRL_get0_extensions,
    X509_CRL_get0_lastUpdate, X509_CRL_get0_nextUpdate, X509_CRL_get0_signature,
    X509_REVOKED_get0_extensions, X509_REVOKED_get0_revocationDate, X509_REVOKED_get0_serialNumber,
};
use super::ctx::{
    X509_STORE_CTX_get_current_cert, X509_STORE_CTX_get_error, X509_STORE_CTX_get_error_depth,
    X509_STORE_CTX_get0_parent_ctx, X509_STORE_CTX_get0_store, X509_STORE_CTX_get0_untrusted,
    X509_verify_cert_error_string,
};
use super::ext::{X509_EXTENSION_get_critical, X509_EXTENSION_get_data, X509_EXTENSION_get_object};
use super::name::{X509_NAME_print_ex, i2d_X509_NAME};
use super::print::{X509_signature_dump, serial_number_print, sig_print};
use super::pubkey::X509_PUBKEY_get0_param;
use super::purpose::X509_check_issued;
use super::req::{
    X509_REQ_extension_nid, X509_REQ_get_X509_PUBKEY, X509_REQ_get_attr, X509_REQ_get_attr_count,
    X509_REQ_get_extensions, X509_REQ_get_subject_name, X509_REQ_get_version, X509_REQ_get0_pubkey,
    X509_REQ_get0_signature,
};
use super::store::{X509_STORE_get0_param, X509_STORE_get1_all_certs};
use super::trust::{
    X509_alias_get0, X509_get0_reject_objects, X509_get0_trust_objects, X509_keyid_get0,
    X509_trusted,
};
use super::vpm::{
    X509_VERIFY_PARAM_get0_email, X509_VERIFY_PARAM_get0_host, X509_VERIFY_PARAM_get1_ip_asc,
};
use crate::asn1::integer::i2a_ASN1_INTEGER;
use crate::asn1::parse::ASN1_parse_dump;
use crate::asn1::text::ASN1_STRING_print;
use crate::asn1::time::{ASN1_GENERALIZEDTIME_print, ASN1_TIME_print, print_time};
use crate::bio::mem::BIO_s_mem;
use crate::bio::print::BIO_printf;
use crate::bio::{BIO_free, BIO_new, BIO_puts, BIO_write};
use crate::err;
use crate::err::strings::{ERR_add_error_mem_bio, ERR_print_errors};
use crate::evp::digest::{EVP_MD_fetch, EVP_MD_free};
use crate::evp::md_ctx::EVP_Digest;
use crate::evp::pkey::print::EVP_PKEY_print_public;
use crate::ffi::ffi_export;
use crate::mem;
use crate::objects::{OBJ_obj2nid, OBJ_obj2txt, i2a_ASN1_OBJECT};
use crate::stack::{OPENSSL_sk_num, OPENSSL_sk_pop_free, OPENSSL_sk_value};
use crate::x509v3::registry::{X509V3_EXT_print, X509V3_extensions_print};
use crate::x509v3::san::GENERAL_NAME_print;

/// `BIO_printf`'s result.
macro_rules! printf {
    ($bp:expr, $fmt:expr $(, $arg:expr)*) => {
        // SAFETY: a live BIO; a format with matching arguments.
        unsafe { BIO_printf($bp, $fmt.as_ptr() $(, $arg)*) }
    };
}

/// An empty C string, for `%*s` padding.
const E: *const c_char = c"".as_ptr();

/// A flag of `x509.h` or `asn1.h` (all non-negative) as the printers' `unsigned long`.
fn fl(v: c_long) -> c_ulong {
    v.cast_unsigned()
}

/// As [`fl`], for an `int` flag.
fn fli(v: c_int) -> c_ulong {
    c_ulong::from(v.cast_unsigned())
}

/// `BIO_write` of octets: its result.
fn write(bp: *mut BIO, s: &[u8]) -> c_int {
    let n = c_int::try_from(s.len()).unwrap_or(c_int::MAX);
    // SAFETY: a live BIO; the octets.
    unsafe { BIO_write(bp, s.as_ptr().cast(), n) }
}

/// `BIO_puts`: its result.
fn puts(bp: *mut BIO, s: &core::ffi::CStr) -> c_int {
    // SAFETY: a live BIO; a C string.
    unsafe { BIO_puts(bp, s.as_ptr()) }
}

/// `printok` and the names' separator and indent for `nmflags`.
fn name_layout(nmflags: c_ulong) -> (c_int, c_int, c_int) {
    let (mlch, nmindent) = if nmflags & fli(XN_FLAG_SEP_MASK) == fli(XN_FLAG_SEP_MULTILINE) {
        (c_int::from(b'\n'), 12)
    } else {
        (c_int::from(b' '), 0)
    };
    (mlch, nmindent, c_int::from(nmflags == fli(XN_FLAG_COMPAT)))
}

/// Runs `f` on a BIO over `fp`, left open (0 and `ERR_R_BUF_LIB` if none).
///
/// # Safety
/// `fp` is an open `FILE`.
unsafe fn with_fp(fp: *mut FILE, func: &'static str, f: impl FnOnce(*mut BIO) -> c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let b = unsafe { crate::bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
    if b.is_null() {
        err::raise(ERR_LIB_X509, ERR_R_BUF_LIB, func);
        return 0;
    }
    let ret = f(b);
    // SAFETY: the BIO made above.
    unsafe { BIO_free(b) };
    ret
}

ffi_export! {
    /// Prints "Signature Algorithm: " and the algorithm, then (with `sig`) the signature, by
    /// its key type's printer or in hex, 4 and 8 in: positive, or 0. A NULL algorithm fails.
    ///
    /// # Safety
    /// `bp` is a live BIO; `sigalg` is NULL or a live AlgorithmIdentifier; `sig` is NULL or a
    /// live string.
    pub unsafe extern "C" fn X509_signature_print(bp: *mut BIO, sigalg: *const X509_ALGOR, sig: *const ASN1_STRING) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        let indent: c_int = 4;
        // SAFETY: the caller's guarantee.
        let Some(alg) = (unsafe { sigalg.as_ref() }) else { return 0 };
        if printf!(bp, c"%*sSignature Algorithm: ", indent, E) <= 0 {
            return 0;
        }
        // SAFETY: as above; its object.
        if unsafe { i2a_ASN1_OBJECT(bp, alg.algorithm) } <= 0 {
            return 0;
        }
        if !sig.is_null() && printf!(bp, c"\n%*sSignature Value:", indent, E) <= 0 {
            return 0;
        }
        // SAFETY: as above.
        if let Some(r) = unsafe { sig_print(bp, alg, sig, indent + 4) } {
            return r;
        }
        if write(bp, b"\n") != 1 {
            return 0;
        }
        if sig.is_null() {
            return 1;
        }
        // SAFETY: as above.
        unsafe { X509_signature_dump(bp, sig, indent + 4) }
    }
}

/// `%02X` of each octet, after `sep` but the first.
fn hex_upper(bp: *mut BIO, s: &[u8], sep: bool) -> bool {
    s.iter().enumerate().all(|(i, &b)| {
        let p = if sep && i > 0 { c":" } else { c"" };
        printf!(bp, c"%s%02X", p.as_ptr(), c_uint::from(b)) > 0
    })
}

/// A list of objects for [`X509_aux_print`].
///
/// # Safety
/// `out` is a live BIO; `objs` is a live list of objects.
unsafe fn print_uses(out: *mut BIO, objs: *mut rustyssl_abi::stack_st_ASN1_OBJECT) {
    // SAFETY: the caller's list.
    for i in 0..unsafe { OPENSSL_sk_num(objs.cast()) } {
        if i > 0 {
            puts(out, c", ");
        }
        let mut buf = [0 as c_char; 80];
        // SAFETY: an index within the list.
        let o = unsafe { OPENSSL_sk_value(objs.cast(), i) }.cast::<ASN1_OBJECT>();
        // SAFETY: the buffer and its size; the list's object.
        unsafe { OBJ_obj2txt(buf.as_mut_ptr(), 80, o, 0) };
        // SAFETY: as above; NUL-terminated by `OBJ_obj2txt`.
        unsafe { BIO_puts(out, buf.as_ptr()) };
    }
    puts(out, c"\n");
}

ffi_export! {
    /// Prints a trusted certificate's auxiliary data at `indent`: its trusted and rejected
    /// uses, alias, and key identifier: 1 (nothing for an untrusted one); 0 for NULL.
    ///
    /// # Safety
    /// `out` is a live BIO; `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_aux_print(out: *mut BIO, x: *mut X509, indent: c_int) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if x.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        if unsafe { X509_trusted(x) } == 0 {
            return 1;
        }
        let inner = indent.saturating_add(2);
        // SAFETY: as above.
        let trust = unsafe { X509_get0_trust_objects(x) };
        // SAFETY: as above.
        let reject = unsafe { X509_get0_reject_objects(x) };
        for (list, have, none) in [
            (trust, c"%*sTrusted Uses:\n%*s", c"%*sNo Trusted Uses.\n"),
            (reject, c"%*sRejected Uses:\n%*s", c"%*sNo Rejected Uses.\n"),
        ] {
            if list.is_null() {
                printf!(out, none, indent, E);
            } else {
                printf!(out, have, indent, E, inner, E);
                // SAFETY: the certificate's list.
                unsafe { print_uses(out, list) };
            }
        }
        let mut n = 0;
        // SAFETY: as above; a local.
        let alias = unsafe { X509_alias_get0(x, &raw mut n) };
        if !alias.is_null() {
            printf!(out, c"%*sAlias: %.*s\n", indent, E, n, alias);
        }
        let mut keyidlen = 0;
        // SAFETY: as above.
        let keyid = unsafe { X509_keyid_get0(x, &raw mut keyidlen) };
        if !keyid.is_null() {
            printf!(out, c"%*sKey Id: ", indent, E);
            let len = usize::try_from(keyidlen).unwrap_or(0);
            // SAFETY: the key identifier's octets.
            let s = unsafe { core::slice::from_raw_parts(keyid, len) };
            hex_upper(out, s, true);
            write(out, b"\n");
        }
        1
    }
}

/// [`X509_print_ex`]'s body: whether it printed.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live certificate.
unsafe fn print_cert(bp: *mut BIO, x: *mut X509, nmflags: c_ulong, cflag: c_ulong) -> bool {
    let (mlch, nmindent, printok) = name_layout(nmflags);
    let on = |f: c_long| cflag & fl(f) == 0;
    if on(X509_FLAG_NO_HEADER)
        && (write(bp, b"Certificate:\n") <= 0 || write(bp, b"    Data:\n") <= 0)
    {
        return false;
    }
    if on(X509_FLAG_NO_VERSION) {
        // SAFETY: the caller's certificate.
        let l = unsafe { X509_get_version(x) };
        let r = if (c_long::from(X509_VERSION_1)..=c_long::from(X509_VERSION_3)).contains(&l) {
            printf!(
                bp,
                c"%8sVersion: %ld (0x%lx)\n",
                E,
                l + 1,
                l.cast_unsigned()
            )
        } else {
            printf!(bp, c"%8sVersion: Unknown (%ld)\n", E, l)
        };
        if r <= 0 {
            return false;
        }
    }
    if on(X509_FLAG_NO_SERIAL) {
        if write(bp, b"        Serial Number:") <= 0 {
            return false;
        }
        // SAFETY: as above.
        let bs = unsafe { X509_get0_serialNumber(x) };
        // SAFETY: the certificate's serial number.
        let Some(bs) = (unsafe { bs.as_ref() }) else {
            return false;
        };
        // SAFETY: as above.
        if unsafe { serial_number_print(bp, bs, 12) } != 0 || puts(bp, c"\n") <= 0 {
            return false;
        }
    }
    if on(X509_FLAG_NO_SIGNAME) {
        // SAFETY: as above.
        let alg = unsafe { X509_get0_tbs_sigalg(x) };
        // SAFETY: as above; its algorithm.
        if puts(bp, c"    ") <= 0 || unsafe { X509_signature_print(bp, alg, ptr::null()) } <= 0 {
            return false;
        }
    }
    let name = |label: &core::ffi::CStr, nm| {
        // SAFETY: the caller's BIO; the certificate's name.
        printf!(bp, label, mlch) > 0
            && unsafe { X509_NAME_print_ex(bp, nm, nmindent, nmflags) } >= printok
            && write(bp, b"\n") > 0
    };
    // SAFETY: as above.
    if on(X509_FLAG_NO_ISSUER) && !name(c"        Issuer:%c", unsafe { X509_get_issuer_name(x) }) {
        return false;
    }
    if on(X509_FLAG_NO_VALIDITY) {
        // SAFETY: as above.
        let (nb, na) = (unsafe { X509_get0_notBefore(x) }, unsafe {
            X509_get0_notAfter(x)
        });
        let ok = write(bp, b"        Validity\n") > 0
            && write(bp, b"            Not Before: ") > 0
            // SAFETY: the certificate's times.
            && unsafe { print_time(bp, nb.cast(), ASN1_DTFLGS_RFC822) } != 0
            && write(bp, b"\n            Not After : ") > 0
            // SAFETY: as above.
            && unsafe { print_time(bp, na.cast(), ASN1_DTFLGS_RFC822) } != 0
            && write(bp, b"\n") > 0;
        if !ok {
            return false;
        }
    }
    // SAFETY: as above.
    if on(X509_FLAG_NO_SUBJECT) && !name(c"        Subject:%c", unsafe { X509_get_subject_name(x) })
    {
        return false;
    }
    if on(X509_FLAG_NO_PUBKEY) {
        // SAFETY: as above.
        let xpkey = unsafe { X509_get_X509_PUBKEY(x) };
        let mut xpoid: *mut ASN1_OBJECT = ptr::null_mut();
        // SAFETY: a local and no other outputs; the certificate's key.
        unsafe {
            X509_PUBKEY_get0_param(
                &raw mut xpoid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                xpkey,
            )
        };
        if write(bp, b"        Subject Public Key Info:\n") <= 0
            || printf!(bp, c"%12sPublic Key Algorithm: ", E) <= 0
            // SAFETY: the key's algorithm, or NULL.
            || unsafe { i2a_ASN1_OBJECT(bp, xpoid) } <= 0
            || puts(bp, c"\n") <= 0
        {
            return false;
        }
        // SAFETY: as above.
        let pkey = unsafe { X509_get0_pubkey(x) };
        if pkey.is_null() {
            printf!(bp, c"%12sUnable to load Public Key\n", E);
            // SAFETY: the caller's BIO.
            unsafe { ERR_print_errors(bp) };
        } else {
            // SAFETY: as above; the certificate's key.
            unsafe { EVP_PKEY_print_public(bp, pkey, 16, ptr::null_mut()) };
        }
    }
    if on(X509_FLAG_NO_IDS) {
        let (mut iuid, mut suid): (*const ASN1_BIT_STRING, *const ASN1_BIT_STRING) =
            (ptr::null(), ptr::null());
        // SAFETY: locals; the certificate.
        unsafe { X509_get0_uids(x, &raw mut iuid, &raw mut suid) };
        for (uid, label) in [
            (iuid, c"%8sIssuer Unique ID: "),
            (suid, c"%8sSubject Unique ID: "),
        ] {
            if !uid.is_null()
                && (printf!(bp, label, E) <= 0
                    // SAFETY: the certificate's identifier.
                    || unsafe { X509_signature_dump(bp, uid, 12) } == 0)
            {
                return false;
            }
        }
    }
    if on(X509_FLAG_NO_EXTENSIONS) {
        // SAFETY: as above.
        let exts = unsafe { X509_get0_extensions(x) };
        // SAFETY: as above; the certificate's extensions.
        if unsafe { X509V3_extensions_print(bp, c"X509v3 extensions".as_ptr(), exts, cflag, 8) }
            == 0
        {
            return false;
        }
    }
    if on(X509_FLAG_NO_SIGDUMP) {
        let (mut sig, mut alg): (*const ASN1_BIT_STRING, *const X509_ALGOR) =
            (ptr::null(), ptr::null());
        // SAFETY: locals; the certificate.
        unsafe { X509_get0_signature(&raw mut sig, &raw mut alg, x) };
        // SAFETY: the certificate's signature.
        if unsafe { X509_signature_print(bp, alg, sig.cast()) } <= 0 {
            return false;
        }
    }
    // SAFETY: as above.
    if on(X509_FLAG_NO_AUX) && unsafe { X509_aux_print(bp, x, 0) } == 0 {
        return false;
    }
    true
}

ffi_export! {
    /// Prints the certificate (the parts `cflag`'s `X509_FLAG_NO_*` don't leave out; names
    /// with `nmflags`): 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_print_ex(bp: *mut BIO, x: *mut X509, nmflags: c_ulong, cflag: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if x.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { print_cert(bp, x, nmflags, cflag) })
    }
}

ffi_export! {
    /// `X509_print_ex` with `XN_FLAG_COMPAT` and `X509_FLAG_COMPAT`.
    ///
    /// # Safety
    /// As for `X509_print_ex`.
    pub unsafe extern "C" fn X509_print(bp: *mut BIO, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_print_ex(bp, x, fli(XN_FLAG_COMPAT), 0) }
    }
}

ffi_export! {
    /// `X509_print_ex` to a `FILE`, left open.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_print_ex_fp(fp: *mut FILE, x: *mut X509, nmflag: c_ulong, cflag: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        let print = |b| {
            // SAFETY: the BIO over `fp`; the caller's certificate.
            unsafe { X509_print_ex(b, x, nmflag, cflag) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "X509_print_ex_fp", print) }
    }
}

ffi_export! {
    /// `X509_print` to a `FILE`, left open.
    ///
    /// # Safety
    /// As for `X509_print_ex_fp`.
    pub unsafe extern "C" fn X509_print_fp(fp: *mut FILE, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_print_ex_fp(fp, x, fli(XN_FLAG_COMPAT), 0) }
    }
}

ffi_export! {
    /// Prints the SHA-1 hashes of the subject name's DER and of the public key's bits (OCSP's
    /// identifiers): 1, or 0 (also for NULL).
    ///
    /// # Safety
    /// `bp` is NULL or a live BIO; `x` is NULL or a live certificate.
    pub unsafe extern "C" fn X509_ocspid_print(bp: *mut BIO, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if x.is_null() || bp.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        let Some((libctx, propq)) = (unsafe { cert_of(x) }).map(|c| (c.libctx, c.propq)) else { return 0 };
        let mut md = ptr::null_mut();
        let mut der = ptr::null_mut::<u8>();
        let ok = 'err: {
            if printf!(bp, c"        Subject OCSP hash: ") <= 0 {
                break 'err false;
            }
            // SAFETY: as above.
            let subj = unsafe { X509_get_subject_name(x) };
            // SAFETY: the certificate's name; no output.
            let derlen = unsafe { i2d_X509_NAME(subj, ptr::null_mut()) };
            let Some(len) = usize::try_from(derlen).ok().filter(|&n| n > 0) else { break 'err false };
            der = mem::alloc(len).cast();
            if der.is_null() {
                break 'err false;
            }
            let mut p = der;
            // SAFETY: as above; room for its encoding.
            if unsafe { i2d_X509_NAME(subj, &raw mut p) } < 0 {
                break 'err false;
            }
            // SAFETY: the certificate's library context; a name; its properties.
            md = unsafe { EVP_MD_fetch(libctx, c"SHA1".as_ptr(), propq) };
            if md.is_null() {
                break 'err false;
            }
            let mut sha1 = [0u8; 20];
            let none = ptr::null_mut();
            // SAFETY: the encoding; the digest's room; the digest.
            if unsafe { EVP_Digest(der.cast(), len, sha1.as_mut_ptr(), none, md, none.cast()) } == 0 {
                break 'err false;
            }
            if !hex_upper(bp, &sha1, false) {
                break 'err false;
            }
            // SAFETY: allocated above.
            unsafe { mem::release(der.cast()) };
            der = ptr::null_mut();
            if printf!(bp, c"\n        Public key OCSP hash: ") <= 0 {
                break 'err false;
            }
            // SAFETY: as above.
            let keybstr = unsafe { X509_get0_pubkey_bitstr(x) };
            // SAFETY: the key's bits, or NULL.
            let Some(k) = (unsafe { keybstr.as_ref() }) else { break 'err false };
            let klen = usize::try_from(k.length).unwrap_or(0);
            // SAFETY: as above.
            if unsafe { EVP_Digest(k.data.cast(), klen, sha1.as_mut_ptr(), none, md, none.cast()) } == 0 {
                break 'err false;
            }
            if !hex_upper(bp, &sha1, false) {
                break 'err false;
            }
            printf!(bp, c"\n");
            true
        };
        // SAFETY: allocated above, or NULL.
        unsafe { mem::release(der.cast()) };
        // SAFETY: fetched above, or NULL.
        unsafe { EVP_MD_free(md) };
        c_int::from(ok)
    }
}

/// `ossl_x509_print_ex_brief`: the certificate's subject, issuer (or "self-issued"), serial
/// number, validity (and whether current), and the rest but `neg_cflags`.
///
/// # Safety
/// `bio` is a live BIO; `cert` is NULL or a live certificate.
unsafe fn print_ex_brief(bio: *mut BIO, cert: *mut X509, neg_cflags: c_ulong) -> bool {
    let flags = fli(ASN1_STRFLGS_RFC2253)
        | fli(ASN1_STRFLGS_ESC_QUOTE)
        | fli(XN_FLAG_SEP_CPLUS_SPC)
        | fli(XN_FLAG_FN_SN);
    if cert.is_null() {
        return printf!(bio, c"    (no certificate)\n") > 0;
    }
    // SAFETY: the caller's guarantee, for each.
    let p = |cflag| unsafe { X509_print_ex(bio, cert, flags, cflag) } != 0;
    if printf!(bio, c"    certificate\n") <= 0 || !p(!fl(X509_FLAG_NO_SUBJECT)) {
        return false;
    }
    // SAFETY: as above.
    if unsafe { X509_check_issued(cert, cert) } == X509_V_OK {
        if printf!(bio, c"        self-issued\n") <= 0 {
            return false;
        }
    } else if printf!(bio, c" ") <= 0 || !p(!fl(X509_FLAG_NO_ISSUER)) {
        return false;
    }
    if !p(!(fl(X509_FLAG_NO_SERIAL) | fl(X509_FLAG_NO_VALIDITY))) {
        return false;
    }
    // SAFETY: as above.
    let nb = unsafe { X509_get0_notBefore(cert) };
    // SAFETY: its time.
    if unsafe { X509_cmp_current_time(nb) } > 0 && printf!(bio, c"        not yet valid\n") <= 0 {
        return false;
    }
    // SAFETY: as above.
    let na = unsafe { X509_get0_notAfter(cert) };
    // SAFETY: its time.
    if unsafe { X509_cmp_current_time(na) } < 0 && printf!(bio, c"        no more valid\n") <= 0 {
        return false;
    }
    p(!neg_cflags & !fl(X509_FLAG_EXTENSIONS_ONLY_KID))
}

/// `print_certs`.
///
/// # Safety
/// `bio` is a live BIO; `certs` is NULL or a live list of certificates.
unsafe fn print_certs(bio: *mut BIO, certs: *mut stack_st_X509) -> bool {
    // SAFETY: the caller's guarantee.
    let n = unsafe { OPENSSL_sk_num(certs.cast()) };
    if certs.is_null() || n <= 0 {
        return printf!(bio, c"    (no certificates)\n") >= 0;
    }
    for i in 0..n {
        // SAFETY: an index within the list.
        let cert = unsafe { OPENSSL_sk_value(certs.cast(), i) }.cast::<X509>();
        if cert.is_null() {
            continue;
        }
        // SAFETY: a certificate of the list.
        if !unsafe { print_ex_brief(bio, cert, 0) } {
            return false;
        }
        // SAFETY: as above.
        let exts = unsafe { X509_get0_extensions(cert) };
        let kid = fl(X509_FLAG_EXTENSIONS_ONLY_KID);
        // SAFETY: as above; its extensions.
        if unsafe { X509V3_extensions_print(bio, ptr::null(), exts, kid, 8) } == 0 {
            return false;
        }
    }
    true
}

ffi_export! {
    /// A verification callback that, for a failure, raises
    /// `X509_R_CERTIFICATE_VERIFICATION_FAILED` with a description as its data (the error,
    /// what was expected, the certificate, and for issuer errors the untrusted and trusted
    /// certificates): `ok`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn X509_STORE_CTX_print_verify_cb(ok: c_int, ctx: *mut X509_STORE_CTX) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if ok != 0 || ctx.is_null() {
            return ok;
        }
        // SAFETY: the caller's guarantee.
        let cert_error = unsafe { X509_STORE_CTX_get_error(ctx) };
        // SAFETY: no preconditions.
        let method = unsafe { BIO_s_mem() };
        // SAFETY: a method.
        let bio = unsafe { BIO_new(method) };
        if bio.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let what = if unsafe { X509_STORE_CTX_get0_parent_ctx(ctx) }.is_null() {
            c"Certificate verification"
        } else {
            c"CRL path validation"
        };
        // SAFETY: as above.
        let depth = unsafe { X509_STORE_CTX_get_error_depth(ctx) };
        // SAFETY: an error code.
        let text = unsafe { X509_verify_cert_error_string(c_long::from(cert_error)) };
        printf!(bio, c"%s at depth = %d error = %d (%s)\n", what.as_ptr(), depth, cert_error, text);
        // SAFETY: as above.
        let ts: *mut X509_STORE = unsafe { X509_STORE_CTX_get0_store(ctx) };
        // SAFETY: the store, or NULL.
        let vpm = unsafe { X509_STORE_get0_param(ts) };
        match cert_error {
            X509_V_ERR_HOSTNAME_MISMATCH => {
                printf!(bio, c"Expected hostname(s) = ");
                let mut idx = 0;
                loop {
                    // SAFETY: the store's parameters, or NULL.
                    let s = unsafe { X509_VERIFY_PARAM_get0_host(vpm, idx) };
                    if s.is_null() {
                        break;
                    }
                    idx += 1;
                    let sep = if idx == 1 { c"" } else { c", " };
                    printf!(bio, c"%s%s", sep.as_ptr(), s);
                }
                printf!(bio, c"\n");
            }
            X509_V_ERR_EMAIL_MISMATCH => {
                // SAFETY: as above.
                let s = unsafe { X509_VERIFY_PARAM_get0_email(vpm) };
                if !s.is_null() {
                    printf!(bio, c"Expected email address = %s\n", s);
                }
            }
            X509_V_ERR_IP_ADDRESS_MISMATCH => {
                // SAFETY: as above.
                let s = unsafe { X509_VERIFY_PARAM_get1_ip_asc(vpm) };
                if !s.is_null() {
                    printf!(bio, c"Expected IP address = %s\n", s);
                }
                // SAFETY: a copy for the caller, or NULL.
                unsafe { mem::release(s.cast()) };
            }
            _ => {}
        }
        printf!(bio, c"Failure for:\n");
        // SAFETY: as above.
        let current = unsafe { X509_STORE_CTX_get_current_cert(ctx) };
        // SAFETY: the BIO; the context's certificate, or NULL.
        unsafe { print_ex_brief(bio, current, fl(X509_FLAG_NO_EXTENSIONS)) };
        if [
            X509_V_ERR_CERT_UNTRUSTED,
            X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
            X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT,
            X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
            X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER,
            X509_V_ERR_STORE_LOOKUP,
        ]
        .contains(&cert_error)
        {
            printf!(bio, c"Non-trusted certs:\n");
            // SAFETY: as above.
            let untrusted = unsafe { X509_STORE_CTX_get0_untrusted(ctx) };
            // SAFETY: the BIO; the context's certificates, or NULL.
            unsafe { print_certs(bio, untrusted) };
            printf!(bio, c"Certs in trust store:\n");
            if ts.is_null() {
                printf!(bio, c"    (no trusted store)\n");
            } else {
                // SAFETY: the store.
                let certs = unsafe { X509_STORE_get1_all_certs(ts) };
                // SAFETY: its certificates, or NULL.
                unsafe { print_certs(bio, certs) };
                // SAFETY: the copy.
                unsafe { OSSL_STACK_OF_X509_free(certs) };
            }
        }
        err::raise(ERR_LIB_X509, X509_R_CERTIFICATE_VERIFICATION_FAILED, "X509_STORE_CTX_print_verify_cb");
        // SAFETY: a separator; the BIO.
        unsafe { ERR_add_error_mem_bio(c"\n".as_ptr(), bio) };
        // SAFETY: made above.
        unsafe { BIO_free(bio) };
        ok
    }
}

ffi_export! {
    /// Prints the CRL (its issuer with `nmflag`): 1 (0 for NULL).
    ///
    /// # Safety
    /// `out` is a live BIO; `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_print_ex(out: *mut BIO, x: *mut X509_CRL, nmflag: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if x.is_null() {
            return 0;
        }
        printf!(out, c"Certificate Revocation List (CRL):\n");
        // SAFETY: the caller's guarantee, for each getter.
        let l = unsafe { X509_CRL_get_version(x) };
        if (c_long::from(X509_CRL_VERSION_1)..=c_long::from(X509_CRL_VERSION_2)).contains(&l) {
            printf!(out, c"%8sVersion %ld (0x%lx)\n", E, l + 1, l.cast_unsigned());
        } else {
            printf!(out, c"%8sVersion unknown (%ld)\n", E, l);
        }
        let (mut sig, mut alg): (*const ASN1_BIT_STRING, *const X509_ALGOR) = (ptr::null(), ptr::null());
        // SAFETY: as above; locals.
        unsafe { X509_CRL_get0_signature(x, &raw mut sig, &raw mut alg) };
        puts(out, c"    ");
        // SAFETY: the CRL's algorithm.
        unsafe { X509_signature_print(out, alg, ptr::null()) };
        printf!(out, c"%8sIssuer: ", E);
        // SAFETY: as above.
        let issuer = unsafe { X509_CRL_get_issuer(x) };
        // SAFETY: its issuer.
        unsafe { X509_NAME_print_ex(out, issuer, 0, nmflag) };
        puts(out, c"\n");
        printf!(out, c"%8sLast Update: ", E);
        // SAFETY: as above.
        let last = unsafe { X509_CRL_get0_lastUpdate(x) };
        // SAFETY: its time.
        unsafe { ASN1_TIME_print(out, last) };
        printf!(out, c"\n%8sNext Update: ", E);
        // SAFETY: as above.
        let next = unsafe { X509_CRL_get0_nextUpdate(x) };
        if next.is_null() {
            printf!(out, c"NONE");
        } else {
            // SAFETY: the CRL's time.
            unsafe { ASN1_TIME_print(out, next) };
        }
        printf!(out, c"\n");
        // SAFETY: as above.
        let exts = unsafe { X509_CRL_get0_extensions(x) };
        // SAFETY: its extensions.
        unsafe { X509V3_extensions_print(out, c"CRL extensions".as_ptr(), exts, 0, 8) };
        // SAFETY: as above.
        let rev = unsafe { X509_CRL_get_REVOKED(x) };
        // SAFETY: its entries, or NULL.
        let n = unsafe { OPENSSL_sk_num(rev.cast()) };
        if n > 0 {
            printf!(out, c"Revoked Certificates:\n");
        } else {
            printf!(out, c"No Revoked Certificates.\n");
        }
        for i in 0..n {
            // SAFETY: an index within them.
            let r = unsafe { OPENSSL_sk_value(rev.cast(), i) }.cast::<X509_REVOKED>();
            printf!(out, c"    Serial Number: ");
            // SAFETY: the CRL's entry.
            let serial = unsafe { X509_REVOKED_get0_serialNumber(r) };
            // SAFETY: its serial number.
            unsafe { i2a_ASN1_INTEGER(out, serial) };
            printf!(out, c"\n        Revocation Date: ");
            // SAFETY: as above.
            let date = unsafe { X509_REVOKED_get0_revocationDate(r) };
            // SAFETY: its time.
            unsafe { ASN1_TIME_print(out, date) };
            printf!(out, c"\n");
            // SAFETY: as above.
            let exts = unsafe { X509_REVOKED_get0_extensions(r) };
            // SAFETY: its extensions.
            unsafe { X509V3_extensions_print(out, c"CRL entry extensions".as_ptr(), exts, 0, 8) };
        }
        // SAFETY: the CRL's signature.
        unsafe { X509_signature_print(out, alg, sig.cast()) };
        1
    }
}

ffi_export! {
    /// `X509_CRL_print_ex` with `XN_FLAG_COMPAT`.
    ///
    /// # Safety
    /// As for `X509_CRL_print_ex`.
    pub unsafe extern "C" fn X509_CRL_print(out: *mut BIO, x: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_CRL_print_ex(out, x, fli(XN_FLAG_COMPAT)) }
    }
}

ffi_export! {
    /// `X509_CRL_print` to a `FILE`, left open.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `x` is NULL or a live CRL.
    pub unsafe extern "C" fn X509_CRL_print_fp(fp: *mut FILE, x: *mut X509_CRL) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        let print = |b| {
            // SAFETY: the BIO over `fp`; the caller's CRL.
            unsafe { X509_CRL_print(b, x) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "X509_CRL_print_fp", print) }
    }
}

/// Whether an attribute value's type prints as text.
fn is_text(t: c_int) -> bool {
    [
        V_ASN1_PRINTABLESTRING,
        V_ASN1_T61STRING,
        V_ASN1_NUMERICSTRING,
        V_ASN1_UTF8STRING,
        V_ASN1_IA5STRING,
    ]
    .contains(&t)
}

/// Writes a string's octets: whether all were written.
///
/// # Safety
/// `bp` is a live BIO; `bs` is NULL or a live string.
unsafe fn write_string(bp: *mut BIO, bs: *const ASN1_STRING) -> bool {
    // SAFETY: the caller's guarantee.
    let Some(s) = (unsafe { bs.as_ref() }) else {
        return false;
    };
    // SAFETY: as above; its data holds its length.
    unsafe { BIO_write(bp, s.data.cast(), s.length) == s.length }
}

/// An attribute's value at `i`: its type and string (`None` for none).
///
/// # Safety
/// `a` is a live attribute.
unsafe fn attr_value(a: *mut X509_ATTRIBUTE, i: c_int) -> Option<(c_int, *mut ASN1_STRING)> {
    // SAFETY: the caller's guarantee.
    let at = unsafe { X509_ATTRIBUTE_get0_type(a, i) };
    // SAFETY: the attribute's value, or NULL.
    let at = unsafe { at.as_ref() }?;
    // SAFETY: every string member is a pointer.
    Some((at.type_, unsafe { at.value.asn1_string }))
}

/// [`X509_REQ_print_ex`]'s body: whether it printed.
///
/// # Safety
/// `bp` is a live BIO; `x` is a live request; `exts` holds the requested extensions to free.
unsafe fn print_req(
    bp: *mut BIO,
    x: *mut X509_REQ,
    nmflags: c_ulong,
    cflag: c_ulong,
    exts: &mut *mut stack_st_X509_EXTENSION,
) -> Option<bool> {
    let (mlch, nmindent, printok) = name_layout(nmflags);
    let on = |f: c_long| cflag & fl(f) == 0;
    if on(X509_FLAG_NO_HEADER)
        && (write(bp, b"Certificate Request:\n") <= 0 || write(bp, b"    Data:\n") <= 0)
    {
        return Some(false);
    }
    if on(X509_FLAG_NO_VERSION) {
        // SAFETY: the caller's request.
        let l = unsafe { X509_REQ_get_version(x) };
        let r = if l == c_long::from(X509_REQ_VERSION_1) {
            printf!(
                bp,
                c"%8sVersion: %ld (0x%lx)\n",
                E,
                l + 1,
                l.cast_unsigned()
            )
        } else {
            printf!(bp, c"%8sVersion: Unknown (%ld)\n", E, l)
        };
        if r <= 0 {
            return Some(false);
        }
    }
    if on(X509_FLAG_NO_SUBJECT) {
        // SAFETY: as above.
        let nm = unsafe { X509_REQ_get_subject_name(x) };
        if printf!(bp, c"        Subject:%c", mlch) <= 0
            // SAFETY: the request's name.
            || unsafe { X509_NAME_print_ex(bp, nm, nmindent, nmflags) } < printok
            || write(bp, b"\n") <= 0
        {
            return Some(false);
        }
    }
    if on(X509_FLAG_NO_PUBKEY) {
        if write(bp, b"        Subject Public Key Info:\n") <= 0
            || printf!(bp, c"%12sPublic Key Algorithm: ", E) <= 0
        {
            return Some(false);
        }
        // SAFETY: as above.
        let xpkey = unsafe { X509_REQ_get_X509_PUBKEY(x) };
        let mut koid: *mut ASN1_OBJECT = ptr::null_mut();
        // SAFETY: a local and no other outputs; the request's key.
        unsafe {
            X509_PUBKEY_get0_param(
                &raw mut koid,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                xpkey,
            )
        };
        // SAFETY: the key's algorithm, or NULL.
        if unsafe { i2a_ASN1_OBJECT(bp, koid) } <= 0 || puts(bp, c"\n") <= 0 {
            return Some(false);
        }
        // SAFETY: as above.
        let pkey = unsafe { X509_REQ_get0_pubkey(x) };
        if pkey.is_null() {
            if printf!(bp, c"%12sUnable to load Public Key\n", E) <= 0 {
                return Some(false);
            }
            // SAFETY: the caller's BIO.
            unsafe { ERR_print_errors(bp) };
        // SAFETY: as above; the request's key.
        } else if unsafe { EVP_PKEY_print_public(bp, pkey, 16, ptr::null_mut()) } <= 0 {
            return Some(false);
        }
    }
    if on(X509_FLAG_NO_ATTRIBUTES) {
        if printf!(bp, c"%8sAttributes:\n", E) <= 0 {
            return Some(false);
        }
        // SAFETY: as above.
        let n = unsafe { X509_REQ_get_attr_count(x) };
        if n == 0 && printf!(bp, c"%12s(none)\n", E) <= 0 {
            return Some(false);
        }
        for i in 0..n {
            // SAFETY: as above; an index within its attributes.
            let a = unsafe { X509_REQ_get_attr(x, i) };
            // SAFETY: the request's attribute.
            let aobj = unsafe { X509_ATTRIBUTE_get0_object(a) };
            // SAFETY: its object.
            let nid = unsafe { OBJ_obj2nid(aobj) };
            // SAFETY: a NID.
            if unsafe { X509_REQ_extension_nid(nid) } != 0 {
                continue;
            }
            if printf!(bp, c"%12s", E) <= 0 {
                return Some(false);
            }
            // SAFETY: as above.
            let mut j = unsafe { i2a_ASN1_OBJECT(bp, aobj) };
            let named = j > 0;
            let mut count = 1;
            if named {
                // SAFETY: as above.
                count = unsafe { X509_ATTRIBUTE_count(a) };
                if count == 0 {
                    err::raise(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES, "X509_REQ_print_ex");
                    return None;
                }
            }
            let mut ii = 0;
            loop {
                let (mut ty, mut bs) = (0, ptr::null_mut());
                if named {
                    // SAFETY: as above.
                    let Some(v) = (unsafe { attr_value(a, ii) }) else {
                        return Some(false);
                    };
                    (ty, bs) = v;
                }
                // The padding after the name (after the first value, 25 more: OpenSSL's `j` is
                // 0 by then).
                for _ in 0..25_i32.saturating_sub(j) {
                    if write(bp, b" ") != 1 {
                        return Some(false);
                    }
                }
                j = 0;
                if puts(bp, c":") <= 0 {
                    return Some(false);
                }
                if is_text(ty) {
                    // SAFETY: the value's string.
                    if !unsafe { write_string(bp, bs) } || puts(bp, c"\n") <= 0 {
                        return Some(false);
                    }
                } else if puts(bp, c"unable to print attribute\n") <= 0 {
                    return Some(false);
                }
                ii += 1;
                if ii >= count {
                    break;
                }
            }
        }
    }
    if on(X509_FLAG_NO_EXTENSIONS) {
        // SAFETY: as above.
        *exts = unsafe { X509_REQ_get_extensions(x) };
        if !exts.is_null() {
            if printf!(bp, c"%12sRequested Extensions:\n", E) <= 0 {
                return Some(false);
            }
            // SAFETY: the extensions.
            for i in 0..unsafe { OPENSSL_sk_num(exts.cast()) } {
                // SAFETY: an index within them.
                let ex = unsafe { OPENSSL_sk_value(exts.cast(), i) }.cast::<X509_EXTENSION>();
                // SAFETY: an extension, for each call.
                if unsafe { print_ext(bp, ex, cflag, 16, 20, false) } == 0 {
                    return Some(false);
                }
            }
            // SAFETY: the extensions, with their own.
            unsafe { OPENSSL_sk_pop_free(exts.cast(), Some(crate::x509v3::registry::free_ext)) };
            *exts = ptr::null_mut();
        }
    }
    if on(X509_FLAG_NO_SIGDUMP) {
        let (mut sig, mut alg): (*const ASN1_BIT_STRING, *const X509_ALGOR) =
            (ptr::null(), ptr::null());
        // SAFETY: as above; locals.
        unsafe { X509_REQ_get0_signature(x, &raw mut sig, &raw mut alg) };
        // SAFETY: the request's signature.
        if unsafe { X509_signature_print(bp, alg, sig.cast()) } == 0 {
            return Some(false);
        }
    }
    Some(true)
}

/// An extension as the request and attribute-certificate printers list it, `indent` in: its
/// object, whether critical, then its value by its printer (20 in) or, if that fails (with
/// `fail_negative`, also for a negative answer), as a string `fallback` in: 1, or 0.
///
/// # Safety
/// `bp` is a live BIO; `ex` is a live extension.
unsafe fn print_ext(
    bp: *mut BIO,
    ex: *mut X509_EXTENSION,
    cflag: c_ulong,
    indent: c_int,
    fallback: c_int,
    fail_negative: bool,
) -> c_int {
    if printf!(bp, c"%*s", indent, E) <= 0 {
        return 0;
    }
    // SAFETY: the caller's guarantee.
    let obj = unsafe { X509_EXTENSION_get_object(ex) };
    // SAFETY: its object.
    if unsafe { i2a_ASN1_OBJECT(bp, obj) } <= 0 {
        return 0;
    }
    // SAFETY: as above.
    let critical = unsafe { X509_EXTENSION_get_critical(ex) } != 0;
    let c = if critical { c"critical" } else { c"" };
    if printf!(bp, c": %s\n", c.as_ptr()) <= 0 {
        return 0;
    }
    // SAFETY: as above.
    let r = unsafe { X509V3_EXT_print(bp, ex, cflag, 20) };
    if r == 0 || (fail_negative && r < 0) {
        // SAFETY: as above.
        let data = unsafe { X509_EXTENSION_get_data(ex) };
        if printf!(bp, c"%*s", fallback, E) <= 0
            // SAFETY: its value.
            || unsafe { ASN1_STRING_print(bp, data.cast()) } <= 0
        {
            return 0;
        }
    }
    c_int::from(write(bp, b"\n") > 0)
}

ffi_export! {
    /// Prints the request (the parts `cflag`'s `X509_FLAG_NO_*` don't leave out; its subject
    /// with `nmflags`): 1, or 0 (with `ERR_R_BUF_LIB` if it couldn't write).
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_print_ex(bp: *mut BIO, x: *mut X509_REQ, nmflags: c_ulong, cflag: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if x.is_null() {
            return 0;
        }
        let mut exts = ptr::null_mut();
        // SAFETY: the caller's guarantee.
        let r = unsafe { print_req(bp, x, nmflags, cflag, &mut exts) };
        // SAFETY: the requested extensions left, or NULL.
        unsafe { OPENSSL_sk_pop_free(exts.cast(), Some(crate::x509v3::registry::free_ext)) };
        match r {
            Some(true) => 1,
            Some(false) => {
                err::raise(ERR_LIB_X509, ERR_R_BUF_LIB, "X509_REQ_print_ex");
                0
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// `X509_REQ_print_ex` with `XN_FLAG_COMPAT` and `X509_FLAG_COMPAT`.
    ///
    /// # Safety
    /// As for `X509_REQ_print_ex`.
    pub unsafe extern "C" fn X509_REQ_print(bp: *mut BIO, x: *mut X509_REQ) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_REQ_print_ex(bp, x, fli(XN_FLAG_COMPAT), 0) }
    }
}

ffi_export! {
    /// `X509_REQ_print` to a `FILE`, left open.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; `x` is NULL or a live request.
    pub unsafe extern "C" fn X509_REQ_print_fp(fp: *mut FILE, x: *mut X509_REQ) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        let print = |b| {
            // SAFETY: the BIO over `fp`; the caller's request.
            unsafe { X509_REQ_print(b, x) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "X509_REQ_print_fp", print) }
    }
}

/// An issuer and serial's serial number.
fn serial_of(bcid: *const rustyssl_abi::OSSL_ISSUER_SERIAL) -> *const ASN1_INTEGER {
    // SAFETY: a live identifier.
    unsafe { OSSL_ISSUER_SERIAL_get0_serial(bcid) }
}

/// `print_attribute` of `t_acert.c`: whether it printed.
///
/// # Safety
/// `bp` is a live BIO; `a` is a live attribute.
unsafe fn print_acert_attribute(bp: *mut BIO, a: *mut X509_ATTRIBUTE) -> bool {
    // SAFETY: the caller's guarantee.
    let aobj = unsafe { X509_ATTRIBUTE_get0_object(a) };
    if printf!(bp, c"%12s", E) <= 0 {
        return false;
    }
    // SAFETY: its object.
    let j = unsafe { i2a_ASN1_OBJECT(bp, aobj) };
    if j <= 0 {
        return false;
    }
    // SAFETY: as above.
    let count = unsafe { X509_ATTRIBUTE_count(a) };
    if count == 0 {
        err::raise(ERR_LIB_X509, X509_R_INVALID_ATTRIBUTES, "print_attribute");
        return false;
    }
    if j < 25 && printf!(bp, c"%*s", 25 - j, c" ".as_ptr()) <= 0 {
        return false;
    }
    if puts(bp, c":") <= 0 {
        return false;
    }
    for i in 0..count {
        // SAFETY: as above.
        let Some((ty, bs)) = (unsafe { attr_value(a, i) }) else {
            return false;
        };
        if is_text(ty) {
            // SAFETY: the value's string.
            if !unsafe { write_string(bp, bs) } || puts(bp, c"\n") <= 0 {
                return false;
            }
        } else if ty == V_ASN1_SEQUENCE {
            if puts(bp, c"\n") <= 0 {
                return false;
            }
            // SAFETY: the value's encoding, or NULL.
            let Some(s) = (unsafe { bs.as_ref() }) else {
                return false;
            };
            // SAFETY: as above; its data holds its length.
            if unsafe { ASN1_parse_dump(bp, s.data, c_long::from(s.length), i, 1) } <= 0 {
                return false;
            }
        } else if printf!(bp, c"unable to print attribute of type 0x%X\n", ty) < 0 {
            return false;
        }
    }
    true
}

/// [`X509_ACERT_print_ex`]'s body: `Some(printed)`, or `None` to fail without
/// `ERR_R_BUF_LIB` (the signature).
///
/// # Safety
/// `bp` is a live BIO; `x` is a live attribute certificate.
unsafe fn print_acert(
    bp: *mut BIO,
    x: *mut X509_ACERT,
    nmflags: c_ulong,
    cflag: c_ulong,
) -> Option<bool> {
    let (mlch, _, _) = name_layout(nmflags);
    let on = |f: c_long| cflag & fl(f) == 0;
    if on(X509_FLAG_NO_HEADER)
        && (printf!(bp, c"Attribute Certificate:\n") <= 0 || printf!(bp, c"%4sData:\n", E) <= 0)
    {
        return Some(false);
    }
    if on(X509_FLAG_NO_VERSION) {
        // SAFETY: the caller's certificate.
        let l = unsafe { X509_ACERT_get_version(x) };
        let r = if l == c_long::from(X509_ACERT_VERSION_2) {
            printf!(
                bp,
                c"%8sVersion: %ld (0x%lx)\n",
                E,
                l + 1,
                l.cast_unsigned()
            )
        } else {
            printf!(bp, c"%8sVersion: Unknown (%ld)\n", E, l)
        };
        if r <= 0 {
            return Some(false);
        }
    }
    if on(X509_FLAG_NO_SERIAL) {
        // SAFETY: as above.
        let serial: *const ASN1_INTEGER = unsafe { X509_ACERT_get0_serialNumber(x) };
        if printf!(bp, c"%8sSerial Number: ", E) <= 0
            // SAFETY: its serial number.
            || unsafe { i2a_ASN1_INTEGER(bp, serial) } <= 0
            || write(bp, b"\n") <= 0
        {
            return Some(false);
        }
    }
    if on(X509_FLAG_NO_SUBJECT) {
        if printf!(bp, c"%8sHolder:\n", E) <= 0 {
            return Some(false);
        }
        // SAFETY: as above.
        let entities = unsafe { X509_ACERT_get0_holder_entityName(x) };
        // SAFETY: its names, or NULL.
        for i in 0..unsafe { OPENSSL_sk_num(entities.cast()) } {
            // SAFETY: an index within them.
            let entity = unsafe { OPENSSL_sk_value(entities.cast(), i) }.cast::<GENERAL_NAME>();
            if printf!(bp, c"%12sName:%c", E, mlch) <= 0
                // SAFETY: a name.
                || unsafe { GENERAL_NAME_print(bp, entity) } <= 0
                || write(bp, b"\n") <= 0
            {
                return Some(false);
            }
        }
        // SAFETY: as above.
        let bcid = unsafe { X509_ACERT_get0_holder_baseCertId(x) };
        let issuer = if bcid.is_null() {
            ptr::null()
        } else {
            // SAFETY: its base certificate identifier.
            unsafe { OSSL_ISSUER_SERIAL_get0_issuer(bcid) }
        };
        if !issuer.is_null() {
            if printf!(bp, c"%12sIssuer:%c", E, mlch) <= 0
                // SAFETY: the identifier's issuer.
                || unsafe { X509_NAME_print_ex(bp, issuer, 0, nmflags) } <= 0
                || write(bp, b"\n") <= 0
                || printf!(bp, c"%12sSerial: ", E) <= 0
                // SAFETY: the identifier's serial number.
                || unsafe { i2a_ASN1_INTEGER(bp, serial_of(bcid)) } <= 0
            {
                return Some(false);
            }
            // SAFETY: as above.
            let iuid = unsafe { OSSL_ISSUER_SERIAL_get0_issuerUID(bcid) };
            if !iuid.is_null()
                && (printf!(bp, c"%12sIssuer UID: ", E) <= 0
                    // SAFETY: the identifier's issuer UID.
                    || unsafe { X509_signature_dump(bp, iuid.cast(), 24) } <= 0)
            {
                return Some(false);
            }
            if write(bp, b"\n") <= 0 {
                return Some(false);
            }
        }
    }
    if on(X509_FLAG_NO_ISSUER) {
        if printf!(bp, c"%8sIssuer:%c", E, mlch) <= 0 {
            return Some(false);
        }
        // SAFETY: as above.
        let issuer = unsafe { X509_ACERT_get0_issuerName(x) };
        let r = if issuer.is_null() {
            printf!(bp, c"Unsupported Issuer Type")
        } else {
            // SAFETY: its issuer.
            let r = unsafe { X509_NAME_print_ex(bp, issuer, 0, nmflags) };
            if r < 0 { 0 } else { 1 }
        };
        if r <= 0 || write(bp, b"\n") <= 0 {
            return Some(false);
        }
    }
    if on(X509_FLAG_NO_VALIDITY) {
        // SAFETY: as above.
        let (nb, na) = (unsafe { X509_ACERT_get0_notBefore(x) }, unsafe {
            X509_ACERT_get0_notAfter(x)
        });
        let ok = printf!(bp, c"%8sValidity\n", E) > 0
            && printf!(bp, c"%12sNot Before: ", E) > 0
            // SAFETY: its times.
            && unsafe { ASN1_GENERALIZEDTIME_print(bp, nb) } != 0
            && printf!(bp, c"\n%12sNot After : ", E) > 0
            // SAFETY: as above.
            && unsafe { ASN1_GENERALIZEDTIME_print(bp, na) } != 0
            && write(bp, b"\n") > 0;
        if !ok {
            return Some(false);
        }
    }
    if on(X509_FLAG_NO_ATTRIBUTES) {
        if printf!(bp, c"%8sAttributes:\n", E) <= 0 {
            return Some(false);
        }
        // SAFETY: as above.
        let n = unsafe { X509_ACERT_get_attr_count(x) };
        if n == 0 && printf!(bp, c"%12s(none)\n", E) <= 0 {
            return Some(false);
        }
        for i in 0..n {
            // SAFETY: as above; an index within its attributes.
            let a = unsafe { X509_ACERT_get_attr(x, i) };
            // SAFETY: its attribute.
            if !unsafe { print_acert_attribute(bp, a) } {
                return Some(false);
            }
        }
    }
    if on(X509_FLAG_NO_EXTENSIONS) {
        // SAFETY: as above.
        let exts = unsafe { X509_ACERT_get0_extensions(x) };
        if !exts.is_null() {
            if printf!(bp, c"%8sExtensions:\n", E) <= 0 {
                return Some(false);
            }
            // SAFETY: its extensions.
            for i in 0..unsafe { OPENSSL_sk_num(exts.cast()) } {
                // SAFETY: an index within them.
                let ex = unsafe { OPENSSL_sk_value(exts.cast(), i) }.cast::<X509_EXTENSION>();
                // SAFETY: an extension.
                if unsafe { print_ext(bp, ex, cflag, 12, 16, true) } == 0 {
                    return Some(false);
                }
            }
        }
    }
    if on(X509_FLAG_NO_SIGDUMP) {
        let (mut sig, mut alg): (*const ASN1_BIT_STRING, *const X509_ALGOR) =
            (ptr::null(), ptr::null());
        // SAFETY: as above; locals.
        unsafe { X509_ACERT_get0_signature(x, &raw mut sig, &raw mut alg) };
        // SAFETY: its signature.
        if unsafe { X509_signature_print(bp, alg, sig.cast()) } <= 0 {
            return None;
        }
    }
    Some(true)
}

ffi_export! {
    /// Prints the attribute certificate (the parts `cflag`'s `X509_FLAG_NO_*` don't leave out;
    /// names with `nmflags`): 1, or 0 (with `ERR_R_BUF_LIB` if it couldn't write).
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or a live attribute certificate.
    pub unsafe extern "C" fn X509_ACERT_print_ex(bp: *mut BIO, x: *mut X509_ACERT, nmflags: c_ulong, cflag: c_ulong) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        if x.is_null() {
            return 0;
        }
        // SAFETY: the caller's guarantee.
        match unsafe { print_acert(bp, x, nmflags, cflag) } {
            Some(true) => 1,
            Some(false) => {
                err::raise(ERR_LIB_X509, ERR_R_BUF_LIB, "X509_ACERT_print_ex");
                0
            }
            None => 0,
        }
    }
}

ffi_export! {
    /// `X509_ACERT_print_ex` with `XN_FLAG_COMPAT` and `X509_FLAG_COMPAT`.
    ///
    /// # Safety
    /// As for `X509_ACERT_print_ex`.
    pub unsafe extern "C" fn X509_ACERT_print(bp: *mut BIO, x: *mut X509_ACERT) -> c_int
    where failure = 0, library = ERR_LIB_X509
    {
        // SAFETY: the caller's guarantee.
        unsafe { X509_ACERT_print_ex(bp, x, fli(XN_FLAG_COMPAT), 0) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: the printers with a NULL object, which OpenSSL reads through.
    #[test]
    fn null_objects_print_nothing() {
        let b = ptr::null_mut();
        // SAFETY: NULL objects, which they refuse before touching the BIO.
        unsafe {
            assert_eq!(X509_print_ex(b, ptr::null_mut(), 0, 0), 0);
        }
        // SAFETY: as above.
        assert_eq!(unsafe { X509_CRL_print_ex(b, ptr::null_mut(), 0) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_REQ_print_ex(b, ptr::null_mut(), 0, 0) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_ACERT_print_ex(b, ptr::null_mut(), 0, 0) }, 0);
        // SAFETY: as above.
        assert_eq!(unsafe { X509_aux_print(b, ptr::null_mut(), 0) }, 0);
        // SAFETY: as above.
        let r = unsafe { X509_signature_print(b, ptr::null(), ptr::null()) };
        assert_eq!(r, 0);
    }
}
