//! Loading a context's or connection's certificates and keys (`ssl_rsa.c`,
//! `ssl_rsa_legacy.c`): objects, DER, PEM and DER files, certificate chain files, and a
//! certificate with its key and chain at once.

use core::ffi::{c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    BIO, BIO_C_SET_FILENAME, BIO_CLOSE, BIO_FP_READ, ERR_LIB_PEM, ERR_LIB_SSL, ERR_R_ASN1_LIB,
    ERR_R_BUF_LIB, ERR_R_EVP_LIB, ERR_R_PEM_LIB, ERR_R_SYS_LIB, ERR_R_X509_LIB, EVP_PKEY,
    EVP_PKEY_RSA, OSSL_LIB_CTX, PEM_R_NO_START_LINE, RSA, SSL, SSL_CTX, SSL_FILETYPE_ASN1,
    SSL_FILETYPE_PEM, SSL_R_BAD_SSL_FILETYPE, SSL_R_COPY_PARAMETERS_FAILED,
    SSL_R_MISSING_PARAMETERS, SSL_R_NO_CERTIFICATE_ASSIGNED, SSL_R_NO_PRIVATE_KEY_ASSIGNED,
    SSL_R_NOT_REPLACING_CERTIFICATE, SSL_R_PRIVATE_KEY_MISMATCH, SSL_R_UNKNOWN_CERTIFICATE_TYPE,
    X509, pem_password_cb, stack_st_X509,
};

use super::cert::{self, Owner, raise_reason, security_cert, with_cert};
use super::conn;
use super::ctx;
use crate::bio::{BIO_ctrl, BIO_free, BIO_new};
use crate::err::{self, ERR_clear_error, ERR_peek_error, ERR_peek_last_error};
use crate::evp::pkey::{
    EVP_PKEY_copy_parameters, EVP_PKEY_eq, EVP_PKEY_free, EVP_PKEY_missing_parameters,
    EVP_PKEY_new, EVP_PKEY_up_ref,
};
use crate::ffi::ffi_export;
use crate::x509::cert::{X509_chain_up_ref, X509_free, X509_get_pubkey, X509_up_ref};

/// The owner's password callback and its data.
///
/// # Safety
/// The owner is a live object.
unsafe fn passwd(owner: Owner) -> (pem_password_cb, *mut c_void) {
    match owner {
        // SAFETY: the caller's guarantee.
        Owner::Ctx(c) => unsafe { ctx::ctx(c) }.map_or((None, ptr::null_mut()), |x| {
            let st = x.state();
            (
                st.default_passwd_callback,
                st.default_passwd_callback_userdata,
            )
        }),
        // SAFETY: as above.
        Owner::Ssl(s) => unsafe { conn::ssl(s) }.map_or((None, ptr::null_mut()), |x| {
            let st = x.state();
            (
                st.default_passwd_callback,
                st.default_passwd_callback_userdata,
            )
        }),
    }
}

/// The library context and properties the owner's objects are made with (a connection's are
/// its context's).
///
/// # Safety
/// The owner is a live object.
unsafe fn library(owner: Owner) -> (*mut OSSL_LIB_CTX, *const c_char) {
    let c = match owner {
        Owner::Ctx(c) => c,
        Owner::Ssl(s) => {
            // SAFETY: the caller's guarantee.
            unsafe { conn::ssl(s) }.map_or(ptr::null(), |x| x.state().ctx.cast_const())
        }
    };
    // SAFETY: a live context, or NULL.
    unsafe { ctx::ctx(c) }.map_or((ptr::null_mut(), ptr::null()), |x| {
        (x.libctx, x.propq_ptr())
    })
}

/// The owner, if it is live (a NULL connection or context isn't).
///
/// # Safety
/// The owner is NULL or live.
unsafe fn live(owner: Owner) -> bool {
    match owner {
        // SAFETY: the caller's guarantee.
        Owner::Ctx(c) => unsafe { ctx::ctx(c) }.is_some(),
        // SAFETY: as above.
        Owner::Ssl(s) => unsafe { conn::ssl(s) }.is_some(),
    }
}

/// `SSL_use_certificate`/`SSL_CTX_use_certificate`: the security check, then the slot.
///
/// # Safety
/// The owner is NULL or live; `x` NULL or a live certificate.
unsafe fn use_certificate(owner: Owner, x: *mut X509, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    if !unsafe { live(owner) } {
        return 0;
    }
    if x.is_null() {
        cert::null_argument(f);
        return 0;
    }
    // SAFETY: the live owner; the caller's certificate.
    let rv = unsafe { security_cert(owner, x, true) };
    if rv != 1 {
        raise_reason(rv, f);
        return 0;
    }
    let mut rel = cert::Released::default();
    let f = |c: &mut cert::Cert| {
        // SAFETY: the caller's certificate.
        unsafe { cert::set_cert(c, x, &mut rel) }
    };
    // SAFETY: as above.
    unsafe { with_cert(owner, f) }.unwrap_or(0)
}

/// `SSL_use_PrivateKey`/`SSL_CTX_use_PrivateKey`.
///
/// # Safety
/// The owner is NULL or live; `pkey` NULL or a live key.
unsafe fn use_pkey(owner: Owner, pkey: *mut EVP_PKEY, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    if !unsafe { live(owner) } {
        return 0;
    }
    if pkey.is_null() {
        cert::null_argument(f);
        return 0;
    }
    let mut rel = cert::Released::default();
    let f = |c: &mut cert::Cert| {
        // SAFETY: the caller's key.
        unsafe { cert::set_pkey(c, pkey, &mut rel) }
    };
    // SAFETY: as above.
    unsafe { with_cert(owner, f) }.unwrap_or(0)
}

/// A file BIO reading `file`, or NULL (with OpenSSL's errors raised).
///
/// # Safety
/// `file` is NULL or a path.
unsafe fn open(file: *const c_char, f: &str) -> *mut BIO {
    if file.is_null() {
        cert::null_argument(f);
        return ptr::null_mut();
    }
    // SAFETY: no preconditions.
    let m = unsafe { crate::bio::file::BIO_s_file() };
    // SAFETY: the built-in method.
    let b = unsafe { BIO_new(m) };
    if b.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_BUF_LIB, f);
        return b;
    }
    let flags = c_long::from(BIO_CLOSE | BIO_FP_READ);
    // SAFETY: a file BIO; the caller's path (`BIO_read_filename`).
    if unsafe { BIO_ctrl(b, BIO_C_SET_FILENAME, flags, file.cast_mut().cast()) } <= 0 {
        err::raise(ERR_LIB_SSL, ERR_R_SYS_LIB, f);
        // SAFETY: made here.
        unsafe { BIO_free(b) };
        return ptr::null_mut();
    }
    b
}

/// `SSL_use_certificate_file`/`SSL_CTX_use_certificate_file`.
///
/// # Safety
/// The owner is NULL or live; `file` NULL or a path.
unsafe fn certificate_file(owner: Owner, file: *const c_char, type_: c_int, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let b = unsafe { open(file, f) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: as above.
    let (libctx, propq) = unsafe { library(owner) };
    // SAFETY: the library context and properties.
    let mut x = unsafe { crate::x509::cert::X509_new_ex(libctx, propq) };
    let ret = 'r: {
        if x.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_ASN1_LIB, f);
            break 'r 0;
        }
        let (got, reason) = if type_ == SSL_FILETYPE_ASN1 {
            // SAFETY: the BIO; the certificate to fill.
            (
                unsafe { crate::x509::cert::d2i_X509_bio(b, &raw mut x) },
                ERR_R_ASN1_LIB,
            )
        } else if type_ == SSL_FILETYPE_PEM {
            // SAFETY: as above.
            let (cb, u) = unsafe { passwd(owner) };
            // SAFETY: as above, with the owner's password callback (no lock held).
            (
                unsafe { crate::pem_pkey::PEM_read_bio_X509(b, &raw mut x, cb, u) },
                ERR_R_PEM_LIB,
            )
        } else {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_SSL_FILETYPE, f);
            break 'r 0;
        };
        if got.is_null() {
            err::raise(ERR_LIB_SSL, reason, f);
            break 'r 0;
        }
        // SAFETY: as above; the certificate read.
        unsafe { use_certificate(owner, x, f) }
    };
    // SAFETY: ours, or NULL.
    unsafe { X509_free(x) };
    // SAFETY: made here.
    unsafe { BIO_free(b) };
    ret
}

/// `SSL_use_PrivateKey_file`/`SSL_CTX_use_PrivateKey_file`.
///
/// # Safety
/// The owner is NULL or live; `file` NULL or a path.
unsafe fn pkey_file(owner: Owner, file: *const c_char, type_: c_int, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let b = unsafe { open(file, f) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: as above.
    let (libctx, propq) = unsafe { library(owner) };
    let ret = 'r: {
        let (pkey, reason) = if type_ == SSL_FILETYPE_PEM {
            // SAFETY: as above.
            let (cb, u) = unsafe { passwd(owner) };
            // SAFETY: the BIO; the owner's password callback (no lock held).
            (
                unsafe {
                    crate::pem_pkey::PEM_read_bio_PrivateKey_ex(
                        b,
                        ptr::null_mut(),
                        cb,
                        u,
                        libctx,
                        propq,
                    )
                },
                ERR_R_PEM_LIB,
            )
        } else if type_ == SSL_FILETYPE_ASN1 {
            // SAFETY: as above.
            (
                unsafe {
                    crate::evp::pkey::d2i::d2i_PrivateKey_ex_bio(b, ptr::null_mut(), libctx, propq)
                },
                ERR_R_ASN1_LIB,
            )
        } else {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_SSL_FILETYPE, f);
            break 'r 0;
        };
        if pkey.is_null() {
            err::raise(ERR_LIB_SSL, reason, f);
            break 'r 0;
        }
        // SAFETY: as above; the key read.
        let r = unsafe { use_pkey(owner, pkey, f) };
        // SAFETY: ours.
        unsafe { EVP_PKEY_free(pkey) };
        r
    };
    // SAFETY: made here.
    unsafe { BIO_free(b) };
    ret
}

/// `SSL_use_certificate_ASN1`/`SSL_CTX_use_certificate_ASN1`.
///
/// # Safety
/// The owner is NULL or live; `d` points to `len` octets.
unsafe fn certificate_der(owner: Owner, d: *const c_uchar, len: c_int, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let (libctx, propq) = unsafe { library(owner) };
    // SAFETY: the library context and properties.
    let mut x = unsafe { crate::x509::cert::X509_new_ex(libctx, propq) };
    if x.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_ASN1_LIB, f);
        return 0;
    }
    let mut p = d;
    // SAFETY: the certificate to fill; the caller's octets.
    if unsafe { crate::x509::cert::d2i_X509(&raw mut x, &raw mut p, c_long::from(len)) }.is_null() {
        // SAFETY: ours (left as it was by the failed decoding).
        unsafe { X509_free(x) };
        err::raise(ERR_LIB_SSL, ERR_R_ASN1_LIB, f);
        return 0;
    }
    // SAFETY: as above.
    let r = unsafe { use_certificate(owner, x, f) };
    // SAFETY: ours.
    unsafe { X509_free(x) };
    r
}

/// `SSL_use_PrivateKey_ASN1`/`SSL_CTX_use_PrivateKey_ASN1`.
///
/// # Safety
/// The owner is NULL or live; `d` points to `len` octets.
unsafe fn pkey_der(owner: Owner, type_: c_int, d: *const c_uchar, len: c_long, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let (libctx, propq) = unsafe { library(owner) };
    let mut p = d;
    // SAFETY: the caller's octets.
    let pkey = unsafe {
        crate::evp::pkey::d2i::d2i_PrivateKey_ex(
            type_,
            ptr::null_mut(),
            &raw mut p,
            len,
            libctx,
            propq,
        )
    };
    if pkey.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_ASN1_LIB, f);
        return 0;
    }
    // SAFETY: as above.
    let r = unsafe { use_pkey(owner, pkey, f) };
    // SAFETY: ours.
    unsafe { EVP_PKEY_free(pkey) };
    r
}

/// `SSL_use_RSAPrivateKey`/`SSL_CTX_use_RSAPrivateKey`: the key in an `EVP_PKEY`.
///
/// # Safety
/// The owner is NULL or live; `rsa` NULL or a live key.
unsafe fn rsa_key(owner: Owner, rsa: *mut RSA, f: &str) -> c_int {
    if rsa.is_null() {
        cert::null_argument(f);
        return 0;
    }
    // SAFETY: no preconditions.
    let pkey = unsafe { EVP_PKEY_new() };
    if pkey.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_EVP_LIB, f);
        return 0;
    }
    // SAFETY: the caller's key.
    if unsafe { crate::rsa_lib::RSA_up_ref(rsa) } == 0 {
        // SAFETY: made here.
        unsafe { EVP_PKEY_free(pkey) };
        return 0;
    }
    // SAFETY: the new key takes the new reference.
    if unsafe { crate::evp::pkey::EVP_PKEY_assign(pkey, EVP_PKEY_RSA, rsa.cast()) } <= 0 {
        // SAFETY: the reference taken above.
        unsafe { crate::rsa_lib::RSA_free(rsa) };
        // SAFETY: made here.
        unsafe { EVP_PKEY_free(pkey) };
        return 0;
    }
    // SAFETY: as above.
    let r = unsafe { use_pkey(owner, pkey, f) };
    // SAFETY: ours.
    unsafe { EVP_PKEY_free(pkey) };
    r
}

/// `SSL_use_RSAPrivateKey_file`/`SSL_CTX_use_RSAPrivateKey_file`.
///
/// # Safety
/// The owner is NULL or live; `file` NULL or a path.
unsafe fn rsa_file(owner: Owner, file: *const c_char, type_: c_int, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let b = unsafe { open(file, f) };
    if b.is_null() {
        return 0;
    }
    let ret = 'r: {
        let (rsa, reason) = if type_ == SSL_FILETYPE_ASN1 {
            // SAFETY: the BIO.
            (
                unsafe { crate::rsa_asn1::d2i_RSAPrivateKey_bio(b, ptr::null_mut()) },
                ERR_R_ASN1_LIB,
            )
        } else if type_ == SSL_FILETYPE_PEM {
            // SAFETY: as above.
            let (cb, u) = unsafe { passwd(owner) };
            // SAFETY: the BIO; the owner's password callback (no lock held).
            (
                unsafe { crate::pem_pkey::PEM_read_bio_RSAPrivateKey(b, ptr::null_mut(), cb, u) },
                ERR_R_PEM_LIB,
            )
        } else {
            err::raise(ERR_LIB_SSL, SSL_R_BAD_SSL_FILETYPE, f);
            break 'r 0;
        };
        if rsa.is_null() {
            err::raise(ERR_LIB_SSL, reason, f);
            break 'r 0;
        }
        // SAFETY: as above; the key read.
        let r = unsafe { rsa_key(owner, rsa, f) };
        // SAFETY: ours.
        unsafe { crate::rsa_lib::RSA_free(rsa) };
        r
    };
    // SAFETY: made here.
    unsafe { BIO_free(b) };
    ret
}

/// `SSL_use_RSAPrivateKey_ASN1`/`SSL_CTX_use_RSAPrivateKey_ASN1`.
///
/// # Safety
/// The owner is NULL or live; `d` points to `len` octets.
unsafe fn rsa_der(owner: Owner, d: *const c_uchar, len: c_long, f: &str) -> c_int {
    let mut p = d;
    // SAFETY: the caller's octets.
    let rsa = unsafe { crate::rsa_asn1::d2i_RSAPrivateKey(ptr::null_mut(), &raw mut p, len) };
    if rsa.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_ASN1_LIB, f);
        return 0;
    }
    // SAFETY: the caller's guarantee; the key read.
    let r = unsafe { rsa_key(owner, rsa, f) };
    // SAFETY: ours.
    unsafe { crate::rsa_lib::RSA_free(rsa) };
    r
}

/// `use_certificate_chain_file`: the first certificate (with its trust settings) as the
/// owner's, the rest as its chain, until the end of the file.
///
/// # Safety
/// The owner is NULL or live; `file` NULL or a path.
unsafe fn chain_file(owner: Owner, file: *const c_char, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    if !unsafe { live(owner) } {
        return 0;
    }
    // SAFETY: no preconditions.
    unsafe { ERR_clear_error() };
    // SAFETY: the live owner.
    let (cb, u) = unsafe { passwd(owner) };
    // SAFETY: as above.
    let b = unsafe { open(file, f) };
    if b.is_null() {
        return 0;
    }
    // SAFETY: as above.
    let (libctx, propq) = unsafe { library(owner) };
    // SAFETY: the library context and properties.
    let mut x = unsafe { crate::x509::cert::X509_new_ex(libctx, propq) };
    let ret = 'r: {
        if x.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_ASN1_LIB, f);
            break 'r 0;
        }
        // SAFETY: the BIO; the certificate to fill; the password callback (no lock held).
        if unsafe { crate::pem_pkey::PEM_read_bio_X509_AUX(b, &raw mut x, cb, u) }.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_PEM_LIB, f);
            break 'r 0;
        }
        // SAFETY: as above; the certificate read.
        let mut ret = unsafe { use_certificate(owner, x, f) };
        // A key/certificate mismatch doesn't fail `use_certificate`, but it leaves an error.
        // SAFETY: no preconditions.
        if unsafe { ERR_peek_error() } != 0 {
            ret = 0;
        }
        if ret == 0 {
            break 'r 0;
        }
        // SAFETY: as above: an empty chain.
        if unsafe { cert::set0_chain(owner, ptr::null_mut()) } == 0 {
            break 'r 0;
        }
        loop {
            // SAFETY: as above.
            let mut ca = unsafe { crate::x509::cert::X509_new_ex(libctx, propq) };
            if ca.is_null() {
                err::raise(ERR_LIB_SSL, ERR_R_ASN1_LIB, f);
                break 'r 0;
            }
            // SAFETY: the BIO; the certificate to fill; the password callback.
            if unsafe { crate::pem_pkey::PEM_read_bio_X509(b, &raw mut ca, cb, u) }.is_null() {
                // SAFETY: ours.
                unsafe { X509_free(ca) };
                break;
            }
            // SAFETY: as above; the certificate read, taken on success.
            if unsafe { cert::add0_chain(owner, ca) } == 0 {
                // SAFETY: not taken.
                unsafe { X509_free(ca) };
                break 'r 0;
            }
        }
        // The loop usually ends at the end of the file, which is no error.
        // SAFETY: no preconditions.
        let e = unsafe { ERR_peek_last_error() };
        let (lib, reason) = (err::library_of(e), err::reason_of(e));
        if lib == ERR_LIB_PEM && reason == PEM_R_NO_START_LINE {
            // SAFETY: as above.
            unsafe { ERR_clear_error() };
            1
        } else {
            0
        }
    };
    // SAFETY: ours, or NULL.
    unsafe { X509_free(x) };
    // SAFETY: made here.
    unsafe { BIO_free(b) };
    ret
}

/// `ssl_set_cert_and_key`: the certificate, its key (or, for NULL, its public key), and a
/// chain into the key type's slot at once, after the security checks; with `override_` 0, only
/// into an empty slot.
///
/// # Safety
/// The owner is NULL or live; the objects NULL or live.
unsafe fn cert_and_key(
    owner: Owner,
    x509: *mut X509,
    privatekey: *mut EVP_PKEY,
    chain: *mut stack_st_X509,
    override_: c_int,
    f: &str,
) -> c_int {
    // SAFETY: the caller's guarantee.
    if !unsafe { live(owner) } {
        return 0;
    }
    // SAFETY: the live owner; the caller's certificate.
    let rv = unsafe { security_cert(owner, x509, true) };
    if rv != 1 {
        raise_reason(rv, f);
        return 0;
    }
    // SAFETY: the caller's list, or NULL (-1).
    let n = unsafe { crate::stack::OPENSSL_sk_num(chain.cast()) };
    for i in 0..n {
        // SAFETY: an index in range.
        let ca: *mut X509 = unsafe { crate::stack::OPENSSL_sk_value(chain.cast(), i) }.cast();
        // SAFETY: as above; a member of the list.
        let rv = unsafe { security_cert(owner, ca, false) };
        if rv != 1 {
            raise_reason(rv, f);
            return 0;
        }
    }
    // SAFETY: the caller's certificate.
    let pubkey = unsafe { X509_get_pubkey(x509) };
    if pubkey.is_null() {
        return 0;
    }
    // SAFETY: the certificate's key (ours); the caller's key, or NULL.
    let ret = unsafe { install(owner, x509, privatekey, pubkey, chain, override_ != 0, f) };
    // SAFETY: ours.
    unsafe { EVP_PKEY_free(pubkey) };
    ret
}

/// The second half of [`cert_and_key`]: the parameters, the match, the slot.
///
/// # Safety
/// As for [`cert_and_key`], with `pubkey` the certificate's key.
unsafe fn install(
    owner: Owner,
    x509: *mut X509,
    privatekey: *mut EVP_PKEY,
    pubkey: *mut EVP_PKEY,
    chain: *mut stack_st_X509,
    override_: bool,
    f: &str,
) -> c_int {
    let key = if privatekey.is_null() {
        pubkey
    } else {
        // SAFETY: the caller's key; RSA has no parameters (and isn't missing them).
        if unsafe { EVP_PKEY_missing_parameters(privatekey) } != 0 {
            // SAFETY: the certificate's key.
            if unsafe { EVP_PKEY_missing_parameters(pubkey) } != 0 {
                err::raise(ERR_LIB_SSL, SSL_R_MISSING_PARAMETERS, f);
                return 0;
            }
            // SAFETY: the two keys.
            if unsafe { EVP_PKEY_copy_parameters(privatekey, pubkey) } == 0 {
                err::raise(ERR_LIB_SSL, SSL_R_COPY_PARAMETERS_FAILED, f);
                return 0;
            }
        // SAFETY: as above.
        } else if unsafe { EVP_PKEY_missing_parameters(pubkey) } != 0
            // SAFETY: as above.
            && unsafe { EVP_PKEY_copy_parameters(pubkey, privatekey) } == 0
        {
            err::raise(ERR_LIB_SSL, SSL_R_COPY_PARAMETERS_FAILED, f);
            return 0;
        }
        // SAFETY: as above.
        if unsafe { EVP_PKEY_eq(pubkey, privatekey) } != 1 {
            err::raise(ERR_LIB_SSL, SSL_R_PRIVATE_KEY_MISMATCH, f);
            return 0;
        }
        privatekey
    };
    // SAFETY: the live owner.
    let types = unsafe { with_cert(owner, |c| c.provider_types.clone()) }.unwrap_or_default();
    // SAFETY: the certificate's key.
    let Some(i) = (unsafe { cert::lookup_by_pkey(pubkey, &types) }) else {
        err::raise(ERR_LIB_SSL, SSL_R_UNKNOWN_CERTIFICATE_TYPE, f);
        return 0;
    };
    // SAFETY: the live owner.
    let busy = unsafe {
        with_cert(owner, |c| {
            c.pkeys
                .get(i)
                .is_some_and(|p| !p.x509.is_null() || !p.privatekey.is_null() || !p.chain.is_null())
        })
    }
    .unwrap_or(true);
    if !override_ && busy {
        err::raise(ERR_LIB_SSL, SSL_R_NOT_REPLACING_CERTIFICATE, f);
        return 0;
    }
    let dup_chain = if chain.is_null() {
        ptr::null_mut()
    } else {
        // SAFETY: the caller's list.
        let d = unsafe { X509_chain_up_ref(chain) };
        if d.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, f);
            return 0;
        }
        d
    };
    // SAFETY: the caller's certificate.
    unsafe { X509_up_ref(x509) };
    // SAFETY: the key chosen above.
    unsafe { EVP_PKEY_up_ref(key) };
    let mut new = cert::CertPkey {
        x509,
        privatekey: key,
        chain: dup_chain,
        serverinfo: None,
    };
    let mut rel = cert::Released::default();
    let f = |c: &mut cert::Cert| match c.pkeys.get_mut(i) {
        Some(slot) => {
            // The slot's server information stays.
            new.serverinfo = slot.serverinfo.take();
            rel.slot(core::mem::replace(slot, new));
            c.key = i;
            true
        }
        None => {
            rel.slot(new);
            false
        }
    };
    // SAFETY: the live owner; the new references, taken by the slot.
    let done = unsafe { with_cert(owner, f) };
    c_int::from(done == Some(true))
}

/// `SSL_check_private_key`/`SSL_CTX_check_private_key` for the current slot.
///
/// # Safety
/// The owner is live.
unsafe fn check_private_key(owner: Owner, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    let cur =
        unsafe { with_cert(owner, |c| c.current().map(|p| (p.x509, p.privatekey))) }.flatten();
    let Some((x, k)) = cur else { return 0 };
    if x.is_null() {
        err::raise(ERR_LIB_SSL, SSL_R_NO_CERTIFICATE_ASSIGNED, f);
        return 0;
    }
    if k.is_null() {
        err::raise(ERR_LIB_SSL, SSL_R_NO_PRIVATE_KEY_ASSIGNED, f);
        return 0;
    }
    // SAFETY: the slot's certificate and key, alive while the owner holds them.
    unsafe { crate::x509::cert::X509_check_private_key(x, k) }
}

/// The current slot's certificate and key.
///
/// # Safety
/// The owner is NULL or live.
unsafe fn current(owner: Owner) -> (*mut X509, *mut EVP_PKEY) {
    // SAFETY: the caller's guarantee.
    unsafe {
        with_cert(owner, |c| {
            c.current().map_or((ptr::null_mut(), ptr::null_mut()), |p| {
                (p.x509, p.privatekey)
            })
        })
    }
    .unwrap_or((ptr::null_mut(), ptr::null_mut()))
}

/// `SSL_set0_tmp_dh_pkey`/`SSL_CTX_set0_tmp_dh_pkey`: the key (taken) after the security
/// check of its strength.
///
/// # Safety
/// The owner is NULL or live; `dhpkey` NULL or a live key.
unsafe fn set0_tmp_dh(owner: Owner, dhpkey: *mut EVP_PKEY, f: &str) -> c_int {
    // SAFETY: the caller's guarantee.
    if !unsafe { live(owner) } {
        return 0;
    }
    let bits = if dhpkey.is_null() {
        0
    } else {
        // SAFETY: the caller's key.
        unsafe { crate::evp::pkey::EVP_PKEY_get_security_bits(dhpkey) }
    };
    // SAFETY: as above; the key as the operation's object.
    if !unsafe {
        cert::security(
            owner,
            rustyssl_abi::SSL_SECOP_TMP_DH,
            bits,
            0,
            dhpkey.cast(),
        )
    } {
        err::raise(ERR_LIB_SSL, rustyssl_abi::SSL_R_DH_KEY_TOO_SMALL, f);
        return 0;
    }
    // SAFETY: as above.
    let old = unsafe { with_cert(owner, |c| core::mem::replace(&mut c.dh_tmp, dhpkey)) }
        .unwrap_or(ptr::null_mut());
    // SAFETY: our old reference, or NULL.
    unsafe { EVP_PKEY_free(old) };
    1
}

ffi_export! {
    /// The context's certificate (in its key type's slot, after the security level's check):
    /// 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `x` NULL or a live certificate.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_certificate(c: *mut SSL_CTX, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { use_certificate(Owner::Ctx(c), x, "SSL_CTX_use_certificate") }
    }
}

ffi_export! {
    /// The connection's certificate: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `x` NULL or a live certificate.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_certificate(s: *mut SSL, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { use_certificate(Owner::Ssl(s), x, "SSL_use_certificate") }
    }
}

ffi_export! {
    /// The context's certificate from a PEM or DER file: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_certificate_file(c: *mut SSL_CTX, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { certificate_file(Owner::Ctx(c), file, type_, "SSL_CTX_use_certificate_file") }
    }
}

ffi_export! {
    /// The connection's certificate from a PEM or DER file: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_certificate_file(s: *mut SSL, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { certificate_file(Owner::Ssl(s), file, type_, "SSL_use_certificate_file") }
    }
}

ffi_export! {
    /// The context's certificate from its DER: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `d` points to `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_certificate_ASN1(c: *mut SSL_CTX, len: c_int, d: *const c_uchar) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { certificate_der(Owner::Ctx(c), d, len, "SSL_CTX_use_certificate_ASN1") }
    }
}

ffi_export! {
    /// The connection's certificate from its DER: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `d` points to `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_certificate_ASN1(s: *mut SSL, d: *const c_uchar, len: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { certificate_der(Owner::Ssl(s), d, len, "SSL_use_certificate_ASN1") }
    }
}

ffi_export! {
    /// The context's private key (in its type's slot, checked against the certificate there):
    /// 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `pkey` NULL or a live key.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_PrivateKey(c: *mut SSL_CTX, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { use_pkey(Owner::Ctx(c), pkey, "SSL_CTX_use_PrivateKey") }
    }
}

ffi_export! {
    /// The connection's private key: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `pkey` NULL or a live key.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_PrivateKey(s: *mut SSL, pkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { use_pkey(Owner::Ssl(s), pkey, "SSL_use_PrivateKey") }
    }
}

ffi_export! {
    /// The context's private key from a PEM (with the password callback) or DER file: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_PrivateKey_file(c: *mut SSL_CTX, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { pkey_file(Owner::Ctx(c), file, type_, "SSL_CTX_use_PrivateKey_file") }
    }
}

ffi_export! {
    /// The connection's private key from a file: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_PrivateKey_file(s: *mut SSL, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { pkey_file(Owner::Ssl(s), file, type_, "SSL_use_PrivateKey_file") }
    }
}

ffi_export! {
    /// The context's private key of type `type_` from its DER: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `d` points to `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_PrivateKey_ASN1(type_: c_int, c: *mut SSL_CTX, d: *const c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { pkey_der(Owner::Ctx(c), type_, d, len, "SSL_CTX_use_PrivateKey_ASN1") }
    }
}

ffi_export! {
    /// The connection's private key of type `type_` from its DER: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `d` points to `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_PrivateKey_ASN1(type_: c_int, s: *mut SSL, d: *const c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { pkey_der(Owner::Ssl(s), type_, d, len, "SSL_use_PrivateKey_ASN1") }
    }
}

ffi_export! {
    /// The context's RSA private key (deprecated): 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `rsa` NULL or a live key.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_RSAPrivateKey(c: *mut SSL_CTX, rsa: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_key(Owner::Ctx(c), rsa, "SSL_CTX_use_RSAPrivateKey") }
    }
}

ffi_export! {
    /// The connection's RSA private key (deprecated): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `rsa` NULL or a live key.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_RSAPrivateKey(s: *mut SSL, rsa: *mut RSA) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_key(Owner::Ssl(s), rsa, "SSL_use_RSAPrivateKey") }
    }
}

ffi_export! {
    /// The context's RSA private key from a file (deprecated): 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_RSAPrivateKey_file(c: *mut SSL_CTX, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_file(Owner::Ctx(c), file, type_, "SSL_CTX_use_RSAPrivateKey_file") }
    }
}

ffi_export! {
    /// The connection's RSA private key from a file (deprecated): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_RSAPrivateKey_file(s: *mut SSL, file: *const c_char, type_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_file(Owner::Ssl(s), file, type_, "SSL_use_RSAPrivateKey_file") }
    }
}

ffi_export! {
    /// The context's RSA private key from its PKCS #1 DER (deprecated): 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `d` points to `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_RSAPrivateKey_ASN1(c: *mut SSL_CTX, d: *const c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_der(Owner::Ctx(c), d, len, "SSL_CTX_use_RSAPrivateKey_ASN1") }
    }
}

ffi_export! {
    /// The connection's RSA private key from its PKCS #1 DER (deprecated): 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `d` points to `len` octets.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_RSAPrivateKey_ASN1(s: *mut SSL, d: *const c_uchar, len: c_long) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rsa_der(Owner::Ssl(s), d, len, "SSL_use_RSAPrivateKey_ASN1") }
    }
}

ffi_export! {
    /// The context's certificate and chain from a PEM file: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_certificate_chain_file(c: *mut SSL_CTX, file: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { chain_file(Owner::Ctx(c), file, "SSL_CTX_use_certificate_chain_file") }
    }
}

ffi_export! {
    /// The connection's certificate and chain from a PEM file: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_certificate_chain_file(s: *mut SSL, file: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { chain_file(Owner::Ssl(s), file, "SSL_use_certificate_chain_file") }
    }
}

ffi_export! {
    /// The context's certificate, key, and chain at once: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; the objects NULL or live.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_use_cert_and_key(c: *mut SSL_CTX, x509: *mut X509, privatekey: *mut EVP_PKEY, chain: *mut stack_st_X509, override_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { cert_and_key(Owner::Ctx(c), x509, privatekey, chain, override_, "ssl_set_cert_and_key") }
    }
}

ffi_export! {
    /// The connection's certificate, key, and chain at once: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; the objects NULL or live.
    pub unsafe extern "C" fn rustyssl_private_SSL_use_cert_and_key(s: *mut SSL, x509: *mut X509, privatekey: *mut EVP_PKEY, chain: *mut stack_st_X509, override_: c_int) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { cert_and_key(Owner::Ssl(s), x509, privatekey, chain, override_, "ssl_set_cert_and_key") }
    }
}

ffi_export! {
    /// Whether the current certificate and key match: 1, or 0 (with the error raised).
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_check_private_key(c: *const SSL_CTX) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_CTX_check_private_key";
        // SAFETY: the caller's guarantee.
        if unsafe { ctx::ctx(c) }.is_none() {
            err::raise(ERR_LIB_SSL, SSL_R_NO_CERTIFICATE_ASSIGNED, F);
            return 0;
        }
        // SAFETY: as above.
        unsafe { check_private_key(Owner::Ctx(c), F) }
    }
}

ffi_export! {
    /// Whether the connection's current certificate and key match: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_check_private_key(s: *const SSL) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_check_private_key";
        // SAFETY: the caller's guarantee.
        if unsafe { conn::ssl(s) }.is_none() {
            cert::null_argument(F);
            return 0;
        }
        // SAFETY: as above.
        unsafe { check_private_key(Owner::Ssl(s), F) }
    }
}

ffi_export! {
    /// The context's current certificate (`get0`), or NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get0_certificate(c: *const SSL_CTX) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { current(Owner::Ctx(c)) }.0
    }
}

ffi_export! {
    /// The context's current private key (`get0`), or NULL.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get0_privatekey(c: *const SSL_CTX) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { current(Owner::Ctx(c)) }.1
    }
}

ffi_export! {
    /// The connection's current certificate (`get0`), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_certificate(s: *const SSL) -> *mut X509
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { current(Owner::Ssl(s)) }.0
    }
}

ffi_export! {
    /// The connection's current private key (`get0`), or NULL.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_privatekey(s: *const SSL) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { current(Owner::Ssl(s)) }.1
    }
}

ffi_export! {
    /// The context's temporary DH key (taken), after the security check: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `dhpkey` NULL or a live key it takes on success.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set0_tmp_dh_pkey(c: *mut SSL_CTX, dhpkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { set0_tmp_dh(Owner::Ctx(c), dhpkey, "SSL_CTX_set0_tmp_dh_pkey") }
    }
}

ffi_export! {
    /// The connection's temporary DH key (taken), after the security check: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `dhpkey` NULL or a live key it takes on success.
    pub unsafe extern "C" fn rustyssl_private_SSL_set0_tmp_dh_pkey(s: *mut SSL, dhpkey: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { set0_tmp_dh(Owner::Ssl(s), dhpkey, "SSL_set0_tmp_dh_pkey") }
    }
}
