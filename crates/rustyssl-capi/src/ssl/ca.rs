//! The CA name lists (`ssl_cert.c`): the names a context or connection sends as acceptable
//! CAs (`ca_names`) and in a CertificateRequest (`client_ca_names`), and the functions that
//! read subject names from certificate files, directories, and stores. Duplicates are names
//! with the same DER (OpenSSL's `xname_cmp`).

use core::ffi::{c_char, c_int};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_SSL, ERR_LIB_SYS, ERR_R_BIO_LIB, ERR_R_CRYPTO_LIB, ERR_R_SYS_LIB, ERR_R_X509_LIB,
    OSSL_LIB_CTX, OSSL_STORE_INFO_CERT, OSSL_STORE_INFO_NAME, SSL, SSL_CTX, SSL_R_PATH_TOO_LONG,
    X509, X509_NAME, stack_st_X509_NAME,
};

use super::{conn, ctx};
use crate::bio::{BIO_ctrl, BIO_free, BIO_new};
use crate::err::{self, ERR_clear_error};
use crate::ffi::ffi_export;
use crate::stack::{
    OPENSSL_sk_new_null, OPENSSL_sk_new_reserve, OPENSSL_sk_num, OPENSSL_sk_pop_free,
    OPENSSL_sk_push, OPENSSL_sk_value,
};
use crate::x509::cert::{X509_free, X509_get_subject_name};
use crate::x509::name::{X509_NAME_dup, X509_NAME_free, i2d_X509_NAME};

/// A name's DER, for duplicate checks (`xname_cmp`); `None` if it doesn't encode.
///
/// # Safety
/// `n` is a live name.
unsafe fn der(n: *const X509_NAME) -> Option<Vec<u8>> {
    let mut p: *mut u8 = ptr::null_mut();
    // SAFETY: the caller's name; the slot for the encoding.
    let len = unsafe { i2d_X509_NAME(n, &raw mut p) };
    let n = usize::try_from(len).ok()?;
    // SAFETY: the encoding's `n` octets, ours.
    let v = unsafe { core::slice::from_raw_parts(p, n) }.to_vec();
    // SAFETY: as above.
    unsafe { crate::mem::release(p.cast()) };
    Some(v)
}

/// The DER of every name of `sk`.
///
/// # Safety
/// `sk` is NULL or a live list of names.
unsafe fn ders(sk: *const stack_st_X509_NAME) -> Vec<Vec<u8>> {
    // SAFETY: the caller's list, or NULL (-1).
    let n = unsafe { OPENSSL_sk_num(sk.cast()) };
    (0..n)
        .filter_map(|i| {
            // SAFETY: an index in range.
            let x: *const X509_NAME = unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast();
            // SAFETY: a name of the list.
            unsafe { der(x) }
        })
        .collect()
}

/// `SSL_dup_CA_list`'s copy of every name, or NULL.
///
/// # Safety
/// `sk` is NULL or a live list of names.
unsafe fn dup_list(sk: *const stack_st_X509_NAME) -> *mut stack_st_X509_NAME {
    const F: &str = "SSL_dup_CA_list";
    // SAFETY: the caller's list, or NULL (-1).
    let num = unsafe { OPENSSL_sk_num(sk.cast()) }.max(0);
    // SAFETY: no preconditions.
    let ret = unsafe { OPENSSL_sk_new_reserve(None, num) };
    if ret.is_null() {
        err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, F);
        return ptr::null_mut();
    }
    for i in 0..num {
        // SAFETY: an index in range.
        let x: *const X509_NAME = unsafe { OPENSSL_sk_value(sk.cast(), i) }.cast();
        // SAFETY: a name of the list.
        let name = unsafe { X509_NAME_dup(x) };
        if name.is_null() {
            err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
            // SAFETY: the copy, with what it holds.
            unsafe { OPENSSL_sk_pop_free(ret, Some(ctx::name_free)) };
            return ptr::null_mut();
        }
        // Room was reserved, so this can't fail.
        // SAFETY: the copy; the name, taken.
        unsafe { OPENSSL_sk_push(ret, name.cast()) };
    }
    ret.cast()
}

ffi_export! {
    /// A copy of the list and its names, or NULL.
    ///
    /// # Safety
    /// `sk` is NULL or a live list of names.
    pub unsafe extern "C" fn rustyssl_private_SSL_dup_CA_list(sk: *const stack_st_X509_NAME) -> *mut stack_st_X509_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { dup_list(sk) }
    }
}

/// `add_ca_name`: a copy of `x`'s subject onto the list in `*slot`, made if need be: 1, or 0.
///
/// # Safety
/// `slot` holds NULL or a live list; `x` NULL or a live certificate.
unsafe fn add_name(slot: &mut *mut stack_st_X509_NAME, x: *const X509) -> c_int {
    if x.is_null() {
        return 0;
    }
    if slot.is_null() {
        // SAFETY: no preconditions.
        *slot = unsafe { OPENSSL_sk_new_null() }.cast();
        if slot.is_null() {
            return 0;
        }
    }
    // SAFETY: the caller's certificate.
    let name = unsafe { subject(x) };
    if name.is_null() {
        return 0;
    }
    // SAFETY: the list; the copy, taken.
    if unsafe { OPENSSL_sk_push((*slot).cast(), name.cast()) } == 0 {
        // SAFETY: not taken.
        unsafe { X509_NAME_free(name) };
        return 0;
    }
    1
}

/// Replaces the list in `slot` with `list` (taken), freeing the old one and its names.
fn set0(
    slot: &mut *mut stack_st_X509_NAME,
    list: *mut stack_st_X509_NAME,
) -> *mut stack_st_X509_NAME {
    core::mem::replace(slot, list)
}

/// Frees a list replaced by [`set0`].
///
/// # Safety
/// `old` is NULL or a list the caller owns.
unsafe fn free_list(old: *mut stack_st_X509_NAME) {
    // SAFETY: the caller's guarantee.
    unsafe { OPENSSL_sk_pop_free(old.cast(), Some(ctx::name_free)) };
}

ffi_export! {
    /// Replaces the context's CA names with `name_list` (taken).
    ///
    /// # Safety
    /// `c` is NULL or a live context; `name_list` NULL or a list it takes.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set0_CA_list(c: *mut SSL_CTX, name_list: *mut stack_st_X509_NAME)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx::ctx(c) }) else { return };
        let old = set0(&mut x.state().ca_names, name_list);
        // SAFETY: the old list, ours.
        unsafe { free_list(old) };
    }
}

ffi_export! {
    /// Replaces the connection's CA names with `name_list` (taken; NULL: use the context's).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `name_list` NULL or a list it takes.
    pub unsafe extern "C" fn rustyssl_private_SSL_set0_CA_list(s: *mut SSL, name_list: *mut stack_st_X509_NAME)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return };
        let old = set0(&mut x.state().ca_names, name_list);
        // SAFETY: the old list, ours.
        unsafe { free_list(old) };
    }
}

ffi_export! {
    /// The context's CA names (`get0`).
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get0_CA_list(c: *const SSL_CTX) -> *const stack_st_X509_NAME
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx::ctx(c) }.map_or(ptr::null(), |x| x.state().ca_names.cast_const())
    }
}

ffi_export! {
    /// The connection's CA names, or its context's (`get0`).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_CA_list(s: *const SSL) -> *const stack_st_X509_NAME
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return ptr::null() };
        let st = x.state();
        if !st.ca_names.is_null() {
            return st.ca_names;
        }
        // SAFETY: the connection's context.
        unsafe { conn::ctx_of(&st) }.map_or(ptr::null(), |c| c.state().ca_names.cast_const())
    }
}

ffi_export! {
    /// The CA names the peer sent (`get0`; none before a handshake).
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get0_peer_CA_list(s: *const SSL) -> *const stack_st_X509_NAME
    where failure = ptr::null(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { conn::ssl(s) }.map_or(ptr::null(), |x| x.state().peer_ca_names.cast_const())
    }
}

ffi_export! {
    /// Replaces the context's client CA names with `name_list` (taken).
    ///
    /// # Safety
    /// `c` is NULL or a live context; `name_list` NULL or a list it takes.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_set_client_CA_list(c: *mut SSL_CTX, name_list: *mut stack_st_X509_NAME)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { ctx::ctx(c) }) else { return };
        let old = set0(&mut x.state().client_ca_names, name_list);
        // SAFETY: the old list, ours.
        unsafe { free_list(old) };
    }
}

ffi_export! {
    /// Replaces the connection's client CA names with `name_list` (taken; NULL: the context's).
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `name_list` NULL or a list it takes.
    pub unsafe extern "C" fn rustyssl_private_SSL_set_client_CA_list(s: *mut SSL, name_list: *mut stack_st_X509_NAME)
    where failure = (), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return };
        let old = set0(&mut x.state().client_ca_names, name_list);
        // SAFETY: the old list, ours.
        unsafe { free_list(old) };
    }
}

ffi_export! {
    /// The context's client CA names.
    ///
    /// # Safety
    /// `c` is NULL or a live context.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_get_client_CA_list(c: *const SSL_CTX) -> *mut stack_st_X509_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctx::ctx(c) }.map_or(ptr::null_mut(), |x| x.state().client_ca_names)
    }
}

ffi_export! {
    /// For a server, its client CA names (or its context's); for a client, those the server
    /// sent.
    ///
    /// # Safety
    /// `s` is NULL or a live connection.
    pub unsafe extern "C" fn rustyssl_private_SSL_get_client_CA_list(s: *const SSL) -> *mut stack_st_X509_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { conn::ssl(s) }) else { return ptr::null_mut() };
        let st = x.state();
        if !st.server {
            return st.peer_ca_names;
        }
        if !st.client_ca_names.is_null() {
            return st.client_ca_names;
        }
        // SAFETY: the connection's context.
        unsafe { conn::ctx_of(&st) }.map_or(ptr::null_mut(), |c| c.state().client_ca_names)
    }
}

ffi_export! {
    /// Adds `x`'s subject to the context's CA names: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `x` NULL or a live certificate.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_add1_to_CA_list(c: *mut SSL_CTX, x: *const X509) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(cx) = (unsafe { ctx::ctx(c) }) else { return 0 };
        // SAFETY: the list; the caller's certificate.
        unsafe { add_name(&mut cx.state().ca_names, x) }
    }
}

ffi_export! {
    /// Adds `x`'s subject to the connection's CA names: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `x` NULL or a live certificate.
    pub unsafe extern "C" fn rustyssl_private_SSL_add1_to_CA_list(s: *mut SSL, x: *const X509) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(sx) = (unsafe { conn::ssl(s) }) else { return 0 };
        // SAFETY: the list; the caller's certificate.
        unsafe { add_name(&mut sx.state().ca_names, x) }
    }
}

ffi_export! {
    /// Adds `x`'s subject to the context's client CA names: 1, or 0.
    ///
    /// # Safety
    /// `c` is NULL or a live context; `x` NULL or a live certificate.
    pub unsafe extern "C" fn rustyssl_private_SSL_CTX_add_client_CA(c: *mut SSL_CTX, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(cx) = (unsafe { ctx::ctx(c) }) else { return 0 };
        // SAFETY: the list; the caller's certificate.
        unsafe { add_name(&mut cx.state().client_ca_names, x) }
    }
}

ffi_export! {
    /// Adds `x`'s subject to the connection's client CA names: 1, or 0.
    ///
    /// # Safety
    /// `s` is NULL or a live connection; `x` NULL or a live certificate.
    pub unsafe extern "C" fn rustyssl_private_SSL_add_client_CA(s: *mut SSL, x: *mut X509) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        let Some(sx) = (unsafe { conn::ssl(s) }) else { return 0 };
        // SAFETY: the list; the caller's certificate.
        unsafe { add_name(&mut sx.state().client_ca_names, x) }
    }
}

/// A copy of `x`'s subject, or NULL.
///
/// # Safety
/// `x` is a live certificate.
unsafe fn subject(x: *const X509) -> *mut X509_NAME {
    // SAFETY: the caller's certificate.
    let n = unsafe { X509_get_subject_name(x) };
    // SAFETY: its subject.
    unsafe { X509_NAME_dup(n) }
}

/// A file BIO (unopened), or NULL (no error raised: the callers raise their own).
///
/// # Safety
/// `file` is a path.
unsafe fn read_bio() -> Option<*mut rustyssl_abi::BIO> {
    // SAFETY: no preconditions.
    let m = unsafe { crate::bio::file::BIO_s_file() };
    // SAFETY: the built-in method.
    let b = unsafe { BIO_new(m) };
    (!b.is_null()).then_some(b)
}

/// Opens `file` on the file BIO `b`: whether it worked.
///
/// # Safety
/// `b` is a file BIO; `file` a path.
unsafe fn read_filename(b: *mut rustyssl_abi::BIO, file: *const c_char) -> bool {
    let flags = core::ffi::c_long::from(rustyssl_abi::BIO_CLOSE | rustyssl_abi::BIO_FP_READ);
    // SAFETY: the caller's BIO and path.
    unsafe {
        BIO_ctrl(
            b,
            rustyssl_abi::BIO_C_SET_FILENAME,
            flags,
            file.cast_mut().cast(),
        ) > 0
    }
}

/// The subjects of the PEM certificates in `file`, each not already in `seen`, pushed onto
/// `stack`: `Err(())` on failure (the list keeps what was pushed).
///
/// # Safety
/// `stack` is a live list of names; `file` a path; `libctx`/`propq` the certificates'.
unsafe fn add_file_subjects(
    stack: *mut stack_st_X509_NAME,
    file: *const c_char,
    seen: &mut Vec<Vec<u8>>,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
) -> Result<(), ()> {
    // SAFETY: the caller's guarantee.
    let Some(b) = (unsafe { read_bio() }) else {
        err::raise(
            ERR_LIB_SSL,
            ERR_R_BIO_LIB,
            "add_file_cert_subjects_to_stack",
        );
        return Err(());
    };
    // SAFETY: the library context and properties.
    let mut x = unsafe { crate::x509::cert::X509_new_ex(libctx, propq) };
    let r = 'r: {
        // SAFETY: the BIO; the caller's path.
        if !unsafe { read_filename(b, file) } {
            break 'r Err(());
        }
        loop {
            // SAFETY: the BIO; the certificate to fill.
            if unsafe { crate::pem_pkey::PEM_read_bio_X509(b, &raw mut x, None, ptr::null_mut()) }
                .is_null()
            {
                break;
            }
            // SAFETY: the certificate read.
            let xn = unsafe { subject(x) };
            if xn.is_null() {
                break 'r Err(());
            }
            // SAFETY: the copy.
            let d = unsafe { der(xn) }.unwrap_or_default();
            if seen.contains(&d) {
                // SAFETY: the copy, a duplicate.
                unsafe { X509_NAME_free(xn) };
                continue;
            }
            // SAFETY: the list; the copy, taken.
            if unsafe { OPENSSL_sk_push(stack.cast(), xn.cast()) } == 0 {
                // SAFETY: not taken.
                unsafe { X509_NAME_free(xn) };
                break 'r Err(());
            }
            seen.push(d);
        }
        Ok(())
    };
    // SAFETY: ours, or NULL.
    unsafe { X509_free(x) };
    // SAFETY: made here.
    unsafe { BIO_free(b) };
    r
}

ffi_export! {
    /// The distinct subjects of the PEM certificates in `file`, as a new list; NULL if the
    /// file can't be read or has none.
    ///
    /// # Safety
    /// `file` is NULL or a path; `libctx` NULL or live; `propq` NULL or a string.
    pub unsafe extern "C" fn rustyssl_private_SSL_load_client_CA_file_ex(file: *const c_char, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut stack_st_X509_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        const F: &str = "SSL_load_client_CA_file_ex";
        if file.is_null() {
            super::cert::null_argument(F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's path.
        let Some(b) = (unsafe { read_bio() }) else {
            err::raise(ERR_LIB_SSL, ERR_R_BIO_LIB, F);
            return ptr::null_mut();
        };
        // SAFETY: the caller's library context and properties.
        let mut x = unsafe { crate::x509::cert::X509_new_ex(libctx, propq) };
        let mut ret: *mut stack_st_X509_NAME = ptr::null_mut();
        let mut seen: Vec<Vec<u8>> = Vec::new();
        let ok = 'r: {
            if x.is_null() {
                err::raise(ERR_LIB_SSL, ERR_R_X509_LIB, F);
                break 'r false;
            }
            // SAFETY: the BIO; the caller's path.
            if !unsafe { read_filename(b, file) } {
                break 'r false;
            }
            loop {
                // SAFETY: the BIO; the certificate to fill.
                if unsafe { crate::pem_pkey::PEM_read_bio_X509(b, &raw mut x, None, ptr::null_mut()) }.is_null() {
                    break 'r true;
                }
                if ret.is_null() {
                    // SAFETY: no preconditions.
                    ret = unsafe { OPENSSL_sk_new_null() }.cast();
                    if ret.is_null() {
                        err::raise(ERR_LIB_SSL, ERR_R_CRYPTO_LIB, F);
                        break 'r false;
                    }
                }
                // SAFETY: the certificate read.
                let xn = unsafe { subject(x) };
                if xn.is_null() {
                    break 'r false;
                }
                // SAFETY: the copy.
                let d = unsafe { der(xn) }.unwrap_or_default();
                if seen.contains(&d) {
                    // SAFETY: a duplicate, ours.
                    unsafe { X509_NAME_free(xn) };
                    continue;
                }
                // SAFETY: the list; the copy, taken.
                if unsafe { OPENSSL_sk_push(ret.cast(), xn.cast()) } == 0 {
                    // SAFETY: not taken.
                    unsafe { X509_NAME_free(xn) };
                    break 'r false;
                }
                seen.push(d);
            }
        };
        if !ok {
            // SAFETY: the list made here, or NULL.
            unsafe { free_list(ret) };
            ret = ptr::null_mut();
        }
        // SAFETY: made here.
        unsafe { BIO_free(b) };
        // SAFETY: ours, or NULL.
        unsafe { X509_free(x) };
        if !ret.is_null() {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_error() };
        }
        ret
    }
}

ffi_export! {
    /// `SSL_load_client_CA_file_ex` with the default library context.
    ///
    /// # Safety
    /// `file` is NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_load_client_CA_file(file: *const c_char) -> *mut stack_st_X509_NAME
    where failure = ptr::null_mut(), library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        unsafe { rustyssl_private_SSL_load_client_CA_file_ex(file, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Adds the subjects of the PEM certificates in `file` to `stack`, skipping names already
    /// there: 1, or 0.
    ///
    /// # Safety
    /// `stack` is a live list of names; `file` NULL or a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_add_file_cert_subjects_to_stack(stack: *mut stack_st_X509_NAME, file: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        if file.is_null() {
            super::cert::null_argument("SSL_add_file_cert_subjects_to_stack");
            return 0;
        }
        // SAFETY: the caller's list.
        let mut seen = unsafe { ders(stack) };
        // SAFETY: the caller's list and path.
        let r = unsafe { add_file_subjects(stack, file, &mut seen, ptr::null_mut(), ptr::null()) };
        if r.is_ok() {
            // SAFETY: no preconditions.
            unsafe { ERR_clear_error() };
        }
        c_int::from(r.is_ok())
    }
}

ffi_export! {
    /// Adds the subjects of the PEM certificates in every file of directory `dir` (not its
    /// subdirectories) to `stack`, skipping names already there: 1, or 0.
    ///
    /// # Safety
    /// `stack` is a live list of names; `dir` a path.
    pub unsafe extern "C" fn rustyssl_private_SSL_add_dir_cert_subjects_to_stack(stack: *mut stack_st_X509_NAME, dir: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        const F: &str = "SSL_add_dir_cert_subjects_to_stack";
        // SAFETY: the caller's list.
        let mut seen = unsafe { ders(stack) };
        let mut d: *mut rustyssl_abi::OPENSSL_DIR_CTX = ptr::null_mut();
        // SAFETY: the caller's path.
        let dir_bytes = unsafe { core::ffi::CStr::from_ptr(dir) }.to_bytes().to_vec();
        let ret = 'r: {
            loop {
                // SAFETY: the iteration's context; the caller's path.
                let name = unsafe { crate::dir::OPENSSL_DIR_read(&raw mut d, dir) };
                if name.is_null() {
                    break;
                }
                // SAFETY: the entry's NUL-terminated name.
                let name = unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes();
                if dir_bytes.len().saturating_add(name.len()).saturating_add(2) > 1024 {
                    err::raise(ERR_LIB_SSL, SSL_R_PATH_TOO_LONG, F);
                    break 'r 0;
                }
                let mut path = dir_bytes.clone();
                path.push(b'/');
                path.extend_from_slice(name);
                let Ok(p) = std::ffi::CString::new(path) else { break 'r 0 };
                // Subdirectories are skipped.
                let os_path = <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(p.as_bytes());
                if std::fs::metadata(os_path).is_ok_and(|m| m.is_dir()) {
                    continue;
                }
                // SAFETY: the list; the entry's path.
                if unsafe { add_file_subjects(stack, p.as_ptr(), &mut seen, ptr::null_mut(), ptr::null()) }.is_err() {
                    break 'r 0;
                }
                // SAFETY: no preconditions.
                unsafe { ERR_clear_error() };
            }
            let e = crate::errno::get();
            if e != 0 {
                err::raise_with_text(ERR_LIB_SYS, e, F, &format!("calling OPENSSL_dir_read({})", String::from_utf8_lossy(&dir_bytes)));
                err::raise(ERR_LIB_SSL, ERR_R_SYS_LIB, F);
                break 'r 0;
            }
            1
        };
        if !d.is_null() {
            // SAFETY: the iteration's context.
            unsafe { crate::dir::OPENSSL_DIR_end(&raw mut d) };
        }
        ret
    }
}

/// `add_uris_recursive`: the certificates' subjects from store `uri` (and, `depth` levels
/// down, the stores it names), skipping names already in `stack`: whether it worked.
///
/// # Safety
/// `stack` is a live list of names; `uri` a string.
unsafe fn add_uris(stack: *mut stack_st_X509_NAME, uri: *const c_char, depth: c_int) -> bool {
    use crate::store::ctx::{
        OSSL_STORE_close, OSSL_STORE_eof, OSSL_STORE_error, OSSL_STORE_load, OSSL_STORE_open,
    };
    use crate::store::info::{
        OSSL_STORE_INFO_free, OSSL_STORE_INFO_get_type, OSSL_STORE_INFO_get0_CERT,
        OSSL_STORE_INFO_get0_NAME,
    };
    // SAFETY: the caller's URI; no UI or post-processing.
    let ctx = unsafe { OSSL_STORE_open(uri, ptr::null(), ptr::null_mut(), None, ptr::null_mut()) };
    if ctx.is_null() {
        return false;
    }
    let mut ok = true;
    // SAFETY: the store, for each check.
    while unsafe { OSSL_STORE_eof(ctx) } == 0 && unsafe { OSSL_STORE_error(ctx) } == 0 {
        // SAFETY: the store.
        let info = unsafe { OSSL_STORE_load(ctx) };
        if info.is_null() {
            continue;
        }
        // SAFETY: the object loaded.
        let t = unsafe { OSSL_STORE_INFO_get_type(info) };
        if t == OSSL_STORE_INFO_NAME {
            if depth > 0 {
                // SAFETY: as above; its name.
                let name = unsafe { OSSL_STORE_INFO_get0_NAME(info) };
                // SAFETY: the caller's list; the name.
                ok = unsafe { add_uris(stack, name, depth.saturating_sub(1)) };
            }
        } else if t == OSSL_STORE_INFO_CERT {
            // SAFETY: as above.
            let x = unsafe { OSSL_STORE_INFO_get0_CERT(info) };
            let xn = if x.is_null() {
                ptr::null_mut()
            } else {
                // SAFETY: the entry's certificate.
                unsafe { subject(x) }
            };
            if xn.is_null() {
                // SAFETY: the object loaded.
                unsafe { OSSL_STORE_INFO_free(info) };
                ok = false;
                break;
            }
            // SAFETY: the copy; the caller's list.
            let dup = unsafe { der(xn) }.is_some_and(|d| unsafe { ders(stack) }.contains(&d));
            // SAFETY: the list; the copy, taken when pushed.
            if dup || unsafe { OPENSSL_sk_push(stack.cast(), xn.cast()) } == 0 {
                // SAFETY: not taken.
                unsafe { X509_NAME_free(xn) };
                if !dup {
                    // SAFETY: as above.
                    unsafe { OSSL_STORE_INFO_free(info) };
                    ok = false;
                    break;
                }
            }
        }
        // SAFETY: the object loaded.
        unsafe { OSSL_STORE_INFO_free(info) };
    }
    if ok {
        // SAFETY: no preconditions.
        unsafe { ERR_clear_error() };
    }
    // SAFETY: the store.
    unsafe { OSSL_STORE_close(ctx) };
    ok
}

ffi_export! {
    /// Adds the subjects of the certificates in store `store` (and the stores it lists, one
    /// level down) to `stack`, skipping names already there: 1, or 0.
    ///
    /// # Safety
    /// `stack` is a live list of names; `store` a URI.
    pub unsafe extern "C" fn rustyssl_private_SSL_add_store_cert_subjects_to_stack(stack: *mut stack_st_X509_NAME, store: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_SSL
    {
        // SAFETY: the caller's guarantee.
        c_int::from(unsafe { add_uris(stack, store, 1) })
    }
}
