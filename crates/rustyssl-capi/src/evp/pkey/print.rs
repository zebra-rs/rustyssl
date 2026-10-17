//! Printing keys (`EVP_PKEY_print_public(3)`, `_private`, `_params`, and their `_fp` forms;
//! `p_lib.c`): with the text encoders of the key's providers, else with the key's ASN.1 method's
//! print function, else a line saying the algorithm is unsupported.
//!
//! As in OpenSSL:
//! - A positive indentation applies to every line: the BIO's own (a prefix BIO's), else through
//!   a prefix BIO pushed for the call; the BIO's indentation is restored after. Without one,
//!   the BIO's indentation is set to 0.
//! - A key without data can't be encoded (`OSSL_ENCODER_CTX_new_for_pkey` raises that, and the
//!   error stays); a key typed by an ASN.1 method has no encoders.
//! - The fallback line says "Public Key" for the private key and parameters too, and names the
//!   key type by its long name (`<NULL>`, with `OBJ_R_UNKNOWN_NID`, for a type without one).

use core::ffi::{CStr, c_int, c_long};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    ASN1_PCTX, BIO, BIO_CTRL_GET_INDENT, BIO_CTRL_SET_INDENT, BIO_NOCLOSE, ERR_LIB_EVP, EVP_PKEY,
    EVP_PKEY_KEY_PARAMETERS, EVP_PKEY_KEYPAIR, EVP_PKEY_PUBLIC_KEY,
};

use super::Pkey;
use super::ameth::Print;
use crate::bio::{BIO_ctrl, BIO_free, BIO_indent, BIO_new, BIO_pop, BIO_push, BIO_write};
use crate::encoder::ctx::{
    OSSL_ENCODER_CTX_free, OSSL_ENCODER_CTX_get_num_encoders, OSSL_ENCODER_to_bio,
};
use crate::encoder::pkey::OSSL_ENCODER_CTX_new_for_pkey;
use crate::ffi::ffi_export;

/// `print_set_indent` and `print_reset_indent`: runs `f` with `out` (or a prefix BIO pushed on
/// it) indenting by `indent`; 0 if the indentation can't be set.
///
/// # Safety
/// `out` is a live BIO.
unsafe fn with_indent(out: *mut BIO, indent: c_int, f: impl FnOnce(*mut BIO) -> c_int) -> c_int {
    if indent <= 0 {
        let ret = f(out);
        // OpenSSL resets the indentation all the same: to 0.
        // SAFETY: the caller's BIO.
        unsafe { BIO_ctrl(out, BIO_CTRL_SET_INDENT, 0, ptr::null_mut()) };
        return ret;
    }
    let set = |b: *mut BIO| {
        // SAFETY: a live BIO.
        unsafe {
            BIO_ctrl(
                b,
                BIO_CTRL_SET_INDENT,
                c_long::from(indent),
                ptr::null_mut(),
            )
        }
    };
    // SAFETY: the caller's BIO.
    let saved = unsafe { BIO_ctrl(out, BIO_CTRL_GET_INDENT, 0, ptr::null_mut()) }.max(0);
    let mut b = out;
    let mut pushed = false;
    if set(b) <= 0 {
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::prefix::BIO_f_prefix() };
        // SAFETY: the method.
        let prefix = unsafe { BIO_new(method) };
        if prefix.is_null() {
            return 0;
        }
        // SAFETY: the new BIO on the caller's.
        b = unsafe { BIO_push(prefix, out) };
        pushed = true;
    }
    let reset = |b: *mut BIO| {
        // SAFETY: a live BIO.
        unsafe { BIO_ctrl(b, BIO_CTRL_SET_INDENT, saved, ptr::null_mut()) };
        if pushed {
            // SAFETY: the prefix BIO pushed above, taken off the caller's and freed.
            unsafe { BIO_pop(b) };
            // SAFETY: as above.
            unsafe { BIO_free(b) };
        }
    };
    if set(b) <= 0 {
        reset(b);
        return 0;
    }
    let ret = f(b);
    reset(b);
    ret
}

/// `unsup_alg`: the line for a key nothing prints (it says "Public Key" whatever it was asked
/// for, as OpenSSL's does).
///
/// # Safety
/// `out` is a live BIO.
unsafe fn unsupported(out: *mut BIO, k: &Pkey) -> c_int {
    // SAFETY: the caller's BIO.
    if unsafe { BIO_indent(out, 0, 128) } == 0 {
        return 0;
    }
    // SAFETY: a number.
    let ln = unsafe { crate::objects::OBJ_nid2ln(k.type_()) };
    // OpenSSL's printf prints a NULL string as `<NULL>`.
    // SAFETY: NULL or a static name.
    let name = unsafe { super::text(ln) }.map_or(&b"<NULL>"[..], CStr::to_bytes);
    let mut line = b"Public Key algorithm \"".to_vec();
    line.extend_from_slice(name);
    line.extend_from_slice(b"\" unsupported\n");
    let Ok(n) = c_int::try_from(line.len()) else {
        return 0;
    };
    // SAFETY: the caller's BIO; the line.
    c_int::from(unsafe { BIO_write(out, line.as_ptr().cast(), n) } > 0)
}

/// Which of the key's ASN.1 method's print functions.
#[derive(Clone, Copy)]
enum Part {
    Public,
    Private,
    Params,
}

/// `print_pkey`.
///
/// # Safety
/// `out` is a live BIO; `pkey` is NULL or a live key; `pctx` is what the key's method's print
/// function takes.
unsafe fn print(
    out: *mut BIO,
    pkey: *const EVP_PKEY,
    indent: c_int,
    part: Part,
    pctx: *mut ASN1_PCTX,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { super::pkey(pkey) }) else {
        // The reference reads the NULL key (docs/DEVIATIONS.md).
        return 0;
    };
    let legacy: Option<Print> = k.ameth_funcs().and_then(|f| match part {
        Part::Public => f.pub_print,
        Part::Private => f.priv_print,
        Part::Params => f.param_print,
    });
    let selection = match part {
        Part::Public => EVP_PKEY_PUBLIC_KEY,
        Part::Private => EVP_PKEY_KEYPAIR,
        Part::Params => EVP_PKEY_KEY_PARAMETERS,
    };
    let body = |b: *mut BIO| {
        // SAFETY: the caller's key; a static output type.
        let ctx = unsafe {
            OSSL_ENCODER_CTX_new_for_pkey(
                pkey,
                selection,
                c"TEXT".as_ptr(),
                ptr::null(),
                ptr::null(),
            )
        };
        let mut ret = -2;
        // SAFETY: the new context, or NULL.
        if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } != 0 {
            // SAFETY: as above; the (indenting) BIO.
            ret = unsafe { OSSL_ENCODER_to_bio(ctx, b) };
        }
        // SAFETY: as above.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        if ret != -2 {
            return ret;
        }
        match legacy {
            // SAFETY: the method's function with the (indenting) BIO, the key, and the caller's
            // context.
            Some(p) => unsafe { p(b, pkey, 0, pctx) },
            // SAFETY: the (indenting) BIO.
            None => unsafe { unsupported(b, k) },
        }
    };
    // SAFETY: the caller's BIO.
    unsafe { with_indent(out, indent, body) }
}

/// The `_fp` forms: `f` with a BIO on `fp`.
///
/// # Safety
/// `fp` is a live `FILE`.
unsafe fn on_file(fp: *mut FILE, f: impl FnOnce(*mut BIO) -> c_int) -> c_int {
    // SAFETY: the caller's guarantee.
    let b = unsafe { crate::bio::file::BIO_new_fp(fp, BIO_NOCLOSE) };
    if b.is_null() {
        return 0;
    }
    let ret = f(b);
    // SAFETY: made above.
    unsafe { BIO_free(b) };
    ret
}

ffi_export! {
    /// Prints the key's public key to `out`, each line indented by `indent`: 1 (or what the
    /// key's ASN.1 method's print function returns), 0 on failure.
    ///
    /// # Safety
    /// `out` is a live BIO; `pkey` is NULL or a live key; `pctx` is NULL or a print context.
    pub unsafe extern "C" fn EVP_PKEY_print_public(out: *mut BIO, pkey: *const EVP_PKEY, indent: c_int, pctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { print(out, pkey, indent, Part::Public, pctx) }
    }
}

ffi_export! {
    /// Prints the key's private key, as `EVP_PKEY_print_public`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_print_public`.
    pub unsafe extern "C" fn EVP_PKEY_print_private(out: *mut BIO, pkey: *const EVP_PKEY, indent: c_int, pctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { print(out, pkey, indent, Part::Private, pctx) }
    }
}

ffi_export! {
    /// Prints the key's parameters, as `EVP_PKEY_print_public`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_print_public`.
    pub unsafe extern "C" fn EVP_PKEY_print_params(out: *mut BIO, pkey: *const EVP_PKEY, indent: c_int, pctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { print(out, pkey, indent, Part::Params, pctx) }
    }
}

ffi_export! {
    /// `EVP_PKEY_print_public` to a `FILE`.
    ///
    /// # Safety
    /// `fp` is a live `FILE`; otherwise as for `EVP_PKEY_print_public`.
    pub unsafe extern "C" fn EVP_PKEY_print_public_fp(fp: *mut FILE, pkey: *const EVP_PKEY, indent: c_int, pctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's key, with the BIO on the caller's file.
        let f = |b| unsafe { print(b, pkey, indent, Part::Public, pctx) };
        // SAFETY: the caller's file.
        unsafe { on_file(fp, f) }
    }
}

ffi_export! {
    /// `EVP_PKEY_print_private` to a `FILE`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_print_public_fp`.
    pub unsafe extern "C" fn EVP_PKEY_print_private_fp(fp: *mut FILE, pkey: *const EVP_PKEY, indent: c_int, pctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's key, with the BIO on the caller's file.
        let f = |b| unsafe { print(b, pkey, indent, Part::Private, pctx) };
        // SAFETY: the caller's file.
        unsafe { on_file(fp, f) }
    }
}

ffi_export! {
    /// `EVP_PKEY_print_params` to a `FILE`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_print_public_fp`.
    pub unsafe extern "C" fn EVP_PKEY_print_params_fp(fp: *mut FILE, pkey: *const EVP_PKEY, indent: c_int, pctx: *mut ASN1_PCTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's key, with the BIO on the caller's file.
        let f = |b| unsafe { print(b, pkey, indent, Part::Params, pctx) };
        // SAFETY: the caller's file.
        unsafe { on_file(fp, f) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: printing a NULL key fails (the reference reads it).
    #[test]
    fn null_keys_print_nothing() {
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::mem::BIO_s_mem() };
        // SAFETY: the method.
        let b = unsafe { BIO_new(method) };
        // SAFETY: the BIO; NULL is the case under test, here and below.
        let r = unsafe { EVP_PKEY_print_public(b, ptr::null(), 2, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_PKEY_print_private(b, ptr::null(), 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        let r = unsafe { EVP_PKEY_print_params(b, ptr::null(), 0, ptr::null_mut()) };
        assert_eq!(r, 0);
        // SAFETY: made above.
        unsafe { BIO_free(b) };
    }
}
