//! Asymmetric ciphers (`EVP_ASYM_CIPHER(3)`, `EVP_PKEY_encrypt(3)`, `EVP_PKEY_decrypt(3)`;
//! `asymcipher.c`, `p_enc.c`, `p_dec.c`): an `EVP_ASYM_CIPHER` made from a provider's
//! algorithm, fetched and introspected, and the key context's encryption and decryption
//! through it.
//!
//! As in OpenSSL:
//! - A cipher must have `newctx` and `freectx`, and at least one of the pairs (`encrypt_init`,
//!   `encrypt`) and (`decrypt_init`, `decrypt`), each whole or absent; its parameter getters and
//!   setters come in pairs.
//! - The init finds the cipher the key manager names and exports the key to its provider's key
//!   manager; where none takes the key, the legacy path: a legacy context's `EVP_PKEY_METHOD`
//!   encrypts and decrypts (its init, though, wants `encrypt` for either), and a method that
//!   sizes outputs itself answers size queries with the key's size. Without one, the operation
//!   isn't supported, and stays set.
//! - A provider function that fails without an error gets `EVP_R_PROVIDER_ASYM_CIPHER_FAILURE`
//!   naming the cipher and the function.
//!
//! `EVP_PKEY_encrypt_old` and `EVP_PKEY_decrypt_old` take RSA keys only; an RSA key with data
//! comes with 4.3 (until then they abort on one, AGENTS.md rule 10).

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, EVP_ASYM_CIPHER, EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_OP_DECRYPT, EVP_PKEY_OP_ENCRYPT,
    EVP_PKEY_OP_UNDEFINED, EVP_PKEY_RSA, EVP_R_INITIALIZATION_ERROR, EVP_R_NO_KEY_SET,
    EVP_R_OPERATION_NOT_INITIALIZED, EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
    EVP_R_PROVIDER_ASYM_CIPHER_FAILURE, EVP_R_PROVIDER_ASYM_CIPHER_NOT_SUPPORTED,
    EVP_R_PUBLIC_KEY_NOT_RSA, OSSL_FUNC_ASYM_CIPHER_DECRYPT, OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT,
    OSSL_FUNC_ASYM_CIPHER_DUPCTX, OSSL_FUNC_ASYM_CIPHER_ENCRYPT,
    OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, OSSL_FUNC_ASYM_CIPHER_FREECTX,
    OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS, OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
    OSSL_FUNC_ASYM_CIPHER_NEWCTX, OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
    OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, OSSL_LIB_CTX, OSSL_OP_ASYM_CIPHER, OSSL_PARAM,
    OSSL_PROVIDER,
};

use super::fetch::Kind;
use super::opmeth::{self, AnyFn, Common, OpMethod, Table, keep, method_exports};
use super::pkey;
use super::pkey_ctx;
use super::pmeth;
use crate::err::{self, ERR_clear_last_mark, ERR_count_to_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_export;
use crate::handle::handle_type;
use crate::provider::Ptr;

type InitFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *const OSSL_PARAM) -> c_int;
type CryptFn =
    unsafe extern "C" fn(*mut c_void, *mut u8, *mut usize, usize, *const u8, usize) -> c_int;

/// An asymmetric cipher's functions.
#[derive(Default, Clone, Copy)]
pub(crate) struct Funcs {
    common: Common,
    encrypt_init: Option<InitFn>,
    encrypt: Option<CryptFn>,
    decrypt_init: Option<InitFn>,
    decrypt: Option<CryptFn>,
}

impl Table for Funcs {
    const FROM_ALGORITHM: &'static str = "evp_asym_cipher_from_algorithm";

    fn set(&mut self, id: c_int, f: AnyFn) {
        let c = &mut self.common;
        match id {
            OSSL_FUNC_ASYM_CIPHER_NEWCTX => keep!(c.newctx, f),
            OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT => keep!(self.encrypt_init, f),
            OSSL_FUNC_ASYM_CIPHER_ENCRYPT => keep!(self.encrypt, f),
            OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT => keep!(self.decrypt_init, f),
            OSSL_FUNC_ASYM_CIPHER_DECRYPT => keep!(self.decrypt, f),
            OSSL_FUNC_ASYM_CIPHER_FREECTX => keep!(c.freectx, f),
            OSSL_FUNC_ASYM_CIPHER_DUPCTX => keep!(c.dupctx, f),
            OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS => keep!(c.get_ctx_params, f),
            OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS => {
                keep!(c.gettable_ctx_params, f);
            }
            OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS => keep!(c.set_ctx_params, f),
            OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS => {
                keep!(c.settable_ctx_params, f);
            }
            _ => {}
        }
    }

    fn whole(&self) -> bool {
        let c = &self.common;
        let enc = usize::from(self.encrypt_init.is_some()) + usize::from(self.encrypt.is_some());
        let dec = usize::from(self.decrypt_init.is_some()) + usize::from(self.decrypt.is_some());
        c.newctx.is_some()
            && c.freectx.is_some()
            && (enc == 0 || enc == 2)
            && (dec == 0 || dec == 2)
            && (enc == 2 || dec == 2)
            && c.params_paired()
    }

    fn common(&self) -> &Common {
        &self.common
    }
}

/// An asymmetric cipher (`EVP_ASYM_CIPHER`).
pub(crate) type AsymCipher = OpMethod<Funcs>;

handle_type!(EVP_ASYM_CIPHER => AsymCipher);

/// A reference to an asymmetric cipher.
pub(crate) type Ref = opmeth::Ref<EVP_ASYM_CIPHER>;

/// Asymmetric ciphers to fetching.
static CIPHERS: Kind = Kind {
    operation: OSSL_OP_ASYM_CIPHER,
    from_algorithm: opmeth::from_algorithm::<EVP_ASYM_CIPHER, Funcs>,
    up_ref: opmeth::up_ref::<EVP_ASYM_CIPHER>,
    free: opmeth::free::<EVP_ASYM_CIPHER>,
};

method_exports! {
    EVP_ASYM_CIPHER, CIPHERS;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_fetch;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_up_ref;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_free;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_get0_provider;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_get0_name;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_get0_description;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_is_a;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_names_do_all;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_do_all_provided;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_gettable_ctx_params;
    pub unsafe extern "C" fn EVP_ASYM_CIPHER_settable_ctx_params;
}

/// `evp_pkey_asym_cipher_init`: starts encrypting or decrypting. 1, or <= 0 with an error.
///
/// # Safety
/// `ctx` is NULL or a live context; `params` is NULL or an array.
unsafe fn cipher_init(
    ctx: *mut EVP_PKEY_CTX,
    operation: c_int,
    params: *const OSSL_PARAM,
) -> c_int {
    const F: &str = "evp_pkey_asym_cipher_init";
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            F,
        );
        return -2;
    };
    let (libctx, keymgmt, pkey, propq) = {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = operation;
        (
            s.libctx.0,
            s.keymgmt.clone(),
            s.pkey.clone(),
            s.propquery.clone(),
        )
    };
    let fail = |ret: c_int| {
        let mut s = c.lock();
        s.free_old_ops();
        s.operation = EVP_PKEY_OP_UNDEFINED;
        ret
    };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let Some(km) = keymgmt else {
        // A legacy context: its method's init.
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
        // OpenSSL wants `encrypt` for either operation.
        let f = c.lock().pmeth_funcs().filter(|f| f.encrypt.is_some());
        let Some(f) = f else {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                F,
            );
            return -2;
        };
        let init = if operation == EVP_PKEY_OP_ENCRYPT {
            f.encrypt_init
        } else {
            f.decrypt_init
        };
        let Some(init) = init else { return 1 };
        // SAFETY: the method's function with the caller's context.
        let ret = unsafe { init(ctx) };
        return if ret <= 0 { fail(ret) } else { ret };
    };
    let Some(pkey) = pkey else {
        // SAFETY: the mark set above.
        unsafe { ERR_clear_last_mark() };
        err::raise(ERR_LIB_EVP, EVP_R_NO_KEY_SET, F);
        return fail(0);
    };
    let supported = km.get().query_operation_name(OSSL_OP_ASYM_CIPHER);
    // SAFETY: the context's library context; the ciphers' kind.
    let found = unsafe {
        opmeth::find::<EVP_ASYM_CIPHER, Funcs>(
            libctx,
            &CIPHERS,
            &km,
            &pkey,
            propq.as_deref(),
            &supported,
        )
    };
    // SAFETY: the mark set above.
    unsafe { ERR_pop_to_mark() };
    let Ok(found) = found else {
        // `legacy`: a context with a key manager has no method, so it isn't supported.
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            F,
        );
        return -2;
    };
    let m = found.method;
    let algctx = m.get().newctx();
    {
        let mut s = c.lock();
        s.cipher = Some(m.clone());
        s.ciphctx = Ptr(algctx);
    }
    if algctx.is_null() {
        err::raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR, F);
        return fail(0);
    }
    let (init, what) = if operation == EVP_PKEY_OP_ENCRYPT {
        (m.get().funcs.encrypt_init, "encrypt_init")
    } else {
        (m.get().funcs.decrypt_init, "decrypt_init")
    };
    let Some(init) = init else {
        err::raise_with_text(
            ERR_LIB_EVP,
            EVP_R_PROVIDER_ASYM_CIPHER_NOT_SUPPORTED,
            F,
            &m.get().text(what),
        );
        return fail(-2);
    };
    // SAFETY: the provider's function with its context, the key's data, and the caller's array.
    let ret = unsafe { init(algctx, found.keydata.ptr(), params) };
    if ret <= 0 {
        return fail(ret);
    }
    1
}

ffi_export! {
    /// Starts encrypting with the cipher the key's type names.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_encrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { cipher_init(ctx, EVP_PKEY_OP_ENCRYPT, ptr::null()) }
    }
}

ffi_export! {
    /// Starts encrypting, giving the cipher `params`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_encrypt_init_ex(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { cipher_init(ctx, EVP_PKEY_OP_ENCRYPT, params) }
    }
}

ffi_export! {
    /// Starts decrypting with the cipher the key's type names.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_decrypt_init(ctx: *mut EVP_PKEY_CTX) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { cipher_init(ctx, EVP_PKEY_OP_DECRYPT, ptr::null()) }
    }
}

ffi_export! {
    /// Starts decrypting, giving the cipher `params`.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `params` is NULL or an array.
    pub unsafe extern "C" fn EVP_PKEY_decrypt_init_ex(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { cipher_init(ctx, EVP_PKEY_OP_DECRYPT, params) }
    }
}

/// `EVP_PKEY_encrypt` and `EVP_PKEY_decrypt`.
///
/// # Safety
/// `ctx` is NULL or a live context; `out` is NULL or has room for `*outlen` octets; `outlen` is
/// room for a size; `in_` holds `inlen` octets.
unsafe fn crypt(
    ctx: *mut EVP_PKEY_CTX,
    operation: c_int,
    out: *mut u8,
    outlen: *mut usize,
    in_: *const u8,
    inlen: usize,
) -> c_int {
    let (f, what) = if operation == EVP_PKEY_OP_ENCRYPT {
        ("EVP_PKEY_encrypt", "encrypt")
    } else {
        ("EVP_PKEY_decrypt", "decrypt")
    };
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            f,
        );
        return -2;
    };
    let (op, m, algctx, pmeth) = {
        let s = c.lock();
        (s.operation, s.cipher.clone(), s.ciphctx.0, s.pmeth.clone())
    };
    if op != operation {
        err::raise(ERR_LIB_EVP, EVP_R_OPERATION_NOT_INITIALIZED, f);
        return -1;
    }
    let (Some(m), false) = (m, algctx.is_null()) else {
        // `legacy`: a legacy context's method.
        let func = pmeth.as_ref().and_then(|m| {
            let funcs = m.get().funcs();
            if operation == EVP_PKEY_OP_ENCRYPT {
                funcs.encrypt
            } else {
                funcs.decrypt
            }
        });
        let (Some(pm), Some(func)) = (pmeth, func) else {
            err::raise(
                ERR_LIB_EVP,
                EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                f,
            );
            return -2;
        };
        // SAFETY: the caller's context.
        let pkey = unsafe { pkey_ctx::EVP_PKEY_CTX_get0_pkey(ctx) };
        // SAFETY: the context's key, or NULL; the caller's room for the size.
        if let Some(r) = unsafe { pmeth::check_autoarg(pm.get(), pkey, out.is_null(), outlen, f) } {
            return r;
        }
        // SAFETY: the method's function with the caller's context and buffers.
        return unsafe { func(ctx, out, outlen, in_, inlen) };
    };
    let func = if operation == EVP_PKEY_OP_ENCRYPT {
        m.get().funcs.encrypt
    } else {
        m.get().funcs.decrypt
    };
    let Some(func) = func else {
        // An init can't have succeeded without the function (they come in pairs).
        err::raise(
            ERR_LIB_EVP,
            EVP_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
            f,
        );
        return -2;
    };
    let size = if out.is_null() || outlen.is_null() {
        0
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { outlen.read() }
    };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    // SAFETY: the provider's function with its context and the caller's buffers.
    let ret = unsafe { func(algctx, out, outlen, size, in_, inlen) };
    // SAFETY: the mark set above.
    if ret <= 0 && unsafe { ERR_count_to_mark() } == 0 {
        err::raise_with_text(
            ERR_LIB_EVP,
            EVP_R_PROVIDER_ASYM_CIPHER_FAILURE,
            f,
            &m.get().text(what),
        );
    }
    // SAFETY: the mark set above.
    unsafe { ERR_clear_last_mark() };
    ret
}

ffi_export! {
    /// Encrypts `inlen` octets at `in_` into `out` (its room in `*outlen`, the length back);
    /// with a NULL `out`, the size it needs. 1, or <= 0 with an error.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `out` is NULL or has room for `*outlen` octets;
    /// `outlen` is room for a size; `in_` holds `inlen` octets.
    pub unsafe extern "C" fn EVP_PKEY_encrypt(ctx: *mut EVP_PKEY_CTX, out: *mut u8, outlen: *mut usize, in_: *const u8, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { crypt(ctx, EVP_PKEY_OP_ENCRYPT, out, outlen, in_, inlen) }
    }
}

ffi_export! {
    /// Decrypts `inlen` octets at `in_` into `out`, as `EVP_PKEY_encrypt`.
    ///
    /// # Safety
    /// As for `EVP_PKEY_encrypt`.
    pub unsafe extern "C" fn EVP_PKEY_decrypt(ctx: *mut EVP_PKEY_CTX, out: *mut u8, outlen: *mut usize, in_: *const u8, inlen: usize) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { crypt(ctx, EVP_PKEY_OP_DECRYPT, out, outlen, in_, inlen) }
    }
}

/// Checks that an RSA key has no RSA data, which the `_old` functions then fail on quietly
/// (`evp_pkey_get0_RSA_int` gives NULL). An RSA key with data needs RSA (4.3).
fn require_no_rsa_data(k: &pkey::Pkey) {
    if k.is_provided() {
        // Its RSA form comes from the key manager's data, through RSA's ASN.1 method (4.3).
        crate::stub::unimplemented("the RSA form of a provided RSA key");
    }
}

ffi_export! {
    /// Encrypts `key_len` octets at `key` into `ek` with RSA PKCS#1 v1.5 padding: the length,
    /// or 0 with an error. Not an RSA key: 0 with `EVP_R_PUBLIC_KEY_NOT_RSA`.
    ///
    /// # Safety
    /// `pubk` is NULL or a live key; `ek` has room for the key's size; `key` holds `key_len`
    /// octets.
    pub unsafe extern "C" fn EVP_PKEY_encrypt_old(ek: *mut u8, key: *const u8, key_len: c_int, pubk: *mut EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let _ = (ek, key, key_len);
        // SAFETY: the caller's guarantee.
        let k = unsafe { pkey::pkey(pubk) };
        let Some(k) = k.filter(|k| k.type_() == EVP_PKEY_RSA) else {
            err::raise(ERR_LIB_EVP, EVP_R_PUBLIC_KEY_NOT_RSA, "EVP_PKEY_encrypt_old");
            return 0;
        };
        require_no_rsa_data(k);
        0
    }
}

ffi_export! {
    /// Decrypts `ekl` octets at `ek` into `key` with RSA PKCS#1 v1.5 padding: the length, or
    /// -1 with an error. Not an RSA key: -1 with `EVP_R_PUBLIC_KEY_NOT_RSA`.
    ///
    /// # Safety
    /// `priv_` is NULL or a live key; `key` has room for the key's size; `ek` holds `ekl`
    /// octets.
    pub unsafe extern "C" fn EVP_PKEY_decrypt_old(key: *mut u8, ek: *const u8, ekl: c_int, priv_: *mut EVP_PKEY) -> c_int
    where failure = -1, library = ERR_LIB_EVP
    {
        let _ = (key, ek, ekl);
        // SAFETY: the caller's guarantee.
        let k = unsafe { pkey::pkey(priv_) };
        let Some(k) = k.filter(|k| k.type_() == EVP_PKEY_RSA) else {
            err::raise(ERR_LIB_EVP, EVP_R_PUBLIC_KEY_NOT_RSA, "EVP_PKEY_decrypt_old");
            return -1;
        };
        require_no_rsa_data(k);
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: a NULL cipher is refused (the reference crashes).
    #[test]
    fn null_methods_are_refused() {
        let m: *mut EVP_ASYM_CIPHER = ptr::null_mut();
        // SAFETY: NULL is the case under test, here and below.
        assert_eq!(unsafe { EVP_ASYM_CIPHER_up_ref(m) }, 0);
        // SAFETY: as above.
        assert!(unsafe { EVP_ASYM_CIPHER_get0_name(m) }.is_null());
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_ASYM_CIPHER_is_a(m, c"RSA".as_ptr()) }, 0);
        // SAFETY: as above.
        let got = unsafe { EVP_ASYM_CIPHER_names_do_all(m, None, ptr::null_mut()) };
        assert_eq!(got, 0);
        // docs/DEVIATIONS.md: the old functions refuse a NULL key (the reference crashes).
        let mut buf = [0u8; 8];
        // SAFETY: as above; the buffer.
        let got =
            unsafe { EVP_PKEY_encrypt_old(buf.as_mut_ptr(), buf.as_ptr(), 1, ptr::null_mut()) };
        assert_eq!(got, 0);
        // SAFETY: as above.
        let got =
            unsafe { EVP_PKEY_decrypt_old(buf.as_mut_ptr(), buf.as_ptr(), 1, ptr::null_mut()) };
        assert_eq!(got, -1);
        crate::err::take_all();
    }
}
