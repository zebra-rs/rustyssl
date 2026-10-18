//! Reading keys from PEM (`PEM_read_bio_PrivateKey(3)`, `PEM_read_bio_PUBKEY`,
//! `PEM_read_bio_Parameters`, the type-specific readers; `pem_pkey.c`, `pem_all.c`,
//! `pem_pk8.c`): through the decoders from the BIO's current position (the first PEM block of
//! a supported kind that holds a key with the parts asked for), then through the legacy
//! reading (`PEM_bytes_read_bio` by name, then the key type's ASN.1 method) from the same
//! position; and the readers of single structures (`PEM_ASN1_read_bio` with their `d2i`).
//!
//! As in OpenSSL, the password callback (the default one for none) is asked through a cache, so
//! a key read in both ways asks once; a BIO that can't tell its position is read through a
//! read buffer. An encrypted key (a traditional DEK-Info one, or an EncryptedPrivateKeyInfo)
//! is decrypted with the password the callback gives.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    BIO, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_CTRL_EOF, DSA, EC_GROUP, EC_KEY, ERR_LIB_PEM,
    ERR_R_ASN1_LIB, ERR_R_UNSUPPORTED, ERR_REASON_MASK, ERR_SYSTEM_FLAG, EVP_CIPHER, EVP_PKEY,
    EVP_PKEY_KEY_PARAMETERS, EVP_PKEY_KEYPAIR, EVP_PKEY_PUBLIC_KEY, NETSCAPE_CERT_SEQUENCE,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, PEM_BUFSIZE,
    PEM_R_BAD_PASSWORD_READ, PEM_R_UNSUPPORTED_KEY_COMPONENTS, PEM_STRING_ACERT, PEM_STRING_DSA,
    PEM_STRING_ECPARAMETERS, PEM_STRING_ECPRIVATEKEY, PEM_STRING_EVP_PKEY, PEM_STRING_PARAMETERS,
    PEM_STRING_PKCS8, PEM_STRING_PKCS8INF, PEM_STRING_PUBLIC, PEM_STRING_RSA,
    PEM_STRING_RSA_PUBLIC, PEM_STRING_X509, PEM_STRING_X509_CRL, PEM_STRING_X509_REQ,
    PEM_STRING_X509_REQ_OLD, PEM_STRING_X509_TRUSTED, PKCS8_PRIV_KEY_INFO, RSA, X509, X509_ACERT,
    X509_CRL, X509_PUBKEY, X509_REQ, X509_SIG, pem_password_cb,
};

use crate::bio::{BIO_ctrl, BIO_free, BIO_new, BIO_pop, BIO_push};
use crate::decoder::ctx::{
    OSSL_DECODER_CTX_free, OSSL_DECODER_CTX_set_pem_password_cb, OSSL_DECODER_from_bio,
};
use crate::decoder::pkey::OSSL_DECODER_CTX_new_for_pkey;
use crate::err::{self, ERR_clear_last_mark, ERR_peek_error, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::pkey::{EVP_PKEY_free, EVP_PKEY_new, pkey};
use crate::ffi::ffi_export;
use crate::passphrase::{PwData, pw_pem_password};
use crate::pem_read::{
    PEM_ASN1_read, PEM_ASN1_read_bio, PEM_bytes_read_bio, PEM_bytes_read_bio_secmem,
};

type D2iOfVoid = unsafe extern "C" fn(*mut *mut c_void, *mut *const c_uchar, c_long) -> *mut c_void;

/// `BIO_tell`.
///
/// # Safety
/// `bp` is a live BIO.
unsafe fn tell(bp: *mut BIO) -> c_int {
    // SAFETY: the caller's guarantee.
    let r = unsafe { BIO_ctrl(bp, BIO_C_FILE_TELL, 0, ptr::null_mut()) };
    c_int::try_from(r).unwrap_or(-1)
}

/// The reason of the oldest error queued (`ERR_GET_REASON(ERR_peek_error())`).
fn oldest_reason() -> c_int {
    // SAFETY: no preconditions.
    let code: c_ulong = unsafe { ERR_peek_error() };
    if code & c_ulong::from(ERR_SYSTEM_FLAG) != 0 {
        return c_int::try_from(code & 0x7fff_ffff).unwrap_or(0);
    }
    c_int::try_from(code & c_ulong::from(ERR_REASON_MASK.cast_unsigned())).unwrap_or(0)
}

/// `pem_read_bio_key_decoder`: the first key the decoders find from the BIO's position that
/// has the parts the selection asks for (a private key's public part aside), moving past
/// blocks they don't support; NULL otherwise.
///
/// # Safety
/// `bp` is a live BIO; `x` is NULL or holds NULL or a live key; `cb` takes `u`.
unsafe fn read_decoder(
    bp: *mut BIO,
    x: *mut *mut EVP_PKEY,
    cb: pem_password_cb,
    u: *mut c_void,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    selection: c_int,
) -> *mut EVP_PKEY {
    // SAFETY: the caller's guarantee.
    let mut pos = unsafe { tell(bp) };
    if pos < 0 {
        return ptr::null_mut();
    }
    let mut pk: *mut EVP_PKEY = ptr::null_mut();
    // SAFETY: a local key pointer that outlives the context; a static input type; the caller's
    // library context and properties.
    let dctx = unsafe {
        OSSL_DECODER_CTX_new_for_pkey(
            &raw mut pk,
            c"PEM".as_ptr(),
            ptr::null(),
            ptr::null(),
            selection,
            libctx,
            propq,
        )
    };
    if dctx.is_null() {
        return ptr::null_mut();
    }
    let cb = cb.or(Some(crate::pem_cipher::PEM_def_callback));
    let done = |pk: *mut EVP_PKEY| {
        // SAFETY: made above, freed once.
        unsafe { OSSL_DECODER_CTX_free(dctx) };
        pk
    };
    // SAFETY: the context; the caller's callback and argument.
    if unsafe { OSSL_DECODER_CTX_set_pem_password_cb(dctx, cb, u) } == 0 {
        return done(pk);
    }
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    loop {
        // SAFETY: the context; the caller's BIO.
        if unsafe { OSSL_DECODER_from_bio(dctx, bp) } != 0 && !pk.is_null() {
            break;
        }
        // SAFETY: the caller's BIO.
        let eof = unsafe { BIO_ctrl(bp, BIO_CTRL_EOF, 0, ptr::null_mut()) } != 0;
        // SAFETY: as above.
        let newpos = if eof { -1 } else { unsafe { tell(bp) } };
        if eof || newpos < 0 || newpos <= pos {
            // SAFETY: the mark set above.
            unsafe { ERR_clear_last_mark() };
            return done(pk);
        }
        if oldest_reason() == ERR_R_UNSUPPORTED {
            // SAFETY: as above.
            unsafe { ERR_pop_to_mark() };
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
        } else {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            return done(pk);
        }
        pos = newpos;
    }
    // SAFETY: as above.
    unsafe { ERR_pop_to_mark() };
    let selection = if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        selection & !OSSL_KEYMGMT_SELECT_PUBLIC_KEY
    } else {
        selection
    };
    // SAFETY: the decoded key.
    if !unsafe { pkey(pk) }.is_some_and(|k| crate::evp::pkey::util_has(k, selection)) {
        // SAFETY: as above, freed once.
        unsafe { EVP_PKEY_free(pk) };
        err::raise(
            ERR_LIB_PEM,
            PEM_R_UNSUPPORTED_KEY_COMPONENTS,
            "pem_read_bio_key_decoder",
        );
        return done(ptr::null_mut());
    }
    if !x.is_null() {
        // SAFETY: the caller's guarantee.
        let old = unsafe { x.read() };
        // SAFETY: the caller's old key, or NULL.
        unsafe { EVP_PKEY_free(old) };
        // SAFETY: as above.
        unsafe { x.write(pk) };
    }
    done(pk)
}

/// Replaces `*x` (freed) with `ret` when `x` is given.
///
/// # Safety
/// `x` is NULL or holds NULL or a live key.
unsafe fn give(x: *mut *mut EVP_PKEY, ret: *mut EVP_PKEY) {
    if !x.is_null() {
        // SAFETY: the caller's guarantee.
        let old = unsafe { x.read() };
        // SAFETY: the caller's old key, or NULL.
        unsafe { EVP_PKEY_free(old) };
        // SAFETY: as above.
        unsafe { x.write(ret) };
    }
}

/// `pem_read_bio_key_legacy`: the first PEM block named for the selection (any private key,
/// else a public key, else parameters), decoded by its name: a PrivateKeyInfo, an encrypted
/// one, a type's traditional private key, a SubjectPublicKeyInfo, or a type's parameters.
///
/// # Safety
/// As for `read_decoder`.
unsafe fn read_legacy(
    bp: *mut BIO,
    x: *mut *mut EVP_PKEY,
    cb: pem_password_cb,
    u: *mut c_void,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    selection: c_int,
) -> *mut EVP_PKEY {
    const F: &str = "pem_read_bio_key_legacy";
    let (mut data, mut len, mut nm): (*mut c_uchar, c_long, *mut c_char) =
        (ptr::null_mut(), 0, ptr::null_mut());
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let read = if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY != 0 {
        // SAFETY: locals; the caller's BIO and callback.
        unsafe {
            PEM_bytes_read_bio_secmem(
                &raw mut data,
                &raw mut len,
                &raw mut nm,
                PEM_STRING_EVP_PKEY.as_ptr(),
                bp,
                cb,
                u,
            )
        }
    } else {
        let name = if selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0 {
            PEM_STRING_PUBLIC
        } else {
            PEM_STRING_PARAMETERS
        };
        // SAFETY: as above.
        unsafe {
            PEM_bytes_read_bio(
                &raw mut data,
                &raw mut len,
                &raw mut nm,
                name.as_ptr(),
                bp,
                cb,
                u,
            )
        }
    };
    if read == 0 {
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
        return ptr::null_mut();
    }
    // SAFETY: as above.
    unsafe { ERR_clear_last_mark() };
    // SAFETY: the block's name.
    let name = unsafe { CStr::from_ptr(nm) }.to_bytes();
    let mut p = data.cast_const();
    let mut ret: *mut EVP_PKEY = ptr::null_mut();
    let mut raise_asn1 = true;
    if name == PEM_STRING_PKCS8INF.to_bytes() {
        // SAFETY: the block's octets.
        let p8 =
            unsafe { crate::x509::p8::d2i_PKCS8_PRIV_KEY_INFO(ptr::null_mut(), &raw mut p, len) };
        if !p8.is_null() {
            // SAFETY: the structure; the caller's library context and properties.
            ret = unsafe { crate::evp::pkey::d2i::pkcs82pkey_legacy(p8, libctx, propq) };
            // SAFETY: the caller's guarantee.
            unsafe { give(x, ret) };
            // SAFETY: decoded above, freed once.
            unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8) };
        }
    } else if name == PEM_STRING_PKCS8.to_bytes() {
        // SAFETY: the block's octets.
        let p8 = unsafe { crate::x509::sig::d2i_X509_SIG(ptr::null_mut(), &raw mut p, len) };
        if !p8.is_null() {
            let mut psbuf = rustyssl_crypto::bn::Zeroizing::new(
                [0 as c_char; PEM_BUFSIZE.unsigned_abs() as usize],
            );
            let klen = match cb {
                // SAFETY: the caller's callback with room for a passphrase.
                Some(cb) => unsafe { cb(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u) },
                // SAFETY: as above.
                None => unsafe {
                    crate::pem_cipher::PEM_def_callback(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u)
                },
            };
            if klen < 0 {
                err::raise(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, F);
                // SAFETY: decoded above, freed once.
                unsafe { crate::x509::sig::X509_SIG_free(p8) };
                raise_asn1 = false;
            } else {
                // SAFETY: the structure; the passphrase's `klen` octets.
                let p8inf = unsafe { crate::pkcs8_crypt::PKCS8_decrypt(p8, psbuf.as_ptr(), klen) };
                // SAFETY: decoded above, freed once.
                unsafe { crate::x509::sig::X509_SIG_free(p8) };
                if !p8inf.is_null() {
                    // SAFETY: the decrypted structure; the caller's library context and
                    // properties.
                    ret = unsafe { crate::evp::pkey::d2i::pkcs82pkey_legacy(p8inf, libctx, propq) };
                    // SAFETY: the caller's guarantee.
                    unsafe { give(x, ret) };
                    // SAFETY: decrypted above, freed once.
                    unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8inf) };
                }
            }
        }
    } else if let Some(stem) = crate::pem_read::check_suffix(name, b"PRIVATE KEY") {
        let method = crate::evp::pkey::ameth::find_str(stem);
        if let Some(m) = method.filter(|m| m.get().funcs().old_priv_decode.is_some()) {
            let id = m.get().pkey_id;
            // SAFETY: the caller's key pointer; the block's octets.
            ret = unsafe {
                crate::evp::pkey::d2i::private_legacy(id, x, &raw mut p, len, libctx, propq)
            };
        }
    } else if selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY == 0
        && selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY != 0
    {
        // SAFETY: as above.
        ret = unsafe {
            crate::x509::pubkey::d2i_pubkey_int(
                x,
                &raw mut p,
                len,
                ptr::null_mut(),
                ptr::null(),
                true,
            )
        };
    } else if selection & EVP_PKEY_KEYPAIR == 0
        && let Some(stem) = crate::pem_read::check_suffix(name, b"PARAMETERS")
    {
        // SAFETY: no preconditions.
        let pk = unsafe { EVP_PKEY_new() };
        let slen = c_int::try_from(stem.len()).unwrap_or(0);
        // SAFETY: the new key; the block's name.
        let typed =
            !pk.is_null() && unsafe { crate::evp::pkey::EVP_PKEY_set_type_str(pk, nm, slen) } != 0;
        let decode = if typed {
            // SAFETY: as above.
            unsafe { pkey(pk) }
                .and_then(|k| k.ameth_funcs())
                .and_then(|f| f.param_decode)
        } else {
            None
        };
        let lenc = c_int::try_from(len).unwrap_or(c_int::MAX);
        // SAFETY: the method's function with the new key and the block's octets.
        if decode.is_some_and(|d| unsafe { d(pk, &raw mut p, lenc) } != 0) {
            ret = pk;
            // SAFETY: the caller's guarantee.
            unsafe { give(x, ret) };
        } else {
            // SAFETY: made above, or NULL.
            unsafe { EVP_PKEY_free(pk) };
        }
        raise_asn1 = false;
    }
    // SAFETY: no preconditions.
    if raise_asn1 && ret.is_null() && unsafe { err::ERR_peek_last_error() } == 0 {
        err::raise(ERR_LIB_PEM, ERR_R_ASN1_LIB, F);
    }
    // SAFETY: the block's name, from either allocator (the secure free hands others back).
    unsafe { crate::secure::CRYPTO_secure_free(nm.cast(), ptr::null(), 0) };
    // SAFETY: as above, `len` octets.
    unsafe {
        crate::secure::CRYPTO_secure_clear_free(
            data.cast(),
            usize::try_from(len).unwrap_or(0),
            ptr::null(),
            0,
        )
    };
    ret
}

/// `pem_read_bio_key`: the decoders' reading, else the legacy reading from the same position,
/// with the password callback asked through a cache (and a read buffer under a BIO that can't
/// tell its position).
///
/// # Safety
/// As for `read_decoder`.
unsafe fn read_key(
    bp: *mut BIO,
    x: *mut *mut EVP_PKEY,
    cb: pem_password_cb,
    u: *mut c_void,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
    selection: c_int,
) -> *mut EVP_PKEY {
    let mut bp = bp;
    let mut new_bio: *mut BIO = ptr::null_mut();
    // SAFETY: the caller's guarantee.
    let mut pos = unsafe { tell(bp) };
    if pos < 0 {
        // SAFETY: no preconditions.
        let method = unsafe { crate::bio::buffer::BIO_f_readbuffer() };
        // SAFETY: a BIO method.
        new_bio = unsafe { BIO_new(method) };
        if new_bio.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the new filter over the caller's BIO.
        bp = unsafe { BIO_push(new_bio, bp) };
        // SAFETY: the chain.
        pos = unsafe { tell(bp) };
    }
    let cb = cb.or(Some(crate::pem_cipher::PEM_def_callback));
    let mut pw = PwData::default();
    let mut ret = ptr::null_mut();
    if pw.set_pem_password_cb(cb, u) {
        pw.enable_caching();
        let pwp: *mut c_void = (&raw mut pw).cast();
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        // SAFETY: the BIO; the caller's key pointer; the passphrase data, live for the call.
        ret = unsafe { read_decoder(bp, x, Some(pw_pem_password), pwp, libctx, propq, selection) };
        if ret.is_null() {
            // SAFETY: as above.
            let seek = unsafe { BIO_ctrl(bp, BIO_C_FILE_SEEK, c_long::from(pos), ptr::null_mut()) };
            if seek >= 0 {
                // SAFETY: as above.
                ret = unsafe {
                    read_legacy(bp, x, Some(pw_pem_password), pwp, libctx, propq, selection)
                };
            }
        }
        if ret.is_null() {
            // SAFETY: the mark set above.
            unsafe { ERR_clear_last_mark() };
        } else {
            // SAFETY: as above.
            unsafe { ERR_pop_to_mark() };
        }
    }
    pw.clear();
    if !new_bio.is_null() {
        // SAFETY: the filter pushed above, taken off the caller's BIO and freed.
        unsafe { BIO_pop(new_bio) };
        // SAFETY: as above.
        unsafe { BIO_free(new_bio) };
    }
    ret
}

/// A file BIO over `fp` for `f`, or NULL with `ERR_R_BUF_LIB`.
///
/// # Safety
/// `fp` is an open `FILE`.
unsafe fn with_fp<T>(fp: *mut FILE, func: &str, f: impl FnOnce(*mut BIO) -> *mut T) -> *mut T {
    // SAFETY: the caller's guarantee.
    let b = unsafe { crate::pem::file_bio(fp, func) };
    if b.is_null() {
        return ptr::null_mut();
    }
    let ret = f(b);
    // SAFETY: made above.
    unsafe { BIO_free(b) };
    ret
}

ffi_export! {
    /// Reads a public key from PEM (through the decoders, else a SubjectPublicKeyInfo block) in
    /// a library context, replacing `*x`. NULL on failure.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or holds NULL or a live key; `cb` takes `u`; `libctx` is
    /// NULL or a live library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn PEM_read_bio_PUBKEY_ex(bp: *mut BIO, x: *mut *mut EVP_PKEY, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_key(bp, x, cb, u, libctx, propq, EVP_PKEY_PUBLIC_KEY) }
    }
}

ffi_export! {
    /// `PEM_read_bio_PUBKEY_ex` in the default library context.
    ///
    /// # Safety
    /// As for `PEM_read_bio_PUBKEY_ex`.
    pub unsafe extern "C" fn PEM_read_bio_PUBKEY(bp: *mut BIO, x: *mut *mut EVP_PKEY, cb: pem_password_cb, u: *mut c_void) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_key(bp, x, cb, u, ptr::null_mut(), ptr::null(), EVP_PKEY_PUBLIC_KEY) }
    }
}

ffi_export! {
    /// `PEM_read_bio_PUBKEY_ex` from a `FILE`.
    ///
    /// # Safety
    /// As for `PEM_read_bio_PUBKEY_ex`, with `fp` an open `FILE`.
    pub unsafe extern "C" fn PEM_read_PUBKEY_ex(fp: *mut FILE, x: *mut *mut EVP_PKEY, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        let f = |b| {
            // SAFETY: the file's BIO; the caller's guarantee.
            unsafe { read_key(b, x, cb, u, libctx, propq, EVP_PKEY_PUBLIC_KEY) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "PEM_read_PUBKEY_ex", f) }
    }
}

ffi_export! {
    /// `PEM_read_PUBKEY_ex` in the default library context.
    ///
    /// # Safety
    /// As for `PEM_read_PUBKEY_ex`.
    pub unsafe extern "C" fn PEM_read_PUBKEY(fp: *mut FILE, x: *mut *mut EVP_PKEY, cb: pem_password_cb, u: *mut c_void) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { PEM_read_PUBKEY_ex(fp, x, cb, u, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Reads a private key from PEM (through the decoders, else a PKCS#8 or a type's
    /// traditional block) in a library context, replacing `*x`. NULL on failure.
    ///
    /// # Safety
    /// As for `PEM_read_bio_PUBKEY_ex`.
    pub unsafe extern "C" fn PEM_read_bio_PrivateKey_ex(bp: *mut BIO, x: *mut *mut EVP_PKEY, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_key(bp, x, cb, u, libctx, propq, EVP_PKEY_KEYPAIR) }
    }
}

ffi_export! {
    /// `PEM_read_bio_PrivateKey_ex` in the default library context.
    ///
    /// # Safety
    /// As for `PEM_read_bio_PrivateKey_ex`.
    pub unsafe extern "C" fn PEM_read_bio_PrivateKey(bp: *mut BIO, x: *mut *mut EVP_PKEY, cb: pem_password_cb, u: *mut c_void) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_key(bp, x, cb, u, ptr::null_mut(), ptr::null(), EVP_PKEY_KEYPAIR) }
    }
}

ffi_export! {
    /// `PEM_read_bio_PrivateKey_ex` from a `FILE`.
    ///
    /// # Safety
    /// As for `PEM_read_bio_PrivateKey_ex`, with `fp` an open `FILE`.
    pub unsafe extern "C" fn PEM_read_PrivateKey_ex(fp: *mut FILE, x: *mut *mut EVP_PKEY, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        let f = |b| {
            // SAFETY: the file's BIO; the caller's guarantee.
            unsafe { read_key(b, x, cb, u, libctx, propq, EVP_PKEY_KEYPAIR) }
        };
        // SAFETY: the caller's guarantee.
        unsafe { with_fp(fp, "PEM_read_PrivateKey_ex", f) }
    }
}

ffi_export! {
    /// `PEM_read_PrivateKey_ex` in the default library context.
    ///
    /// # Safety
    /// As for `PEM_read_PrivateKey_ex`.
    pub unsafe extern "C" fn PEM_read_PrivateKey(fp: *mut FILE, x: *mut *mut EVP_PKEY, cb: pem_password_cb, u: *mut c_void) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { PEM_read_PrivateKey_ex(fp, x, cb, u, ptr::null_mut(), ptr::null()) }
    }
}

/// `no_password_cb`: refuses (parameters are never encrypted).
unsafe extern "C" fn no_password_cb(
    _buf: *mut c_char,
    _num: c_int,
    _rwflag: c_int,
    _u: *mut c_void,
) -> c_int {
    -1
}

ffi_export! {
    /// Reads a key's parameters from PEM (through the decoders, else a type's PARAMETERS
    /// block) in a library context, replacing `*x`. NULL on failure.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or holds NULL or a live key; `libctx` is NULL or a live
    /// library context; `propq` is NULL or a string.
    pub unsafe extern "C" fn PEM_read_bio_Parameters_ex(bp: *mut BIO, x: *mut *mut EVP_PKEY, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { read_key(bp, x, Some(no_password_cb), ptr::null_mut(), libctx, propq, EVP_PKEY_KEY_PARAMETERS) }
    }
}

ffi_export! {
    /// `PEM_read_bio_Parameters_ex` in the default library context.
    ///
    /// # Safety
    /// As for `PEM_read_bio_Parameters_ex`.
    pub unsafe extern "C" fn PEM_read_bio_Parameters(bp: *mut BIO, x: *mut *mut EVP_PKEY) -> *mut EVP_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { PEM_read_bio_Parameters_ex(bp, x, ptr::null_mut(), ptr::null()) }
    }
}

/// A typed key from a key read (`pkey_get_rsa` and the others): `get1` of it, replacing `*out`
/// (freed with `free`); the key freed. NULL when there's none or it's another type.
///
/// # Safety
/// `pk` is NULL or a key the caller gives up; `out` is NULL or holds NULL or a live key.
unsafe fn typed<T>(
    pk: *mut EVP_PKEY,
    out: *mut *mut T,
    get1: unsafe extern "C" fn(*mut EVP_PKEY) -> *mut T,
    free: unsafe extern "C" fn(*mut T),
) -> *mut T {
    if pk.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the caller's key.
    let t = unsafe { get1(pk) };
    // SAFETY: as above, given up.
    unsafe { EVP_PKEY_free(pk) };
    if t.is_null() {
        return ptr::null_mut();
    }
    if !out.is_null() {
        // SAFETY: the caller's guarantee.
        let old = unsafe { out.read() };
        // SAFETY: the caller's old key, or NULL.
        unsafe { free(old) };
        // SAFETY: as above.
        unsafe { out.write(t) };
    }
    t
}

/// The type-specific private key readers over `PEM_read_bio_PrivateKey`.
macro_rules! typed_private {
    (
        $ty:ty, $get1:path, $free:path;
        pub unsafe extern "C" fn $bio:ident();
        pub unsafe extern "C" fn $fp:ident();
    ) => {
        ffi_export! {
            /// Reads a private key of the type from PEM, replacing `*x`; NULL for none or another
            /// type.
            ///
            /// # Safety
            /// `bp` is a live BIO; `x` is NULL or holds NULL or a live key; `cb` takes `u`.
            pub unsafe extern "C" fn $bio(bp: *mut BIO, x: *mut *mut $ty, cb: pem_password_cb, u: *mut c_void) -> *mut $ty
            where failure = ptr::null_mut(), library = ERR_LIB_PEM
            {
                // SAFETY: the caller's guarantee.
                let pk = unsafe { read_key(bp, ptr::null_mut(), cb, u, ptr::null_mut(), ptr::null(), EVP_PKEY_KEYPAIR) };
                // SAFETY: the key read, given up; the caller's pointer.
                unsafe { typed(pk, x, $get1, $free) }
            }
        }

        ffi_export! {
            /// The reader from a `FILE`.
            ///
            /// # Safety
            /// As for the BIO reader, with `fp` an open `FILE`.
            pub unsafe extern "C" fn $fp(fp: *mut FILE, x: *mut *mut $ty, cb: pem_password_cb, u: *mut c_void) -> *mut $ty
            where failure = ptr::null_mut(), library = ERR_LIB_PEM
            {
                // SAFETY: the caller's guarantee.
                let pk = unsafe { PEM_read_PrivateKey(fp, ptr::null_mut(), cb, u) };
                // SAFETY: the key read, given up; the caller's pointer.
                unsafe { typed(pk, x, $get1, $free) }
            }
        }
    };
}

typed_private! {
    RSA, crate::evp::pkey::rsa::EVP_PKEY_get1_RSA, crate::rsa_lib::RSA_free;
    pub unsafe extern "C" fn PEM_read_bio_RSAPrivateKey();
    pub unsafe extern "C" fn PEM_read_RSAPrivateKey();
}

typed_private! {
    DSA, crate::evp::pkey::dsa::EVP_PKEY_get1_DSA, crate::dsa::DSA_free;
    pub unsafe extern "C" fn PEM_read_bio_DSAPrivateKey();
    pub unsafe extern "C" fn PEM_read_DSAPrivateKey();
}

typed_private! {
    EC_KEY, crate::evp::pkey::ec::EVP_PKEY_get1_EC_KEY, crate::ec::key::EC_KEY_free;
    pub unsafe extern "C" fn PEM_read_bio_ECPrivateKey();
    pub unsafe extern "C" fn PEM_read_ECPrivateKey();
}

/// Single-structure PEM readers (`IMPLEMENT_PEM_read`): `PEM_ASN1_read_bio` and
/// `PEM_ASN1_read` with the structure's `d2i` and PEM name.
macro_rules! pem_read {
    (
        $ty:ty, $d2i:path, $name:expr, $void:ident;
        pub unsafe extern "C" fn $bio:ident();
        pub unsafe extern "C" fn $fp:ident();
    ) => {
        /// The structure's `d2i` as a `d2i_of_void`.
        unsafe extern "C" fn $void(a: *mut *mut c_void, pp: *mut *const c_uchar, len: c_long) -> *mut c_void {
            // SAFETY: the caller's guarantee.
            unsafe { $d2i(a.cast(), pp, len) }.cast()
        }

        ffi_export! {
            /// Reads the structure from the first PEM block of its name, into `*x` if given.
            ///
            /// # Safety
            /// `bp` is a live BIO; `x` is NULL or holds NULL or a live value; `cb` takes `u`.
            pub unsafe extern "C" fn $bio(bp: *mut BIO, x: *mut *mut $ty, cb: pem_password_cb, u: *mut c_void) -> *mut $ty
            where failure = ptr::null_mut(), library = ERR_LIB_PEM
            {
                let f: D2iOfVoid = $void;
                // SAFETY: the caller's guarantee.
                unsafe { PEM_ASN1_read_bio(Some(f), $name.as_ptr(), bp, x.cast(), cb, u) }.cast()
            }
        }

        ffi_export! {
            /// The reader from a `FILE`.
            ///
            /// # Safety
            /// As for the BIO reader, with `fp` an open `FILE`.
            pub unsafe extern "C" fn $fp(fp: *mut FILE, x: *mut *mut $ty, cb: pem_password_cb, u: *mut c_void) -> *mut $ty
            where failure = ptr::null_mut(), library = ERR_LIB_PEM
            {
                let f: D2iOfVoid = $void;
                // SAFETY: the caller's guarantee.
                unsafe { PEM_ASN1_read(Some(f), $name.as_ptr(), fp, x.cast(), cb, u) }.cast()
            }
        }
    };
}

pem_read! {
    RSA, crate::rsa_asn1::d2i_RSAPublicKey, PEM_STRING_RSA_PUBLIC, d2i_rsa_public_void;
    pub unsafe extern "C" fn PEM_read_bio_RSAPublicKey();
    pub unsafe extern "C" fn PEM_read_RSAPublicKey();
}

pem_read! {
    RSA, crate::x509::pubkey::d2i_RSA_PUBKEY, PEM_STRING_PUBLIC, d2i_rsa_pubkey_void;
    pub unsafe extern "C" fn PEM_read_bio_RSA_PUBKEY();
    pub unsafe extern "C" fn PEM_read_RSA_PUBKEY();
}

pem_read! {
    DSA, crate::x509::pubkey::d2i_DSA_PUBKEY, PEM_STRING_PUBLIC, d2i_dsa_pubkey_void;
    pub unsafe extern "C" fn PEM_read_bio_DSA_PUBKEY();
    pub unsafe extern "C" fn PEM_read_DSA_PUBKEY();
}

pem_read! {
    EC_KEY, crate::x509::pubkey::d2i_EC_PUBKEY, PEM_STRING_PUBLIC, d2i_ec_pubkey_void;
    pub unsafe extern "C" fn PEM_read_bio_EC_PUBKEY();
    pub unsafe extern "C" fn PEM_read_EC_PUBKEY();
}

pem_read! {
    EC_GROUP, crate::ec::asn1::d2i_ECPKParameters, PEM_STRING_ECPARAMETERS, d2i_ecpk_void;
    pub unsafe extern "C" fn PEM_read_bio_ECPKParameters();
    pub unsafe extern "C" fn PEM_read_ECPKParameters();
}

pem_read! {
    X509_PUBKEY, crate::x509::pubkey::d2i_X509_PUBKEY, PEM_STRING_PUBLIC, d2i_x509_pubkey_void;
    pub unsafe extern "C" fn PEM_read_bio_X509_PUBKEY();
    pub unsafe extern "C" fn PEM_read_X509_PUBKEY();
}

pem_read! {
    X509_SIG, crate::x509::sig::d2i_X509_SIG, PEM_STRING_PKCS8, d2i_x509_sig_void;
    pub unsafe extern "C" fn PEM_read_bio_PKCS8();
    pub unsafe extern "C" fn PEM_read_PKCS8();
}

pem_read! {
    PKCS8_PRIV_KEY_INFO, crate::x509::p8::d2i_PKCS8_PRIV_KEY_INFO, PEM_STRING_PKCS8INF, d2i_p8inf_void;
    pub unsafe extern "C" fn PEM_read_bio_PKCS8_PRIV_KEY_INFO();
    pub unsafe extern "C" fn PEM_read_PKCS8_PRIV_KEY_INFO();
}

pem_read! {
    X509, crate::x509::cert::d2i_X509, PEM_STRING_X509, d2i_x509_void;
    pub unsafe extern "C" fn PEM_read_bio_X509();
    pub unsafe extern "C" fn PEM_read_X509();
}

pem_read! {
    X509, crate::x509::cert::d2i_X509_AUX, PEM_STRING_X509_TRUSTED, d2i_x509_aux_void;
    pub unsafe extern "C" fn PEM_read_bio_X509_AUX();
    pub unsafe extern "C" fn PEM_read_X509_AUX();
}

pem_read! {
    X509_ACERT, crate::x509::acert::d2i_X509_ACERT, PEM_STRING_ACERT, d2i_acert_void;
    pub unsafe extern "C" fn PEM_read_bio_X509_ACERT();
    pub unsafe extern "C" fn PEM_read_X509_ACERT();
}

pem_read! {
    NETSCAPE_CERT_SEQUENCE, crate::x509::spki::d2i_NETSCAPE_CERT_SEQUENCE, PEM_STRING_X509, d2i_nsseq_void;
    pub unsafe extern "C" fn PEM_read_bio_NETSCAPE_CERT_SEQUENCE();
    pub unsafe extern "C" fn PEM_read_NETSCAPE_CERT_SEQUENCE();
}

pem_read! {
    X509_CRL, crate::x509::crl::d2i_X509_CRL, PEM_STRING_X509_CRL, d2i_x509_crl_void;
    pub unsafe extern "C" fn PEM_read_bio_X509_CRL();
    pub unsafe extern "C" fn PEM_read_X509_CRL();
}

pem_read! {
    rustyssl_abi::PKCS7, crate::pkcs7::d2i_PKCS7, rustyssl_abi::PEM_STRING_PKCS7, d2i_pkcs7_void;
    pub unsafe extern "C" fn PEM_read_bio_PKCS7();
    pub unsafe extern "C" fn PEM_read_PKCS7();
}

pem_read! {
    rustyssl_abi::CMS_ContentInfo, crate::cms::base::d2i_CMS_ContentInfo, rustyssl_abi::PEM_STRING_CMS, d2i_cms_void;
    pub unsafe extern "C" fn PEM_read_bio_CMS();
    pub unsafe extern "C" fn PEM_read_CMS();
}

pem_read! {
    X509_REQ, crate::x509::req::d2i_X509_REQ, PEM_STRING_X509_REQ, d2i_x509_req_void;
    pub unsafe extern "C" fn PEM_read_bio_X509_REQ();
    pub unsafe extern "C" fn PEM_read_X509_REQ();
}

type I2dOfVoid = unsafe extern "C" fn(*const c_void, *mut *mut c_uchar) -> c_int;

/// Single-structure PEM writers (`IMPLEMENT_PEM_write`, unencrypted): `PEM_ASN1_write_bio`
/// and `PEM_ASN1_write` with the structure's `i2d` and PEM name.
macro_rules! pem_write {
    (
        $ty:ty, $i2d:path, $name:expr, $void:ident;
        pub unsafe extern "C" fn $bio:ident();
        pub unsafe extern "C" fn $fp:ident();
    ) => {
        /// The structure's `i2d` as an `i2d_of_void`.
        unsafe extern "C" fn $void(x: *const c_void, pp: *mut *mut c_uchar) -> c_int {
            // SAFETY: the caller's guarantee.
            unsafe { $i2d(x.cast_mut().cast(), pp) }
        }

        ffi_export! {
            /// Writes the structure as a PEM block of its name. 1, or 0.
            ///
            /// # Safety
            /// `bp` is a live BIO; `x` is a live value.
            pub unsafe extern "C" fn $bio(bp: *mut BIO, x: *const $ty) -> c_int
            where failure = 0, library = ERR_LIB_PEM
            {
                let f: I2dOfVoid = $void;
                // SAFETY: the caller's guarantee; no encryption.
                unsafe { crate::pem_cipher::PEM_ASN1_write_bio(Some(f), $name.as_ptr(), bp, x.cast(), ptr::null(), ptr::null(), 0, None, ptr::null_mut()) }
            }
        }

        ffi_export! {
            /// The writer to a `FILE`.
            ///
            /// # Safety
            /// `fp` is an open `FILE`; `x` is a live value.
            pub unsafe extern "C" fn $fp(fp: *mut FILE, x: *const $ty) -> c_int
            where failure = 0, library = ERR_LIB_PEM
            {
                let f: I2dOfVoid = $void;
                // SAFETY: the caller's guarantee; no encryption.
                unsafe { crate::pem_cipher::PEM_ASN1_write(Some(f), $name.as_ptr(), fp, x.cast(), ptr::null(), ptr::null(), 0, None, ptr::null_mut()) }
            }
        }
    };
}

pem_write! {
    X509_PUBKEY, crate::x509::pubkey::i2d_X509_PUBKEY, PEM_STRING_PUBLIC, i2d_x509_pubkey_void;
    pub unsafe extern "C" fn PEM_write_bio_X509_PUBKEY();
    pub unsafe extern "C" fn PEM_write_X509_PUBKEY();
}

pem_write! {
    X509_SIG, crate::x509::sig::i2d_X509_SIG, PEM_STRING_PKCS8, i2d_x509_sig_void;
    pub unsafe extern "C" fn PEM_write_bio_PKCS8();
    pub unsafe extern "C" fn PEM_write_PKCS8();
}

pem_write! {
    PKCS8_PRIV_KEY_INFO, crate::x509::p8::i2d_PKCS8_PRIV_KEY_INFO, PEM_STRING_PKCS8INF, i2d_p8inf_void;
    pub unsafe extern "C" fn PEM_write_bio_PKCS8_PRIV_KEY_INFO();
    pub unsafe extern "C" fn PEM_write_PKCS8_PRIV_KEY_INFO();
}

pem_write! {
    X509, crate::x509::cert::i2d_X509, PEM_STRING_X509, i2d_x509_void;
    pub unsafe extern "C" fn PEM_write_bio_X509();
    pub unsafe extern "C" fn PEM_write_X509();
}

pem_write! {
    X509, crate::x509::cert::i2d_X509_AUX, PEM_STRING_X509_TRUSTED, i2d_x509_aux_void;
    pub unsafe extern "C" fn PEM_write_bio_X509_AUX();
    pub unsafe extern "C" fn PEM_write_X509_AUX();
}

pem_write! {
    X509_ACERT, crate::x509::acert::i2d_X509_ACERT, PEM_STRING_ACERT, i2d_acert_void;
    pub unsafe extern "C" fn PEM_write_bio_X509_ACERT();
    pub unsafe extern "C" fn PEM_write_X509_ACERT();
}

pem_write! {
    NETSCAPE_CERT_SEQUENCE, crate::x509::spki::i2d_NETSCAPE_CERT_SEQUENCE, PEM_STRING_X509, i2d_nsseq_void;
    pub unsafe extern "C" fn PEM_write_bio_NETSCAPE_CERT_SEQUENCE();
    pub unsafe extern "C" fn PEM_write_NETSCAPE_CERT_SEQUENCE();
}

pem_write! {
    X509_CRL, crate::x509::crl::i2d_X509_CRL, PEM_STRING_X509_CRL, i2d_x509_crl_void;
    pub unsafe extern "C" fn PEM_write_bio_X509_CRL();
    pub unsafe extern "C" fn PEM_write_X509_CRL();
}

pem_write! {
    rustyssl_abi::PKCS7, crate::pkcs7::i2d_PKCS7, rustyssl_abi::PEM_STRING_PKCS7, i2d_pkcs7_void;
    pub unsafe extern "C" fn PEM_write_bio_PKCS7();
    pub unsafe extern "C" fn PEM_write_PKCS7();
}

pem_write! {
    rustyssl_abi::CMS_ContentInfo, crate::cms::base::i2d_CMS_ContentInfo, rustyssl_abi::PEM_STRING_CMS, i2d_cms_void;
    pub unsafe extern "C" fn PEM_write_bio_CMS();
    pub unsafe extern "C" fn PEM_write_CMS();
}

pem_write! {
    X509_REQ, crate::x509::req::i2d_X509_REQ, PEM_STRING_X509_REQ, i2d_x509_req_void;
    pub unsafe extern "C" fn PEM_write_bio_X509_REQ();
    pub unsafe extern "C" fn PEM_write_X509_REQ();
}

pem_write! {
    X509_REQ, crate::x509::req::i2d_X509_REQ, PEM_STRING_X509_REQ_OLD, i2d_x509_req_new_void;
    pub unsafe extern "C" fn PEM_write_bio_X509_REQ_NEW();
    pub unsafe extern "C" fn PEM_write_X509_REQ_NEW();
}

/// The type-specific writers that may encrypt (`IMPLEMENT_PEM_write_cb`): the structure's
/// `i2d` through `PEM_ASN1_write_bio` with the cipher, passphrase, and callback.
macro_rules! pem_write_cb {
    (
        $ty:ty, $i2d:path, $name:expr, $void:ident;
        pub unsafe extern "C" fn $bio:ident();
        pub unsafe extern "C" fn $fp:ident();
    ) => {
        /// The structure's `i2d` as an `i2d_of_void`.
        unsafe extern "C" fn $void(x: *const c_void, pp: *mut *mut c_uchar) -> c_int {
            // SAFETY: the caller's guarantee.
            unsafe { $i2d(x.cast_mut().cast(), pp) }
        }

        ffi_export! {
            /// Writes the structure as a PEM block of its name, encrypted with `enc` (and the
            /// passphrase `kstr`, else asked of `cb`) if given. 1, or 0.
            ///
            /// # Safety
            /// `bp` is a live BIO; `x` is a live value; `enc` is NULL or a cipher; `kstr` is NULL
            /// or `klen` octets; `cb` is NULL or a password callback taking `u`.
            pub unsafe extern "C" fn $bio(bp: *mut BIO, x: *const $ty, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, cb: pem_password_cb, u: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_PEM
            {
                let f: I2dOfVoid = $void;
                // SAFETY: the caller's guarantee.
                unsafe { crate::pem_cipher::PEM_ASN1_write_bio(Some(f), $name.as_ptr(), bp, x.cast(), enc, kstr, klen, cb, u) }
            }
        }

        ffi_export! {
            /// The writer to a `FILE`.
            ///
            /// # Safety
            /// `fp` is an open `FILE`; otherwise as for the BIO writer.
            pub unsafe extern "C" fn $fp(fp: *mut FILE, x: *const $ty, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, cb: pem_password_cb, u: *mut c_void) -> c_int
            where failure = 0, library = ERR_LIB_PEM
            {
                let f: I2dOfVoid = $void;
                // SAFETY: the caller's guarantee.
                unsafe { crate::pem_cipher::PEM_ASN1_write(Some(f), $name.as_ptr(), fp, x.cast(), enc, kstr, klen, cb, u) }
            }
        }
    };
}

pem_write_cb! {
    RSA, crate::rsa_asn1::i2d_RSAPrivateKey, PEM_STRING_RSA, i2d_rsa_private_void;
    pub unsafe extern "C" fn PEM_write_bio_RSAPrivateKey();
    pub unsafe extern "C" fn PEM_write_RSAPrivateKey();
}

pem_write! {
    RSA, crate::rsa_asn1::i2d_RSAPublicKey, PEM_STRING_RSA_PUBLIC, i2d_rsa_public_void;
    pub unsafe extern "C" fn PEM_write_bio_RSAPublicKey();
    pub unsafe extern "C" fn PEM_write_RSAPublicKey();
}

pem_write! {
    RSA, crate::x509::pubkey::i2d_RSA_PUBKEY, PEM_STRING_PUBLIC, i2d_rsa_pubkey_void;
    pub unsafe extern "C" fn PEM_write_bio_RSA_PUBKEY();
    pub unsafe extern "C" fn PEM_write_RSA_PUBKEY();
}

pem_write_cb! {
    DSA, crate::dsa_asn1::i2d_DSAPrivateKey, PEM_STRING_DSA, i2d_dsa_private_void;
    pub unsafe extern "C" fn PEM_write_bio_DSAPrivateKey();
    pub unsafe extern "C" fn PEM_write_DSAPrivateKey();
}

pem_write! {
    DSA, crate::x509::pubkey::i2d_DSA_PUBKEY, PEM_STRING_PUBLIC, i2d_dsa_pubkey_void;
    pub unsafe extern "C" fn PEM_write_bio_DSA_PUBKEY();
    pub unsafe extern "C" fn PEM_write_DSA_PUBKEY();
}

pem_write! {
    EC_GROUP, crate::ec::asn1::i2d_ECPKParameters, PEM_STRING_ECPARAMETERS, i2d_ecpkparameters_void;
    pub unsafe extern "C" fn PEM_write_bio_ECPKParameters();
    pub unsafe extern "C" fn PEM_write_ECPKParameters();
}

pem_write_cb! {
    EC_KEY, crate::ec::key_asn1::i2d_ECPrivateKey, PEM_STRING_ECPRIVATEKEY, i2d_ec_private_void;
    pub unsafe extern "C" fn PEM_write_bio_ECPrivateKey();
    pub unsafe extern "C" fn PEM_write_ECPrivateKey();
}

pem_write! {
    EC_KEY, crate::x509::pubkey::i2d_EC_PUBKEY, PEM_STRING_PUBLIC, i2d_ec_pubkey_void;
    pub unsafe extern "C" fn PEM_write_bio_EC_PUBKEY();
    pub unsafe extern "C" fn PEM_write_EC_PUBKEY();
}

// The key writers (`pem_pkey.c`, `pem_pk8.c`, and `pem_all.c`'s PUBKEY): a provided key through
// the PEM encoders (`IMPLEMENT_PEM_provided_write_body_*`), a legacy one through its ASN.1
// method.

/// Where a key writer writes: a BIO, or a `FILE` (`OSSL_ENCODER_to_bio` or `_to_fp`, and
/// `PEM_ASN1_write_bio` or `PEM_ASN1_write`).
#[derive(Clone, Copy)]
enum Sink {
    Bio(*mut BIO),
    File(*mut FILE),
}

impl Sink {
    /// The encoder's output into it.
    ///
    /// # Safety
    /// The context is live; the sink's BIO or `FILE` is.
    unsafe fn encode(self, ctx: *mut rustyssl_abi::OSSL_ENCODER_CTX) -> c_int {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Bio(b) => unsafe { crate::encoder::ctx::OSSL_ENCODER_to_bio(ctx, b) },
            // SAFETY: as above.
            Self::File(f) => unsafe { crate::encoder::ctx::OSSL_ENCODER_to_fp(ctx, f) },
        }
    }

    /// `PEM_ASN1_write_bio` (or `PEM_ASN1_write`) into it.
    ///
    /// # Safety
    /// As for `PEM_ASN1_write_bio`.
    #[allow(clippy::too_many_arguments, reason = "PEM_ASN1_write_bio's")]
    unsafe fn asn1(
        self,
        i2d: I2dOfVoid,
        name: *const c_char,
        x: *const c_void,
        enc: *const EVP_CIPHER,
        kstr: *const c_uchar,
        klen: c_int,
        cb: pem_password_cb,
        u: *mut c_void,
    ) -> c_int {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Bio(b) => unsafe {
                crate::pem_cipher::PEM_ASN1_write_bio(Some(i2d), name, b, x, enc, kstr, klen, cb, u)
            },
            // SAFETY: as above.
            Self::File(f) => unsafe {
                crate::pem_cipher::PEM_ASN1_write(Some(i2d), name, f, x, enc, kstr, klen, cb, u)
            },
        }
    }
}

/// `IMPLEMENT_PEM_provided_write_body_vars`: the PEM encoders of the key's part and structure,
/// or `None` (the context freed) when there are none, for the legacy path.
///
/// # Safety
/// `x` is NULL or a live key; `propq` is NULL or a C string.
unsafe fn pem_encoders(
    x: *const EVP_PKEY,
    selection: c_int,
    structure: &CStr,
    propq: *const c_char,
) -> Option<*mut rustyssl_abi::OSSL_ENCODER_CTX> {
    use crate::encoder::ctx::{OSSL_ENCODER_CTX_free, OSSL_ENCODER_CTX_get_num_encoders};
    // SAFETY: the caller's key; static strings; the caller's properties.
    let ctx = unsafe {
        crate::encoder::pkey::OSSL_ENCODER_CTX_new_for_pkey(
            x,
            selection,
            c"PEM".as_ptr(),
            structure.as_ptr(),
            propq,
        )
    };
    // SAFETY: the new context, or NULL.
    if unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } == 0 {
        // SAFETY: as above.
        unsafe { OSSL_ENCODER_CTX_free(ctx) };
        return None;
    }
    Some(ctx)
}

/// `IMPLEMENT_PEM_provided_write_body_pass`: the cipher and passphrase (`kstr`, else `u` as
/// one, else `cb` or `PEM_def_callback`) set on the context. False if they can't be.
///
/// # Safety
/// The context is live; `enc`, `kstr`, `cb`, and `u` as for a key writer.
unsafe fn pem_pass(
    ctx: *mut rustyssl_abi::OSSL_ENCODER_CTX,
    enc: *const EVP_CIPHER,
    mut kstr: *const c_uchar,
    mut klen: c_int,
    mut cb: pem_password_cb,
    u: *mut c_void,
) -> bool {
    use crate::encoder::ctx::{
        OSSL_ENCODER_CTX_set_cipher, OSSL_ENCODER_CTX_set_passphrase,
        OSSL_ENCODER_CTX_set_pem_password_cb,
    };
    if kstr.is_null() && cb.is_none() {
        if u.is_null() {
            cb = Some(crate::pem_cipher::PEM_def_callback);
        } else {
            kstr = u.cast_const().cast();
            // SAFETY: OpenSSL takes `u` as the passphrase then, a C string.
            klen = c_int::try_from(unsafe { CStr::from_ptr(kstr.cast()) }.to_bytes().len())
                .unwrap_or(c_int::MAX);
        }
    }
    if enc.is_null() {
        return true;
    }
    // SAFETY: the caller's cipher.
    let name = unsafe { crate::evp::cipher::EVP_CIPHER_get0_name(enc) };
    // SAFETY: the caller's context; the cipher's name.
    if unsafe { OSSL_ENCODER_CTX_set_cipher(ctx, name, ptr::null()) } == 0 {
        return false;
    }
    if !kstr.is_null() {
        let Ok(len) = usize::try_from(klen) else {
            return false;
        };
        // SAFETY: the caller's `klen` octets.
        return unsafe { OSSL_ENCODER_CTX_set_passphrase(ctx, kstr, len) } != 0;
    }
    // SAFETY: the caller's callback and argument.
    cb.is_none() || unsafe { OSSL_ENCODER_CTX_set_pem_password_cb(ctx, cb, u) } != 0
}

/// `PEM_write_bio_PrivateKey_ex`: a provided key's PrivateKeyInfo through
/// the encoders, a legacy one's PKCS#8 or, for a type without, its traditional form.
///
/// # Safety
/// As for `PEM_write_bio_PrivateKey_ex`.
#[allow(clippy::too_many_arguments, reason = "PEM_write_bio_PrivateKey_ex's")]
unsafe fn write_private_key(
    out: *mut BIO,
    x: *const EVP_PKEY,
    enc: *const EVP_CIPHER,
    kstr: *const c_uchar,
    klen: c_int,
    cb: pem_password_cb,
    u: *mut c_void,
    propq: *const c_char,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let encoders = unsafe { pem_encoders(x, EVP_PKEY_KEYPAIR, c"PrivateKeyInfo", propq) };
    if let Some(ctx) = encoders {
        // SAFETY: the new context; the caller's arguments.
        let ret = if unsafe { pem_pass(ctx, enc, kstr, klen, cb, u) } {
            // SAFETY: as above.
            unsafe { Sink::Bio(out).encode(ctx) }
        } else {
            0
        };
        // SAFETY: made above.
        unsafe { crate::encoder::ctx::OSSL_ENCODER_CTX_free(ctx) };
        return ret;
    }
    // SAFETY: the caller's guarantee.
    let pkcs8 =
        unsafe { pkey(x) }.is_some_and(|k| k.ameth_funcs().is_none_or(|f| f.priv_encode.is_some()));
    if pkcs8 {
        // SAFETY: as above.
        return unsafe { do_pk8pkey(Sink::Bio(out), x, false, -1, enc, kstr.cast(), klen, cb, u) };
    }
    // SAFETY: as above.
    unsafe { PEM_write_bio_PrivateKey_traditional(out, x, enc, kstr, klen, cb, u) }
}

ffi_export! {
    /// Writes the private key as PEM: a PrivateKeyInfo (encrypted with `enc` if given, as an
    /// EncryptedPrivateKeyInfo), or a legacy key's traditional form when its type has no
    /// PKCS#8 encoding. 1, or 0.
    ///
    /// # Safety
    /// `out` is a live BIO; `x` is NULL or a live key; `enc` is NULL or a cipher; `kstr` is NULL
    /// or `klen` octets; `cb` is NULL or a password callback taking `u` (or `u` is NULL or a C
    /// string); `propq` is NULL or a C string.
    pub unsafe extern "C" fn PEM_write_bio_PrivateKey_ex(out: *mut BIO, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, cb: pem_password_cb, u: *mut c_void, _libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_private_key(out, x, enc, kstr, klen, cb, u, propq) }
    }
}

ffi_export! {
    /// `PEM_write_bio_PrivateKey_ex` without a library context or properties.
    ///
    /// # Safety
    /// As for `PEM_write_bio_PrivateKey_ex`.
    pub unsafe extern "C" fn PEM_write_bio_PrivateKey(out: *mut BIO, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, cb: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_private_key(out, x, enc, kstr, klen, cb, u, ptr::null()) }
    }
}

/// A BIO on the `FILE` (not closing it), or NULL with `ERR_R_BUF_LIB`.
///
/// # Safety
/// `fp` is an open `FILE`.
unsafe fn fp_bio(fp: *mut FILE, f: &str) -> *mut BIO {
    // SAFETY: the caller's guarantee.
    let b = unsafe { crate::bio::file::BIO_new_fp(fp, rustyssl_abi::BIO_NOCLOSE) };
    if b.is_null() {
        err::raise(ERR_LIB_PEM, rustyssl_abi::ERR_R_BUF_LIB, f);
    }
    b
}

ffi_export! {
    /// `PEM_write_bio_PrivateKey_ex` to a `FILE`.
    ///
    /// # Safety
    /// `out` is an open `FILE`; otherwise as for `PEM_write_bio_PrivateKey_ex`.
    pub unsafe extern "C" fn PEM_write_PrivateKey_ex(out: *mut FILE, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { fp_bio(out, "PEM_write_PrivateKey_ex") };
        if b.is_null() {
            return 0;
        }
        // SAFETY: as above, into the BIO.
        let ret = unsafe { PEM_write_bio_PrivateKey_ex(b, x, enc, kstr, klen, cb, u, libctx, propq) };
        // SAFETY: made above.
        unsafe { BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// `PEM_write_PrivateKey_ex` without a library context or properties.
    ///
    /// # Safety
    /// As for `PEM_write_PrivateKey_ex`.
    pub unsafe extern "C" fn PEM_write_PrivateKey(out: *mut FILE, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, cb: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { PEM_write_PrivateKey_ex(out, x, enc, kstr, klen, cb, u, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Writes the private key in its type's traditional form ("RSA PRIVATE KEY" and so on; a
    /// provided key through a legacy copy). 1, or 0 (with `PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE`
    /// for a type without one).
    ///
    /// # Safety
    /// As for `PEM_write_bio_PrivateKey`.
    pub unsafe extern "C" fn PEM_write_bio_PrivateKey_traditional(bp: *mut BIO, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, cb: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { pkey(x) }) else { return 0 };
        let copy = if k.assigned() && k.is_provided() { crate::evp::pkey::copy_downgraded(k) } else { None };
        let key = copy.as_ref().map_or(x, |c| c.as_ptr().cast_const());
        // SAFETY: the caller's key, or the copy made here.
        let Some(kk) = (unsafe { pkey(key) }) else { return 0 };
        if kk.ameth_funcs().is_none_or(|f| f.old_priv_encode.is_none()) {
            err::raise(ERR_LIB_PEM, rustyssl_abi::PEM_R_UNSUPPORTED_PUBLIC_KEY_TYPE, "PEM_write_bio_PrivateKey_traditional");
            return 0;
        }
        let mut name = kk.ameth_pem_str().map_or_else(|| b"<NULL>".to_vec(), |s| s.into_bytes());
        name.extend_from_slice(b" PRIVATE KEY");
        name.truncate(79);
        let Ok(name) = std::ffi::CString::new(name) else { return 0 };
        let f: I2dOfVoid = crate::evp::pkey::i2d::private_key_void;
        // SAFETY: the key; the name; the caller's BIO, cipher, passphrase, and callback.
        unsafe { crate::pem_cipher::PEM_ASN1_write_bio(Some(f), name.as_ptr(), bp, key.cast(), enc, kstr, klen, cb, u) }
    }
}

/// `PEM_write_bio_Parameters` into the sink.
///
/// # Safety
/// `x` is NULL or a live key.
unsafe fn write_parameters(out: Sink, x: *const EVP_PKEY) -> c_int {
    // SAFETY: the caller's guarantee.
    let encoders =
        unsafe { pem_encoders(x, EVP_PKEY_KEY_PARAMETERS, c"type-specific", ptr::null()) };
    if let Some(ctx) = encoders {
        // SAFETY: the new context.
        let ret = unsafe { out.encode(ctx) };
        // SAFETY: made above.
        unsafe { crate::encoder::ctx::OSSL_ENCODER_CTX_free(ctx) };
        return ret;
    }
    // SAFETY: the caller's guarantee.
    let Some(k) = (unsafe { pkey(x) }) else {
        return 0;
    };
    if k.ameth_funcs().is_none_or(|f| f.param_encode.is_none()) {
        return 0;
    }
    let mut name = k
        .ameth_pem_str()
        .map_or_else(|| b"<NULL>".to_vec(), |s| s.into_bytes());
    name.extend_from_slice(b" PARAMETERS");
    name.truncate(79);
    let Ok(name) = std::ffi::CString::new(name) else {
        return 0;
    };
    let f: I2dOfVoid = crate::evp::pkey::i2d::key_params_void;
    // SAFETY: the key; the name; no encryption.
    unsafe {
        out.asn1(
            f,
            name.as_ptr(),
            x.cast(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

ffi_export! {
    /// Writes the key's parameters as PEM ("<type> PARAMETERS"). 1, or 0.
    ///
    /// # Safety
    /// `out` is a live BIO; `x` is NULL or a live key.
    pub unsafe extern "C" fn PEM_write_bio_Parameters(out: *mut BIO, x: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_parameters(Sink::Bio(out), x) }
    }
}

/// `i2d_PUBKEY` as an `i2d_of_void`.
unsafe extern "C" fn i2d_pubkey_void(x: *const c_void, pp: *mut *mut c_uchar) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { crate::x509::pubkey::i2d_PUBKEY(x.cast(), pp) }
}

/// `PEM_write_bio_PUBKEY_ex` into the sink: a provided key's SubjectPublicKeyInfo through the
/// encoders, a legacy one's through `i2d_PUBKEY`.
///
/// # Safety
/// `x` is NULL or a live key; `propq` is NULL or a C string.
unsafe fn write_pubkey(out: Sink, x: *const EVP_PKEY, propq: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee.
    let encoders = unsafe { pem_encoders(x, EVP_PKEY_PUBLIC_KEY, c"SubjectPublicKeyInfo", propq) };
    if let Some(ctx) = encoders {
        // SAFETY: the new context.
        let ret = unsafe { out.encode(ctx) };
        // SAFETY: made above.
        unsafe { crate::encoder::ctx::OSSL_ENCODER_CTX_free(ctx) };
        return ret;
    }
    // SAFETY: the caller's key; no encryption.
    unsafe {
        out.asn1(
            i2d_pubkey_void,
            PEM_STRING_PUBLIC.as_ptr(),
            x.cast(),
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        )
    }
}

ffi_export! {
    /// Writes the key's SubjectPublicKeyInfo as PEM ("PUBLIC KEY"). 1, or 0.
    ///
    /// # Safety
    /// `out` is a live BIO; `x` is NULL or a live key.
    pub unsafe extern "C" fn PEM_write_bio_PUBKEY(out: *mut BIO, x: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_pubkey(Sink::Bio(out), x, ptr::null()) }
    }
}

ffi_export! {
    /// `PEM_write_bio_PUBKEY` with the encoders' properties.
    ///
    /// # Safety
    /// As for `PEM_write_bio_PUBKEY`; `propq` is NULL or a C string.
    pub unsafe extern "C" fn PEM_write_bio_PUBKEY_ex(out: *mut BIO, x: *const EVP_PKEY, _libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_pubkey(Sink::Bio(out), x, propq) }
    }
}

ffi_export! {
    /// `PEM_write_bio_PUBKEY` to a `FILE`.
    ///
    /// # Safety
    /// `out` is an open `FILE`; `x` is NULL or a live key.
    pub unsafe extern "C" fn PEM_write_PUBKEY(out: *mut FILE, x: *const EVP_PKEY) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_pubkey(Sink::File(out), x, ptr::null()) }
    }
}

ffi_export! {
    /// `PEM_write_bio_PUBKEY_ex` to a `FILE`.
    ///
    /// # Safety
    /// As for `PEM_write_PUBKEY`; `propq` is NULL or a C string.
    pub unsafe extern "C" fn PEM_write_PUBKEY_ex(out: *mut FILE, x: *const EVP_PKEY, _libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_pubkey(Sink::File(out), x, propq) }
    }
}

/// `do_pk8pkey` (and `do_pk8pkey_fp`'s body): the key's PrivateKeyInfo in DER or PEM, through
/// the encoders when they can (no PBE `nid`), else through `EVP_PKEY2PKCS8` (encrypted with
/// `PKCS8_encrypt` for `enc` or the PBE `nid`).
///
/// # Safety
/// As for `PEM_write_bio_PKCS8PrivateKey`, into the sink.
#[allow(clippy::too_many_arguments, reason = "do_pk8pkey's")]
unsafe fn do_pk8pkey(
    out: Sink,
    x: *const EVP_PKEY,
    isder: bool,
    nid: c_int,
    enc: *const EVP_CIPHER,
    kstr: *const c_char,
    klen: c_int,
    cb: pem_password_cb,
    u: *mut c_void,
) -> c_int {
    use crate::encoder::ctx::{OSSL_ENCODER_CTX_free, OSSL_ENCODER_CTX_get_num_encoders};
    let outtype = if isder { c"DER" } else { c"PEM" };
    // SAFETY: the caller's key; static strings.
    let ctx = unsafe {
        crate::encoder::pkey::OSSL_ENCODER_CTX_new_for_pkey(
            x,
            rustyssl_abi::OSSL_KEYMGMT_SELECT_ALL,
            outtype.as_ptr(),
            c"PrivateKeyInfo".as_ptr(),
            ptr::null(),
        )
    };
    if ctx.is_null() {
        return 0;
    }
    let (mut kstr, mut klen, mut cb) = (kstr.cast::<c_uchar>(), klen, cb);
    if kstr.is_null() && cb.is_none() {
        if u.is_null() {
            cb = Some(crate::pem_cipher::PEM_def_callback);
        } else {
            kstr = u.cast_const().cast();
            // SAFETY: OpenSSL takes `u` as the passphrase then, a C string.
            klen = c_int::try_from(unsafe { CStr::from_ptr(kstr.cast()) }.to_bytes().len())
                .unwrap_or(c_int::MAX);
        }
    }
    let ret;
    // SAFETY: the new context.
    if nid == -1 && unsafe { OSSL_ENCODER_CTX_get_num_encoders(ctx) } != 0 {
        // SAFETY: as above; the caller's arguments (`kstr` and `cb` settled above).
        let ok = unsafe { pem_pass(ctx, enc, kstr, klen, cb, u) };
        // SAFETY: as above.
        ret = c_int::from(ok && unsafe { out.encode(ctx) } != 0);
    } else {
        // SAFETY: the caller's key.
        let p8inf = unsafe { crate::evp::pkey::d2i::EVP_PKEY2PKCS8(x) };
        if p8inf.is_null() {
            err::raise(
                ERR_LIB_PEM,
                rustyssl_abi::PEM_R_ERROR_CONVERTING_PRIVATE_KEY,
                "do_pk8pkey",
            );
            ret = 0;
        } else {
            if !enc.is_null() || nid != -1 {
                let mut buf = zeroize_buf();
                let (mut pass, mut plen) = (kstr.cast::<c_char>(), klen);
                if kstr.is_null() {
                    // SAFETY: room for `PEM_BUFSIZE` octets; the callback (set above) and its
                    // argument.
                    let n = cb.map_or(-1, |f| unsafe { f(buf.as_mut_ptr(), PEM_BUFSIZE, 1, u) });
                    if n < 0 {
                        err::raise(ERR_LIB_PEM, rustyssl_abi::PEM_R_READ_KEY, "do_pk8pkey");
                        // SAFETY: made above.
                        unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8inf) };
                        // SAFETY: as above.
                        unsafe { OSSL_ENCODER_CTX_free(ctx) };
                        return 0;
                    }
                    (pass, plen) = (buf.as_ptr(), n);
                }
                // SAFETY: the cipher or PBE NID; the passphrase; the PrivateKeyInfo.
                let p8 = unsafe {
                    crate::pkcs8_crypt::PKCS8_encrypt(
                        nid,
                        enc,
                        pass,
                        plen,
                        ptr::null_mut(),
                        0,
                        0,
                        p8inf,
                    )
                };
                ret = if p8.is_null() {
                    0
                } else {
                    let r = match (out, isder) {
                        // SAFETY: the sink's BIO; the new structure.
                        (Sink::Bio(b), true) => unsafe { crate::x509::sig::i2d_PKCS8_bio(b, p8) },
                        // SAFETY: as above.
                        (Sink::Bio(b), false) => unsafe { PEM_write_bio_PKCS8(b, p8) },
                        // SAFETY: the sink's `FILE`; the new structure.
                        (Sink::File(f), true) => unsafe { crate::x509::sig::i2d_PKCS8_fp(f, p8) },
                        // SAFETY: as above.
                        (Sink::File(f), false) => unsafe { PEM_write_PKCS8(f, p8) },
                    };
                    // SAFETY: made above.
                    unsafe { crate::x509::sig::X509_SIG_free(p8) };
                    r
                };
            } else {
                ret = match (out, isder) {
                    // SAFETY: the sink's BIO; the new structure.
                    (Sink::Bio(b), true) => unsafe {
                        crate::x509::p8::i2d_PKCS8_PRIV_KEY_INFO_bio(b, p8inf)
                    },
                    // SAFETY: as above.
                    (Sink::Bio(b), false) => unsafe { PEM_write_bio_PKCS8_PRIV_KEY_INFO(b, p8inf) },
                    // SAFETY: the sink's `FILE`; the new structure.
                    (Sink::File(f), true) => unsafe {
                        crate::x509::p8::i2d_PKCS8_PRIV_KEY_INFO_fp(f, p8inf)
                    },
                    // SAFETY: as above.
                    (Sink::File(f), false) => unsafe { PEM_write_PKCS8_PRIV_KEY_INFO(f, p8inf) },
                };
            }
            // SAFETY: made above.
            unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8inf) };
        }
    }
    // SAFETY: made above.
    unsafe { OSSL_ENCODER_CTX_free(ctx) };
    ret
}

/// A wiped buffer of `PEM_BUFSIZE` for a passphrase.
fn zeroize_buf() -> rustyssl_crypto::bn::Zeroizing<[c_char; 1024]> {
    rustyssl_crypto::bn::Zeroizing::new([0; 1024])
}

/// `do_pk8pkey_fp`: `do_pk8pkey` through a BIO on the `FILE`.
///
/// # Safety
/// `fp` is an open `FILE`; otherwise as for `do_pk8pkey`.
#[allow(clippy::too_many_arguments, reason = "do_pk8pkey's")]
unsafe fn do_pk8pkey_fp(
    fp: *mut FILE,
    x: *const EVP_PKEY,
    isder: bool,
    nid: c_int,
    enc: *const EVP_CIPHER,
    kstr: *const c_char,
    klen: c_int,
    cb: pem_password_cb,
    u: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let b = unsafe { fp_bio(fp, "do_pk8pkey_fp") };
    if b.is_null() {
        return 0;
    }
    // SAFETY: as above, into the BIO.
    let ret = unsafe { do_pk8pkey(Sink::Bio(b), x, isder, nid, enc, kstr, klen, cb, u) };
    // SAFETY: made above.
    unsafe { BIO_free(b) };
    ret
}

/// The PKCS#8 writers (`pem_pk8.c`): `PEM_write_bio_PKCS8PrivateKey` and the others, each a
/// `do_pk8pkey` (or `do_pk8pkey_fp`) with its output and cipher.
macro_rules! pk8_writer {
    ($(
        $(#[$doc:meta])*
        pub unsafe extern "C" fn $name:ident($out:ident: $outty:ty, $x:ident: $xty:ty, $t:ident: $tty:ty, $kstr:ident: $kty:ty, $klen:ident: $klty:ty, $cb:ident: $cbty:ty, $u:ident: $uty:ty) via $do:ident($isder:expr, $nid:expr, $enc:expr);
    )*) => {$(
        ffi_export! {
            $(#[$doc])*
            ///
            /// # Safety
            /// The output is live; `x` is NULL or a live key; `kstr` is NULL or `klen` octets;
            /// `cb` is NULL or a password callback taking `u` (or `u` is NULL or a C string).
            pub unsafe extern "C" fn $name($out: $outty, $x: $xty, $t: $tty, $kstr: $kty, $klen: $klty, $cb: $cbty, $u: $uty) -> c_int
            where failure = 0, library = ERR_LIB_PEM
            {
                // SAFETY: the caller's guarantee.
                unsafe { $do($out, $x, $isder, $nid, $enc, $kstr, $klen, $cb, $u) }
            }
        }
    )*};
}

/// `do_pk8pkey` into a BIO.
///
/// # Safety
/// As for `do_pk8pkey`, with `bp` a live BIO.
#[allow(clippy::too_many_arguments, reason = "do_pk8pkey's")]
unsafe fn do_pk8pkey_bio(
    bp: *mut BIO,
    x: *const EVP_PKEY,
    isder: bool,
    nid: c_int,
    enc: *const EVP_CIPHER,
    kstr: *const c_char,
    klen: c_int,
    cb: pem_password_cb,
    u: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { do_pk8pkey(Sink::Bio(bp), x, isder, nid, enc, kstr, klen, cb, u) }
}

pk8_writer! {
    /// Writes the key's PrivateKeyInfo as PEM, encrypted with `enc` if given. 1, or 0.
    pub unsafe extern "C" fn PEM_write_bio_PKCS8PrivateKey(bp: *mut BIO, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_char, klen: c_int, cb: pem_password_cb, u: *mut c_void) via do_pk8pkey_bio(false, -1, enc);
    /// Writes the key's PrivateKeyInfo as PEM, encrypted with the PBE algorithm `nid`. 1, or 0.
    pub unsafe extern "C" fn PEM_write_bio_PKCS8PrivateKey_nid(bp: *mut BIO, x: *const EVP_PKEY, nid: c_int, kstr: *const c_char, klen: c_int, cb: pem_password_cb, u: *mut c_void) via do_pk8pkey_bio(false, nid, ptr::null());
    /// Writes the key's PrivateKeyInfo as DER, encrypted with `enc` if given. 1, or 0.
    pub unsafe extern "C" fn i2d_PKCS8PrivateKey_bio(bp: *mut BIO, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_char, klen: c_int, cb: pem_password_cb, u: *mut c_void) via do_pk8pkey_bio(true, -1, enc);
    /// Writes the key's PrivateKeyInfo as DER, encrypted with the PBE algorithm `nid`. 1, or 0.
    pub unsafe extern "C" fn i2d_PKCS8PrivateKey_nid_bio(bp: *mut BIO, x: *const EVP_PKEY, nid: c_int, kstr: *const c_char, klen: c_int, cb: pem_password_cb, u: *mut c_void) via do_pk8pkey_bio(true, nid, ptr::null());
    /// `PEM_write_bio_PKCS8PrivateKey` to a `FILE`.
    pub unsafe extern "C" fn PEM_write_PKCS8PrivateKey(fp: *mut FILE, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_char, klen: c_int, cb: pem_password_cb, u: *mut c_void) via do_pk8pkey_fp(false, -1, enc);
    /// `PEM_write_bio_PKCS8PrivateKey_nid` to a `FILE`.
    pub unsafe extern "C" fn PEM_write_PKCS8PrivateKey_nid(fp: *mut FILE, x: *const EVP_PKEY, nid: c_int, kstr: *const c_char, klen: c_int, cb: pem_password_cb, u: *mut c_void) via do_pk8pkey_fp(false, nid, ptr::null());
    /// `i2d_PKCS8PrivateKey_bio` to a `FILE`.
    pub unsafe extern "C" fn i2d_PKCS8PrivateKey_fp(fp: *mut FILE, x: *const EVP_PKEY, enc: *const EVP_CIPHER, kstr: *const c_char, klen: c_int, cb: pem_password_cb, u: *mut c_void) via do_pk8pkey_fp(true, -1, enc);
    /// `i2d_PKCS8PrivateKey_nid_bio` to a `FILE`.
    pub unsafe extern "C" fn i2d_PKCS8PrivateKey_nid_fp(fp: *mut FILE, x: *const EVP_PKEY, nid: c_int, kstr: *const c_char, klen: c_int, cb: pem_password_cb, u: *mut c_void) via do_pk8pkey_fp(true, nid, ptr::null());
}
