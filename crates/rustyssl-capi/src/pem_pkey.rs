//! Reading keys from PEM (`PEM_read_bio_PrivateKey(3)`, `PEM_read_bio_PUBKEY`,
//! `PEM_read_bio_Parameters`, the type-specific readers; `pem_pkey.c`, `pem_all.c`,
//! `pem_pk8.c`): through the decoders from the BIO's current position (the first PEM block of
//! a supported kind that holds a key with the parts asked for), then through the legacy
//! reading (`PEM_bytes_read_bio` by name, then the key type's ASN.1 method) from the same
//! position; and the readers of single structures (`PEM_ASN1_read_bio` with their `d2i`).
//!
//! As in OpenSSL, the password callback (the default one for none) is asked through a cache, so
//! a key read in both ways asks once; a BIO that can't tell its position is read through a
//! read buffer. Encrypted keys need the UI layer and PKCS#8 decryption (step 4.7d): until then
//! asking for a passphrase through a `pem_password_cb` aborts.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_ulong, c_void};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    BIO, BIO_C_FILE_SEEK, BIO_C_FILE_TELL, BIO_CTRL_EOF, DSA, EC_GROUP, EC_KEY, ERR_LIB_PEM,
    ERR_R_ASN1_LIB, ERR_R_UNSUPPORTED, ERR_REASON_MASK, ERR_SYSTEM_FLAG, EVP_PKEY,
    EVP_PKEY_KEY_PARAMETERS, EVP_PKEY_KEYPAIR, EVP_PKEY_PUBLIC_KEY,
    OSSL_KEYMGMT_SELECT_PRIVATE_KEY, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, OSSL_LIB_CTX, PEM_BUFSIZE,
    PEM_R_BAD_PASSWORD_READ, PEM_R_UNSUPPORTED_KEY_COMPONENTS, PEM_STRING_ECPARAMETERS,
    PEM_STRING_EVP_PKEY, PEM_STRING_PARAMETERS, PEM_STRING_PKCS8, PEM_STRING_PKCS8INF,
    PEM_STRING_PUBLIC, PEM_STRING_RSA_PUBLIC, PKCS8_PRIV_KEY_INFO, RSA, X509_PUBKEY, X509_SIG,
    pem_password_cb,
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
            let mut psbuf = [0 as c_char; PEM_BUFSIZE.unsigned_abs() as usize];
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
                crate::stub::unimplemented("PKCS8_decrypt of an encrypted PEM key (step 4.7d)");
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
