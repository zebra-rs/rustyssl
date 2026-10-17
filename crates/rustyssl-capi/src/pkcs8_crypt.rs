//! Encrypting and decrypting with a PBE AlgorithmIdentifier (`p12_decr.c`), and PKCS#8's
//! EncryptedPrivateKeyInfo over it (`p12_p8e.c`, `p12_p8d.c`): `PKCS12_pbe_crypt` (with an
//! AEAD cipher's tag appended or checked), the item encryption and decryption it serves, and
//! `PKCS8_encrypt`, `PKCS8_set0_pbe`, and `PKCS8_decrypt`.

use core::ffi::{c_char, c_int, c_uchar, c_void};
use core::ptr;

use rustyssl_abi::{
    ASN1_ITEM, ASN1_OCTET_STRING, ERR_LIB_PKCS12, ERR_R_ASN1_LIB, ERR_R_EVP_LIB,
    ERR_R_INTERNAL_ERROR, ERR_R_PASSED_NULL_PARAMETER, EVP_CIPH_FLAG_CIPHER_WITH_MAC, EVP_CIPHER,
    EVP_CTRL_AEAD_GET_TAG, EVP_CTRL_AEAD_SET_TAG, EVP_CTRL_AEAD_TLS1_AAD, EVP_PBE_TYPE_PRF,
    OSSL_LIB_CTX, PKCS8_PRIV_KEY_INFO, PKCS12_R_DECODE_ERROR, PKCS12_R_ENCODE_ERROR,
    PKCS12_R_ENCRYPT_ERROR, PKCS12_R_PKCS12_CIPHERFINAL_ERROR, PKCS12_R_UNSUPPORTED_PKCS12_MODE,
    X509_ALGOR, X509_SIG,
};

use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_get_block_size,
    EVP_CIPHER_CTX_get0_cipher, EVP_CIPHER_CTX_is_encrypting, EVP_CIPHER_CTX_new,
    EVP_CipherFinal_ex, EVP_CipherUpdate,
};
use crate::ffi::ffi_export;
use crate::mem;

/// Whether the context's cipher appends its MAC (`EVP_CIPH_FLAG_CIPHER_WITH_MAC`).
///
/// # Safety
/// `ctx` is a live context with a cipher.
unsafe fn with_mac(ctx: *mut rustyssl_abi::EVP_CIPHER_CTX) -> bool {
    // SAFETY: the caller's guarantee.
    let c = unsafe { EVP_CIPHER_CTX_get0_cipher(ctx) };
    // SAFETY: the context's cipher.
    let flags = unsafe { crate::evp::cipher::EVP_CIPHER_get_flags(c) };
    flags & core::ffi::c_ulong::from(EVP_CIPH_FLAG_CIPHER_WITH_MAC.cast_unsigned()) != 0
}

ffi_export! {
    /// Encrypts (`en_de` 1) or decrypts `inlen` octets with the PBE AlgorithmIdentifier and the
    /// password: a new buffer (from `CRYPTO_malloc`, also into `*data`) and its length into
    /// `*datalen`, or NULL. A cipher with a MAC has it appended, or checked and removed.
    ///
    /// # Safety
    /// `algor` is a live AlgorithmIdentifier; `pass` is NULL or `passlen` octets (a C string for
    /// -1); `in_` holds `inlen` octets; `data` and `datalen` are NULL or writable; `libctx` is
    /// NULL or live; `propq` is NULL or a C string.
    pub unsafe extern "C" fn PKCS12_pbe_crypt_ex(algor: *const X509_ALGOR, pass: *const c_char, passlen: c_int, in_: *const c_uchar, inlen: c_int, data: *mut *mut c_uchar, datalen: *mut c_int, en_de: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_pbe_crypt_ex";
        // SAFETY: no preconditions.
        let ctx = unsafe { EVP_CIPHER_CTX_new() };
        let mut out: *mut c_uchar = ptr::null_mut();
        let mut inlen = inlen;
        'go: {
            if ctx.is_null() {
                err::raise(ERR_LIB_PKCS12, ERR_R_EVP_LIB, F);
                break 'go;
            }
            // SAFETY: the caller's AlgorithmIdentifier.
            let Some(a) = (unsafe { algor.as_ref() }) else { break 'go };
            // SAFETY: the caller's guarantee; the new context.
            if unsafe { crate::evp::pbe::EVP_PBE_CipherInit_ex(a.algorithm, pass, passlen, a.parameter, ctx, en_de, libctx, propq) } == 0 {
                break 'go;
            }
            // SAFETY: the context, with its cipher.
            let block_size = unsafe { EVP_CIPHER_CTX_get_block_size(ctx) };
            if block_size == 0 {
                err::raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER, F);
                break 'go;
            }
            let mut max_out_len = inlen.saturating_add(block_size);
            let mut mac_len: c_int = 0;
            // SAFETY: as above.
            let mac = unsafe { with_mac(ctx) };
            // SAFETY: as above.
            let encrypting = unsafe { EVP_CIPHER_CTX_is_encrypting(ctx) } != 0;
            if mac {
                // SAFETY: the context; a local for the MAC's length.
                if unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, 0, (&raw mut mac_len).cast()) } <= 0 {
                    err::raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR, F);
                    break 'go;
                }
                if encrypting {
                    max_out_len = max_out_len.saturating_add(mac_len);
                } else {
                    if inlen < mac_len {
                        err::raise(ERR_LIB_PKCS12, PKCS12_R_UNSUPPORTED_PKCS12_MODE, F);
                        break 'go;
                    }
                    inlen -= mac_len;
                    let tag = in_.wrapping_add(usize::try_from(inlen).unwrap_or(0)).cast_mut();
                    // SAFETY: the context; the input's last `mac_len` octets.
                    if unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, mac_len, tag.cast()) } <= 0 {
                        err::raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR, F);
                        break 'go;
                    }
                }
            }
            let Ok(max) = usize::try_from(max_out_len) else { break 'go };
            out = mem::zalloc(max, ptr::null(), 0).cast();
            if out.is_null() {
                break 'go;
            }
            let mut i: c_int = 0;
            // SAFETY: the context; room for `inlen + block_size`; the caller's octets.
            if unsafe { EVP_CipherUpdate(ctx, out, &raw mut i, in_, inlen) } == 0 {
                // SAFETY: made above.
                unsafe { mem::release_clean(out.cast(), max) };
                out = ptr::null_mut();
                err::raise(ERR_LIB_PKCS12, ERR_R_EVP_LIB, F);
                break 'go;
            }
            let mut outlen = i;
            let at = out.wrapping_add(usize::try_from(i).unwrap_or(0));
            // SAFETY: as above, past what was written.
            if unsafe { EVP_CipherFinal_ex(ctx, at, &raw mut i) } == 0 {
                // SAFETY: made above.
                unsafe { mem::release_clean(out.cast(), max) };
                out = ptr::null_mut();
                let why = if passlen == 0 { "empty password" } else { "maybe wrong password" };
                err::raise_with_text(ERR_LIB_PKCS12, PKCS12_R_PKCS12_CIPHERFINAL_ERROR, F, why);
                break 'go;
            }
            outlen = outlen.saturating_add(i);
            if mac && encrypting {
                let tag = out.wrapping_add(usize::try_from(outlen).unwrap_or(0));
                // SAFETY: the context; room for the MAC after the ciphertext.
                if unsafe { EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, mac_len, tag.cast()) } <= 0 {
                    // SAFETY: made above.
                    unsafe { mem::release_clean(out.cast(), max) };
                    out = ptr::null_mut();
                    err::raise(ERR_LIB_PKCS12, ERR_R_INTERNAL_ERROR, F);
                    break 'go;
                }
                outlen = outlen.saturating_add(mac_len);
            }
            if !datalen.is_null() {
                // SAFETY: the caller's guarantee.
                unsafe { datalen.write(outlen) };
            }
            if !data.is_null() {
                // SAFETY: as above.
                unsafe { data.write(out) };
            }
        }
        // SAFETY: made above, or NULL.
        unsafe { EVP_CIPHER_CTX_free(ctx) };
        out
    }
}

ffi_export! {
    /// `PKCS12_pbe_crypt_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS12_pbe_crypt_ex`.
    pub unsafe extern "C" fn PKCS12_pbe_crypt(algor: *const X509_ALGOR, pass: *const c_char, passlen: c_int, in_: *const c_uchar, inlen: c_int, data: *mut *mut c_uchar, datalen: *mut c_int, en_de: c_int) -> *mut c_uchar
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_pbe_crypt_ex(algor, pass, passlen, in_, inlen, data, datalen, en_de, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Decrypts the OCTET STRING with the PBE AlgorithmIdentifier and the password, and decodes
    /// the plaintext as `it` (wiped after when `zbuf`): the new value, or NULL.
    ///
    /// # Safety
    /// As for `PKCS12_pbe_crypt_ex`; `it` is a live item; `oct` is NULL or a live OCTET STRING.
    pub unsafe extern "C" fn PKCS12_item_decrypt_d2i_ex(algor: *const X509_ALGOR, it: *const ASN1_ITEM, pass: *const c_char, passlen: c_int, oct: *const ASN1_OCTET_STRING, zbuf: c_int, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_item_decrypt_d2i_ex";
        // SAFETY: the caller's guarantee.
        let Some(o) = (unsafe { oct.as_ref() }) else {
            err::raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER, F);
            return ptr::null_mut();
        };
        let mut out: *mut c_uchar = ptr::null_mut();
        let mut outlen: c_int = 0;
        // SAFETY: the caller's guarantee; the OCTET STRING's octets.
        if unsafe { PKCS12_pbe_crypt_ex(algor, pass, passlen, o.data, o.length, &raw mut out, &raw mut outlen, 0, libctx, propq) }.is_null() {
            return ptr::null_mut();
        }
        let mut p = out.cast_const();
        // SAFETY: the plaintext's octets; the caller's item.
        let ret = unsafe { crate::asn1::tpl::decode::ASN1_item_d2i(ptr::null_mut(), &raw mut p, outlen.into(), it) };
        let n = usize::try_from(outlen).unwrap_or(0);
        if zbuf != 0 {
            // SAFETY: the plaintext.
            unsafe { mem::OPENSSL_cleanse(out.cast(), n) };
        }
        if ret.is_null() {
            err::raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR, F);
        }
        // SAFETY: made by `PKCS12_pbe_crypt_ex`.
        unsafe { mem::release(out.cast()) };
        ret.cast()
    }
}

ffi_export! {
    /// `PKCS12_item_decrypt_d2i_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS12_item_decrypt_d2i_ex`.
    pub unsafe extern "C" fn PKCS12_item_decrypt_d2i(algor: *const X509_ALGOR, it: *const ASN1_ITEM, pass: *const c_char, passlen: c_int, oct: *const ASN1_OCTET_STRING, zbuf: c_int) -> *mut c_void
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_item_decrypt_d2i_ex(algor, it, pass, passlen, oct, zbuf, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Encodes `obj` as `it` and encrypts the DER with the PBE AlgorithmIdentifier and the
    /// password (the DER wiped after when `zbuf`): a new OCTET STRING of the ciphertext, or
    /// NULL.
    ///
    /// # Safety
    /// As for `PKCS12_pbe_crypt_ex`; `it` is a live item and `obj` a value of it.
    pub unsafe extern "C" fn PKCS12_item_i2d_encrypt_ex(algor: *mut X509_ALGOR, it: *const ASN1_ITEM, pass: *const c_char, passlen: c_int, obj: *mut c_void, zbuf: c_int, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        const F: &str = "PKCS12_item_i2d_encrypt_ex";
        // SAFETY: no preconditions.
        let oct = unsafe { crate::asn1::string::ASN1_OCTET_STRING_new() };
        // SAFETY: made above, or NULL.
        let Some(o) = (unsafe { oct.as_mut() }) else {
            err::raise(ERR_LIB_PKCS12, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        };
        let mut in_: *mut c_uchar = ptr::null_mut();
        // SAFETY: the caller's value and item; a new buffer into `in_`.
        let inlen = unsafe { crate::asn1::tpl::encode::ASN1_item_i2d(obj.cast(), &raw mut in_, it) };
        let fail = |oct: *mut ASN1_OCTET_STRING| {
            // SAFETY: made above.
            unsafe { crate::asn1::string::ASN1_STRING_free(oct) };
            ptr::null_mut()
        };
        if in_.is_null() {
            err::raise(ERR_LIB_PKCS12, PKCS12_R_ENCODE_ERROR, F);
            return fail(oct);
        }
        let n = usize::try_from(inlen).unwrap_or(0);
        // SAFETY: the caller's guarantee; the DER; the OCTET STRING's fields for the ciphertext.
        let made = unsafe { PKCS12_pbe_crypt_ex(algor, pass, passlen, in_, inlen, &raw mut o.data, &raw mut o.length, 1, ctx, propq) };
        if made.is_null() {
            err::raise(ERR_LIB_PKCS12, PKCS12_R_ENCRYPT_ERROR, F);
            // SAFETY: the DER, which may hold a key.
            unsafe { mem::release_clean(in_.cast(), n) };
            return fail(oct);
        }
        if zbuf != 0 {
            // SAFETY: as above.
            unsafe { mem::OPENSSL_cleanse(in_.cast(), n) };
        }
        // SAFETY: as above.
        unsafe { mem::release(in_.cast()) };
        oct
    }
}

ffi_export! {
    /// `PKCS12_item_i2d_encrypt_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS12_item_i2d_encrypt_ex`.
    pub unsafe extern "C" fn PKCS12_item_i2d_encrypt(algor: *mut X509_ALGOR, it: *const ASN1_ITEM, pass: *const c_char, passlen: c_int, obj: *mut c_void, zbuf: c_int) -> *mut ASN1_OCTET_STRING
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS12_item_i2d_encrypt_ex(algor, it, pass, passlen, obj, zbuf, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The PrivateKeyInfo encrypted under `pbe` (which the result takes) as an
    /// EncryptedPrivateKeyInfo, or NULL (`pbe` still the caller's).
    ///
    /// # Safety
    /// `pass` is NULL or `passlen` octets (a C string for -1); `p8inf` is a live PrivateKeyInfo;
    /// `pbe` is a live AlgorithmIdentifier; `ctx` is NULL or live; `propq` is NULL or a C string.
    pub unsafe extern "C" fn PKCS8_set0_pbe_ex(pass: *const c_char, passlen: c_int, p8inf: *mut PKCS8_PRIV_KEY_INFO, pbe: *mut X509_ALGOR, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: no preconditions.
        let it = unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_it() };
        // SAFETY: the caller's guarantee.
        let enckey = unsafe { PKCS12_item_i2d_encrypt_ex(pbe, it, pass, passlen, p8inf.cast(), 1, ctx, propq) };
        if enckey.is_null() {
            err::raise(ERR_LIB_PKCS12, PKCS12_R_ENCRYPT_ERROR, "PKCS8_set0_pbe_ex");
            return ptr::null_mut();
        }
        let p8: *mut crate::x509::sig::Sig = mem::zalloc(size_of::<crate::x509::sig::Sig>(), ptr::null(), 0).cast();
        // SAFETY: made above, or NULL.
        let Some(s) = (unsafe { p8.as_mut() }) else {
            // SAFETY: made above.
            unsafe { crate::asn1::string::ASN1_STRING_free(enckey) };
            return ptr::null_mut();
        };
        s.algor = pbe;
        s.digest = enckey;
        p8.cast()
    }
}

ffi_export! {
    /// `PKCS8_set0_pbe_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS8_set0_pbe_ex`.
    pub unsafe extern "C" fn PKCS8_set0_pbe(pass: *const c_char, passlen: c_int, p8inf: *mut PKCS8_PRIV_KEY_INFO, pbe: *mut X509_ALGOR) -> *mut X509_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS8_set0_pbe_ex(pass, passlen, p8inf, pbe, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The PrivateKeyInfo encrypted with the password as an EncryptedPrivateKeyInfo: PBES2 of
    /// `cipher` for `pbe_nid` -1 (or a PRF's NID), else the PBE algorithm `pbe_nid`, with the
    /// salt and iterations (defaults for none). NULL on failure.
    ///
    /// # Safety
    /// As for `PKCS8_set0_pbe_ex`; `cipher` is NULL or live; `salt` is NULL or `saltlen` octets.
    pub unsafe extern "C" fn PKCS8_encrypt_ex(pbe_nid: c_int, cipher: *const EVP_CIPHER, pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, iter: c_int, p8inf: *mut PKCS8_PRIV_KEY_INFO, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut X509_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        use crate::x509::pbe::{PKCS5_pbe2_set_iv_ex, PKCS5_pbe_set_ex};
        const F: &str = "PKCS8_encrypt_ex";
        let pbe = if pbe_nid == -1 {
            if cipher.is_null() {
                err::raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER, F);
                return ptr::null_mut();
            }
            // SAFETY: the caller's guarantee.
            unsafe { PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, ptr::null_mut(), -1, libctx) }
        } else {
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
            // SAFETY: no outputs.
            if unsafe { crate::evp::pbe::EVP_PBE_find(EVP_PBE_TYPE_PRF, pbe_nid, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()) } != 0 {
                // SAFETY: the mark set above.
                unsafe { ERR_clear_last_mark() };
                if cipher.is_null() {
                    err::raise(ERR_LIB_PKCS12, ERR_R_PASSED_NULL_PARAMETER, F);
                    return ptr::null_mut();
                }
                // SAFETY: the caller's guarantee.
                unsafe { PKCS5_pbe2_set_iv_ex(cipher, iter, salt, saltlen, ptr::null_mut(), pbe_nid, libctx) }
            } else {
                // SAFETY: the mark set above.
                unsafe { ERR_pop_to_mark() };
                // SAFETY: the caller's guarantee.
                unsafe { PKCS5_pbe_set_ex(pbe_nid, iter, salt, saltlen, libctx) }
            }
        };
        if pbe.is_null() {
            err::raise(ERR_LIB_PKCS12, ERR_R_ASN1_LIB, F);
            return ptr::null_mut();
        }
        // SAFETY: the caller's guarantee; the new AlgorithmIdentifier.
        let p8 = unsafe { PKCS8_set0_pbe_ex(pass, passlen, p8inf, pbe, libctx, propq) };
        if p8.is_null() {
            // SAFETY: not taken.
            unsafe { crate::asn1::tpl::items::X509_ALGOR_free(pbe) };
        }
        p8
    }
}

ffi_export! {
    /// `PKCS8_encrypt_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS8_encrypt_ex`.
    pub unsafe extern "C" fn PKCS8_encrypt(pbe_nid: c_int, cipher: *const EVP_CIPHER, pass: *const c_char, passlen: c_int, salt: *mut c_uchar, saltlen: c_int, iter: c_int, p8inf: *mut PKCS8_PRIV_KEY_INFO) -> *mut X509_SIG
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS8_encrypt_ex(pbe_nid, cipher, pass, passlen, salt, saltlen, iter, p8inf, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// The EncryptedPrivateKeyInfo decrypted with the password: its PrivateKeyInfo, or NULL.
    ///
    /// # Safety
    /// `p8` is a live `X509_SIG`; `pass` as for `PKCS8_encrypt_ex`; `ctx` and `propq` as for
    /// the fetches.
    pub unsafe extern "C" fn PKCS8_decrypt_ex(p8: *const X509_SIG, pass: *const c_char, passlen: c_int, ctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut PKCS8_PRIV_KEY_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee; an `X509_SIG` is a `Sig`.
        let Some(s) = (unsafe { p8.cast::<crate::x509::sig::Sig>().as_ref() }) else { return ptr::null_mut() };
        // SAFETY: no preconditions.
        let it = unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_it() };
        // SAFETY: the structure's fields; the caller's password.
        unsafe { PKCS12_item_decrypt_d2i_ex(s.algor, it, pass, passlen, s.digest, 1, ctx, propq) }.cast()
    }
}

ffi_export! {
    /// `PKCS8_decrypt_ex` with the default library context.
    ///
    /// # Safety
    /// As for `PKCS8_decrypt_ex`.
    pub unsafe extern "C" fn PKCS8_decrypt(p8: *const X509_SIG, pass: *const c_char, passlen: c_int) -> *mut PKCS8_PRIV_KEY_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PKCS12
    {
        // SAFETY: the caller's guarantee.
        unsafe { PKCS8_decrypt_ex(p8, pass, passlen, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Reads an EncryptedPrivateKeyInfo from the BIO and decrypts it with the password `cb`
    /// gives (`PEM_def_callback`'s for none): the key (also into `*x`, freeing the one there),
    /// or NULL.
    ///
    /// # Safety
    /// `bp` is a live BIO; `x` is NULL or holds NULL or a live key; `cb` is NULL or a callback
    /// taking `u`.
    pub unsafe extern "C" fn d2i_PKCS8PrivateKey_bio(bp: *mut rustyssl_abi::BIO, x: *mut *mut rustyssl_abi::EVP_PKEY, cb: rustyssl_abi::pem_password_cb, u: *mut c_void) -> *mut rustyssl_abi::EVP_PKEY
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_PEM
    {
        use rustyssl_abi::{PEM_BUFSIZE, PEM_R_BAD_PASSWORD_READ};
        // SAFETY: the caller's BIO.
        let p8 = unsafe { crate::x509::sig::d2i_PKCS8_bio(bp, ptr::null_mut()) };
        if p8.is_null() {
            return ptr::null_mut();
        }
        let mut psbuf = rustyssl_crypto::bn::Zeroizing::new([0 as c_char; PEM_BUFSIZE as usize + 1]);
        let f = cb.unwrap_or(crate::pem_cipher::PEM_def_callback);
        // SAFETY: the callback with room for `PEM_BUFSIZE`.
        let klen = unsafe { f(psbuf.as_mut_ptr(), PEM_BUFSIZE, 0, u) };
        if !(0..=PEM_BUFSIZE).contains(&klen) {
            err::raise(rustyssl_abi::ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, "d2i_PKCS8PrivateKey_bio");
            // SAFETY: decoded above.
            unsafe { crate::x509::sig::X509_SIG_free(p8) };
            return ptr::null_mut();
        }
        // SAFETY: the structure; the password.
        let p8inf = unsafe { PKCS8_decrypt(p8, psbuf.as_ptr(), klen) };
        // SAFETY: decoded above.
        unsafe { crate::x509::sig::X509_SIG_free(p8) };
        if p8inf.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the decrypted PrivateKeyInfo.
        let ret = unsafe { crate::evp::pkey::d2i::EVP_PKCS82PKEY(p8inf) };
        // SAFETY: as above.
        unsafe { crate::x509::p8::PKCS8_PRIV_KEY_INFO_free(p8inf) };
        if ret.is_null() {
            return ret;
        }
        if !x.is_null() {
            // SAFETY: the caller's slot and its old key.
            let old = unsafe { x.read() };
            // SAFETY: the caller's old key, or NULL.
            unsafe { crate::evp::pkey::EVP_PKEY_free(old) };
            // SAFETY: as above.
            unsafe { x.write(ret) };
        }
        ret
    }
}

ffi_export! {
    /// `d2i_PKCS8PrivateKey_bio` from a `FILE`.
    ///
    /// # Safety
    /// `fp` is an open `FILE`; otherwise as for `d2i_PKCS8PrivateKey_bio`.
    pub unsafe extern "C" fn d2i_PKCS8PrivateKey_fp(fp: *mut libc::FILE, x: *mut *mut rustyssl_abi::EVP_PKEY, cb: rustyssl_abi::pem_password_cb, u: *mut c_void) -> *mut rustyssl_abi::EVP_PKEY
    where failure = ptr::null_mut(), library = rustyssl_abi::ERR_LIB_PEM
    {
        // SAFETY: the caller's `FILE`.
        let bp = unsafe { crate::bio::file::BIO_new_fp(fp, rustyssl_abi::BIO_NOCLOSE) };
        if bp.is_null() {
            err::raise(rustyssl_abi::ERR_LIB_PEM, rustyssl_abi::ERR_R_BUF_LIB, "d2i_PKCS8PrivateKey_fp");
            return ptr::null_mut();
        }
        // SAFETY: the BIO; the caller's guarantee.
        let ret = unsafe { d2i_PKCS8PrivateKey_bio(bp, x, cb, u) };
        // SAFETY: made above.
        unsafe { crate::bio::BIO_free(bp) };
        ret
    }
}
