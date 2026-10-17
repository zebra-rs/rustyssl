//! Encrypted PEM (`pem_lib.c`): a header's `Proc-Type`/`DEK-Info` read into an
//! `EVP_CIPHER_INFO` (`PEM_get_EVP_CIPHER_INFO`), the body decrypted in place under a password
//! (`PEM_do_header`), and a DER value written as PEM, encrypted or not (`PEM_ASN1_write`,
//! `_bio`, `_bio_ctx`). The key is OpenSSL's `EVP_BytesToKey` with MD5, one round, and the IV's
//! first 8 octets as the salt; the password comes from `kstr`, the callback, or
//! `PEM_def_callback` (the caller's data as the password, else a prompt).
//!
//! As the reference does, these run over the EVP API on the caller's buffers. The random IV
//! comes from the operating system until the library's generators (3.7).

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    BIO, CRYPTO_R_INVALID_NULL_ARGUMENT, ERR_LIB_CRYPTO, ERR_LIB_PEM, ERR_R_ASN1_LIB, EVP_CIPHER,
    EVP_CIPHER_INFO, EVP_MAX_BLOCK_LENGTH, EVP_MAX_IV_LENGTH, EVP_MAX_KEY_LENGTH,
    OSSL_i2d_of_void_ctx, PEM_BUFSIZE, PEM_R_BAD_DECRYPT, PEM_R_BAD_IV_CHARS,
    PEM_R_BAD_PASSWORD_READ, PEM_R_HEADER_TOO_LONG, PEM_R_MISSING_DEK_IV, PEM_R_NOT_DEK_INFO,
    PEM_R_NOT_ENCRYPTED, PEM_R_NOT_PROC_TYPE, PEM_R_READ_KEY, PEM_R_SHORT_HEADER,
    PEM_R_UNEXPECTED_DEK_IV, PEM_R_UNSUPPORTED_CIPHER, PEM_R_UNSUPPORTED_ENCRYPTION,
    PEM_TYPE_ENCRYPTED, i2d_of_void, pem_password_cb,
};

use crate::bio;
use crate::err;
use crate::evp::cipher::{EVP_CIPHER_get_iv_length, EVP_CIPHER_get0_name};
use crate::evp::cipher_ctx::{
    EVP_CIPHER_CTX_free, EVP_CIPHER_CTX_new, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
    EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate,
};
use crate::evp::key::EVP_BytesToKey;
use crate::evp::legacy_cipher::EVP_get_cipherbyname;
use crate::evp::legacy_md::EVP_md5;
use crate::ffi::ffi_export;
use crate::mem;
use crate::pem::{PEM_dek_info, PEM_proc_type, PEM_write_bio, file_bio};
use crate::string::OPENSSL_hexchar2int;

/// Zeroes `b` (`OPENSSL_cleanse`).
fn wipe(b: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { crate::mem::OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) };
}

/// `PEM_BUFSIZE`, the password buffer's size.
const BUFSIZE: usize = PEM_BUFSIZE as usize;
const MAX_IV: usize = EVP_MAX_IV_LENGTH as usize;
const MAX_KEY: usize = EVP_MAX_KEY_LENGTH as usize;

ffi_export! {
    /// The default password callback: `userdata` as a string, cut to `num` octets, copied into
    /// `buf`; with no `userdata`, a prompt on the terminal (`EVP_read_pw_string_min`). Returns
    /// the password's length, or -1.
    ///
    /// # Safety
    /// `buf` has room for `num` octets; `userdata` is NULL or a string.
    pub unsafe extern "C" fn PEM_def_callback(buf: *mut c_char, num: c_int, rwflag: c_int, userdata: *mut c_void) -> c_int
    where failure = -1, library = ERR_LIB_PEM
    {
        if userdata.is_null() {
            // `MIN_LENGTH`: a password to encrypt with has at least 4 characters.
            const MIN_LENGTH: c_int = 4;
            // SAFETY: no preconditions.
            let mut prompt = unsafe { crate::ui::EVP_get_pw_prompt() }.cast_const();
            if prompt.is_null() {
                prompt = c"Enter PEM pass phrase:".as_ptr();
            }
            let min_len = if rwflag != 0 { MIN_LENGTH } else { 0 };
            // SAFETY: the caller's room for `num` octets; the prompt.
            if unsafe { crate::ui::EVP_read_pw_string_min(buf, min_len, num, prompt, rwflag) } != 0 {
                err::raise(ERR_LIB_PEM, rustyssl_abi::PEM_R_PROBLEMS_GETTING_PASSWORD, "PEM_def_callback");
                // SAFETY: as above.
                unsafe { ptr::write_bytes(buf, 0, usize::try_from(num).unwrap_or(0)) };
                return -1;
            }
            // SAFETY: the UI's result, a C string in the caller's buffer.
            return c_int::try_from(unsafe { CStr::from_ptr(buf) }.count_bytes()).unwrap_or(-1);
        }
        // SAFETY: the caller's guarantee: a string.
        let len = unsafe { CStr::from_ptr(userdata.cast::<c_char>()) }.count_bytes();
        let n = len.min(usize::try_from(num).unwrap_or(0));
        // SAFETY: the caller's guarantees: `n` octets of the string, room for `num` in `buf`.
        unsafe { ptr::copy_nonoverlapping(userdata.cast::<c_char>(), buf, n) };
        c_int::try_from(n).unwrap_or(-1)
    }
}

/// The password: from `callback`, or `PEM_def_callback`, into `buf`.
///
/// # Safety
/// `callback` is the caller's, taking `u`.
unsafe fn password(
    buf: &mut [u8; BUFSIZE],
    rwflag: c_int,
    callback: pem_password_cb,
    u: *mut c_void,
) -> c_int {
    let f = callback.unwrap_or(PEM_def_callback);
    // SAFETY: the caller's callback (or the default) with a buffer of its size.
    unsafe { f(buf.as_mut_ptr().cast(), PEM_BUFSIZE, rwflag, u) }
}

/// `load_iv`: `num` octets from `2 * num` hex digits at `from`.
fn load_iv(from: &[u8], to: &mut [u8], num: usize) -> bool {
    to.iter_mut().take(num).for_each(|b| *b = 0);
    for i in 0..num.saturating_mul(2) {
        let c = from.get(i).copied().unwrap_or(0);
        // SAFETY: no preconditions.
        let v = unsafe { OPENSSL_hexchar2int(c) };
        let Ok(v) = u8::try_from(v) else {
            err::raise(ERR_LIB_PEM, PEM_R_BAD_IV_CHARS, "load_iv");
            return false;
        };
        if let Some(b) = to.get_mut(i / 2) {
            *b |= if i % 2 == 0 { v << 4 } else { v };
        }
    }
    true
}

/// Skips the octets of `s` in `set`.
fn skip<'a>(s: &'a [u8], set: &[u8]) -> &'a [u8] {
    let n = s.iter().take_while(|c| set.contains(c)).count();
    s.get(n..).unwrap_or_default()
}

ffi_export! {
    /// Reads a PEM header's `Proc-Type: 4,ENCRYPTED` and `DEK-Info: cipher,hex-IV` into
    /// `cipher` (its cipher NULL for an empty header). Returns 1, or 0.
    ///
    /// # Safety
    /// `header` is NULL or a string; `cipher` is a writable `EVP_CIPHER_INFO`.
    pub unsafe extern "C" fn PEM_get_EVP_CIPHER_INFO(header: *mut c_char, cipher: *mut EVP_CIPHER_INFO) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        const F: &str = "PEM_get_EVP_CIPHER_INFO";
        // SAFETY: the caller's guarantee.
        let Some(cipher) = (unsafe { cipher.as_mut() }) else { return 0 };
        cipher.cipher = ptr::null();
        cipher.iv = [0; MAX_IV];
        if header.is_null() {
            return 1;
        }
        // SAFETY: the caller's guarantee: a string.
        let h = unsafe { CStr::from_ptr(header) }.to_bytes();
        if matches!(h.first(), None | Some(b'\n')) {
            return 1;
        }
        let Some(h) = h.strip_prefix(b"Proc-Type:") else {
            err::raise(ERR_LIB_PEM, PEM_R_NOT_PROC_TYPE, F);
            return 0;
        };
        let h = skip(h, b" \t");
        let Some(h) = h.strip_prefix(b"4,") else { return 0 };
        let h = skip(h, b" \t");
        let h = match h.strip_prefix(b"ENCRYPTED") {
            Some(rest) if rest.first().is_some_and(|c| b" \t\r\n".contains(c)) => rest,
            _ => {
                err::raise(ERR_LIB_PEM, PEM_R_NOT_ENCRYPTED, F);
                return 0;
            }
        };
        let h = skip(h, b" \t\r");
        let Some(h) = h.strip_prefix(b"\n") else {
            err::raise(ERR_LIB_PEM, PEM_R_SHORT_HEADER, F);
            return 0;
        };
        let Some(h) = h.strip_prefix(b"DEK-Info:") else {
            err::raise(ERR_LIB_PEM, PEM_R_NOT_DEK_INFO, F);
            return 0;
        };
        let h = skip(h, b" \t");
        let n = h.iter().take_while(|c| !b" \t,".contains(c)).count();
        let (name, h) = h.split_at(n);
        // The name as a string of its own (the reference ends it in the header for a moment).
        let mut name = name.to_vec();
        name.push(0);
        // SAFETY: a string.
        let enc = unsafe { EVP_get_cipherbyname(name.as_ptr().cast()) };
        cipher.cipher = enc;
        let h = skip(h, b" \t");
        if enc.is_null() {
            err::raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_ENCRYPTION, F);
            return 0;
        }
        // SAFETY: a static cipher.
        let ivlen = unsafe { EVP_CIPHER_get_iv_length(enc) };
        let h = if ivlen > 0 {
            let Some(rest) = h.strip_prefix(b",") else {
                err::raise(ERR_LIB_PEM, PEM_R_MISSING_DEK_IV, F);
                return 0;
            };
            rest
        } else if h.first() == Some(&b',') {
            err::raise(ERR_LIB_PEM, PEM_R_UNEXPECTED_DEK_IV, F);
            return 0;
        } else {
            h
        };
        let num = usize::try_from(ivlen).unwrap_or(0).min(MAX_IV);
        c_int::from(load_iv(h, &mut cipher.iv, num))
    }
}

ffi_export! {
    /// Decrypts `*plen` octets at `data` in place as `cipher` says (doing nothing for no
    /// cipher), under the password from `callback` (`PEM_def_callback` for NULL) given `u`,
    /// setting `*plen` to the plaintext's length. Returns 1, or 0.
    ///
    /// # Safety
    /// `cipher` is a live `EVP_CIPHER_INFO`; `data` holds `*plen` writable octets; `plen` is
    /// valid; `callback` is NULL or callable with `u`.
    pub unsafe extern "C" fn PEM_do_header(cipher: *mut EVP_CIPHER_INFO, data: *mut c_uchar, plen: *mut c_long, callback: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        const F: &str = "PEM_do_header";
        // SAFETY: the caller's guarantee.
        let (Some(info), Some(len)) = (unsafe { cipher.as_ref() }, unsafe { plen.as_ref() }) else {
            return 0;
        };
        let len = *len;
        let Ok(mut ilen) = c_int::try_from(len) else {
            err::raise(ERR_LIB_PEM, PEM_R_HEADER_TOO_LONG, F);
            return 0;
        };
        if info.cipher.is_null() {
            return 1;
        }
        let mut buf = [0u8; BUFSIZE];
        // SAFETY: the caller's callback and data.
        let keylen = unsafe { password(&mut buf, 0, callback, u) };
        if keylen < 0 {
            err::raise(ERR_LIB_PEM, PEM_R_BAD_PASSWORD_READ, F);
            return 0;
        }
        let mut key = [0u8; MAX_KEY];
        let iv = info.iv;
        // SAFETY: no preconditions.
        let md5 = unsafe { EVP_md5() };
        // SAFETY: a static cipher and digest; the IV's first 8 octets as the salt; the
        // password of `keylen` octets; room for the key.
        let derived = unsafe {
            EVP_BytesToKey(info.cipher, md5, iv.as_ptr(), buf.as_ptr(), keylen, 1, key.as_mut_ptr(), ptr::null_mut())
        };
        let mut ok = 0;
        if derived != 0 {
            // SAFETY: no preconditions.
            let ctx = unsafe { EVP_CIPHER_CTX_new() };
            if !ctx.is_null() {
                // SAFETY: a live context, the cipher, the key and IV derived.
                ok = unsafe { EVP_DecryptInit_ex(ctx, info.cipher, ptr::null_mut(), key.as_ptr(), iv.as_ptr()) };
                if ok != 0 {
                    // SAFETY: the caller's data, in place, `ilen` octets.
                    ok = unsafe { EVP_DecryptUpdate(ctx, data, &raw mut ilen, data, ilen) };
                }
                if ok != 0 {
                    // SAFETY: as above.
                    unsafe { plen.write(c_long::from(ilen)) };
                    let at = usize::try_from(ilen).unwrap_or(0);
                    // SAFETY: the rest of the caller's data, where the last block goes.
                    ok = unsafe { EVP_DecryptFinal_ex(ctx, data.wrapping_add(at), &raw mut ilen) };
                }
                if ok != 0 {
                    // SAFETY: as above.
                    let so_far = unsafe { len_now(plen) };
                    // SAFETY: as above.
                    unsafe { plen.write(c_long::from(ilen).saturating_add(so_far)) };
                } else {
                    err::raise(ERR_LIB_PEM, PEM_R_BAD_DECRYPT, F);
                }
                // SAFETY: the context made here.
                unsafe { EVP_CIPHER_CTX_free(ctx) };
            }
        }
        wipe(&mut buf);
        wipe(&mut key);
        ok
    }
}

/// `*plen` as it is now.
///
/// # Safety
/// `plen` is valid.
unsafe fn len_now(plen: *const c_long) -> c_long {
    // SAFETY: the caller's guarantee.
    unsafe { plen.read() }
}

/// The encoding through `i2d` or `i2d_ctx` (`PEM_ASN1_write_bio_internal`).
#[derive(Clone, Copy)]
enum Encoder {
    Plain(i2d_of_void),
    Ctx(OSSL_i2d_of_void_ctx, *mut c_void),
}

impl Encoder {
    /// The encoding's length (for a NULL `out`), or the encoding written at `*out`.
    ///
    /// # Safety
    /// The caller's function takes `x` (and its context).
    unsafe fn run(self, x: *const c_void, out: *mut *mut c_uchar) -> c_int {
        match self {
            // SAFETY: the caller's guarantee.
            Self::Plain(Some(f)) => unsafe { f(x, out) },
            // SAFETY: as above.
            Self::Ctx(Some(f), vctx) => unsafe { f(x, out, vctx) },
            _ => 0,
        }
    }

    fn is_none(self) -> bool {
        matches!(self, Self::Plain(None) | Self::Ctx(None, _))
    }
}

/// `PEM_ASN1_write_bio_internal`: `x`'s DER as a PEM `name` to `bp`, encrypted with `enc`
/// under `kstr` (or the callback's password) if `enc` isn't NULL.
///
/// # Safety
/// As for `PEM_ASN1_write_bio`.
#[allow(clippy::too_many_arguments)]
unsafe fn write_bio_internal(
    encoder: Encoder,
    name: *const c_char,
    bp: *mut BIO,
    x: *const c_void,
    enc: *const EVP_CIPHER,
    (kstr, klen): (*const c_uchar, c_int),
    callback: pem_password_cb,
    u: *mut c_void,
) -> c_int {
    const F: &str = "PEM_ASN1_write_bio_internal";
    let mut buf = [0u8; BUFSIZE];
    let mut key = [0u8; MAX_KEY];
    let mut iv = [0u8; MAX_IV];
    let mut objstr: *const c_char = ptr::null();
    let mut ivlen = 0;
    if !enc.is_null() {
        // SAFETY: the caller's cipher.
        objstr = unsafe { EVP_CIPHER_get0_name(enc) };
        // SAFETY: as above.
        ivlen = unsafe { EVP_CIPHER_get_iv_length(enc) };
        // "Proc-Type: 4,ENCRYPTED\nDEK-Info: " objstr "," hex-IV "\n" must fit `buf`.
        let fits = !objstr.is_null()
            && usize::try_from(ivlen).is_ok_and(|n| (1..=MAX_IV).contains(&n))
            && {
                // SAFETY: the cipher's name.
                let n = unsafe { CStr::from_ptr(objstr) }.count_bytes();
                n + 23 + 2 * usize::try_from(ivlen).unwrap_or(0) + 13 <= BUFSIZE
            };
        if !fits {
            err::raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_CIPHER, F);
            return 0;
        }
    }
    if encoder.is_none() {
        err::raise(ERR_LIB_CRYPTO, CRYPTO_R_INVALID_NULL_ARGUMENT, F);
        return 0;
    }
    // SAFETY: the caller's encoder and value.
    let dsize = unsafe { encoder.run(x, ptr::null_mut()) };
    let Some(size) = usize::try_from(dsize).ok().filter(|&n| n > 0) else {
        err::raise(ERR_LIB_PEM, ERR_R_ASN1_LIB, F);
        return 0;
    };
    // Room for one more cipher block.
    let room = size.saturating_add(EVP_MAX_BLOCK_LENGTH as usize);
    let data: *mut c_uchar = mem::alloc(room).cast();
    if data.is_null() {
        return 0;
    }
    let mut p = data;
    // SAFETY: as above, with room for the encoding.
    let mut i = unsafe { encoder.run(x, &raw mut p) };
    let mut ret = 0;
    'out: {
        if !enc.is_null() {
            let (kstr, klen) = if kstr.is_null() {
                // SAFETY: the caller's callback and data.
                let n = unsafe { password(&mut buf, 1, callback, u) };
                if n <= 0 {
                    err::raise(ERR_LIB_PEM, PEM_R_READ_KEY, F);
                    break 'out;
                }
                (buf.as_ptr(), n)
            } else {
                (kstr, klen)
            };
            let n = usize::try_from(ivlen).unwrap_or(0);
            // The salt and IV, from `RAND_bytes`.
            let iv_part = iv.get_mut(..n).unwrap_or_default();
            // SAFETY: room for the IV's octets.
            if unsafe {
                crate::rand_lib::RAND_bytes(iv_part.as_mut_ptr(), c_int::try_from(n).unwrap_or(0))
            } <= 0
            {
                break 'out;
            }
            // SAFETY: no preconditions.
            let md5 = unsafe { EVP_md5() };
            // SAFETY: the cipher; MD5; the IV's first 8 octets as the salt; the password;
            // room for the key.
            if unsafe {
                EVP_BytesToKey(
                    enc,
                    md5,
                    iv.as_ptr(),
                    kstr,
                    klen,
                    1,
                    key.as_mut_ptr(),
                    ptr::null_mut(),
                )
            } == 0
            {
                break 'out;
            }
            wipe(&mut buf);
            // SAFETY: `buf` is a string buffer of its size; the cipher's name; the IV.
            unsafe {
                PEM_proc_type(buf.as_mut_ptr().cast(), PEM_TYPE_ENCRYPTED as c_int);
            }
            // SAFETY: as above.
            unsafe { PEM_dek_info(buf.as_mut_ptr().cast(), objstr, ivlen, iv.as_ptr().cast()) };
            // SAFETY: no preconditions.
            let ctx = unsafe { EVP_CIPHER_CTX_new() };
            let mut j = 0;
            let ok = !ctx.is_null()
                // SAFETY: a live context, the cipher, the key and IV.
                && unsafe { EVP_EncryptInit_ex(ctx, enc, ptr::null_mut(), key.as_ptr(), iv.as_ptr()) } != 0
                // SAFETY: the encoding, in place, with a block's room after it.
                && unsafe { EVP_EncryptUpdate(ctx, data, &raw mut j, data, i) } != 0
                // SAFETY: as above.
                && unsafe { EVP_EncryptFinal_ex(ctx, data.wrapping_add(usize::try_from(j).unwrap_or(0)), &raw mut i) } != 0;
            // SAFETY: the context made here, or NULL.
            unsafe { EVP_CIPHER_CTX_free(ctx) };
            if !ok {
                break 'out;
            }
            i = i.saturating_add(j);
        }
        ret = 1;
        // SAFETY: the caller's BIO and name; the header in `buf`; the data.
        if unsafe { PEM_write_bio(bp, name, buf.as_ptr().cast(), data, c_long::from(i)) } <= 0 {
            ret = 0;
        }
    }
    wipe(&mut key);
    wipe(&mut iv);
    wipe(&mut buf);
    // SAFETY: from `mem::alloc`, `room` octets.
    unsafe { mem::release_clean(data.cast(), room) };
    ret
}

ffi_export! {
    /// Writes `x`, encoded by `i2d`, as PEM `name` to `bp`; encrypted with `enc` (not NULL)
    /// under `klen` octets of `kstr`, or else the password from `callback`
    /// (`PEM_def_callback` for NULL) given `u`. Returns 1, or 0.
    ///
    /// # Safety
    /// `i2d` is NULL or encodes `x`; `name` is a string; `bp` is a live BIO; `enc` is NULL or
    /// a live cipher; `kstr` is NULL or holds `klen` octets; `callback` is NULL or callable
    /// with `u`.
    pub unsafe extern "C" fn PEM_ASN1_write_bio(i2d: i2d_of_void, name: *const c_char, bp: *mut BIO, x: *const c_void, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, callback: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_bio_internal(Encoder::Plain(i2d), name, bp, x, enc, (kstr, klen), callback, u) }
    }
}

ffi_export! {
    /// `PEM_ASN1_write_bio` with an encoder taking a context, `vctx`.
    ///
    /// # Safety
    /// As for `PEM_ASN1_write_bio`, with `i2d` taking `vctx`.
    pub unsafe extern "C" fn PEM_ASN1_write_bio_ctx(i2d: OSSL_i2d_of_void_ctx, vctx: *mut c_void, name: *const c_char, bp: *mut BIO, x: *const c_void, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, callback: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { write_bio_internal(Encoder::Ctx(i2d, vctx), name, bp, x, enc, (kstr, klen), callback, u) }
    }
}

ffi_export! {
    /// `PEM_ASN1_write_bio` to a `FILE`, which is left open.
    ///
    /// # Safety
    /// As for `PEM_ASN1_write_bio`, with `fp` an open `FILE`.
    pub unsafe extern "C" fn PEM_ASN1_write(i2d: i2d_of_void, name: *const c_char, fp: *mut FILE, x: *const c_void, enc: *const EVP_CIPHER, kstr: *const c_uchar, klen: c_int, callback: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { file_bio(fp, "PEM_ASN1_write") };
        if b.is_null() {
            return 0;
        }
        // SAFETY: as above.
        let ret = unsafe { PEM_ASN1_write_bio(i2d, name, b, x, enc, kstr, klen, callback, u) };
        // SAFETY: the BIO made above.
        unsafe { bio::BIO_free(b) };
        ret
    }
}
