//! PEM bundles (`pem_info.c`, `x_info.c`, `x_pkey.c`; `PEM_X509_INFO_read_bio_ex(3)`): a stream
//! of PEM blocks read into `X509_INFO`s, each a certificate, a CRL, and a private key that came
//! together, and one written back.
//!
//! As OpenSSL's:
//! - A block of a kind the current entry already has starts a new entry; other blocks are
//!   skipped.
//! - Certificates (`CERTIFICATE`, `X509 CERTIFICATE`, `TRUSTED CERTIFICATE`) are decoded into
//!   the library context; CRLs; and private keys of any `… PRIVATE KEY` block, typed by the name
//!   before it (`RSA`, `EC`, …) or detected. A key encrypted with PEM's own headers (or as an
//!   encrypted PKCS#8) is kept encrypted, with its cipher, rather than decrypted.
//! - Writing puts the key (only as RSA, or as kept encrypted) then the certificate.

use core::ffi::{CStr, c_char, c_int, c_long, c_uchar, c_void};
use core::ptr;

use libc::FILE;
use rustyssl_abi::{
    BIO, ERR_LIB_ASN1, ERR_LIB_PEM, ERR_R_ASN1_LIB, ERR_R_CRYPTO_LIB, EVP_CIPHER, EVP_CIPHER_INFO,
    EVP_PKEY_NONE, OSSL_LIB_CTX, PEM_BUFSIZE, PEM_R_CIPHER_IS_NULL, PEM_R_NO_START_LINE,
    PEM_R_UNSUPPORTED_CIPHER, PEM_STRING_PKCS8, PEM_STRING_PKCS8INF, PEM_STRING_RSA,
    PEM_STRING_X509, PEM_STRING_X509_CRL, PEM_STRING_X509_OLD, PEM_STRING_X509_TRUSTED,
    PEM_TYPE_ENCRYPTED, X509_INFO, X509_PKEY, pem_password_cb, stack_st_X509_INFO,
};

use super::cert::{X509_free, X509_new_ex, d2i_X509, d2i_X509_AUX};
use super::crl::{X509_CRL_free, d2i_X509_CRL};
use crate::asn1::string::{ASN1_OCTET_STRING_free, ASN1_OCTET_STRING_new};
use crate::asn1::tpl::items::{X509_ALGOR_free, X509_ALGOR_new};
use crate::err::{self, ERR_clear_last_mark, ERR_peek_last_error, ERR_pop_to_mark, ERR_set_mark};
use crate::evp::cipher::{EVP_CIPHER_get_iv_length, EVP_CIPHER_get0_name};
use crate::evp::pkey::EVP_PKEY_free;
use crate::evp::pkey::d2i::{d2i_AutoPrivateKey, d2i_PrivateKey_ex};
use crate::evp::pkey::rsa::EVP_PKEY_get0_RSA;
use crate::ffi::ffi_export;
use crate::mem;
use crate::pem::{PEM_dek_info, PEM_proc_type, PEM_read_bio, PEM_write_bio, file_bio};
use crate::pem_cipher::{PEM_do_header, PEM_get_EVP_CIPHER_INFO};
use crate::stack::{
    OPENSSL_sk_free, OPENSSL_sk_new_null, OPENSSL_sk_num, OPENSSL_sk_push, OPENSSL_sk_value,
};

ffi_export! {
    /// A new, empty `X509_PKEY` (with an empty AlgorithmIdentifier and OCTET STRING), or NULL.
    pub unsafe extern "C" fn X509_PKEY_new() -> *mut X509_PKEY
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        let p = mem::zalloc(core::mem::size_of::<X509_PKEY>(), ptr::null(), 0).cast::<X509_PKEY>();
        // SAFETY: new zeroed memory for one, or NULL.
        let Some(k) = (unsafe { p.as_mut() }) else { return ptr::null_mut() };
        // SAFETY: no preconditions.
        k.enc_algor = unsafe { X509_ALGOR_new() };
        // SAFETY: as above.
        k.enc_pkey = unsafe { ASN1_OCTET_STRING_new() };
        if k.enc_algor.is_null() || k.enc_pkey.is_null() {
            // SAFETY: made above.
            unsafe { X509_PKEY_free(p) };
            err::raise(ERR_LIB_ASN1, ERR_R_ASN1_LIB, "X509_PKEY_new");
            return ptr::null_mut();
        }
        p
    }
}

ffi_export! {
    /// Frees an `X509_PKEY` with its parts.
    ///
    /// # Safety
    /// `x` is NULL or a live `X509_PKEY` from `X509_PKEY_new`.
    pub unsafe extern "C" fn X509_PKEY_free(x: *mut X509_PKEY)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(k) = (unsafe { x.as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { X509_ALGOR_free(k.enc_algor) };
        // SAFETY: as above.
        unsafe { ASN1_OCTET_STRING_free(k.enc_pkey) };
        // SAFETY: as above.
        unsafe { EVP_PKEY_free(k.dec_pkey) };
        if k.key_free != 0 {
            // SAFETY: as above.
            unsafe { mem::release(k.key_data.cast()) };
        }
        // SAFETY: made by `X509_PKEY_new`.
        unsafe { mem::release(x.cast()) };
    }
}

ffi_export! {
    /// A new, empty `X509_INFO`, or NULL.
    pub unsafe extern "C" fn X509_INFO_new() -> *mut X509_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_ASN1
    {
        mem::zalloc(core::mem::size_of::<X509_INFO>(), ptr::null(), 0).cast()
    }
}

ffi_export! {
    /// Frees an `X509_INFO` with what it holds.
    ///
    /// # Safety
    /// `x` is NULL or a live `X509_INFO`.
    pub unsafe extern "C" fn X509_INFO_free(x: *mut X509_INFO)
    where failure = (), library = ERR_LIB_ASN1
    {
        // SAFETY: the caller's guarantee.
        let Some(i) = (unsafe { x.as_mut() }) else { return };
        // SAFETY: its own, or NULL.
        unsafe { X509_free(i.x509) };
        // SAFETY: as above.
        unsafe { X509_CRL_free(i.crl) };
        // SAFETY: as above.
        unsafe { X509_PKEY_free(i.x_pkey) };
        // SAFETY: as above.
        unsafe { mem::release(i.enc_data.cast()) };
        // SAFETY: made by `X509_INFO_new`.
        unsafe { mem::release(x.cast()) };
    }
}

/// What a block's name makes of it.
enum Kind {
    Cert { trusted: bool },
    Crl,
    Key { type_: c_int, raw: bool },
    Other,
}

/// The kind of the block `name` (with its `header`).
fn kind(name: &[u8], header: &[u8]) -> Kind {
    let is = |s: &CStr| name == s.to_bytes();
    if is(PEM_STRING_X509) || is(PEM_STRING_X509_OLD) || is(PEM_STRING_X509_TRUSTED) {
        return Kind::Cert {
            trusted: is(PEM_STRING_X509_TRUSTED),
        };
    }
    if is(PEM_STRING_X509_CRL) {
        return Kind::Crl;
    }
    let inf = PEM_STRING_PKCS8INF.to_bytes();
    if let Some(at) = name.windows(inf.len()).position(|w| w == inf) {
        let pkcs8 = is(PEM_STRING_PKCS8);
        // As OpenSSL's, the name ends just before `PRIVATE KEY` (its last character dropped).
        let type_ = if at == 0 || pkcs8 {
            EVP_PKEY_NONE
        } else {
            crate::evp::pkey::ameth::name2type(name.get(..at.saturating_sub(1)).unwrap_or_default())
        };
        return Kind::Key {
            type_,
            raw: header.len() > 10 || pkcs8,
        };
    }
    Kind::Other
}

/// Frees the entries of a list (not the list).
///
/// # Safety
/// `sk` is a live stack of `X509_INFO`s.
unsafe fn free_entries(sk: *mut stack_st_X509_INFO) {
    // SAFETY: the caller's guarantee.
    for i in 0..unsafe { OPENSSL_sk_num(sk.cast()) } {
        // SAFETY: an index within it.
        let x = unsafe { OPENSSL_sk_value(sk.cast(), i) };
        // SAFETY: an entry it held.
        unsafe { X509_INFO_free(x.cast()) };
    }
}

/// The block's buffers, freed together.
struct Block {
    name: *mut c_char,
    header: *mut c_char,
    data: *mut c_uchar,
}

impl Block {
    fn free(&mut self) {
        // SAFETY: from `PEM_read_bio`, or NULL.
        unsafe { mem::release(self.name.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(self.header.cast()) };
        // SAFETY: as above.
        unsafe { mem::release(self.data.cast()) };
        self.name = ptr::null_mut();
        self.header = ptr::null_mut();
        self.data = ptr::null_mut();
    }
}

/// The text of a C string, or none.
///
/// # Safety
/// `s` is NULL or a C string.
unsafe fn text<'a>(s: *const c_char) -> &'a [u8] {
    if s.is_null() {
        &[]
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { CStr::from_ptr(s) }.to_bytes()
    }
}

/// The passphrase callback and library context blocks are read with.
#[derive(Clone, Copy)]
struct How {
    cb: pem_password_cb,
    u: *mut c_void,
    libctx: *mut OSSL_LIB_CTX,
    propq: *const c_char,
}

/// `PEM_X509_INFO_read_bio_ex`'s loop: reads blocks into `ret` until the stream's PEM ends.
///
/// # Safety
/// As for [`PEM_X509_INFO_read_bio_ex`]; `ret` is a live list; `xi` holds a live entry.
unsafe fn read_blocks(
    bp: *mut BIO,
    ret: *mut stack_st_X509_INFO,
    xi: &mut *mut X509_INFO,
    b: &mut Block,
    how: &How,
) -> bool {
    let How {
        cb,
        u,
        libctx,
        propq,
    } = *how;
    loop {
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        let mut len: c_long = 0;
        // SAFETY: the caller's BIO; the block's slots.
        if unsafe {
            PEM_read_bio(
                bp,
                &raw mut b.name,
                &raw mut b.header,
                &raw mut b.data,
                &raw mut len,
            )
        } == 0
        {
            // SAFETY: no preconditions.
            let reason = err::reason_of(unsafe { ERR_peek_last_error() });
            if reason == PEM_R_NO_START_LINE {
                // SAFETY: as above.
                unsafe { ERR_pop_to_mark() };
                return true;
            }
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            return false;
        }
        // SAFETY: as above.
        unsafe { ERR_clear_last_mark() };
        // SAFETY: from `PEM_read_bio`.
        let name = unsafe { text(b.name) };
        // SAFETY: as above.
        let header = unsafe { text(b.header) };
        let k = kind(name, header);
        loop {
            // SAFETY: the current entry.
            let x = unsafe { &mut **xi };
            let full = match k {
                Kind::Cert { .. } => !x.x509.is_null(),
                Kind::Crl => !x.crl.is_null(),
                Kind::Key { .. } => !x.x_pkey.is_null(),
                Kind::Other => false,
            };
            if !full {
                break;
            }
            // SAFETY: the list; the entry, which it takes.
            if unsafe { OPENSSL_sk_push(ret.cast(), (*xi).cast()) } == 0 {
                return false;
            }
            // SAFETY: no preconditions.
            *xi = unsafe { X509_INFO_new() };
            if xi.is_null() {
                return false;
            }
        }
        // SAFETY: the current entry.
        let x = unsafe { &mut **xi };
        let mut p = b.data.cast_const();
        match k {
            Kind::Cert { trusted } => {
                // SAFETY: the caller's library context and properties.
                x.x509 = unsafe { X509_new_ex(libctx, propq) };
                if x.x509.is_null() {
                    return false;
                }
                // SAFETY: the block.
                if !unsafe { decrypt(b, &mut len, cb, u) } {
                    return false;
                }
                let r = if trusted {
                    // SAFETY: the decoded block's octets; the entry's certificate, decoded into.
                    unsafe { d2i_X509_AUX(&raw mut x.x509, &raw mut p, len) }
                } else {
                    // SAFETY: as above.
                    unsafe { d2i_X509(&raw mut x.x509, &raw mut p, len) }
                };
                if r.is_null() {
                    err::raise(ERR_LIB_PEM, ERR_R_ASN1_LIB, "PEM_X509_INFO_read_bio_ex");
                    return false;
                }
            }
            Kind::Crl => {
                // SAFETY: as above.
                if !unsafe { decrypt(b, &mut len, cb, u) } {
                    return false;
                }
                // SAFETY: as above.
                if unsafe { d2i_X509_CRL(&raw mut x.crl, &raw mut p, len) }.is_null() {
                    err::raise(ERR_LIB_PEM, ERR_R_ASN1_LIB, "PEM_X509_INFO_read_bio_ex");
                    return false;
                }
            }
            Kind::Key { type_, raw } => {
                x.enc_data = ptr::null_mut();
                x.enc_len = 0;
                // SAFETY: no preconditions.
                x.x_pkey = unsafe { X509_PKEY_new() };
                // SAFETY: new, or NULL.
                let Some(pk) = (unsafe { x.x_pkey.as_mut() }) else {
                    return false;
                };
                if raw {
                    // SAFETY: the block's header; the entry's cipher.
                    if unsafe { PEM_get_EVP_CIPHER_INFO(b.header, &raw mut x.enc_cipher) } == 0 {
                        return false;
                    }
                    x.enc_data = b.data.cast();
                    x.enc_len = c_int::try_from(len).unwrap_or(c_int::MAX);
                    b.data = ptr::null_mut();
                } else {
                    // SAFETY: as above.
                    if !unsafe { decrypt(b, &mut len, cb, u) } {
                        return false;
                    }
                    let k = if type_ != EVP_PKEY_NONE {
                        // SAFETY: as above; the key's slot.
                        unsafe {
                            d2i_PrivateKey_ex(
                                type_,
                                &raw mut pk.dec_pkey,
                                &raw mut p,
                                len,
                                libctx,
                                propq,
                            )
                        }
                    } else {
                        // SAFETY: as above.
                        unsafe { d2i_AutoPrivateKey(&raw mut pk.dec_pkey, &raw mut p, len) }
                    };
                    if k.is_null() {
                        err::raise(ERR_LIB_PEM, ERR_R_ASN1_LIB, "PEM_X509_INFO_read_bio_ex");
                        return false;
                    }
                }
            }
            Kind::Other => {}
        }
        b.free();
    }
}

/// `PEM_get_EVP_CIPHER_INFO` and `PEM_do_header` on a block: its data decrypted in place.
///
/// # Safety
/// `b` holds a block from `PEM_read_bio` of `len` octets.
unsafe fn decrypt(b: &Block, len: &mut c_long, cb: pem_password_cb, u: *mut c_void) -> bool {
    // SAFETY: all-zero is a valid cipher information.
    let mut cipher: EVP_CIPHER_INFO = unsafe { core::mem::zeroed() };
    // SAFETY: the block's header; a local.
    if unsafe { PEM_get_EVP_CIPHER_INFO(b.header, &raw mut cipher) } == 0 {
        return false;
    }
    // SAFETY: the cipher; the block's data and length; the caller's callback.
    (unsafe { PEM_do_header(&raw mut cipher, b.data, len, cb, u) }) != 0
}

ffi_export! {
    /// Reads the PEM blocks of `bp` into `X509_INFO`s, added to `sk` (or a new list), in
    /// `libctx` with `propq`: the list, or NULL (a new list freed; `sk`'s entries before the
    /// error kept, those after freed).
    ///
    /// # Safety
    /// `bp` is a live BIO; `sk` is NULL or a live list; `cb` and `u` as for PEM passphrases;
    /// `libctx` is NULL or live; `propq` is NULL or a string.
    pub unsafe extern "C" fn PEM_X509_INFO_read_bio_ex(bp: *mut BIO, sk: *mut stack_st_X509_INFO, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut stack_st_X509_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        let ret = if sk.is_null() {
            // SAFETY: no preconditions.
            let r = unsafe { OPENSSL_sk_new_null() }.cast::<stack_st_X509_INFO>();
            if r.is_null() {
                err::raise(ERR_LIB_PEM, ERR_R_CRYPTO_LIB, "PEM_X509_INFO_read_bio_ex");
                return ptr::null_mut();
            }
            r
        } else {
            sk
        };
        let mut b = Block { name: ptr::null_mut(), header: ptr::null_mut(), data: ptr::null_mut() };
        // SAFETY: no preconditions.
        let mut xi = unsafe { X509_INFO_new() };
        // SAFETY: the caller's guarantee; the list; the entry.
        let mut ok = !xi.is_null() && unsafe { read_blocks(bp, ret, &mut xi, &mut b, &How { cb, u, libctx, propq }) };
        if ok
            // SAFETY: the last entry.
            && let Some(x) = unsafe { xi.as_ref() }
            && (!x.x509.is_null() || !x.crl.is_null() || !x.x_pkey.is_null() || !x.enc_data.is_null())
        {
            // SAFETY: the list; the entry, which it takes.
            if unsafe { OPENSSL_sk_push(ret.cast(), xi.cast()) } == 0 {
                ok = false;
            } else {
                xi = ptr::null_mut();
            }
        }
        // SAFETY: the entry not added, or NULL.
        unsafe { X509_INFO_free(xi) };
        b.free();
        if ok {
            return ret;
        }
        // SAFETY: the list.
        unsafe { free_entries(ret) };
        if ret != sk {
            // SAFETY: made above.
            unsafe { OPENSSL_sk_free(ret.cast()) };
        }
        ptr::null_mut()
    }
}

ffi_export! {
    /// [`PEM_X509_INFO_read_bio_ex`] without a library context.
    ///
    /// # Safety
    /// As for [`PEM_X509_INFO_read_bio_ex`].
    pub unsafe extern "C" fn PEM_X509_INFO_read_bio(bp: *mut BIO, sk: *mut stack_st_X509_INFO, cb: pem_password_cb, u: *mut c_void) -> *mut stack_st_X509_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { PEM_X509_INFO_read_bio_ex(bp, sk, cb, u, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// [`PEM_X509_INFO_read_bio_ex`] from a `FILE`, which is left open.
    ///
    /// # Safety
    /// As for [`PEM_X509_INFO_read_bio_ex`], with `fp` an open `FILE`.
    pub unsafe extern "C" fn PEM_X509_INFO_read_ex(fp: *mut FILE, sk: *mut stack_st_X509_INFO, cb: pem_password_cb, u: *mut c_void, libctx: *mut OSSL_LIB_CTX, propq: *const c_char) -> *mut stack_st_X509_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        let b = unsafe { file_bio(fp, "PEM_X509_INFO_read_ex") };
        if b.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the BIO; the caller's arguments.
        let ret = unsafe { PEM_X509_INFO_read_bio_ex(b, sk, cb, u, libctx, propq) };
        // SAFETY: made above.
        unsafe { crate::bio::BIO_free(b) };
        ret
    }
}

ffi_export! {
    /// [`PEM_X509_INFO_read_ex`] without a library context.
    ///
    /// # Safety
    /// As for [`PEM_X509_INFO_read_ex`].
    pub unsafe extern "C" fn PEM_X509_INFO_read(fp: *mut FILE, sk: *mut stack_st_X509_INFO, cb: pem_password_cb, u: *mut c_void) -> *mut stack_st_X509_INFO
    where failure = ptr::null_mut(), library = ERR_LIB_PEM
    {
        // SAFETY: the caller's guarantee.
        unsafe { PEM_X509_INFO_read_ex(fp, sk, cb, u, ptr::null_mut(), ptr::null()) }
    }
}

ffi_export! {
    /// Writes the entry: its key (kept encrypted, which needs `enc`; or its RSA key, encrypted
    /// with `enc`), then its certificate. 1, or 0.
    ///
    /// # Safety
    /// `bp` is a live BIO; `xi` is a live entry; `enc` is NULL or a cipher; `kstr` holds `klen`
    /// octets or is NULL; `cb` and `u` as for PEM passphrases.
    pub unsafe extern "C" fn PEM_X509_INFO_write_bio(bp: *mut BIO, xi: *const X509_INFO, enc: *mut EVP_CIPHER, kstr: *const c_uchar, klen: c_int, cb: pem_password_cb, u: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_PEM
    {
        const F: &str = "PEM_X509_INFO_write_bio";
        // SAFETY: the caller's guarantee.
        let Some(x) = (unsafe { xi.as_ref() }) else { return 0 };
        let mut buf = [0u8; PEM_BUFSIZE as usize];
        let ok = 'write: {
            if !enc.is_null() {
                // SAFETY: the caller's cipher.
                let objstr = unsafe { EVP_CIPHER_get0_name(enc) };
                // SAFETY: its name, or NULL.
                let name = unsafe { text(objstr) };
                // SAFETY: as above.
                let iv = usize::try_from(unsafe { EVP_CIPHER_get_iv_length(enc) }).unwrap_or(0);
                if objstr.is_null() || name.len() + 23 + 2 * iv + 13 > buf.len() {
                    err::raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_CIPHER, F);
                    break 'write false;
                }
            }
            if !x.x_pkey.is_null() {
                if !x.enc_data.is_null() && x.enc_len > 0 {
                    if enc.is_null() {
                        err::raise(ERR_LIB_PEM, PEM_R_CIPHER_IS_NULL, F);
                        break 'write false;
                    }
                    // SAFETY: the entry's cipher.
                    let objstr = unsafe { EVP_CIPHER_get0_name(x.enc_cipher.cipher) };
                    if objstr.is_null() {
                        err::raise(ERR_LIB_PEM, PEM_R_UNSUPPORTED_CIPHER, F);
                        break 'write false;
                    }
                    let b = buf.as_mut_ptr().cast::<c_char>();
                    // SAFETY: a buffer of `PEM_BUFSIZE` octets.
                    unsafe { PEM_proc_type(b, PEM_TYPE_ENCRYPTED) };
                    // SAFETY: the caller's cipher.
                    let ivlen = unsafe { EVP_CIPHER_get_iv_length(enc) };
                    // SAFETY: as above; the name; the entry's IV.
                    unsafe { PEM_dek_info(b, objstr, ivlen, x.enc_cipher.iv.as_ptr().cast()) };
                    // SAFETY: the caller's BIO; the header; the entry's encrypted octets.
                    if unsafe { PEM_write_bio(bp, PEM_STRING_RSA.as_ptr(), b, x.enc_data.cast(), c_long::from(x.enc_len)) } <= 0 {
                        break 'write false;
                    }
                } else {
                    // SAFETY: the entry's `X509_PKEY`.
                    let key = unsafe { (*x.x_pkey).dec_pkey };
                    // SAFETY: its key, or NULL.
                    let rsa = unsafe { EVP_PKEY_get0_RSA(key) };
                    // SAFETY: the caller's BIO, cipher, passphrase, and callback; the key, or NULL.
                    if unsafe { crate::pem_pkey::PEM_write_bio_RSAPrivateKey(bp, rsa, enc, kstr, klen, cb, u) } <= 0 {
                        break 'write false;
                    }
                }
            }
            // SAFETY: as above; the entry's certificate.
            if !x.x509.is_null() && unsafe { crate::pem_pkey::PEM_write_bio_X509(bp, x.x509) } <= 0 {
                break 'write false;
            }
            true
        };
        // SAFETY: the local buffer.
        unsafe { crate::mem::OPENSSL_cleanse(buf.as_mut_ptr().cast(), buf.len()) };
        c_int::from(ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// docs/DEVIATIONS.md: an entry with a key slot but no key, or kept encrypted without a
    /// cipher (an encrypted PKCS#8) written with a cipher, which OpenSSL reads through, fails.
    #[test]
    fn entries_without_a_key_or_cipher_fail() {
        // SAFETY: no preconditions.
        let xi = unsafe { X509_INFO_new() };
        // SAFETY: no preconditions.
        let pk = unsafe { X509_PKEY_new() };
        // SAFETY: the new entry's field.
        unsafe { (*xi).x_pkey = pk };
        // SAFETY: as above.
        let m = unsafe { crate::bio::mem::BIO_s_mem() };
        // SAFETY: a method.
        let bio = unsafe { crate::bio::BIO_new(m) };
        let n = ptr::null_mut();
        // SAFETY: the BIO; the entry; no cipher or passphrase.
        let r =
            unsafe { PEM_X509_INFO_write_bio(bio, xi, ptr::null_mut(), ptr::null(), 0, None, n) };
        assert_eq!(r, 0);
        // SAFETY: as above.
        unsafe { (*xi).enc_data = mem::alloc(4).cast() };
        // SAFETY: as above.
        unsafe { (*xi).enc_len = 4 };
        // SAFETY: no preconditions.
        let aes = unsafe { crate::evp::legacy_cipher::EVP_aes_128_cbc() }.cast_mut();
        // SAFETY: as above, with a cipher.
        let r = unsafe { PEM_X509_INFO_write_bio(bio, xi, aes, ptr::null(), 0, None, n) };
        assert_eq!(r, 0);
        // SAFETY: made above.
        unsafe { crate::bio::BIO_free(bio) };
        // SAFETY: as above.
        unsafe { X509_INFO_free(xi) };
        crate::err::take_all();
    }
}
