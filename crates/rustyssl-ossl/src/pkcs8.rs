//! PKCS#8: private key infos, their encrypted form (`X509_SIG`), and the PBE algorithms.

use core::ffi::c_int;

use crate::bio::Bio;
use crate::evp::Cipher;
use crate::ffi;
use crate::pkey::Pkey;

crate::handle!(
    /// An owned `PKCS8_PRIV_KEY_INFO`.
    P8Info, PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free
);
crate::handle!(
    /// An owned `X509_SIG` (an encrypted PKCS#8 key).
    EncryptedKey, X509_SIG, X509_SIG_free
);
crate::handle!(
    /// An owned `X509_ALGOR`.
    Algor, X509_ALGOR, X509_ALGOR_free
);

impl P8Info {
    /// `EVP_PKEY2PKCS8`.
    pub fn from_pkey(pkey: &Pkey) -> Option<Self> {
        // SAFETY: the key is live; the result is the caller's.
        Self::from_ptr(unsafe { ffi::EVP_PKEY2PKCS8(pkey.as_ptr()) })
    }

    /// `EVP_PKCS82PKEY`.
    pub fn to_pkey(&self) -> Option<Pkey> {
        // SAFETY: self is live; the result is the caller's.
        Pkey::from_raw(unsafe { ffi::EVP_PKCS82PKEY(self.as_ptr()) })
    }

    /// `PEM_read_bio_PKCS8_PRIV_KEY_INFO(in, NULL, NULL, NULL)`.
    pub fn read_pem(input: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; no callback or reuse.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_PKCS8_PRIV_KEY_INFO(
                input.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `d2i_PKCS8_PRIV_KEY_INFO_bio(in, NULL)`.
    pub fn read_der(input: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe {
            ffi::d2i_PKCS8_PRIV_KEY_INFO_bio(input.as_ptr(), core::ptr::null_mut())
        })
    }

    /// `PEM_write_bio_PKCS8_PRIV_KEY_INFO`.
    pub fn write_pem(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_PKCS8_PRIV_KEY_INFO(out.as_ptr(), self.as_ptr()) }
    }

    /// `i2d_PKCS8_PRIV_KEY_INFO_bio`.
    pub fn write_der(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2d_PKCS8_PRIV_KEY_INFO_bio(out.as_ptr(), self.as_ptr()) }
    }
}

fn len_of(s: &[u8]) -> Option<c_int> {
    c_int::try_from(s.len()).ok()
}

impl EncryptedKey {
    /// `PKCS8_set0_pbe(pass, passlen, p8inf, pbe)`: on success the result owns `pbe`; on
    /// failure it is freed (as upstream's caller does).
    pub fn encrypt(pass: &[u8], p8inf: &P8Info, pbe: Algor) -> Option<Self> {
        let n = len_of(pass)?;
        // SAFETY: pass is valid for n bytes; p8inf and pbe are live.
        let p8 = Self::from_ptr(unsafe {
            ffi::PKCS8_set0_pbe(pass.as_ptr().cast(), n, p8inf.as_ptr(), pbe.as_ptr())
        });
        if p8.is_some() {
            // The result owns it now.
            let _ = pbe.into_ptr();
        }
        p8
    }

    /// `PKCS8_decrypt(p8, pass, passlen)`.
    pub fn decrypt(&self, pass: &[u8]) -> Option<P8Info> {
        let n = len_of(pass)?;
        // SAFETY: self is live; pass is valid for n bytes.
        P8Info::from_ptr(unsafe { ffi::PKCS8_decrypt(self.as_ptr(), pass.as_ptr().cast(), n) })
    }

    /// `PEM_read_bio_PKCS8(in, NULL, NULL, NULL)`.
    pub fn read_pem(input: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live; no callback or reuse.
        Self::from_ptr(unsafe {
            ffi::PEM_read_bio_PKCS8(
                input.as_ptr(),
                core::ptr::null_mut(),
                None,
                core::ptr::null_mut(),
            )
        })
    }

    /// `d2i_PKCS8_bio(in, NULL)`.
    pub fn read_der(input: &Bio) -> Option<Self> {
        // SAFETY: the BIO is live.
        Self::from_ptr(unsafe { ffi::d2i_PKCS8_bio(input.as_ptr(), core::ptr::null_mut()) })
    }

    /// `PEM_write_bio_PKCS8`.
    pub fn write_pem(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::PEM_write_bio_PKCS8(out.as_ptr(), self.as_ptr()) }
    }

    /// `i2d_PKCS8_bio`.
    pub fn write_der(&self, out: &Bio) -> c_int {
        // SAFETY: both are live.
        unsafe { ffi::i2d_PKCS8_bio(out.as_ptr(), self.as_ptr()) }
    }
}

impl Algor {
    /// `PKCS5_pbe2_set_scrypt(cipher, NULL, saltlen, NULL, n, r, p)`.
    pub fn pbe2_scrypt(cipher: &Cipher, saltlen: c_int, n: u64, r: u64, p: u64) -> Option<Self> {
        // SAFETY: the cipher is live; NULL salt and IV ask for random ones.
        Self::from_ptr(unsafe {
            ffi::PKCS5_pbe2_set_scrypt(
                cipher.as_ptr(),
                core::ptr::null(),
                saltlen,
                core::ptr::null_mut(),
                n,
                r,
                p,
            )
        })
    }

    /// `PKCS5_pbe2_set_iv(cipher, iter, NULL, saltlen, NULL, prf_nid)`.
    pub fn pbe2_iv(cipher: &Cipher, iter: c_int, saltlen: c_int, prf_nid: c_int) -> Option<Self> {
        // SAFETY: as above.
        Self::from_ptr(unsafe {
            ffi::PKCS5_pbe2_set_iv(
                cipher.as_ptr(),
                iter,
                core::ptr::null_mut(),
                saltlen,
                core::ptr::null_mut(),
                prf_nid,
            )
        })
    }

    /// `PKCS5_pbe_set(nid, iter, NULL, saltlen)`.
    pub fn pbe1(nid: c_int, iter: c_int, saltlen: c_int) -> Option<Self> {
        // SAFETY: a NULL salt asks for a random one.
        Self::from_ptr(unsafe { ffi::PKCS5_pbe_set(nid, iter, core::ptr::null(), saltlen) })
    }
}

/// `EVP_PBE_find(type, nid, NULL, NULL, 0)`.
pub fn pbe_find(kind: c_int, nid: c_int) -> bool {
    // SAFETY: NULL out-pointers are allowed.
    unsafe {
        ffi::EVP_PBE_find(
            kind,
            nid,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        ) != 0
    }
}
