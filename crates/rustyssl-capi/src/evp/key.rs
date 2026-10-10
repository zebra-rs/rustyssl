//! `EVP_BytesToKey(3)` (`evp_key.c`): OpenSSL's original password-to-key derivation, which
//! encrypted PEM uses. D_i = MD^count(D_(i-1) || data || salt), the octets filling the key, then
//! the IV, for as many rounds as they take. It runs over the `EVP_MD_CTX` functions, so any
//! digest an application has works.
//!
//! The reference asserts the cipher's key and IV fit their maximums; a cipher beyond them
//! fails here instead (docs/DEVIATIONS.md).

use core::ffi::{c_int, c_uint};
use core::ptr;

use rustyssl_abi::{
    ERR_LIB_EVP, EVP_CIPHER, EVP_MAX_IV_LENGTH, EVP_MAX_KEY_LENGTH, EVP_MAX_MD_SIZE, EVP_MD,
    PKCS5_SALT_LEN,
};

use super::cipher::{EVP_CIPHER_get_iv_length, EVP_CIPHER_get_key_length};
use super::md_ctx::{
    EVP_DigestFinal_ex, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_MD_CTX_free, EVP_MD_CTX_new,
};
use crate::ffi::ffi_export;

/// Zeroes `b` (`OPENSSL_cleanse`).
fn wipe(b: &mut [u8]) {
    // SAFETY: the slice's own octets.
    unsafe { crate::mem::OPENSSL_cleanse(b.as_mut_ptr().cast(), b.len()) };
}

ffi_export! {
    /// Derives `type`'s key (into `key`) and IV (into `iv`), each skipped where NULL, from
    /// `datal` octets of `data` and 8 octets of `salt` (none for NULL) with `count` rounds of
    /// `md`. Returns the key's length (also for NULL `data`, deriving nothing), or 0.
    ///
    /// # Safety
    /// `type_` is NULL or a live cipher; `md` is NULL or a live digest; `salt` is NULL or holds
    /// 8 octets; `data` is NULL or holds `datal` octets; `key` and `iv` are NULL or have room
    /// for the cipher's key and IV.
    pub unsafe extern "C" fn EVP_BytesToKey(type_: *const EVP_CIPHER, md: *const EVP_MD, salt: *const u8, data: *const u8, datal: c_int, count: c_int, key: *mut u8, iv: *mut u8) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let keylen = unsafe { EVP_CIPHER_get_key_length(type_) };
        // SAFETY: as above.
        let ivlen = unsafe { EVP_CIPHER_get_iv_length(type_) };
        let (Ok(mut nkey), Ok(mut niv)) = (usize::try_from(keylen), usize::try_from(ivlen)) else {
            return 0;
        };
        if nkey > EVP_MAX_KEY_LENGTH as usize || niv > EVP_MAX_IV_LENGTH as usize {
            // The reference asserts (docs/DEVIATIONS.md).
            return 0;
        }
        if data.is_null() {
            return keylen;
        }
        let Ok(datal) = usize::try_from(datal) else { return 0 };
        // SAFETY: no preconditions.
        let c = unsafe { EVP_MD_CTX_new() };
        if c.is_null() {
            return 0;
        }
        let mut md_buf = [0u8; EVP_MAX_MD_SIZE as usize];
        let mut mds: c_uint = 0;
        let (mut key, mut iv) = (key, iv);
        let mut first = true;
        let mut rv = 0;
        'rounds: loop {
            // SAFETY: a live context; the caller's digest.
            if unsafe { EVP_DigestInit_ex(c, md, ptr::null_mut()) } == 0 {
                break;
            }
            // SAFETY: the context; the previous round's digest, of `mds` octets.
            if !first && unsafe { EVP_DigestUpdate(c, md_buf.as_ptr().cast(), mds as usize) } == 0 {
                break;
            }
            first = false;
            // SAFETY: the context; the caller's data.
            if unsafe { EVP_DigestUpdate(c, data.cast(), datal) } == 0 {
                break;
            }
            // SAFETY: the context; the caller's salt.
            if !salt.is_null() && unsafe { EVP_DigestUpdate(c, salt.cast(), PKCS5_SALT_LEN as usize) } == 0 {
                break;
            }
            // SAFETY: the context; room for any digest.
            if unsafe { EVP_DigestFinal_ex(c, md_buf.as_mut_ptr(), &raw mut mds) } == 0 {
                break;
            }
            for _ in 1..count.max(1) {
                // SAFETY: as above.
                let ok = unsafe { EVP_DigestInit_ex(c, md, ptr::null_mut()) } != 0
                    // SAFETY: as above.
                    && unsafe { EVP_DigestUpdate(c, md_buf.as_ptr().cast(), mds as usize) } != 0
                    // SAFETY: as above.
                    && unsafe { EVP_DigestFinal_ex(c, md_buf.as_mut_ptr(), &raw mut mds) } != 0;
                if !ok {
                    break 'rounds;
                }
            }
            let available = md_buf.get(..mds as usize).unwrap_or_default();
            let mut taken = available.iter();
            while nkey > 0 {
                let Some(&b) = taken.next() else { break };
                if !key.is_null() {
                    // SAFETY: the caller's guarantee: room for the key, `nkey` more octets.
                    unsafe { key.write(b) };
                    key = key.wrapping_add(1);
                }
                nkey -= 1;
            }
            if niv > 0 && taken.len() > 0 {
                while niv > 0 {
                    let Some(&b) = taken.next() else { break };
                    if !iv.is_null() {
                        // SAFETY: as above, for the IV.
                        unsafe { iv.write(b) };
                        iv = iv.wrapping_add(1);
                    }
                    niv -= 1;
                }
            }
            if nkey == 0 && niv == 0 {
                rv = keylen;
                break;
            }
        }
        // SAFETY: the context made here.
        unsafe { EVP_MD_CTX_free(c) };
        wipe(&mut md_buf);
        rv
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evp::legacy_cipher::EVP_aes_128_cbc;
    use crate::evp::legacy_md::EVP_md5;

    /// docs/DEVIATIONS.md: a negative count is one round (the reference runs about 2^32).
    #[test]
    #[cfg_attr(miri, ignore = "fetches the digest, which loads the configuration")]
    fn negative_counts_are_one_round() {
        let mut once = [0u8; 16];
        let mut negative = [1u8; 16];
        // SAFETY: no preconditions.
        let cipher = unsafe { EVP_aes_128_cbc() };
        // SAFETY: no preconditions.
        let md5 = unsafe { EVP_md5() };
        for (count, key) in [(1, &mut once), (-5, &mut negative)] {
            // SAFETY: static methods; a password of 2 octets; room for the key.
            let r = unsafe {
                EVP_BytesToKey(
                    cipher,
                    md5,
                    ptr::null(),
                    b"pw".as_ptr(),
                    2,
                    count,
                    key.as_mut_ptr(),
                    ptr::null_mut(),
                )
            };
            assert_eq!(r, 16);
        }
        assert_eq!(once, negative);
    }
}
