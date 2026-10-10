//! The legacy cipher names (`EVP_get_cipherbyname(3)`, `EVP_aes_128_cbc(3)`,
//! `EVP_CIPHER_do_all(3)`): the static ciphers `EVP_aes_128_cbc()` and the like return, the
//! `OBJ_NAME` table that `OPENSSL_INIT_ADD_ALL_CIPHERS` fills with their names
//! (`crypto/evp/c_allc.c`, `names.c`), and the lookup through it and each context's name map.
//!
//! A static cipher has no provider: it carries OpenSSL's NID, lengths, and flags for the cipher
//! (`e_aes.c` and the others), `EVP_CIPHER_up_ref` and `EVP_CIPHER_free` do nothing to it, and
//! `EVP_CipherInit_ex` fetches the provider's cipher by its short name. The table is also what
//! each context's name map starts with ([`cipher_nids`], before the digests') and where fetched
//! ciphers find their NIDs. The legacy provider's ciphers (DES, DESX, RC4, IDEA, RC2, Blowfish,
//! CAST5, SEED) have static ciphers as in OpenSSL's default build; using them needs the legacy
//! provider (9.1). The AES-CBC-HMAC composites exist where OpenSSL's do: on x86-64 with AES-NI.

use core::ffi::{c_char, c_int, c_ulong, c_void};
use core::ptr;
use std::sync::OnceLock;

use rustyssl_abi::{
    ERR_LIB_EVP, EVP_CIPH_ALWAYS_CALL_INIT, EVP_CIPH_CBC_MODE, EVP_CIPH_CCM_MODE,
    EVP_CIPH_CFB_MODE, EVP_CIPH_CTR_MODE, EVP_CIPH_CTRL_INIT, EVP_CIPH_CUSTOM_COPY,
    EVP_CIPH_CUSTOM_IV, EVP_CIPH_CUSTOM_IV_LENGTH, EVP_CIPH_ECB_MODE, EVP_CIPH_FLAG_AEAD_CIPHER,
    EVP_CIPH_FLAG_CUSTOM_CIPHER, EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK, EVP_CIPH_GCM_MODE,
    EVP_CIPH_OCB_MODE, EVP_CIPH_OFB_MODE, EVP_CIPH_RAND_KEY, EVP_CIPH_VARIABLE_LENGTH,
    EVP_CIPH_WRAP_MODE, EVP_CIPH_XTS_MODE, EVP_CIPHER, NID_aes_128_cbc, NID_aes_128_cbc_hmac_sha1,
    NID_aes_128_cbc_hmac_sha256, NID_aes_128_ccm, NID_aes_128_cfb1, NID_aes_128_cfb8,
    NID_aes_128_cfb128, NID_aes_128_ctr, NID_aes_128_ecb, NID_aes_128_gcm, NID_aes_128_ocb,
    NID_aes_128_ofb128, NID_aes_128_xts, NID_aes_192_cbc, NID_aes_192_ccm, NID_aes_192_cfb1,
    NID_aes_192_cfb8, NID_aes_192_cfb128, NID_aes_192_ctr, NID_aes_192_ecb, NID_aes_192_gcm,
    NID_aes_192_ocb, NID_aes_192_ofb128, NID_aes_256_cbc, NID_aes_256_cbc_hmac_sha1,
    NID_aes_256_cbc_hmac_sha256, NID_aes_256_ccm, NID_aes_256_cfb1, NID_aes_256_cfb8,
    NID_aes_256_cfb128, NID_aes_256_ctr, NID_aes_256_ecb, NID_aes_256_gcm, NID_aes_256_ocb,
    NID_aes_256_ofb128, NID_aes_256_xts, NID_aria_128_cbc, NID_aria_128_ccm, NID_aria_128_cfb1,
    NID_aria_128_cfb8, NID_aria_128_cfb128, NID_aria_128_ctr, NID_aria_128_ecb, NID_aria_128_gcm,
    NID_aria_128_ofb128, NID_aria_192_cbc, NID_aria_192_ccm, NID_aria_192_cfb1, NID_aria_192_cfb8,
    NID_aria_192_cfb128, NID_aria_192_ctr, NID_aria_192_ecb, NID_aria_192_gcm, NID_aria_192_ofb128,
    NID_aria_256_cbc, NID_aria_256_ccm, NID_aria_256_cfb1, NID_aria_256_cfb8, NID_aria_256_cfb128,
    NID_aria_256_ctr, NID_aria_256_ecb, NID_aria_256_gcm, NID_aria_256_ofb128, NID_bf_cbc,
    NID_bf_cfb64, NID_bf_ecb, NID_bf_ofb64, NID_camellia_128_cbc, NID_camellia_128_cfb1,
    NID_camellia_128_cfb8, NID_camellia_128_cfb128, NID_camellia_128_ctr, NID_camellia_128_ecb,
    NID_camellia_128_ofb128, NID_camellia_192_cbc, NID_camellia_192_cfb1, NID_camellia_192_cfb8,
    NID_camellia_192_cfb128, NID_camellia_192_ctr, NID_camellia_192_ecb, NID_camellia_192_ofb128,
    NID_camellia_256_cbc, NID_camellia_256_cfb1, NID_camellia_256_cfb8, NID_camellia_256_cfb128,
    NID_camellia_256_ctr, NID_camellia_256_ecb, NID_camellia_256_ofb128, NID_cast5_cbc,
    NID_cast5_cfb64, NID_cast5_ecb, NID_cast5_ofb64, NID_chacha20, NID_chacha20_poly1305,
    NID_des_cbc, NID_des_cfb1, NID_des_cfb8, NID_des_cfb64, NID_des_ecb, NID_des_ede_cbc,
    NID_des_ede_cfb64, NID_des_ede_ecb, NID_des_ede_ofb64, NID_des_ede3_cbc, NID_des_ede3_cfb1,
    NID_des_ede3_cfb8, NID_des_ede3_cfb64, NID_des_ede3_ecb, NID_des_ede3_ofb64, NID_des_ofb64,
    NID_desx_cbc, NID_id_aes128_wrap, NID_id_aes128_wrap_pad, NID_id_aes192_wrap,
    NID_id_aes192_wrap_pad, NID_id_aes256_wrap, NID_id_aes256_wrap_pad,
    NID_id_smime_alg_CMS3DESwrap, NID_idea_cbc, NID_idea_cfb64, NID_idea_ecb, NID_idea_ofb64,
    NID_rc2_40_cbc, NID_rc2_64_cbc, NID_rc2_cbc, NID_rc2_cfb64, NID_rc2_ecb, NID_rc2_ofb64,
    NID_rc4, NID_rc4_40, NID_rc4_hmac_md5, NID_seed_cbc, NID_seed_cfb128, NID_seed_ecb,
    NID_seed_ofb128, NID_sm4_cbc, NID_sm4_cfb128, NID_sm4_ctr, NID_sm4_ecb, NID_sm4_ofb128,
    NID_undef, OBJ_NAME, OBJ_NAME_ALIAS, OBJ_NAME_TYPE_CIPHER_METH, OPENSSL_INIT_ADD_ALL_CIPHERS,
    SN_aes_128_cbc, SN_aes_192_cbc, SN_aes_256_cbc, SN_aria_128_cbc, SN_aria_192_cbc,
    SN_aria_256_cbc, SN_bf_cbc, SN_camellia_128_cbc, SN_camellia_192_cbc, SN_camellia_256_cbc,
    SN_cast5_cbc, SN_des_cbc, SN_des_ede_ecb, SN_des_ede3_cbc, SN_des_ede3_ecb, SN_desx_cbc,
    SN_id_aes128_wrap, SN_id_aes128_wrap_pad, SN_id_aes192_wrap, SN_id_aes192_wrap_pad,
    SN_id_aes256_wrap, SN_id_aes256_wrap_pad, SN_id_smime_alg_CMS3DESwrap, SN_idea_cbc,
    SN_rc2_40_cbc, SN_rc2_64_cbc, SN_rc2_cbc, SN_seed_cbc, SN_sm4_cbc,
};

use super::cipher::{Cipher, EVP_CIPHER_fetch, EVP_CIPHER_free, method};
use super::fetch;
use crate::err::{ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::{ffi_callback, ffi_export};
use crate::handle::Handle;
use crate::init::OPENSSL_init_crypto;
use crate::objects::name::{OBJ_NAME_add, OBJ_NAME_do_all, OBJ_NAME_do_all_sorted, OBJ_NAME_get};
use crate::objects::{OBJ_nid2ln, OBJ_nid2sn};
use crate::provider::Ptr;

/// `EVP_CIPH_*` flags as the flags' type.
const fn flags(f: c_int) -> c_ulong {
    f.cast_unsigned() as c_ulong
}

/// `OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS, NULL)`.
fn init_ciphers() -> c_int {
    let opts = OPENSSL_INIT_ADD_ALL_CIPHERS.cast_unsigned();
    // SAFETY: no settings.
    unsafe { OPENSSL_init_crypto(opts, ptr::null()) }
}

/// One static cipher: OpenSSL's definition, made into a method on first use and never freed.
struct Static {
    nid: c_int,
    block_size: c_int,
    key_len: c_int,
    iv_len: c_int,
    flags: c_ulong,
    handle: OnceLock<Ptr<EVP_CIPHER>>,
}

impl Static {
    const fn new(
        nid: c_int,
        block_size: c_int,
        key_len: c_int,
        iv_len: c_int,
        flags: c_ulong,
    ) -> Self {
        Self {
            nid,
            block_size,
            key_len,
            iv_len,
            flags,
            handle: OnceLock::new(),
        }
    }

    fn get(&self) -> *const EVP_CIPHER {
        self.handle
            .get_or_init(|| {
                let c = Cipher::legacy(
                    self.nid,
                    self.block_size,
                    self.key_len,
                    self.iv_len,
                    self.flags,
                );
                Ptr(EVP_CIPHER::new_handle(c))
            })
            .0
            .cast_const()
    }
}

/// Whether the CPU has AES-NI, as OpenSSL's `AESNI_CAPABLE` (its `OPENSSL_ia32cap` override
/// aside): where the AES-CBC-HMAC composites exist.
fn aesni() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        false
    }
}

/// The flags of the AES-CBC-HMAC composites.
const CBC_HMAC: c_ulong =
    flags(EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK);

ffi_export! {
    /// The static NULL cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_enc_null() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_undef, 1, 0, 0, 0);
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-ECB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ecb, 8, 8, 0, flags(EVP_CIPH_ECB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE cipher, the same as `EVP_des_ede_ecb()`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // The same cipher as `EVP_des_ede_ecb()`, as in OpenSSL.
        // SAFETY: no preconditions.
        unsafe { EVP_des_ede_ecb() }
    }
}

ffi_export! {
    /// The static DES-EDE3 cipher, the same as `EVP_des_ede3_ecb()`.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede3() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        // The same cipher as `EVP_des_ede3_ecb()`, as in OpenSSL.
        // SAFETY: no preconditions.
        unsafe { EVP_des_ede3_ecb() }
    }
}

ffi_export! {
    /// The static DES-EDE cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede_ecb, 8, 16, 0, flags(EVP_CIPH_ECB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE3 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede3_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede3_ecb, 8, 24, 0, flags(EVP_CIPH_ECB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-CFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_cfb64() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_cfb64, 1, 8, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-CFB1 cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_cfb1, 1, 8, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-CFB8 cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_cfb8, 1, 8, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede_cfb64() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede_cfb64, 1, 16, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE3-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede3_cfb64() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede3_cfb64, 1, 24, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE3-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede3_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede3_cfb1, 1, 24, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE3-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede3_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede3_cfb8, 1, 24, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-OFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ofb64, 1, 8, 8, flags(EVP_CIPH_OFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede_ofb64, 1, 16, 8, flags(EVP_CIPH_OFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE3-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede3_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede3_ofb64, 1, 24, 8, flags(EVP_CIPH_OFB_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_cbc, 8, 8, 8, flags(EVP_CIPH_CBC_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede_cbc, 8, 16, 8, flags(EVP_CIPH_CBC_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DES-EDE3-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede3_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_des_ede3_cbc, 8, 24, 8, flags(EVP_CIPH_CBC_MODE | EVP_CIPH_RAND_KEY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static DESX-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_desx_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_desx_cbc, 8, 24, 8, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-smime-alg-CMS3DESwrap cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_des_ede3_wrap() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_id_smime_alg_CMS3DESwrap, 8, 24, 0, flags(EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC4 cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc4() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc4, 1, 16, 0, flags(EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC4-40 cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc4_40() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc4_40, 1, 5, 0, flags(EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC4-HMAC-MD5 cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc4_hmac_md5() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc4_hmac_md5, 1, 16, 0, flags(EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static IDEA-ECB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_idea_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_idea_ecb, 8, 16, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static IDEA-CFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_idea_cfb64() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_idea_cfb64, 1, 16, 8, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static IDEA-OFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_idea_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_idea_ofb64, 1, 16, 8, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static IDEA-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_idea_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_idea_cbc, 8, 16, 8, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC2-ECB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc2_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc2_ecb, 8, 16, 0, flags(EVP_CIPH_ECB_MODE | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC2-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc2_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc2_cbc, 8, 16, 8, flags(EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC2-40-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc2_40_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc2_40_cbc, 8, 5, 8, flags(EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC2-64-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc2_64_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc2_64_cbc, 8, 8, 8, flags(EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC2-CFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc2_cfb64() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc2_cfb64, 1, 16, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static RC2-OFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_rc2_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_rc2_ofb64, 1, 16, 8, flags(EVP_CIPH_OFB_MODE | EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static BF-ECB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_bf_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_bf_ecb, 8, 16, 0, flags(EVP_CIPH_ECB_MODE | EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static BF-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_bf_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_bf_cbc, 8, 16, 8, flags(EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static BF-CFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_bf_cfb64() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_bf_cfb64, 1, 16, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static BF-OFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_bf_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_bf_ofb64, 1, 16, 8, flags(EVP_CIPH_OFB_MODE | EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAST5-ECB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_cast5_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_cast5_ecb, 8, 16, 0, flags(EVP_CIPH_ECB_MODE | EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAST5-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_cast5_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_cast5_cbc, 8, 16, 8, flags(EVP_CIPH_CBC_MODE | EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAST5-CFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_cast5_cfb64() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_cast5_cfb64, 1, 16, 8, flags(EVP_CIPH_CFB_MODE | EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAST5-OFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_cast5_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_cast5_ofb64, 1, 16, 8, flags(EVP_CIPH_OFB_MODE | EVP_CIPH_VARIABLE_LENGTH));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_ecb, 16, 16, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_cbc, 16, 16, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_cfb1, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_cfb8, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_cfb128, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_ofb128, 1, 16, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_ctr, 1, 16, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes128-CCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_ccm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_ccm, 1, 16, 12, flags(EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes128-GCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_gcm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_gcm, 1, 16, 12, flags(EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-XTS cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_xts() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_xts, 1, 32, 16, flags(EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes128-wrap cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_wrap() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_id_aes128_wrap, 8, 16, 8, flags(EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes128-wrap-pad cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_wrap_pad() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_id_aes128_wrap_pad, 8, 16, 4, flags(EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-OCB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_ocb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_ocb, 16, 16, 12, flags(EVP_CIPH_OCB_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-192-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_ecb, 16, 24, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-192-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_cbc, 16, 24, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-192-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_cfb1, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-192-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_cfb8, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-192-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_cfb128, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-192-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_ofb128, 1, 24, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-192-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_ctr, 1, 24, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes192-CCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_ccm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_ccm, 1, 24, 12, flags(EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes192-GCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_gcm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_gcm, 1, 24, 12, flags(EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes192-wrap cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_wrap() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_id_aes192_wrap, 8, 24, 8, flags(EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes192-wrap-pad cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_wrap_pad() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_id_aes192_wrap_pad, 8, 24, 4, flags(EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-192-OCB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_192_ocb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_192_ocb, 16, 24, 12, flags(EVP_CIPH_OCB_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_ecb, 16, 32, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_cbc, 16, 32, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_cfb1, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_cfb8, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_cfb128, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_ofb128, 1, 32, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_ctr, 1, 32, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes256-CCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_ccm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_ccm, 1, 32, 12, flags(EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes256-GCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_gcm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_gcm, 1, 32, 12, flags(EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-XTS cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_xts() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_xts, 1, 64, 16, flags(EVP_CIPH_XTS_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes256-wrap cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_wrap() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_id_aes256_wrap, 8, 32, 8, flags(EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static id-aes256-wrap-pad cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_wrap_pad() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_id_aes256_wrap_pad, 8, 32, 4, flags(EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_FLAG_CUSTOM_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-256-OCB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_ocb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_ocb, 16, 32, 12, flags(EVP_CIPH_OCB_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_ecb, 16, 16, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_cbc, 16, 16, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_cfb1, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_cfb8, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_cfb128, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_ctr, 1, 16, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_ofb128, 1, 16, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-GCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_gcm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_gcm, 1, 16, 12, flags(EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-128-CCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_128_ccm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_128_ccm, 1, 16, 12, flags(EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_ecb, 16, 24, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_cbc, 16, 24, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_cfb1, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_cfb8, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_cfb128, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_ctr, 1, 24, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_ofb128, 1, 24, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-GCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_gcm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_gcm, 1, 24, 12, flags(EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-192-CCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_192_ccm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_192_ccm, 1, 24, 12, flags(EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_ecb, 16, 32, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_cbc, 16, 32, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_cfb1, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_cfb8, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_cfb128, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_ctr, 1, 32, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_ofb128, 1, 32, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-GCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_gcm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_gcm, 1, 32, 12, flags(EVP_CIPH_GCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ARIA-256-CCM cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aria_256_ccm() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aria_256_ccm, 1, 32, 12, flags(EVP_CIPH_CCM_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-128-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_128_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_128_ecb, 16, 16, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-128-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_128_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_128_cbc, 16, 16, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-128-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_128_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_128_cfb1, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-128-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_128_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_128_cfb8, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-128-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_128_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_128_cfb128, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-128-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_128_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_128_ofb128, 1, 16, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-128-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_128_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_128_ctr, 1, 16, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-192-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_192_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_192_ecb, 16, 24, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-192-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_192_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_192_cbc, 16, 24, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-192-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_192_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_192_cfb1, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-192-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_192_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_192_cfb8, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-192-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_192_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_192_cfb128, 1, 24, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-192-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_192_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_192_ofb128, 1, 24, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-192-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_192_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_192_ctr, 1, 24, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-256-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_256_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_256_ecb, 16, 32, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-256-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_256_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_256_cbc, 16, 32, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-256-CFB1 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_256_cfb1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_256_cfb1, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-256-CFB8 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_256_cfb8() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_256_cfb8, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-256-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_256_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_256_cfb128, 1, 32, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-256-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_256_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_256_ofb128, 1, 32, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static CAMELLIA-256-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_camellia_256_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_camellia_256_ctr, 1, 32, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ChaCha20 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_chacha20() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_chacha20, 1, 32, 16, flags(EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static ChaCha20-Poly1305 cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_chacha20_poly1305() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_chacha20_poly1305, 1, 32, 12, flags(EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_CUSTOM_IV_LENGTH | EVP_CIPH_FLAG_CUSTOM_CIPHER | EVP_CIPH_FLAG_AEAD_CIPHER));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SEED-ECB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_seed_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_seed_ecb, 16, 16, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SEED-CBC cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_seed_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_seed_cbc, 16, 16, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SEED-CFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_seed_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_seed_cfb128, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SEED-OFB cipher (the legacy provider's).
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_seed_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_seed_ofb128, 1, 16, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SM4-ECB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sm4_ecb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_sm4_ecb, 16, 16, 0, flags(EVP_CIPH_ECB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SM4-CBC cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sm4_cbc() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_sm4_cbc, 16, 16, 16, flags(EVP_CIPH_CBC_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SM4-CFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sm4_cfb128() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_sm4_cfb128, 1, 16, 16, flags(EVP_CIPH_CFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SM4-OFB cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sm4_ofb() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_sm4_ofb128, 1, 16, 16, flags(EVP_CIPH_OFB_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static SM4-CTR cipher.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_sm4_ctr() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_sm4_ctr, 1, 16, 16, flags(EVP_CIPH_CTR_MODE));
        CIPHER.get()
    }
}

ffi_export! {
    /// The static AES-128-CBC-HMAC-SHA1 cipher where the CPU has AES-NI, else NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_cbc_hmac_sha1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_cbc_hmac_sha1, 16, 16, 16, CBC_HMAC);
        if aesni() { CIPHER.get() } else { ptr::null() }
    }
}

ffi_export! {
    /// The static AES-256-CBC-HMAC-SHA1 cipher where the CPU has AES-NI, else NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_cbc_hmac_sha1() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_cbc_hmac_sha1, 16, 32, 16, CBC_HMAC);
        if aesni() { CIPHER.get() } else { ptr::null() }
    }
}

ffi_export! {
    /// The static AES-128-CBC-HMAC-SHA256 cipher where the CPU has AES-NI, else NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_128_cbc_hmac_sha256() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_128_cbc_hmac_sha256, 16, 16, 16, CBC_HMAC);
        if aesni() { CIPHER.get() } else { ptr::null() }
    }
}

ffi_export! {
    /// The static AES-256-CBC-HMAC-SHA256 cipher where the CPU has AES-NI, else NULL.
    ///
    /// # Safety
    /// No preconditions.
    pub unsafe extern "C" fn EVP_aes_256_cbc_hmac_sha256() -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        static CIPHER: Static = Static::new(NID_aes_256_cbc_hmac_sha256, 16, 32, 16, CBC_HMAC);
        if aesni() { CIPHER.get() } else { ptr::null() }
    }
}

/// `OBJ_NAME_add` with an alias's or cipher's data. 0 on failure.
///
/// # Safety
/// `name` and `data` are NULL or strings or a live cipher method.
unsafe fn add(name: *const c_char, kind: c_int, data: *const c_char) -> c_int {
    // SAFETY: the caller's guarantee; the table keeps the pointers, which are static.
    unsafe { OBJ_NAME_add(name, kind, data) }
}

ffi_export! {
    /// Adds `cipher` to the cipher names under its NID's short and long names. Returns 1, or
    /// 0 (for NULL too, as OpenSSL does: an absent composite is skipped).
    ///
    /// # Safety
    /// `cipher` is NULL or a live cipher method that outlives its names.
    pub unsafe extern "C" fn EVP_add_cipher(cipher: *const EVP_CIPHER) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let Some(m) = (unsafe { method(cipher) }) else { return 0 };
        let nid = m.nid;
        // SAFETY: no preconditions.
        let name = unsafe { OBJ_nid2sn(nid) };
        // SAFETY: static strings and the caller's method.
        if unsafe { add(name, OBJ_NAME_TYPE_CIPHER_METH, cipher.cast()) } == 0 {
            return 0;
        }
        // SAFETY: no preconditions.
        let long = unsafe { OBJ_nid2ln(nid) };
        // SAFETY: as above.
        unsafe { add(long, OBJ_NAME_TYPE_CIPHER_METH, cipher.cast()) }
    }
}

/// A step of `openssl_add_all_ciphers_int`.
enum Add {
    Cipher(unsafe extern "C" fn() -> *const EVP_CIPHER),
    /// `EVP_add_cipher_alias(name, alias)`.
    Alias(&'static core::ffi::CStr, &'static core::ffi::CStr),
}

/// `openssl_add_all_ciphers_int`: the static ciphers and their aliases, in OpenSSL's order.
pub(crate) fn add_all_ciphers() {
    use Add::{Alias, Cipher as C};
    let steps = [
        C(EVP_des_cfb64),
        C(EVP_des_cfb1),
        C(EVP_des_cfb8),
        C(EVP_des_ede_cfb64),
        C(EVP_des_ede3_cfb64),
        C(EVP_des_ede3_cfb1),
        C(EVP_des_ede3_cfb8),
        C(EVP_des_ofb),
        C(EVP_des_ede_ofb),
        C(EVP_des_ede3_ofb),
        C(EVP_desx_cbc),
        Alias(SN_desx_cbc, c"DESX"),
        Alias(SN_desx_cbc, c"desx"),
        C(EVP_des_cbc),
        Alias(SN_des_cbc, c"DES"),
        Alias(SN_des_cbc, c"des"),
        C(EVP_des_ede_cbc),
        C(EVP_des_ede3_cbc),
        Alias(SN_des_ede3_cbc, c"DES3"),
        Alias(SN_des_ede3_cbc, c"des3"),
        C(EVP_des_ecb),
        C(EVP_des_ede),
        Alias(SN_des_ede_ecb, c"DES-EDE-ECB"),
        Alias(SN_des_ede_ecb, c"des-ede-ecb"),
        C(EVP_des_ede3),
        Alias(SN_des_ede3_ecb, c"DES-EDE3-ECB"),
        Alias(SN_des_ede3_ecb, c"des-ede3-ecb"),
        C(EVP_des_ede3_wrap),
        Alias(SN_id_smime_alg_CMS3DESwrap, c"des3-wrap"),
        C(EVP_rc4),
        C(EVP_rc4_40),
        C(EVP_rc4_hmac_md5),
        C(EVP_idea_ecb),
        C(EVP_idea_cfb64),
        C(EVP_idea_ofb),
        C(EVP_idea_cbc),
        Alias(SN_idea_cbc, c"IDEA"),
        Alias(SN_idea_cbc, c"idea"),
        C(EVP_seed_ecb),
        C(EVP_seed_cfb128),
        C(EVP_seed_ofb),
        C(EVP_seed_cbc),
        Alias(SN_seed_cbc, c"SEED"),
        Alias(SN_seed_cbc, c"seed"),
        C(EVP_sm4_ecb),
        C(EVP_sm4_cbc),
        C(EVP_sm4_cfb128),
        C(EVP_sm4_ofb),
        C(EVP_sm4_ctr),
        Alias(SN_sm4_cbc, c"SM4"),
        Alias(SN_sm4_cbc, c"sm4"),
        C(EVP_rc2_ecb),
        C(EVP_rc2_cfb64),
        C(EVP_rc2_ofb),
        C(EVP_rc2_cbc),
        C(EVP_rc2_40_cbc),
        C(EVP_rc2_64_cbc),
        Alias(SN_rc2_cbc, c"RC2"),
        Alias(SN_rc2_cbc, c"rc2"),
        Alias(SN_rc2_cbc, c"rc2-128"),
        Alias(SN_rc2_64_cbc, c"rc2-64"),
        Alias(SN_rc2_40_cbc, c"rc2-40"),
        C(EVP_bf_ecb),
        C(EVP_bf_cfb64),
        C(EVP_bf_ofb),
        C(EVP_bf_cbc),
        Alias(SN_bf_cbc, c"BF"),
        Alias(SN_bf_cbc, c"bf"),
        Alias(SN_bf_cbc, c"blowfish"),
        C(EVP_cast5_ecb),
        C(EVP_cast5_cfb64),
        C(EVP_cast5_ofb),
        C(EVP_cast5_cbc),
        Alias(SN_cast5_cbc, c"CAST"),
        Alias(SN_cast5_cbc, c"cast"),
        Alias(SN_cast5_cbc, c"CAST-cbc"),
        Alias(SN_cast5_cbc, c"cast-cbc"),
        C(EVP_aes_128_ecb),
        C(EVP_aes_128_cbc),
        C(EVP_aes_128_cfb128),
        C(EVP_aes_128_cfb1),
        C(EVP_aes_128_cfb8),
        C(EVP_aes_128_ofb),
        C(EVP_aes_128_ctr),
        C(EVP_aes_128_gcm),
        C(EVP_aes_128_ocb),
        C(EVP_aes_128_xts),
        C(EVP_aes_128_ccm),
        C(EVP_aes_128_wrap),
        Alias(SN_id_aes128_wrap, c"aes128-wrap"),
        C(EVP_aes_128_wrap_pad),
        Alias(SN_id_aes128_wrap_pad, c"aes128-wrap-pad"),
        Alias(SN_aes_128_cbc, c"AES128"),
        Alias(SN_aes_128_cbc, c"aes128"),
        C(EVP_aes_192_ecb),
        C(EVP_aes_192_cbc),
        C(EVP_aes_192_cfb128),
        C(EVP_aes_192_cfb1),
        C(EVP_aes_192_cfb8),
        C(EVP_aes_192_ofb),
        C(EVP_aes_192_ctr),
        C(EVP_aes_192_gcm),
        C(EVP_aes_192_ocb),
        C(EVP_aes_192_ccm),
        C(EVP_aes_192_wrap),
        Alias(SN_id_aes192_wrap, c"aes192-wrap"),
        C(EVP_aes_192_wrap_pad),
        Alias(SN_id_aes192_wrap_pad, c"aes192-wrap-pad"),
        Alias(SN_aes_192_cbc, c"AES192"),
        Alias(SN_aes_192_cbc, c"aes192"),
        C(EVP_aes_256_ecb),
        C(EVP_aes_256_cbc),
        C(EVP_aes_256_cfb128),
        C(EVP_aes_256_cfb1),
        C(EVP_aes_256_cfb8),
        C(EVP_aes_256_ofb),
        C(EVP_aes_256_ctr),
        C(EVP_aes_256_gcm),
        C(EVP_aes_256_ocb),
        C(EVP_aes_256_xts),
        C(EVP_aes_256_ccm),
        C(EVP_aes_256_wrap),
        Alias(SN_id_aes256_wrap, c"aes256-wrap"),
        C(EVP_aes_256_wrap_pad),
        Alias(SN_id_aes256_wrap_pad, c"aes256-wrap-pad"),
        Alias(SN_aes_256_cbc, c"AES256"),
        Alias(SN_aes_256_cbc, c"aes256"),
        C(EVP_aes_128_cbc_hmac_sha1),
        C(EVP_aes_256_cbc_hmac_sha1),
        C(EVP_aes_128_cbc_hmac_sha256),
        C(EVP_aes_256_cbc_hmac_sha256),
        C(EVP_aria_128_ecb),
        C(EVP_aria_128_cbc),
        C(EVP_aria_128_cfb128),
        C(EVP_aria_128_cfb1),
        C(EVP_aria_128_cfb8),
        C(EVP_aria_128_ctr),
        C(EVP_aria_128_ofb),
        C(EVP_aria_128_gcm),
        C(EVP_aria_128_ccm),
        Alias(SN_aria_128_cbc, c"ARIA128"),
        Alias(SN_aria_128_cbc, c"aria128"),
        C(EVP_aria_192_ecb),
        C(EVP_aria_192_cbc),
        C(EVP_aria_192_cfb128),
        C(EVP_aria_192_cfb1),
        C(EVP_aria_192_cfb8),
        C(EVP_aria_192_ctr),
        C(EVP_aria_192_ofb),
        C(EVP_aria_192_gcm),
        C(EVP_aria_192_ccm),
        Alias(SN_aria_192_cbc, c"ARIA192"),
        Alias(SN_aria_192_cbc, c"aria192"),
        C(EVP_aria_256_ecb),
        C(EVP_aria_256_cbc),
        C(EVP_aria_256_cfb128),
        C(EVP_aria_256_cfb1),
        C(EVP_aria_256_cfb8),
        C(EVP_aria_256_ctr),
        C(EVP_aria_256_ofb),
        C(EVP_aria_256_gcm),
        C(EVP_aria_256_ccm),
        Alias(SN_aria_256_cbc, c"ARIA256"),
        Alias(SN_aria_256_cbc, c"aria256"),
        C(EVP_camellia_128_ecb),
        C(EVP_camellia_128_cbc),
        C(EVP_camellia_128_cfb128),
        C(EVP_camellia_128_cfb1),
        C(EVP_camellia_128_cfb8),
        C(EVP_camellia_128_ofb),
        Alias(SN_camellia_128_cbc, c"CAMELLIA128"),
        Alias(SN_camellia_128_cbc, c"camellia128"),
        C(EVP_camellia_192_ecb),
        C(EVP_camellia_192_cbc),
        C(EVP_camellia_192_cfb128),
        C(EVP_camellia_192_cfb1),
        C(EVP_camellia_192_cfb8),
        C(EVP_camellia_192_ofb),
        Alias(SN_camellia_192_cbc, c"CAMELLIA192"),
        Alias(SN_camellia_192_cbc, c"camellia192"),
        C(EVP_camellia_256_ecb),
        C(EVP_camellia_256_cbc),
        C(EVP_camellia_256_cfb128),
        C(EVP_camellia_256_cfb1),
        C(EVP_camellia_256_cfb8),
        C(EVP_camellia_256_ofb),
        Alias(SN_camellia_256_cbc, c"CAMELLIA256"),
        Alias(SN_camellia_256_cbc, c"camellia256"),
        C(EVP_camellia_128_ctr),
        C(EVP_camellia_192_ctr),
        C(EVP_camellia_256_ctr),
        C(EVP_chacha20),
        C(EVP_chacha20_poly1305),
    ];
    for step in steps {
        match step {
            Add::Cipher(get) => {
                // SAFETY: a getter without preconditions.
                let c = unsafe { get() };
                // SAFETY: a static method, or NULL (which is skipped).
                unsafe { EVP_add_cipher(c) };
            }
            Add::Alias(name, alias) => {
                // SAFETY: static strings.
                unsafe {
                    add(
                        alias.as_ptr(),
                        OBJ_NAME_TYPE_CIPHER_METH | OBJ_NAME_ALIAS,
                        name.as_ptr(),
                    )
                };
            }
        }
    }
}

/// The cipher an `OBJ_NAME` entry's name resolves to (following aliases), or NULL.
///
/// # Safety
/// `entry` is a live entry of the table.
unsafe fn resolve(entry: *const OBJ_NAME) -> *const EVP_CIPHER {
    // SAFETY: the caller's guarantee.
    let e = unsafe { &*entry };
    // SAFETY: the entry's name and type.
    unsafe { OBJ_NAME_get(e.name, e.type_) }.cast()
}

ffi_callback! {
    /// Collects the type (`EVP_CIPHER_get_type`) of each cipher entry's cipher into a
    /// `Vec<c_int>`.
    ///
    /// # Safety
    /// `entry` is a live entry; `arg` is a `Vec<c_int>`.
    pub(crate) unsafe extern "C" fn collect_type(entry: *const OBJ_NAME, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let c = unsafe { resolve(entry) };
        if !c.is_null() {
            // SAFETY: the table's cipher method.
            let t = unsafe { super::cipher::EVP_CIPHER_get_type(c) };
            // SAFETY: the caller's guarantee.
            unsafe { &mut *arg.cast::<Vec<c_int>>() }.push(t);
        }
    }
}

/// The types of the cipher names' ciphers (`get_legacy_cipher_names`: CFB1 and CFB8 count as
/// CFB, and a cipher without an OID as none), in the table's order, after
/// `OPENSSL_INIT_ADD_ALL_CIPHERS`: what each context's name map starts with.
pub(crate) fn cipher_types() -> Vec<c_int> {
    init_ciphers();
    let mut types: Vec<c_int> = Vec::new();
    // SAFETY: the callback takes the vector.
    unsafe {
        OBJ_NAME_do_all(
            OBJ_NAME_TYPE_CIPHER_METH,
            Some(collect_type),
            (&raw mut types).cast(),
        )
    };
    types
}

/// `ossl_namemap_doall_names` with `cipher_from_name`: the first of a number's names that's
/// a cipher name.
fn cipher_from_names(id: u32) -> *const EVP_CIPHER {
    for n in fetch::names_of(ptr::null(), id) {
        let Ok(c) = std::ffi::CString::new(n) else {
            continue;
        };
        // SAFETY: a string and a type.
        let cp = unsafe { OBJ_NAME_get(c.as_ptr(), OBJ_NAME_TYPE_CIPHER_METH) };
        if !cp.is_null() {
            return cp.cast();
        }
    }
    ptr::null()
}

ffi_export! {
    /// The cipher named `name`: a cipher name's, or else the first cipher name among the
    /// names `name` shares a number with in the default context's name map (fetching once to
    /// learn the name if it's new). NULL if there's none.
    ///
    /// # Safety
    /// `name` is NULL or a string.
    pub unsafe extern "C" fn EVP_get_cipherbyname(name: *const c_char) -> *const EVP_CIPHER
    where failure = ptr::null(), library = ERR_LIB_EVP
    {
        if init_ciphers() == 0 {
            return ptr::null();
        }
        // SAFETY: the caller's guarantee.
        let cp = unsafe { OBJ_NAME_get(name, OBJ_NAME_TYPE_CIPHER_METH) };
        if !cp.is_null() {
            return cp.cast();
        }
        let bytes = if name.is_null() {
            &b""[..]
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { core::ffi::CStr::from_ptr(name) }.to_bytes()
        };
        let mut id = fetch::number_in(ptr::null(), bytes);
        if id == 0 {
            // The name may not be known yet: a fetch teaches the context its names.
            // SAFETY: no preconditions.
            unsafe { ERR_set_mark() };
            // SAFETY: the default context and the caller's name.
            let fetched = unsafe { EVP_CIPHER_fetch(ptr::null_mut(), name, ptr::null()) };
            // SAFETY: the fetched reference, or NULL.
            unsafe { EVP_CIPHER_free(fetched) };
            // SAFETY: no preconditions.
            unsafe { ERR_pop_to_mark() };
            id = fetch::number_in(ptr::null(), bytes);
            if id == 0 {
                return ptr::null();
            }
        }
        cipher_from_names(id)
    }
}

/// `EVP_CIPHER_do_all`'s callback.
type DoAllFn = unsafe extern "C" fn(*const EVP_CIPHER, *const c_char, *const c_char, *mut c_void);

/// The callback and its argument (`struct doall_cipher`).
struct DoAll {
    fn_: DoAllFn,
    arg: *mut c_void,
}

ffi_callback! {
    /// `do_all_cipher_fn`: an alias as `(NULL, alias, name)`, a cipher as
    /// `(cipher, name, NULL)`.
    ///
    /// # Safety
    /// `entry` is a live entry; `arg` is a `DoAll`.
    pub(crate) unsafe extern "C" fn do_all_cipher(entry: *const OBJ_NAME, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        let e = unsafe { &*entry };
        // SAFETY: as above.
        let d = unsafe { &*arg.cast::<DoAll>() };
        if e.alias != 0 {
            // SAFETY: the application's callback with the entry's strings.
            unsafe { (d.fn_)(ptr::null(), e.name, e.data, d.arg) };
        } else {
            // SAFETY: as above, with the entry's cipher.
            unsafe { (d.fn_)(e.data.cast(), e.name, ptr::null(), d.arg) };
        }
    }
}

ffi_export! {
    /// Calls `fn_` for each cipher name, in the table's order, after adding the ciphers.
    ///
    /// # Safety
    /// `fn_` is NULL or a function of the documented type.
    pub unsafe extern "C" fn EVP_CIPHER_do_all(fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        init_ciphers();
        let Some(f) = fn_ else { return };
        let mut d = DoAll { fn_: f, arg };
        // SAFETY: the callback takes the `DoAll`.
        unsafe { OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, Some(do_all_cipher), (&raw mut d).cast()) };
    }
}

ffi_export! {
    /// As [`EVP_CIPHER_do_all`], in order of name.
    ///
    /// # Safety
    /// As for [`EVP_CIPHER_do_all`].
    pub unsafe extern "C" fn EVP_CIPHER_do_all_sorted(fn_: Option<DoAllFn>, arg: *mut c_void)
    where failure = (), library = ERR_LIB_EVP
    {
        init_ciphers();
        let Some(f) = fn_ else { return };
        let mut d = DoAll { fn_: f, arg };
        // SAFETY: the callback takes the `DoAll`.
        unsafe { OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH, Some(do_all_cipher), (&raw mut d).cast()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_ciphers_are_refused() {
        // SAFETY: NULL is the case under test.
        assert_eq!(unsafe { EVP_add_cipher(ptr::null()) }, 0);
    }

    #[test]
    fn static_ciphers_outlive_frees() {
        // SAFETY: no preconditions.
        let c = unsafe { EVP_aes_128_cbc() };
        for _ in 0..3 {
            // SAFETY: a static cipher, whose frees do nothing.
            unsafe { EVP_CIPHER_free(c.cast_mut()) };
        }
        // SAFETY: as above.
        assert_eq!(unsafe { EVP_aes_128_cbc() }, c);
        // SAFETY: the live static cipher.
        let m = unsafe { method(c) }.map(|m| (m.nid, m.block_size, m.key_len, m.iv_len));
        assert_eq!(m, Some((NID_aes_128_cbc, 16, 16, 16)));
        // SAFETY: no preconditions.
        assert_eq!(unsafe { EVP_des_ede() }, unsafe { EVP_des_ede_ecb() });
    }
}
