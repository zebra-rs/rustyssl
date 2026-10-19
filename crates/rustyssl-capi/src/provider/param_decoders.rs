//! 3.6's parameter decoders: what each provider function that 3.6 generates a decoder for
//! (`produce_param_decoder` in the providers' `.c.in` files, `util/perl/OpenSSL/paramnames.pm`)
//! takes, field by field. 3.6 reads a request through its decoder before anything else, and
//! fails it when it gives a field twice (`PROV_R_REPEATED_PARAMETER`, "param <key> is repeated";
//! 3.5 took the first) or a list field more times than its limit (`PROV_R_TOO_MANY_RECORDS`,
//! "param <key> present ><n> times"). The tables follow OpenSSL 3.6.5's decoders without their
//! FIPS-only fields (and without those that have only FIPS fields); keys of other functions are
//! ignored, as there.

use core::ffi::CStr;

use rustyssl_abi::{
    ERR_LIB_PROV, OSSL_ALG_PARAM_ENGINE, OSSL_ASYM_CIPHER_PARAM_DIGEST,
    OSSL_ASYM_CIPHER_PARAM_ENGINE, OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION,
    OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS,
    OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS,
    OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_ASYM_CIPHER_PARAM_PAD_MODE,
    OSSL_ASYM_CIPHER_PARAM_PROPERTIES, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION,
    OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, OSSL_CIPHER_PARAM_AEAD,
    OSSL_CIPHER_PARAM_AEAD_IV_GENERATED, OSSL_CIPHER_PARAM_AEAD_IVLEN, OSSL_CIPHER_PARAM_AEAD_TAG,
    OSSL_CIPHER_PARAM_AEAD_TAGLEN, OSSL_CIPHER_PARAM_AEAD_TLS1_AAD,
    OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN,
    OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED, OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV,
    OSSL_CIPHER_PARAM_BLOCK_SIZE, OSSL_CIPHER_PARAM_CTS, OSSL_CIPHER_PARAM_CUSTOM_IV,
    OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC, OSSL_CIPHER_PARAM_HAS_RAND_KEY, OSSL_CIPHER_PARAM_IV,
    OSSL_CIPHER_PARAM_IVLEN, OSSL_CIPHER_PARAM_KEYLEN, OSSL_CIPHER_PARAM_MODE,
    OSSL_CIPHER_PARAM_NUM, OSSL_CIPHER_PARAM_PADDING, OSSL_CIPHER_PARAM_TLS_MAC,
    OSSL_CIPHER_PARAM_TLS_MAC_SIZE, OSSL_CIPHER_PARAM_TLS_VERSION,
    OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, OSSL_CIPHER_PARAM_UPDATED_IV, OSSL_CIPHER_PARAM_USE_BITS,
    OSSL_DECODER_PARAM_PROPERTIES, OSSL_DIGEST_PARAM_ALGID_ABSENT, OSSL_DIGEST_PARAM_BLOCK_SIZE,
    OSSL_DIGEST_PARAM_SIZE, OSSL_DIGEST_PARAM_XOF, OSSL_DIGEST_PARAM_XOFLEN,
    OSSL_DRBG_PARAM_CIPHER, OSSL_DRBG_PARAM_DIGEST, OSSL_DRBG_PARAM_MAC,
    OSSL_DRBG_PARAM_MAX_ADINLEN, OSSL_DRBG_PARAM_MAX_ENTROPYLEN, OSSL_DRBG_PARAM_MAX_NONCELEN,
    OSSL_DRBG_PARAM_MAX_PERSLEN, OSSL_DRBG_PARAM_MIN_ENTROPYLEN, OSSL_DRBG_PARAM_MIN_NONCELEN,
    OSSL_DRBG_PARAM_PROPERTIES, OSSL_DRBG_PARAM_RESEED_COUNTER, OSSL_DRBG_PARAM_RESEED_REQUESTS,
    OSSL_DRBG_PARAM_RESEED_TIME, OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL, OSSL_DRBG_PARAM_USE_DF,
    OSSL_ENCODER_PARAM_CIPHER, OSSL_ENCODER_PARAM_ENCRYPT_LEVEL, OSSL_ENCODER_PARAM_PROPERTIES,
    OSSL_ENCODER_PARAM_SAVE_PARAMETERS, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
    OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS,
    OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_EXCHANGE_PARAM_KDF_TYPE, OSSL_EXCHANGE_PARAM_KDF_UKM,
    OSSL_EXCHANGE_PARAM_PAD, OSSL_KDF_PARAM_ARGON2_AD, OSSL_KDF_PARAM_ARGON2_LANES,
    OSSL_KDF_PARAM_ARGON2_MEMCOST, OSSL_KDF_PARAM_ARGON2_VERSION, OSSL_KDF_PARAM_CEK_ALG,
    OSSL_KDF_PARAM_CIPHER, OSSL_KDF_PARAM_CONSTANT, OSSL_KDF_PARAM_DATA, OSSL_KDF_PARAM_DIGEST,
    OSSL_KDF_PARAM_EARLY_CLEAN, OSSL_KDF_PARAM_HMACDRBG_ENTROPY, OSSL_KDF_PARAM_HMACDRBG_NONCE,
    OSSL_KDF_PARAM_INFO, OSSL_KDF_PARAM_ITER, OSSL_KDF_PARAM_KBKDF_R, OSSL_KDF_PARAM_KBKDF_USE_L,
    OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR, OSSL_KDF_PARAM_KEY, OSSL_KDF_PARAM_LABEL,
    OSSL_KDF_PARAM_MAC, OSSL_KDF_PARAM_MAC_SIZE, OSSL_KDF_PARAM_MODE, OSSL_KDF_PARAM_PASSWORD,
    OSSL_KDF_PARAM_PKCS5, OSSL_KDF_PARAM_PKCS12_ID, OSSL_KDF_PARAM_PREFIX,
    OSSL_KDF_PARAM_PROPERTIES, OSSL_KDF_PARAM_SALT, OSSL_KDF_PARAM_SCRYPT_MAXMEM,
    OSSL_KDF_PARAM_SCRYPT_N, OSSL_KDF_PARAM_SCRYPT_P, OSSL_KDF_PARAM_SCRYPT_R,
    OSSL_KDF_PARAM_SECRET, OSSL_KDF_PARAM_SEED, OSSL_KDF_PARAM_SIZE,
    OSSL_KDF_PARAM_SSHKDF_SESSION_ID, OSSL_KDF_PARAM_SSHKDF_TYPE, OSSL_KDF_PARAM_SSHKDF_XCGHASH,
    OSSL_KDF_PARAM_THREADS, OSSL_KDF_PARAM_UKM, OSSL_KDF_PARAM_X942_ACVPINFO,
    OSSL_KDF_PARAM_X942_PARTYUINFO, OSSL_KDF_PARAM_X942_PARTYVINFO,
    OSSL_KDF_PARAM_X942_SUPP_PRIVINFO, OSSL_KDF_PARAM_X942_SUPP_PUBINFO,
    OSSL_KDF_PARAM_X942_USE_KEYBITS, OSSL_KEM_PARAM_IKME, OSSL_KEM_PARAM_OPERATION,
    OSSL_MAC_PARAM_BLOCK_SIZE, OSSL_MAC_PARAM_C_ROUNDS, OSSL_MAC_PARAM_CIPHER,
    OSSL_MAC_PARAM_CUSTOM, OSSL_MAC_PARAM_D_ROUNDS, OSSL_MAC_PARAM_DIGEST, OSSL_MAC_PARAM_IV,
    OSSL_MAC_PARAM_KEY, OSSL_MAC_PARAM_PROPERTIES, OSSL_MAC_PARAM_SALT, OSSL_MAC_PARAM_SIZE,
    OSSL_MAC_PARAM_TLS_DATA_SIZE, OSSL_MAC_PARAM_XOF, OSSL_OBJECT_PARAM_DATA_STRUCTURE, OSSL_PARAM,
    OSSL_PKEY_PARAM_BITS, OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM, OSSL_PKEY_PARAM_CMS_RI_TYPE,
    OSSL_PKEY_PARAM_DHKEM_IKM, OSSL_PKEY_PARAM_DIST_ID, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
    OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_MANDATORY_DIGEST, OSSL_PKEY_PARAM_MAX_SIZE,
    OSSL_PKEY_PARAM_ML_DSA_SEED, OSSL_PKEY_PARAM_ML_KEM_SEED, OSSL_PKEY_PARAM_PRIV_KEY,
    OSSL_PKEY_PARAM_PROPERTIES, OSSL_PKEY_PARAM_PUB_KEY, OSSL_PKEY_PARAM_SECURITY_BITS,
    OSSL_PKEY_PARAM_SECURITY_CATEGORY, OSSL_PKEY_PARAM_SLH_DSA_SEED,
    OSSL_PROV_PARAM_CORE_PROV_NAME, OSSL_RAND_PARAM_GENERATE, OSSL_RAND_PARAM_MAX_REQUEST,
    OSSL_RAND_PARAM_STATE, OSSL_RAND_PARAM_STRENGTH, OSSL_RAND_PARAM_TEST_ENTROPY,
    OSSL_RAND_PARAM_TEST_NONCE, OSSL_SIGNATURE_PARAM_ALGORITHM_ID,
    OSSL_SIGNATURE_PARAM_CONTEXT_STRING, OSSL_SIGNATURE_PARAM_DETERMINISTIC,
    OSSL_SIGNATURE_PARAM_DIGEST, OSSL_SIGNATURE_PARAM_DIGEST_SIZE, OSSL_SIGNATURE_PARAM_INSTANCE,
    OSSL_SIGNATURE_PARAM_KAT, OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING,
    OSSL_SIGNATURE_PARAM_MGF1_DIGEST, OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES,
    OSSL_SIGNATURE_PARAM_MU, OSSL_SIGNATURE_PARAM_NONCE_TYPE, OSSL_SIGNATURE_PARAM_PAD_MODE,
    OSSL_SIGNATURE_PARAM_PROPERTIES, OSSL_SIGNATURE_PARAM_PSS_SALTLEN,
    OSSL_SIGNATURE_PARAM_SIGNATURE, OSSL_SIGNATURE_PARAM_TEST_ENTROPY, OSSL_SKEY_PARAM_RAW_BYTES,
    OSSL_STORE_PARAM_EXPECT, OSSL_STORE_PARAM_INPUT_TYPE, OSSL_STORE_PARAM_PROPERTIES,
    OSSL_STORE_PARAM_SUBJECT, PROV_R_REPEATED_PARAMETER, PROV_R_TOO_MANY_RECORDS,
};

/// One field of a decoder: the keys that fill it and how many times it may be given.
pub(crate) struct Field {
    keys: &'static [&'static CStr],
    max: usize,
}

/// A decoder: its C name (the function its errors name) and fields.
pub(crate) struct Decoder {
    name: &'static str,
    fields: &'static [Field],
}

/// Reads `params` (a C parameter array, or NULL) as `decoder` does: false, with the decoder's
/// error raised, if it gives a field more often than it may.
///
/// # Safety
/// `params` is NULL or a parameter array ending in an entry with a NULL key.
pub(crate) unsafe fn decode(params: *const OSSL_PARAM, decoder: &Decoder) -> bool {
    let mut counts = [0usize; 32];
    let mut p = params;
    while !p.is_null() {
        // SAFETY: an entry of the caller's array, up to its end.
        let entry = unsafe { &*p };
        if entry.key.is_null() {
            break;
        }
        // SAFETY: a key is a C string.
        let key = unsafe { CStr::from_ptr(entry.key) };
        if let Some(i) = decoder.fields.iter().position(|f| f.keys.contains(&key))
            && let (Some(count), Some(field)) = (counts.get_mut(i), decoder.fields.get(i))
        {
            if *count >= field.max {
                let text = if field.max == 1 {
                    format!("param {} is repeated", key.to_string_lossy())
                } else {
                    format!(
                        "param {} present >{} times",
                        key.to_string_lossy(),
                        field.max
                    )
                };
                let reason = if field.max == 1 {
                    PROV_R_REPEATED_PARAMETER
                } else {
                    PROV_R_TOO_MANY_RECORDS
                };
                crate::err::raise_with_bytes(ERR_LIB_PROV, reason, decoder.name, text.as_bytes());
                return false;
            }
            *count += 1;
        }
        p = p.wrapping_add(1);
    }
    true
}

/// `any2obj_set_ctx_params`: used by `any2obj_set_ctx_params` (file_store_any2obj.c.in).
pub(crate) const ANY2OBJ_SET_CTX_PARAMS: Decoder = Decoder {
    name: "any2obj_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_OBJECT_PARAM_DATA_STRUCTURE],
        max: 1,
    }],
};

/// `argon2_get_ctx_params`: used by `kdf_argon2_get_ctx_params` (argon2.c.in).
pub(crate) const ARGON2_GET_CTX_PARAMS: Decoder = Decoder {
    name: "argon2_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `argon2_set_ctx_params`: used by `argon2_set_ctx_params` (argon2.c.in).
pub(crate) const ARGON2_SET_CTX_PARAMS: Decoder = Decoder {
    name: "argon2_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PASSWORD],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SECRET],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_ARGON2_AD],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_ITER],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_THREADS],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_ARGON2_LANES],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_ARGON2_MEMCOST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_EARLY_CLEAN],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_ARGON2_VERSION],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
    ],
};

/// `blake2_get_ctx`: used by `blake2_get_ctx_params` (blake2_mac_impl.c).
pub(crate) const BLAKE2_GET_CTX: Decoder = Decoder {
    name: "blake2_get_ctx_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_BLOCK_SIZE],
            max: 1,
        },
    ],
};

/// `blake2_mac_set_ctx`: used by `blake2_mac_set_ctx_params` (blake2_mac_impl.c).
pub(crate) const BLAKE2_MAC_SET_CTX: Decoder = Decoder {
    name: "blake2_mac_set_ctx_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_CUSTOM],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_SALT],
            max: 1,
        },
    ],
};

/// `blake_get_ctx_params`: used by `blake_settable_ctx_params` (blake2_prov.c.in).
pub(crate) const BLAKE_GET_CTX_PARAMS: Decoder = Decoder {
    name: "blake_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_DIGEST_PARAM_SIZE],
        max: 1,
    }],
};

/// `blake_set_ctx_params`: used by `blake_settable_ctx_params` (blake2_prov.c.in).
pub(crate) const BLAKE_SET_CTX_PARAMS: Decoder = Decoder {
    name: "blake_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_DIGEST_PARAM_SIZE],
        max: 1,
    }],
};

/// `chacha20_poly1305_get_ctx_params`: used by `chacha20_poly1305_get_ctx_params` (cipher_chacha20_poly1305.c.in).
pub(crate) const CHACHA20_POLY1305_GET_CTX_PARAMS: Decoder = Decoder {
    name: "chacha20_poly1305_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_KEYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IVLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAGLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAG],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD],
            max: 1,
        },
    ],
};

/// `chacha20_poly1305_set_ctx_params`: used by `chacha20_poly1305_set_ctx_params` (cipher_chacha20_poly1305.c.in).
pub(crate) const CHACHA20_POLY1305_SET_CTX_PARAMS: Decoder = Decoder {
    name: "chacha20_poly1305_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_KEYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IVLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAG],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_AAD],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED],
            max: 1,
        },
    ],
};

/// `cipher_generic_get_ctx_params`: used by `ossl_cipher_generic_get_ctx_params` (ciphercommon.c.in).
pub(crate) const CIPHER_GENERIC_GET_CTX_PARAMS: Decoder = Decoder {
    name: "cipher_generic_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_KEYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IVLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_PADDING],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_NUM],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IV],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_UPDATED_IV],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_TLS_MAC],
            max: 1,
        },
    ],
};

/// `cipher_generic_set_ctx_params`: used by `ossl_cipher_generic_set_ctx_params` (ciphercommon.c.in).
pub(crate) const CIPHER_GENERIC_SET_CTX_PARAMS: Decoder = Decoder {
    name: "cipher_generic_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_PADDING],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_NUM],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_USE_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_TLS_VERSION],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_TLS_MAC_SIZE],
            max: 1,
        },
    ],
};

/// `cipher_var_keylen_set_ctx_params`: used by `ossl_cipher_var_keylen_set_ctx_params` (ciphercommon.c.in).
pub(crate) const CIPHER_VAR_KEYLEN_SET_CTX_PARAMS: Decoder = Decoder {
    name: "cipher_var_keylen_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_PADDING],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_NUM],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_USE_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_TLS_VERSION],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_TLS_MAC_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_KEYLEN],
            max: 1,
        },
    ],
};

/// `cmac_get_ctx_params`: used by `cmac_get_ctx_params` (cmac_prov.c.in).
pub(crate) const CMAC_GET_CTX_PARAMS: Decoder = Decoder {
    name: "cmac_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_BLOCK_SIZE],
            max: 1,
        },
    ],
};

/// `cmac_set_ctx_params`: used by `cmac_set_ctx_params` (cmac_prov.c.in).
pub(crate) const CMAC_SET_CTX_PARAMS: Decoder = Decoder {
    name: "cmac_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_CIPHER],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_KEY],
            max: 1,
        },
    ],
};

/// `der2key_set_ctx_params`: used by `der2key_set_ctx_params` (decode_der2key.c.in).
pub(crate) const DER2KEY_SET_CTX_PARAMS: Decoder = Decoder {
    name: "der2key_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_DECODER_PARAM_PROPERTIES],
        max: 1,
    }],
};

/// `dh_get_ctx_params`: used by `dh_get_ctx_params` (dh_exch.c.in).
pub(crate) const DH_GET_CTX_PARAMS: Decoder = Decoder {
    name: "dh_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_TYPE],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_OUTLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_UKM],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_CEK_ALG],
            max: 1,
        },
    ],
};

/// `dh_set_ctx_params`: used by `dh_set_ctx_params` (dh_exch.c.in).
pub(crate) const DH_SET_CTX_PARAMS: Decoder = Decoder {
    name: "dh_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_PAD],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_TYPE],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_OUTLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_UKM],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_CEK_ALG],
            max: 1,
        },
    ],
};

/// `digest_default_get_params`: used by `ossl_digest_default_get_params` (digestcommon.c.in).
pub(crate) const DIGEST_DEFAULT_GET_PARAMS: Decoder = Decoder {
    name: "digest_default_get_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DIGEST_PARAM_BLOCK_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_DIGEST_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_DIGEST_PARAM_XOF],
            max: 1,
        },
        Field {
            keys: &[OSSL_DIGEST_PARAM_ALGID_ABSENT],
            max: 1,
        },
    ],
};

/// `drbg_ctr_get_ctx_params`: used by `drbg_ctr_get_ctx_params` (drbg_ctr.c.in).
pub(crate) const DRBG_CTR_GET_CTX_PARAMS: Decoder = Decoder {
    name: "drbg_ctr_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DRBG_PARAM_CIPHER],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_USE_DF],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STATE],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STRENGTH],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_MAX_REQUEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MIN_ENTROPYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_ENTROPYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MIN_NONCELEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_NONCELEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_PERSLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_ADINLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_COUNTER],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_REQUESTS],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL],
            max: 1,
        },
    ],
};

/// `drbg_ctr_set_ctx_params`: used by `drbg_ctr_instantiate_wrapper` (drbg_ctr.c.in), `drbg_ctr_set_ctx_params_decoder` (drbg_ctr.c.in), `drbg_ctr_set_ctx_params` (drbg_ctr.c.in).
pub(crate) const DRBG_CTR_SET_CTX_PARAMS: Decoder = Decoder {
    name: "drbg_ctr_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DRBG_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_CIPHER],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_USE_DF],
            max: 1,
        },
        Field {
            keys: &[OSSL_PROV_PARAM_CORE_PROV_NAME],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_REQUESTS],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL],
            max: 1,
        },
    ],
};

/// `drbg_hash_get_ctx_params`: used by `drbg_hash_get_ctx_params` (drbg_hash.c.in).
pub(crate) const DRBG_HASH_GET_CTX_PARAMS: Decoder = Decoder {
    name: "drbg_hash_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DRBG_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STATE],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STRENGTH],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_MAX_REQUEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MIN_ENTROPYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_ENTROPYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MIN_NONCELEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_NONCELEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_PERSLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_ADINLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_COUNTER],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_REQUESTS],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL],
            max: 1,
        },
    ],
};

/// `drbg_hash_set_ctx_params`: used by `drbg_hash_instantiate_wrapper` (drbg_hash.c.in), `drbg_hash_set_ctx_params_decoder` (drbg_hash.c.in), `drbg_hash_set_ctx_params` (drbg_hash.c.in).
pub(crate) const DRBG_HASH_SET_CTX_PARAMS: Decoder = Decoder {
    name: "drbg_hash_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DRBG_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_PROV_PARAM_CORE_PROV_NAME],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_REQUESTS],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL],
            max: 1,
        },
    ],
};

/// `drbg_hmac_get_ctx_params`: used by `drbg_hmac_get_ctx_params` (drbg_hmac.c.in).
pub(crate) const DRBG_HMAC_GET_CTX_PARAMS: Decoder = Decoder {
    name: "drbg_hmac_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DRBG_PARAM_MAC],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STATE],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STRENGTH],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_MAX_REQUEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MIN_ENTROPYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_ENTROPYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MIN_NONCELEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_NONCELEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_PERSLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAX_ADINLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_COUNTER],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_REQUESTS],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL],
            max: 1,
        },
    ],
};

/// `drbg_hmac_set_ctx_params`: used by `drbg_hmac_instantiate_wrapper` (drbg_hmac.c.in), `drbg_hmac_set_ctx_params_decoder` (drbg_hmac.c.in), `drbg_hmac_set_ctx_params` (drbg_hmac.c.in).
pub(crate) const DRBG_HMAC_SET_CTX_PARAMS: Decoder = Decoder {
    name: "drbg_hmac_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DRBG_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_MAC],
            max: 1,
        },
        Field {
            keys: &[OSSL_PROV_PARAM_CORE_PROV_NAME],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_REQUESTS],
            max: 1,
        },
        Field {
            keys: &[OSSL_DRBG_PARAM_RESEED_TIME_INTERVAL],
            max: 1,
        },
    ],
};

/// `dsa_get_ctx_params`: used by `dsa_get_ctx_params` (dsa_sig.c.in).
pub(crate) const DSA_GET_CTX_PARAMS: Decoder = Decoder {
    name: "dsa_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_ALGORITHM_ID],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_NONCE_TYPE],
            max: 1,
        },
    ],
};

/// `dsa_set_ctx_params`: used by `dsa_set_ctx_params` (dsa_sig.c.in).
pub(crate) const DSA_SET_CTX_PARAMS: Decoder = Decoder {
    name: "dsa_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_NONCE_TYPE],
            max: 1,
        },
    ],
};

/// `dsa_sigalg_set_ctx_params`: used by `dsa_sigalg_set_ctx_params` (dsa_sig.c.in).
pub(crate) const DSA_SIGALG_SET_CTX_PARAMS: Decoder = Decoder {
    name: "dsa_sigalg_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_SIGNATURE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_NONCE_TYPE],
            max: 1,
        },
    ],
};

/// `ecdh_get_ctx_params`: used by `ecdh_get_ctx_params` (ecdh_exch.c.in).
pub(crate) const ECDH_GET_CTX_PARAMS: Decoder = Decoder {
    name: "ecdh_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_TYPE],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_OUTLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_UKM],
            max: 1,
        },
    ],
};

/// `ecdh_set_ctx_params`: used by `ecdh_set_ctx_params` (ecdh_exch.c.in).
pub(crate) const ECDH_SET_CTX_PARAMS: Decoder = Decoder {
    name: "ecdh_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_TYPE],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_DIGEST_PROPS],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_OUTLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_EXCHANGE_PARAM_KDF_UKM],
            max: 1,
        },
    ],
};

/// `ecdsa_get_ctx_params`: used by `ecdsa_get_ctx_params` (ecdsa_sig.c.in).
pub(crate) const ECDSA_GET_CTX_PARAMS: Decoder = Decoder {
    name: "ecdsa_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_ALGORITHM_ID],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_NONCE_TYPE],
            max: 1,
        },
    ],
};

/// `ecdsa_set_ctx_params`: used by `ecdsa_set_ctx_params` (ecdsa_sig.c.in).
pub(crate) const ECDSA_SET_CTX_PARAMS: Decoder = Decoder {
    name: "ecdsa_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_KAT],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_NONCE_TYPE],
            max: 1,
        },
    ],
};

/// `ecdsa_sigalg_set_ctx_params`: used by `ecdsa_sigalg_set_ctx_params` (ecdsa_sig.c.in).
pub(crate) const ECDSA_SIGALG_SET_CTX_PARAMS: Decoder = Decoder {
    name: "ecdsa_sigalg_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_SIGNATURE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_KAT],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_NONCE_TYPE],
            max: 1,
        },
    ],
};

/// `eckem_set_ctx_params`: used by `eckem_set_ctx_params` (ec_kem.c.in).
pub(crate) const ECKEM_SET_CTX_PARAMS: Decoder = Decoder {
    name: "eckem_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KEM_PARAM_OPERATION],
            max: 1,
        },
        Field {
            keys: &[OSSL_KEM_PARAM_IKME],
            max: 1,
        },
    ],
};

/// `ecx_gen_set_params`: used by `ecx_gen_set_params` (ecx_kmgmt.c.in).
pub(crate) const ECX_GEN_SET_PARAMS: Decoder = Decoder {
    name: "ecx_gen_set_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_GROUP_NAME],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_DHKEM_IKM],
            max: 1,
        },
    ],
};

/// `ecx_get_params`: used by `ecx_get_params` (ecx_kmgmt.c.in).
pub(crate) const ECX_GET_PARAMS: Decoder = Decoder {
    name: "ecx_get_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MAX_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_CATEGORY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY],
            max: 1,
        },
    ],
};

/// `ecx_imexport_types`: used by `ecx_import` (ecx_kmgmt.c.in).
pub(crate) const ECX_IMEXPORT_TYPES: Decoder = Decoder {
    name: "ecx_imexport_types_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
    ],
};

/// `ecx_set_params`: used by `ecx_set_params` (ecx_kmgmt.c.in).
pub(crate) const ECX_SET_PARAMS: Decoder = Decoder {
    name: "ecx_set_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PROPERTIES],
            max: 1,
        },
    ],
};

/// `ecxkem_set_ctx_params`: used by `ecxkem_set_ctx_params` (ecx_kem.c.in).
pub(crate) const ECXKEM_SET_CTX_PARAMS: Decoder = Decoder {
    name: "ecxkem_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KEM_PARAM_OPERATION],
            max: 1,
        },
        Field {
            keys: &[OSSL_KEM_PARAM_IKME],
            max: 1,
        },
    ],
};

/// `ed_get_params`: used by `ed_get_params` (ecx_kmgmt.c.in).
pub(crate) const ED_GET_PARAMS: Decoder = Decoder {
    name: "ed_get_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MAX_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_CATEGORY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MANDATORY_DIGEST],
            max: 1,
        },
    ],
};

/// `eddsa_get_ctx_params`: used by `eddsa_get_ctx_params` (eddsa_sig.c.in).
pub(crate) const EDDSA_GET_CTX_PARAMS: Decoder = Decoder {
    name: "eddsa_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_SIGNATURE_PARAM_ALGORITHM_ID],
        max: 1,
    }],
};

/// `eddsa_set_ctx_params`: used by `eddsa_set_ctx_params` (eddsa_sig.c.in).
pub(crate) const EDDSA_SET_CTX_PARAMS: Decoder = Decoder {
    name: "eddsa_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_INSTANCE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_CONTEXT_STRING],
            max: 1,
        },
    ],
};

/// `eddsa_set_variant_ctx_params`: used by `eddsa_set_variant_ctx_params` (eddsa_sig.c.in).
pub(crate) const EDDSA_SET_VARIANT_CTX_PARAMS: Decoder = Decoder {
    name: "eddsa_set_variant_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_SIGNATURE_PARAM_CONTEXT_STRING],
        max: 1,
    }],
};

/// `epki2pki_set_ctx_params`: used by `epki2pki_set_ctx_params` (decode_epki2pki.c.in).
pub(crate) const EPKI2PKI_SET_CTX_PARAMS: Decoder = Decoder {
    name: "epki2pki_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_DECODER_PARAM_PROPERTIES],
        max: 1,
    }],
};

/// `file_set_ctx_params`: used by `file_set_ctx_params` (file_store.c.in).
pub(crate) const FILE_SET_CTX_PARAMS: Decoder = Decoder {
    name: "file_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_STORE_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_STORE_PARAM_EXPECT],
            max: 1,
        },
        Field {
            keys: &[OSSL_STORE_PARAM_SUBJECT],
            max: 1,
        },
        Field {
            keys: &[OSSL_STORE_PARAM_INPUT_TYPE],
            max: 1,
        },
    ],
};

/// `generic_skey_import`: used by `generic_import` (generic.c.in).
pub(crate) const GENERIC_SKEY_IMPORT: Decoder = Decoder {
    name: "generic_skey_import_decoder",
    fields: &[Field {
        keys: &[OSSL_SKEY_PARAM_RAW_BYTES],
        max: 1,
    }],
};

/// `gmac_get_params`: used by `gmac_get_params` (gmac_prov.c.in).
pub(crate) const GMAC_GET_PARAMS: Decoder = Decoder {
    name: "gmac_get_params_decoder",
    fields: &[Field {
        keys: &[OSSL_MAC_PARAM_SIZE],
        max: 1,
    }],
};

/// `gmac_set_ctx_params`: used by `gmac_set_ctx_params` (gmac_prov.c.in).
pub(crate) const GMAC_SET_CTX_PARAMS: Decoder = Decoder {
    name: "gmac_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_CIPHER],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_IV],
            max: 1,
        },
    ],
};

/// `hkdf_fixed_digest_set_ctx_params`: used by `kdf_hkdf_fixed_digest_set_ctx_params` (hkdf.c.in).
pub(crate) const HKDF_FIXED_DIGEST_SET_CTX_PARAMS: Decoder = Decoder {
    name: "hkdf_fixed_digest_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_INFO],
            max: 5,
        },
    ],
};

/// `hkdf_get_ctx_params`: used by `hkdf_common_get_ctx_params` (hkdf.c.in).
pub(crate) const HKDF_GET_CTX_PARAMS: Decoder = Decoder {
    name: "hkdf_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_INFO],
            max: 1,
        },
    ],
};

/// `hkdf_set_ctx_params`: used by `kdf_hkdf_set_ctx_params` (hkdf.c.in).
pub(crate) const HKDF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "hkdf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_INFO],
            max: 5,
        },
    ],
};

/// `hmac_drbg_kdf_get_ctx_params`: used by `hmac_drbg_kdf_get_ctx_params` (hmacdrbg_kdf.c.in).
pub(crate) const HMAC_DRBG_KDF_GET_CTX_PARAMS: Decoder = Decoder {
    name: "hmac_drbg_kdf_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_MAC],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
    ],
};

/// `hmac_drbg_kdf_set_ctx_params`: used by `hmac_drbg_kdf_set_ctx_params` (hmacdrbg_kdf.c.in).
pub(crate) const HMAC_DRBG_KDF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "hmac_drbg_kdf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_HMACDRBG_ENTROPY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_HMACDRBG_NONCE],
            max: 1,
        },
    ],
};

/// `hmac_get_ctx_params`: used by `hmac_get_ctx_params` (hmac_prov.c.in).
pub(crate) const HMAC_GET_CTX_PARAMS: Decoder = Decoder {
    name: "hmac_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_BLOCK_SIZE],
            max: 1,
        },
    ],
};

/// `hmac_set_ctx_params`: used by `hmac_set_ctx_params` (hmac_prov.c.in).
pub(crate) const HMAC_SET_CTX_PARAMS: Decoder = Decoder {
    name: "hmac_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_TLS_DATA_SIZE],
            max: 1,
        },
    ],
};

/// `kbkdf_get_ctx_params`: used by `kbkdf_get_ctx_params` (kbkdf.c.in).
pub(crate) const KBKDF_GET_CTX_PARAMS: Decoder = Decoder {
    name: "kbkdf_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `kbkdf_set_ctx_params`: used by `kbkdf_set_ctx_params` (kbkdf.c.in).
pub(crate) const KBKDF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "kbkdf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_INFO],
            max: 5,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SEED],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_CIPHER],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_MAC],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KBKDF_USE_L],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KBKDF_R],
            max: 1,
        },
    ],
};

/// `kdf_tls1_3_set_ctx_params`: used by `kdf_tls1_3_set_ctx_params` (hkdf.c.in).
pub(crate) const KDF_TLS1_3_SET_CTX_PARAMS: Decoder = Decoder {
    name: "kdf_tls1_3_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PREFIX],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_LABEL],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DATA],
            max: 1,
        },
    ],
};

/// `key2any_set_ctx_params`: used by `key2any_set_ctx_params` (encode_key2any.c.in).
pub(crate) const KEY2ANY_SET_CTX_PARAMS: Decoder = Decoder {
    name: "key2any_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_ENCODER_PARAM_CIPHER],
            max: 1,
        },
        Field {
            keys: &[OSSL_ENCODER_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ENCODER_PARAM_SAVE_PARAMETERS],
            max: 1,
        },
    ],
};

/// `key2pvk_set_ctx_params`: used by `key2pvk_set_ctx_params` (encode_key2ms.c.in).
pub(crate) const KEY2PVK_SET_CTX_PARAMS: Decoder = Decoder {
    name: "key2pvk_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_ENCODER_PARAM_ENCRYPT_LEVEL],
        max: 1,
    }],
};

/// `kmac_get_ctx_params`: used by `kmac_get_ctx_params` (kmac_prov.c.in).
pub(crate) const KMAC_GET_CTX_PARAMS: Decoder = Decoder {
    name: "kmac_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_BLOCK_SIZE],
            max: 1,
        },
    ],
};

/// `kmac_set_ctx_params`: used by `kmac_set_ctx_params` (kmac_prov.c.in).
pub(crate) const KMAC_SET_CTX_PARAMS: Decoder = Decoder {
    name: "kmac_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_XOF],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_CUSTOM],
            max: 1,
        },
    ],
};

/// `krb5kdf_get_ctx_params`: used by `krb5kdf_get_ctx_params` (krb5kdf.c.in).
pub(crate) const KRB5KDF_GET_CTX_PARAMS: Decoder = Decoder {
    name: "krb5kdf_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `krb5kdf_set_ctx_params`: used by `krb5kdf_set_ctx_params` (krb5kdf.c.in).
pub(crate) const KRB5KDF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "krb5kdf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_CIPHER],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_CONSTANT],
            max: 1,
        },
    ],
};

/// `mac_legacy_set_ctx_params`: used by `mac_set_ctx_params` (mac_legacy_sig.c).
pub(crate) const MAC_LEGACY_SET_CTX_PARAMS: Decoder = Decoder {
    name: "mac_legacy_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_MAC_PARAM_KEY],
        max: 1,
    }],
};

/// `ml_dsa_gen_set_params`: used by `ml_dsa_gen_set_params` (ml_dsa_kmgmt.c.in).
pub(crate) const ML_DSA_GEN_SET_PARAMS: Decoder = Decoder {
    name: "ml_dsa_gen_set_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_ML_DSA_SEED],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PROPERTIES],
            max: 1,
        },
    ],
};

/// `ml_dsa_get_ctx_params`: used by `ml_dsa_get_ctx_params` (ml_dsa_sig.c.in).
pub(crate) const ML_DSA_GET_CTX_PARAMS: Decoder = Decoder {
    name: "ml_dsa_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_SIGNATURE_PARAM_ALGORITHM_ID],
        max: 1,
    }],
};

/// `ml_dsa_get_params`: used by `ml_dsa_get_params` (ml_dsa_kmgmt.c.in).
pub(crate) const ML_DSA_GET_PARAMS: Decoder = Decoder {
    name: "ml_dsa_get_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MAX_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_CATEGORY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MANDATORY_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_ML_DSA_SEED],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
    ],
};

/// `ml_dsa_key_type_params`: used by `ml_dsa_key_fromdata` (ml_dsa_kmgmt.c.in).
pub(crate) const ML_DSA_KEY_TYPE_PARAMS: Decoder = Decoder {
    name: "ml_dsa_key_type_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_ML_DSA_SEED],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
    ],
};

/// `ml_dsa_verifymsg_set_ctx_params`: used by `ml_dsa_set_ctx_params` (ml_dsa_sig.c.in).
pub(crate) const ML_DSA_VERIFYMSG_SET_CTX_PARAMS: Decoder = Decoder {
    name: "ml_dsa_verifymsg_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_CONTEXT_STRING],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_TEST_ENTROPY],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DETERMINISTIC],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_MU],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_SIGNATURE],
            max: 1,
        },
    ],
};

/// `ml_kem_gen_set_params`: used by `ml_kem_gen_set_params` (ml_kem_kmgmt.c.in).
pub(crate) const ML_KEM_GEN_SET_PARAMS: Decoder = Decoder {
    name: "ml_kem_gen_set_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_ML_DSA_SEED],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PROPERTIES],
            max: 1,
        },
    ],
};

/// `ml_kem_get_params`: used by `ml_kem_get_params` (ml_kem_kmgmt.c.in).
pub(crate) const ML_KEM_GET_PARAMS: Decoder = Decoder {
    name: "ml_kem_get_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MAX_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_CATEGORY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_ML_KEM_SEED],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_CMS_RI_TYPE],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_CMS_KEMRI_KDF_ALGORITHM],
            max: 1,
        },
    ],
};

/// `ml_kem_import_export`: used by `export_sub_cb` (mlx_kmgmt.c.in), `mlx_kem_key_fromdata` (mlx_kmgmt.c.in).
pub(crate) const ML_KEM_IMPORT_EXPORT: Decoder = Decoder {
    name: "ml_kem_import_export_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
    ],
};

/// `ml_kem_key_type_params`: used by `ml_kem_key_fromdata` (ml_kem_kmgmt.c.in).
pub(crate) const ML_KEM_KEY_TYPE_PARAMS: Decoder = Decoder {
    name: "ml_kem_key_type_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_ML_KEM_SEED],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
    ],
};

/// `ml_kem_set_ctx_params`: used by `ml_kem_set_ctx_params` (ml_kem_kem.c.in).
pub(crate) const ML_KEM_SET_CTX_PARAMS: Decoder = Decoder {
    name: "ml_kem_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KEM_PARAM_IKME],
        max: 1,
    }],
};

/// `ml_kem_set_params`: used by `ml_kem_set_params` (ml_kem_kmgmt.c.in).
pub(crate) const ML_KEM_SET_PARAMS: Decoder = Decoder {
    name: "ml_kem_set_params_decoder",
    fields: &[Field {
        keys: &[OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY],
        max: 1,
    }],
};

/// `mlx_gen_set_params`: used by `mlx_kem_gen_set_params` (mlx_kmgmt.c.in).
pub(crate) const MLX_GEN_SET_PARAMS: Decoder = Decoder {
    name: "mlx_gen_set_params_decoder",
    fields: &[Field {
        keys: &[OSSL_PKEY_PARAM_PROPERTIES],
        max: 1,
    }],
};

/// `mlx_get_params`: used by `mlx_kem_get_params` (mlx_kmgmt.c.in).
pub(crate) const MLX_GET_PARAMS: Decoder = Decoder {
    name: "mlx_get_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MAX_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_CATEGORY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
    ],
};

/// `mlx_set_params`: used by `mlx_kem_set_params` (mlx_kmgmt.c.in).
pub(crate) const MLX_SET_PARAMS: Decoder = Decoder {
    name: "mlx_set_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PROPERTIES],
            max: 1,
        },
    ],
};

/// `ossl_cipher_ccm_get_ctx_params`: used by `ossl_ccm_get_ctx_params` (ciphercommon_ccm.c.in).
pub(crate) const OSSL_CIPHER_CCM_GET_CTX_PARAMS: Decoder = Decoder {
    name: "ossl_cipher_ccm_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_KEYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IVLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAGLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IV],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_UPDATED_IV],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAG],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD],
            max: 1,
        },
    ],
};

/// `ossl_cipher_ccm_set_ctx_params`: used by `ossl_ccm_set_ctx_params` (ciphercommon_ccm.c.in).
pub(crate) const OSSL_CIPHER_CCM_SET_CTX_PARAMS: Decoder = Decoder {
    name: "ossl_cipher_ccm_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_IVLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAG],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_AAD],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED],
            max: 1,
        },
    ],
};

/// `ossl_cipher_gcm_get_ctx_params`: used by `ossl_gcm_get_ctx_params` (ciphercommon_gcm.c.in).
pub(crate) const OSSL_CIPHER_GCM_GET_CTX_PARAMS: Decoder = Decoder {
    name: "ossl_cipher_gcm_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_KEYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IVLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAGLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IV],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_UPDATED_IV],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAG],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_IV_GENERATED],
            max: 1,
        },
    ],
};

/// `ossl_cipher_gcm_set_ctx_params`: used by `ossl_gcm_set_ctx_params` (ciphercommon_gcm.c.in).
pub(crate) const OSSL_CIPHER_GCM_SET_CTX_PARAMS: Decoder = Decoder {
    name: "ossl_cipher_gcm_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_IVLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TAG],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_AAD],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_IV_FIXED],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD_TLS1_SET_IV_INV],
            max: 1,
        },
    ],
};

/// `ossl_cipher_generic_get_params`: used by `ossl_cipher_generic_get_params` (ciphercommon.c.in).
pub(crate) const OSSL_CIPHER_GENERIC_GET_PARAMS: Decoder = Decoder {
    name: "ossl_cipher_generic_get_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_CIPHER_PARAM_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_KEYLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_IVLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_BLOCK_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_AEAD],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_CUSTOM_IV],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_CTS],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_HAS_RAND_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_CIPHER_PARAM_ENCRYPT_THEN_MAC],
            max: 1,
        },
    ],
};

/// `pbkdf1_get_ctx_params`: used by `kdf_pbkdf1_get_ctx_params` (pbkdf1.c.in).
pub(crate) const PBKDF1_GET_CTX_PARAMS: Decoder = Decoder {
    name: "pbkdf1_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `pbkdf1_set_ctx_params`: used by `kdf_pbkdf1_set_ctx_params` (pbkdf1.c.in).
pub(crate) const PBKDF1_SET_CTX_PARAMS: Decoder = Decoder {
    name: "pbkdf1_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PASSWORD],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_ITER],
            max: 1,
        },
    ],
};

/// `pbkdf2_get_ctx_params`: used by `kdf_pbkdf2_get_ctx_params` (pbkdf2.c.in).
pub(crate) const PBKDF2_GET_CTX_PARAMS: Decoder = Decoder {
    name: "pbkdf2_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `pbkdf2_set_ctx_params`: used by `kdf_pbkdf2_set_ctx_params` (pbkdf2.c.in).
pub(crate) const PBKDF2_SET_CTX_PARAMS: Decoder = Decoder {
    name: "pbkdf2_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PASSWORD],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_ITER],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PKCS5],
            max: 1,
        },
    ],
};

/// `pem2der_set_ctx_params`: used by `pem2der_set_ctx_params` (decode_pem2der.c.in).
pub(crate) const PEM2DER_SET_CTX_PARAMS: Decoder = Decoder {
    name: "pem2der_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DECODER_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_OBJECT_PARAM_DATA_STRUCTURE],
            max: 1,
        },
    ],
};

/// `pkcs12_get_ctx_params`: used by `kdf_pkcs12_get_ctx_params` (pkcs12kdf.c.in).
pub(crate) const PKCS12_GET_CTX_PARAMS: Decoder = Decoder {
    name: "pkcs12_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `pkcs12_set_ctx_params`: used by `kdf_pkcs12_set_ctx_params` (pkcs12kdf.c.in).
pub(crate) const PKCS12_SET_CTX_PARAMS: Decoder = Decoder {
    name: "pkcs12_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PASSWORD],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_ITER],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PKCS12_ID],
            max: 1,
        },
    ],
};

/// `poly1305_get_params`: used by `poly1305_get_params` (poly1305_prov.c.in).
pub(crate) const POLY1305_GET_PARAMS: Decoder = Decoder {
    name: "poly1305_get_params_decoder",
    fields: &[Field {
        keys: &[OSSL_MAC_PARAM_SIZE],
        max: 1,
    }],
};

/// `poly1305_set_ctx_params`: used by `poly1305_set_ctx_params` (poly1305_prov.c.in).
pub(crate) const POLY1305_SET_CTX_PARAMS: Decoder = Decoder {
    name: "poly1305_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_MAC_PARAM_KEY],
        max: 1,
    }],
};

/// `pvk2key_set_ctx_params`: used by `pvk2key_set_ctx_params` (decode_pvk2key.c.in).
pub(crate) const PVK2KEY_SET_CTX_PARAMS: Decoder = Decoder {
    name: "pvk2key_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_DECODER_PARAM_PROPERTIES],
        max: 1,
    }],
};

/// `pvk_get_ctx_params`: used by `kdf_pvk_get_ctx_params` (pvkkdf.c.in).
pub(crate) const PVK_GET_CTX_PARAMS: Decoder = Decoder {
    name: "pvk_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `pvk_set_ctx_params`: used by `kdf_pvk_set_ctx_params` (pvkkdf.c.in).
pub(crate) const PVK_SET_CTX_PARAMS: Decoder = Decoder {
    name: "pvk_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PASSWORD],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
    ],
};

/// `rsa_get_ctx_params`: used by `rsa_get_ctx_params` (rsa_enc.c.in).
pub(crate) const RSA_ENC_RSA_GET_CTX_PARAMS: Decoder = Decoder {
    name: "rsa_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_PAD_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION],
            max: 1,
        },
    ],
};

/// `rsa_get_ctx_params`: used by `rsa_get_ctx_params` (rsa_sig.c.in).
pub(crate) const RSA_SIG_RSA_GET_CTX_PARAMS: Decoder = Decoder {
    name: "rsa_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_ALGORITHM_ID],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PAD_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_MGF1_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PSS_SALTLEN],
            max: 1,
        },
    ],
};

/// `rsa_set_ctx_params`: used by `rsa_set_ctx_params` (rsa_enc.c.in).
pub(crate) const RSA_ENC_RSA_SET_CTX_PARAMS: Decoder = Decoder {
    name: "rsa_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_PAD_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION],
            max: 1,
        },
    ],
};

/// `rsa_set_ctx_params`: used by `rsa_set_ctx_params` (rsa_sig.c.in).
pub(crate) const RSA_SIG_RSA_SET_CTX_PARAMS: Decoder = Decoder {
    name: "rsa_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PAD_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_MGF1_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PSS_SALTLEN],
            max: 1,
        },
    ],
};

/// `rsa_set_ctx_params_no_digest`: used by `rsa_set_ctx_params` (rsa_sig.c.in).
pub(crate) const RSA_SET_CTX_PARAMS_NO_DIGEST: Decoder = Decoder {
    name: "rsa_set_ctx_params_no_digest_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PAD_MODE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_MGF1_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_PSS_SALTLEN],
            max: 1,
        },
    ],
};

/// `rsa_sigalg_set_ctx_params`: used by `rsa_sigalg_set_ctx_params` (rsa_sig.c.in).
pub(crate) const RSA_SIGALG_SET_CTX_PARAMS: Decoder = Decoder {
    name: "rsa_sigalg_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_SIGNATURE_PARAM_SIGNATURE],
        max: 1,
    }],
};

/// `rsakem_set_ctx_params`: used by `rsakem_set_ctx_params` (rsa_kem.c.in).
pub(crate) const RSAKEM_SET_CTX_PARAMS: Decoder = Decoder {
    name: "rsakem_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KEM_PARAM_OPERATION],
        max: 1,
    }],
};

/// `scrypt_get_ctx_params`: used by `kdf_scrypt_get_ctx_params` (scrypt.c.in).
pub(crate) const SCRYPT_GET_CTX_PARAMS: Decoder = Decoder {
    name: "scrypt_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `scrypt_set_ctx_params`: used by `kdf_scrypt_set_ctx_params` (scrypt.c.in).
pub(crate) const SCRYPT_SET_CTX_PARAMS: Decoder = Decoder {
    name: "scrypt_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PASSWORD],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SCRYPT_N],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SCRYPT_R],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SCRYPT_P],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SCRYPT_MAXMEM],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
    ],
};

/// `seed_src_get_ctx_params`: used by `seed_src_get_ctx_params` (seed_src.c.in).
pub(crate) const SEED_SRC_GET_CTX_PARAMS: Decoder = Decoder {
    name: "seed_src_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_RAND_PARAM_STATE],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STRENGTH],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_MAX_REQUEST],
            max: 1,
        },
    ],
};

/// `shake_get_ctx_params`: used by `shake_get_ctx_params` (sha3_prov.c.in).
pub(crate) const SHAKE_GET_CTX_PARAMS: Decoder = Decoder {
    name: "shake_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_DIGEST_PARAM_XOFLEN],
            max: 1,
        },
        Field {
            keys: &[OSSL_DIGEST_PARAM_SIZE],
            max: 1,
        },
    ],
};

/// `shake_set_ctx_params`: used by `shake_set_ctx_params` (sha3_prov.c.in).
pub(crate) const SHAKE_SET_CTX_PARAMS: Decoder = Decoder {
    name: "shake_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_DIGEST_PARAM_XOFLEN, OSSL_DIGEST_PARAM_SIZE],
        max: 1,
    }],
};

/// `siphash_get_ctx_params`: used by `siphash_get_ctx_params` (siphash_prov.c.in).
pub(crate) const SIPHASH_GET_CTX_PARAMS: Decoder = Decoder {
    name: "siphash_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_C_ROUNDS],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_D_ROUNDS],
            max: 1,
        },
    ],
};

/// `siphash_set_params`: used by `siphash_set_params` (siphash_prov.c.in).
pub(crate) const SIPHASH_SET_PARAMS: Decoder = Decoder {
    name: "siphash_set_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_MAC_PARAM_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_C_ROUNDS],
            max: 1,
        },
        Field {
            keys: &[OSSL_MAC_PARAM_D_ROUNDS],
            max: 1,
        },
    ],
};

/// `slh_dsa_gen_set_params`: used by `slh_dsa_gen_set_params` (slh_dsa_kmgmt.c.in).
pub(crate) const SLH_DSA_GEN_SET_PARAMS: Decoder = Decoder {
    name: "slh_dsa_gen_set_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SLH_DSA_SEED],
            max: 1,
        },
    ],
};

/// `slh_dsa_get_ctx_params`: used by `slh_dsa_get_ctx_params` (slh_dsa_sig.c.in).
pub(crate) const SLH_DSA_GET_CTX_PARAMS: Decoder = Decoder {
    name: "slh_dsa_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_SIGNATURE_PARAM_ALGORITHM_ID],
        max: 1,
    }],
};

/// `slh_dsa_get_params`: used by `slh_dsa_get_params` (slh_dsa_kmgmt.c.in).
pub(crate) const SLH_DSA_GET_PARAMS: Decoder = Decoder {
    name: "slh_dsa_get_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_BITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MAX_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_SECURITY_CATEGORY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_MANDATORY_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
    ],
};

/// `slh_dsa_import`: used by `slh_dsa_import` (slh_dsa_kmgmt.c.in).
pub(crate) const SLH_DSA_IMPORT: Decoder = Decoder {
    name: "slh_dsa_import_decoder",
    fields: &[
        Field {
            keys: &[OSSL_PKEY_PARAM_PUB_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_PRIV_KEY],
            max: 1,
        },
    ],
};

/// `slh_dsa_set_ctx_params`: used by `slh_dsa_set_ctx_params` (slh_dsa_sig.c.in).
pub(crate) const SLH_DSA_SET_CTX_PARAMS: Decoder = Decoder {
    name: "slh_dsa_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_CONTEXT_STRING],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_TEST_ENTROPY],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DETERMINISTIC],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING],
            max: 1,
        },
    ],
};

/// `sm2_get_ctx_params`: used by `sm2_get_ctx_params` (sm2_enc.c.in).
pub(crate) const SM2_GET_CTX_PARAMS: Decoder = Decoder {
    name: "sm2_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_ASYM_CIPHER_PARAM_DIGEST],
        max: 1,
    }],
};

/// `sm2_set_ctx_params`: used by `sm2_set_ctx_params` (sm2_enc.c.in).
pub(crate) const SM2_SET_CTX_PARAMS: Decoder = Decoder {
    name: "sm2_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ASYM_CIPHER_PARAM_ENGINE],
            max: 1,
        },
    ],
};

/// `sm2sig_get_ctx_params`: used by `sm2sig_get_ctx_params` (sm2_sig.c.in).
pub(crate) const SM2SIG_GET_CTX_PARAMS: Decoder = Decoder {
    name: "sm2sig_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_ALGORITHM_ID],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST],
            max: 1,
        },
    ],
};

/// `sm2sig_set_ctx_params`: used by `sm2sig_set_ctx_params` (sm2_sig.c.in).
pub(crate) const SM2SIG_SET_CTX_PARAMS: Decoder = Decoder {
    name: "sm2sig_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST_SIZE],
            max: 1,
        },
        Field {
            keys: &[OSSL_SIGNATURE_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_PKEY_PARAM_DIST_ID],
            max: 1,
        },
    ],
};

/// `spki2typespki_set_ctx_params`: used by `spki2typespki_set_ctx_params` (decode_spki2typespki.c.in).
pub(crate) const SPKI2TYPESPKI_SET_CTX_PARAMS: Decoder = Decoder {
    name: "spki2typespki_set_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_DECODER_PARAM_PROPERTIES],
        max: 1,
    }],
};

/// `sshkdf_get_ctx_params`: used by `kdf_sshkdf_get_ctx_params` (sshkdf.c.in).
pub(crate) const SSHKDF_GET_CTX_PARAMS: Decoder = Decoder {
    name: "sshkdf_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `sshkdf_get_ctx_params`: used by `x942kdf_get_ctx_params` (x942kdf.c.in).
pub(crate) const X942KDF_SSHKDF_GET_CTX_PARAMS: Decoder = Decoder {
    name: "sshkdf_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `sshkdf_set_ctx_params`: used by `kdf_sshkdf_set_ctx_params` (sshkdf.c.in).
pub(crate) const SSHKDF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "sshkdf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SSHKDF_XCGHASH],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SSHKDF_SESSION_ID],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SSHKDF_TYPE],
            max: 1,
        },
    ],
};

/// `sshkdf_set_ctx_params`: used by `x942kdf_set_ctx_params` (x942kdf.c.in).
pub(crate) const X942KDF_SSHKDF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "sshkdf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SECRET, OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_UKM, OSSL_KDF_PARAM_X942_PARTYUINFO],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_X942_ACVPINFO],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_X942_PARTYVINFO],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_X942_SUPP_PUBINFO],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_X942_SUPP_PRIVINFO],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_X942_USE_KEYBITS],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_CEK_ALG],
            max: 1,
        },
    ],
};

/// `sskdf_get_ctx_params`: used by `sskdf_common_get_ctx_params` (sskdf.c.in).
pub(crate) const SSKDF_GET_CTX_PARAMS: Decoder = Decoder {
    name: "sskdf_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `sskdf_set_ctx_params`: used by `sskdf_set_ctx_params` (sskdf.c.in).
pub(crate) const SSKDF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "sskdf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_SECRET, OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_INFO],
            max: 5,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_MAC],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_MAC_SIZE],
            max: 1,
        },
    ],
};

/// `test_rng_get_ctx_params`: used by `test_rng_get_ctx_params` (test_rng.c.in).
pub(crate) const TEST_RNG_GET_CTX_PARAMS: Decoder = Decoder {
    name: "test_rng_get_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_RAND_PARAM_STATE],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STRENGTH],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_MAX_REQUEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_GENERATE],
            max: 1,
        },
    ],
};

/// `test_rng_set_ctx_params`: used by `test_rng_set_ctx_params` (test_rng.c.in).
pub(crate) const TEST_RNG_SET_CTX_PARAMS: Decoder = Decoder {
    name: "test_rng_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_RAND_PARAM_TEST_ENTROPY],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_TEST_NONCE],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_STRENGTH],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_MAX_REQUEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_RAND_PARAM_GENERATE],
            max: 1,
        },
    ],
};

/// `tls1prf_get_ctx_params`: used by `kdf_tls1_prf_get_ctx_params` (tls1_prf.c.in).
pub(crate) const TLS1PRF_GET_CTX_PARAMS: Decoder = Decoder {
    name: "tls1prf_get_ctx_params_decoder",
    fields: &[Field {
        keys: &[OSSL_KDF_PARAM_SIZE],
        max: 1,
    }],
};

/// `tls1prf_set_ctx_params`: used by `kdf_tls1_prf_set_ctx_params` (tls1_prf.c.in).
pub(crate) const TLS1PRF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "tls1prf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SECRET],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SEED],
            max: 6,
        },
    ],
};

/// `x963kdf_set_ctx_params`: used by `x963kdf_set_ctx_params` (sskdf.c.in).
pub(crate) const X963KDF_SET_CTX_PARAMS: Decoder = Decoder {
    name: "x963kdf_set_ctx_params_decoder",
    fields: &[
        Field {
            keys: &[OSSL_KDF_PARAM_SECRET, OSSL_KDF_PARAM_KEY],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_INFO],
            max: 5,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_PROPERTIES],
            max: 1,
        },
        Field {
            keys: &[OSSL_ALG_PARAM_ENGINE],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_DIGEST],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_MAC],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_SALT],
            max: 1,
        },
        Field {
            keys: &[OSSL_KDF_PARAM_MAC_SIZE],
            max: 1,
        },
    ],
};
