//! Key context ctrls (`EVP_PKEY_CTX_ctrl(3)`, `EVP_PKEY_CTX_ctrl_str(3)`; `pmeth_lib.c`,
//! `ctrl_params_translate.c`): the legacy ctrl commands and ctrl strings, translated to the
//! parameters of the context's provider operation, and the distinguishing ID a context keeps
//! for its next operation.
//!
//! As in OpenSSL:
//! - A ctrl before an operation is set fails with `EVP_R_NO_OPERATION_SET`, except setting the
//!   distinguishing ID, which is kept and given to the operation when it starts (only signature
//!   operations take it).
//! - The translation table, its order (the first entry matching the key type, operation, and
//!   command or string wins), and its fixups are OpenSSL's, quirks included: the HKDF mode's
//!   ctrl passes the length of the mode's name, `EVP_PKEY_CTRL_DH_PARAMGEN_TYPE` passes a NULL
//!   string as long as the type number, getting an object identifier never returns it, getting
//!   the ID's length gives 0, and the "get" ctrls return the length of what they got.
//! - Translated ctrls are strict: a parameter the operation doesn't list as settable (or
//!   gettable) gives -2 without an error; ctrl strings without a translation are taken as
//!   parameter names (with "hex" for hexadecimal values).
//!
//! The other directions (parameters to the ctrls of an application's `EVP_PKEY_METHOD`, and the
//! legacy keys' parameters) come with 4.2d. Where the reference reads memory it shouldn't, this
//! fails instead (docs/DEVIATIONS.md): a padding mode without a name, a digest or cipher NID
//! without a name, NULL names and values, and the scrypt commands' `uint64_t` arguments, which
//! it reads as BIGNUMs.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use rustyssl_abi::{
    BIGNUM, ERR_LIB_EVP, ERR_LIB_RSA, ERR_R_INTERNAL_ERROR, ERR_R_UNSUPPORTED, EVP_CIPHER, EVP_MD,
    EVP_PKEY_CTRL_CIPHER, EVP_PKEY_CTRL_DH_KDF_MD, EVP_PKEY_CTRL_DH_KDF_OID,
    EVP_PKEY_CTRL_DH_KDF_OUTLEN, EVP_PKEY_CTRL_DH_KDF_TYPE, EVP_PKEY_CTRL_DH_KDF_UKM,
    EVP_PKEY_CTRL_DH_NID, EVP_PKEY_CTRL_DH_PAD, EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR,
    EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN,
    EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, EVP_PKEY_CTRL_DH_RFC5114, EVP_PKEY_CTRL_DSA_PARAMGEN_BITS,
    EVP_PKEY_CTRL_DSA_PARAMGEN_MD, EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS,
    EVP_PKEY_CTRL_EC_ECDH_COFACTOR, EVP_PKEY_CTRL_EC_KDF_MD, EVP_PKEY_CTRL_EC_KDF_OUTLEN,
    EVP_PKEY_CTRL_EC_KDF_TYPE, EVP_PKEY_CTRL_EC_KDF_UKM, EVP_PKEY_CTRL_EC_PARAM_ENC,
    EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, EVP_PKEY_CTRL_GET_DH_KDF_MD, EVP_PKEY_CTRL_GET_DH_KDF_OID,
    EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, EVP_PKEY_CTRL_GET_DH_KDF_UKM, EVP_PKEY_CTRL_GET_EC_KDF_MD,
    EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, EVP_PKEY_CTRL_GET_EC_KDF_UKM, EVP_PKEY_CTRL_GET_MD,
    EVP_PKEY_CTRL_GET_RSA_MGF1_MD, EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, EVP_PKEY_CTRL_GET_RSA_OAEP_MD,
    EVP_PKEY_CTRL_GET_RSA_PADDING, EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, EVP_PKEY_CTRL_GET1_ID,
    EVP_PKEY_CTRL_GET1_ID_LEN, EVP_PKEY_CTRL_HKDF_INFO, EVP_PKEY_CTRL_HKDF_KEY,
    EVP_PKEY_CTRL_HKDF_MD, EVP_PKEY_CTRL_HKDF_MODE, EVP_PKEY_CTRL_HKDF_SALT, EVP_PKEY_CTRL_MD,
    EVP_PKEY_CTRL_PASS, EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION, EVP_PKEY_CTRL_RSA_KEYGEN_BITS,
    EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, EVP_PKEY_CTRL_RSA_MGF1_MD,
    EVP_PKEY_CTRL_RSA_OAEP_LABEL, EVP_PKEY_CTRL_RSA_OAEP_MD, EVP_PKEY_CTRL_RSA_PADDING,
    EVP_PKEY_CTRL_RSA_PSS_SALTLEN, EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, EVP_PKEY_CTRL_SCRYPT_N,
    EVP_PKEY_CTRL_SCRYPT_P, EVP_PKEY_CTRL_SCRYPT_R, EVP_PKEY_CTRL_SCRYPT_SALT,
    EVP_PKEY_CTRL_SET_DIGEST_SIZE, EVP_PKEY_CTRL_SET_MAC_KEY, EVP_PKEY_CTRL_SET1_ID,
    EVP_PKEY_CTRL_TLS_MD, EVP_PKEY_CTRL_TLS_SECRET, EVP_PKEY_CTRL_TLS_SEED, EVP_PKEY_CTX,
    EVP_PKEY_DH, EVP_PKEY_DH_KDF_NONE, EVP_PKEY_DH_KDF_X9_42, EVP_PKEY_DHX, EVP_PKEY_DSA,
    EVP_PKEY_EC, EVP_PKEY_ECDH_KDF_NONE, EVP_PKEY_ECDH_KDF_X9_63, EVP_PKEY_OP_DERIVE,
    EVP_PKEY_OP_KEYGEN, EVP_PKEY_OP_PARAMGEN, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_OP_TYPE_DATA,
    EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_OP_UNDEFINED, EVP_PKEY_RSA,
    EVP_PKEY_RSA_PSS, EVP_PKEY_SM2, EVP_PKEY_X448, EVP_PKEY_X25519, EVP_R_COMMAND_NOT_SUPPORTED,
    EVP_R_INVALID_DIGEST, EVP_R_INVALID_OPERATION, EVP_R_INVALID_VALUE, EVP_R_NO_OPERATION_SET,
    OPENSSL_EC_EXPLICIT_CURVE, OPENSSL_EC_NAMED_CURVE, OSSL_ALG_PARAM_DIGEST,
    OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST,
    OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE,
    OSSL_EXCHANGE_PARAM_KDF_DIGEST, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, OSSL_EXCHANGE_PARAM_KDF_TYPE,
    OSSL_EXCHANGE_PARAM_KDF_UKM, OSSL_EXCHANGE_PARAM_PAD, OSSL_KDF_NAME_X942KDF_ASN1,
    OSSL_KDF_NAME_X963KDF, OSSL_KDF_PARAM_CEK_ALG, OSSL_KDF_PARAM_DIGEST, OSSL_KDF_PARAM_INFO,
    OSSL_KDF_PARAM_KEY, OSSL_KDF_PARAM_MODE, OSSL_KDF_PARAM_PASSWORD, OSSL_KDF_PARAM_SALT,
    OSSL_KDF_PARAM_SCRYPT_MAXMEM, OSSL_KDF_PARAM_SCRYPT_N, OSSL_KDF_PARAM_SCRYPT_P,
    OSSL_KDF_PARAM_SCRYPT_R, OSSL_KDF_PARAM_SECRET, OSSL_KDF_PARAM_SEED, OSSL_MAC_PARAM_SIZE,
    OSSL_PARAM, OSSL_PARAM_INTEGER, OSSL_PARAM_OCTET_PTR, OSSL_PARAM_OCTET_STRING,
    OSSL_PARAM_UNSIGNED_INTEGER, OSSL_PARAM_UTF8_PTR, OSSL_PARAM_UTF8_STRING,
    OSSL_PKEY_EC_ENCODING_EXPLICIT, OSSL_PKEY_EC_ENCODING_GROUP, OSSL_PKEY_PARAM_CIPHER,
    OSSL_PKEY_PARAM_DH_GENERATOR, OSSL_PKEY_PARAM_DIST_ID, OSSL_PKEY_PARAM_EC_ENCODING,
    OSSL_PKEY_PARAM_FFC_DIGEST, OSSL_PKEY_PARAM_FFC_PBITS, OSSL_PKEY_PARAM_FFC_QBITS,
    OSSL_PKEY_PARAM_FFC_TYPE, OSSL_PKEY_PARAM_GROUP_NAME, OSSL_PKEY_PARAM_MGF1_DIGEST,
    OSSL_PKEY_PARAM_PAD_MODE, OSSL_PKEY_PARAM_PRIV_KEY, OSSL_PKEY_PARAM_RSA_BITS,
    OSSL_PKEY_PARAM_RSA_E, OSSL_PKEY_PARAM_RSA_PRIMES, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN,
    OSSL_SIGNATURE_PARAM_DIGEST, OSSL_SIGNATURE_PARAM_PSS_SALTLEN, RSA_NO_PADDING,
    RSA_PKCS1_OAEP_PADDING, RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING, RSA_PKCS1_WITH_TLS_PADDING,
    RSA_PSS_SALTLEN_AUTO, RSA_PSS_SALTLEN_DIGEST, RSA_PSS_SALTLEN_MAX, RSA_R_UNKNOWN_PADDING_TYPE,
    RSA_X931_PADDING,
};

use super::pkey_ctx::{self, EVP_PKEY_CTX_get_params, EVP_PKEY_CTX_set_params, PkeyCtx};
use crate::err::{self, ERR_clear_last_mark, ERR_pop_to_mark, ERR_set_mark};
use crate::ffi::ffi_export;
use crate::params::bn::OSSL_PARAM_allocate_from_text;
use crate::params::{
    OSSL_PARAM_construct_BN, OSSL_PARAM_construct_int, OSSL_PARAM_construct_octet_ptr,
    OSSL_PARAM_construct_octet_string, OSSL_PARAM_construct_uint, OSSL_PARAM_construct_uint64,
    OSSL_PARAM_construct_utf8_ptr, OSSL_PARAM_construct_utf8_string, OSSL_PARAM_locate_const, end,
};

/// `OSSL_MAX_NAME_SIZE` (`internal/sizes.h`, not a public header): the room the fixups give
/// names they get.
const NAME_SIZE: usize = 50;
/// [`NAME_SIZE`] as a C `int`.
const NAME_SIZE_INT: c_int = 50;

/// The distinguishing ID a context keeps for its next operation (`cached_parameters`).
pub(crate) struct CachedId {
    /// The ctrl string it was given with (`distid` or `hexdistid`), or none for the ctrl.
    name: Option<CString>,
    /// Its octets (for a ctrl string, the value and its NUL).
    data: Vec<u8>,
}

/// What a translation does.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Action {
    /// Either; the fixup decides.
    None = 0,
    Get = 1,
    Set = 2,
}

/// Where the fixups are called from (OpenSSL's state numbers, which errors print).
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    PreCtrl = 1,
    PostCtrl = 2,
    PreStr = 4,
    PostStr = 5,
}

/// A translation's fixup function.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fixup {
    Default,
    Md,
    Cipher,
    DistidLen,
    DhKdfType,
    EcKdfType,
    Oid,
    DhNid,
    DhNid5114,
    DhParamgenType,
    EcParamEnc,
    EcParamgenCurveNid,
    EcdhCofactor,
    RsaPadding,
    RsaPssSaltlen,
    HkdfMode,
    GroupEcx,
}

/// One entry of the translation table (`struct translation_st`).
struct Translation {
    action: Action,
    keytype1: c_int,
    keytype2: c_int,
    optype: c_int,
    ctrl_num: c_int,
    ctrl_str: Option<&'static str>,
    ctrl_hexstr: Option<&'static str>,
    param_key: &'static CStr,
    data_type: c_int,
    fixup: Fixup,
}

/// A table entry.
#[expect(clippy::too_many_arguments, reason = "the table's columns")]
const fn t(
    action: Action,
    keytype1: c_int,
    keytype2: c_int,
    optype: c_int,
    ctrl_num: c_int,
    ctrl_str: Option<&'static str>,
    ctrl_hexstr: Option<&'static str>,
    param_key: &'static CStr,
    data_type: c_int,
    fixup: Fixup,
) -> Translation {
    Translation {
        action,
        keytype1,
        keytype2,
        optype,
        ctrl_num,
        ctrl_str,
        ctrl_hexstr,
        param_key,
        data_type,
        fixup,
    }
}

use Action::{Get as G, None as N, Set as S};
use Fixup as X;

const DERIVE: c_int = EVP_PKEY_OP_DERIVE;
const PGEN: c_int = EVP_PKEY_OP_PARAMGEN;
const KGEN: c_int = EVP_PKEY_OP_KEYGEN;
const UTF8: c_int = OSSL_PARAM_UTF8_STRING;
const UINT: c_int = OSSL_PARAM_UNSIGNED_INTEGER;
const INT: c_int = OSSL_PARAM_INTEGER;
const OCTETS: c_int = OSSL_PARAM_OCTET_STRING;
const OCTET_PTR: c_int = OSSL_PARAM_OCTET_PTR;

/// `evp_pkey_ctx_translations`, in its order.
#[rustfmt::skip]
static TRANSLATIONS: &[Translation] = &[
    // DistID.
    t(S, -1, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_SET1_ID, Some("distid"), Some("hexdistid"), OSSL_PKEY_PARAM_DIST_ID, OCTETS, X::Default),
    t(G, -1, -1, -1, EVP_PKEY_CTRL_GET1_ID, Some("distid"), Some("hexdistid"), OSSL_PKEY_PARAM_DIST_ID, OCTET_PTR, X::Default),
    t(G, -1, -1, -1, EVP_PKEY_CTRL_GET1_ID_LEN, None, None, OSSL_PKEY_PARAM_DIST_ID, OCTET_PTR, X::DistidLen),
    // DH and DHX.
    t(N, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_DH_KDF_TYPE, None, None, OSSL_EXCHANGE_PARAM_KDF_TYPE, UTF8, X::DhKdfType),
    t(S, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_DH_KDF_MD, None, None, OSSL_EXCHANGE_PARAM_KDF_DIGEST, UTF8, X::Md),
    t(G, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_GET_DH_KDF_MD, None, None, OSSL_EXCHANGE_PARAM_KDF_DIGEST, UTF8, X::Md),
    t(S, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_DH_KDF_OUTLEN, None, None, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, UINT, X::Default),
    t(G, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_GET_DH_KDF_OUTLEN, None, None, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, UINT, X::Default),
    t(S, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_DH_KDF_UKM, None, None, OSSL_EXCHANGE_PARAM_KDF_UKM, OCTETS, X::Default),
    t(G, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_GET_DH_KDF_UKM, None, None, OSSL_EXCHANGE_PARAM_KDF_UKM, OCTET_PTR, X::Default),
    t(S, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_DH_KDF_OID, None, None, OSSL_KDF_PARAM_CEK_ALG, UTF8, X::Oid),
    t(G, EVP_PKEY_DHX, 0, DERIVE, EVP_PKEY_CTRL_GET_DH_KDF_OID, None, None, OSSL_KDF_PARAM_CEK_ALG, UTF8, X::Oid),
    t(S, EVP_PKEY_DHX, 0, PGEN, EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, Some("dh_paramgen_type"), None, OSSL_PKEY_PARAM_FFC_TYPE, UTF8, X::DhParamgenType),
    t(S, EVP_PKEY_DHX, 0, PGEN, EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, Some("dh_paramgen_prime_len"), None, OSSL_PKEY_PARAM_FFC_PBITS, UINT, X::Default),
    t(S, EVP_PKEY_DHX, 0, PGEN | KGEN, EVP_PKEY_CTRL_DH_NID, Some("dh_param"), None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::Default),
    t(S, EVP_PKEY_DHX, 0, PGEN | KGEN, EVP_PKEY_CTRL_DH_RFC5114, Some("dh_rfc5114"), None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::DhNid5114),
    t(S, EVP_PKEY_DH, 0, PGEN, EVP_PKEY_CTRL_DH_PARAMGEN_TYPE, Some("dh_paramgen_type"), None, OSSL_PKEY_PARAM_FFC_TYPE, UTF8, X::DhParamgenType),
    t(S, EVP_PKEY_DH, 0, PGEN, EVP_PKEY_CTRL_DH_PARAMGEN_PRIME_LEN, Some("dh_paramgen_prime_len"), None, OSSL_PKEY_PARAM_FFC_PBITS, UINT, X::Default),
    t(S, EVP_PKEY_DH, 0, PGEN | KGEN, EVP_PKEY_CTRL_DH_NID, Some("dh_param"), None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::DhNid),
    t(S, EVP_PKEY_DH, 0, PGEN | KGEN, EVP_PKEY_CTRL_DH_RFC5114, Some("dh_rfc5114"), None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::DhNid5114),
    t(S, EVP_PKEY_DH, 0, PGEN, EVP_PKEY_CTRL_DH_PARAMGEN_GENERATOR, Some("dh_paramgen_generator"), None, OSSL_PKEY_PARAM_DH_GENERATOR, INT, X::Default),
    t(S, EVP_PKEY_DHX, 0, PGEN, EVP_PKEY_CTRL_DH_PARAMGEN_SUBPRIME_LEN, Some("dh_paramgen_subprime_len"), None, OSSL_PKEY_PARAM_FFC_QBITS, UINT, X::Default),
    t(S, EVP_PKEY_DH, 0, DERIVE, EVP_PKEY_CTRL_DH_PAD, Some("dh_pad"), None, OSSL_EXCHANGE_PARAM_PAD, UINT, X::Default),
    // DSA.
    t(S, EVP_PKEY_DSA, 0, PGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, Some("dsa_paramgen_bits"), None, OSSL_PKEY_PARAM_FFC_PBITS, UINT, X::Default),
    t(S, EVP_PKEY_DSA, 0, PGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_Q_BITS, Some("dsa_paramgen_q_bits"), None, OSSL_PKEY_PARAM_FFC_QBITS, UINT, X::Default),
    t(S, EVP_PKEY_DSA, 0, PGEN, EVP_PKEY_CTRL_DSA_PARAMGEN_MD, Some("dsa_paramgen_md"), None, OSSL_PKEY_PARAM_FFC_DIGEST, UTF8, X::Md),
    // EC.
    t(S, EVP_PKEY_EC, 0, PGEN | KGEN, EVP_PKEY_CTRL_EC_PARAM_ENC, Some("ec_param_enc"), None, OSSL_PKEY_PARAM_EC_ENCODING, UTF8, X::EcParamEnc),
    t(S, EVP_PKEY_EC, 0, PGEN | KGEN, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, Some("ec_paramgen_curve"), None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::EcParamgenCurveNid),
    t(N, EVP_PKEY_EC, 0, DERIVE, EVP_PKEY_CTRL_EC_ECDH_COFACTOR, Some("ecdh_cofactor_mode"), None, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, INT, X::EcdhCofactor),
    t(N, EVP_PKEY_EC, 0, DERIVE, EVP_PKEY_CTRL_EC_KDF_TYPE, None, None, OSSL_EXCHANGE_PARAM_KDF_TYPE, UTF8, X::EcKdfType),
    t(S, EVP_PKEY_EC, 0, DERIVE, EVP_PKEY_CTRL_EC_KDF_MD, Some("ecdh_kdf_md"), None, OSSL_EXCHANGE_PARAM_KDF_DIGEST, UTF8, X::Md),
    t(G, EVP_PKEY_EC, 0, DERIVE, EVP_PKEY_CTRL_GET_EC_KDF_MD, None, None, OSSL_EXCHANGE_PARAM_KDF_DIGEST, UTF8, X::Md),
    t(S, EVP_PKEY_EC, 0, DERIVE, EVP_PKEY_CTRL_EC_KDF_OUTLEN, None, None, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, UINT, X::Default),
    t(G, EVP_PKEY_EC, 0, DERIVE, EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, None, None, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, UINT, X::Default),
    t(S, EVP_PKEY_EC, 0, DERIVE, EVP_PKEY_CTRL_EC_KDF_UKM, None, None, OSSL_EXCHANGE_PARAM_KDF_UKM, OCTETS, X::Default),
    t(G, EVP_PKEY_EC, 0, DERIVE, EVP_PKEY_CTRL_GET_EC_KDF_UKM, None, None, OSSL_EXCHANGE_PARAM_KDF_UKM, OCTET_PTR, X::Default),
    // SM2.
    t(S, EVP_PKEY_SM2, 0, PGEN | KGEN, EVP_PKEY_CTRL_EC_PARAM_ENC, Some("ec_param_enc"), None, OSSL_PKEY_PARAM_EC_ENCODING, UTF8, X::EcParamEnc),
    t(S, EVP_PKEY_SM2, 0, PGEN | KGEN, EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, Some("ec_paramgen_curve"), None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::EcParamgenCurveNid),
    t(N, EVP_PKEY_SM2, 0, DERIVE, EVP_PKEY_CTRL_EC_ECDH_COFACTOR, Some("ecdh_cofactor_mode"), None, OSSL_EXCHANGE_PARAM_EC_ECDH_COFACTOR_MODE, INT, X::EcdhCofactor),
    t(N, EVP_PKEY_SM2, 0, DERIVE, EVP_PKEY_CTRL_EC_KDF_TYPE, None, None, OSSL_EXCHANGE_PARAM_KDF_TYPE, UTF8, X::EcKdfType),
    t(S, EVP_PKEY_SM2, 0, DERIVE, EVP_PKEY_CTRL_EC_KDF_MD, Some("ecdh_kdf_md"), None, OSSL_EXCHANGE_PARAM_KDF_DIGEST, UTF8, X::Md),
    t(G, EVP_PKEY_SM2, 0, DERIVE, EVP_PKEY_CTRL_GET_EC_KDF_MD, None, None, OSSL_EXCHANGE_PARAM_KDF_DIGEST, UTF8, X::Md),
    t(S, EVP_PKEY_SM2, 0, DERIVE, EVP_PKEY_CTRL_EC_KDF_OUTLEN, None, None, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, UINT, X::Default),
    t(G, EVP_PKEY_SM2, 0, DERIVE, EVP_PKEY_CTRL_GET_EC_KDF_OUTLEN, None, None, OSSL_EXCHANGE_PARAM_KDF_OUTLEN, UINT, X::Default),
    t(S, EVP_PKEY_SM2, 0, DERIVE, EVP_PKEY_CTRL_EC_KDF_UKM, None, None, OSSL_EXCHANGE_PARAM_KDF_UKM, OCTETS, X::Default),
    t(G, EVP_PKEY_SM2, 0, DERIVE, EVP_PKEY_CTRL_GET_EC_KDF_UKM, None, None, OSSL_EXCHANGE_PARAM_KDF_UKM, OCTET_PTR, X::Default),
    // RSA.
    t(S, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_RSA_PADDING, Some("rsa_padding_mode"), None, OSSL_PKEY_PARAM_PAD_MODE, UTF8, X::RsaPadding),
    t(G, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_GET_RSA_PADDING, None, None, OSSL_PKEY_PARAM_PAD_MODE, UTF8, X::RsaPadding),
    t(S, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_RSA_MGF1_MD, Some("rsa_mgf1_md"), None, OSSL_PKEY_PARAM_MGF1_DIGEST, UTF8, X::Md),
    t(G, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_TYPE_CRYPT | EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_GET_RSA_MGF1_MD, None, None, OSSL_PKEY_PARAM_MGF1_DIGEST, UTF8, X::Md),
    t(S, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_RSA_PSS_SALTLEN, Some("rsa_pss_saltlen"), None, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, UTF8, X::RsaPssSaltlen),
    t(G, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_GET_RSA_PSS_SALTLEN, None, None, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, UTF8, X::RsaPssSaltlen),
    t(S, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_MD, Some("rsa_oaep_md"), None, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, UTF8, X::Md),
    t(G, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_GET_RSA_OAEP_MD, None, None, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, UTF8, X::Md),
    t(S, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_OAEP_LABEL, None, Some("rsa_oaep_label"), OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OCTETS, X::Default),
    t(G, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_GET_RSA_OAEP_LABEL, None, None, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OCTET_PTR, X::Default),
    t(S, EVP_PKEY_RSA, 0, EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION, None, Some("rsa_pkcs1_implicit_rejection"), OSSL_ASYM_CIPHER_PARAM_IMPLICIT_REJECTION, UINT, X::Default),
    t(S, EVP_PKEY_RSA_PSS, 0, EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_CTRL_MD, Some("rsa_pss_keygen_md"), None, OSSL_ALG_PARAM_DIGEST, UTF8, X::Md),
    t(S, EVP_PKEY_RSA_PSS, 0, EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_CTRL_RSA_MGF1_MD, Some("rsa_pss_keygen_mgf1_md"), None, OSSL_PKEY_PARAM_MGF1_DIGEST, UTF8, X::Md),
    t(S, EVP_PKEY_RSA_PSS, 0, EVP_PKEY_OP_TYPE_GEN, EVP_PKEY_CTRL_RSA_PSS_SALTLEN, Some("rsa_pss_keygen_saltlen"), None, OSSL_SIGNATURE_PARAM_PSS_SALTLEN, INT, X::Default),
    t(S, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, KGEN, EVP_PKEY_CTRL_RSA_KEYGEN_BITS, Some("rsa_keygen_bits"), None, OSSL_PKEY_PARAM_RSA_BITS, UINT, X::Default),
    t(S, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, KGEN, EVP_PKEY_CTRL_RSA_KEYGEN_PUBEXP, Some("rsa_keygen_pubexp"), None, OSSL_PKEY_PARAM_RSA_E, UINT, X::Default),
    t(S, EVP_PKEY_RSA, EVP_PKEY_RSA_PSS, KGEN, EVP_PKEY_CTRL_RSA_KEYGEN_PRIMES, Some("rsa_keygen_primes"), None, OSSL_PKEY_PARAM_RSA_PRIMES, UINT, X::Default),
    // SipHash.
    t(S, -1, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_SET_DIGEST_SIZE, Some("digestsize"), None, OSSL_MAC_PARAM_SIZE, UINT, X::Default),
    // TLS1-PRF.
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_TLS_MD, Some("md"), None, OSSL_KDF_PARAM_DIGEST, UTF8, X::Md),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_TLS_SECRET, Some("secret"), Some("hexsecret"), OSSL_KDF_PARAM_SECRET, OCTETS, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_TLS_SEED, Some("seed"), Some("hexseed"), OSSL_KDF_PARAM_SEED, OCTETS, X::Default),
    // HKDF.
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_HKDF_MD, Some("md"), None, OSSL_KDF_PARAM_DIGEST, UTF8, X::Md),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_HKDF_SALT, Some("salt"), Some("hexsalt"), OSSL_KDF_PARAM_SALT, OCTETS, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_HKDF_KEY, Some("key"), Some("hexkey"), OSSL_KDF_PARAM_KEY, OCTETS, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_HKDF_INFO, Some("info"), Some("hexinfo"), OSSL_KDF_PARAM_INFO, OCTETS, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_HKDF_MODE, Some("mode"), None, OSSL_KDF_PARAM_MODE, INT, X::HkdfMode),
    // Scrypt.
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_PASS, Some("pass"), Some("hexpass"), OSSL_KDF_PARAM_PASSWORD, OCTETS, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_SCRYPT_SALT, Some("salt"), Some("hexsalt"), OSSL_KDF_PARAM_SALT, OCTETS, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_SCRYPT_N, Some("N"), None, OSSL_KDF_PARAM_SCRYPT_N, UINT, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_SCRYPT_R, Some("r"), None, OSSL_KDF_PARAM_SCRYPT_R, UINT, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_SCRYPT_P, Some("p"), None, OSSL_KDF_PARAM_SCRYPT_P, UINT, X::Default),
    t(S, -1, -1, DERIVE, EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES, Some("maxmem_bytes"), None, OSSL_KDF_PARAM_SCRYPT_MAXMEM, UINT, X::Default),
    t(S, -1, -1, KGEN | EVP_PKEY_OP_TYPE_CRYPT, EVP_PKEY_CTRL_CIPHER, None, None, OSSL_PKEY_PARAM_CIPHER, UTF8, X::Cipher),
    t(S, -1, -1, KGEN, EVP_PKEY_CTRL_SET_MAC_KEY, Some("key"), Some("hexkey"), OSSL_PKEY_PARAM_PRIV_KEY, OCTETS, X::Default),
    t(S, -1, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_MD, None, None, OSSL_SIGNATURE_PARAM_DIGEST, UTF8, X::Md),
    t(G, -1, -1, EVP_PKEY_OP_TYPE_SIG, EVP_PKEY_CTRL_GET_MD, None, None, OSSL_SIGNATURE_PARAM_DIGEST, UTF8, X::Md),
    // ECX.
    t(S, EVP_PKEY_X25519, EVP_PKEY_X25519, KGEN, -1, None, None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::GroupEcx),
    t(S, EVP_PKEY_X25519, EVP_PKEY_X25519, PGEN, -1, None, None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::GroupEcx),
    t(S, EVP_PKEY_X448, EVP_PKEY_X448, KGEN, -1, None, None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::GroupEcx),
    t(S, EVP_PKEY_X448, EVP_PKEY_X448, PGEN, -1, None, None, OSSL_PKEY_PARAM_GROUP_NAME, UTF8, X::GroupEcx),
];

/// What a lookup searches by.
enum By<'a> {
    Ctrl(c_int),
    /// A ctrl string, matched against both names, never against getters.
    Str(&'a [u8]),
}

/// `lookup_translation`: the first entry for the key type, operation type, and command or
/// string; for a string, also whether it matched the hexadecimal name.
fn lookup(keytype: c_int, optype: c_int, by: &By<'_>) -> Option<(&'static Translation, bool)> {
    for item in TRANSLATIONS {
        if item.optype != -1 && optype & item.optype == 0 {
            continue;
        }
        if item.keytype1 != -1 && keytype != item.keytype1 && keytype != item.keytype2 {
            continue;
        }
        match by {
            By::Ctrl(cmd) => {
                if *cmd != item.ctrl_num {
                    continue;
                }
                return Some((item, false));
            }
            By::Str(name) => {
                if item.action != Action::None && item.action != Action::Set {
                    continue;
                }
                if item
                    .ctrl_str
                    .is_some_and(|s| s.as_bytes().eq_ignore_ascii_case(name))
                {
                    return Some((item, false));
                }
                if item
                    .ctrl_hexstr
                    .is_some_and(|s| s.as_bytes().eq_ignore_ascii_case(name))
                {
                    return Some((item, true));
                }
            }
        }
    }
    None
}

/// What a ctrl's pointer argument is.
#[derive(Clone, Copy)]
enum P2 {
    /// The C `void *`.
    Ptr(*mut c_void),
    /// A 64-bit value (`EVP_PKEY_CTX_ctrl_uint64`, or a scrypt command's argument).
    U64(u64),
    /// The context's `name_buf`, whose pointer is taken fresh at each use (one kept across a
    /// reborrow of the context would no longer be valid).
    NameBuf,
}

impl P2 {
    fn is_null(self) -> bool {
        matches!(self, Self::Ptr(p) if p.is_null())
    }
}

/// `struct translation_ctx_st`. It isn't moved while its parameters point into it.
struct Tctx<'a> {
    pctx: &'a PkeyCtx,
    action: Action,
    ishex: bool,
    /// The ctrl string, for the string direction.
    ctrl_str: Vec<u8>,
    p1: c_int,
    p2: P2,
    /// The 64-bit value a parameter points to.
    u64_value: u64,
    params: [OSSL_PARAM; 2],
    orig_p2: *mut c_void,
    name_buf: [u8; NAME_SIZE],
    /// What `OSSL_PARAM_allocate_from_text` allocated (C memory).
    allocated_c: *mut c_void,
    /// The native-endian octets of a BIGNUM argument.
    allocated: Vec<u8>,
}

impl Drop for Tctx<'_> {
    fn drop(&mut self) {
        if !self.allocated_c.is_null() {
            // SAFETY: `OSSL_PARAM_allocate_from_text`'s C allocation, freed once.
            unsafe { crate::mem::free(self.allocated_c, ptr::null(), 0) };
        }
    }
}

impl Tctx<'_> {
    /// The NUL-terminated string `p2` points to (empty for NULL).
    ///
    /// # Safety
    /// `p2` is NULL or a NUL-terminated string.
    unsafe fn p2_str(&self) -> &CStr {
        match self.p2 {
            P2::NameBuf => CStr::from_bytes_until_nul(&self.name_buf).unwrap_or(c""),
            P2::Ptr(p) if !p.is_null() => {
                // SAFETY: the caller's guarantee.
                unsafe { CStr::from_ptr(p.cast()) }
            }
            _ => c"",
        }
    }

    /// The pointer `p2` stands for (NULL for a 64-bit value).
    fn p2(&mut self) -> *mut c_void {
        match self.p2 {
            P2::Ptr(p) => p,
            P2::U64(_) => ptr::null_mut(),
            P2::NameBuf => self.name_buf.as_mut_ptr().cast(),
        }
    }

    /// Points `p2` at `name_buf` holding `s` (truncated to fit) and `p1` at its length.
    fn set_name(&mut self, s: &[u8]) {
        self.name_buf = [0; NAME_SIZE];
        let mut n = 0;
        for (d, &b) in self.name_buf.iter_mut().zip(s.iter().take(NAME_SIZE - 1)) {
            *d = b;
            n += 1;
        }
        self.p2 = P2::NameBuf;
        self.p1 = c_int::try_from(n).unwrap_or(0);
    }

    /// Points `p2` at `name_buf` with room for a name, for a getter.
    fn name_room(&mut self) {
        self.name_buf = [0; NAME_SIZE];
        self.p2 = P2::NameBuf;
        self.p1 = NAME_SIZE_INT;
    }

    /// Points `p2` at a static string.
    fn set_static(&mut self, s: &'static CStr) {
        self.p2 = P2::Ptr(s.as_ptr().cast_mut().cast());
        self.p1 = c_int::try_from(s.to_bytes().len()).unwrap_or(0);
    }
}

/// `default_check`.
fn default_check(state: State, tr: Option<&Translation>) -> c_int {
    const F: &str = "default_check";
    match state {
        State::PreCtrl => {
            if tr.is_none() {
                err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
                return -2;
            }
        }
        State::PreStr => {
            if let Some(tr) = tr
                && tr.action == Action::Get
            {
                err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
                return -2;
            }
        }
        State::PostCtrl | State::PostStr => {}
    }
    1
}

/// Whether the operation of `pctx` has no provider context though its type has one
/// (`default_fixup_args`' check for translations of an operation type).
fn no_algctx(pctx: &PkeyCtx) -> bool {
    let s = pctx.lock();
    let typed = s.is_sig_op()
        || s.is_derive_op()
        || s.is_crypt_op()
        || s.is_kem_op()
        || s.is_gen_op()
        || s.operation & EVP_PKEY_OP_TYPE_DATA != 0;
    typed && s.algctx().is_null()
}

/// `default_fixup_args` for the ctrl and ctrl string directions.
///
/// # Safety
/// `c.p2` is what the translation's data type says (a string, octets, a BIGNUM, ...) for the
/// length `c.p1`.
unsafe fn default_fixup(state: State, tr: Option<&Translation>, c: &mut Tctx<'_>) -> c_int {
    const F: &str = "default_fixup_args";
    let ret = default_check(state, tr);
    if ret <= 0 {
        return ret;
    }
    match state {
        State::PreCtrl => {
            let Some(tr) = tr else { return -2 };
            if c.action == Action::None {
                err::raise_with_text(
                    ERR_LIB_EVP,
                    ERR_R_UNSUPPORTED,
                    F,
                    &format!("[action:{}, state:{}]", c.action as c_int, state as c_int),
                );
                return 0;
            }
            if tr.optype != 0 && no_algctx(c.pctx) {
                err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
                return -2;
            }
            let key = tr.param_key.as_ptr();
            // `(size_t)p1`, as C converts it.
            let size = isize::try_from(c.p1).unwrap_or(0).cast_unsigned();
            c.params[0] = match tr.data_type {
                // SAFETY: a static key; the context's own value, which outlives the call.
                INT => unsafe { OSSL_PARAM_construct_int(key, &raw mut c.p1) },
                UINT => match c.p2 {
                    P2::U64(v) => {
                        c.u64_value = v;
                        // SAFETY: as above.
                        unsafe { OSSL_PARAM_construct_uint64(key, &raw mut c.u64_value) }
                    }
                    P2::Ptr(p) if !p.is_null() && is_scrypt(tr) => {
                        // The scrypt commands take a pointer to a `uint64_t` (the reference
                        // reads it as a BIGNUM, docs/DEVIATIONS.md).
                        // SAFETY: the caller's guarantee: the command's argument.
                        c.u64_value = unsafe { p.cast::<u64>().read_unaligned() };
                        // SAFETY: as above.
                        unsafe { OSSL_PARAM_construct_uint64(key, &raw mut c.u64_value) }
                    }
                    P2::Ptr(p) if !p.is_null() => {
                        if c.action != Action::Set {
                            err::raise_with_text(
                                ERR_LIB_EVP,
                                ERR_R_UNSUPPORTED,
                                F,
                                &format!(
                                    "[action:{}, state:{}] trying to get a BIGNUM via ctrl call",
                                    c.action as c_int, state as c_int
                                ),
                            );
                            return 0;
                        }
                        let bn = p.cast::<BIGNUM>();
                        // SAFETY: the caller's guarantee: a BIGNUM.
                        let bits = unsafe { crate::bn::BN_num_bits(bn) };
                        let len = usize::try_from(bits).unwrap_or(0).div_ceil(8);
                        c.allocated = vec![0; len];
                        let Ok(n) = c_int::try_from(len) else {
                            return 0;
                        };
                        // SAFETY: the BIGNUM; the buffer of `len` octets.
                        if unsafe {
                            crate::bn::conv::BN_bn2nativepad(bn, c.allocated.as_mut_ptr(), n)
                        } < 0
                        {
                            return 0;
                        }
                        // SAFETY: as above; the buffer outlives the call.
                        unsafe { OSSL_PARAM_construct_BN(key, c.allocated.as_mut_ptr(), len) }
                    }
                    // SAFETY: as above.
                    P2::Ptr(_) | P2::NameBuf => unsafe {
                        OSSL_PARAM_construct_uint(key, (&raw mut c.p1).cast())
                    },
                },
                // SAFETY: a static key; the caller's string or octets of `size`.
                UTF8 => unsafe { OSSL_PARAM_construct_utf8_string(key, c.p2().cast(), size) },
                // SAFETY: as above.
                OSSL_PARAM_UTF8_PTR => unsafe {
                    OSSL_PARAM_construct_utf8_ptr(key, c.p2().cast(), size)
                },
                // SAFETY: as above.
                OCTETS => unsafe { OSSL_PARAM_construct_octet_string(key, c.p2(), size) },
                // SAFETY: as above.
                OCTET_PTR => unsafe { OSSL_PARAM_construct_octet_ptr(key, c.p2().cast(), size) },
                _ => c.params[0],
            };
        }
        State::PostCtrl => {
            if c.action == Action::Get
                && let Some(tr) = tr
                && matches!(
                    tr.data_type,
                    UTF8 | OSSL_PARAM_UTF8_PTR | OCTETS | OCTET_PTR
                )
            {
                c.p1 = c_int::try_from(c.params[0].return_size).unwrap_or(c_int::MAX);
            }
        }
        State::PreStr => {
            if c.action != Action::Set {
                err::raise_with_text(
                    ERR_LIB_EVP,
                    EVP_R_COMMAND_NOT_SUPPORTED,
                    F,
                    &format!(
                        "[action:{}, state:{}] only setting allowed",
                        c.action as c_int, state as c_int
                    ),
                );
                return 0;
            }
            let orig_name = c.ctrl_str.clone();
            // SAFETY: the value is a string here.
            let orig_value = unsafe { c.p2_str() }.to_bytes().to_vec();
            let mut name = c.ctrl_str.clone();
            if let Some(tr) = tr {
                name = tr.param_key.to_bytes().to_vec();
                if c.ishex {
                    let mut h = b"hex".to_vec();
                    h.extend_from_slice(&name);
                    h.truncate(NAME_SIZE - 1);
                    name = h;
                }
            }
            let Ok(name) = CString::new(name) else {
                err::raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR, F);
                return -1;
            };
            let settable = settable_of(c.pctx);
            let mut exists: c_int = 0;
            // The value's pointer first: taking it borrows the whole context.
            let value = c.p2().cast_const().cast();
            // SAFETY: the parameter to fill; the list (or NULL); the name and value strings.
            let ok = unsafe {
                OSSL_PARAM_allocate_from_text(
                    c.params.as_mut_ptr(),
                    settable,
                    name.as_ptr(),
                    value,
                    orig_value.len(),
                    &raw mut exists,
                )
            };
            if ok == 0 {
                if exists == 0 {
                    err::raise_with_text(
                        ERR_LIB_EVP,
                        EVP_R_COMMAND_NOT_SUPPORTED,
                        F,
                        &format!(
                            "[action:{}, state:{}] name={}, value={}",
                            c.action as c_int,
                            state as c_int,
                            String::from_utf8_lossy(&orig_name),
                            String::from_utf8_lossy(&orig_value)
                        ),
                    );
                    return -2;
                }
                return 0;
            }
            c.allocated_c = c.params[0].data;
        }
        State::PostStr => {}
    }
    ret
}

/// Whether a translation is one of the scrypt commands', whose argument is a `uint64_t`.
fn is_scrypt(tr: &Translation) -> bool {
    tr.keytype1 == -1
        && matches!(
            tr.ctrl_num,
            EVP_PKEY_CTRL_SCRYPT_N
                | EVP_PKEY_CTRL_SCRYPT_R
                | EVP_PKEY_CTRL_SCRYPT_P
                | EVP_PKEY_CTRL_SCRYPT_MAXMEM_BYTES
        )
}

/// The settable parameters of the context's operation.
fn settable_of(pctx: &PkeyCtx) -> *const OSSL_PARAM {
    let op = pctx.lock().op_alg();
    // SAFETY: the operation's context, or NULL.
    unsafe { op.settable() }.unwrap_or(ptr::null())
}

/// The gettable parameters of the context's operation.
fn gettable_of(pctx: &PkeyCtx) -> *const OSSL_PARAM {
    let op = pctx.lock().op_alg();
    // SAFETY: the operation's context, or NULL.
    unsafe { op.gettable() }.unwrap_or(ptr::null())
}

/// `get_md_name` and `get_cipher_name`.
///
/// # Safety
/// `p` is a live digest (or cipher, for `cipher`).
unsafe fn algo_name(p: *mut c_void, cipher: bool) -> *const c_char {
    if cipher {
        // SAFETY: the caller's guarantee.
        unsafe { super::cipher::EVP_CIPHER_get0_name(p.cast::<EVP_CIPHER>()) }
    } else {
        // SAFETY: the caller's guarantee.
        unsafe { super::digest::EVP_MD_get0_name(p.cast::<EVP_MD>()) }
    }
}

/// `fix_cipher_md`.
///
/// # Safety
/// As for [`default_fixup`]; for a setter, `p2` is NULL or a live digest (cipher).
unsafe fn fix_cipher_md(state: State, tr: &Translation, c: &mut Tctx<'_>, cipher: bool) -> c_int {
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if state == State::PreCtrl && c.action == Action::Get {
        c.orig_p2 = c.p2();
        c.name_room();
    } else if state == State::PreCtrl && c.action == Action::Set {
        let name = if c.p2.is_null() {
            // SAFETY: a number.
            unsafe { crate::objects::OBJ_nid2sn(c.p1) }
        } else {
            // SAFETY: the caller's guarantee.
            unsafe { algo_name(c.p2(), cipher) }
        };
        if name.is_null() {
            // The reference takes the length of the missing name (docs/DEVIATIONS.md).
            return 0;
        }
        c.p2 = P2::Ptr(name.cast_mut().cast());
        // SAFETY: a static name.
        c.p1 = c_int::try_from(unsafe { CStr::from_ptr(name) }.to_bytes().len()).unwrap_or(0);
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    if state == State::PostCtrl && c.action == Action::Get {
        let libctx = c.pctx.lock().libctx.0;
        let name = c.name_buf.as_ptr().cast::<c_char>();
        let found: *const c_void = if cipher {
            // SAFETY: the context's library context; the NUL-terminated buffer.
            unsafe { super::legacy_cipher::get_cipherbyname_ex(libctx, name) }.cast()
        } else {
            // SAFETY: as above.
            unsafe { super::legacy_md::get_digestbyname_ex(libctx, name) }.cast()
        };
        if !c.orig_p2.is_null() {
            // SAFETY: the caller's pointer to fill (`const EVP_MD **`).
            unsafe { c.orig_p2.cast::<*const c_void>().write(found) };
        }
        c.p1 = 1;
    }
    ret
}

/// `fix_distid_len`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_distid_len(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    // Only the post states give anything; the pre state's 0 ends the ctrl before them.
    0
}

/// `fix_kdf_type` with the map of KDF type numbers to names.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_kdf_type(
    state: State,
    tr: &Translation,
    c: &mut Tctx<'_>,
    map: &[(c_int, &'static CStr)],
) -> c_int {
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if state == State::PreCtrl {
        if c.action != Action::None {
            return 0;
        }
        if c.p1 == -2 {
            c.name_room();
            c.action = Action::Get;
        } else {
            c.action = Action::Set;
        }
    }
    if state == State::PreCtrl && c.action == Action::Set {
        let Some(&(_, name)) = map.iter().find(|(n, _)| *n == c.p1) else {
            return -2;
        };
        c.set_static(name);
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    if state == State::PostCtrl && c.action == Action::Get {
        // SAFETY: the name buffer, NUL-terminated.
        let got = unsafe { c.p2_str() }.to_bytes().to_vec();
        c.p1 = map
            .iter()
            .find(|(_, s)| s.to_bytes().eq_ignore_ascii_case(&got))
            .map_or(-1, |&(n, _)| n);
        c.p2 = P2::Ptr(ptr::null_mut());
        return if c.p1 == -1 { -1 } else { 1 };
    }
    ret
}

/// The FFC named groups' names by number (`dh_named_groups` in `ffc_dh.c`: the NIDs of the
/// RFC 7919 and RFC 3526 groups, then 1 to 3 for RFC 5114's).
fn dh_named_group(uid: c_int) -> Option<&'static CStr> {
    use rustyssl_abi::{
        NID_ffdhe2048, NID_ffdhe3072, NID_ffdhe4096, NID_ffdhe6144, NID_ffdhe8192, NID_modp_1536,
        NID_modp_2048, NID_modp_3072, NID_modp_4096, NID_modp_6144, NID_modp_8192, SN_ffdhe2048,
        SN_ffdhe3072, SN_ffdhe4096, SN_ffdhe6144, SN_ffdhe8192, SN_modp_1536, SN_modp_2048,
        SN_modp_3072, SN_modp_4096, SN_modp_6144, SN_modp_8192,
    };
    let groups: [(c_int, &'static CStr); 14] = [
        (NID_ffdhe2048, SN_ffdhe2048),
        (NID_ffdhe3072, SN_ffdhe3072),
        (NID_ffdhe4096, SN_ffdhe4096),
        (NID_ffdhe6144, SN_ffdhe6144),
        (NID_ffdhe8192, SN_ffdhe8192),
        (NID_modp_1536, SN_modp_1536),
        (NID_modp_2048, SN_modp_2048),
        (NID_modp_3072, SN_modp_3072),
        (NID_modp_4096, SN_modp_4096),
        (NID_modp_6144, SN_modp_6144),
        (NID_modp_8192, SN_modp_8192),
        (1, c"dh_1024_160"),
        (2, c"dh_2048_224"),
        (3, c"dh_2048_256"),
    ];
    groups.iter().find(|(u, _)| *u == uid).map(|&(_, n)| n)
}

/// `ossl_dh_gen_type_id2name`.
fn dh_gen_type_name(id: c_int) -> Option<&'static CStr> {
    use rustyssl_abi::{
        DH_PARAMGEN_TYPE_FIPS_186_2, DH_PARAMGEN_TYPE_FIPS_186_4, DH_PARAMGEN_TYPE_GENERATOR,
        DH_PARAMGEN_TYPE_GROUP,
    };
    [
        (DH_PARAMGEN_TYPE_GROUP, c"group"),
        (DH_PARAMGEN_TYPE_GENERATOR, c"generator"),
        (DH_PARAMGEN_TYPE_FIPS_186_4, c"fips186_4"),
        (DH_PARAMGEN_TYPE_FIPS_186_2, c"fips186_2"),
    ]
    .iter()
    .find(|(n, _)| *n == id)
    .map(|&(_, s)| s)
}

/// C's `atoi`: optional space and sign, then digits (wrapping where C's is undefined).
fn atoi(s: &[u8]) -> c_int {
    let mut it = s
        .iter()
        .skip_while(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
        .peekable();
    let mut neg = false;
    if let Some(&&c) = it.peek()
        && (c == b'-' || c == b'+')
    {
        neg = c == b'-';
        it.next();
    }
    let mut v: c_int = 0;
    for &c in it {
        if !c.is_ascii_digit() {
            break;
        }
        v = v.wrapping_mul(10).wrapping_add(c_int::from(c - b'0'));
    }
    if neg { v.wrapping_neg() } else { v }
}

/// `fix_dh_nid`, `fix_dh_nid5114`, and `fix_dh_paramgen_type`: a number (or for the strings of
/// the latter two, a number in a string) to a name.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_dh_names(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    const F: &str = "fix_dh_nid5114";
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if c.action != Action::Set {
        return 0;
    }
    let invalid = || {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_VALUE, F);
        0
    };
    match (tr.fixup, state) {
        (X::DhNid | X::DhNid5114, State::PreCtrl) => {
            let Some(name) = dh_named_group(c.p1) else {
                return invalid();
            };
            c.p2 = P2::Ptr(name.as_ptr().cast_mut().cast());
            c.p1 = 0;
        }
        (X::DhNid5114, State::PreStr) => {
            if c.p2.is_null() {
                return 0;
            }
            // SAFETY: the value string.
            let n = atoi(unsafe { c.p2_str() }.to_bytes());
            let Some(name) = dh_named_group(n) else {
                return invalid();
            };
            c.p2 = P2::Ptr(name.as_ptr().cast_mut().cast());
            c.p1 = 0;
        }
        (X::DhParamgenType, State::PreStr) => {
            // SAFETY: the value string.
            let n = atoi(unsafe { c.p2_str() }.to_bytes());
            let Some(name) = dh_gen_type_name(n) else {
                return invalid();
            };
            c.set_static(name);
        }
        _ => {}
    }
    // SAFETY: the caller's guarantee.
    unsafe { default_fixup(state, Some(tr), c) }
}

/// `fix_ec_param_enc`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_ec_param_enc(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if c.action != Action::Set {
        return 0;
    }
    if state == State::PreCtrl {
        let name = match c.p1 {
            OPENSSL_EC_EXPLICIT_CURVE => OSSL_PKEY_EC_ENCODING_EXPLICIT,
            OPENSSL_EC_NAMED_CURVE => OSSL_PKEY_EC_ENCODING_GROUP,
            _ => {
                err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, "fix_ec_param_enc");
                return -2;
            }
        };
        c.p2 = P2::Ptr(name.as_ptr().cast_mut().cast());
        c.p1 = 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { default_fixup(state, Some(tr), c) }
}

/// `fix_ec_paramgen_curve_nid`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_ec_paramgen_curve_nid(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if c.action != Action::Set {
        return 0;
    }
    if state == State::PreCtrl {
        // SAFETY: a number.
        let sn = unsafe { crate::objects::OBJ_nid2sn(c.p1) };
        c.p2 = P2::Ptr(sn.cast_mut().cast());
        c.p1 = 0;
    }
    // SAFETY: the caller's guarantee.
    unsafe { default_fixup(state, Some(tr), c) }
}

/// `fix_ecdh_cofactor`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_ecdh_cofactor(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    if state == State::PreCtrl {
        if c.action != Action::None {
            return 0;
        }
        c.action = if c.p1 == -2 { Action::Get } else { Action::Set };
    } else if state == State::PreStr {
        c.action = Action::Set;
    }
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if state == State::PreCtrl && c.action == Action::Set && !(-1..=1).contains(&c.p1) {
        return -2;
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    if state == State::PostCtrl && c.action == Action::Get && !(0..=1).contains(&c.p1) {
        c.p1 = -1;
        return -1;
    }
    ret
}

/// The RSA padding modes' names (`fix_rsa_padding_mode`'s map; TLS padding has none).
const PADDINGS: [(c_int, Option<&str>); 7] = [
    (RSA_PKCS1_PADDING, Some("pkcs1")),
    (RSA_NO_PADDING, Some("none")),
    (RSA_PKCS1_OAEP_PADDING, Some("oaep")),
    (RSA_PKCS1_OAEP_PADDING, Some("oeap")),
    (RSA_X931_PADDING, Some("x931")),
    (RSA_PKCS1_PSS_PADDING, Some("pss")),
    (RSA_PKCS1_WITH_TLS_PADDING, None),
];

/// `fix_rsa_padding_mode`.
///
/// # Safety
/// As for [`default_fixup`]; for the getter, `p2` is NULL or room for an `int`.
unsafe fn fix_rsa_padding_mode(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if state == State::PreCtrl && c.action == Action::Get {
        c.orig_p2 = c.p2();
        c.name_room();
    } else if state == State::PreCtrl && c.action == Action::Set {
        // Numeric modes pass as integers, whatever the parameter's documented type.
        // SAFETY: a static key; the context's own value, which outlives the call.
        c.params[0] = unsafe { OSSL_PARAM_construct_int(tr.param_key.as_ptr(), &raw mut c.p1) };
        return 1;
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    if c.action == Action::Get && state == State::PostCtrl {
        // SAFETY: the name buffer, NUL-terminated.
        let got = unsafe { c.p2_str() }.to_bytes().to_vec();
        // The reference compares the name with the TLS mode's missing name too, and crashes
        // for an unknown one (docs/DEVIATIONS.md).
        match PADDINGS
            .iter()
            .find(|(_, n)| n.is_some_and(|n| n.as_bytes() == got))
        {
            None => {
                err::raise_with_text(
                    ERR_LIB_RSA,
                    RSA_R_UNKNOWN_PADDING_TYPE,
                    "fix_rsa_padding_mode",
                    &format!(
                        "[action:{}, state:{}] padding name {}",
                        c.action as c_int,
                        state as c_int,
                        String::from_utf8_lossy(&got)
                    ),
                );
                c.p1 = -2;
                c.p2 = P2::Ptr(ptr::null_mut());
                return -2;
            }
            Some(&(id, _)) => {
                if !c.orig_p2.is_null() {
                    // SAFETY: the caller's `int *`.
                    unsafe { c.orig_p2.cast::<c_int>().write(id) };
                }
            }
        }
        c.p2 = P2::Ptr(ptr::null_mut());
    }
    ret
}

/// The PSS salt length keywords.
const SALTLENS: [(c_int, &str); 3] = [
    (RSA_PSS_SALTLEN_DIGEST, "digest"),
    (RSA_PSS_SALTLEN_MAX, "max"),
    (RSA_PSS_SALTLEN_AUTO, "auto"),
];

/// `fix_rsa_pss_saltlen`.
///
/// # Safety
/// As for [`default_fixup`]; for the getter, `p2` is NULL or room for an `int`.
unsafe fn fix_rsa_pss_saltlen(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if state == State::PreCtrl && c.action == Action::Get {
        c.orig_p2 = c.p2();
        c.name_room();
    } else if state == State::PreCtrl && c.action == Action::Set {
        let s = SALTLENS
            .iter()
            .find(|(n, _)| *n == c.p1)
            .map_or_else(|| c.p1.to_string(), |(_, s)| (*s).to_owned());
        c.set_name(s.as_bytes());
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    if c.action == Action::Get && state == State::PostCtrl {
        // SAFETY: the name buffer, NUL-terminated.
        let got = unsafe { c.p2_str() }.to_bytes().to_vec();
        let val = SALTLENS
            .iter()
            .find(|(_, s)| s.as_bytes() == got)
            .map_or_else(|| atoi(&got), |&(n, _)| n);
        if !c.orig_p2.is_null() {
            // SAFETY: the caller's `int *`.
            unsafe { c.orig_p2.cast::<c_int>().write(val) };
        }
        c.p2 = P2::Ptr(ptr::null_mut());
    }
    ret
}

/// `fix_hkdf_mode`.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fix_hkdf_mode(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    const MODES: [(c_int, &CStr); 3] = [
        (0, c"EXTRACT_AND_EXPAND"),
        (1, c"EXTRACT_ONLY"),
        (2, c"EXPAND_ONLY"),
    ];
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if c.action == Action::Set && state == State::PreCtrl {
        let Some(&(_, name)) = MODES.iter().find(|(n, _)| *n == c.p1) else {
            return 0;
        };
        // The name's length becomes the mode (`p1`), which the integer parameter points to.
        c.set_static(name);
    }
    // SAFETY: the caller's guarantee.
    let ret = unsafe { default_fixup(state, Some(tr), c) };
    if ret <= 0 {
        return ret;
    }
    1
}

/// Runs a translation's fixup.
///
/// # Safety
/// As for [`default_fixup`].
unsafe fn fixup(state: State, tr: Option<&Translation>, c: &mut Tctx<'_>) -> c_int {
    let Some(tr) = tr else {
        // SAFETY: the caller's guarantee.
        return unsafe { default_fixup(state, None, c) };
    };
    match tr.fixup {
        // SAFETY: the caller's guarantee.
        X::Default => unsafe { default_fixup(state, Some(tr), c) },
        // SAFETY: the caller's guarantee.
        X::Md => unsafe { fix_cipher_md(state, tr, c, false) },
        // SAFETY: the caller's guarantee.
        X::Cipher => unsafe { fix_cipher_md(state, tr, c, true) },
        // SAFETY: the caller's guarantee.
        X::DistidLen => unsafe { fix_distid_len(state, tr, c) },
        // SAFETY: the caller's guarantee.
        X::DhKdfType => unsafe {
            fix_kdf_type(
                state,
                tr,
                c,
                &[
                    (EVP_PKEY_DH_KDF_NONE, c""),
                    (EVP_PKEY_DH_KDF_X9_42, OSSL_KDF_NAME_X942KDF_ASN1),
                ],
            )
        },
        // SAFETY: the caller's guarantee.
        X::EcKdfType => unsafe {
            fix_kdf_type(
                state,
                tr,
                c,
                &[
                    (EVP_PKEY_ECDH_KDF_NONE, c""),
                    (EVP_PKEY_ECDH_KDF_X9_63, OSSL_KDF_NAME_X963KDF),
                ],
            )
        },
        // SAFETY: the caller's guarantee.
        X::Oid => unsafe { fix_oid(state, tr, c) },
        // SAFETY: the caller's guarantee.
        X::DhNid | X::DhNid5114 | X::DhParamgenType => unsafe { fix_dh_names(state, tr, c) },
        // SAFETY: the caller's guarantee.
        X::EcParamEnc => unsafe { fix_ec_param_enc(state, tr, c) },
        // SAFETY: the caller's guarantee.
        X::EcParamgenCurveNid => unsafe { fix_ec_paramgen_curve_nid(state, tr, c) },
        // SAFETY: the caller's guarantee.
        X::EcdhCofactor => unsafe { fix_ecdh_cofactor(state, tr, c) },
        // SAFETY: the caller's guarantee.
        X::RsaPadding => unsafe { fix_rsa_padding_mode(state, tr, c) },
        // SAFETY: the caller's guarantee.
        X::RsaPssSaltlen => unsafe { fix_rsa_pss_saltlen(state, tr, c) },
        // SAFETY: the caller's guarantee.
        X::HkdfMode => unsafe { fix_hkdf_mode(state, tr, c) },
        // Only for parameters to ctrls (4.2d).
        X::GroupEcx => 0,
    }
}

/// `fix_oid`.
///
/// # Safety
/// As for [`default_fixup`]; for the setter, `p2` is NULL or a live object.
unsafe fn fix_oid(state: State, tr: &Translation, c: &mut Tctx<'_>) -> c_int {
    let ret = default_check(state, Some(tr));
    if ret <= 0 {
        return ret;
    }
    if state == State::PreCtrl && c.action == Action::Set {
        c.name_buf = [0; NAME_SIZE];
        // SAFETY: the buffer and its size; the caller's object (or NULL).
        unsafe {
            crate::objects::OBJ_obj2txt(
                c.name_buf.as_mut_ptr().cast(),
                NAME_SIZE_INT,
                c.p2().cast(),
                0,
            )
        };
        c.p2 = P2::NameBuf;
        c.p1 = 0;
    }
    // SAFETY: the caller's guarantee. (The getter's object, which the reference makes from what
    // it got and never returns, isn't made: the getter passes no room for a name, so no
    // provider gives one.)
    unsafe { default_fixup(state, Some(tr), c) }
}

/// `evp_pkey_ctx_set_params_strict`: -2 if the operation doesn't list a parameter as settable.
///
/// # Safety
/// `ctx` is NULL or a live context; `params` is NULL or an array.
pub(crate) unsafe fn set_params_strict(ctx: *mut EVP_PKEY_CTX, params: *const OSSL_PARAM) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        return 0;
    };
    if params.is_null() {
        return 0;
    }
    if c.lock().keymgmt.is_some() {
        let settable = settable_of(c);
        // SAFETY: the caller's guarantee: an array ended by a NULL key.
        if unsafe { !all_listed(params, settable) } {
            return -2;
        }
    }
    // SAFETY: the caller's guarantee.
    unsafe { EVP_PKEY_CTX_set_params(ctx, params) }
}

/// `evp_pkey_ctx_get_params_strict`: -2 if the operation doesn't list a parameter as gettable.
///
/// # Safety
/// `ctx` is NULL or a live context; `params` is NULL or an array.
pub(crate) unsafe fn get_params_strict(ctx: *mut EVP_PKEY_CTX, params: *mut OSSL_PARAM) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        return 0;
    };
    if params.is_null() {
        return 0;
    }
    if c.lock().keymgmt.is_some() {
        let gettable = gettable_of(c);
        // SAFETY: the caller's guarantee.
        if unsafe { !all_listed(params, gettable) } {
            return -2;
        }
    }
    // SAFETY: the caller's guarantee.
    unsafe { EVP_PKEY_CTX_get_params(ctx, params) }
}

/// Whether each parameter of `params` has its key in `list`.
///
/// # Safety
/// `params` is an array ended by a NULL key; `list` is NULL or such an array.
unsafe fn all_listed(params: *const OSSL_PARAM, list: *const OSSL_PARAM) -> bool {
    let mut p = params;
    // SAFETY: the caller's guarantee.
    while let Some(q) = unsafe { p.as_ref() } {
        if q.key.is_null() {
            break;
        }
        // SAFETY: as above.
        if unsafe { OSSL_PARAM_locate_const(list, q.key) }.is_null() {
            return false;
        }
        p = p.wrapping_add(1);
    }
    true
}

/// `evp_pkey_ctx_ctrl_to_param`.
///
/// # Safety
/// `ctx` is a live context; `p2` is what the command takes.
unsafe fn ctrl_to_param(
    ctx: *mut EVP_PKEY_CTX,
    pctx: &PkeyCtx,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: P2,
) -> c_int {
    let keytype = if keytype == -1 {
        pctx.lock().legacy_keytype()
    } else {
        keytype
    };
    let Some((tr, _)) = lookup(keytype, optype, &By::Ctrl(cmd)) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_COMMAND_NOT_SUPPORTED,
            "evp_pkey_ctx_ctrl_to_param",
        );
        return -2;
    };
    let mut c = Tctx {
        pctx,
        action: tr.action,
        ishex: false,
        ctrl_str: Vec::new(),
        p1,
        p2,
        u64_value: 0,
        params: [end(), end()],
        orig_p2: ptr::null_mut(),
        name_buf: [0; NAME_SIZE],
        allocated_c: ptr::null_mut(),
        allocated: Vec::new(),
    };
    // SAFETY: the caller's guarantee.
    let mut ret = unsafe { fixup(State::PreCtrl, Some(tr), &mut c) };
    if ret > 0 {
        ret = match c.action {
            // SAFETY: the context; the translation's parameters.
            Action::Get => unsafe { get_params_strict(ctx, c.params.as_mut_ptr()) },
            // SAFETY: as above.
            Action::Set => unsafe { set_params_strict(ctx, c.params.as_ptr()) },
            Action::None => ret,
        };
    }
    if ret > 0 {
        c.p1 = ret;
        // SAFETY: the caller's guarantee.
        unsafe { fixup(State::PostCtrl, Some(tr), &mut c) };
        ret = c.p1;
    }
    ret
}

/// `evp_pkey_ctx_ctrl_str_to_param`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn ctrl_str_to_param(
    ctx: *mut EVP_PKEY_CTX,
    pctx: &PkeyCtx,
    name: &CStr,
    value: &CStr,
) -> c_int {
    let (keytype, op) = {
        let s = pctx.lock();
        (s.legacy_keytype(), s.operation)
    };
    let optype = if op == 0 { -1 } else { op };
    let found = lookup(keytype, optype, &By::Str(name.to_bytes()));
    let mut c = Tctx {
        pctx,
        action: found.map_or(Action::Set, |(tr, _)| tr.action),
        ishex: found.is_some_and(|(_, hex)| hex),
        ctrl_str: name.to_bytes().to_vec(),
        p1: c_int::try_from(value.to_bytes().len()).unwrap_or(c_int::MAX),
        p2: P2::Ptr(value.as_ptr().cast_mut().cast()),
        u64_value: 0,
        params: [end(), end()],
        orig_p2: ptr::null_mut(),
        name_buf: [0; NAME_SIZE],
        allocated_c: ptr::null_mut(),
        allocated: Vec::new(),
    };
    let tr = found.map(|(tr, _)| tr);
    // SAFETY: the value is a string.
    let mut ret = unsafe { fixup(State::PreStr, tr, &mut c) };
    if ret > 0 && c.action == Action::Set {
        // SAFETY: the context; the parameter made from the string.
        ret = unsafe { set_params_strict(ctx, c.params.as_ptr()) };
    }
    if ret > 0 {
        // SAFETY: as above.
        ret = unsafe { fixup(State::PostStr, tr, &mut c) };
    }
    ret
}

/// `evp_pkey_ctx_store_cached_data` for the ctrl (`name` None) and ctrl string directions:
/// keeps the distinguishing ID; -2 (with an error, which the callers drop) for anything else.
///
/// # Safety
/// `data` holds `data_len` octets (when the command is the ID's).
unsafe fn store_cached(
    c: &PkeyCtx,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    name: Option<&CStr>,
    data: *const u8,
    data_len: usize,
) -> c_int {
    const F: &str = "evp_pkey_ctx_store_cached_data";
    let cmd = if cmd == -1
        && name.is_some_and(|n| n.to_bytes() == b"distid" || n.to_bytes() == b"hexdistid")
    {
        EVP_PKEY_CTRL_SET1_ID
    } else {
        cmd
    };
    if cmd != EVP_PKEY_CTRL_SET1_ID {
        err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
        return -2;
    }
    let mut s = c.lock();
    if keytype != -1 {
        if !s.provider_state() || s.keymgmt.is_none() {
            // Without an operation's provider side, an EVP_PKEY_METHOD (4.2d) would say.
            drop(s);
            err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
            return -2;
        }
        let name = super::pkey::ameth::type2name(keytype);
        if !s.keymgmt.as_ref().is_some_and(|m| m.get().is_a(&name)) {
            drop(s);
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION, F);
            return -1;
        }
    }
    if optype != -1 && s.operation & optype == 0 {
        drop(s);
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION, F);
        return -1;
    }
    s.cached_id = None;
    let bytes = if data_len > 0 && !data.is_null() {
        // SAFETY: the caller's guarantee.
        unsafe { core::slice::from_raw_parts(data, data_len) }.to_vec()
    } else {
        Vec::new()
    };
    s.cached_id = Some(CachedId {
        name: name.map(CStr::to_owned),
        data: bytes,
    });
    1
}

/// `evp_pkey_ctx_ctrl_int`.
///
/// # Safety
/// `ctx` is a live context; `p2` is what the command takes.
unsafe fn ctrl_int(
    ctx: *mut EVP_PKEY_CTX,
    c: &PkeyCtx,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: P2,
) -> c_int {
    const F: &str = "evp_pkey_ctx_ctrl_int";
    let (op, provider) = {
        let s = c.lock();
        (s.operation, s.provider_state())
    };
    if op == EVP_PKEY_OP_UNDEFINED {
        err::raise(ERR_LIB_EVP, EVP_R_NO_OPERATION_SET, F);
        return -1;
    }
    if optype != -1 && op & optype == 0 {
        err::raise(ERR_LIB_EVP, EVP_R_INVALID_OPERATION, F);
        return -1;
    }
    if provider {
        // SAFETY: the caller's guarantee.
        return unsafe { ctrl_to_param(ctx, c, keytype, optype, cmd, p1, p2) };
    }
    // Without a provider side, the context's EVP_PKEY_METHOD (an application's, 4.2d) would
    // take it; contexts with key managers have none.
    err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
    -2
}

/// `EVP_PKEY_CTX_ctrl` with the argument as given.
///
/// # Safety
/// `ctx` is NULL or a live context; `p2` is what the command takes.
pub(crate) unsafe fn ctrl(
    ctx: *mut EVP_PKEY_CTX,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: *mut c_void,
) -> c_int {
    // SAFETY: the caller's guarantee.
    unsafe { ctrl_arg(ctx, keytype, optype, cmd, p1, P2::Ptr(p2)) }
}

/// `EVP_PKEY_CTX_ctrl`.
///
/// # Safety
/// `ctx` is NULL or a live context; `p2` is what the command takes.
unsafe fn ctrl_arg(
    ctx: *mut EVP_PKEY_CTX,
    keytype: c_int,
    optype: c_int,
    cmd: c_int,
    p1: c_int,
    p2: P2,
) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        err::raise(
            ERR_LIB_EVP,
            EVP_R_COMMAND_NOT_SUPPORTED,
            "EVP_PKEY_CTX_ctrl",
        );
        return -2;
    };
    // SAFETY: no preconditions.
    unsafe { ERR_set_mark() };
    let len = usize::try_from(p1).unwrap_or(0);
    // SAFETY: for the ID's command, `p2` holds `p1` octets (the caller's guarantee).
    let data = match p2 {
        P2::Ptr(p) => p.cast_const().cast(),
        P2::U64(_) | P2::NameBuf => ptr::null(),
    };
    // SAFETY: as above.
    let ret = unsafe { store_cached(c, keytype, optype, cmd, None, data, len) };
    if ret == -2 {
        // SAFETY: the mark set above.
        unsafe { ERR_pop_to_mark() };
    } else {
        // SAFETY: as above.
        unsafe { ERR_clear_last_mark() };
        if ret < 1 || c.lock().operation == EVP_PKEY_OP_UNDEFINED {
            return ret;
        }
    }
    // SAFETY: the caller's guarantee.
    unsafe { ctrl_int(ctx, c, keytype, optype, cmd, p1, p2) }
}

/// `evp_pkey_ctx_ctrl_str_int`.
///
/// # Safety
/// `ctx` is a live context.
unsafe fn ctrl_str_int(ctx: *mut EVP_PKEY_CTX, c: &PkeyCtx, name: &CStr, value: &CStr) -> c_int {
    let (op, provider) = {
        let s = c.lock();
        (s.operation, s.provider_state())
    };
    if op != EVP_PKEY_OP_UNDEFINED && provider {
        // SAFETY: the caller's guarantee.
        return unsafe { ctrl_str_to_param(ctx, c, name, value) };
    }
    // Without a provider side, the context's EVP_PKEY_METHOD (4.2d) would take it.
    err::raise(
        ERR_LIB_EVP,
        EVP_R_COMMAND_NOT_SUPPORTED,
        "evp_pkey_ctx_ctrl_str_int",
    );
    -2
}

/// `evp_pkey_ctx_use_cached_data`: gives the operation just started the kept distinguishing
/// ID. 1, or its ctrl's failure.
///
/// # Safety
/// `ctx` is a live context.
pub(crate) unsafe fn use_cached_data(ctx: *mut EVP_PKEY_CTX) -> c_int {
    // SAFETY: the caller's guarantee.
    let Some(c) = (unsafe { pkey_ctx::context(ctx) }) else {
        return 1;
    };
    let (id, op) = {
        let s = c.lock();
        (
            s.cached_id
                .as_ref()
                .map(|i| (i.name.clone(), i.data.clone())),
            s.operation,
        )
    };
    let Some((name, data)) = id else { return 1 };
    match name {
        Some(name) => {
            // The value as kept, NUL included.
            let value = CStr::from_bytes_until_nul(&data).unwrap_or(c"");
            // SAFETY: the caller's guarantee.
            unsafe { ctrl_str_int(ctx, c, &name, value) }
        }
        None => {
            let mut data = data;
            let len = c_int::try_from(data.len()).unwrap_or(c_int::MAX);
            let p = if data.is_empty() {
                ptr::null_mut()
            } else {
                data.as_mut_ptr().cast()
            };
            // SAFETY: the caller's guarantee; the ID's octets.
            unsafe { ctrl_int(ctx, c, -1, op, EVP_PKEY_CTRL_SET1_ID, len, P2::Ptr(p)) }
        }
    }
}

ffi_export! {
    /// Sends the ctrl command `cmd` for the key type `keytype` and operation types `optype`
    /// (-1 for any): translated to the operation's parameters. The command's result, or <= 0
    /// (-2 for an unsupported command).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `p2` is what the command takes.
    pub unsafe extern "C" fn EVP_PKEY_CTX_ctrl(ctx: *mut EVP_PKEY_CTX, keytype: c_int, optype: c_int, cmd: c_int, p1: c_int, p2: *mut c_void) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl(ctx, keytype, optype, cmd, p1, p2) }
    }
}

ffi_export! {
    /// `EVP_PKEY_CTX_ctrl` with a 64-bit value (the reference passes its address, which the
    /// translation reads as a BIGNUM; docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context.
    pub unsafe extern "C" fn EVP_PKEY_CTX_ctrl_uint64(ctx: *mut EVP_PKEY_CTX, keytype: c_int, optype: c_int, cmd: c_int, value: u64) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        // SAFETY: the caller's guarantee.
        unsafe { ctrl_arg(ctx, keytype, optype, cmd, 0, P2::U64(value)) }
    }
}

ffi_export! {
    /// Sends the ctrl string `name`=`value`: translated to a parameter of the operation (or
    /// taken as one's name). The result, or <= 0 (-2 if unsupported). NULL strings fail
    /// (docs/DEVIATIONS.md).
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `name` and `value` are NULL or strings.
    pub unsafe extern "C" fn EVP_PKEY_CTX_ctrl_str(ctx: *mut EVP_PKEY_CTX, name: *const c_char, value: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        const F: &str = "EVP_PKEY_CTX_ctrl_str";
        // SAFETY: the caller's guarantee.
        let (Some(c), Some(n), Some(v)) = (unsafe { pkey_ctx::context(ctx) }, unsafe { super::opmeth::text(name) }, unsafe { super::opmeth::text(value) }) else {
            err::raise(ERR_LIB_EVP, EVP_R_COMMAND_NOT_SUPPORTED, F);
            return -2;
        };
        // SAFETY: no preconditions.
        unsafe { ERR_set_mark() };
        let bytes = v.to_bytes_with_nul();
        // SAFETY: the value's octets and its NUL.
        let ret = unsafe { store_cached(c, -1, -1, -1, Some(n), bytes.as_ptr(), bytes.len()) };
        if ret == -2 {
            // SAFETY: the mark set above.
            unsafe { ERR_pop_to_mark() };
        } else {
            // SAFETY: as above.
            unsafe { ERR_clear_last_mark() };
            if ret < 1 || c.lock().operation == EVP_PKEY_OP_UNDEFINED {
                return ret;
            }
        }
        // SAFETY: the caller's guarantee.
        unsafe { ctrl_str_int(ctx, c, n, v) }
    }
}

ffi_export! {
    /// Sends `cmd` with the digest named `md`: 0 with `EVP_R_INVALID_DIGEST` if there's none.
    ///
    /// # Safety
    /// `ctx` is NULL or a live context; `md` is NULL or a string.
    pub unsafe extern "C" fn EVP_PKEY_CTX_md(ctx: *mut EVP_PKEY_CTX, optype: c_int, cmd: c_int, md: *const c_char) -> c_int
    where failure = 0, library = ERR_LIB_EVP
    {
        let m = if md.is_null() {
            ptr::null()
        } else {
            // SAFETY: the caller's string.
            unsafe { super::legacy_md::EVP_get_digestbyname(md) }
        };
        if m.is_null() {
            err::raise(ERR_LIB_EVP, EVP_R_INVALID_DIGEST, "EVP_PKEY_CTX_md");
            return 0;
        }
        // SAFETY: the caller's guarantee; a digest.
        unsafe { ctrl(ctx, -1, optype, cmd, 0, m.cast_mut().cast()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustyssl_abi::{
        EVP_PKEY_CTRL_GET_RSA_PADDING, EVP_PKEY_OP_TYPE_CRYPT, RSA_PKCS1_PSS_PADDING,
    };

    #[test]
    fn atoi_is_c_s() {
        assert_eq!(atoi(b"  -12x"), -12);
        assert_eq!(atoi(b"+7"), 7);
        assert_eq!(atoi(b"abc"), 0);
        assert_eq!(atoi(b""), 0);
    }

    #[test]
    fn lookups_take_the_first_match() {
        // "md" is TLS1-PRF's first, with HKDF's the same parameter.
        let (tr, hex) = lookup(-1, EVP_PKEY_OP_DERIVE, &By::Str(b"MD")).expect("found");
        assert_eq!(tr.ctrl_num, EVP_PKEY_CTRL_TLS_MD);
        assert!(!hex);
        let (tr, hex) = lookup(-1, EVP_PKEY_OP_DERIVE, &By::Str(b"hexsalt")).expect("found");
        assert_eq!(tr.ctrl_num, EVP_PKEY_CTRL_HKDF_SALT);
        assert!(hex);
        // Getters aren't found by string.
        assert!(lookup(-1, -1, &By::Str(b"nothing")).is_none());
        let (tr, _) = lookup(EVP_PKEY_DH, PGEN, &By::Ctrl(EVP_PKEY_CTRL_DH_NID)).expect("found");
        assert_eq!(tr.keytype1, EVP_PKEY_DH);
        // Commands share numbers: RSA's padding command is TLS1-PRF's secret, whose entry is for
        // any key type.
        let (tr, _) = lookup(1036, -1, &By::Ctrl(EVP_PKEY_CTRL_RSA_PADDING)).expect("found");
        assert_eq!(tr.ctrl_num, EVP_PKEY_CTRL_TLS_SECRET);
        assert!(lookup(1036, -1, &By::Ctrl(9999)).is_none());
    }

    /// A derivation context of `name` in a context of its own (whose fetches load no
    /// configuration, which Miri can't run), with the context to free after it.
    fn derive_ctx(name: &CStr) -> (*mut rustyssl_abi::OSSL_LIB_CTX, *mut EVP_PKEY_CTX) {
        // SAFETY: no preconditions.
        let lib = unsafe { crate::libctx::OSSL_LIB_CTX_new() };
        // SAFETY: the context; a static name.
        let c = unsafe { pkey_ctx::EVP_PKEY_CTX_new_from_name(lib, name.as_ptr(), ptr::null()) };
        // SAFETY: the context.
        let got = unsafe { super::super::exchange::EVP_PKEY_derive_init(c) };
        assert_eq!(got, 1);
        (lib, c)
    }

    fn free_ctx((lib, c): (*mut rustyssl_abi::OSSL_LIB_CTX, *mut EVP_PKEY_CTX)) {
        // SAFETY: made by `derive_ctx`, freed once.
        unsafe { pkey_ctx::EVP_PKEY_CTX_free(c) };
        // SAFETY: as above, its objects freed.
        unsafe { crate::libctx::OSSL_LIB_CTX_free(lib) };
        crate::err::take_all();
    }

    /// docs/DEVIATIONS.md: a digest given by a NID without a name fails (the reference takes
    /// the length of the missing name).
    #[test]
    fn nameless_digests_are_refused() {
        let (lib, c) = derive_ctx(c"HKDF");
        // SAFETY: the context; no pointer.
        let got = unsafe {
            ctrl(
                c,
                -1,
                EVP_PKEY_OP_DERIVE,
                EVP_PKEY_CTRL_HKDF_MD,
                99_999,
                ptr::null_mut(),
            )
        };
        assert_eq!(got, 0);
        // SAFETY: as above, a NID with a name.
        let got = unsafe {
            ctrl(
                c,
                -1,
                EVP_PKEY_OP_DERIVE,
                EVP_PKEY_CTRL_HKDF_MD,
                rustyssl_abi::NID_sha256,
                ptr::null_mut(),
            )
        };
        assert_eq!(got, 1);
        free_ctx((lib, c));
    }

    /// docs/DEVIATIONS.md: NULL strings, and a NULL context with a distinguishing ID, fail (the
    /// reference crashes).
    #[test]
    fn null_strings_are_refused() {
        let (lib, c) = derive_ctx(c"HKDF");
        // SAFETY: NULL is the case under test, here and below.
        let got =
            unsafe { EVP_PKEY_CTX_ctrl_str(ptr::null_mut(), c"distid".as_ptr(), c"x".as_ptr()) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_CTX_ctrl_str(c, ptr::null(), c"x".as_ptr()) };
        assert_eq!(got, -2);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_CTX_ctrl_str(c, c"md".as_ptr(), ptr::null()) };
        assert_eq!(got, -2);
        // SAFETY: the context; static strings.
        let got = unsafe { EVP_PKEY_CTX_ctrl_str(c, c"md".as_ptr(), c"SHA256".as_ptr()) };
        assert_eq!(got, 1);
        free_ctx((lib, c));
    }

    /// docs/DEVIATIONS.md: the scrypt commands take a `uint64_t` (the reference reads its
    /// address as a BIGNUM), as `EVP_PKEY_CTX_ctrl_uint64` gives it.
    #[test]
    #[cfg_attr(
        all(miri, target_arch = "aarch64"),
        ignore = "sha2's ARMv8 path breaks Stacked Borrows (docs/DEPENDENCIES.md)"
    )]
    fn scrypt_arguments_are_64_bit() {
        let (lib, c) = derive_ctx(c"SCRYPT");
        let mut r: u64 = 1;
        // SAFETY: the context; the value.
        let got = unsafe {
            EVP_PKEY_CTX_ctrl_uint64(c, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SCRYPT_N, 16)
        };
        assert_eq!(got, 1);
        // SAFETY: the context; a pointer to the value.
        let got = unsafe {
            ctrl(
                c,
                -1,
                EVP_PKEY_OP_DERIVE,
                EVP_PKEY_CTRL_SCRYPT_R,
                0,
                (&raw mut r).cast(),
            )
        };
        assert_eq!(got, 1);
        // SAFETY: as above, by `p1`.
        let got = unsafe {
            ctrl(
                c,
                -1,
                EVP_PKEY_OP_DERIVE,
                EVP_PKEY_CTRL_SCRYPT_P,
                1,
                ptr::null_mut(),
            )
        };
        assert_eq!(got, 1);
        // SAFETY: the context; static strings.
        let got = unsafe { EVP_PKEY_CTX_ctrl_str(c, c"pass".as_ptr(), c"".as_ptr()) };
        assert_eq!(got, 1);
        // SAFETY: as above.
        let got = unsafe { EVP_PKEY_CTX_ctrl_str(c, c"salt".as_ptr(), c"".as_ptr()) };
        assert_eq!(got, 1);
        let mut out = [0u8; 8];
        let mut len = out.len();
        // SAFETY: the context; the buffer.
        let got =
            unsafe { super::super::exchange::EVP_PKEY_derive(c, out.as_mut_ptr(), &raw mut len) };
        assert_eq!(got, 1);
        // RFC 7914's first vector (N=16, r=1, p=1, empty password and salt).
        assert_eq!(out, [0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20]);
        free_ctx((lib, c));
    }

    /// docs/DEVIATIONS.md: a padding mode read back by a name without a mode fails (the
    /// reference compares it with the TLS mode's missing name and crashes).
    #[test]
    fn unknown_padding_names_fail() {
        let (lib, ctx) = derive_ctx(c"HKDF");
        // SAFETY: the live context.
        let pctx = unsafe { pkey_ctx::context(ctx) }.expect("a context");
        let (tr, _) = lookup(
            EVP_PKEY_RSA,
            EVP_PKEY_OP_TYPE_CRYPT,
            &By::Ctrl(EVP_PKEY_CTRL_GET_RSA_PADDING),
        )
        .expect("found");
        let mut mode: c_int = 0;
        let mut c = Tctx {
            pctx,
            action: Action::Get,
            ishex: false,
            ctrl_str: Vec::new(),
            p1: 0,
            p2: P2::Ptr(ptr::null_mut()),
            u64_value: 0,
            params: [end(), end()],
            orig_p2: (&raw mut mode).cast(),
            name_buf: [0; NAME_SIZE],
            allocated_c: ptr::null_mut(),
            allocated: Vec::new(),
        };
        c.set_name(b"tls");
        // SAFETY: the name buffer; the `int` to fill.
        let got = unsafe { fixup(State::PostCtrl, Some(tr), &mut c) };
        assert_eq!(got, -2);
        assert_eq!(mode, 0);
        c.set_name(b"pss");
        // SAFETY: as above.
        let got = unsafe { fixup(State::PostCtrl, Some(tr), &mut c) };
        assert_eq!(got, 1);
        assert_eq!(mode, RSA_PKCS1_PSS_PADDING);
        drop(c);
        free_ctx((lib, ctx));
    }

    #[test]
    fn named_groups() {
        assert_eq!(dh_named_group(2), Some(c"dh_2048_224"));
        assert_eq!(
            dh_named_group(rustyssl_abi::NID_ffdhe2048),
            Some(c"ffdhe2048")
        );
        assert_eq!(dh_named_group(0), None);
        assert_eq!(dh_gen_type_name(1), Some(c"fips186_2"));
        assert_eq!(dh_gen_type_name(9), None);
    }
}
