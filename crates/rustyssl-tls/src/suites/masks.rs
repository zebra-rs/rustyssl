//! The algorithm bits of a cipher suite (`ssl/ssl_local.h`). They are internal to OpenSSL, not
//! part of its ABI, but the cipher-string language is defined in their terms (each alias selects
//! by them), so they keep OpenSSL's names and values.

#![allow(non_upper_case_globals, missing_docs)]

// Key exchange (`algorithm_mkey`).
pub const SSL_kRSA: u32 = 0x0000_0001;
pub const SSL_kDHE: u32 = 0x0000_0002;
pub const SSL_kECDHE: u32 = 0x0000_0004;
pub const SSL_kPSK: u32 = 0x0000_0008;
pub const SSL_kGOST: u32 = 0x0000_0010;
pub const SSL_kSRP: u32 = 0x0000_0020;
pub const SSL_kRSAPSK: u32 = 0x0000_0040;
pub const SSL_kECDHEPSK: u32 = 0x0000_0080;
pub const SSL_kDHEPSK: u32 = 0x0000_0100;
pub const SSL_kGOST18: u32 = 0x0000_0200;
/// Every PSK key exchange.
pub const SSL_PSK: u32 = SSL_kPSK | SSL_kRSAPSK | SSL_kECDHEPSK | SSL_kDHEPSK;
/// TLS 1.3's: the key exchange isn't part of the suite.
pub const SSL_kANY: u32 = 0;

// Server authentication (`algorithm_auth`).
pub const SSL_aRSA: u32 = 0x0000_0001;
pub const SSL_aDSS: u32 = 0x0000_0002;
pub const SSL_aNULL: u32 = 0x0000_0004;
pub const SSL_aECDSA: u32 = 0x0000_0008;
pub const SSL_aPSK: u32 = 0x0000_0010;
pub const SSL_aGOST01: u32 = 0x0000_0020;
pub const SSL_aSRP: u32 = 0x0000_0040;
pub const SSL_aGOST12: u32 = 0x0000_0080;
/// TLS 1.3's: the authentication isn't part of the suite.
pub const SSL_aANY: u32 = 0;
/// Every certificate-based authentication.
pub const SSL_aCERT: u32 = SSL_aRSA | SSL_aDSS | SSL_aECDSA | SSL_aGOST01 | SSL_aGOST12;

// Symmetric encryption (`algorithm_enc`).
pub const SSL_DES: u32 = 0x0000_0001;
pub const SSL_3DES: u32 = 0x0000_0002;
pub const SSL_RC4: u32 = 0x0000_0004;
pub const SSL_RC2: u32 = 0x0000_0008;
pub const SSL_IDEA: u32 = 0x0000_0010;
pub const SSL_eNULL: u32 = 0x0000_0020;
pub const SSL_AES128: u32 = 0x0000_0040;
pub const SSL_AES256: u32 = 0x0000_0080;
pub const SSL_CAMELLIA128: u32 = 0x0000_0100;
pub const SSL_CAMELLIA256: u32 = 0x0000_0200;
pub const SSL_eGOST2814789CNT: u32 = 0x0000_0400;
pub const SSL_SEED: u32 = 0x0000_0800;
pub const SSL_AES128GCM: u32 = 0x0000_1000;
pub const SSL_AES256GCM: u32 = 0x0000_2000;
pub const SSL_AES128CCM: u32 = 0x0000_4000;
pub const SSL_AES256CCM: u32 = 0x0000_8000;
pub const SSL_AES128CCM8: u32 = 0x0001_0000;
pub const SSL_AES256CCM8: u32 = 0x0002_0000;
pub const SSL_eGOST2814789CNT12: u32 = 0x0004_0000;
pub const SSL_CHACHA20POLY1305: u32 = 0x0008_0000;
pub const SSL_ARIA128GCM: u32 = 0x0010_0000;
pub const SSL_ARIA256GCM: u32 = 0x0020_0000;
pub const SSL_MAGMA: u32 = 0x0040_0000;
pub const SSL_KUZNYECHIK: u32 = 0x0080_0000;
pub const SSL_AESGCM: u32 = SSL_AES128GCM | SSL_AES256GCM;
pub const SSL_AESCCM: u32 = SSL_AES128CCM | SSL_AES256CCM | SSL_AES128CCM8 | SSL_AES256CCM8;
pub const SSL_AES: u32 = SSL_AES128 | SSL_AES256 | SSL_AESGCM | SSL_AESCCM;
pub const SSL_CAMELLIA: u32 = SSL_CAMELLIA128 | SSL_CAMELLIA256;
pub const SSL_CHACHA20: u32 = SSL_CHACHA20POLY1305;
pub const SSL_ARIAGCM: u32 = SSL_ARIA128GCM | SSL_ARIA256GCM;
pub const SSL_ARIA: u32 = SSL_ARIAGCM;
pub const SSL_CBC: u32 = SSL_DES
    | SSL_3DES
    | SSL_RC2
    | SSL_IDEA
    | SSL_AES128
    | SSL_AES256
    | SSL_CAMELLIA128
    | SSL_CAMELLIA256
    | SSL_SEED;

// Symmetric authentication (`algorithm_mac`).
pub const SSL_MD5: u32 = 0x0000_0001;
pub const SSL_SHA1: u32 = 0x0000_0002;
pub const SSL_GOST94: u32 = 0x0000_0004;
pub const SSL_GOST89MAC: u32 = 0x0000_0008;
pub const SSL_SHA256: u32 = 0x0000_0010;
pub const SSL_SHA384: u32 = 0x0000_0020;
/// Not a MAC: the encryption is an AEAD.
pub const SSL_AEAD: u32 = 0x0000_0040;
pub const SSL_GOST12_256: u32 = 0x0000_0080;
pub const SSL_GOST89MAC12: u32 = 0x0000_0100;
pub const SSL_GOST12_512: u32 = 0x0000_0200;
pub const SSL_MAGMAOMAC: u32 = 0x0000_0400;
pub const SSL_KUZNYECHIKOMAC: u32 = 0x0000_0800;

// The digest indexes (`SSL_MD_*_IDX`), which `algorithm2` holds for the handshake and the PRF.
pub const SSL_MD_MD5_IDX: u32 = 0;
pub const SSL_MD_SHA1_IDX: u32 = 1;
pub const SSL_MD_GOST94_IDX: u32 = 2;
pub const SSL_MD_GOST89MAC_IDX: u32 = 3;
pub const SSL_MD_SHA256_IDX: u32 = 4;
pub const SSL_MD_SHA384_IDX: u32 = 5;
pub const SSL_MD_GOST12_256_IDX: u32 = 6;
pub const SSL_MD_GOST89MAC12_IDX: u32 = 7;
pub const SSL_MD_GOST12_512_IDX: u32 = 8;
pub const SSL_MD_MD5_SHA1_IDX: u32 = 9;
pub const SSL_MD_SHA224_IDX: u32 = 10;
pub const SSL_MD_SHA512_IDX: u32 = 11;
pub const SSL_MD_MAGMAOMAC_IDX: u32 = 12;
pub const SSL_MD_KUZNYECHIKOMAC_IDX: u32 = 13;
pub const SSL_MD_NUM_IDX: u32 = 14;

// `algorithm2`: bits 0-7 the handshake digest, 8-15 the PRF's, then flags.
pub const SSL_HANDSHAKE_MAC_MASK: u32 = 0xFF;
pub const SSL_HANDSHAKE_MAC_MD5_SHA1: u32 = SSL_MD_MD5_SHA1_IDX;
pub const SSL_HANDSHAKE_MAC_SHA256: u32 = SSL_MD_SHA256_IDX;
pub const SSL_HANDSHAKE_MAC_SHA384: u32 = SSL_MD_SHA384_IDX;
pub const SSL_HANDSHAKE_MAC_GOST94: u32 = SSL_MD_GOST94_IDX;
pub const SSL_HANDSHAKE_MAC_GOST12_256: u32 = SSL_MD_GOST12_256_IDX;
pub const SSL_HANDSHAKE_MAC_GOST12_512: u32 = SSL_MD_GOST12_512_IDX;
pub const SSL_HANDSHAKE_MAC_DEFAULT: u32 = SSL_HANDSHAKE_MAC_MD5_SHA1;
pub const TLS1_PRF_DGST_SHIFT: u32 = 8;
pub const TLS1_PRF_SHA1_MD5: u32 = SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT;
pub const TLS1_PRF_SHA256: u32 = SSL_MD_SHA256_IDX << TLS1_PRF_DGST_SHIFT;
pub const TLS1_PRF_SHA384: u32 = SSL_MD_SHA384_IDX << TLS1_PRF_DGST_SHIFT;
pub const TLS1_PRF_GOST94: u32 = SSL_MD_GOST94_IDX << TLS1_PRF_DGST_SHIFT;
pub const TLS1_PRF_GOST12_256: u32 = SSL_MD_GOST12_256_IDX << TLS1_PRF_DGST_SHIFT;
pub const TLS1_PRF_GOST12_512: u32 = SSL_MD_GOST12_512_IDX << TLS1_PRF_DGST_SHIFT;
pub const TLS1_PRF: u32 = SSL_MD_MD5_SHA1_IDX << TLS1_PRF_DGST_SHIFT;
/// GOST's stream MAC.
pub const TLS1_STREAM_MAC: u32 = 0x1_0000;
/// GOST's TLSTREE key derivation.
pub const TLS1_TLSTREE: u32 = 0x2_0000;
/// The suite may be used with QUIC.
pub const SSL_QUIC: u32 = 0x0004_0000;

// Strength classes (`algo_strength`).
pub const SSL_STRONG_MASK: u32 = 0x0000_001F;
pub const SSL_DEFAULT_MASK: u32 = 0x0000_0020;
pub const SSL_STRONG_NONE: u32 = 0x0000_0001;
pub const SSL_LOW: u32 = 0x0000_0002;
pub const SSL_MEDIUM: u32 = 0x0000_0004;
pub const SSL_HIGH: u32 = 0x0000_0008;
pub const SSL_FIPS: u32 = 0x0000_0010;
pub const SSL_NOT_DEFAULT: u32 = 0x0000_0020;
