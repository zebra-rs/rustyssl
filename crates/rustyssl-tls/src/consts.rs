//! Wire constants as the codec uses them.
//!
//! What OpenSSL's public headers define (extension types, message types, versions, the
//! `SSL_EXT_*` contexts) comes from `rustyssl_abi`, converted here to the widths the wire uses.
//! What only its internal headers define (signature schemes, groups, the HelloRetryRequest
//! random, the downgrade sentinels, GOST's `cryptopro_bug` extension) is written out here; those
//! are IANA and RFC values, not ABI.

use core::ffi::c_int;

use rustyssl_abi as abi;

/// A 16-bit wire value from a header's `c_int` constant (every such constant fits).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the arm matched 0..=0xffff"
)]
const fn w16(v: c_int) -> u16 {
    match v {
        0..=0xffff => v as u16,
        _ => 0,
    }
}

/// An 8-bit wire value from a header's `c_int` constant (every such constant fits).
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the arm matched 0..=0xff"
)]
const fn w8(v: c_int) -> u8 {
    match v {
        0..=0xff => v as u8,
        _ => 0,
    }
}

/// A context flag set (`SSL_EXT_*`) from its `c_int` constant.
#[expect(clippy::cast_sign_loss, reason = "the arm matched non-negative values")]
const fn ctx(v: c_int) -> u32 {
    match v {
        0.. => v as u32,
        _ => 0,
    }
}

/// Protocol versions.
pub mod version {
    use super::{abi, w16};

    /// SSL 3.0.
    pub const SSL3: u16 = w16(abi::SSL3_VERSION);
    /// TLS 1.0.
    pub const TLS1: u16 = w16(abi::TLS1_VERSION);
    /// TLS 1.1.
    pub const TLS1_1: u16 = w16(abi::TLS1_1_VERSION);
    /// TLS 1.2.
    pub const TLS1_2: u16 = w16(abi::TLS1_2_VERSION);
    /// TLS 1.3.
    pub const TLS1_3: u16 = w16(abi::TLS1_3_VERSION);
    /// DTLS 1.0.
    pub const DTLS1: u16 = w16(abi::DTLS1_VERSION);
    /// DTLS 1.2.
    pub const DTLS1_2: u16 = w16(abi::DTLS1_2_VERSION);
    /// OpenSSL's pre-standard DTLS ("DTLS1_BAD_VER").
    pub const DTLS1_BAD: u16 = w16(abi::DTLS1_BAD_VER);
}

/// Handshake message types.
pub mod handshake {
    use super::{abi, w8};

    /// HelloRequest.
    pub const HELLO_REQUEST: u8 = w8(abi::SSL3_MT_HELLO_REQUEST);
    /// ClientHello.
    pub const CLIENT_HELLO: u8 = w8(abi::SSL3_MT_CLIENT_HELLO);
    /// ServerHello (and HelloRetryRequest).
    pub const SERVER_HELLO: u8 = w8(abi::SSL3_MT_SERVER_HELLO);
    /// DTLS's HelloVerifyRequest.
    pub const HELLO_VERIFY_REQUEST: u8 = w8(abi::DTLS1_MT_HELLO_VERIFY_REQUEST);
    /// NewSessionTicket.
    pub const NEW_SESSION_TICKET: u8 = w8(abi::SSL3_MT_NEWSESSION_TICKET);
    /// EndOfEarlyData.
    pub const END_OF_EARLY_DATA: u8 = w8(abi::SSL3_MT_END_OF_EARLY_DATA);
    /// EncryptedExtensions.
    pub const ENCRYPTED_EXTENSIONS: u8 = w8(abi::SSL3_MT_ENCRYPTED_EXTENSIONS);
    /// Certificate.
    pub const CERTIFICATE: u8 = w8(abi::SSL3_MT_CERTIFICATE);
    /// ServerKeyExchange.
    pub const SERVER_KEY_EXCHANGE: u8 = w8(abi::SSL3_MT_SERVER_KEY_EXCHANGE);
    /// CertificateRequest.
    pub const CERTIFICATE_REQUEST: u8 = w8(abi::SSL3_MT_CERTIFICATE_REQUEST);
    /// ServerHelloDone.
    pub const SERVER_HELLO_DONE: u8 = w8(abi::SSL3_MT_SERVER_DONE);
    /// CertificateVerify.
    pub const CERTIFICATE_VERIFY: u8 = w8(abi::SSL3_MT_CERTIFICATE_VERIFY);
    /// ClientKeyExchange.
    pub const CLIENT_KEY_EXCHANGE: u8 = w8(abi::SSL3_MT_CLIENT_KEY_EXCHANGE);
    /// Finished.
    pub const FINISHED: u8 = w8(abi::SSL3_MT_FINISHED);
    /// CertificateURL (RFC 6066; OpenSSL neither sends nor accepts it).
    pub const CERTIFICATE_URL: u8 = w8(abi::SSL3_MT_CERTIFICATE_URL);
    /// CertificateStatus.
    pub const CERTIFICATE_STATUS: u8 = w8(abi::SSL3_MT_CERTIFICATE_STATUS);
    /// SupplementalData (RFC 4680; OpenSSL neither sends nor accepts it).
    pub const SUPPLEMENTAL_DATA: u8 = w8(abi::SSL3_MT_SUPPLEMENTAL_DATA);
    /// KeyUpdate.
    pub const KEY_UPDATE: u8 = w8(abi::SSL3_MT_KEY_UPDATE);
    /// CompressedCertificate (RFC 8879).
    pub const COMPRESSED_CERTIFICATE: u8 = w8(abi::SSL3_MT_COMPRESSED_CERTIFICATE);
    /// NextProtocol (the NPN draft).
    pub const NEXT_PROTO: u8 = w8(abi::SSL3_MT_NEXT_PROTO);
    /// The synthetic message_hash that replaces the first ClientHello after a
    /// HelloRetryRequest.
    pub const MESSAGE_HASH: u8 = w8(abi::SSL3_MT_MESSAGE_HASH);
}

/// Extension types.
pub mod ext {
    use super::{abi, w16};

    /// server_name (RFC 6066).
    pub const SERVER_NAME: u16 = w16(abi::TLSEXT_TYPE_server_name);
    /// max_fragment_length (RFC 6066).
    pub const MAX_FRAGMENT_LENGTH: u16 = w16(abi::TLSEXT_TYPE_max_fragment_length);
    /// status_request (RFC 6066).
    pub const STATUS_REQUEST: u16 = w16(abi::TLSEXT_TYPE_status_request);
    /// supported_groups (RFC 8422, RFC 7919).
    pub const SUPPORTED_GROUPS: u16 = w16(abi::TLSEXT_TYPE_supported_groups);
    /// ec_point_formats (RFC 8422).
    pub const EC_POINT_FORMATS: u16 = w16(abi::TLSEXT_TYPE_ec_point_formats);
    /// srp (RFC 5054).
    pub const SRP: u16 = w16(abi::TLSEXT_TYPE_srp);
    /// signature_algorithms.
    pub const SIGNATURE_ALGORITHMS: u16 = w16(abi::TLSEXT_TYPE_signature_algorithms);
    /// use_srtp (RFC 5764).
    pub const USE_SRTP: u16 = w16(abi::TLSEXT_TYPE_use_srtp);
    /// application_layer_protocol_negotiation (RFC 7301).
    pub const ALPN: u16 = w16(abi::TLSEXT_TYPE_application_layer_protocol_negotiation);
    /// signed_certificate_timestamp (RFC 6962).
    pub const SIGNED_CERTIFICATE_TIMESTAMP: u16 =
        w16(abi::TLSEXT_TYPE_signed_certificate_timestamp);
    /// client_certificate_type (RFC 7250).
    pub const CLIENT_CERT_TYPE: u16 = w16(abi::TLSEXT_TYPE_client_cert_type);
    /// server_certificate_type (RFC 7250).
    pub const SERVER_CERT_TYPE: u16 = w16(abi::TLSEXT_TYPE_server_cert_type);
    /// padding (RFC 7685).
    pub const PADDING: u16 = w16(abi::TLSEXT_TYPE_padding);
    /// encrypt_then_mac (RFC 7366).
    pub const ENCRYPT_THEN_MAC: u16 = w16(abi::TLSEXT_TYPE_encrypt_then_mac);
    /// extended_master_secret (RFC 7627).
    pub const EXTENDED_MASTER_SECRET: u16 = w16(abi::TLSEXT_TYPE_extended_master_secret);
    /// compress_certificate (RFC 8879).
    pub const COMPRESS_CERTIFICATE: u16 = w16(abi::TLSEXT_TYPE_compress_certificate);
    /// session_ticket (RFC 5077).
    pub const SESSION_TICKET: u16 = w16(abi::TLSEXT_TYPE_session_ticket);
    /// pre_shared_key.
    pub const PRE_SHARED_KEY: u16 = w16(abi::TLSEXT_TYPE_psk);
    /// early_data.
    pub const EARLY_DATA: u16 = w16(abi::TLSEXT_TYPE_early_data);
    /// supported_versions.
    pub const SUPPORTED_VERSIONS: u16 = w16(abi::TLSEXT_TYPE_supported_versions);
    /// cookie.
    pub const COOKIE: u16 = w16(abi::TLSEXT_TYPE_cookie);
    /// psk_key_exchange_modes.
    pub const PSK_KEY_EXCHANGE_MODES: u16 = w16(abi::TLSEXT_TYPE_psk_kex_modes);
    /// certificate_authorities.
    pub const CERTIFICATE_AUTHORITIES: u16 = w16(abi::TLSEXT_TYPE_certificate_authorities);
    /// post_handshake_auth.
    pub const POST_HANDSHAKE_AUTH: u16 = w16(abi::TLSEXT_TYPE_post_handshake_auth);
    /// signature_algorithms_cert.
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = w16(abi::TLSEXT_TYPE_signature_algorithms_cert);
    /// key_share.
    pub const KEY_SHARE: u16 = w16(abi::TLSEXT_TYPE_key_share);
    /// next_protocol_negotiation (the NPN draft).
    pub const NEXT_PROTO_NEG: u16 = w16(abi::TLSEXT_TYPE_next_proto_neg);
    /// renegotiation_info (RFC 5746).
    pub const RENEGOTIATE: u16 = w16(abi::TLSEXT_TYPE_renegotiate);
    /// The "cryptopro bug" extension GOST servers send (OpenSSL's `statem_local.h`).
    pub const CRYPTOPRO_BUG: u16 = 0xfde8;
}

/// The extension contexts (`SSL_EXT_*`).
pub mod context {
    use super::{abi, ctx};

    /// Valid in TLS only.
    pub const TLS_ONLY: u32 = ctx(abi::SSL_EXT_TLS_ONLY);
    /// Valid in DTLS only.
    pub const DTLS_ONLY: u32 = ctx(abi::SSL_EXT_DTLS_ONLY);
    /// Implemented only in TLS (DTLS ignores it).
    pub const TLS_IMPLEMENTATION_ONLY: u32 = ctx(abi::SSL_EXT_TLS_IMPLEMENTATION_ONLY);
    /// Valid in SSL 3.0.
    pub const SSL3_ALLOWED: u32 = ctx(abi::SSL_EXT_SSL3_ALLOWED);
    /// Valid in TLS 1.2 and below only.
    pub const TLS1_2_AND_BELOW_ONLY: u32 = ctx(abi::SSL_EXT_TLS1_2_AND_BELOW_ONLY);
    /// Valid in TLS 1.3 only.
    pub const TLS1_3_ONLY: u32 = ctx(abi::SSL_EXT_TLS1_3_ONLY);
    /// Ignored when resuming.
    pub const IGNORE_ON_RESUMPTION: u32 = ctx(abi::SSL_EXT_IGNORE_ON_RESUMPTION);
    /// In the ClientHello.
    pub const CLIENT_HELLO: u32 = ctx(abi::SSL_EXT_CLIENT_HELLO);
    /// In a TLS 1.2 ServerHello.
    pub const TLS1_2_SERVER_HELLO: u32 = ctx(abi::SSL_EXT_TLS1_2_SERVER_HELLO);
    /// In a TLS 1.3 ServerHello.
    pub const TLS1_3_SERVER_HELLO: u32 = ctx(abi::SSL_EXT_TLS1_3_SERVER_HELLO);
    /// In EncryptedExtensions.
    pub const TLS1_3_ENCRYPTED_EXTENSIONS: u32 = ctx(abi::SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS);
    /// In a HelloRetryRequest.
    pub const TLS1_3_HELLO_RETRY_REQUEST: u32 = ctx(abi::SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST);
    /// In a TLS 1.3 Certificate entry.
    pub const TLS1_3_CERTIFICATE: u32 = ctx(abi::SSL_EXT_TLS1_3_CERTIFICATE);
    /// In a TLS 1.3 NewSessionTicket.
    pub const TLS1_3_NEW_SESSION_TICKET: u32 = ctx(abi::SSL_EXT_TLS1_3_NEW_SESSION_TICKET);
    /// In a TLS 1.3 CertificateRequest.
    pub const TLS1_3_CERTIFICATE_REQUEST: u32 = ctx(abi::SSL_EXT_TLS1_3_CERTIFICATE_REQUEST);
    /// In a TLS 1.3 raw public key entry (RFC 7250).
    pub const TLS1_3_RAW_PUBLIC_KEY: u32 = ctx(abi::SSL_EXT_TLS1_3_RAW_PUBLIC_KEY);
}

/// Signature schemes (IANA; OpenSSL's `TLSEXT_SIGALG_*` in `ssl_local.h`).
pub mod sigscheme {
    /// ecdsa_secp256r1_sha256.
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    /// ecdsa_secp384r1_sha384.
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    /// ecdsa_secp521r1_sha512.
    pub const ECDSA_SECP521R1_SHA512: u16 = 0x0603;
    /// ecdsa_sha224 (TLS 1.2).
    pub const ECDSA_SHA224: u16 = 0x0303;
    /// ecdsa_sha1 (TLS 1.2).
    pub const ECDSA_SHA1: u16 = 0x0203;
    /// rsa_pss_rsae_sha256.
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    /// rsa_pss_rsae_sha384.
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    /// rsa_pss_rsae_sha512.
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    /// rsa_pss_pss_sha256.
    pub const RSA_PSS_PSS_SHA256: u16 = 0x0809;
    /// rsa_pss_pss_sha384.
    pub const RSA_PSS_PSS_SHA384: u16 = 0x080a;
    /// rsa_pss_pss_sha512.
    pub const RSA_PSS_PSS_SHA512: u16 = 0x080b;
    /// rsa_pkcs1_sha256.
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    /// rsa_pkcs1_sha384.
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    /// rsa_pkcs1_sha512.
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    /// rsa_pkcs1_sha224 (TLS 1.2).
    pub const RSA_PKCS1_SHA224: u16 = 0x0301;
    /// rsa_pkcs1_sha1 (TLS 1.2).
    pub const RSA_PKCS1_SHA1: u16 = 0x0201;
    /// dsa_sha256 (TLS 1.2).
    pub const DSA_SHA256: u16 = 0x0402;
    /// dsa_sha384 (TLS 1.2).
    pub const DSA_SHA384: u16 = 0x0502;
    /// dsa_sha512 (TLS 1.2).
    pub const DSA_SHA512: u16 = 0x0602;
    /// dsa_sha224 (TLS 1.2).
    pub const DSA_SHA224: u16 = 0x0302;
    /// dsa_sha1 (TLS 1.2).
    pub const DSA_SHA1: u16 = 0x0202;
    /// Not a code point: TLS 1.0 and 1.1's MD5+SHA-1 RSA signature (OpenSSL's
    /// `legacy_rsa_sigalg`, which has none), as the core passes it to the provider. TLS 1.0–1.1's
    /// ECDSA and DSA signatures use [`ECDSA_SHA1`] and [`DSA_SHA1`].
    pub const RSA_PKCS1_MD5_SHA1: u16 = 0xff01;
    /// gostr34102012_256 (intrinsic).
    pub const GOSTR34102012_256_INTRINSIC: u16 = 0x0840;
    /// gostr34102012_512 (intrinsic).
    pub const GOSTR34102012_512_INTRINSIC: u16 = 0x0841;
    /// GOST R 34.10-2012 (256) with GOST R 34.11-2012 (256), OpenSSL's private code point.
    pub const GOSTR34102012_256_GOSTR34112012_256: u16 = 0xeeee;
    /// GOST R 34.10-2012 (512) with GOST R 34.11-2012 (512), OpenSSL's private code point.
    pub const GOSTR34102012_512_GOSTR34112012_512: u16 = 0xefef;
    /// GOST R 34.10-2001 with GOST R 34.11-94, OpenSSL's private code point.
    pub const GOSTR34102001_GOSTR3411: u16 = 0xeded;
    /// ed25519.
    pub const ED25519: u16 = 0x0807;
    /// ed448.
    pub const ED448: u16 = 0x0808;
    /// ecdsa_brainpoolP256r1tls13_sha256.
    pub const ECDSA_BRAINPOOLP256R1_SHA256: u16 = 0x081a;
    /// ecdsa_brainpoolP384r1tls13_sha384.
    pub const ECDSA_BRAINPOOLP384R1_SHA384: u16 = 0x081b;
    /// ecdsa_brainpoolP512r1tls13_sha512.
    pub const ECDSA_BRAINPOOLP512R1_SHA512: u16 = 0x081c;
    /// mldsa44.
    pub const MLDSA44: u16 = 0x0904;
    /// mldsa65.
    pub const MLDSA65: u16 = 0x0905;
    /// mldsa87.
    pub const MLDSA87: u16 = 0x0906;
}

/// Named groups (IANA; OpenSSL's `OSSL_TLS_GROUP_ID_*` in `tlsgroups.h`).
#[allow(
    missing_docs,
    reason = "each constant is the IANA group of the same name"
)]
pub mod group {
    pub const SECT163K1: u16 = 0x0001;
    pub const SECT163R1: u16 = 0x0002;
    pub const SECT163R2: u16 = 0x0003;
    pub const SECT193R1: u16 = 0x0004;
    pub const SECT193R2: u16 = 0x0005;
    pub const SECT233K1: u16 = 0x0006;
    pub const SECT233R1: u16 = 0x0007;
    pub const SECT239K1: u16 = 0x0008;
    pub const SECT283K1: u16 = 0x0009;
    pub const SECT283R1: u16 = 0x000a;
    pub const SECT409K1: u16 = 0x000b;
    pub const SECT409R1: u16 = 0x000c;
    pub const SECT571K1: u16 = 0x000d;
    pub const SECT571R1: u16 = 0x000e;
    pub const SECP160K1: u16 = 0x000f;
    pub const SECP160R1: u16 = 0x0010;
    pub const SECP160R2: u16 = 0x0011;
    pub const SECP192K1: u16 = 0x0012;
    pub const SECP192R1: u16 = 0x0013;
    pub const SECP224K1: u16 = 0x0014;
    pub const SECP224R1: u16 = 0x0015;
    pub const SECP256K1: u16 = 0x0016;
    pub const SECP256R1: u16 = 0x0017;
    pub const SECP384R1: u16 = 0x0018;
    pub const SECP521R1: u16 = 0x0019;
    pub const BRAINPOOLP256R1: u16 = 0x001a;
    pub const BRAINPOOLP384R1: u16 = 0x001b;
    pub const BRAINPOOLP512R1: u16 = 0x001c;
    pub const X25519: u16 = 0x001d;
    pub const X448: u16 = 0x001e;
    pub const BRAINPOOLP256R1_TLS13: u16 = 0x001f;
    pub const BRAINPOOLP384R1_TLS13: u16 = 0x0020;
    pub const BRAINPOOLP512R1_TLS13: u16 = 0x0021;
    pub const GC256A: u16 = 0x0022;
    pub const GC256B: u16 = 0x0023;
    pub const GC256C: u16 = 0x0024;
    pub const GC256D: u16 = 0x0025;
    pub const GC512A: u16 = 0x0026;
    pub const GC512B: u16 = 0x0027;
    pub const GC512C: u16 = 0x0028;
    pub const FFDHE2048: u16 = 0x0100;
    pub const FFDHE3072: u16 = 0x0101;
    pub const FFDHE4096: u16 = 0x0102;
    pub const FFDHE6144: u16 = 0x0103;
    pub const FFDHE8192: u16 = 0x0104;
    pub const MLKEM512: u16 = 0x0200;
    pub const MLKEM768: u16 = 0x0201;
    pub const MLKEM1024: u16 = 0x0202;
    pub const SECP256R1_MLKEM768: u16 = 0x11eb;
    pub const X25519_MLKEM768: u16 = 0x11ec;
    pub const SECP384R1_MLKEM1024: u16 = 0x11ed;
}

/// psk_key_exchange_modes values (RFC 8446, section 4.2.9).
pub mod psk_mode {
    /// psk_ke.
    pub const KE: u8 = 0;
    /// psk_dhe_ke.
    pub const KE_DHE: u8 = 1;
}

/// The random a HelloRetryRequest carries: SHA-256 of "HelloRetryRequest" (RFC 8446, section
/// 4.1.3).
pub const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The last 8 octets of a TLS 1.3 server's random when it negotiates TLS 1.1 or below (RFC
/// 8446, section 4.1.3).
pub const TLS11_DOWNGRADE: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00];

/// The last 8 octets of a TLS 1.3 server's random when it negotiates TLS 1.2.
pub const TLS12_DOWNGRADE: [u8; 8] = [0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01];

/// The length of a hello's random.
pub const RANDOM_LEN: usize = 32;

/// The longest session ID.
pub const MAX_SESSION_ID_LEN: usize = 32;

/// The longest DTLS cookie (`DTLS1_COOKIE_LENGTH`).
pub const MAX_DTLS_COOKIE_LEN: usize = 255;

/// The longest host name OpenSSL accepts in server_name (`TLSEXT_MAXLEN_host_name`).
pub const MAX_HOST_NAME_LEN: usize = 255;

/// The longest PSK identity (`PSK_MAX_IDENTITY_LEN`).
pub const MAX_PSK_IDENTITY_LEN: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_constants_convert_exactly() {
        assert_eq!(c_int::from(ext::KEY_SHARE), abi::TLSEXT_TYPE_key_share);
        assert_eq!(
            c_int::from(ext::ALPN),
            abi::TLSEXT_TYPE_application_layer_protocol_negotiation
        );
        assert_eq!(
            c_int::from(handshake::MESSAGE_HASH),
            abi::SSL3_MT_MESSAGE_HASH
        );
        assert_eq!(c_int::from(version::DTLS1_2), abi::DTLS1_2_VERSION);
        assert_eq!(
            i64::from(context::CLIENT_HELLO),
            i64::from(abi::SSL_EXT_CLIENT_HELLO)
        );
        assert_eq!(w16(0x1_0000), 0);
        assert_eq!(w8(256), 0);
    }
}
