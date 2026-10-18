//! The security framework (`ssl_security`, `ssl_security_default_callback` in `ssl_cert.c`):
//! every cipher, version, group, and signature algorithm a handshake considers is checked
//! against the security level, or against the application's callback.
//!
//! The application's callback (`SSL_CTX_set_security_callback`) answers synchronously in
//! OpenSSL, from deep inside cipher and group filtering loops that can't be suspended. It is
//! therefore the one callback the core calls in place: `rustyssl-capi` installs a
//! [`SecurityHook`] that runs the C callback. The hook gets the arguments only, and capi makes
//! the call without holding a lock the callback could need: the callback receives the `SSL`,
//! whose other state (ex_data, options) lives outside the core.

use core::ffi::c_int;

use rustyssl_abi as abi;

use crate::conn::Connection;
use crate::suites::Cipher;
use crate::suites::masks::{
    SSL_MD5, SSL_SHA1, SSL_aNULL, SSL_kDHE, SSL_kDHEPSK, SSL_kECDHE, SSL_kECDHEPSK,
};

/// What a security check is about (the callback's `other`).
#[derive(Clone, Copy, Debug)]
pub enum SecOther<'a> {
    /// Nothing (`NULL`).
    None,
    /// A cipher (`SSL_CIPHER *`).
    Cipher(&'a Cipher),
    /// A group or signature algorithm's code point, as two octets (OpenSSL passes a
    /// `unsigned char[2]` "for historical reasons").
    CodePoint([u8; 2]),
}

/// The application's security callback, as capi wraps it: `(op, bits, nid, other)` to
/// allowed or not.
pub type SecurityHook =
    std::sync::Arc<dyn Fn(c_int, c_int, c_int, SecOther<'_>) -> bool + Send + Sync>;

/// The minimum security bits of each level (`ssl_get_security_level_bits`'s `minbits_table`).
const MINBITS: [c_int; 6] = [0, 80, 112, 128, 192, 256];

/// A level clamped to 0..=5, and its minimum bits.
#[must_use]
pub fn level_bits(level: i32) -> (i32, c_int) {
    let l = level.clamp(0, 5);
    let bits = usize::try_from(l)
        .ok()
        .and_then(|i| MINBITS.get(i).copied())
        .unwrap_or(0);
    (l, bits)
}

/// `ssl_security_default_callback` at `level`.
#[must_use]
pub fn default_policy(level: i32, op: c_int, bits: c_int, nid: c_int, other: SecOther<'_>) -> bool {
    let (level, minbits) = level_bits(level);
    if level == 0 {
        // No EDH keys weaker than 1024 bits even at level 0.
        return !(op == abi::SSL_SECOP_TMP_DH && bits < 80);
    }
    match op {
        abi::SSL_SECOP_CIPHER_SUPPORTED
        | abi::SSL_SECOP_CIPHER_SHARED
        | abi::SSL_SECOP_CIPHER_CHECK => {
            if bits < minbits {
                return false;
            }
            if let SecOther::Cipher(c) = other {
                if c.auth & SSL_aNULL != 0 || c.mac & SSL_MD5 != 0 {
                    return false;
                }
                if minbits > 160 && c.mac & SSL_SHA1 != 0 {
                    return false;
                }
                let pfs = SSL_kDHE | SSL_kECDHE | SSL_kDHEPSK | SSL_kECDHEPSK;
                if level >= 3 && c.min_tls != abi::TLS1_3_VERSION && c.mkey & pfs == 0 {
                    return false;
                }
            }
            true
        }
        // SSLv3 to TLS 1.1, and DTLS 1.0, only at level 0.
        abi::SSL_SECOP_VERSION => {
            let v = u16::try_from(nid).unwrap_or(0);
            if super::version::is_dtls(v) {
                !(super::version::cmp(v, crate::consts::version::DTLS1_2).is_lt() && level > 0)
            } else {
                !(nid <= abi::TLS1_1_VERSION && level > 0)
            }
        }
        abi::SSL_SECOP_COMPRESSION => level < 2,
        abi::SSL_SECOP_TICKET => level < 3,
        _ => bits >= minbits,
    }
}

/// `ssl_security`: the check by the application's callback if it set one, otherwise by the
/// default policy at the connection's level.
#[must_use]
pub fn check(c: &Connection, op: c_int, bits: c_int, nid: c_int, other: SecOther<'_>) -> bool {
    if c.cfg.custom_security_callback
        && let Some(h) = &c.security_hook
    {
        return h(op, bits, nid, other);
    }
    default_policy(c.cfg.security_level, op, bits, nid, other)
}

/// `tls_use_ticket`: tickets are on unless `SSL_OP_NO_TICKET` or the security level forbids
/// them.
#[must_use]
pub fn use_ticket(c: &Connection) -> bool {
    c.cfg.options & abi::SSL_OP_NO_TICKET == 0
        && check(c, abi::SSL_SECOP_TICKET, 0, 0, SecOther::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suites;

    #[test]
    fn the_default_policy_matches_openssls_levels() {
        assert_eq!(level_bits(-3), (0, 0));
        assert_eq!(level_bits(9), (5, 256));
        // Versions below TLS 1.2 only at level 0.
        assert!(default_policy(
            0,
            abi::SSL_SECOP_VERSION,
            0,
            abi::TLS1_VERSION,
            SecOther::None
        ));
        assert!(!default_policy(
            1,
            abi::SSL_SECOP_VERSION,
            0,
            abi::TLS1_1_VERSION,
            SecOther::None
        ));
        assert!(default_policy(
            1,
            abi::SSL_SECOP_VERSION,
            0,
            abi::TLS1_2_VERSION,
            SecOther::None
        ));
        // Weak DH even at level 0.
        assert!(!default_policy(
            0,
            abi::SSL_SECOP_TMP_DH,
            79,
            0,
            SecOther::None
        ));
        // Tickets stop at level 3, compression at 2.
        assert!(default_policy(
            2,
            abi::SSL_SECOP_TICKET,
            0,
            0,
            SecOther::None
        ));
        assert!(!default_policy(
            3,
            abi::SSL_SECOP_TICKET,
            0,
            0,
            SecOther::None
        ));
        assert!(!default_policy(
            2,
            abi::SSL_SECOP_COMPRESSION,
            0,
            0,
            SecOther::None
        ));
        // Ciphers: unauthenticated never, RSA key exchange not at level 3.
        let anon = suites::by_name("ADH-AES128-SHA").unwrap();
        assert!(!default_policy(
            1,
            abi::SSL_SECOP_CIPHER_SUPPORTED,
            128,
            0,
            SecOther::Cipher(anon)
        ));
        let rsa = suites::by_name("AES128-GCM-SHA256").unwrap();
        assert!(default_policy(
            2,
            abi::SSL_SECOP_CIPHER_SUPPORTED,
            128,
            0,
            SecOther::Cipher(rsa)
        ));
        assert!(!default_policy(
            3,
            abi::SSL_SECOP_CIPHER_SUPPORTED,
            128,
            0,
            SecOther::Cipher(rsa)
        ));
        let t13 = suites::by_name("TLS_AES_128_GCM_SHA256").unwrap();
        assert!(default_policy(
            3,
            abi::SSL_SECOP_CIPHER_SUPPORTED,
            128,
            0,
            SecOther::Cipher(t13)
        ));
        // SHA-1 MACs stop above 160 bits.
        let sha1 = suites::by_name("ECDHE-RSA-AES256-SHA").unwrap();
        assert!(default_policy(
            3,
            abi::SSL_SECOP_CIPHER_SUPPORTED,
            256,
            0,
            SecOther::Cipher(sha1)
        ));
        assert!(!default_policy(
            4,
            abi::SSL_SECOP_CIPHER_SUPPORTED,
            256,
            0,
            SecOther::Cipher(sha1)
        ));
        // Groups and sigalgs by bits.
        assert!(!default_policy(
            2,
            abi::SSL_SECOP_CURVE_SUPPORTED,
            80,
            0,
            SecOther::None
        ));
        assert!(default_policy(
            2,
            abi::SSL_SECOP_CURVE_SUPPORTED,
            112,
            0,
            SecOther::None
        ));
    }
}
