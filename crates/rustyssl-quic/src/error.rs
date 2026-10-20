//! QUIC's transport errors (RFC 9000, section 20): the code a CONNECTION_CLOSE carries, the
//! frame type that caused it, and OpenSSL's reason text (`ossl_quic_channel_raise_protocol_error`).

use core::ffi::c_int;

/// A transport error code from `rustyssl_abi` (`OSSL_QUIC_ERR_*`) as the wire's integer.
#[must_use]
pub fn code(c: c_int) -> u64 {
    u64::from(c.unsigned_abs())
}

/// A connection error: what the endpoint sends in its CONNECTION_CLOSE (type 0x1c).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// The error code (`OSSL_QUIC_ERR_*`, or 0x100 plus a TLS alert for CRYPTO_ERROR).
    pub code: u64,
    /// The frame type that triggered it, or 0.
    pub frame_type: u64,
    /// OpenSSL's reason phrase, sent as the CONNECTION_CLOSE's reason.
    pub reason: &'static str,
}

impl Error {
    /// An error with `code` (an `OSSL_QUIC_ERR_*` constant), caused by `frame_type`.
    #[must_use]
    pub fn new(c: c_int, frame_type: u64, reason: &'static str) -> Self {
        Self {
            code: code(c),
            frame_type,
            reason,
        }
    }

    /// PROTOCOL_VIOLATION.
    #[must_use]
    pub fn protocol(frame_type: u64, reason: &'static str) -> Self {
        Self::new(rustyssl_abi::OSSL_QUIC_ERR_PROTOCOL_VIOLATION, frame_type, reason)
    }

    /// FRAME_ENCODING_ERROR for a frame that doesn't decode.
    #[must_use]
    pub fn frame_encoding(frame_type: u64) -> Self {
        Self::new(rustyssl_abi::OSSL_QUIC_ERR_FRAME_ENCODING_ERROR, frame_type, "decode error")
    }

    /// INTERNAL_ERROR.
    #[must_use]
    pub fn internal(reason: &'static str) -> Self {
        Self::new(rustyssl_abi::OSSL_QUIC_ERR_INTERNAL_ERROR, 0, reason)
    }

    /// TRANSPORT_PARAMETER_ERROR.
    #[must_use]
    pub fn transport_param(reason: &'static str) -> Self {
        Self::new(rustyssl_abi::OSSL_QUIC_ERR_TRANSPORT_PARAMETER_ERROR, 0, reason)
    }

    /// CRYPTO_ERROR carrying TLS alert `alert` (RFC 9001, section 4.8).
    #[must_use]
    pub fn crypto(alert: u8, reason: &'static str) -> Self {
        Self {
            code: code(rustyssl_abi::OSSL_QUIC_ERR_CRYPTO_ERR_BEGIN).saturating_add(u64::from(alert)),
            frame_type: 0,
            reason,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "QUIC error {:#x} (frame {:#x}): {}", self.code, self.frame_type, self.reason)
    }
}

/// A result whose error is a QUIC connection error.
pub type Result<T> = core::result::Result<T, Error>;
