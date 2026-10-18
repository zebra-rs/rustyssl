//! Why a connection failed, in OpenSSL's terms: the alert sent to the peer (if any) and the
//! `SSL_R_*` reason libssl records. `rustyssl-capi` turns an [`Error`] into the ERR entry and
//! `SSL_get_error` result in one place.

use core::ffi::c_int;

use crate::codec::DecodeError;

/// An alert's description (`SSL_AD_*`, the second octet of an alert).
pub type AlertDescription = u8;

/// A failure: the fatal alert to send (`None` when nothing is sent, as for an internal error
/// OpenSSL doesn't report to the peer, or after the connection is gone), and OpenSSL's reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    /// The alert sent, or `None`.
    pub alert: Option<AlertDescription>,
    /// The `SSL_R_*` reason (`rustyssl_abi`'s constants), or an `ERR_R_*` one with
    /// [`Error::library_reason`] set.
    pub reason: c_int,
    /// Whether `reason` is a common `ERR_R_*` reason rather than an `SSL_R_*` one.
    pub library_reason: bool,
}

impl Error {
    /// A fatal alert `alert` with the reason `reason` (`SSL_R_*`).
    #[must_use]
    pub const fn alert(alert: c_int, reason: c_int) -> Self {
        Self { alert: Some(alert_octet(alert)), reason, library_reason: false }
    }

    /// A failure that sends no alert, with the reason `reason` (`SSL_R_*`).
    #[must_use]
    pub const fn quiet(reason: c_int) -> Self {
        Self { alert: None, reason, library_reason: false }
    }

    /// An internal error (OpenSSL's `SSL_AD_INTERNAL_ERROR` with `ERR_R_INTERNAL_ERROR`).
    #[must_use]
    pub const fn internal() -> Self {
        Self {
            alert: Some(alert_octet(rustyssl_abi::SSL_AD_INTERNAL_ERROR)),
            reason: rustyssl_abi::ERR_R_INTERNAL_ERROR,
            library_reason: true,
        }
    }

    /// A message that doesn't decode (`SSL_AD_DECODE_ERROR`, `SSL_R_BAD_PACKET`... the caller
    /// names the reason OpenSSL gives for that message).
    #[must_use]
    pub const fn decode(reason: c_int) -> Self {
        Self::alert(rustyssl_abi::SSL_AD_DECODE_ERROR, reason)
    }
}

/// An alert description from its `c_int` constant: they are all below 256.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the arm matched 0..=255"
)]
const fn alert_octet(v: c_int) -> AlertDescription {
    match v {
        0..=255 => v as AlertDescription,
        _ => 80, // SSL_AD_INTERNAL_ERROR; no constant is out of range
    }
}

impl From<DecodeError> for Error {
    /// A decoding failure where the caller has no more specific reason: OpenSSL's
    /// `SSL_R_LENGTH_MISMATCH` with a decode-error alert.
    fn from(_: DecodeError) -> Self {
        Self::decode(rustyssl_abi::SSL_R_LENGTH_MISMATCH)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.alert {
            Some(a) => write!(f, "TLS failure (reason {}, alert {a})", self.reason),
            None => write!(f, "TLS failure (reason {})", self.reason),
        }
    }
}

/// A result with the core's [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
