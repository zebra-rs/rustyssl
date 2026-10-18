//! Why a connection failed, in OpenSSL's terms: the alert sent to the peer (if any) and the
//! `SSL_R_*` reason libssl records. `rustyssl-capi` turns an [`Error`] into the ERR entry and
//! `SSL_get_error` result in one place.

use core::ffi::c_int;

use crate::codec::DecodeError;

/// An alert's description (`SSL_AD_*`, the second octet of an alert).
pub type AlertDescription = u8;

/// A failure: the fatal alert to send (`None` when nothing is sent, as for an internal error
/// OpenSSL doesn't report to the peer, or after the connection is gone), and OpenSSL's reason.
/// Two errors are equal when they are the same failure (alert, reason, and data), wherever
/// they were raised.
#[derive(Clone, Copy, Debug)]
pub struct Error {
    /// The alert sent, or `None`.
    pub alert: Option<AlertDescription>,
    /// The `SSL_R_*` reason (`rustyssl_abi`'s constants), or an `ERR_R_*` one with
    /// [`Error::library_reason`] set.
    pub reason: c_int,
    /// Whether `reason` is a common `ERR_R_*` reason rather than an `SSL_R_*` one.
    pub library_reason: bool,
    /// The error's data string (`ERR_raise_data`'s text), if OpenSSL adds one.
    pub data: Option<&'static str>,
    /// The OpenSSL function that raises this error (`ERR_set_debug`'s function, which
    /// `ERR_print_errors` prints and `ERR_get_error_all` returns): `None` until a caller names
    /// it ([`Error::in_func`]); `Some("")` for an error OpenSSL raises with no function (the
    /// record layer's).
    pub func: Option<&'static str>,
    /// A second entry OpenSSL raises after this one, with no function: a record-layer failure
    /// that sends an alert is followed by `SSL_R_RECORD_LAYER_FAILURE`
    /// (`ossl_tls_handle_rlayer_return`).
    pub follow_up: Option<c_int>,
    /// An entry another library raises before this one (the provider's, under a failed
    /// decryption).
    pub cause: Option<Cause>,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.alert == other.alert
            && self.reason == other.reason
            && self.library_reason == other.library_reason
            && self.data == other.data
    }
}

impl Eq for Error {}

/// An ERR entry outside libssl that comes before an [`Error`]'s own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cause {
    /// The library (`ERR_LIB_*`).
    pub lib: c_int,
    /// Its reason.
    pub reason: c_int,
    /// The function that raises it.
    pub func: &'static str,
}

impl Error {
    /// A fatal alert `alert` with the reason `reason` (`SSL_R_*`).
    #[must_use]
    pub const fn alert(alert: c_int, reason: c_int) -> Self {
        Self {
            alert: Some(alert_octet(alert)),
            reason,
            library_reason: false,
            data: None,
            func: None,
            follow_up: None,
            cause: None,
        }
    }

    /// A fatal alert `alert` with a common reason `reason` (`ERR_R_*`), as OpenSSL gives for
    /// some decoding failures (`ERR_R_ASN1_LIB`, `ERR_R_INTERNAL_ERROR`).
    #[must_use]
    pub const fn alert_lib(alert: c_int, reason: c_int) -> Self {
        Self {
            alert: Some(alert_octet(alert)),
            reason,
            library_reason: true,
            data: None,
            func: None,
            follow_up: None,
            cause: None,
        }
    }

    /// A failure that sends no alert, with the reason `reason` (`SSL_R_*`).
    #[must_use]
    pub const fn quiet(reason: c_int) -> Self {
        Self {
            alert: None,
            reason,
            library_reason: false,
            data: None,
            func: None,
            follow_up: None,
            cause: None,
        }
    }

    /// The same error, after `cause`'s entry.
    #[must_use]
    pub const fn caused_by(mut self, cause: Cause) -> Self {
        self.cause = Some(cause);
        self
    }

    /// The same error, raised by OpenSSL's function `func` unless an inner function already
    /// named itself (as an inner `SSLfatal` does in OpenSSL).
    #[must_use]
    pub const fn in_func(mut self, func: &'static str) -> Self {
        if self.func.is_none() {
            self.func = Some(func);
        }
        self
    }

    /// The same error with OpenSSL's data string.
    #[must_use]
    pub const fn with_data(mut self, data: &'static str) -> Self {
        self.data = Some(data);
        self
    }

    /// An internal error (OpenSSL's `SSL_AD_INTERNAL_ERROR` with `ERR_R_INTERNAL_ERROR`).
    #[must_use]
    pub const fn internal() -> Self {
        Self {
            alert: Some(alert_octet(rustyssl_abi::SSL_AD_INTERNAL_ERROR)),
            reason: rustyssl_abi::ERR_R_INTERNAL_ERROR,
            library_reason: true,
            data: None,
            func: None,
            follow_up: None,
            cause: None,
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

/// Names the OpenSSL function that raised a result's error, unless an inner one already did.
pub trait InFunc {
    /// The result, its error raised by `func` unless already named ([`Error::in_func`]).
    #[must_use]
    fn in_func(self, func: &'static str) -> Self;
}

impl<T> InFunc for Result<T> {
    fn in_func(self, func: &'static str) -> Self {
        self.map_err(|e| e.in_func(func))
    }
}
