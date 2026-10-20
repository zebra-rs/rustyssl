//! Time as the caller supplies it: a monotonic count of nanoseconds (OpenSSL's `OSSL_TIME`).
//! The crate never reads a clock.

/// A point in time, in nanoseconds from an arbitrary origin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Time(pub u64);

/// A span of time, in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(pub u64);

impl Duration {
    /// No time.
    pub const ZERO: Self = Self(0);
    /// Forever (OpenSSL's `ossl_time_infinite`).
    pub const INFINITE: Self = Self(u64::MAX);

    /// `ms` milliseconds.
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        Self(ms.saturating_mul(1_000_000))
    }

    /// `us` microseconds.
    #[must_use]
    pub const fn from_micros(us: u64) -> Self {
        Self(us.saturating_mul(1_000))
    }

    /// Whole microseconds.
    #[must_use]
    pub const fn as_micros(self) -> u64 {
        self.0 / 1_000
    }

    /// Whole milliseconds.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    /// The sum, saturating at forever.
    #[must_use]
    pub const fn add(self, o: Self) -> Self {
        Self(self.0.saturating_add(o.0))
    }

    /// The difference, saturating at zero.
    #[must_use]
    pub const fn sub(self, o: Self) -> Self {
        Self(self.0.saturating_sub(o.0))
    }

    /// `self * n`, saturating.
    #[must_use]
    pub const fn mul(self, n: u64) -> Self {
        Self(self.0.saturating_mul(n))
    }

    /// `self / n` (`n` 0 gives forever).
    #[must_use]
    pub const fn div(self, n: u64) -> Self {
        match self.0.checked_div(n) {
            Some(v) => Self(v),
            None => Self::INFINITE,
        }
    }
}

impl Time {
    /// The earliest time.
    pub const ZERO: Self = Self(0);
    /// Never.
    pub const INFINITE: Self = Self(u64::MAX);

    /// `self + d`, saturating at never.
    #[must_use]
    pub const fn add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.0))
    }

    /// `self - d`, saturating at zero.
    #[must_use]
    pub const fn sub(self, d: Duration) -> Self {
        Self(self.0.saturating_sub(d.0))
    }

    /// The time from `earlier` to `self` (zero if `earlier` is later).
    #[must_use]
    pub const fn since(self, earlier: Self) -> Duration {
        Duration(self.0.saturating_sub(earlier.0))
    }

    /// Whether this is never.
    #[must_use]
    pub const fn is_infinite(self) -> bool {
        self.0 == u64::MAX
    }
}

/// The earlier of two optional deadlines.
#[must_use]
pub fn earliest(a: Option<Time>, b: Option<Time>) -> Option<Time> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}
