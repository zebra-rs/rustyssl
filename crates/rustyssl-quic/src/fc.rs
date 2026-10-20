//! Flow control (RFC 9000, section 4), as OpenSSL's `quic_fc.c` does it: a sending side that
//! tracks the peer's credit (stream and connection), and a receiving side that grows its window
//! by auto-tuning: when the window would be used up in under four RTTs it doubles, up to a
//! maximum, and a new limit is advertised once three quarters of it has been consumed.
//!
//! Stream controllers have the connection's as a parent, passed in by the caller so neither
//! owns the other. The stream-count limits (MAX_STREAMS) use a standalone receiving controller.

use crate::error::{Error, Result};
use crate::time::{Duration, Time};

/// Credit the peer granted us (its MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TxFc {
    /// Sent watermark: the octets consumed.
    swm: u64,
    /// Credit watermark: the peer's limit.
    cwm: u64,
    has_become_blocked: bool,
}

impl TxFc {
    /// A controller with the peer's initial limit.
    #[must_use]
    pub fn new(cwm: u64) -> Self {
        Self {
            swm: 0,
            cwm,
            has_become_blocked: false,
        }
    }

    /// Raises the limit; a lower one is ignored (returns false).
    pub fn bump_cwm(&mut self, cwm: u64) -> bool {
        if cwm <= self.cwm {
            return false;
        }
        self.cwm = cwm;
        true
    }

    /// The credit left of this controller alone.
    #[must_use]
    pub fn credit_local(&self) -> u64 {
        self.cwm.saturating_sub(self.swm)
    }

    /// The credit left of this controller and its parent: the parent's is reduced by
    /// `consumed`, octets the caller is about to consume from it elsewhere.
    #[must_use]
    pub fn credit(&self, parent: Option<&Self>, consumed: u64) -> u64 {
        let r = self.credit_local();
        parent.map_or(r, |p| r.min(p.credit_local().saturating_sub(consumed)))
    }

    /// Consumes `n` octets of credit; consuming more than there is takes what there is and
    /// fails.
    pub fn consume_local(&mut self, n: u64) -> bool {
        let credit = self.credit_local();
        let take = n.min(credit);
        if take > 0 && take == credit {
            self.has_become_blocked = true;
        }
        self.swm = self.swm.saturating_add(take);
        n <= credit
    }

    /// Consumes from this controller and its parent.
    pub fn consume(&mut self, parent: Option<&mut Self>, n: u64) -> bool {
        let ok = self.consume_local(n);
        match parent {
            Some(p) => p.consume_local(n) && ok,
            None => ok,
        }
    }

    /// Whether the credit ran out since the last call with `clear` (to send *_BLOCKED).
    pub fn has_become_blocked(&mut self, clear: bool) -> bool {
        let r = self.has_become_blocked;
        if clear {
            self.has_become_blocked = false;
        }
        r
    }

    /// The peer's limit.
    #[must_use]
    pub fn cwm(&self) -> u64 {
        self.cwm
    }

    /// The octets consumed.
    #[must_use]
    pub fn swm(&self) -> u64 {
        self.swm
    }
}

/// A receiving controller: what we allow the peer to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxFc {
    /// Received watermark (octets counted against the limit).
    swm: u64,
    /// Credit watermark (the limit advertised).
    cwm: u64,
    /// Retired watermark (octets the application consumed).
    rwm: u64,
    /// The retired watermark when the epoch started.
    esrwm: u64,
    /// The highest offset seen.
    hwm: u64,
    cur_window: u64,
    max_window: u64,
    epoch_start: Option<Time>,
    has_cwm_changed: bool,
    is_fin: bool,
    error: Option<u64>,
}

const WINDOW_THRESHOLD_NUM: u64 = 3;
const WINDOW_THRESHOLD_DEN: u64 = 4;

impl RxFc {
    /// A controller with an initial window that may grow to `max_window`.
    #[must_use]
    pub fn new(initial_window: u64, max_window: u64) -> Self {
        Self {
            swm: 0,
            cwm: initial_window,
            rwm: 0,
            esrwm: 0,
            hwm: 0,
            cur_window: initial_window,
            max_window,
            epoch_start: None,
            has_cwm_changed: false,
            is_fin: false,
            error: None,
        }
    }

    /// A standalone controller (stream counts): its window never grows.
    #[must_use]
    pub fn standalone(initial_window: u64) -> Self {
        Self::new(initial_window, initial_window)
    }

    fn on_rx_controlled(&mut self, n: u64) {
        let credit = self.cwm.saturating_sub(self.swm);
        let n = if n > credit {
            self.error = Some(crate::error::code(
                rustyssl_abi::OSSL_QUIC_ERR_FLOW_CONTROL_ERROR,
            ));
            credit
        } else {
            n
        };
        self.swm = self.swm.saturating_add(n);
    }

    /// Data ending at `end` (with FIN if `fin`) arrived on a stream controlled by `self`, whose
    /// connection controller is `parent`. Errors (FLOW_CONTROL_ERROR, FINAL_SIZE_ERROR) are
    /// raised as OpenSSL does, through [`RxFc::error`].
    pub fn on_rx_stream_frame(&mut self, parent: Option<&mut Self>, end: u64, fin: bool) {
        let final_size_err = crate::error::code(rustyssl_abi::OSSL_QUIC_ERR_FINAL_SIZE_ERROR);
        if self.is_fin && ((fin && self.hwm != end) || end > self.hwm) {
            self.error = Some(final_size_err);
            return;
        }
        if fin {
            self.is_fin = true;
        }
        if end > self.hwm {
            let delta = end.saturating_sub(self.hwm);
            self.hwm = end;
            self.on_rx_controlled(delta);
            if let Some(p) = parent {
                p.on_rx_controlled(delta);
            }
        } else if end < self.hwm && fin {
            self.error = Some(final_size_err);
        }
    }

    /// Counts `n` items against a standalone controller (stream counts), as data.
    pub fn on_rx_count(&mut self, end: u64) {
        if end > self.hwm {
            let delta = end.saturating_sub(self.hwm);
            self.hwm = end;
            self.on_rx_controlled(delta);
        }
    }

    fn start_epoch(&mut self, now: Time) {
        self.epoch_start = Some(now);
        self.esrwm = self.rwm;
    }

    fn bump_desired(&self) -> bool {
        let rem = self.cwm.saturating_sub(self.rwm);
        let threshold = self
            .cur_window
            .checked_mul(WINDOW_THRESHOLD_NUM)
            .map_or(self.cur_window / 2, |v| v / WINDOW_THRESHOLD_DEN);
        !self.is_fin && rem <= threshold
    }

    fn should_grow(&self, now: Time, rtt: Duration) -> bool {
        let b = self.rwm.saturating_sub(self.esrwm);
        if b == 0 {
            return false;
        }
        let dt = now.since(self.epoch_start.unwrap_or(now));
        // T_window = dt × window / b; grow if it's under 4 RTT.
        let t_window = u128::from(dt.0)
            .saturating_mul(u128::from(self.cur_window))
            .checked_div(u128::from(b))
            .unwrap_or(u128::MAX);
        t_window < u128::from(rtt.mul(4).0)
    }

    fn retire(&mut self, n: u64, min_window: u64, now: Time, rtt: Duration) {
        if self.epoch_start.is_none() {
            self.start_epoch(now);
        }
        self.rwm = self.rwm.saturating_add(n);
        if !self.bump_desired() {
            return;
        }
        let mut w = self.cur_window;
        if self.should_grow(now, rtt) {
            w = w.saturating_mul(2);
        }
        w = w.max(min_window).min(self.max_window);
        self.cur_window = w;
        self.start_epoch(now);
        let new_cwm = self.rwm.saturating_add(w);
        if new_cwm > self.cwm {
            self.cwm = new_cwm;
            self.has_cwm_changed = true;
        }
    }

    /// The application consumed `n` octets: the window may move (and grow). The connection
    /// controller `parent` moves too, kept at least as wide as the stream's window.
    ///
    /// # Errors
    /// More is retired than was received.
    pub fn on_retire(
        &mut self,
        parent: Option<&mut Self>,
        n: u64,
        now: Time,
        rtt: Duration,
    ) -> Result<()> {
        if n == 0 {
            return Ok(());
        }
        if self.rwm.saturating_add(n) > self.swm {
            return Err(Error::internal("retired more than received"));
        }
        self.retire(n, 0, now, rtt);
        if let Some(p) = parent {
            let w = self.cur_window;
            p.retire(n, w, now, rtt);
        }
        Ok(())
    }

    /// Retires stream-count credit (a standalone controller): streams closed.
    pub fn retire_count(&mut self, n: u64, now: Time) {
        if n == 0 || self.rwm.saturating_add(n) > self.swm {
            return;
        }
        self.retire(n, 0, now, Duration::ZERO);
    }

    /// The limit advertised.
    #[must_use]
    pub fn cwm(&self) -> u64 {
        self.cwm
    }

    /// The octets counted.
    #[must_use]
    pub fn swm(&self) -> u64 {
        self.swm
    }

    /// The octets retired.
    #[must_use]
    pub fn rwm(&self) -> u64 {
        self.rwm
    }

    /// The highest offset seen.
    #[must_use]
    pub fn hwm(&self) -> u64 {
        self.hwm
    }

    /// The credit left.
    #[must_use]
    pub fn credit(&self) -> u64 {
        self.cwm.saturating_sub(self.swm)
    }

    /// Whether the limit moved since the last call with `clear` (to send MAX_*).
    pub fn has_cwm_changed(&mut self, clear: bool) -> bool {
        let r = self.has_cwm_changed;
        if clear {
            self.has_cwm_changed = false;
        }
        r
    }

    /// The error raised, if any (FLOW_CONTROL_ERROR or FINAL_SIZE_ERROR), the stream's or else
    /// the parent's.
    #[must_use]
    pub fn error(&self, parent: Option<&Self>) -> Option<u64> {
        self.error.or_else(|| parent.and_then(|p| p.error))
    }

    /// The final size, once known.
    #[must_use]
    pub fn final_size(&self) -> Option<u64> {
        self.is_fin.then_some(self.hwm)
    }

    /// The current window.
    #[must_use]
    pub fn window(&self) -> u64 {
        self.cur_window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000_000;

    #[test]
    fn tx_credit_and_blocking() {
        let mut conn = TxFc::new(100);
        let mut s = TxFc::new(50);
        assert_eq!(s.credit(Some(&conn), 0), 50);
        assert!(s.consume(Some(&mut conn), 30));
        assert_eq!(s.credit(Some(&conn), 0), 20);
        assert_eq!(s.credit(Some(&conn), 60), 10);
        assert!(!s.consume(Some(&mut conn), 30));
        assert_eq!(s.swm(), 50);
        assert!(s.has_become_blocked(true));
        assert!(!s.has_become_blocked(false));
        assert!(!s.bump_cwm(40));
        assert!(s.bump_cwm(80));
        assert_eq!(s.credit_local(), 30);
    }

    #[test]
    fn rx_errors() {
        let mut conn = RxFc::new(100, 1000);
        let mut s = RxFc::new(50, 500);
        s.on_rx_stream_frame(Some(&mut conn), 40, false);
        assert_eq!(s.error(Some(&conn)), None);
        s.on_rx_stream_frame(Some(&mut conn), 51, false);
        assert_eq!(
            s.error(Some(&conn)),
            Some(crate::error::code(
                rustyssl_abi::OSSL_QUIC_ERR_FLOW_CONTROL_ERROR
            ))
        );
        let mut f = RxFc::new(50, 50);
        f.on_rx_stream_frame(None, 10, true);
        assert_eq!(f.final_size(), Some(10));
        f.on_rx_stream_frame(None, 10, true);
        assert_eq!(f.error(None), None);
        f.on_rx_stream_frame(None, 11, false);
        assert_eq!(
            f.error(None),
            Some(crate::error::code(
                rustyssl_abi::OSSL_QUIC_ERR_FINAL_SIZE_ERROR
            ))
        );
        let mut g = RxFc::new(50, 50);
        g.on_rx_stream_frame(None, 20, false);
        g.on_rx_stream_frame(None, 10, true);
        assert!(g.error(None).is_some(), "a final size below data received");
    }

    #[test]
    fn rx_window_autotunes() {
        let mut conn = RxFc::new(1000, 20_000);
        let mut s = RxFc::new(100, 1000);
        let rtt = Duration(100 * MS);
        s.on_rx_stream_frame(Some(&mut conn), 100, false);
        // 24 retired: 76 left > 75, no update.
        s.on_retire(Some(&mut conn), 24, Time(MS), rtt).unwrap();
        assert!(!s.has_cwm_changed(false));
        // 25 more, fast (well under 4 RTT): the window doubles.
        s.on_retire(Some(&mut conn), 1, Time(2 * MS), rtt).unwrap();
        assert!(s.has_cwm_changed(true));
        assert_eq!(s.window(), 200);
        assert_eq!(s.cwm(), 25 + 200);
        // Slowly: the window stays.
        s.on_rx_stream_frame(Some(&mut conn), 225, false);
        s.on_retire(Some(&mut conn), 200, Time(10_000 * MS), rtt)
            .unwrap();
        assert_eq!(s.window(), 200);
        assert_eq!(s.cwm(), 225 + 200);
        // Never past the maximum; never retire more than received.
        assert!(s.on_retire(None, 1, Time(0), rtt).is_err());
    }
}
