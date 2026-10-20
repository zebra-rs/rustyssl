//! NewReno congestion control (RFC 9002, section 7), as OpenSSL's `cc_newreno.c` does it: the
//! initial window of ten datagrams capped at max(2 datagrams, 14720), a minimum of two, a loss
//! halves the window once per recovery period, and the window grows only while it's nearly
//! used.

use crate::time::Time;

/// RFC 9002, section 7.2's floor on the initial window's cap.
const MIN_MAX_INIT_WND_SIZE: u64 = 14720;

/// The congestion controller's state as OpenSSL's diagnostics report it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    SlowStart,
    Avoidance,
    Recovery,
}

/// A NewReno congestion controller.
#[derive(Clone, Debug)]
pub struct NewReno {
    max_dgram_size: u64,
    k_init_wnd: u64,
    k_min_wnd: u64,
    bytes_in_flight: u64,
    cong_wnd: u64,
    slow_start_thresh: u64,
    bytes_acked: u64,
    cong_recovery_start_time: Time,
    processing_loss: bool,
    tx_time_of_last_loss: Time,
    in_congestion_recovery: bool,
}

impl Default for NewReno {
    fn default() -> Self {
        Self::new(1200)
    }
}

impl NewReno {
    /// A controller for datagrams of up to `max_dgram_size` octets.
    #[must_use]
    pub fn new(max_dgram_size: usize) -> Self {
        let mut nr = Self {
            max_dgram_size: 0,
            k_init_wnd: 0,
            k_min_wnd: 0,
            bytes_in_flight: 0,
            cong_wnd: 0,
            slow_start_thresh: u64::MAX,
            bytes_acked: 0,
            cong_recovery_start_time: Time::ZERO,
            processing_loss: false,
            tx_time_of_last_loss: Time::ZERO,
            in_congestion_recovery: false,
        };
        nr.set_max_dgram_size(max_dgram_size);
        nr.cong_wnd = nr.k_init_wnd;
        nr
    }

    /// Changes the datagram size; a smaller one resets the window to the initial one.
    pub fn set_max_dgram_size(&mut self, size: usize) {
        let size = u64::try_from(size).unwrap_or(u64::MAX);
        let reduced = size < self.max_dgram_size;
        self.max_dgram_size = size;
        let max_init = size.saturating_mul(2).max(MIN_MAX_INIT_WND_SIZE);
        self.k_init_wnd = size.saturating_mul(10).min(max_init);
        self.k_min_wnd = size.saturating_mul(2);
        if reduced {
            self.cong_wnd = self.k_init_wnd;
        }
    }

    /// The octets that may be sent now.
    #[must_use]
    pub fn tx_allowance(&self) -> u64 {
        self.cong_wnd.saturating_sub(self.bytes_in_flight)
    }

    /// The congestion window.
    #[must_use]
    pub fn cwnd(&self) -> u64 {
        self.cong_wnd
    }

    /// The octets in flight.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.bytes_in_flight
    }

    /// The state, as OpenSSL's diagnostics show it ('R', 'S', 'A').
    #[must_use]
    pub fn state(&self) -> State {
        if self.in_congestion_recovery {
            State::Recovery
        } else if self.cong_wnd < self.slow_start_thresh {
            State::SlowStart
        } else {
            State::Avoidance
        }
    }

    /// An in-flight packet of `size` octets was sent.
    pub fn on_data_sent(&mut self, size: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(size);
    }

    /// Data that will never be acknowledged or declared lost left flight (a discarded space).
    pub fn on_data_invalidated(&mut self, size: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(size);
    }

    fn in_recovery(&self, tx_time: Time) -> bool {
        tx_time <= self.cong_recovery_start_time
    }

    fn cong_limited(&self) -> bool {
        if self.bytes_in_flight >= self.cong_wnd {
            return true;
        }
        let rem = self.cong_wnd.saturating_sub(self.bytes_in_flight);
        (self.cong_wnd < self.slow_start_thresh && rem <= self.cong_wnd / 2)
            || rem <= self.max_dgram_size.saturating_mul(3)
    }

    /// An in-flight packet of `size` octets sent at `tx_time` was acknowledged.
    pub fn on_data_acked(&mut self, tx_time: Time, size: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(size);
        if !self.cong_limited() {
            return;
        }
        if self.in_recovery(tx_time) {
            // No growth during recovery.
        } else if self.cong_wnd < self.slow_start_thresh {
            self.cong_wnd = self.cong_wnd.saturating_add(size);
            self.in_congestion_recovery = false;
        } else {
            self.bytes_acked = self.bytes_acked.saturating_add(size);
            if self.bytes_acked >= self.cong_wnd {
                self.bytes_acked = self.bytes_acked.saturating_sub(self.cong_wnd);
                self.cong_wnd = self.cong_wnd.saturating_add(self.max_dgram_size);
            }
            self.in_congestion_recovery = false;
        }
    }

    /// An in-flight packet of `size` octets sent at `tx_time` was declared lost. Losses are
    /// gathered until [`NewReno::on_data_lost_finished`].
    pub fn on_data_lost(&mut self, tx_time: Time, size: u64) {
        if size > self.bytes_in_flight {
            return;
        }
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(size);
        if !self.processing_loss {
            if tx_time <= self.tx_time_of_last_loss {
                return;
            }
            self.processing_loss = true;
            self.bytes_acked = 0;
        }
        self.tx_time_of_last_loss = self.tx_time_of_last_loss.max(tx_time);
    }

    /// The losses of one detection pass are all reported; `persistent` is persistent congestion
    /// (RFC 9002, section 7.6), which collapses the window to the minimum.
    pub fn on_data_lost_finished(&mut self, now: Time, persistent: bool) {
        if !self.processing_loss {
            return;
        }
        self.congestion_event(now, self.tx_time_of_last_loss);
        if persistent {
            self.cong_wnd = self.k_min_wnd;
            self.cong_recovery_start_time = Time::ZERO;
        }
        self.processing_loss = false;
    }

    fn congestion_event(&mut self, now: Time, tx_time: Time) {
        if self.in_recovery(tx_time) {
            return;
        }
        self.in_congestion_recovery = true;
        self.cong_recovery_start_time = now;
        self.slow_start_thresh = self.cong_wnd / 2;
        self.cong_wnd = self.slow_start_thresh.max(self.k_min_wnd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newreno_follows_openssl() {
        let mut nr = NewReno::new(1200);
        // min(10 × 1200, max(2 × 1200, 14720)) = 12000.
        assert_eq!(nr.cwnd(), 12000);
        assert_eq!(nr.state(), State::SlowStart);
        // Not window-limited: no growth.
        nr.on_data_sent(1200);
        nr.on_data_acked(Time(1), 1200);
        assert_eq!(nr.cwnd(), 12000);
        // Window-limited slow start: grows by what's acked.
        nr.on_data_sent(12000);
        nr.on_data_acked(Time(2), 1200);
        assert_eq!(nr.cwnd(), 13200);
        // A loss halves it, once per recovery period.
        nr.on_data_lost(Time(3), 1200);
        nr.on_data_lost_finished(Time(10), false);
        assert_eq!(nr.cwnd(), 6600);
        assert_eq!(nr.state(), State::Recovery);
        nr.on_data_lost(Time(4), 1200);
        nr.on_data_lost_finished(Time(11), false);
        assert_eq!(
            nr.cwnd(),
            6600,
            "a loss sent before recovery began is ignored"
        );
        // Persistent congestion collapses to two datagrams.
        nr.on_data_lost(Time(20), 1200);
        nr.on_data_lost_finished(Time(30), true);
        assert_eq!(nr.cwnd(), 2400);
        assert_eq!(
            nr.tx_allowance(),
            2400u64.saturating_sub(nr.bytes_in_flight())
        );
    }
}
