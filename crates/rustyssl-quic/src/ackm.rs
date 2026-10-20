//! ACK management and loss detection (RFC 9002), after OpenSSL's `quic_ackm.c`:
//!
//! - **Receiving:** each space's received packet numbers as ranges, bounded to 32 ranges by a
//!   watermark below which packets are no longer processable (OpenSSL's rule); when to send
//!   an ACK (the first packet, a packet earlier reported missing, two ACK-eliciting packets,
//!   a new gap, or `max_ack_delay` after the first unacknowledged one, at once in Initial and
//!   Handshake), and the ACK frame itself.
//! - **Sending:** each space's packets in flight, the RTT estimate (section 5), loss by packet
//!   and time threshold (section 6.1), the PTO (section 6.2) and persistent congestion
//!   (section 7.6), driving [`NewReno`].
//!
//! Each sent packet carries the caller's record `T` (what it contained), handed back when the
//! packet is acknowledged or lost.

use std::collections::BTreeMap;

use crate::cc::NewReno;
use crate::error::{Error, Result};
use crate::packet::Space;
use crate::time::{Duration, Time};
use crate::wire::AckRange;

/// The timer granularity (kGranularity).
pub const K_GRANULARITY: Duration = Duration::from_millis(1);
/// The packet reordering threshold (kPacketThreshold).
pub const K_PACKET_THRESHOLD: u64 = 3;
/// The initial RTT (kInitialRtt; OpenSSL's 333 ms).
pub const K_INITIAL_RTT: Duration = Duration::from_millis(333);
/// The most PTOs counted when backing off (OpenSSL's `MAX_PTO_COUNT`).
pub const MAX_PTO_COUNT: u32 = 16;
/// The most ranges an ACK frame carries, and the received history keeps (OpenSSL's 32).
pub const MAX_RX_ACK_RANGES: usize = 32;
/// ACK-eliciting packets received before an ACK is always sent (OpenSSL's 2).
pub const PKTS_BEFORE_ACK: u32 = 2;
/// Sent packets tracked per space at once (ours: OpenSSL bounds them by the congestion window
/// and memory; this caps a peer that never acknowledges).
pub const MAX_SENT_TRACKED: usize = 32 * 1024;

/// A packet sent and not yet acknowledged or lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SentPacket<T> {
    pub pn: u64,
    pub time: Time,
    /// Octets on the wire.
    pub size: u64,
    pub ack_eliciting: bool,
    /// Counted against the congestion window (ACK-only packets aren't).
    pub in_flight: bool,
    /// The largest packet number of the ACK frame it carried, if any.
    pub ack_largest: Option<u64>,
    pub info: T,
}

/// The RTT estimate (RFC 9002, section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rtt {
    pub latest: Duration,
    pub smoothed: Duration,
    pub var: Duration,
    pub min: Duration,
    pub has_sample: bool,
}

impl Default for Rtt {
    fn default() -> Self {
        Self {
            latest: Duration::ZERO,
            smoothed: K_INITIAL_RTT,
            var: K_INITIAL_RTT.div(2),
            min: Duration::ZERO,
            has_sample: false,
        }
    }
}

impl Rtt {
    fn update(
        &mut self,
        latest: Duration,
        ack_delay: Duration,
        max_ack_delay: Duration,
        confirmed: bool,
    ) {
        self.latest = latest;
        if !self.has_sample {
            self.min = latest;
            self.smoothed = latest;
            self.var = latest.div(2);
            self.has_sample = true;
            return;
        }
        self.min = self.min.min(latest);
        let ack_delay = if confirmed {
            ack_delay.min(max_ack_delay)
        } else {
            ack_delay
        };
        let adjusted = if latest >= self.min.add(ack_delay) {
            latest.sub(ack_delay)
        } else {
            latest
        };
        let diff = Duration(self.smoothed.0.abs_diff(adjusted.0));
        // rttvar = 3/4 rttvar + 1/4 |srtt − adjusted|; srtt = 7/8 srtt + 1/8 adjusted.
        self.var = self.var.mul(3).div(4).add(diff.div(4));
        self.smoothed = self.smoothed.mul(7).div(8).add(adjusted.div(8));
    }

    /// The PTO period without backoff or max_ack_delay: srtt + max(4 rttvar, granularity).
    #[must_use]
    pub fn pto_base(&self) -> Duration {
        self.smoothed.add(self.var.mul(4).max(K_GRANULARITY))
    }
}

#[derive(Clone, Debug)]
struct TxSpace<T> {
    sent: BTreeMap<u64, SentPacket<T>>,
    next_pn: u64,
    largest_acked: Option<u64>,
    time_of_last_ack_eliciting: Option<Time>,
    loss_time: Option<Time>,
    discarded: bool,
}

impl<T> Default for TxSpace<T> {
    fn default() -> Self {
        Self {
            sent: BTreeMap::new(),
            next_pn: 0,
            largest_acked: None,
            time_of_last_ack_eliciting: None,
            loss_time: None,
            discarded: false,
        }
    }
}

#[derive(Clone, Debug, Default)]
struct RxSpace {
    /// Received packet numbers as disjoint ranges, ascending.
    ranges: Vec<AckRange>,
    /// Packet numbers below this are no longer processable.
    watermark: u64,
    largest: Option<u64>,
    largest_time: Option<Time>,
    ack_desired: bool,
    flush_deadline: Option<Time>,
    eliciting_since_ack: u32,
    ack_generated: bool,
    /// The ranges of the last ACK frame generated (descending), to tell "was missing".
    last_ack: Vec<AckRange>,
    ect0: u64,
    ect1: u64,
    ce: u64,
}

impl RxSpace {
    fn contains(&self, pn: u64) -> bool {
        self.ranges.iter().any(|r| r.start <= pn && pn <= r.end)
    }

    fn insert(&mut self, pn: u64) {
        let i = self.ranges.partition_point(|r| r.end < pn);
        // Merge with the range before (ending at pn − 1) and the one at i (starting at pn + 1).
        let joins_prev = i > 0
            && self
                .ranges
                .get(i.wrapping_sub(1))
                .is_some_and(|r| r.end.checked_add(1) == Some(pn));
        let joins_next = self
            .ranges
            .get(i)
            .is_some_and(|r| pn.checked_add(1) == Some(r.start));
        match (joins_prev, joins_next) {
            (true, true) => {
                let next_end = self.ranges.get(i).map_or(pn, |r| r.end);
                if let Some(r) = self.ranges.get_mut(i.wrapping_sub(1)) {
                    r.end = next_end;
                }
                self.ranges.remove(i);
            }
            (true, false) => {
                if let Some(r) = self.ranges.get_mut(i.wrapping_sub(1)) {
                    r.end = pn;
                }
            }
            (false, true) => {
                if let Some(r) = self.ranges.get_mut(i) {
                    r.start = pn;
                }
            }
            (false, false) => self.ranges.insert(i, AckRange { start: pn, end: pn }),
        }
        // Bound the history: drop the oldest ranges, raising the watermark past them.
        while self.ranges.len() > MAX_RX_ACK_RANGES {
            let old = self.ranges.remove(0);
            self.watermark = self.watermark.max(old.end.saturating_add(1));
        }
    }

    fn was_missing(&self, pn: u64) -> bool {
        self.last_ack.first().is_some_and(|top| pn <= top.end)
            && !self.last_ack.iter().any(|r| r.start <= pn && pn <= r.end)
    }

    fn newly_missing(&self) -> bool {
        let (Some(top), Some(tail)) = (self.last_ack.first(), self.ranges.last()) else {
            return false;
        };
        tail.start == tail.end && tail.start > top.end.saturating_add(1)
    }

    /// Stops tracking packets at or below `pn` (an ACK of ours that covered them was
    /// acknowledged).
    fn prune_through(&mut self, pn: u64) {
        let w = pn.saturating_add(1);
        self.watermark = self.watermark.max(w);
        self.ranges.retain(|r| r.end >= w);
        if let Some(r) = self.ranges.first_mut()
            && r.start < w
        {
            r.start = w;
        }
    }
}

/// What an ACK or a timeout decided.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<T> {
    pub acked: Vec<SentPacket<T>>,
    pub lost: Vec<SentPacket<T>>,
}

impl<T> Default for Outcome<T> {
    fn default() -> Self {
        Self {
            acked: Vec::new(),
            lost: Vec::new(),
        }
    }
}

/// What a loss-detection timeout asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Timeout<T> {
    /// Nothing to do yet.
    None,
    /// Packets lost by the time threshold.
    Lost(Vec<SentPacket<T>>),
    /// A PTO: send up to two ack-eliciting probes in `Space`.
    Probe(Space),
}

/// The ACK manager of one connection.
#[derive(Debug)]
pub struct Ackm<T> {
    tx: [TxSpace<T>; 3],
    rx: [RxSpace; 3],
    pub rtt: Rtt,
    pub cc: NewReno,
    pto_count: u32,
    /// The peer's max_ack_delay (it delays ACKs this long; part of the PTO).
    pub peer_max_ack_delay: Duration,
    /// Ours (we delay ACKs this long in the application space).
    pub max_ack_delay: Duration,
    /// The peer's ack_delay_exponent, for decoding its ACK frames' delays.
    pub peer_ack_delay_exponent: u32,
    /// The handshake is confirmed (the application space's PTO may run; ack delays count).
    pub handshake_confirmed: bool,
    /// A client: the peer has validated our address (we may stop arming PTO with nothing in
    /// flight).
    pub peer_validated_address: bool,
}

impl<T: Clone> Default for Ackm<T> {
    fn default() -> Self {
        Self::new(1200)
    }
}

impl<T: Clone> Ackm<T> {
    /// A manager for datagrams of up to `max_dgram_size` octets.
    #[must_use]
    pub fn new(max_dgram_size: usize) -> Self {
        Self {
            tx: [TxSpace::default(), TxSpace::default(), TxSpace::default()],
            rx: [RxSpace::default(), RxSpace::default(), RxSpace::default()],
            rtt: Rtt::default(),
            cc: NewReno::new(max_dgram_size),
            pto_count: 0,
            peer_max_ack_delay: Duration::from_millis(25),
            max_ack_delay: Duration::from_millis(25),
            peer_ack_delay_exponent: 3,
            handshake_confirmed: false,
            peer_validated_address: false,
        }
    }

    fn tx(&self, s: Space) -> &TxSpace<T> {
        match s {
            Space::Initial => &self.tx[0],
            Space::Handshake => &self.tx[1],
            Space::Application => &self.tx[2],
        }
    }

    fn tx_mut(&mut self, s: Space) -> &mut TxSpace<T> {
        match s {
            Space::Initial => &mut self.tx[0],
            Space::Handshake => &mut self.tx[1],
            Space::Application => &mut self.tx[2],
        }
    }

    fn rx(&self, s: Space) -> &RxSpace {
        match s {
            Space::Initial => &self.rx[0],
            Space::Handshake => &self.rx[1],
            Space::Application => &self.rx[2],
        }
    }

    fn rx_mut(&mut self, s: Space) -> &mut RxSpace {
        match s {
            Space::Initial => &mut self.rx[0],
            Space::Handshake => &mut self.rx[1],
            Space::Application => &mut self.rx[2],
        }
    }

    /// The next packet number to send in `s` (not yet used).
    #[must_use]
    pub fn next_pn(&self, s: Space) -> u64 {
        self.tx(s).next_pn
    }

    /// The largest packet number the peer acknowledged in `s`.
    #[must_use]
    pub fn largest_acked(&self, s: Space) -> Option<u64> {
        self.tx(s).largest_acked
    }

    /// The largest packet number received in `s`.
    #[must_use]
    pub fn largest_received(&self, s: Space) -> Option<u64> {
        self.rx(s).largest
    }

    /// Whether `s` has been discarded.
    #[must_use]
    pub fn is_discarded(&self, s: Space) -> bool {
        self.tx(s).discarded
    }

    /// Octets in flight across every space.
    #[must_use]
    pub fn bytes_in_flight(&self) -> u64 {
        self.cc.bytes_in_flight()
    }

    /// Records a packet just sent; its number must be [`Ackm::next_pn`].
    ///
    /// # Errors
    /// Too many packets are unacknowledged, or the number is wrong.
    pub fn on_packet_sent(&mut self, s: Space, p: SentPacket<T>) -> Result<()> {
        let sp = self.tx_mut(s);
        if p.pn != sp.next_pn || sp.discarded {
            return Err(Error::internal("packet number out of sequence"));
        }
        if sp.sent.len() >= MAX_SENT_TRACKED {
            return Err(Error::internal("too many packets in flight"));
        }
        sp.next_pn = sp.next_pn.saturating_add(1);
        if p.ack_eliciting {
            sp.time_of_last_ack_eliciting = Some(p.time);
        }
        let in_flight = p.in_flight;
        let size = p.size;
        sp.sent.insert(p.pn, p);
        if in_flight {
            self.cc.on_data_sent(size);
        }
        Ok(())
    }

    /// Processes an ACK frame received in `s` at `now`: `ack_delay_raw` is the frame's field
    /// before the peer's exponent. Returns the newly acknowledged and lost packets.
    ///
    /// # Errors
    /// The frame acknowledges a packet never sent (PROTOCOL_VIOLATION, as OpenSSL).
    pub fn on_ack_received(
        &mut self,
        s: Space,
        ranges: &[AckRange],
        ack_delay_raw: u64,
        frame_type: u64,
        now: Time,
    ) -> Result<Outcome<T>> {
        let Some(top) = ranges.first() else {
            return Ok(Outcome::default());
        };
        if top.end >= self.tx(s).next_pn {
            return Err(Error::protocol(frame_type, "ACK for unsent packet number"));
        }
        let largest = top.end;
        let sp = self.tx_mut(s);
        let mut acked = Vec::new();
        for r in ranges {
            let pns: Vec<u64> = sp.sent.range(r.start..=r.end).map(|(&k, _)| k).collect();
            for pn in pns {
                if let Some(p) = sp.sent.remove(&pn) {
                    acked.push(p);
                }
            }
        }
        sp.largest_acked = Some(sp.largest_acked.map_or(largest, |l| l.max(largest)));
        if acked.is_empty() {
            return Ok(Outcome::default());
        }
        // An RTT sample when the largest acknowledged is newly acknowledged and some newly
        // acknowledged packet was ack-eliciting.
        acked.sort_by_key(|p| p.pn);
        let newest = acked.last().map(|p| (p.pn, p.time));
        if newest.is_some_and(|(pn, _)| pn == largest) && acked.iter().any(|p| p.ack_eliciting) {
            let sent_time = newest.map_or(now, |(_, t)| t);
            let exp = self.peer_ack_delay_exponent.min(20);
            let delay = Duration::from_micros(ack_delay_raw.saturating_mul(1u64 << exp));
            let delay = if s == Space::Application {
                delay
            } else {
                Duration::ZERO
            };
            let confirmed = self.handshake_confirmed;
            let mad = self.peer_max_ack_delay;
            self.rtt.update(now.since(sent_time), delay, mad, confirmed);
        }
        for p in &acked {
            if p.in_flight {
                self.cc.on_data_acked(p.time, p.size);
            }
            if let Some(l) = p.ack_largest {
                self.rx_mut(s).prune_through(l);
            }
        }
        let lost = self.detect_lost(s, now);
        // Reset the backoff, except for a client's Initial ACK before the handshake (RFC 9002,
        // section 6.2.1).
        if self.peer_validated_address || s != Space::Initial {
            self.pto_count = 0;
        }
        Ok(Outcome { acked, lost })
    }

    fn loss_delay(&self) -> Duration {
        // max(kTimeThreshold × max(smoothed, latest), granularity), kTimeThreshold = 9/8.
        let base = self.rtt.smoothed.max(self.rtt.latest);
        base.mul(9).div(8).max(K_GRANULARITY)
    }

    fn detect_lost(&mut self, s: Space, now: Time) -> Vec<SentPacket<T>> {
        let delay = self.loss_delay();
        let sp = self.tx_mut(s);
        sp.loss_time = None;
        let Some(largest) = sp.largest_acked else {
            return Vec::new();
        };
        let lost_send_time = now.sub(delay);
        let mut lost_pns = Vec::new();
        for (&pn, p) in sp.sent.range(..=largest) {
            if p.time <= lost_send_time || largest >= pn.saturating_add(K_PACKET_THRESHOLD) {
                lost_pns.push(pn);
            } else {
                let t = p.time.add(delay);
                sp.loss_time = Some(sp.loss_time.map_or(t, |l: Time| l.min(t)));
            }
        }
        let lost: Vec<SentPacket<T>> = lost_pns
            .iter()
            .filter_map(|pn| sp.sent.remove(pn))
            .collect();
        if !lost.is_empty() {
            let persistent = self.persistent_congestion(&lost);
            for p in &lost {
                if p.in_flight {
                    self.cc.on_data_lost(p.time, p.size);
                }
            }
            self.cc.on_data_lost_finished(now, persistent);
        }
        lost
    }

    fn persistent_congestion(&self, lost: &[SentPacket<T>]) -> bool {
        if !self.rtt.has_sample {
            return false;
        }
        let eliciting: Vec<&SentPacket<T>> = lost.iter().filter(|p| p.ack_eliciting).collect();
        let (Some(first), Some(last)) = (eliciting.first(), eliciting.last()) else {
            return false;
        };
        let period = self.rtt.pto_base().add(self.peer_max_ack_delay).mul(3);
        last.time.since(first.time) > period
    }

    fn pto_period(&self, s: Space) -> Duration {
        let mut d = self.rtt.pto_base();
        if s == Space::Application {
            d = d.add(self.peer_max_ack_delay);
        }
        d.mul(1u64 << self.pto_count.min(MAX_PTO_COUNT))
    }

    fn earliest_loss_time(&self) -> Option<(Time, Space)> {
        Space::ALL
            .iter()
            .filter_map(|&s| self.tx(s).loss_time.map(|t| (t, s)))
            .min_by_key(|(t, _)| *t)
    }

    fn pto_time_and_space(&self, now: Time) -> Option<(Time, Space)> {
        let in_flight_eliciting = Space::ALL
            .iter()
            .any(|&s| self.tx(s).sent.values().any(|p| p.ack_eliciting));
        if !in_flight_eliciting {
            if self.peer_validated_address {
                return None;
            }
            // A client arms the PTO from now to unblock the server (anti-amplification).
            let s = if self.tx(Space::Handshake).discarded || self.is_discarded(Space::Initial) {
                Space::Handshake
            } else {
                Space::Initial
            };
            return Some((now.add(self.pto_period(s)), s));
        }
        let mut best: Option<(Time, Space)> = None;
        for s in Space::ALL {
            let sp = self.tx(s);
            if sp.discarded || !sp.sent.values().any(|p| p.ack_eliciting) {
                continue;
            }
            if s == Space::Application && !self.handshake_confirmed {
                break;
            }
            let Some(t0) = sp.time_of_last_ack_eliciting else {
                continue;
            };
            let t = t0.add(self.pto_period(s));
            if best.is_none_or(|(b, _)| t < b) {
                best = Some((t, s));
            }
        }
        best
    }

    /// When loss detection next needs to run (a time-threshold loss or a PTO), if ever.
    #[must_use]
    pub fn loss_detection_deadline(&self, now: Time) -> Option<Time> {
        if let Some((t, _)) = self.earliest_loss_time() {
            return Some(t);
        }
        self.pto_time_and_space(now).map(|(t, _)| t)
    }

    /// Runs loss detection at `now`, after [`Ackm::loss_detection_deadline`] passed.
    pub fn on_timeout(&mut self, now: Time) -> Timeout<T> {
        if let Some((t, s)) = self.earliest_loss_time() {
            if t <= now {
                return Timeout::Lost(self.detect_lost(s, now));
            }
            return Timeout::None;
        }
        match self.pto_time_and_space(now) {
            Some((t, s)) if t <= now => {
                self.pto_count = self.pto_count.saturating_add(1).min(MAX_PTO_COUNT);
                Timeout::Probe(s)
            }
            _ => Timeout::None,
        }
    }

    /// Discards space `s` (its keys are gone): its packets leave flight without being lost.
    pub fn discard_space(&mut self, s: Space) {
        let sent = core::mem::take(&mut self.tx_mut(s).sent);
        for p in sent.values() {
            if p.in_flight {
                self.cc.on_data_invalidated(p.size);
            }
        }
        let sp = self.tx_mut(s);
        sp.discarded = true;
        sp.loss_time = None;
        sp.time_of_last_ack_eliciting = None;
        *self.rx_mut(s) = RxSpace::default();
        self.pto_count = 0;
    }

    /// The packets still unacknowledged in `s` (to retransmit their contents as probes).
    #[must_use]
    pub fn unacked(&self, s: Space) -> Vec<SentPacket<T>> {
        self.tx(s).sent.values().cloned().collect()
    }

    // ---- receiving ----

    /// Whether a packet numbered `pn` in `s` should be processed: not a duplicate, and not
    /// below the watermark.
    #[must_use]
    pub fn is_processable(&self, s: Space, pn: u64) -> bool {
        let rx = self.rx(s);
        pn >= rx.watermark && !rx.contains(pn)
    }

    /// Records a packet received and processed in `s` at `now`.
    pub fn on_packet_received(&mut self, s: Space, pn: u64, ack_eliciting: bool, now: Time) {
        if !self.is_processable(s, pn) {
            return;
        }
        let max_ack_delay = if s == Space::Application {
            self.max_ack_delay
        } else {
            Duration::ZERO
        };
        let rx = self.rx_mut(s);
        if rx.largest.is_none_or(|l| pn > l) {
            rx.largest = Some(pn);
            rx.largest_time = Some(now);
        }
        let was_missing = rx.was_missing(pn);
        rx.insert(pn);
        if !ack_eliciting || rx.ack_desired {
            return;
        }
        rx.eliciting_since_ack = rx.eliciting_since_ack.saturating_add(1);
        if !rx.ack_generated
            || was_missing
            || rx.eliciting_since_ack >= PKTS_BEFORE_ACK
            || rx.newly_missing()
        {
            rx.ack_desired = true;
            rx.flush_deadline = None;
            return;
        }
        let d = now.add(max_ack_delay);
        rx.flush_deadline = Some(rx.flush_deadline.map_or(d, |f| f.min(d)));
    }

    /// Whether `s` should send an ACK frame now.
    #[must_use]
    pub fn ack_desired(&self, s: Space, now: Time) -> bool {
        let rx = self.rx(s);
        !rx.ranges.is_empty() && (rx.ack_desired || rx.flush_deadline.is_some_and(|d| now >= d))
    }

    /// When `s` will want to send an ACK frame, if it has one pending.
    #[must_use]
    pub fn ack_deadline(&self, s: Space) -> Option<Time> {
        let rx = self.rx(s);
        if rx.ack_desired {
            Some(Time::ZERO)
        } else {
            rx.flush_deadline
        }
    }

    /// Whether `s` has anything to acknowledge.
    #[must_use]
    pub fn has_ack(&self, s: Space) -> bool {
        !self.rx(s).ranges.is_empty()
    }

    /// The ACK frame for `s` at `now`: ranges (highest first, at most 32) and the ACK Delay
    /// field (encoded with our `ack_delay_exponent`), with ECN counts. Generating it resets the
    /// pending-ACK state.
    pub fn ack_frame(
        &mut self,
        s: Space,
        now: Time,
        ack_delay_exponent: u32,
    ) -> Option<(Vec<AckRange>, u64)> {
        let rx = self.rx_mut(s);
        if rx.ranges.is_empty() {
            return None;
        }
        let ranges: Vec<AckRange> = rx
            .ranges
            .iter()
            .rev()
            .take(MAX_RX_ACK_RANGES)
            .copied()
            .collect();
        let delay = match (s, rx.largest_time) {
            (Space::Application, Some(t)) if now > t => now.since(t),
            _ => Duration::ZERO,
        };
        let field = delay.as_micros() >> ack_delay_exponent.min(20);
        rx.last_ack.clone_from(&ranges);
        rx.eliciting_since_ack = 0;
        rx.ack_generated = true;
        rx.ack_desired = false;
        rx.flush_deadline = None;
        Some((ranges, field))
    }

    /// The ECN counts of `s` (ECT(0), ECT(1), CE).
    #[must_use]
    pub fn ecn_counts(&self, s: Space) -> (u64, u64, u64) {
        let rx = self.rx(s);
        (rx.ect0, rx.ect1, rx.ce)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    fn sent(pn: u64, t: u64) -> SentPacket<u64> {
        SentPacket {
            pn,
            time: Time(t),
            size: 1200,
            ack_eliciting: true,
            in_flight: true,
            ack_largest: None,
            info: pn,
        }
    }

    const MS: u64 = 1_000_000;

    #[test]
    fn acks_rtt_and_packet_threshold_loss() {
        let mut a: Ackm<u64> = Ackm::new(1200);
        a.peer_validated_address = true;
        for pn in 0..6 {
            a.on_packet_sent(Space::Initial, sent(pn, pn * MS)).unwrap();
        }
        assert_eq!(a.bytes_in_flight(), 6 * 1200);
        // ACK 4..=5: 0 and 1 are 3+ below the largest, lost by the packet threshold.
        let out = a
            .on_ack_received(
                Space::Initial,
                &[AckRange { start: 4, end: 5 }],
                0,
                2,
                Time(100 * MS),
            )
            .unwrap();
        assert_eq!(out.acked.iter().map(|p| p.pn).collect::<Vec<_>>(), [4, 5]);
        assert_eq!(out.lost.iter().map(|p| p.pn).collect::<Vec<_>>(), [0, 1, 2]);
        assert!(a.rtt.has_sample);
        assert_eq!(a.rtt.latest, Duration(95 * MS));
        // 3 waits for the time threshold.
        let deadline = a.loss_detection_deadline(Time(100 * MS)).unwrap();
        assert!(deadline > Time(100 * MS));
        match a.on_timeout(deadline) {
            Timeout::Lost(l) => assert_eq!(l.iter().map(|p| p.pn).collect::<Vec<_>>(), [3]),
            other => panic!("{other:?}"),
        }
        assert_eq!(a.bytes_in_flight(), 0);
        // Acknowledging a packet never sent is a protocol violation.
        assert!(
            a.on_ack_received(
                Space::Initial,
                &[AckRange { start: 9, end: 9 }],
                0,
                2,
                Time(0)
            )
            .is_err()
        );
    }

    #[test]
    fn pto_backs_off_and_discard_clears_flight() {
        let mut a: Ackm<u64> = Ackm::new(1200);
        a.peer_validated_address = true;
        a.on_packet_sent(Space::Handshake, sent(0, 0)).unwrap();
        let d1 = a.loss_detection_deadline(Time(0)).unwrap();
        // srtt 333 ms + 4 × 166.5 ms.
        assert_eq!(d1, Time(333 * MS + 666 * MS));
        assert_eq!(a.on_timeout(d1), Timeout::Probe(Space::Handshake));
        let d2 = a.loss_detection_deadline(d1).unwrap();
        assert_eq!(d2, Time(2 * (333 * MS + 666 * MS)));
        a.discard_space(Space::Handshake);
        assert_eq!(a.bytes_in_flight(), 0);
        assert_eq!(a.loss_detection_deadline(Time(0)), None);
    }

    #[test]
    fn ack_generation_follows_openssl() {
        let mut a: Ackm<u64> = Ackm::new(1200);
        let s = Space::Application;
        // The first ACK-eliciting packet is acknowledged at once.
        a.on_packet_received(s, 0, true, Time(0));
        assert!(a.ack_desired(s, Time(0)));
        let (r, _) = a.ack_frame(s, Time(0), 3).unwrap();
        assert_eq!(r, [AckRange { start: 0, end: 0 }]);
        // One more: delayed by max_ack_delay.
        a.on_packet_received(s, 1, true, Time(MS));
        assert!(!a.ack_desired(s, Time(MS)));
        assert_eq!(a.ack_deadline(s), Some(Time(26 * MS)));
        assert!(a.ack_desired(s, Time(26 * MS)));
        // A second one reaches the threshold.
        a.on_packet_received(s, 2, true, Time(2 * MS));
        assert!(a.ack_desired(s, Time(2 * MS)));
        let (r, delay) = a.ack_frame(s, Time(10 * MS), 3).unwrap();
        assert_eq!(r, [AckRange { start: 0, end: 2 }]);
        assert_eq!(delay, (8 * 1000) >> 3);
        // A gap is reported at once; the missing packet, when it comes, too.
        a.on_packet_received(s, 5, true, Time(11 * MS));
        assert!(a.ack_desired(s, Time(11 * MS)));
        let (r, _) = a.ack_frame(s, Time(11 * MS), 3).unwrap();
        assert_eq!(
            r,
            [AckRange { start: 5, end: 5 }, AckRange { start: 0, end: 2 }]
        );
        a.on_packet_received(s, 3, true, Time(12 * MS));
        assert!(a.ack_desired(s, Time(12 * MS)));
        // Duplicates aren't processable.
        assert!(!a.is_processable(s, 3));
        // Initial and Handshake never delay.
        a.on_packet_received(Space::Initial, 0, true, Time(0));
        a.ack_frame(Space::Initial, Time(0), 3);
        a.on_packet_received(Space::Initial, 1, true, Time(5));
        assert_eq!(a.ack_deadline(Space::Initial), Some(Time(5)));
    }

    #[test]
    fn rx_history_is_bounded() {
        let mut a: Ackm<u64> = Ackm::new(1200);
        let s = Space::Application;
        for i in 0..100 {
            a.on_packet_received(s, i * 2, false, Time(0));
        }
        let (r, _) = a.ack_frame(s, Time(0), 3).unwrap();
        assert_eq!(r.len(), MAX_RX_ACK_RANGES);
        assert_eq!(
            r[0],
            AckRange {
                start: 198,
                end: 198
            }
        );
        // Below the watermark: dropped.
        assert!(!a.is_processable(s, 1));
        assert!(a.is_processable(s, 199));
    }

    #[test]
    fn range_insertion_merges() {
        let mut rx = RxSpace::default();
        for pn in [5, 3, 4, 10, 1, 2, 0, 9, 11] {
            rx.insert(pn);
        }
        assert_eq!(
            rx.ranges,
            [
                AckRange { start: 0, end: 5 },
                AckRange { start: 9, end: 11 }
            ]
        );
    }
}
