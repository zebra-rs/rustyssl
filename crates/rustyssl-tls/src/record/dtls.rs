//! DTLS's record layer (RFC 6347, section 4.1; OpenSSL's `dtls_meth.c`): 13-octet headers
//! with the epoch and a 48-bit sequence number, the replay window, the next epoch's records
//! held back during a handshake, and records that fail their checks dropped without an alert.

use std::collections::VecDeque;

use rustyssl_abi as abi;

use super::{ContentType, Mode, Protection, Record, RecordReader, alert, fatal, size};
use crate::crypto::Provider;
use crate::error::{Error, Result};

/// The length of a DTLS record header.
pub const HEADER_LEN: usize = 13;

/// The largest sequence number (48 bits).
const MAX_SEQ: u64 = (1 << 48) - 1;

/// How many records of the next epoch are held back (`dtls_rlayer_buffer_record`).
const MAX_BUFFERED: usize = 16;

/// A record header: type, version, epoch, sequence number, length.
///
/// # Errors
/// The length doesn't fit 16 bits.
pub fn header(ty: ContentType, version: u16, seq: u64, len: usize) -> Result<[u8; HEADER_LEN]> {
    let l = u16::try_from(len).map_err(|_| Error::internal())?;
    let mut h = [0u8; HEADER_LEN];
    let s = seq.to_be_bytes();
    let [v0, v1] = version.to_be_bytes();
    let [l0, l1] = l.to_be_bytes();
    for (d, v) in h
        .iter_mut()
        .zip([ty, v0, v1].into_iter().chain(s).chain([l0, l1]))
    {
        *d = v;
    }
    Ok(h)
}

/// The 64-record replay window of an epoch (`DTLS_BITMAP`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    /// Bit `i`: record `max_seq - i` was received.
    map: u64,
    /// The highest sequence number received.
    max_seq: u64,
}

impl Window {
    /// `satsub64be`: `a - b`, clamped to ±128.
    fn diff(a: u64, b: u64) -> i64 {
        if a >= b {
            i64::try_from(a.saturating_sub(b).min(128)).unwrap_or(128)
        } else {
            i64::try_from(b.saturating_sub(a).min(128))
                .unwrap_or(128)
                .saturating_neg()
        }
    }

    /// `dtls_record_replay_check`: whether `seq` is new and inside the window.
    #[must_use]
    pub fn check(&self, seq: u64) -> bool {
        let cmp = Self::diff(seq, self.max_seq);
        if cmp > 0 {
            return true;
        }
        let shift = cmp.unsigned_abs();
        if shift >= 64 {
            return false;
        }
        self.map & (1u64 << shift) == 0
    }

    /// `dtls_record_bitmap_update`: marks `seq` received.
    pub fn update(&mut self, seq: u64) {
        let cmp = Self::diff(seq, self.max_seq);
        if cmp > 0 {
            let shift = cmp.unsigned_abs();
            self.map = if shift < 64 {
                (self.map << shift) | 1
            } else {
                1
            };
            self.max_seq = seq;
        } else {
            let shift = cmp.unsigned_abs();
            if shift < 64 {
                self.map |= 1u64 << shift;
            }
        }
    }
}

/// DTLS's read state.
#[derive(Clone, Debug, Default)]
pub struct ReadState {
    /// The epoch being read (`r_epoch`).
    pub epoch: u16,
    /// Its replay window.
    window: Window,
    /// The next epoch's (its records are checked against it before being held back).
    next_window: Window,
    /// The next epoch's records, held back while in a handshake (header and body), with
    /// their sequence numbers.
    held: Vec<(u64, Vec<u8>)>,
    /// Records to read again before any new input (the held records, once their epoch
    /// starts).
    pub replay: VecDeque<Vec<u8>>,
    /// Whether a handshake is in progress (`dtls_set_in_init`).
    pub in_init: bool,
}

impl ReadState {
    /// The epoch changes: the held records are read again, with fresh windows (a new
    /// record layer in OpenSSL).
    pub fn next_epoch(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.window = Window::default();
        self.next_window = Window::default();
        self.held.sort_by_key(|h| h.0);
        for (_, r) in self.held.drain(..) {
            self.replay.push_back(r);
        }
    }
}

/// A previous epoch's write state, kept to retransmit the flight that left it.
#[derive(Debug)]
pub struct PrevEpoch {
    /// The epoch.
    epoch: u16,
    /// Its next sequence number.
    seq: u64,
    /// Its checks.
    pub(super) mode: Mode,
    /// Its protection.
    pub(super) protection: Protection,
}

/// DTLS's write state.
#[derive(Debug, Default)]
pub struct WriteState {
    /// The epoch being written (`w_epoch`).
    pub epoch: u16,
    /// The next sequence number.
    pub seq: u64,
    /// The previous epoch.
    prev: Option<PrevEpoch>,
}

impl WriteState {
    /// The next record's `epoch || sequence`.
    ///
    /// # Errors
    /// The sequence number wrapped (`SSL_R_SEQUENCE_CTR_WRAPPED`).
    pub fn take_seq(&mut self) -> Result<u64> {
        let s = self.seq;
        if s > MAX_SEQ {
            return Err(
                fatal(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_SEQUENCE_CTR_WRAPPED)
                    .in_func("tls_increment_sequence_ctr"),
            );
        }
        self.seq = s.saturating_add(1);
        Ok((u64::from(self.epoch) << 48) | s)
    }

    /// Moves on to the next epoch, keeping this one.
    pub(super) fn next_epoch(&mut self, mode: Mode, protection: Protection) {
        self.prev = Some(PrevEpoch {
            epoch: self.epoch,
            seq: self.seq,
            mode,
            protection,
        });
        self.epoch = self.epoch.wrapping_add(1);
        self.seq = 0;
    }

    /// Takes the previous epoch's state, if it is `epoch`.
    pub(super) fn take_prev(&mut self, epoch: u16) -> Option<PrevEpoch> {
        if self.prev.as_ref().is_some_and(|p| p.epoch == epoch) {
            self.prev.take()
        } else {
            None
        }
    }

    /// Puts the previous epoch back.
    pub(super) fn put_prev(&mut self, p: PrevEpoch) {
        self.prev = Some(p);
    }

    /// Swaps the epoch and sequence number with `p`'s.
    pub(super) fn swap_counters(&mut self, p: &mut PrevEpoch) {
        core::mem::swap(&mut self.epoch, &mut p.epoch);
        core::mem::swap(&mut self.seq, &mut p.seq);
    }

    /// Advances the sequence number (`DTLSv1_listen` answers in the client's record number).
    pub fn set_seq(&mut self, seq: u64) {
        self.seq = seq & MAX_SEQ;
    }
}

/// What [`RecordReader::read_dtls`] found in a datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DRead {
    /// A record, from the first `consumed` octets.
    Record {
        /// The octets the record took.
        consumed: usize,
        /// The record (`header` is the 13-octet header).
        record: Record,
        /// Its epoch.
        epoch: u16,
    },
    /// A record (or the rest of the datagram) dropped without an alert; `header` is a
    /// header that was read (the message callback sees it).
    Dropped {
        /// The octets dropped.
        consumed: usize,
        /// The header, if one was whole.
        header: Option<Vec<u8>>,
    },
}

impl RecordReader {
    /// The record at the start of `buf`, the rest of a datagram (`dtls_get_more_records`).
    ///
    /// # Errors
    /// A fatal error (the few OpenSSL raises in DTLS: an encrypt-then-MAC record too short
    /// or with a bad MAC, a record over the negotiated fragment length).
    pub fn read_dtls(&mut self, p: &dyn Provider, buf: &[u8]) -> Result<DRead> {
        let all = DRead::Dropped {
            consumed: buf.len(),
            header: None,
        };
        let Some(head) = buf.get(..HEADER_LEN) else {
            return Ok(all);
        };
        let b = |i: usize| head.get(i).copied().unwrap_or(0);
        let ty = b(0);
        let version = u16::from_be_bytes([b(1), b(2)]);
        let epoch = u16::from_be_bytes([b(3), b(4)]);
        let seq = u64::from_be_bytes([0, 0, b(5), b(6), b(7), b(8), b(9), b(10)]);
        let len = usize::from(u16::from_be_bytes([b(11), b(12)]));
        let header = head.to_vec();
        let drop_one = |consumed: usize, header: &[u8]| DRead::Dropped {
            consumed,
            header: Some(header.to_vec()),
        };
        let known = match self.mode {
            Mode::Plain(v) => v,
            Mode::Tls12(v) => Some(v),
            Mode::Tls13 => None,
        };
        let Some(total) = HEADER_LEN.checked_add(len) else {
            return Ok(all);
        };
        // A record that doesn't fit the datagram drops the rest of it.
        let Some(body) = buf.get(HEADER_LEN..total) else {
            return Ok(DRead::Dropped {
                consumed: buf.len(),
                header: Some(header),
            });
        };
        // Version, length: silently discarded.
        if let Some(v) = known
            && ty != alert()
            && version != v
        {
            return Ok(drop_one(total, &header));
        }
        let major = known.map_or(0xfe, |v| v >> 8);
        if version >> 8 != major {
            return Ok(drop_one(total, &header));
        }
        if len > size(abi::SSL3_RT_MAX_ENCRYPTED_LENGTH)
            || len
                > self
                    .max_frag_len
                    .saturating_add(size(abi::SSL3_RT_MAX_ENCRYPTED_OVERHEAD))
        {
            return Ok(drop_one(total, &header));
        }
        let Some(d) = self.dtls.as_mut() else {
            return Err(Error::internal());
        };
        // Epochs: the current one, or the next one's held back; others dropped.
        let next = epoch == d.epoch.wrapping_add(1);
        if epoch != d.epoch && !next {
            return Ok(drop_one(total, &header));
        }
        let window = if next { &d.next_window } else { &d.window };
        if !window.check(seq) || len == 0 {
            return Ok(drop_one(total, &header));
        }
        if next {
            if d.in_init && d.held.len() < MAX_BUFFERED && !d.held.iter().any(|h| h.0 == seq) {
                d.held
                    .push((seq, buf.get(..total).unwrap_or_default().to_vec()));
            }
            return Ok(drop_one(total, &header));
        }
        let mut record = Record {
            content_type: ty,
            version,
            header: header.clone(),
            data: body.to_vec(),
            inner: false,
        };
        self.dtls_seq = Some((u64::from(epoch) << 48) | seq);
        self.etm_failed = false;
        let r = self.unprotect(p, &mut record);
        self.dtls_seq = None;
        if let Err(e) = r {
            // A bad MAC or tag (and anything else the cipher refuses) is ignored; an
            // encrypt-then-MAC record that is too short or fails its MAC is fatal.
            if e.reason == abi::SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC && !self.etm_failed {
                return Ok(drop_one(total, &header));
            }
            let mut e = e;
            e.cause = None;
            return Err(e.in_func("dtls_process_record"));
        }
        if record.data.len() > self.max_frag_len {
            return Err(
                fatal(abi::SSL_AD_RECORD_OVERFLOW, abi::SSL_R_DATA_LENGTH_TOO_LONG)
                    .in_func("dtls_process_record"),
            );
        }
        if let Some(d) = self.dtls.as_mut() {
            d.window.update(seq);
        }
        if record.data.is_empty() {
            return Ok(drop_one(total, &header));
        }
        Ok(DRead::Record {
            consumed: total,
            record,
            epoch,
        })
    }

    /// DTLS: a held-back record to read before new input, once its epoch started.
    pub fn take_replay(&mut self) -> Option<Vec<u8>> {
        self.dtls.as_mut()?.replay.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_window_takes_each_number_once() {
        let mut w = Window::default();
        assert!(w.check(1));
        w.update(1);
        assert!(!w.check(1));
        assert!(w.check(0));
        w.update(0);
        assert!(!w.check(0));
        w.update(100);
        assert!(w.check(99));
        assert!(!w.check(36), "64 behind is outside the window");
        assert!(w.check(37));
        w.update(37);
        assert!(!w.check(37));
    }

    #[test]
    fn headers_carry_the_epoch_and_sequence() {
        let h = header(22, 0xfefd, (1 << 48) | 5, 3).unwrap_or_default();
        assert_eq!(h, [22, 0xfe, 0xfd, 0, 1, 0, 0, 0, 0, 0, 5, 0, 3]);
    }
}
