//! The packetiser's parts (after OpenSSL's `quic_txp.c`): what each sent packet carried, so an
//! acknowledgement or a loss reaches the right owner, and a payload builder that fits frames
//! into the room a packet has. The channel decides which frames go where and in what order
//! (ACK first, then CONNECTION_CLOSE or the control frames, CRYPTO, then streams), as OpenSSL's
//! packetiser does.

use crate::error::Result;
use crate::wire::{Frame, encode_frame, encode_stream_header, stream_header_len};

/// A frame of a sent packet, as far as acknowledgement and loss need to know it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SentFrame {
    /// An ACK frame whose largest acknowledged was this.
    Ack(u64),
    Crypto {
        offset: u64,
        len: u64,
    },
    Stream {
        id: u64,
        offset: u64,
        len: u64,
        fin: bool,
    },
    ResetStream(u64),
    StopSending(u64),
    MaxData,
    MaxStreamData(u64),
    MaxStreams {
        bidi: bool,
    },
    DataBlocked,
    StreamDataBlocked(u64),
    StreamsBlocked {
        bidi: bool,
    },
    RetireConnectionId(u64),
    NewToken(Vec<u8>),
    HandshakeDone,
    /// Sent once; never retransmitted (PING, PATH_RESPONSE, CONNECTION_CLOSE, PADDING).
    Unreliable,
}

/// What one sent packet carried.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SentInfo {
    pub frames: Vec<SentFrame>,
}

/// A packet's payload being filled.
#[derive(Debug)]
pub struct PayloadBuilder {
    buf: Vec<u8>,
    limit: usize,
    pub info: SentInfo,
    pub ack_eliciting: bool,
    /// Counted in flight (anything but ACK and padding alone).
    pub in_flight: bool,
}

impl PayloadBuilder {
    /// A payload of at most `limit` octets.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            buf: Vec::with_capacity(limit.min(1500)),
            limit,
            info: SentInfo::default(),
            ack_eliciting: false,
            in_flight: false,
        }
    }

    /// Octets left.
    #[must_use]
    pub fn room(&self) -> usize {
        self.limit.saturating_sub(self.buf.len())
    }

    /// Octets used.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether nothing was added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Adds `f` if it fits, recording `rec`; returns whether it was added.
    ///
    /// # Errors
    /// The frame doesn't encode.
    pub fn push(&mut self, f: &Frame<'_>, rec: SentFrame) -> Result<bool> {
        let mut tmp = Vec::new();
        encode_frame(&mut tmp, f)?;
        if tmp.len() > self.room() {
            return Ok(false);
        }
        self.buf.extend_from_slice(&tmp);
        if f.is_ack_eliciting() {
            self.ack_eliciting = true;
        }
        if !matches!(f, Frame::Ack { .. }) {
            self.in_flight = true;
        }
        self.info.frames.push(rec);
        Ok(true)
    }

    /// The most stream data a STREAM frame for `id` at `offset` can carry here (with an
    /// explicit length).
    #[must_use]
    pub fn stream_room(&self, id: u64, offset: u64) -> usize {
        let room = self.room();
        let hdr = stream_header_len(id, offset, room, true);
        room.saturating_sub(hdr)
    }

    /// Adds a STREAM frame (`data` must fit [`PayloadBuilder::stream_room`]).
    ///
    /// # Errors
    /// A field is out of range.
    pub fn push_stream(&mut self, id: u64, offset: u64, data: &[u8], fin: bool) -> Result<()> {
        encode_stream_header(&mut self.buf, id, offset, data.len(), fin, true)?;
        self.buf.extend_from_slice(data);
        self.ack_eliciting = true;
        self.in_flight = true;
        self.info.frames.push(SentFrame::Stream {
            id,
            offset,
            len: u64::try_from(data.len()).unwrap_or(u64::MAX),
            fin,
        });
        Ok(())
    }

    /// Raises the limit (to pad past the room first planned).
    pub fn grow_limit(&mut self, n: usize) {
        self.limit = self.limit.max(n);
    }

    /// Pads with PADDING frames to `n` octets in all.
    pub fn pad_to(&mut self, n: usize) {
        if self.buf.len() < n {
            self.buf.resize(n, 0);
            self.in_flight = true;
        }
    }

    /// The payload.
    #[must_use]
    pub fn into_parts(self) -> (Vec<u8>, SentInfo, bool, bool) {
        (self.buf, self.info, self.ack_eliciting, self.in_flight)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_fits_frames() {
        let mut b = PayloadBuilder::new(20);
        assert!(b.push(&Frame::Ping, SentFrame::Unreliable).unwrap());
        assert!(b.ack_eliciting && b.in_flight);
        let room = b.stream_room(4, 0);
        assert_eq!(room, 20 - 1 - 3);
        b.push_stream(4, 0, &vec![7u8; room], true).unwrap();
        assert_eq!(b.room(), 0);
        assert!(!b.push(&Frame::Ping, SentFrame::Unreliable).unwrap());
        let (buf, info, _, _) = b.into_parts();
        assert_eq!(buf.len(), 20);
        assert_eq!(info.frames.len(), 2);
    }
}
