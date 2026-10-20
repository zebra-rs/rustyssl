//! QUIC's wire encodings (RFC 9000, sections 16, 18 and 19): variable-length integers, every
//! frame, and transport parameters. Decoding is strict and bounded, with OpenSSL's checks
//! (`quic_wire.c`); a frame that doesn't decode is FRAME_ENCODING_ERROR at the caller.

use rustyssl_tls::codec::{DecodeError, Reader};

use crate::error::{Error, Result};

/// The largest varint (2^62 − 1).
pub const VARINT_MAX: u64 = (1 << 62) - 1;

/// The longest connection ID (RFC 9000, section 17.2).
pub const MAX_CID_LEN: usize = 20;

/// A stateless reset token's length.
pub const RESET_TOKEN_LEN: usize = 16;

/// Frame types (RFC 9000, section 19).
pub mod frame_type {
    pub const PADDING: u64 = 0x00;
    pub const PING: u64 = 0x01;
    pub const ACK: u64 = 0x02;
    pub const ACK_ECN: u64 = 0x03;
    pub const RESET_STREAM: u64 = 0x04;
    pub const STOP_SENDING: u64 = 0x05;
    pub const CRYPTO: u64 = 0x06;
    pub const NEW_TOKEN: u64 = 0x07;
    /// STREAM's base; the low three bits are OFF (4), LEN (2) and FIN (1).
    pub const STREAM: u64 = 0x08;
    pub const STREAM_MAX: u64 = 0x0f;
    pub const MAX_DATA: u64 = 0x10;
    pub const MAX_STREAM_DATA: u64 = 0x11;
    pub const MAX_STREAMS_BIDI: u64 = 0x12;
    pub const MAX_STREAMS_UNI: u64 = 0x13;
    pub const DATA_BLOCKED: u64 = 0x14;
    pub const STREAM_DATA_BLOCKED: u64 = 0x15;
    pub const STREAMS_BLOCKED_BIDI: u64 = 0x16;
    pub const STREAMS_BLOCKED_UNI: u64 = 0x17;
    pub const NEW_CONNECTION_ID: u64 = 0x18;
    pub const RETIRE_CONNECTION_ID: u64 = 0x19;
    pub const PATH_CHALLENGE: u64 = 0x1a;
    pub const PATH_RESPONSE: u64 = 0x1b;
    pub const CONNECTION_CLOSE: u64 = 0x1c;
    pub const CONNECTION_CLOSE_APP: u64 = 0x1d;
    pub const HANDSHAKE_DONE: u64 = 0x1e;
}

/// The number of octets `v`'s varint takes, or `None` above [`VARINT_MAX`].
#[must_use]
pub const fn varint_len(v: u64) -> Option<usize> {
    if v < (1 << 6) {
        Some(1)
    } else if v < (1 << 14) {
        Some(2)
    } else if v < (1 << 30) {
        Some(4)
    } else if v <= VARINT_MAX {
        Some(8)
    } else {
        None
    }
}

/// Appends `v` as a varint in its shortest encoding.
///
/// # Errors
/// `v` is above [`VARINT_MAX`].
pub fn put_varint(out: &mut Vec<u8>, v: u64) -> Result<()> {
    let len = varint_len(v).ok_or_else(|| Error::internal("varint too large"))?;
    put_varint_len(out, v, len)
}

/// Appends `v` as a varint of exactly `len` octets (1, 2, 4 or 8), for fields whose width is
/// fixed before the value is known (a long header's Length).
///
/// # Errors
/// `v` doesn't fit `len` octets, or `len` isn't a varint width.
pub fn put_varint_len(out: &mut Vec<u8>, v: u64, len: usize) -> Result<()> {
    let fits = varint_len(v).is_some_and(|n| n <= len);
    let [b0, b1, b2, b3, b4, b5, b6, b7] = v.to_be_bytes();
    match (len, fits) {
        (1, true) => out.push(b7),
        (2, true) => out.extend_from_slice(&[b6 | 0x40, b7]),
        (4, true) => out.extend_from_slice(&[b4 | 0x80, b5, b6, b7]),
        (8, true) => out.extend_from_slice(&[b0 | 0xc0, b1, b2, b3, b4, b5, b6, b7]),
        _ => return Err(Error::internal("varint width")),
    }
    Ok(())
}

/// A varint read from `r`, with whether its encoding was the shortest.
///
/// # Errors
/// `r` runs out.
pub fn get_varint_minimal(r: &mut Reader<'_>) -> core::result::Result<(u64, bool), DecodeError> {
    let first = r.u8()?;
    let len = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3f);
    let rest = r.take(len.saturating_sub(1))?;
    for &b in rest {
        v = (v << 8) | u64::from(b);
    }
    let minimal = varint_len(v) == Some(len);
    Ok((v, minimal))
}

/// A varint read from `r`.
///
/// # Errors
/// `r` runs out.
pub fn get_varint(r: &mut Reader<'_>) -> core::result::Result<u64, DecodeError> {
    get_varint_minimal(r).map(|(v, _)| v)
}

/// A varint length followed by that many octets.
fn get_vbytes<'a>(r: &mut Reader<'a>) -> core::result::Result<&'a [u8], DecodeError> {
    let n = usize::try_from(get_varint(r)?).map_err(|_| DecodeError)?;
    r.take(n)
}

/// One acknowledged range, `start..=end` (packet numbers).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AckRange {
    /// The lowest acknowledged packet number.
    pub start: u64,
    /// The highest.
    pub end: u64,
}

/// ECN counts of an ACK frame of type 0x03.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EcnCounts {
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}

/// A decoded frame. Borrowed fields point into the packet's plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A run of PADDING octets (one or more).
    Padding(usize),
    Ping,
    Ack {
        /// The ranges, highest first, disjoint and descending.
        ranges: Vec<AckRange>,
        /// The ACK Delay field before the exponent is applied.
        ack_delay: u64,
        ecn: Option<EcnCounts>,
    },
    ResetStream {
        id: u64,
        code: u64,
        final_size: u64,
    },
    StopSending {
        id: u64,
        code: u64,
    },
    Crypto {
        offset: u64,
        data: &'a [u8],
    },
    NewToken {
        token: &'a [u8],
    },
    Stream {
        id: u64,
        offset: u64,
        data: &'a [u8],
        fin: bool,
    },
    MaxData(u64),
    MaxStreamData {
        id: u64,
        max: u64,
    },
    MaxStreams {
        bidi: bool,
        max: u64,
    },
    DataBlocked(u64),
    StreamDataBlocked {
        id: u64,
        limit: u64,
    },
    StreamsBlocked {
        bidi: bool,
        limit: u64,
    },
    NewConnectionId {
        seq: u64,
        retire_prior_to: u64,
        cid: &'a [u8],
        reset_token: [u8; RESET_TOKEN_LEN],
    },
    RetireConnectionId(u64),
    PathChallenge([u8; 8]),
    PathResponse([u8; 8]),
    ConnectionClose {
        /// Type 0x1d (the application's) rather than 0x1c (the transport's).
        app: bool,
        code: u64,
        /// The frame type that caused it (0x1c only; 0 for 0x1d).
        frame_type: u64,
        reason: &'a [u8],
    },
    HandshakeDone,
}

impl Frame<'_> {
    /// The frame's type as the wire carries it (for STREAM, with its flag bits).
    #[must_use]
    pub fn frame_type(&self) -> u64 {
        use frame_type as t;
        match self {
            Self::Padding(_) => t::PADDING,
            Self::Ping => t::PING,
            Self::Ack { ecn, .. } => {
                if ecn.is_some() {
                    t::ACK_ECN
                } else {
                    t::ACK
                }
            }
            Self::ResetStream { .. } => t::RESET_STREAM,
            Self::StopSending { .. } => t::STOP_SENDING,
            Self::Crypto { .. } => t::CRYPTO,
            Self::NewToken { .. } => t::NEW_TOKEN,
            Self::Stream { .. } => t::STREAM,
            Self::MaxData(_) => t::MAX_DATA,
            Self::MaxStreamData { .. } => t::MAX_STREAM_DATA,
            Self::MaxStreams { bidi, .. } => {
                if *bidi {
                    t::MAX_STREAMS_BIDI
                } else {
                    t::MAX_STREAMS_UNI
                }
            }
            Self::DataBlocked(_) => t::DATA_BLOCKED,
            Self::StreamDataBlocked { .. } => t::STREAM_DATA_BLOCKED,
            Self::StreamsBlocked { bidi, .. } => {
                if *bidi {
                    t::STREAMS_BLOCKED_BIDI
                } else {
                    t::STREAMS_BLOCKED_UNI
                }
            }
            Self::NewConnectionId { .. } => t::NEW_CONNECTION_ID,
            Self::RetireConnectionId(_) => t::RETIRE_CONNECTION_ID,
            Self::PathChallenge(_) => t::PATH_CHALLENGE,
            Self::PathResponse(_) => t::PATH_RESPONSE,
            Self::ConnectionClose { app, .. } => {
                if *app {
                    t::CONNECTION_CLOSE_APP
                } else {
                    t::CONNECTION_CLOSE
                }
            }
            Self::HandshakeDone => t::HANDSHAKE_DONE,
        }
    }

    /// Whether the frame elicits an ACK (RFC 9002, section 2): all but PADDING, ACK and
    /// CONNECTION_CLOSE.
    #[must_use]
    pub fn is_ack_eliciting(&self) -> bool {
        !matches!(
            self,
            Self::Padding(_) | Self::Ack { .. } | Self::ConnectionClose { .. }
        )
    }
}

/// The frame type at the front of `r`, without consuming it, and whether its encoding was the
/// shortest (OpenSSL refuses a longer one with PROTOCOL_VIOLATION).
///
/// # Errors
/// The type doesn't decode.
pub fn peek_frame_type(r: &Reader<'_>) -> core::result::Result<(u64, bool), DecodeError> {
    let mut c = Reader::new(r.rest());
    get_varint_minimal(&mut c)
}

/// Decodes one frame from `r`. A frame that doesn't decode is FRAME_ENCODING_ERROR with its
/// type, as `depack_process_frames` raises it; an unknown type is FRAME_ENCODING_ERROR too
/// (RFC 9000, section 12.4).
///
/// # Errors
/// The frame is malformed or unknown.
pub fn decode_frame<'a>(r: &mut Reader<'a>) -> Result<Frame<'a>> {
    use frame_type as t;
    let ty = get_varint(r).map_err(|_| Error::protocol(0, "malformed frame header"))?;
    let bad = || Error::frame_encoding(ty);
    let v = |r: &mut Reader<'a>| get_varint(r).map_err(|_| Error::frame_encoding(ty));
    let frame = match ty {
        t::PADDING => {
            let rest = r.rest();
            let n = rest.iter().take_while(|&&b| b == 0).count();
            let _ = r.take(n).map_err(|_| bad())?;
            Frame::Padding(n.saturating_add(1))
        }
        t::PING => Frame::Ping,
        t::ACK | t::ACK_ECN => {
            let largest = v(r)?;
            let ack_delay = v(r)?;
            let count = v(r)?;
            let first = v(r)?;
            let mut start = largest.checked_sub(first).ok_or_else(bad)?;
            let mut ranges = vec![AckRange {
                start,
                end: largest,
            }];
            for _ in 0..count {
                let gap = v(r)?;
                let len = v(r)?;
                // end = start − gap − 2, and len ≤ end.
                let end = start
                    .checked_sub(gap)
                    .and_then(|x| x.checked_sub(2))
                    .ok_or_else(bad)?;
                start = end.checked_sub(len).ok_or_else(bad)?;
                ranges.push(AckRange { start, end });
            }
            let ecn = if ty == t::ACK_ECN {
                Some(EcnCounts {
                    ect0: v(r)?,
                    ect1: v(r)?,
                    ce: v(r)?,
                })
            } else {
                None
            };
            Frame::Ack {
                ranges,
                ack_delay,
                ecn,
            }
        }
        t::RESET_STREAM => Frame::ResetStream {
            id: v(r)?,
            code: v(r)?,
            final_size: v(r)?,
        },
        t::STOP_SENDING => Frame::StopSending {
            id: v(r)?,
            code: v(r)?,
        },
        t::CRYPTO => {
            let offset = v(r)?;
            let len = v(r)?;
            if offset.checked_add(len).is_none_or(|e| e > VARINT_MAX) {
                return Err(bad());
            }
            let n = usize::try_from(len).map_err(|_| bad())?;
            Frame::Crypto {
                offset,
                data: r.take(n).map_err(|_| bad())?,
            }
        }
        t::NEW_TOKEN => {
            let token = get_vbytes(r).map_err(|_| bad())?;
            // RFC 9000, section 19.7: an empty token is FRAME_ENCODING_ERROR.
            if token.is_empty() {
                return Err(bad());
            }
            Frame::NewToken { token }
        }
        t::STREAM..=t::STREAM_MAX => {
            let id = v(r)?;
            let offset = if ty & 0x04 != 0 { v(r)? } else { 0 };
            let len = if ty & 0x02 != 0 {
                v(r)?
            } else {
                u64::try_from(r.len()).map_err(|_| bad())?
            };
            if offset.checked_add(len).is_none_or(|e| e > VARINT_MAX) {
                return Err(bad());
            }
            let n = usize::try_from(len).map_err(|_| bad())?;
            Frame::Stream {
                id,
                offset,
                data: r.take(n).map_err(|_| bad())?,
                fin: ty & 0x01 != 0,
            }
        }
        t::MAX_DATA => Frame::MaxData(v(r)?),
        t::MAX_STREAM_DATA => Frame::MaxStreamData {
            id: v(r)?,
            max: v(r)?,
        },
        t::MAX_STREAMS_BIDI | t::MAX_STREAMS_UNI => Frame::MaxStreams {
            bidi: ty == t::MAX_STREAMS_BIDI,
            max: v(r)?,
        },
        t::DATA_BLOCKED => Frame::DataBlocked(v(r)?),
        t::STREAM_DATA_BLOCKED => Frame::StreamDataBlocked {
            id: v(r)?,
            limit: v(r)?,
        },
        t::STREAMS_BLOCKED_BIDI | t::STREAMS_BLOCKED_UNI => Frame::StreamsBlocked {
            bidi: ty == t::STREAMS_BLOCKED_BIDI,
            limit: v(r)?,
        },
        t::NEW_CONNECTION_ID => {
            let seq = v(r)?;
            let retire_prior_to = v(r)?;
            if seq < retire_prior_to {
                return Err(bad());
            }
            let len = usize::from(r.u8().map_err(|_| bad())?);
            if !(1..=MAX_CID_LEN).contains(&len) {
                return Err(bad());
            }
            let cid = r.take(len).map_err(|_| bad())?;
            let token = r.take(RESET_TOKEN_LEN).map_err(|_| bad())?;
            let reset_token: [u8; RESET_TOKEN_LEN] = token.try_into().map_err(|_| bad())?;
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                reset_token,
            }
        }
        t::RETIRE_CONNECTION_ID => Frame::RetireConnectionId(v(r)?),
        t::PATH_CHALLENGE | t::PATH_RESPONSE => {
            let d: [u8; 8] = r
                .take(8)
                .map_err(|_| bad())?
                .try_into()
                .map_err(|_| bad())?;
            if ty == t::PATH_CHALLENGE {
                Frame::PathChallenge(d)
            } else {
                Frame::PathResponse(d)
            }
        }
        t::CONNECTION_CLOSE | t::CONNECTION_CLOSE_APP => {
            let app = ty == t::CONNECTION_CLOSE_APP;
            let code = v(r)?;
            let frame_type = if app { 0 } else { v(r)? };
            let reason = get_vbytes(r).map_err(|_| bad())?;
            Frame::ConnectionClose {
                app,
                code,
                frame_type,
                reason,
            }
        }
        t::HANDSHAKE_DONE => Frame::HandshakeDone,
        _ => {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_FRAME_ENCODING_ERROR,
                ty,
                "unknown frame type",
            ));
        }
    };
    Ok(frame)
}

/// Appends `f`'s encoding. A STREAM frame always carries its offset (when non-zero) and an
/// explicit length; [`encode_stream_header`] writes the last-in-packet form.
///
/// # Errors
/// A field is out of range.
pub fn encode_frame(out: &mut Vec<u8>, f: &Frame<'_>) -> Result<()> {
    use frame_type as t;
    match f {
        Frame::Padding(n) => out.resize(out.len().saturating_add(*n), 0),
        Frame::Ping => out.push(0x01),
        Frame::Ack {
            ranges,
            ack_delay,
            ecn,
        } => {
            let first = ranges.first().ok_or_else(|| Error::internal("empty ACK"))?;
            put_varint(out, f.frame_type())?;
            put_varint(out, first.end)?;
            put_varint(out, *ack_delay)?;
            let count = u64::try_from(ranges.len().saturating_sub(1))
                .map_err(|_| Error::internal("ACK ranges"))?;
            put_varint(out, count)?;
            put_varint(
                out,
                first
                    .end
                    .checked_sub(first.start)
                    .ok_or_else(|| Error::internal("ACK range"))?,
            )?;
            let mut prev_start = first.start;
            for rg in ranges.iter().skip(1) {
                let gap = prev_start
                    .checked_sub(rg.end)
                    .and_then(|x| x.checked_sub(2))
                    .ok_or_else(|| Error::internal("ACK gap"))?;
                put_varint(out, gap)?;
                put_varint(
                    out,
                    rg.end
                        .checked_sub(rg.start)
                        .ok_or_else(|| Error::internal("ACK range"))?,
                )?;
                prev_start = rg.start;
            }
            if let Some(e) = ecn {
                put_varint(out, e.ect0)?;
                put_varint(out, e.ect1)?;
                put_varint(out, e.ce)?;
            }
        }
        Frame::ResetStream {
            id,
            code,
            final_size,
        } => {
            put_varint(out, t::RESET_STREAM)?;
            put_varint(out, *id)?;
            put_varint(out, *code)?;
            put_varint(out, *final_size)?;
        }
        Frame::StopSending { id, code } => {
            put_varint(out, t::STOP_SENDING)?;
            put_varint(out, *id)?;
            put_varint(out, *code)?;
        }
        Frame::Crypto { offset, data } => {
            put_varint(out, t::CRYPTO)?;
            put_varint(out, *offset)?;
            put_varint(out, len64(data.len())?)?;
            out.extend_from_slice(data);
        }
        Frame::NewToken { token } => {
            put_varint(out, t::NEW_TOKEN)?;
            put_varint(out, len64(token.len())?)?;
            out.extend_from_slice(token);
        }
        Frame::Stream {
            id,
            offset,
            data,
            fin,
        } => {
            encode_stream_header(out, *id, *offset, data.len(), *fin, true)?;
            out.extend_from_slice(data);
        }
        Frame::MaxData(m) => {
            put_varint(out, t::MAX_DATA)?;
            put_varint(out, *m)?;
        }
        Frame::MaxStreamData { id, max } => {
            put_varint(out, t::MAX_STREAM_DATA)?;
            put_varint(out, *id)?;
            put_varint(out, *max)?;
        }
        Frame::MaxStreams { max, .. } => {
            put_varint(out, f.frame_type())?;
            put_varint(out, *max)?;
        }
        Frame::DataBlocked(l) => {
            put_varint(out, t::DATA_BLOCKED)?;
            put_varint(out, *l)?;
        }
        Frame::StreamDataBlocked { id, limit } => {
            put_varint(out, t::STREAM_DATA_BLOCKED)?;
            put_varint(out, *id)?;
            put_varint(out, *limit)?;
        }
        Frame::StreamsBlocked { limit, .. } => {
            put_varint(out, f.frame_type())?;
            put_varint(out, *limit)?;
        }
        Frame::NewConnectionId {
            seq,
            retire_prior_to,
            cid,
            reset_token,
        } => {
            put_varint(out, t::NEW_CONNECTION_ID)?;
            put_varint(out, *seq)?;
            put_varint(out, *retire_prior_to)?;
            out.push(u8::try_from(cid.len()).map_err(|_| Error::internal("CID length"))?);
            out.extend_from_slice(cid);
            out.extend_from_slice(reset_token);
        }
        Frame::RetireConnectionId(s) => {
            put_varint(out, t::RETIRE_CONNECTION_ID)?;
            put_varint(out, *s)?;
        }
        Frame::PathChallenge(d) => {
            put_varint(out, t::PATH_CHALLENGE)?;
            out.extend_from_slice(d);
        }
        Frame::PathResponse(d) => {
            put_varint(out, t::PATH_RESPONSE)?;
            out.extend_from_slice(d);
        }
        Frame::ConnectionClose {
            app,
            code,
            frame_type,
            reason,
        } => {
            put_varint(out, f.frame_type())?;
            put_varint(out, *code)?;
            if !app {
                put_varint(out, *frame_type)?;
            }
            put_varint(out, len64(reason.len())?)?;
            out.extend_from_slice(reason);
        }
        Frame::HandshakeDone => out.push(0x1e),
    }
    Ok(())
}

/// Appends a STREAM frame's header for `len` octets at `offset`. With `explicit_len` false the
/// frame runs to the packet's end.
///
/// # Errors
/// A field is out of range.
pub fn encode_stream_header(
    out: &mut Vec<u8>,
    id: u64,
    offset: u64,
    len: usize,
    fin: bool,
    explicit_len: bool,
) -> Result<()> {
    let mut ty = frame_type::STREAM;
    if offset != 0 {
        ty |= 0x04;
    }
    if explicit_len {
        ty |= 0x02;
    }
    if fin {
        ty |= 0x01;
    }
    put_varint(out, ty)?;
    put_varint(out, id)?;
    if offset != 0 {
        put_varint(out, offset)?;
    }
    if explicit_len {
        put_varint(out, len64(len)?)?;
    }
    Ok(())
}

/// The STREAM header's length for these fields.
#[must_use]
pub fn stream_header_len(id: u64, offset: u64, len: usize, explicit_len: bool) -> usize {
    let l = |v: u64| varint_len(v).unwrap_or(8);
    let mut n = 1usize.saturating_add(l(id));
    if offset != 0 {
        n = n.saturating_add(l(offset));
    }
    if explicit_len {
        n = n.saturating_add(l(u64::try_from(len).unwrap_or(u64::MAX)));
    }
    n
}

/// The CRYPTO header's length for these fields.
#[must_use]
pub fn crypto_header_len(offset: u64, len: usize) -> usize {
    let l = |v: u64| varint_len(v).unwrap_or(8);
    1usize
        .saturating_add(l(offset))
        .saturating_add(l(u64::try_from(len).unwrap_or(u64::MAX)))
}

fn len64(n: usize) -> Result<u64> {
    u64::try_from(n).map_err(|_| Error::internal("length"))
}

/// Transport parameter ids (RFC 9000, section 18.2).
pub mod tparam {
    pub const ORIGINAL_DCID: u64 = 0x00;
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    pub const INITIAL_SCID: u64 = 0x0f;
    pub const RETRY_SCID: u64 = 0x10;
}

/// A connection ID (at most 20 octets).
#[derive(Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConnId {
    len: u8,
    id: [u8; MAX_CID_LEN],
}

impl core::fmt::Debug for ConnId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ConnId(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

impl ConnId {
    /// The ID with these octets.
    ///
    /// # Errors
    /// `b` is longer than 20 octets.
    pub fn new(b: &[u8]) -> Result<Self> {
        if b.len() > MAX_CID_LEN {
            return Err(Error::protocol(0, "connection ID too long"));
        }
        let mut id = [0u8; MAX_CID_LEN];
        id.get_mut(..b.len())
            .ok_or_else(|| Error::internal("CID"))?
            .copy_from_slice(b);
        Ok(Self {
            len: u8::try_from(b.len()).map_err(|_| Error::internal("CID"))?,
            id,
        })
    }

    /// Its octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.id.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Its length.
    #[must_use]
    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    /// Whether it's zero-length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A preferred address (section 18.2), kept as received; OpenSSL never migrates to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreferredAddress {
    pub raw: Vec<u8>,
    pub cid: ConnId,
    pub reset_token: [u8; RESET_TOKEN_LEN],
}

/// Transport parameters (section 18.2), with RFC 9000's defaults for absent ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportParams {
    pub original_dcid: Option<ConnId>,
    /// Milliseconds; 0 means none.
    pub max_idle_timeout: u64,
    pub stateless_reset_token: Option<[u8; RESET_TOKEN_LEN]>,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u64,
    /// Milliseconds.
    pub max_ack_delay: u64,
    pub disable_active_migration: bool,
    pub preferred_address: Option<PreferredAddress>,
    pub active_connection_id_limit: u64,
    pub initial_scid: Option<ConnId>,
    pub retry_scid: Option<ConnId>,
}

impl Default for TransportParams {
    fn default() -> Self {
        Self {
            original_dcid: None,
            max_idle_timeout: 0,
            stateless_reset_token: None,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay: 25,
            disable_active_migration: false,
            preferred_address: None,
            active_connection_id_limit: 2,
            initial_scid: None,
            retry_scid: None,
        }
    }
}

/// The most transport parameters a peer may send (ours; RFC 9000 has no cap and a peer may
/// grease unknown ones). OpenSSL bounds them only by the extension's length.
pub const MAX_TRANSPORT_PARAMS: usize = 256;

impl TransportParams {
    /// Encodes the parameters in id order, each only where it differs from its default (or is
    /// required).
    ///
    /// # Errors
    /// A value is out of range.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let d = Self::default();
        let mut out = Vec::new();
        let put_int = |out: &mut Vec<u8>, id: u64, v: u64, dv: u64| -> Result<()> {
            if v == dv {
                return Ok(());
            }
            put_varint(out, id)?;
            put_varint(
                out,
                u64::try_from(varint_len(v).ok_or_else(|| Error::internal("tparam"))?)
                    .map_err(|_| Error::internal("tparam"))?,
            )?;
            put_varint(out, v)
        };
        let put_bytes = |out: &mut Vec<u8>, id: u64, v: &[u8]| -> Result<()> {
            put_varint(out, id)?;
            put_varint(out, len64(v.len())?)?;
            out.extend_from_slice(v);
            Ok(())
        };
        if let Some(c) = &self.original_dcid {
            put_bytes(&mut out, tparam::ORIGINAL_DCID, c.as_bytes())?;
        }
        put_int(
            &mut out,
            tparam::MAX_IDLE_TIMEOUT,
            self.max_idle_timeout,
            d.max_idle_timeout,
        )?;
        if let Some(t) = &self.stateless_reset_token {
            put_bytes(&mut out, tparam::STATELESS_RESET_TOKEN, t)?;
        }
        put_int(
            &mut out,
            tparam::MAX_UDP_PAYLOAD_SIZE,
            self.max_udp_payload_size,
            d.max_udp_payload_size,
        )?;
        put_int(&mut out, tparam::INITIAL_MAX_DATA, self.initial_max_data, 0)?;
        put_int(
            &mut out,
            tparam::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
            0,
        )?;
        put_int(
            &mut out,
            tparam::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
            self.initial_max_stream_data_bidi_remote,
            0,
        )?;
        put_int(
            &mut out,
            tparam::INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
            0,
        )?;
        put_int(
            &mut out,
            tparam::INITIAL_MAX_STREAMS_BIDI,
            self.initial_max_streams_bidi,
            0,
        )?;
        put_int(
            &mut out,
            tparam::INITIAL_MAX_STREAMS_UNI,
            self.initial_max_streams_uni,
            0,
        )?;
        put_int(
            &mut out,
            tparam::ACK_DELAY_EXPONENT,
            self.ack_delay_exponent,
            d.ack_delay_exponent,
        )?;
        put_int(
            &mut out,
            tparam::MAX_ACK_DELAY,
            self.max_ack_delay,
            d.max_ack_delay,
        )?;
        if self.disable_active_migration {
            put_varint(&mut out, tparam::DISABLE_ACTIVE_MIGRATION)?;
            put_varint(&mut out, 0)?;
        }
        if let Some(p) = &self.preferred_address {
            put_bytes(&mut out, tparam::PREFERRED_ADDRESS, &p.raw)?;
        }
        put_int(
            &mut out,
            tparam::ACTIVE_CONNECTION_ID_LIMIT,
            self.active_connection_id_limit,
            d.active_connection_id_limit,
        )?;
        if let Some(c) = &self.initial_scid {
            put_bytes(&mut out, tparam::INITIAL_SCID, c.as_bytes())?;
        }
        if let Some(c) = &self.retry_scid {
            put_bytes(&mut out, tparam::RETRY_SCID, c.as_bytes())?;
        }
        Ok(out)
    }

    /// Decodes a peer's parameters, checking each one (section 18.2 and 7.4.1): duplicates,
    /// lengths, ranges, and the parameters only a server may send (`from_server` false refuses
    /// them). Unknown ids are skipped.
    ///
    /// # Errors
    /// TRANSPORT_PARAMETER_ERROR with OpenSSL's reason.
    pub fn decode(data: &[u8], from_server: bool) -> Result<Self> {
        let mut p = Self::default();
        let mut seen: Vec<u64> = Vec::new();
        let mut r = Reader::new(data);
        let malformed = || Error::transport_param("malformed transport parameter");
        while !r.is_empty() {
            if seen.len() >= MAX_TRANSPORT_PARAMS {
                return Err(Error::transport_param("too many transport parameters"));
            }
            let id = get_varint(&mut r).map_err(|_| malformed())?;
            let body = get_vbytes(&mut r).map_err(|_| malformed())?;
            if seen.contains(&id) {
                return Err(Error::transport_param("duplicate transport parameter"));
            }
            seen.push(id);
            let int = || -> Result<u64> {
                let mut b = Reader::new(body);
                let v = get_varint(&mut b).map_err(|_| malformed())?;
                if !b.is_empty() {
                    return Err(malformed());
                }
                Ok(v)
            };
            let cid = || -> Result<ConnId> {
                ConnId::new(body).map_err(|_| Error::transport_param("bad connection ID"))
            };
            let server_only = |id| -> Result<()> {
                if from_server {
                    Ok(())
                } else {
                    let _ = id;
                    Err(Error::transport_param("server-only transport parameter"))
                }
            };
            match id {
                tparam::ORIGINAL_DCID => {
                    server_only(id)?;
                    p.original_dcid = Some(cid()?);
                }
                tparam::MAX_IDLE_TIMEOUT => p.max_idle_timeout = int()?,
                tparam::STATELESS_RESET_TOKEN => {
                    server_only(id)?;
                    p.stateless_reset_token = Some(body.try_into().map_err(|_| malformed())?);
                }
                tparam::MAX_UDP_PAYLOAD_SIZE => {
                    let v = int()?;
                    if v < 1200 {
                        return Err(Error::transport_param("max_udp_payload_size below 1200"));
                    }
                    p.max_udp_payload_size = v;
                }
                tparam::INITIAL_MAX_DATA => p.initial_max_data = int()?,
                tparam::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    p.initial_max_stream_data_bidi_local = int()?;
                }
                tparam::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    p.initial_max_stream_data_bidi_remote = int()?;
                }
                tparam::INITIAL_MAX_STREAM_DATA_UNI => p.initial_max_stream_data_uni = int()?,
                tparam::INITIAL_MAX_STREAMS_BIDI | tparam::INITIAL_MAX_STREAMS_UNI => {
                    let v = int()?;
                    if v > (1 << 60) {
                        return Err(Error::transport_param("initial_max_streams too large"));
                    }
                    if id == tparam::INITIAL_MAX_STREAMS_BIDI {
                        p.initial_max_streams_bidi = v;
                    } else {
                        p.initial_max_streams_uni = v;
                    }
                }
                tparam::ACK_DELAY_EXPONENT => {
                    let v = int()?;
                    if v > 20 {
                        return Err(Error::transport_param("ack_delay_exponent above 20"));
                    }
                    p.ack_delay_exponent = v;
                }
                tparam::MAX_ACK_DELAY => {
                    let v = int()?;
                    if v >= (1 << 14) {
                        return Err(Error::transport_param("max_ack_delay too large"));
                    }
                    p.max_ack_delay = v;
                }
                tparam::DISABLE_ACTIVE_MIGRATION => {
                    if !body.is_empty() {
                        return Err(malformed());
                    }
                    p.disable_active_migration = true;
                }
                tparam::PREFERRED_ADDRESS => {
                    server_only(id)?;
                    // IPv4 (4+2) + IPv6 (16+2) + CID length + CID + reset token.
                    let mut b = Reader::new(body);
                    let _ = b.take(24).map_err(|_| malformed())?;
                    let len = usize::from(b.u8().map_err(|_| malformed())?);
                    if !(1..=MAX_CID_LEN).contains(&len) {
                        return Err(malformed());
                    }
                    let c = ConnId::new(b.take(len).map_err(|_| malformed())?)?;
                    let tok: [u8; RESET_TOKEN_LEN] = b
                        .take(RESET_TOKEN_LEN)
                        .map_err(|_| malformed())?
                        .try_into()
                        .map_err(|_| malformed())?;
                    if !b.is_empty() {
                        return Err(malformed());
                    }
                    p.preferred_address = Some(PreferredAddress {
                        raw: body.to_vec(),
                        cid: c,
                        reset_token: tok,
                    });
                }
                tparam::ACTIVE_CONNECTION_ID_LIMIT => {
                    let v = int()?;
                    if v < 2 {
                        return Err(Error::transport_param("active_connection_id_limit below 2"));
                    }
                    p.active_connection_id_limit = v;
                }
                tparam::INITIAL_SCID => p.initial_scid = Some(cid()?),
                tparam::RETRY_SCID => {
                    server_only(id)?;
                    p.retry_scid = Some(cid()?);
                }
                _ => {}
            }
        }
        if p.initial_scid.is_none() {
            return Err(Error::transport_param(
                "initial_source_connection_id missing",
            ));
        }
        if from_server && p.original_dcid.is_none() {
            return Err(Error::transport_param(
                "original_destination_connection_id missing",
            ));
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, reason = "test code")]

    use super::*;

    fn varint_bytes(v: u64) -> Vec<u8> {
        let mut o = Vec::new();
        put_varint(&mut o, v).unwrap();
        o
    }

    #[test]
    fn rfc9000_appendix_a1_varints() {
        // RFC 9000, Appendix A.1's examples.
        let cases: &[(&[u8], u64)] = &[
            (
                &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c],
                151_288_809_941_952_652,
            ),
            (&[0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
            (&[0x7b, 0xbd], 15_293),
            (&[0x25], 37),
        ];
        for (enc, v) in cases {
            let mut r = Reader::new(enc);
            assert_eq!(get_varint_minimal(&mut r).unwrap(), (*v, true));
            assert_eq!(&varint_bytes(*v), enc);
        }
        // 37 in two octets decodes, but not minimally.
        let mut r = Reader::new(&[0x40, 0x25]);
        assert_eq!(get_varint_minimal(&mut r).unwrap(), (37, false));
        assert!(put_varint(&mut Vec::new(), VARINT_MAX + 1).is_err());
        let mut o = Vec::new();
        put_varint_len(&mut o, 5, 2).unwrap();
        assert_eq!(o, [0x40, 0x05]);
    }

    fn round_trip(f: &Frame<'_>) {
        let mut b = Vec::new();
        encode_frame(&mut b, f).unwrap();
        let mut r = Reader::new(&b);
        let g = decode_frame(&mut r).unwrap();
        assert!(r.is_empty(), "{f:?}");
        assert_eq!(&g, f);
    }

    #[test]
    fn frames_round_trip() {
        let frames = [
            Frame::Ping,
            Frame::Ack {
                ranges: vec![
                    AckRange {
                        start: 90,
                        end: 100,
                    },
                    AckRange { start: 50, end: 80 },
                    AckRange { start: 0, end: 10 },
                ],
                ack_delay: 7,
                ecn: None,
            },
            Frame::Ack {
                ranges: vec![AckRange { start: 3, end: 3 }],
                ack_delay: 0,
                ecn: Some(EcnCounts {
                    ect0: 1,
                    ect1: 2,
                    ce: 3,
                }),
            },
            Frame::ResetStream {
                id: 4,
                code: 5,
                final_size: 6,
            },
            Frame::StopSending { id: 8, code: 9 },
            Frame::Crypto {
                offset: 1000,
                data: b"hello",
            },
            Frame::NewToken { token: b"tok" },
            Frame::Stream {
                id: 0,
                offset: 0,
                data: b"abc",
                fin: false,
            },
            Frame::Stream {
                id: 3,
                offset: 77,
                data: b"",
                fin: true,
            },
            Frame::MaxData(1 << 40),
            Frame::MaxStreamData { id: 1, max: 2 },
            Frame::MaxStreams {
                bidi: true,
                max: 100,
            },
            Frame::MaxStreams {
                bidi: false,
                max: 0,
            },
            Frame::DataBlocked(9),
            Frame::StreamDataBlocked { id: 1, limit: 2 },
            Frame::StreamsBlocked {
                bidi: false,
                limit: 3,
            },
            Frame::NewConnectionId {
                seq: 2,
                retire_prior_to: 1,
                cid: &[1, 2, 3, 4, 5, 6, 7, 8],
                reset_token: [9; 16],
            },
            Frame::RetireConnectionId(1),
            Frame::PathChallenge([1; 8]),
            Frame::PathResponse([2; 8]),
            Frame::ConnectionClose {
                app: false,
                code: 10,
                frame_type: 6,
                reason: b"why",
            },
            Frame::ConnectionClose {
                app: true,
                code: 0,
                frame_type: 0,
                reason: b"",
            },
            Frame::HandshakeDone,
        ];
        for f in &frames {
            round_trip(f);
        }
    }

    #[test]
    fn padding_runs_are_one_frame() {
        let mut r = Reader::new(&[0, 0, 0, 1]);
        assert_eq!(decode_frame(&mut r).unwrap(), Frame::Padding(3));
        assert_eq!(decode_frame(&mut r).unwrap(), Frame::Ping);
    }

    #[test]
    fn malformed_frames_are_refused() {
        let enc = rustyssl_abi::OSSL_QUIC_ERR_FRAME_ENCODING_ERROR;
        let cases: &[&[u8]] = &[
            // ACK whose first range goes below 0.
            &[0x02, 0x05, 0x00, 0x00, 0x06],
            // ACK whose gap goes below 0.
            &[0x02, 0x05, 0x00, 0x01, 0x00, 0x05, 0x00],
            // NEW_CONNECTION_ID with retire_prior_to above seq.
            &[0x18, 0x01, 0x02, 0x01, 0xaa],
            // NEW_CONNECTION_ID with a 21-octet ID.
            &[0x18, 0x01, 0x00, 21],
            // NEW_TOKEN with an empty token.
            &[0x07, 0x00],
            // CRYPTO longer than the packet.
            &[0x06, 0x00, 0x05, 0x01],
            // An unknown frame type.
            &[0x21],
        ];
        for c in cases {
            let e = decode_frame(&mut Reader::new(c)).unwrap_err();
            assert_eq!(e.code, crate::error::code(enc), "{c:02x?}");
        }
        // A STREAM frame whose end passes 2^62 − 1.
        let mut b = vec![0x0e, 0x00];
        put_varint(&mut b, VARINT_MAX).unwrap();
        b.push(0x01);
        b.push(0xff);
        assert!(decode_frame(&mut Reader::new(&b)).is_err());
    }

    #[test]
    fn transport_params_round_trip_and_checks() {
        let p = TransportParams {
            original_dcid: Some(ConnId::new(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap()),
            max_idle_timeout: 30_000,
            initial_max_data: 768 * 1024,
            initial_max_streams_bidi: 100,
            disable_active_migration: true,
            initial_scid: Some(ConnId::new(&[9; 8]).unwrap()),
            ..TransportParams::default()
        };
        let b = p.encode().unwrap();
        assert_eq!(TransportParams::decode(&b, true).unwrap(), p);
        // A client may not send original_destination_connection_id.
        assert!(TransportParams::decode(&b, false).is_err());
        // Duplicates are refused.
        let mut dup = b.clone();
        dup.extend_from_slice(&[0x04, 0x01, 0x05]);
        dup.extend_from_slice(&[0x04, 0x01, 0x05]);
        assert!(TransportParams::decode(&dup, true).is_err());
        // initial_source_connection_id is required.
        let q = TransportParams {
            initial_scid: None,
            ..p.clone()
        };
        assert!(TransportParams::decode(&q.encode().unwrap(), true).is_err());
        // An ack_delay_exponent above 20.
        let mut bad = p.encode().unwrap();
        bad.extend_from_slice(&[0x0a, 0x01, 21]);
        assert!(TransportParams::decode(&bad, true).is_err());
    }
}
