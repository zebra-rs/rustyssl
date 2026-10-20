//! Streams (RFC 9000, sections 2–3), after OpenSSL's `quic_stream_map.c`, `quic_sstream.c` and
//! `quic_rstream.c`: send buffers that retransmit what was lost, receive buffers that reassemble
//! within the flow-control window, each part's state machine, implicit stream creation, stream
//! limits in both directions, the accept queue, and garbage collection of finished streams.
//!
//! The same buffers carry the CRYPTO streams ([`CryptoStream`]).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::error::{Error, Result};
use crate::fc::{RxFc, TxFc};
use crate::time::{Duration, Time};
use crate::wire::frame_type as ft;

/// The most bytes a send buffer holds unacknowledged (OpenSSL's `MAX_WRITE_BUF_SIZE`).
pub const MAX_SEND_BUF: usize = 6 * 1024 * 1024;
/// The most separate gaps a receive buffer tracks (ours; flow control bounds the octets, this
/// bounds the fragments a peer can scatter within them).
pub const MAX_RECV_FRAGMENTS: usize = 8192;
/// OpenSSL's initial connection receive window and its growth limit.
pub const DEFAULT_INIT_CONN_RXFC_WND: u64 = 768 * 1024;
pub const DEFAULT_CONN_RXFC_MAX_WND_MUL: u64 = 20;
/// OpenSSL's initial stream receive window and its growth limit.
pub const DEFAULT_INIT_STREAM_RXFC_WND: u64 = 512 * 1024;
pub const DEFAULT_STREAM_RXFC_MAX_WND_MUL: u64 = 12;
/// OpenSSL's initial MAX_STREAMS in each direction.
pub const DEFAULT_INIT_CONN_MAX_STREAMS: u64 = 100;
/// The CRYPTO receive window per space (OpenSSL's `INIT_CRYPTO_RECV_BUF_LEN`).
pub const CRYPTO_RECV_WINDOW: u64 = 16384;
/// The largest stream count MAX_STREAMS may carry (2^60).
pub const MAX_STREAM_COUNT: u64 = 1 << 60;

/// Disjoint, ascending half-open ranges of offsets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RangeSet(Vec<(u64, u64)>);

impl RangeSet {
    /// Adds `start..end`.
    pub fn insert(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let (mut s, mut e) = (start, end);
        let first = self.0.partition_point(|&(_, re)| re < s);
        let mut last = first;
        while let Some(&(rs, re)) = self.0.get(last) {
            if rs > e {
                break;
            }
            s = s.min(rs);
            e = e.max(re);
            last = last.saturating_add(1);
        }
        self.0.splice(first..last, [(s, e)]);
    }

    /// Removes `start..end`.
    pub fn remove(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut out = Vec::with_capacity(self.0.len().saturating_add(1));
        for &(rs, re) in &self.0 {
            if re <= start || rs >= end {
                out.push((rs, re));
                continue;
            }
            if rs < start {
                out.push((rs, start));
            }
            if re > end {
                out.push((end, re));
            }
        }
        self.0 = out;
    }

    /// The first range.
    #[must_use]
    pub fn first(&self) -> Option<(u64, u64)> {
        self.0.first().copied()
    }

    /// Whether it's empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The number of ranges.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether `start..end` is entirely covered.
    #[must_use]
    pub fn covers(&self, start: u64, end: u64) -> bool {
        start >= end || self.0.iter().any(|&(rs, re)| rs <= start && end <= re)
    }
}

/// One STREAM or CRYPTO frame's worth of data to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub offset: u64,
    pub data: Vec<u8>,
    pub fin: bool,
}

/// A send buffer: what the application wrote, until the peer acknowledges it.
#[derive(Clone, Debug, Default)]
pub struct SendBuf {
    /// Unacknowledged data from `base`.
    data: VecDeque<u8>,
    /// The offset of `data`'s first octet (everything below is acknowledged).
    base: u64,
    /// The offset after the last octet sent for the first time.
    sent_end: u64,
    /// Ranges sent and acknowledged above `base`.
    acked: RangeSet,
    /// Ranges sent and lost, to send again.
    lost: RangeSet,
    fin: bool,
    fin_sent: bool,
    fin_acked: bool,
    fin_lost: bool,
    cap: usize,
}

impl SendBuf {
    /// A buffer holding up to `cap` unacknowledged octets.
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            ..Self::default()
        }
    }

    /// The offset after the last octet written.
    #[must_use]
    pub fn write_end(&self) -> u64 {
        self.base
            .saturating_add(u64::try_from(self.data.len()).unwrap_or(u64::MAX))
    }

    /// The offset after the last octet sent (the final size once reset).
    #[must_use]
    pub fn sent_end(&self) -> u64 {
        self.sent_end
    }

    /// Room for more writes.
    #[must_use]
    pub fn space(&self) -> usize {
        if self.fin {
            return 0;
        }
        self.cap.saturating_sub(self.data.len())
    }

    /// Appends what fits of `data`; returns how much.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.space());
        self.data.extend(data.iter().take(n));
        n
    }

    /// Marks the end of the stream.
    pub fn finish(&mut self) {
        self.fin = true;
    }

    /// Whether the end was marked.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.fin
    }

    /// Whether there's anything to send (new data up to `limit`, a retransmission, or a FIN).
    #[must_use]
    pub fn has_pending(&self, limit: u64) -> bool {
        !self.lost.is_empty()
            || (self.sent_end < self.write_end() && self.sent_end < limit)
            || (self.fin && (!self.fin_sent || self.fin_lost) && self.sent_end == self.write_end())
    }

    fn slice(&self, offset: u64, len: usize) -> Vec<u8> {
        let skip = usize::try_from(offset.saturating_sub(self.base)).unwrap_or(usize::MAX);
        self.data.iter().skip(skip).take(len).copied().collect()
    }

    /// The next chunk of at most `max_len` octets: lost data first, then new data below
    /// `limit` (the flow-control limit). New data counts as sent.
    pub fn next_chunk(&mut self, max_len: usize, limit: u64) -> Option<Chunk> {
        let max = u64::try_from(max_len).unwrap_or(u64::MAX);
        if let Some((s, e)) = self.lost.first() {
            let end = e.min(s.saturating_add(max));
            if end > s || (max_len == 0 && self.fin_lost && e == self.write_end()) {
                self.lost.remove(s, end);
                let len = usize::try_from(end.saturating_sub(s)).unwrap_or(0);
                let fin = self.fin && end == self.write_end() && self.fin_lost;
                if fin {
                    self.fin_lost = false;
                }
                return Some(Chunk {
                    offset: s,
                    data: self.slice(s, len),
                    fin,
                });
            }
            if max_len == 0 {
                return None;
            }
        }
        let end = self
            .write_end()
            .min(limit)
            .min(self.sent_end.saturating_add(max));
        let fin = self.fin && end == self.write_end() && (!self.fin_sent || self.fin_lost);
        if end <= self.sent_end && !fin {
            return None;
        }
        let start = self.sent_end;
        let len = usize::try_from(end.saturating_sub(start)).unwrap_or(0);
        self.sent_end = self.sent_end.max(end);
        if fin {
            self.fin_sent = true;
            self.fin_lost = false;
        }
        Some(Chunk {
            offset: start,
            data: self.slice(start, len),
            fin,
        })
    }

    /// `offset..offset+len` (with the FIN if `fin`) was acknowledged.
    pub fn on_acked(&mut self, offset: u64, len: u64, fin: bool) {
        let end = offset.saturating_add(len);
        self.acked.insert(offset.max(self.base), end);
        self.lost.remove(offset, end);
        if fin {
            self.fin_acked = true;
            self.fin_lost = false;
        }
        while let Some((s, e)) = self.acked.first() {
            if s > self.base {
                break;
            }
            let drop = usize::try_from(e.saturating_sub(self.base)).unwrap_or(usize::MAX);
            let drop = drop.min(self.data.len());
            self.data.drain(..drop);
            self.base = e;
            self.acked.remove(s, e);
        }
    }

    /// `offset..offset+len` (with the FIN if `fin`) was lost.
    pub fn on_lost(&mut self, offset: u64, len: u64, fin: bool) {
        let start = offset.max(self.base);
        let end = offset.saturating_add(len).min(self.sent_end);
        if start < end {
            self.lost.insert(start, end);
            // Never resend what was acknowledged meanwhile.
            for (s, e) in self.acked.0.clone() {
                self.lost.remove(s, e);
            }
        }
        if fin && !self.fin_acked {
            self.fin_lost = true;
        }
    }

    /// Whether everything written, and the FIN, was acknowledged.
    #[must_use]
    pub fn is_totally_acked(&self) -> bool {
        self.data.is_empty() && self.base == self.sent_end && self.fin && self.fin_acked
    }

    /// Whether everything (and the FIN) has been sent at least once.
    #[must_use]
    pub fn all_sent(&self) -> bool {
        self.fin && self.fin_sent && self.sent_end == self.write_end()
    }

    /// Drops the data (the stream was reset).
    pub fn discard(&mut self) {
        self.data.clear();
        self.lost = RangeSet::default();
        self.acked = RangeSet::default();
    }
}

/// A receive buffer: data reassembled in order.
#[derive(Clone, Debug, Default)]
pub struct RecvBuf {
    /// Fragments by offset, disjoint, at or above `read`.
    frags: BTreeMap<u64, Vec<u8>>,
    /// Octets before this were read.
    read: u64,
    final_size: Option<u64>,
}

impl RecvBuf {
    /// Queues `data` at `offset`, trimming what was read or is already held.
    ///
    /// # Errors
    /// The data would scatter into too many fragments (INTERNAL_ERROR, our own bound).
    pub fn insert(&mut self, offset: u64, data: &[u8], frame_type: u64) -> Result<()> {
        let end = offset.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        let mut pos = offset.max(self.read);
        while pos < end {
            // The fragment at or before pos, if it covers pos, skips us past it.
            if let Some((&fs, f)) = self.frags.range(..=pos).next_back() {
                let fe = fs.saturating_add(u64::try_from(f.len()).unwrap_or(u64::MAX));
                if fe > pos {
                    pos = fe;
                    continue;
                }
            }
            // A gap until the next fragment (or the end).
            let gap_end = self
                .frags
                .range(pos..)
                .next()
                .map_or(end, |(&ns, _)| ns.min(end));
            if self.frags.len() >= MAX_RECV_FRAGMENTS {
                return Err(Error::new(
                    rustyssl_abi::OSSL_QUIC_ERR_INTERNAL_ERROR,
                    frame_type,
                    "internal error (rstream queue)",
                ));
            }
            let from = usize::try_from(pos.saturating_sub(offset)).unwrap_or(usize::MAX);
            let to = usize::try_from(gap_end.saturating_sub(offset)).unwrap_or(usize::MAX);
            if let Some(piece) = data.get(from..to) {
                self.frags.insert(pos, piece.to_vec());
            }
            pos = gap_end;
        }
        Ok(())
    }

    /// Sets the final size.
    pub fn set_final_size(&mut self, size: u64) {
        self.final_size = Some(size);
    }

    /// Octets readable in order now.
    #[must_use]
    pub fn available(&self) -> u64 {
        let mut pos = self.read;
        for (&s, f) in self.frags.range(self.read..) {
            if s != pos {
                break;
            }
            pos = pos.saturating_add(u64::try_from(f.len()).unwrap_or(u64::MAX));
        }
        pos.saturating_sub(self.read)
    }

    /// Whether every octet up to the final size has arrived.
    #[must_use]
    pub fn all_received(&self) -> bool {
        self.final_size
            .is_some_and(|f| self.read.saturating_add(self.available()) == f)
    }

    /// Reads into `buf`; returns the octets read and whether the end was reached.
    pub fn read(&mut self, buf: &mut [u8]) -> (usize, bool) {
        let mut n = 0usize;
        while n < buf.len() {
            let Some(mut f) = self.frags.remove(&self.read) else {
                break;
            };
            let room = buf.len().saturating_sub(n);
            let take = room.min(f.len());
            if let (Some(dst), Some(src)) = (buf.get_mut(n..n.saturating_add(take)), f.get(..take))
            {
                dst.copy_from_slice(src);
            }
            n = n.saturating_add(take);
            self.read = self
                .read
                .saturating_add(u64::try_from(take).unwrap_or(u64::MAX));
            if take < f.len() {
                f.drain(..take);
                self.frags.insert(self.read, f);
                break;
            }
        }
        (n, self.final_size == Some(self.read))
    }

    /// The offset read so far.
    #[must_use]
    pub fn read_offset(&self) -> u64 {
        self.read
    }
}

/// A CRYPTO stream of one packet number space.
#[derive(Clone, Debug)]
pub struct CryptoStream {
    pub send: SendBuf,
    pub recv: RecvBuf,
    pub rxfc: RxFc,
}

impl Default for CryptoStream {
    fn default() -> Self {
        Self {
            send: SendBuf::new(usize::MAX),
            recv: RecvBuf::default(),
            rxfc: RxFc::standalone(CRYPTO_RECV_WINDOW),
        }
    }
}

impl CryptoStream {
    /// A CRYPTO frame arrived.
    ///
    /// # Errors
    /// It exceeds the buffer (CRYPTO_BUFFER_EXCEEDED, as OpenSSL), or reassembly failed.
    pub fn on_frame(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = offset.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        self.rxfc.on_rx_stream_frame(None, end, false);
        if self.rxfc.error(None).is_some() {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_CRYPTO_BUFFER_EXCEEDED,
                ft::CRYPTO,
                "exceeded maximum crypto buffer",
            ));
        }
        self.recv.insert(offset, data, ft::CRYPTO)
    }

    /// Takes everything readable in order (to hand to TLS).
    pub fn take_readable(&mut self, now: Time) -> Vec<u8> {
        let n = usize::try_from(self.recv.available()).unwrap_or(0);
        let mut v = vec![0u8; n];
        let (got, _) = self.recv.read(&mut v);
        v.truncate(got);
        let _ = self
            .rxfc
            .on_retire(None, u64::try_from(got).unwrap_or(0), now, Duration::ZERO);
        v
    }
}

/// A stream's send part state (RFC 9000, section 3.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendState {
    Ready,
    Send,
    DataSent,
    DataRecvd,
    ResetSent,
    ResetRecvd,
}

/// A stream's receive part state (RFC 9000, section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvState {
    Recv,
    SizeKnown,
    DataRecvd,
    DataRead,
    ResetRecvd,
    ResetRead,
}

/// The send part of a stream.
#[derive(Clone, Debug)]
pub struct SendPart {
    pub state: SendState,
    pub buf: SendBuf,
    pub fc: TxFc,
    /// RESET_STREAM's code once reset.
    pub reset_code: Option<u64>,
    want_reset: bool,
    want_blocked: bool,
    /// STOP_SENDING's code if the peer sent one.
    pub peer_stop_sending: Option<u64>,
}

/// The receive part of a stream.
#[derive(Clone, Debug)]
pub struct RecvPart {
    pub state: RecvState,
    pub buf: RecvBuf,
    pub fc: RxFc,
    /// The peer's RESET_STREAM code.
    pub reset_code: Option<u64>,
    /// Our STOP_SENDING code once requested.
    pub stop_sending: Option<u64>,
    want_stop_sending: bool,
    stop_sending_acked: bool,
    want_max_stream_data: bool,
}

/// A stream.
#[derive(Clone, Debug)]
pub struct Stream {
    pub id: u64,
    pub send: Option<SendPart>,
    pub recv: Option<RecvPart>,
    /// The application let go of it (OpenSSL's `deleted`).
    released: bool,
}

/// Whether stream `id` was opened by the server.
#[must_use]
pub fn is_server_init(id: u64) -> bool {
    id & 1 == 1
}

/// Whether stream `id` is unidirectional.
#[must_use]
pub fn is_uni(id: u64) -> bool {
    id & 2 == 2
}

/// What the stream map tells the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    Incoming(u64),
    Readable(u64),
    Writable(u64),
}

/// The peer's and our initial stream parameters.
#[derive(Clone, Copy, Debug)]
pub struct StreamLimits {
    /// The peer's initial_max_stream_data_bidi_local (its window for streams it opens, so for
    /// our sending on streams it opened).
    pub peer_bidi_local: u64,
    /// The peer's initial_max_stream_data_bidi_remote (our sending on streams we opened).
    pub peer_bidi_remote: u64,
    /// The peer's initial_max_stream_data_uni (our sending on unidirectional streams we open).
    pub peer_uni: u64,
}

/// A connection's streams.
#[derive(Debug)]
pub struct StreamMap {
    is_server: bool,
    streams: BTreeMap<u64, Stream>,
    next_local: PerDir<u64>,
    next_remote: PerDir<u64>,
    /// The peer's MAX_STREAMS (bidi, uni).
    local_limit: PerDir<TxFc>,
    streams_blocked_want: PerDir<bool>,
    /// Ours (bidi, uni).
    remote_limit: PerDir<RxFc>,
    max_streams_want: PerDir<bool>,
    pub conn_tx: TxFc,
    pub conn_rx: RxFc,
    data_blocked_want: bool,
    max_data_want: bool,
    pub peer: StreamLimits,
    /// Our receive windows for new streams.
    pub stream_window: u64,
    accept: VecDeque<u64>,
    events: VecDeque<StreamEvent>,
    pending_events: BTreeSet<(u8, u64)>,
}

const BIDI: usize = 0;
const UNI: usize = 1;

/// A value per stream direction, indexed by [`BIDI`] or [`UNI`].
#[derive(Clone, Copy, Debug, Default)]
struct PerDir<T> {
    bidi: T,
    uni: T,
}

impl<T> core::ops::Index<usize> for PerDir<T> {
    type Output = T;
    fn index(&self, d: usize) -> &T {
        if d == UNI { &self.uni } else { &self.bidi }
    }
}

impl<T> core::ops::IndexMut<usize> for PerDir<T> {
    fn index_mut(&mut self, d: usize) -> &mut T {
        if d == UNI {
            &mut self.uni
        } else {
            &mut self.bidi
        }
    }
}

fn dir(id: u64) -> usize {
    if is_uni(id) { UNI } else { BIDI }
}

impl StreamMap {
    /// A map with OpenSSL's default windows and stream limits.
    #[must_use]
    pub fn new(is_server: bool) -> Self {
        let streams = DEFAULT_INIT_CONN_MAX_STREAMS;
        Self {
            is_server,
            streams: BTreeMap::new(),
            next_local: PerDir::default(),
            next_remote: PerDir::default(),
            local_limit: PerDir::default(),
            streams_blocked_want: PerDir::default(),
            remote_limit: PerDir {
                bidi: RxFc::standalone(streams),
                uni: RxFc::standalone(streams),
            },
            max_streams_want: PerDir::default(),
            conn_tx: TxFc::new(0),
            conn_rx: RxFc::new(
                DEFAULT_INIT_CONN_RXFC_WND,
                DEFAULT_INIT_CONN_RXFC_WND.saturating_mul(DEFAULT_CONN_RXFC_MAX_WND_MUL),
            ),
            data_blocked_want: false,
            max_data_want: false,
            peer: StreamLimits {
                peer_bidi_local: 0,
                peer_bidi_remote: 0,
                peer_uni: 0,
            },
            stream_window: DEFAULT_INIT_STREAM_RXFC_WND,
            accept: VecDeque::new(),
            events: VecDeque::new(),
            pending_events: BTreeSet::new(),
        }
    }

    /// Applies the peer's transport parameters.
    pub fn set_peer_params(
        &mut self,
        max_data: u64,
        limits: StreamLimits,
        max_bidi: u64,
        max_uni: u64,
    ) {
        self.conn_tx.bump_cwm(max_data);
        self.peer = limits;
        self.local_limit[BIDI].bump_cwm(max_bidi);
        self.local_limit[UNI].bump_cwm(max_uni);
        // Streams opened before (0-RTT) take their windows now.
        let ids: Vec<u64> = self.streams.keys().copied().collect();
        for id in ids {
            let w = self.peer_window(id);
            if let Some(s) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
                s.fc.bump_cwm(w);
            }
        }
    }

    /// Our initial MAX_STREAMS (bidi, uni) for the transport parameters.
    #[must_use]
    pub fn local_max_streams(&self) -> (u64, u64) {
        (self.remote_limit[BIDI].cwm(), self.remote_limit[UNI].cwm())
    }

    fn is_local(&self, id: u64) -> bool {
        is_server_init(id) == self.is_server
    }

    fn peer_window(&self, id: u64) -> u64 {
        if is_uni(id) {
            self.peer.peer_uni
        } else if self.is_local(id) {
            self.peer.peer_bidi_remote
        } else {
            self.peer.peer_bidi_local
        }
    }

    fn new_stream(&self, id: u64) -> Stream {
        let local = self.is_local(id);
        let has_send = !is_uni(id) || local;
        let has_recv = !is_uni(id) || !local;
        let w = self.stream_window;
        Stream {
            id,
            send: has_send.then(|| SendPart {
                state: SendState::Ready,
                buf: SendBuf::new(MAX_SEND_BUF),
                fc: TxFc::new(self.peer_window(id)),
                reset_code: None,
                want_reset: false,
                want_blocked: false,
                peer_stop_sending: None,
            }),
            recv: has_recv.then(|| RecvPart {
                state: RecvState::Recv,
                buf: RecvBuf::default(),
                fc: RxFc::new(w, w.saturating_mul(DEFAULT_STREAM_RXFC_MAX_WND_MUL)),
                reset_code: None,
                stop_sending: None,
                want_stop_sending: false,
                stop_sending_acked: false,
                want_max_stream_data: false,
            }),
            released: false,
        }
    }

    fn event(&mut self, e: StreamEvent) {
        let key = match e {
            StreamEvent::Incoming(id) => (0, id),
            StreamEvent::Readable(id) => (1, id),
            StreamEvent::Writable(id) => (2, id),
        };
        if self.pending_events.insert(key) {
            self.events.push_back(e);
        }
    }

    /// The next stream event.
    pub fn poll_event(&mut self) -> Option<StreamEvent> {
        let e = self.events.pop_front()?;
        let key = match e {
            StreamEvent::Incoming(id) => (0, id),
            StreamEvent::Readable(id) => (1, id),
            StreamEvent::Writable(id) => (2, id),
        };
        self.pending_events.remove(&key);
        Some(e)
    }

    /// A stream by id.
    #[must_use]
    pub fn get(&self, id: u64) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// The number of live streams.
    #[must_use]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Whether there are no live streams.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.streams.is_empty()
    }

    // ---- the application's side ----

    /// Opens a local stream; `None` if the peer's stream limit is reached (we'll send
    /// STREAMS_BLOCKED).
    pub fn open(&mut self, bidi: bool) -> Option<u64> {
        let d = if bidi { BIDI } else { UNI };
        let ordinal = self.next_local[d];
        if ordinal >= self.local_limit[d].cwm() || ordinal >= MAX_STREAM_COUNT {
            self.streams_blocked_want[d] = true;
            return None;
        }
        self.local_limit[d].consume_local(1);
        self.next_local[d] = ordinal.saturating_add(1);
        let id = (ordinal << 2) | (u64::from(d == UNI) << 1) | u64::from(self.is_server);
        let s = self.new_stream(id);
        self.streams.insert(id, s);
        Some(id)
    }

    /// The next incoming stream the application hasn't accepted.
    pub fn accept(&mut self, now: Time) -> Option<u64> {
        let id = self.accept.pop_front()?;
        let d = dir(id);
        // OpenSSL retires stream-count credit when a stream leaves the accept queue.
        self.remote_limit[d].retire_count(1, now);
        if self.remote_limit[d].has_cwm_changed(true) {
            self.max_streams_want[d] = true;
        }
        Some(id)
    }

    /// Streams waiting to be accepted.
    #[must_use]
    pub fn accept_queue_len(&self) -> usize {
        self.accept.len()
    }

    fn send_part(&mut self, id: u64) -> Result<&mut SendPart> {
        self.streams
            .get_mut(&id)
            .and_then(|s| s.send.as_mut())
            .ok_or_else(|| Error::internal("no such stream"))
    }

    fn recv_part(&mut self, id: u64) -> Result<&mut RecvPart> {
        self.streams
            .get_mut(&id)
            .and_then(|s| s.recv.as_mut())
            .ok_or_else(|| Error::internal("no such stream"))
    }

    /// Writes to stream `id`; returns how much was buffered.
    ///
    /// # Errors
    /// The stream has no send part, or it was finished or reset.
    pub fn send(&mut self, id: u64, data: &[u8], fin: bool) -> Result<usize> {
        let p = self.send_part(id)?;
        if !matches!(p.state, SendState::Ready | SendState::Send) || p.buf.is_finished() {
            return Err(Error::internal("stream not writable"));
        }
        let n = p.buf.write(data);
        if fin && n == data.len() {
            p.buf.finish();
        }
        if n > 0 || fin {
            p.state = SendState::Send;
        }
        Ok(n)
    }

    /// Room in stream `id`'s send buffer.
    #[must_use]
    pub fn send_space(&self, id: u64) -> usize {
        self.streams
            .get(&id)
            .and_then(|s| s.send.as_ref())
            .map_or(0, |p| p.buf.space())
    }

    /// Reads from stream `id`: the octets read and whether the stream ended.
    ///
    /// # Errors
    /// The stream has no receive part, or it was reset (the code is in the error's
    /// `frame_type`... see [`StreamMap::reset_code`]).
    pub fn recv(
        &mut self,
        id: u64,
        buf: &mut [u8],
        now: Time,
        rtt: Duration,
    ) -> Result<(usize, bool)> {
        let p = self
            .streams
            .get_mut(&id)
            .and_then(|s| s.recv.as_mut())
            .ok_or_else(|| Error::internal("no such stream"))?;
        match p.state {
            RecvState::ResetRecvd | RecvState::ResetRead => {
                p.state = RecvState::ResetRead;
                return Err(Error::internal("stream reset"));
            }
            RecvState::DataRead => return Ok((0, true)),
            _ => {}
        }
        let (n, fin) = p.buf.read(buf);
        let n64 = u64::try_from(n).unwrap_or(0);
        p.fc.on_retire(Some(&mut self.conn_rx), n64, now, rtt)?;
        if p.fc.has_cwm_changed(false) {
            p.want_max_stream_data = true;
        }
        if fin {
            p.state = RecvState::DataRead;
        }
        if self.conn_rx.has_cwm_changed(true) {
            self.max_data_want = true;
        }
        self.gc(id);
        Ok((n, fin))
    }

    /// Octets readable on `id` now, and whether the stream's end (or a reset) is pending.
    #[must_use]
    pub fn readable(&self, id: u64) -> (u64, bool) {
        self.streams
            .get(&id)
            .and_then(|s| s.recv.as_ref())
            .map_or((0, false), |p| {
                let end = matches!(p.state, RecvState::DataRecvd | RecvState::ResetRecvd)
                    || p.buf.all_received();
                (p.buf.available(), end)
            })
    }

    /// The peer's RESET_STREAM code for `id`, if it reset it.
    #[must_use]
    pub fn reset_code(&self, id: u64) -> Option<u64> {
        self.streams.get(&id)?.recv.as_ref()?.reset_code
    }

    /// The peer's STOP_SENDING code for `id`, if it sent one.
    #[must_use]
    pub fn peer_stop_sending(&self, id: u64) -> Option<u64> {
        self.streams.get(&id)?.send.as_ref()?.peer_stop_sending
    }

    /// Resets stream `id`'s send part with `code`.
    ///
    /// # Errors
    /// The stream has no send part.
    pub fn reset(&mut self, id: u64, code: u64) -> Result<()> {
        let p = self.send_part(id)?;
        if matches!(
            p.state,
            SendState::DataRecvd | SendState::ResetSent | SendState::ResetRecvd
        ) {
            return Ok(());
        }
        p.state = SendState::ResetSent;
        p.reset_code = Some(code);
        p.want_reset = true;
        p.buf.discard();
        Ok(())
    }

    /// Asks the peer to stop sending on `id`.
    ///
    /// # Errors
    /// The stream has no receive part.
    pub fn stop_sending(&mut self, id: u64, code: u64) -> Result<()> {
        let p = self.recv_part(id)?;
        if p.stop_sending.is_some()
            || matches!(
                p.state,
                RecvState::DataRecvd
                    | RecvState::DataRead
                    | RecvState::ResetRecvd
                    | RecvState::ResetRead
            )
        {
            return Ok(());
        }
        p.stop_sending = Some(code);
        p.want_stop_sending = true;
        Ok(())
    }

    /// The application let go of `id`: an unfinished send part is reset, an unfinished receive
    /// part gets STOP_SENDING (code 0), and the stream goes once both parts are done.
    pub fn release(&mut self, id: u64) {
        let unfinished_send = self
            .streams
            .get(&id)
            .and_then(|s| s.send.as_ref())
            .is_some_and(|p| !p.buf.is_finished() && p.reset_code.is_none());
        if unfinished_send {
            let _ = self.reset(id, 0);
        }
        let _ = self.stop_sending(id, 0);
        if let Some(s) = self.streams.get_mut(&id) {
            s.released = true;
        }
        self.accept.retain(|&a| a != id);
        self.gc(id);
    }

    fn gc(&mut self, id: u64) {
        let ready = self.streams.get(&id).is_some_and(|s| {
            s.released
                && s.recv.as_ref().is_none_or(|r| {
                    r.stop_sending_acked
                        || matches!(r.state, RecvState::DataRead | RecvState::ResetRead)
                })
                && s.send
                    .as_ref()
                    .is_none_or(|p| matches!(p.state, SendState::DataRecvd | SendState::ResetRecvd))
        });
        if ready {
            self.streams.remove(&id);
        }
    }

    // ---- frames received ----

    /// Finds or implicitly creates stream `id` for a frame of type `frame_type`; `None` for an
    /// old local stream since deleted (the frame is ignored).
    fn implicit_create(&mut self, id: u64, frame_type: u64) -> Result<Option<u64>> {
        if self.streams.contains_key(&id) {
            return Ok(Some(id));
        }
        let d = dir(id);
        let ordinal = id >> 2;
        if !self.is_local(id) {
            if ordinal < self.next_remote[d] {
                return Ok(None);
            }
            self.remote_limit[d].on_rx_count(ordinal.saturating_add(1));
            if self.remote_limit[d].error(None).is_some() {
                return Err(Error::new(
                    rustyssl_abi::OSSL_QUIC_ERR_STREAM_LIMIT_ERROR,
                    frame_type,
                    "exceeded maximum allowed streams",
                ));
            }
            while self.next_remote[d] <= ordinal {
                let cur = (self.next_remote[d] << 2) | (id & 3);
                let s = self.new_stream(cur);
                self.streams.insert(cur, s);
                self.accept.push_back(cur);
                self.event(StreamEvent::Incoming(cur));
                self.next_remote[d] = self.next_remote[d].saturating_add(1);
            }
            Ok(Some(id))
        } else if ordinal >= self.next_local[d] {
            Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_STREAM_STATE_ERROR,
                frame_type,
                "STREAM frame for nonexistent stream",
            ))
        } else {
            Ok(None)
        }
    }

    fn fc_error(&self, id: u64, frame_type: u64) -> Result<()> {
        let fce = self
            .streams
            .get(&id)
            .and_then(|s| s.recv.as_ref())
            .and_then(|p| p.fc.error(Some(&self.conn_rx)));
        match fce {
            Some(code) => Err(Error {
                code,
                frame_type,
                reason: "flow control violation",
            }),
            None => Ok(()),
        }
    }

    /// A STREAM frame.
    ///
    /// # Errors
    /// The connection errors of OpenSSL's `depack_do_frame_stream`.
    pub fn on_stream(
        &mut self,
        frame_type: u64,
        id: u64,
        offset: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<()> {
        let Some(id) = self.implicit_create(id, frame_type)? else {
            return Ok(());
        };
        let end = offset.saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        if end > crate::wire::VARINT_MAX {
            return Err(Error::frame_encoding(frame_type));
        }
        let conn_rx = &mut self.conn_rx;
        let Some(p) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) else {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_STREAM_STATE_ERROR,
                frame_type,
                "STREAM frame for TX only stream",
            ));
        };
        p.fc.on_rx_stream_frame(Some(conn_rx), end, fin);
        self.fc_error(id, frame_type)?;
        let Some(p) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) else {
            return Ok(());
        };
        if !matches!(p.state, RecvState::Recv | RecvState::SizeKnown) {
            return Ok(());
        }
        if fin && p.buf.final_size.is_none() {
            p.buf.set_final_size(end);
            p.state = RecvState::SizeKnown;
        }
        if p.stop_sending.is_some() {
            return Ok(());
        }
        let before = p.buf.available();
        if !data.is_empty() {
            p.buf.insert(offset, data, frame_type)?;
        }
        if p.buf.all_received() {
            p.state = RecvState::DataRecvd;
        }
        if p.buf.available() > before || p.state == RecvState::DataRecvd {
            self.event(StreamEvent::Readable(id));
        }
        Ok(())
    }

    /// A RESET_STREAM frame.
    ///
    /// # Errors
    /// The connection errors of OpenSSL's `depack_do_frame_reset_stream`.
    pub fn on_reset_stream(&mut self, id: u64, code: u64, final_size: u64) -> Result<()> {
        let t = ft::RESET_STREAM;
        let Some(id) = self.implicit_create(id, t)? else {
            return Ok(());
        };
        let conn_rx = &mut self.conn_rx;
        let Some(p) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) else {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_STREAM_STATE_ERROR,
                t,
                "RESET_STREAM frame for TX only stream",
            ));
        };
        p.fc.on_rx_stream_frame(Some(conn_rx), final_size, true);
        self.fc_error(id, t)?;
        let Some(p) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) else {
            return Ok(());
        };
        if matches!(
            p.state,
            RecvState::Recv | RecvState::SizeKnown | RecvState::DataRecvd
        ) {
            p.state = RecvState::ResetRecvd;
            p.reset_code = Some(code);
            p.want_stop_sending = false;
            p.buf = RecvBuf::default();
            self.event(StreamEvent::Readable(id));
        }
        Ok(())
    }

    /// A STOP_SENDING frame: reset our send part with the peer's code.
    ///
    /// # Errors
    /// The connection errors of OpenSSL's `depack_do_frame_stop_sending`.
    pub fn on_stop_sending(&mut self, id: u64, code: u64) -> Result<()> {
        let t = ft::STOP_SENDING;
        let Some(id) = self.implicit_create(id, t)? else {
            return Ok(());
        };
        let Some(p) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_STREAM_STATE_ERROR,
                t,
                "STOP_SENDING frame for RX only stream",
            ));
        };
        p.peer_stop_sending = Some(code);
        self.reset(id, code)?;
        self.event(StreamEvent::Writable(id));
        Ok(())
    }

    /// A MAX_DATA frame.
    pub fn on_max_data(&mut self, max: u64) {
        if self.conn_tx.bump_cwm(max) {
            let ids: Vec<u64> = self
                .streams
                .iter()
                .filter(|(_, s)| s.send.as_ref().is_some_and(|p| p.state == SendState::Send))
                .map(|(&id, _)| id)
                .collect();
            for id in ids {
                self.event(StreamEvent::Writable(id));
            }
        }
    }

    /// A MAX_STREAM_DATA frame.
    ///
    /// # Errors
    /// The stream doesn't exist yet as a local one, or has no send part (STREAM_STATE_ERROR).
    pub fn on_max_stream_data(&mut self, id: u64, max: u64) -> Result<()> {
        let t = ft::MAX_STREAM_DATA;
        let Some(id) = self.implicit_create(id, t)? else {
            return Ok(());
        };
        let Some(p) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_STREAM_STATE_ERROR,
                t,
                "MAX_STREAM_DATA for TX only stream",
            ));
        };
        if p.fc.bump_cwm(max) {
            self.event(StreamEvent::Writable(id));
        }
        Ok(())
    }

    /// A MAX_STREAMS frame.
    ///
    /// # Errors
    /// The count exceeds 2^60 (FRAME_ENCODING_ERROR).
    pub fn on_max_streams(&mut self, bidi: bool, max: u64) -> Result<()> {
        let t = if bidi {
            ft::MAX_STREAMS_BIDI
        } else {
            ft::MAX_STREAMS_UNI
        };
        if max > MAX_STREAM_COUNT {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_FRAME_ENCODING_ERROR,
                t,
                "invalid MAX_STREAMS value",
            ));
        }
        self.local_limit[if bidi { BIDI } else { UNI }].bump_cwm(max);
        Ok(())
    }

    /// A STREAM_DATA_BLOCKED frame (checked; nothing else to do).
    ///
    /// # Errors
    /// The stream is a nonexistent local one, or has no receive part.
    pub fn on_stream_data_blocked(&mut self, id: u64) -> Result<()> {
        let t = ft::STREAM_DATA_BLOCKED;
        let Some(id) = self.implicit_create(id, t)? else {
            return Ok(());
        };
        if self.streams.get(&id).is_some_and(|s| s.recv.is_none()) {
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_STREAM_STATE_ERROR,
                t,
                "STREAM_DATA_BLOCKED frame for TX only stream",
            ));
        }
        Ok(())
    }

    /// A STREAMS_BLOCKED frame.
    ///
    /// # Errors
    /// The count exceeds 2^60.
    pub fn on_streams_blocked(&mut self, bidi: bool, limit: u64) -> Result<()> {
        if limit > MAX_STREAM_COUNT {
            let t = if bidi {
                ft::STREAMS_BLOCKED_BIDI
            } else {
                ft::STREAMS_BLOCKED_UNI
            };
            return Err(Error::new(
                rustyssl_abi::OSSL_QUIC_ERR_STREAM_LIMIT_ERROR,
                t,
                "invalid STREAMS_BLOCKED value",
            ));
        }
        Ok(())
    }

    // ---- what to send ----

    /// MAX_DATA to send, if the window moved.
    pub fn take_max_data(&mut self) -> Option<u64> {
        core::mem::take(&mut self.max_data_want).then(|| self.conn_rx.cwm())
    }

    /// A MAX_DATA was lost: send the current one again.
    pub fn lost_max_data(&mut self) {
        self.max_data_want = true;
    }

    /// DATA_BLOCKED to send.
    pub fn take_data_blocked(&mut self) -> Option<u64> {
        if self.conn_tx.has_become_blocked(true) {
            self.data_blocked_want = true;
        }
        core::mem::take(&mut self.data_blocked_want).then(|| self.conn_tx.cwm())
    }

    /// MAX_STREAMS to send.
    pub fn take_max_streams(&mut self, bidi: bool) -> Option<u64> {
        let d = if bidi { BIDI } else { UNI };
        core::mem::take(&mut self.max_streams_want[d]).then(|| self.remote_limit[d].cwm())
    }

    /// A MAX_STREAMS was lost.
    pub fn lost_max_streams(&mut self, bidi: bool) {
        self.max_streams_want[if bidi { BIDI } else { UNI }] = true;
    }

    /// STREAMS_BLOCKED to send.
    pub fn take_streams_blocked(&mut self, bidi: bool) -> Option<u64> {
        let d = if bidi { BIDI } else { UNI };
        core::mem::take(&mut self.streams_blocked_want[d]).then(|| self.local_limit[d].cwm())
    }

    /// The streams with something to send, in id order.
    #[must_use]
    pub fn active(&self) -> Vec<u64> {
        let conn_credit = self.conn_tx.credit_local();
        self.streams
            .iter()
            .filter(|(_, s)| {
                s.send.as_ref().is_some_and(|p| {
                    p.want_reset
                        || p.want_blocked
                        || (p.reset_code.is_none() && {
                            let limit = p
                                .buf
                                .sent_end()
                                .saturating_add(p.fc.credit_local().min(conn_credit));
                            p.buf.has_pending(limit)
                        })
                }) || s.recv.as_ref().is_some_and(|r| {
                    r.want_stop_sending || (r.want_max_stream_data && r.state == RecvState::Recv)
                })
            })
            .map(|(&id, _)| id)
            .collect()
    }

    /// RESET_STREAM to send for `id`: (code, final size).
    pub fn take_reset(&mut self, id: u64) -> Option<(u64, u64)> {
        let p = self.streams.get_mut(&id)?.send.as_mut()?;
        if !core::mem::take(&mut p.want_reset) {
            return None;
        }
        Some((p.reset_code.unwrap_or(0), p.buf.sent_end()))
    }

    /// STOP_SENDING to send for `id`.
    pub fn take_stop_sending(&mut self, id: u64) -> Option<u64> {
        let p = self.streams.get_mut(&id)?.recv.as_mut()?;
        if !core::mem::take(&mut p.want_stop_sending) {
            return None;
        }
        p.stop_sending
    }

    /// MAX_STREAM_DATA to send for `id`.
    pub fn take_max_stream_data(&mut self, id: u64) -> Option<u64> {
        let p = self.streams.get_mut(&id)?.recv.as_mut()?;
        if p.state != RecvState::Recv {
            p.want_max_stream_data = false;
            return None;
        }
        let changed = p.fc.has_cwm_changed(true);
        (core::mem::take(&mut p.want_max_stream_data) || changed).then(|| p.fc.cwm())
    }

    /// STREAM_DATA_BLOCKED to send for `id`.
    pub fn take_stream_data_blocked(&mut self, id: u64) -> Option<u64> {
        let p = self.streams.get_mut(&id)?.send.as_mut()?;
        if p.fc.has_become_blocked(true) {
            p.want_blocked = true;
        }
        core::mem::take(&mut p.want_blocked).then(|| p.fc.cwm())
    }

    /// The next STREAM chunk of `id`, at most `max_len` octets, within flow control.
    pub fn next_chunk(&mut self, id: u64, max_len: usize) -> Option<Chunk> {
        let conn_credit = self.conn_tx.credit_local();
        let p = self.streams.get_mut(&id)?.send.as_mut()?;
        if p.reset_code.is_some() {
            return None;
        }
        let before = p.buf.sent_end();
        let limit = before.saturating_add(p.fc.credit_local().min(conn_credit));
        let c = p.buf.next_chunk(max_len, limit)?;
        let new = p.buf.sent_end().saturating_sub(before);
        p.fc.consume(Some(&mut self.conn_tx), new);
        if p.buf.all_sent() && p.state == SendState::Send {
            p.state = SendState::DataSent;
        }
        Some(c)
    }

    /// A STREAM frame of ours was acknowledged.
    pub fn on_stream_acked(&mut self, id: u64, offset: u64, len: u64, fin: bool) {
        let Some(p) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) else {
            return;
        };
        let space = p.buf.space();
        p.buf.on_acked(offset, len, fin);
        let freed = p.buf.space() > space;
        if p.state == SendState::DataSent && p.buf.is_totally_acked() {
            p.state = SendState::DataRecvd;
        }
        if freed {
            self.event(StreamEvent::Writable(id));
        }
        self.gc(id);
    }

    /// A STREAM frame of ours was lost.
    pub fn on_stream_lost(&mut self, id: u64, offset: u64, len: u64, fin: bool) {
        if let Some(p) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut())
            && p.reset_code.is_none()
        {
            p.buf.on_lost(offset, len, fin);
            if p.state == SendState::DataSent && fin {
                p.state = SendState::Send;
            }
        }
    }

    /// Our RESET_STREAM was acknowledged.
    pub fn on_reset_acked(&mut self, id: u64) {
        if let Some(p) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut()) {
            p.state = SendState::ResetRecvd;
        }
        self.gc(id);
    }

    /// Our RESET_STREAM was lost.
    pub fn on_reset_lost(&mut self, id: u64) {
        if let Some(p) = self.streams.get_mut(&id).and_then(|s| s.send.as_mut())
            && p.state == SendState::ResetSent
        {
            p.want_reset = true;
        }
    }

    /// Our STOP_SENDING was acknowledged.
    pub fn on_stop_sending_acked(&mut self, id: u64) {
        if let Some(p) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) {
            p.stop_sending_acked = true;
        }
        self.gc(id);
    }

    /// Our STOP_SENDING was lost.
    pub fn on_stop_sending_lost(&mut self, id: u64) {
        if let Some(p) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut())
            && matches!(p.state, RecvState::Recv | RecvState::SizeKnown)
        {
            p.want_stop_sending = true;
        }
    }

    /// Our MAX_STREAM_DATA was lost.
    pub fn on_max_stream_data_lost(&mut self, id: u64) {
        if let Some(p) = self.streams.get_mut(&id).and_then(|s| s.recv.as_mut()) {
            p.want_max_stream_data = true;
        }
    }

    /// Whether stream `id` was fully sent and acknowledged, or reset and that acknowledged.
    #[must_use]
    pub fn send_done(&self, id: u64) -> bool {
        self.streams
            .get(&id)
            .and_then(|s| s.send.as_ref())
            .is_none_or(|p| matches!(p.state, SendState::DataRecvd | SendState::ResetRecvd))
    }
}

#[cfg(test)]
mod tests;
