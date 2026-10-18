//! DTLS's handshake layer (RFC 6347, section 4.2; OpenSSL's `statem_dtls.c`, `d1_lib.c` and
//! `rec_layer_d1.c`): message headers with sequence numbers and fragments, messages
//! fragmented to the MTU and packed into datagrams, reassembly and reordering of what
//! arrives, the flight kept for retransmission, and the timer's starts and stops (the caller
//! owns the clock).

use std::collections::{BTreeMap, VecDeque};

use rustyssl_abi as abi;

use super::statem::{msgs_type, st};
use super::{Connection, RECEIVED_SHUTDOWN, SENT_SHUTDOWN, alert, app_data, ccs, handshake};
use crate::crypto::Provider;
use crate::error::{Error, InFunc, Result};
use crate::msgs::{self, DTLS_HEADER_LEN, DtlsHeader};
use crate::record::{self, Record, dtls::DRead};

/// How far ahead of the expected message one is buffered (`dtls1_process_out_of_seq_message`).
const MAX_AHEAD: u16 = 10;

/// How many application data records are held between a ChangeCipherSpec and the Finished
/// (`dtls_buffer_record`).
const MAX_HELD_APP: usize = 100;

/// The largest cookie (`DTLS1_COOKIE_LENGTH`).
pub const COOKIE_LEN: usize = 255;

/// A change to the retransmission timer for the caller to make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Timer {
    /// `dtls1_start_timer`: (re)arm it, now plus the current duration.
    Start,
    /// `dtls1_stop_timer`: disarm it and reset the duration and the timeout count.
    Stop,
}

/// A received message being reassembled, or a whole one buffered ahead of its turn
/// (`hm_fragment`).
#[derive(Clone, Debug)]
struct Frag {
    /// The message type.
    typ: u8,
    /// The message's length.
    len: usize,
    /// The body so far.
    body: Vec<u8>,
    /// Which octets arrived (one bit each); `None` once complete.
    mask: Option<Vec<u8>>,
}

/// A message of the last flight, kept for retransmission.
#[derive(Clone, Debug)]
struct Sent {
    /// The message's sequence number.
    seq: u16,
    /// Whether it is the ChangeCipherSpec.
    ccs: bool,
    /// The epoch it was sent in.
    epoch: u16,
    /// The message type.
    typ: u8,
    /// The body (the ChangeCipherSpec's octet).
    body: Vec<u8>,
}

/// DTLS's state on a connection (`DTLS1_STATE`).
#[derive(Debug, Default)]
pub struct State {
    /// The next message sequence number expected (`handshake_read_seq`).
    pub(crate) read_seq: u16,
    /// The next one to send (`next_handshake_write_seq`).
    pub(crate) next_write_seq: u16,
    /// The sequence number of the message in `hs_in`.
    cur_seq: u16,
    /// Messages received ahead of their turn or in fragments (`buffered_messages`).
    frags: BTreeMap<u16, Frag>,
    /// The flight sent (`sent_messages`).
    sent: Vec<Sent>,
    /// The handshake record being read (octets after the fragments taken so far).
    hs_rec: Vec<u8>,
    /// Application data held between a ChangeCipherSpec and the Finished.
    held_app: VecDeque<Record>,
    /// The datagram being filled (the buffering BIO's contents).
    open: Vec<u8>,
    /// Whether records collect into datagrams (`ssl_init_wbio_buffer`, during a handshake).
    pub(crate) buffering: bool,
    /// Where the output's datagrams end.
    marks: Vec<usize>,
    /// Datagrams received and not yet read.
    input: VecDeque<Vec<u8>>,
    /// The rest of the datagram (or held record) being read.
    cur: Vec<u8>,
    /// The read epoch last seen.
    read_epoch: u16,
    /// The timer change to report.
    timer: Option<Timer>,
    /// Whether messages written start the timer (`statem.use_timer`).
    pub(crate) use_timer: bool,
    /// Whether a retransmission is being written (no transcript).
    retransmitting: bool,
    /// Timeouts without progress (`timeout_num_alerts`).
    timeouts: u32,
    /// The client's cookie from a HelloVerifyRequest, or the server's last cookie.
    pub(crate) cookie: Vec<u8>,
    /// Whether the server verified the client's cookie (`cookie_verified`).
    pub(crate) cookie_verified: bool,
}

/// What [`Connection::dtls_get_message`] got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DGot {
    /// A whole handshake message, now in `hs_in` with a TLS header.
    Message,
    /// A ChangeCipherSpec record, with this many octets after its one.
    Ccs(usize),
    /// Stopped for input or an event.
    Yield,
}

/// What reading a handshake-layer record found.
enum HsRec {
    /// Handshake octets are in `hs_rec`.
    Handshake,
    /// A ChangeCipherSpec record's contents.
    Ccs(Vec<u8>),
    /// Stopped for input or an event.
    Yield,
}

impl State {
    /// Forgets the flight sent (`dtls1_clear_sent_buffer`).
    fn clear_sent(&mut self) {
        self.sent.clear();
    }
}

/// `dtls1_max_handshake_message_len`.
fn max_message_len(c: &Connection) -> usize {
    let enc = usize::try_from(abi::SSL3_RT_MAX_ENCRYPTED_LENGTH).unwrap_or(0);
    let m = DTLS_HEADER_LEN.saturating_add(enc);
    m.max(c.cfg.max_cert_list)
}

/// A 12-octet header.
fn hm_header(typ: u8, len: usize, seq: u16, off: usize, frag: usize) -> Result<Vec<u8>> {
    let u = |v: usize| u32::try_from(v).map_err(|_| Error::internal());
    let mut w = crate::codec::Writer::new();
    DtlsHeader {
        typ,
        len: u(len)?,
        message_seq: seq,
        fragment_offset: u(off)?,
        fragment_length: u(frag)?,
    }
    .write(&mut w);
    Ok(w.into_bytes())
}

impl Connection {
    /// Adds a datagram of network input (DTLS; TLS takes it as a stream).
    pub fn feed_datagram(&mut self, d: &[u8]) {
        if self.cfg.dtls {
            self.dtls.input.push_back(d.to_vec());
            self.needs_input = false;
        } else {
            self.feed(d);
        }
    }

    /// Whether DTLS input is waiting (datagrams, or held records to read again).
    #[must_use]
    pub fn dtls_input_pending(&self) -> bool {
        !self.dtls.input.is_empty()
            || !self.dtls.cur.is_empty()
            || self.rr.dtls.as_ref().is_some_and(|d| !d.replay.is_empty())
    }

    /// The octets of the records held between a ChangeCipherSpec and the Finished, which
    /// `SSL_pending` counts (`ssl3_pending`).
    pub(crate) fn dtls_held_len(&self) -> usize {
        self.dtls.held_app.iter().map(|r| r.data.len()).sum()
    }

    /// DTLS: takes the finished datagrams of the output.
    pub fn take_datagrams(&mut self) -> Vec<Vec<u8>> {
        let out = core::mem::take(&mut self.output);
        let marks = core::mem::take(&mut self.dtls.marks);
        let mut v = Vec::with_capacity(marks.len().saturating_add(1));
        let mut start = 0usize;
        for m in marks {
            if let Some(d) = out.get(start..m) {
                v.push(d.to_vec());
            }
            start = m;
        }
        if let Some(rest) = out.get(start..).filter(|r| !r.is_empty()) {
            v.push(rest.to_vec());
        }
        v
    }

    /// DTLS: closes the open datagram (a flush of the buffering BIO).
    pub(crate) fn dtls_close_datagram(&mut self) {
        if self.dtls.open.is_empty() {
            return;
        }
        let d = core::mem::take(&mut self.dtls.open);
        self.output.extend_from_slice(&d);
        self.dtls.marks.push(self.output.len());
    }

    /// The timer change to make, if any (taken).
    pub fn take_dtls_timer(&mut self) -> Option<Timer> {
        self.dtls.timer.take()
    }

    /// `dtls1_start_timer`.
    pub(crate) fn dtls_start_timer(&mut self) {
        self.dtls.timer = Some(Timer::Start);
    }

    /// `dtls1_stop_timer`: the timer stops and the flight sent is forgotten.
    pub(crate) fn dtls_stop_timer(&mut self) {
        self.dtls.timeouts = 0;
        self.dtls.timer = Some(Timer::Stop);
        self.dtls.clear_sent();
    }

    /// Forgets the flight sent (`dtls1_clear_sent_buffer`).
    pub(crate) fn dtls_clear_sent(&mut self) {
        self.dtls.clear_sent();
    }

    /// Forgets messages received ahead (`dtls1_clear_received_buffer`).
    pub(crate) fn dtls_clear_received(&mut self) {
        self.dtls.frags.clear();
    }

    /// The handshake's end (`tls_finish_handshake`): the sequence numbers restart and the
    /// buffering ends.
    pub(crate) fn dtls_finish(&mut self, cleanuphand: bool, clearbufs: bool) {
        if clearbufs {
            self.dtls_close_datagram();
            self.dtls.buffering = false;
        }
        if cleanuphand {
            self.dtls.read_seq = 0;
            self.dtls.next_write_seq = 0;
            self.dtls_clear_received();
        }
    }

    /// `dtls1_check_timeout_num`: one more timeout; too many is fatal
    /// (`SSL_R_READ_TIMEOUT_EXPIRED`, no alert). Returns whether the caller should fall back
    /// to a smaller MTU (after the third, unless `SSL_OP_NO_QUERY_MTU`).
    ///
    /// # Errors
    /// Too many timeouts.
    pub fn dtls_count_timeout(&mut self, p: &dyn Provider) -> Result<bool> {
        self.dtls.timeouts = self.dtls.timeouts.saturating_add(1);
        let fallback = self.dtls.timeouts > 2 && self.cfg.options & abi::SSL_OP_NO_QUERY_MTU == 0;
        if self.dtls.timeouts > abi::DTLS1_TMO_ALERT_COUNT.unsigned_abs() {
            let e =
                Error::quiet(abi::SSL_R_READ_TIMEOUT_EXPIRED).in_func("dtls1_check_timeout_num");
            self.fatal(p, e);
            return Err(e);
        }
        Ok(fallback)
    }

    /// Whether a flight is being written (a timeout then retransmits nothing).
    #[must_use]
    pub fn dtls_writing_flight(&self) -> bool {
        self.st.state == super::statem::MsgFlow::Writing
            && self.st.write_state != super::statem::WriteState::Transition
    }

    /// `DTLSv1_listen` answered the ClientHello that's coming with a HelloVerifyRequest: the
    /// handshake goes on from its second ClientHello (sequence numbers 1, and the record after
    /// the one the HelloVerifyRequest borrowed).
    pub fn dtls_listen_done(&mut self) {
        self.dtls.read_seq = 1;
        self.dtls.next_write_seq = 1;
        if let Some(w) = self.rw.dtls.as_mut() {
            let next = w.seq.saturating_add(1);
            w.set_seq(next);
        }
    }

    /// The timer fired (`dtls1_handle_timeout` after the caller restarted the timer):
    /// retransmits the flight, unless a flight is being written.
    ///
    /// # Errors
    /// Protection failed.
    pub fn dtls_retransmit_on_timeout(&mut self, p: &dyn Provider) -> Result<()> {
        if self.st.state == super::statem::MsgFlow::Writing
            && self.st.write_state != super::statem::WriteState::Transition
        {
            return Ok(());
        }
        self.dtls_retransmit(p)
    }

    /// `dtls1_retransmit_buffered_messages`: sends the last flight again, each message in the
    /// epoch it was first sent in and flushed on its own.
    ///
    /// # Errors
    /// Protection failed.
    pub fn dtls_retransmit(&mut self, p: &dyn Provider) -> Result<()> {
        let sent = self.dtls.sent.clone();
        self.dtls.retransmitting = true;
        let mut r = Ok(());
        for m in &sent {
            r = if m.ccs {
                self.dtls_do_write(p, ccs(), 0, m.seq, &m.body, m.epoch)
            } else {
                self.dtls_do_write(p, handshake(), m.typ, m.seq, &m.body, m.epoch)
            };
            self.dtls_close_datagram();
            if r.is_err() {
                break;
            }
        }
        self.dtls.retransmitting = false;
        r
    }

    /// Sends a handshake message (`dtls1_set_handshake_header`, `dtls1_close_construct_packet`
    /// and `dtls1_do_write`): numbers it, keeps it for retransmission (all but a
    /// HelloVerifyRequest), adds it to the transcript as one unfragmented message, and writes
    /// it in fragments that fit the MTU.
    ///
    /// # Errors
    /// Protection failed.
    pub(crate) fn dtls_send_message(
        &mut self,
        p: &dyn Provider,
        mt: u8,
        body: &[u8],
    ) -> Result<()> {
        let is_ccs = mt == msgs_type(abi::SSL3_MT_CHANGE_CIPHER_SPEC)
            && (self.st.hand_state == st(abi::TLS_ST_SW_CHANGE)
                || self.st.hand_state == st(abi::TLS_ST_CW_CHANGE));
        if self.dtls.use_timer {
            self.dtls_start_timer();
        }
        let epoch = self.rw.epoch();
        if is_ccs {
            let seq = self.dtls.next_write_seq;
            let one = [msgs_type(abi::SSL3_MT_CCS)];
            self.dtls.sent.push(Sent {
                seq,
                ccs: true,
                epoch,
                typ: 0,
                body: one.to_vec(),
            });
            return self.dtls_do_write(p, ccs(), 0, seq, &one, epoch);
        }
        let seq = self.dtls.next_write_seq;
        self.dtls.next_write_seq = seq.wrapping_add(1);
        if mt != msgs_type(abi::DTLS1_MT_HELLO_VERIFY_REQUEST) {
            self.dtls.sent.push(Sent {
                seq,
                ccs: false,
                epoch,
                typ: mt,
                body: body.to_vec(),
            });
        }
        self.dtls_do_write(p, handshake(), mt, seq, body, epoch)
    }

    /// `dtls1_do_write`: one message (or the ChangeCipherSpec) as records that each fit what
    /// is left of the MTU in the open datagram, starting a new datagram when too little is.
    fn dtls_do_write(
        &mut self,
        p: &dyn Provider,
        ty: u8,
        mt: u8,
        seq: u16,
        body: &[u8],
        epoch: u16,
    ) -> Result<()> {
        let mtu = self.cfg.dtls_mtu.max(1);
        let overhead = self.rw.max_overhead();
        // `ssl_get_max_send_fragment`: the setting, or the peer's max_fragment_length.
        let max_frag = self.rw.max_frag_len.clamp(1, record::MAX_PLAIN);
        if ty == ccs() {
            let curr = mtu.saturating_sub(self.dtls.open.len().saturating_add(overhead));
            if curr <= DTLS_HEADER_LEN {
                self.dtls_close_datagram();
            }
            self.dtls_write_record(p, ty, body, epoch)?;
            self.report_message(true, abi::SSL3_RT_CHANGE_CIPHER_SPEC, body);
            return Ok(());
        }
        let full = [
            hm_header(mt, body.len(), seq, 0, body.len())?,
            body.to_vec(),
        ]
        .concat();
        if !self.dtls.retransmitting {
            self.hs.transcript.add(&full);
        }
        let mut off = 0usize;
        let mut first_len = body.len();
        loop {
            let mut curr = mtu.saturating_sub(self.dtls.open.len().saturating_add(overhead));
            if curr <= DTLS_HEADER_LEN {
                self.dtls_close_datagram();
                curr = mtu.saturating_sub(overhead);
                if curr <= DTLS_HEADER_LEN {
                    return Err(Error::internal());
                }
            }
            let left = body.len().saturating_sub(off);
            let len = left.saturating_add(DTLS_HEADER_LEN).min(curr).min(max_frag);
            let flen = len.saturating_sub(DTLS_HEADER_LEN);
            if off == 0 {
                first_len = flen;
            }
            let chunk = body
                .get(off..off.saturating_add(flen))
                .ok_or_else(Error::internal)?;
            let rec = [hm_header(mt, body.len(), seq, off, flen)?, chunk.to_vec()].concat();
            self.dtls_write_record(p, ty, &rec, epoch)?;
            off = off.saturating_add(flen);
            if off >= body.len() {
                break;
            }
            if flen == 0 {
                return Err(Error::internal());
            }
        }
        // The message callback sees the message with its first fragment's header.
        let shown = [hm_header(mt, body.len(), seq, 0, first_len)?, body.to_vec()].concat();
        self.report_message(true, abi::SSL3_RT_HANDSHAKE, &shown);
        Ok(())
    }

    /// Writes one DTLS record of `data` in `epoch`, into the open datagram while buffering
    /// (else as a datagram of its own), reporting its header to the message callback.
    ///
    /// # Errors
    /// Protection failed.
    pub(crate) fn dtls_write_record(
        &mut self,
        p: &dyn Provider,
        ty: u8,
        data: &[u8],
        epoch: u16,
    ) -> Result<()> {
        let mut rec = Vec::new();
        if !self.rw.write_dtls(p, ty, data, epoch, &mut rec)? {
            // The epoch's keys are gone: nothing to retransmit in it.
            return Ok(());
        }
        if self.cfg.callbacks.msg
            && let Some(h) = rec.get(..record::dtls::HEADER_LEN)
        {
            let v = i32::from(u16::from_be_bytes([
                h.get(1).copied().unwrap_or(0),
                h.get(2).copied().unwrap_or(0),
            ]));
            self.report_message_v(true, v, abi::SSL3_RT_HEADER, h);
        }
        if self.dtls.buffering {
            self.dtls.open.extend_from_slice(&rec);
        } else {
            self.output.extend_from_slice(&rec);
            self.dtls.marks.push(self.output.len());
        }
        Ok(())
    }

    /// Reads the next record from the datagrams (`dtls_get_more_records`), reporting each
    /// header to the message callback. `None`: more input is needed.
    ///
    /// # Errors
    /// The record layer failed (fatal, with OpenSSL's alert).
    pub(crate) fn fetch_record_dtls(&mut self, p: &dyn Provider) -> Result<Option<Record>> {
        let in_init = self.in_init();
        if let Some(d) = self.rr.dtls.as_mut() {
            d.in_init = in_init;
        }
        loop {
            // The rest of the datagram being read, then the records held for the epoch that
            // started, then the next datagram (OpenSSL's read buffer, its record layer's
            // `prev` BIO, the transport).
            if self.dtls.cur.is_empty() {
                self.dtls.cur = match self.rr.take_replay() {
                    Some(r) => r,
                    None => match self.dtls.input.pop_front() {
                        Some(d) => d,
                        None => {
                            self.needs_input = true;
                            return Ok(None);
                        }
                    },
                };
            }
            let buf = core::mem::take(&mut self.dtls.cur);
            let read = self.rr.read_dtls(p, &buf).map_err(|mut e| {
                if e.alert.is_some() {
                    e.follow_up = Some(abi::SSL_R_RECORD_LAYER_FAILURE);
                }
                e
            })?;
            let (consumed, header, record) = match read {
                DRead::Dropped { consumed, header } => (consumed, header, None),
                DRead::Record {
                    consumed, record, ..
                } => (consumed, Some(record.header.clone()), Some(record)),
            };
            if let Some(h) = header {
                let v = i32::from(u16::from_be_bytes([
                    h.get(1).copied().unwrap_or(0),
                    h.get(2).copied().unwrap_or(0),
                ]));
                self.report_message_v(false, v, abi::SSL3_RT_HEADER, &h);
            }
            self.dtls.cur = buf.get(consumed..).unwrap_or_default().to_vec();
            // A new read epoch drops the messages buffered for the old one
            // (`dtls1_increment_epoch`).
            let epoch = self.rr.dtls.as_ref().map_or(0, |d| d.epoch);
            if epoch != self.dtls.read_epoch {
                self.dtls.read_epoch = epoch;
                self.dtls_clear_received();
            }
            if let Some(r) = record {
                return Ok(Some(r));
            }
        }
    }

    /// The record layer's read for the handshake (`dtls1_read_bytes` with
    /// `SSL3_RT_HANDSHAKE`): handshake octets into `hs_rec`, or a ChangeCipherSpec; alerts are
    /// processed, application data after a ChangeCipherSpec is held for later.
    fn dtls_read_hs_record(&mut self, p: &dyn Provider) -> Result<HsRec> {
        loop {
            let Some(rec) = self.fetch_record_dtls(p)? else {
                return Ok(HsRec::Yield);
            };
            let ty = rec.content_type;
            if ty != alert() && !rec.data.is_empty() {
                self.alert_count = 0;
            }
            if self.change_cipher_spec && ty != handshake() {
                // The next epoch's records before the Finished: kept until it's processed.
                if self.dtls.held_app.len() < MAX_HELD_APP {
                    self.dtls.held_app.push_back(rec);
                }
                continue;
            }
            if self.shutdown & RECEIVED_SHUTDOWN != 0 {
                continue;
            }
            if ty == handshake() {
                self.dtls.hs_rec = rec.data;
                return Ok(HsRec::Handshake);
            }
            if ty == ccs() {
                return Ok(HsRec::Ccs(rec.data));
            }
            if ty == alert() {
                match self.process_alert(&rec.data)? {
                    super::AlertOutcome::Continue => continue,
                    super::AlertOutcome::Closed => return Ok(HsRec::Yield),
                }
            }
            if self.shutdown & SENT_SHUTDOWN != 0 {
                continue;
            }
            if ty == app_data() {
                if self.first_handshake {
                    return Err(Error::alert(
                        abi::SSL_AD_UNEXPECTED_MESSAGE,
                        abi::SSL_R_APP_DATA_IN_HANDSHAKE,
                    ));
                }
                if self.app_data_allowed() {
                    self.app_in.extend(rec.data.iter());
                    continue;
                }
            }
            return Err(Error::alert(
                abi::SSL_AD_UNEXPECTED_MESSAGE,
                abi::SSL_R_UNEXPECTED_RECORD,
            ));
        }
    }

    /// Takes up to `n` octets of the handshake record being read.
    fn take_hs(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(self.dtls.hs_rec.len());
        self.dtls.hs_rec.drain(..n).collect()
    }

    /// The next handshake message (`dtls_get_message` and `dtls_get_reassembled_message`):
    /// a buffered one whose turn came, else what the next fragments give; out-of-order and
    /// partial messages are buffered, stale ones dropped.
    ///
    /// # Errors
    /// A fatal error.
    pub(crate) fn dtls_get_message(&mut self, p: &dyn Provider) -> Result<DGot> {
        self.dtls_get_message_inner(p)
            .in_func("dtls_get_reassembled_message")
    }

    /// See [`Connection::dtls_get_message`].
    fn dtls_get_message_inner(&mut self, p: &dyn Provider) -> Result<DGot> {
        loop {
            if let Some(got) = self.retrieve_buffered()? {
                return Ok(got);
            }
            if self.dtls.hs_rec.is_empty() {
                match self.dtls_read_hs_record(p).in_func("dtls1_read_bytes")? {
                    HsRec::Yield => return Ok(DGot::Yield),
                    HsRec::Ccs(data) => {
                        if data.first() != Some(&msgs_type(abi::SSL3_MT_CCS)) {
                            return Err(Error::alert(
                                abi::SSL_AD_UNEXPECTED_MESSAGE,
                                abi::SSL_R_BAD_CHANGE_CIPHER_SPEC,
                            ));
                        }
                        // DTLS reports a received ChangeCipherSpec (`dtls_get_message`).
                        let one = data.get(..1).unwrap_or_default().to_vec();
                        self.report_message(false, abi::SSL3_RT_CHANGE_CIPHER_SPEC, &one);
                        return Ok(DGot::Ccs(data.len().saturating_sub(1)));
                    }
                    HsRec::Handshake => {}
                }
            }
            let hdr = self.take_hs(DTLS_HEADER_LEN);
            if hdr.len() != DTLS_HEADER_LEN {
                return Err(Error::alert(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_UNEXPECTED_MESSAGE,
                ));
            }
            let Some(h) = DtlsHeader::peek(&hdr) else {
                return Err(Error::internal());
            };
            let to = |v: u32| usize::try_from(v).unwrap_or(usize::MAX);
            let (mlen, foff, flen) = (to(h.len), to(h.fragment_offset), to(h.fragment_length));
            if flen > self.dtls.hs_rec.len() {
                return Err(Error::alert(
                    abi::SSL_AD_ILLEGAL_PARAMETER,
                    abi::SSL_R_BAD_LENGTH,
                ));
            }
            let body = self.take_hs(flen);
            let mut chretran = false;
            if h.message_seq != self.dtls.read_seq {
                if !self.cfg.server
                    || h.message_seq != 0
                    || self.dtls.read_seq != 1
                    || h.typ != msgs_type(abi::SSL3_MT_CLIENT_HELLO)
                    || self.st.hand_state != st(abi::DTLS_ST_SW_HELLO_VERIFY_REQUEST)
                {
                    self.out_of_seq(&h, foff, flen, mlen, body);
                    continue;
                }
                chretran = true;
            }
            if flen > 0 && flen < mlen {
                self.reassemble(&h, foff, flen, mlen, &body);
                continue;
            }
            if !self.cfg.server
                && self.st.hand_state != st(abi::TLS_ST_OK)
                && h.typ == msgs_type(abi::SSL3_MT_HELLO_REQUEST)
            {
                if hdr.get(1..4) == Some(&[0, 0, 0][..]) {
                    self.report_message(false, abi::SSL3_RT_HANDSHAKE, &hdr);
                    continue;
                }
                return Err(Error::alert(
                    abi::SSL_AD_UNEXPECTED_MESSAGE,
                    abi::SSL_R_UNEXPECTED_MESSAGE,
                ));
            }
            self.preprocess(foff, flen, mlen)?;
            if chretran {
                self.dtls.read_seq = 0;
                self.dtls.next_write_seq = 0;
            }
            let mut msg = body;
            msg.resize(mlen.min(flen), 0);
            self.deliver(h.typ, h.message_seq, mlen, &msg)?;
            return Ok(DGot::Message);
        }
    }

    /// `dtls1_preprocess_fragment`'s checks.
    fn preprocess(&self, foff: usize, flen: usize, mlen: usize) -> Result<()> {
        if foff.saturating_add(flen) > mlen || mlen > max_message_len(self) {
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_EXCESSIVE_MESSAGE_SIZE,
            )
            .in_func("dtls1_preprocess_fragment"));
        }
        Ok(())
    }

    /// Puts a whole message into `hs_in` with a TLS header, as its turn comes.
    fn deliver(&mut self, typ: u8, seq: u16, mlen: usize, body: &[u8]) -> Result<()> {
        let mut framed = msgs::frame(typ, body)?;
        // A short body (an empty fragment of a longer message) keeps the announced length.
        if body.len() != mlen {
            let l = u32::try_from(mlen)
                .map_err(|_| Error::internal())?
                .to_be_bytes();
            for (d, s) in framed.iter_mut().skip(1).zip(l.iter().skip(1)) {
                *d = *s;
            }
        }
        self.hs_in.extend_from_slice(&framed);
        self.dtls.cur_seq = seq;
        self.dtls.read_seq = seq.wrapping_add(1);
        Ok(())
    }

    /// `dtls1_retrieve_buffered_fragment`: the buffered message whose turn it is, if whole.
    fn retrieve_buffered(&mut self) -> Result<Option<DGot>> {
        let mut chretran = false;
        let key = loop {
            let Some((&seq, _)) = self.dtls.frags.iter().next() else {
                return Ok(None);
            };
            if seq >= self.dtls.read_seq {
                break seq;
            }
            let hvr_retry = self.cfg.server
                && seq == 0
                && self.dtls.read_seq == 1
                && self.st.hand_state == st(abi::DTLS_ST_SW_HELLO_VERIFY_REQUEST);
            if !hvr_retry {
                self.dtls.frags.remove(&seq);
                continue;
            }
            // A ClientHello again after our HelloVerifyRequest: unless the next one is here.
            if self.dtls.frags.contains_key(&self.dtls.read_seq) {
                self.dtls.frags.remove(&seq);
                continue;
            }
            chretran = true;
            break seq;
        };
        let Some(f) = self.dtls.frags.get(&key) else {
            return Ok(None);
        };
        if f.mask.is_some() {
            return Ok(None);
        }
        if key != self.dtls.read_seq && !chretran {
            return Ok(None);
        }
        let Some(f) = self.dtls.frags.remove(&key) else {
            return Ok(None);
        };
        self.preprocess(0, f.body.len(), f.len)
            .in_func("dtls1_retrieve_buffered_fragment")?;
        if chretran {
            self.dtls.read_seq = 0;
            self.dtls.next_write_seq = 0;
        }
        self.deliver(f.typ, key, f.len, &f.body)?;
        Ok(Some(DGot::Message))
    }

    /// `dtls1_process_out_of_seq_message`: buffers a message (or fragment) ahead of its
    /// turn, within reach; drops the rest.
    fn out_of_seq(&mut self, h: &DtlsHeader, foff: usize, flen: usize, mlen: usize, body: Vec<u8>) {
        if foff.saturating_add(flen) > mlen {
            return;
        }
        let seq = h.message_seq;
        let exists = self.dtls.frags.contains_key(&seq);
        let partial_of_existing = exists && flen != mlen;
        let read_seq = self.dtls.read_seq;
        if seq <= read_seq
            || seq > read_seq.saturating_add(MAX_AHEAD)
            || (exists && !partial_of_existing)
            || (read_seq == 0 && h.typ == msgs_type(abi::SSL3_MT_FINISHED))
        {
            return;
        }
        if flen != mlen {
            self.reassemble(h, foff, flen, mlen, &body);
            return;
        }
        if flen > max_message_len(self) {
            return;
        }
        self.dtls.frags.insert(
            seq,
            Frag {
                typ: h.typ,
                len: mlen,
                body,
                mask: None,
            },
        );
    }

    /// `dtls1_reassemble_fragment`: adds a fragment to its message, which is complete when
    /// every octet arrived.
    fn reassemble(&mut self, h: &DtlsHeader, foff: usize, flen: usize, mlen: usize, data: &[u8]) {
        let Some(end) = foff.checked_add(flen) else {
            return;
        };
        if end > mlen || mlen > max_message_len(self) || flen == 0 {
            return;
        }
        let f = self
            .dtls
            .frags
            .entry(h.message_seq)
            .or_insert_with(|| Frag {
                typ: h.typ,
                len: mlen,
                body: vec![0; mlen],
                mask: Some(vec![0; mlen.div_ceil(8)]),
            });
        if f.len != mlen {
            return;
        }
        let Some(mask) = f.mask.as_mut() else {
            // Already whole: the octets are discarded.
            return;
        };
        if let Some(dst) = f.body.get_mut(foff..end) {
            dst.copy_from_slice(data.get(..flen).unwrap_or_default());
        }
        for i in foff..end {
            if let Some(b) = mask.get_mut(i / 8) {
                *b |= 1 << (i % 8);
            }
        }
        let complete = (0..mlen).all(|i| mask.get(i / 8).is_some_and(|b| b & (1 << (i % 8)) != 0));
        if complete {
            f.mask = None;
        }
    }

    /// The message in `hs_in` (`raw`, with a TLS header) as the transcript and the message
    /// callback take it: with its DTLS header, unfragmented.
    pub(crate) fn dtls_full_form(&self, raw: &[u8]) -> Vec<u8> {
        let typ = raw.first().copied().unwrap_or(0);
        let body = raw.get(msgs::HEADER_LEN..).unwrap_or_default();
        let len = msgs::Header::peek(raw).map_or(0, |h| usize::try_from(h.len).unwrap_or(0));
        let hdr = hm_header(typ, len, self.dtls.cur_seq, 0, len).unwrap_or_default();
        [hdr, body.to_vec()].concat()
    }

    /// Application data held back during the handshake, once it finished
    /// (`dtls_unbuffer_record`).
    pub(crate) fn dtls_take_held_app(&mut self) -> Option<Record> {
        if self.in_init() {
            return None;
        }
        self.dtls.held_app.pop_front()
    }

    /// A handshake record after the handshake (`dtls1_read_bytes`): the peer's Finished
    /// again means our last flight was lost, and is retransmitted; anything else in the
    /// current epoch starts a handshake.
    ///
    /// # Errors
    /// Too many timeouts, or protection failed.
    pub(crate) fn dtls_post_handshake_record(
        &mut self,
        p: &dyn Provider,
        rec: Record,
    ) -> Result<bool> {
        if rec.data.len() < DTLS_HEADER_LEN {
            return Ok(false);
        }
        if rec.data.first() == Some(&msgs_type(abi::SSL3_MT_FINISHED)) {
            self.dtls_count_timeout(p)?;
            self.dtls_retransmit(p)?;
            return Ok(false);
        }
        self.dtls.hs_rec = rec.data;
        Ok(true)
    }
}
