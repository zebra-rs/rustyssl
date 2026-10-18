//! The handshake state machine's driver (OpenSSL's `statem.c`): the message flow alternates
//! between writing and reading sub-machines, each resumable at its sub-state, and the client
//! and server supply the transitions, the work before and after each message, and the
//! messages themselves (`client.rs`, `server.rs`).
//!
//! The observable sequence is OpenSSL's: the info callback's `SSL_CB_*_LOOP` before each write
//! transition and after each message header is read, `SSL_CB_HANDSHAKE_START` when a handshake
//! begins, and the message callback for each message as it is read and written.

use rustyssl_abi as abi;

use super::funcs::{self, Phase};
use super::{Connection, client, server};
use crate::crypto::Provider;
use crate::error::{Error, InFunc, Result};
use crate::msgs;

/// The message flow (`MSG_FLOW_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MsgFlow {
    /// No handshake yet.
    #[default]
    Uninited,
    /// A fatal error happened.
    Error,
    /// Reading messages.
    Reading,
    /// Writing messages.
    Writing,
    /// The handshake finished.
    Finished,
}

/// The writing sub-machine's state (`WRITE_STATE_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WriteState {
    /// Choosing the next message.
    #[default]
    Transition,
    /// The work before constructing it.
    PreWork,
    /// Sending it.
    Send,
    /// The work after sending it.
    PostWork,
}

/// The reading sub-machine's state (`READ_STATE_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ReadState {
    /// Reading a message's header.
    #[default]
    Header,
    /// Reading and processing its body.
    Body,
    /// The work after processing it.
    PostProcess,
}

/// Where pre-work, post-work, and post-processing stand (`WORK_*`). The `More` states are
/// resumption points: the function is called again with the same state after the caller
/// supplied what was missing (output taken, input fed, a request answered).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Work {
    /// Failed (the error is returned alongside).
    Error,
    /// Done; the handshake ends.
    FinishedStop,
    /// Done; carry on in the same direction.
    FinishedContinue,
    /// Done; switch direction.
    FinishedSwap,
    /// Not done; resume here.
    #[default]
    MoreA,
    /// Not done; resume here.
    MoreB,
    /// Not done; resume here.
    MoreC,
}

/// A write transition's outcome (`WRITE_TRAN_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTran {
    /// There is a message to write.
    Continue,
    /// Nothing more to write: read next.
    Finished,
}

/// What processing a message decided (`MSG_PROCESS_*`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsgProcess {
    /// Done reading: switch to writing.
    FinishedReading,
    /// Post-processing follows.
    ContinueProcessing,
    /// Read the next message.
    ContinueReading,
    /// Waiting for an answer to a request (the message is processed again after it).
    Ask,
}

/// A constructed message (`confunc`'s result).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Construct {
    /// A message body to send with the handshake type given.
    Send(Vec<u8>),
    /// The construction function decided not to send it (`CON_FUNC_DONT_SEND`).
    DontSend,
    /// Not a real message (`SSL3_MT_DUMMY`): skip to post-work.
    Dummy,
    /// Waiting for an answer to a request (construction runs again after it).
    Ask,
}

/// The state machine's state (`OSSL_STATEM`).
#[derive(Clone, Debug, Default)]
pub struct Statem {
    /// The message flow.
    pub state: MsgFlow,
    /// The writing sub-machine.
    pub write_state: WriteState,
    /// Its work state.
    pub write_state_work: Work,
    /// The reading sub-machine.
    pub read_state: ReadState,
    /// Its work state.
    pub read_state_work: Work,
    /// The handshake state (`OSSL_HANDSHAKE_STATE`, `TLS_ST_*`).
    pub hand_state: u32,
    /// A state requested from outside (`SSL_key_update`, `SSL_verify_client_post_handshake`,
    /// `SSL_renegotiate`).
    pub request_state: u32,
    /// Whether a handshake is in progress (`SSL_in_init`).
    pub in_init: bool,
    /// Whether the first read of a handshake is pending (`read_state_first_init`).
    pub read_state_first_init: bool,
    /// The nesting of handshake processing (`in_handshake`).
    pub in_handshake: u32,
    /// Whether the write side should clean up the handshake (`cleanuphand`).
    pub cleanuphand: bool,
    /// Whether the peer's CertificateVerify is skipped (`no_cert_verify`).
    pub no_cert_verify: bool,
    /// The type of the message being read (`s->s3.tmp.message_type`).
    pub message_type: u8,
    /// The size its header announced (`s->s3.tmp.message_size`).
    pub message_size: usize,
    /// Whether the message callback for the info LOOP before the current read transition was
    /// already reported (a resumed read doesn't report it twice).
    pub(crate) loop_reported: bool,
    /// Whether the header of the message being read has been taken (`init_num`'s header).
    pub(crate) header_done: bool,
    /// Shared fix (tls-server): whether the message being read is a ChangeCipherSpec record
    /// rather than a handshake message. `message_type` can't tell them apart: the CCS
    /// pseudo-type (`SSL3_MT_CHANGE_CIPHER_SPEC`, 0x101) doesn't fit an octet and becomes 0,
    /// HelloRequest's type, so a HelloRequest must never pass for a ChangeCipherSpec.
    pub(crate) ccs: bool,
}

/// The handshake state as a `TLS_ST_*` number.
pub(crate) fn st(v: abi::OSSL_HANDSHAKE_STATE) -> u32 {
    v
}

/// The info callback's `where` for a loop or an exit on this side.
fn where_(server: bool, server_value: i32, client_value: i32) -> i32 {
    if server { server_value } else { client_value }
}

impl Connection {
    /// The handshake state machine (`state_machine`), run until it yields. Returns `Ok(true)`
    /// when the handshake finished.
    ///
    /// # Errors
    /// A fatal error (the alert is already queued).
    pub(crate) fn state_machine(&mut self, p: &dyn Provider) -> Result<bool> {
        if self.st.state == MsgFlow::Error {
            return Err(self.failed.unwrap_or_else(Error::internal));
        }
        if matches!(self.st.state, MsgFlow::Uninited | MsgFlow::Finished) {
            if self.st.state == MsgFlow::Uninited {
                self.st.hand_state = st(abi::TLS_ST_BEFORE);
                self.st.request_state = st(abi::TLS_ST_BEFORE);
            }
            if self.cfg.callbacks.info && (self.first_handshake || !self.is_tls13()) {
                self.notify(super::Event::Info {
                    where_: abi::SSL_CB_HANDSHAKE_START,
                    ret: 1,
                });
            }
            if self.before() || self.renegotiate {
                self.setup_handshake(p).in_func("tls_setup_handshake")?;
                if self.first_handshake {
                    self.st.read_state_first_init = true;
                }
            }
            self.st.state = MsgFlow::Writing;
            self.st.write_state = WriteState::Transition;
            self.st.in_init = true;
            if self.cfg.dtls {
                // `ssl_init_wbio_buffer`: records collect into datagrams until a flush.
                self.dtls.buffering = true;
            }
            if self.has_events() {
                return Ok(false);
            }
        }
        while self.st.state != MsgFlow::Finished {
            let done = match self.st.state {
                MsgFlow::Reading => match self.read_state_machine(p)? {
                    Sub::Finished => {
                        self.st.state = MsgFlow::Writing;
                        self.st.write_state = WriteState::Transition;
                        true
                    }
                    Sub::EndHandshake => {
                        self.st.state = MsgFlow::Finished;
                        true
                    }
                    Sub::Yield => false,
                },
                MsgFlow::Writing => match self.write_state_machine(p)? {
                    Sub::Finished => {
                        self.st.state = MsgFlow::Reading;
                        self.st.read_state = ReadState::Header;
                        self.st.loop_reported = false;
                        true
                    }
                    Sub::EndHandshake => {
                        self.st.state = MsgFlow::Finished;
                        true
                    }
                    Sub::Yield => false,
                },
                _ => return Err(Error::internal()),
            };
            if !done || self.has_events() {
                return Ok(self.st.state == MsgFlow::Finished);
            }
        }
        Ok(true)
    }

    /// The reading sub-machine (`read_state_machine`).
    fn read_state_machine(&mut self, p: &dyn Provider) -> Result<Sub> {
        if self.st.read_state_first_init {
            self.first_packet = true;
            self.st.read_state_first_init = false;
        }
        loop {
            match self.st.read_state {
                ReadState::Header => {
                    if !self.st.header_done {
                        match self.get_message_header(p)? {
                            Got::Yes => self.st.header_done = true,
                            Got::Yield => return Ok(Sub::Yield),
                        }
                    }
                    if self.cfg.callbacks.info && !self.st.loop_reported {
                        self.st.loop_reported = true;
                        let w = where_(
                            self.cfg.server,
                            abi::SSL_CB_ACCEPT_LOOP,
                            abi::SSL_CB_CONNECT_LOOP,
                        );
                        self.notify(super::Event::Info { where_: w, ret: 1 });
                        return Ok(Sub::Yield);
                    }
                    let mt = self.st.message_type;
                    let tr = if self.cfg.server {
                        server::read_transition(self, mt).in_func(funcs::of(
                            true,
                            Phase::ReadTransition,
                            self.st.hand_state,
                        ))
                    } else {
                        client::read_transition(self, mt).in_func(funcs::of(
                            false,
                            Phase::ReadTransition,
                            self.st.hand_state,
                        ))
                    };
                    match tr {
                        Ok(()) => {}
                        Err(e) if self.cfg.dtls && e.reason == -1 && e.alert.is_none() => {
                            // Dropped: read the next message.
                            self.cur_msg = None;
                            self.st.header_done = false;
                            self.st.loop_reported = false;
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
                    let max = if self.cfg.server {
                        server::max_message_size(self)
                    } else {
                        client::max_message_size(self)
                    };
                    if self.st.message_size > max {
                        return Err(Error::alert(
                            abi::SSL_AD_ILLEGAL_PARAMETER,
                            abi::SSL_R_EXCESSIVE_MESSAGE_SIZE,
                        )
                        .in_func("read_state_machine"));
                    }
                    self.st.read_state = ReadState::Body;
                }
                ReadState::Body => {
                    if self.cur_msg.is_none() {
                        match self.get_message_body(p)? {
                            Got::Yes => {}
                            Got::Yield => return Ok(Sub::Yield),
                        }
                        self.first_packet = false;
                        if self.has_events() {
                            return Ok(Sub::Yield);
                        }
                    }
                    let body = self.cur_msg.clone().map(|m| m.1).unwrap_or_default();
                    let r = if self.cfg.server {
                        server::process_message(self, p, &body).in_func(funcs::of(
                            true,
                            Phase::Process,
                            self.st.hand_state,
                        ))?
                    } else {
                        client::process_message(self, p, &body).in_func(funcs::of(
                            false,
                            Phase::Process,
                            self.st.hand_state,
                        ))?
                    };
                    if r == MsgProcess::Ask {
                        return Ok(Sub::Yield);
                    }
                    self.cur_msg = None;
                    self.st.header_done = false;
                    self.st.loop_reported = false;
                    match r {
                        MsgProcess::FinishedReading => {
                            if self.cfg.dtls {
                                self.dtls_stop_timer();
                            }
                            return Ok(Sub::Finished);
                        }
                        MsgProcess::ContinueProcessing => {
                            self.st.read_state = ReadState::PostProcess;
                            self.st.read_state_work = Work::MoreA;
                        }
                        _ => self.st.read_state = ReadState::Header,
                    }
                    if self.has_events() {
                        return Ok(Sub::Yield);
                    }
                }
                ReadState::PostProcess => {
                    let wst = self.st.read_state_work;
                    let w = if self.cfg.server {
                        server::post_process_message(self, p, wst).in_func(funcs::of(
                            true,
                            Phase::PostProcess,
                            self.st.hand_state,
                        ))?
                    } else {
                        client::post_process_message(self, p, wst).in_func(funcs::of(
                            false,
                            Phase::PostProcess,
                            self.st.hand_state,
                        ))?
                    };
                    self.st.read_state_work = w;
                    match w {
                        Work::Error => return Err(self.failed.unwrap_or_else(Error::internal)),
                        Work::MoreA | Work::MoreB | Work::MoreC => return Ok(Sub::Yield),
                        Work::FinishedContinue => self.st.read_state = ReadState::Header,
                        Work::FinishedSwap => {
                            if self.cfg.dtls {
                                self.dtls_stop_timer();
                            }
                            return Ok(Sub::Finished);
                        }
                        Work::FinishedStop => {
                            if self.cfg.dtls {
                                self.dtls_stop_timer();
                            }
                            return Ok(Sub::EndHandshake);
                        }
                    }
                }
            }
        }
    }

    /// The writing sub-machine (`write_state_machine`).
    fn write_state_machine(&mut self, p: &dyn Provider) -> Result<Sub> {
        loop {
            match self.st.write_state {
                WriteState::Transition => {
                    if self.cfg.callbacks.info && !self.st.loop_reported {
                        self.st.loop_reported = true;
                        let w = where_(
                            self.cfg.server,
                            abi::SSL_CB_ACCEPT_LOOP,
                            abi::SSL_CB_CONNECT_LOOP,
                        );
                        self.notify(super::Event::Info { where_: w, ret: 1 });
                        return Ok(Sub::Yield);
                    }
                    let t = if self.cfg.server {
                        server::write_transition(self).in_func(funcs::of(
                            true,
                            Phase::WriteTransition,
                            self.st.hand_state,
                        ))?
                    } else {
                        client::write_transition(self).in_func(funcs::of(
                            false,
                            Phase::WriteTransition,
                            self.st.hand_state,
                        ))?
                    };
                    self.st.loop_reported = false;
                    match t {
                        WriteTran::Continue => {
                            self.st.write_state = WriteState::PreWork;
                            self.st.write_state_work = Work::MoreA;
                        }
                        WriteTran::Finished => return Ok(Sub::Finished),
                    }
                }
                WriteState::PreWork => {
                    let wst = self.st.write_state_work;
                    let w = if self.cfg.server {
                        server::pre_work(self, p, wst).in_func(funcs::of(
                            true,
                            Phase::PreWork,
                            self.st.hand_state,
                        ))?
                    } else {
                        client::pre_work(self, p, wst).in_func(funcs::of(
                            false,
                            Phase::PreWork,
                            self.st.hand_state,
                        ))?
                    };
                    self.st.write_state_work = w;
                    match w {
                        Work::Error => return Err(self.failed.unwrap_or_else(Error::internal)),
                        Work::MoreA | Work::MoreB | Work::MoreC => return Ok(Sub::Yield),
                        Work::FinishedContinue => {}
                        Work::FinishedSwap => return Ok(Sub::Finished),
                        Work::FinishedStop => return Ok(Sub::EndHandshake),
                    }
                    let (mt, c) = if self.cfg.server {
                        server::construct_message(self, p).in_func(funcs::of(
                            true,
                            Phase::Construct,
                            self.st.hand_state,
                        ))?
                    } else {
                        client::construct_message(self, p).in_func(funcs::of(
                            false,
                            Phase::Construct,
                            self.st.hand_state,
                        ))?
                    };
                    if c != Construct::Ask {
                        self.hs.sh.answers.clear();
                    }
                    match c {
                        Construct::Ask => {
                            // Construction runs again, from pre-work done, after the answer.
                            self.st.write_state_work = Work::FinishedContinue;
                            self.st.write_state = WriteState::Send;
                            self.pending_construct = true;
                            return Ok(Sub::Yield);
                        }
                        Construct::Dummy | Construct::DontSend => {
                            self.st.write_state = WriteState::PostWork;
                            self.st.write_state_work = Work::MoreA;
                        }
                        Construct::Send(body) => {
                            self.queue_handshake_message(p, mt, &body)?;
                            self.st.write_state = WriteState::PostWork;
                            self.st.write_state_work = Work::MoreA;
                        }
                    }
                }
                WriteState::Send => {
                    // Only reached to retry a construction that asked for an answer.
                    if self.pending_construct {
                        let (mt, c) = if self.cfg.server {
                            server::construct_message(self, p).in_func(funcs::of(
                                true,
                                Phase::Construct,
                                self.st.hand_state,
                            ))?
                        } else {
                            client::construct_message(self, p).in_func(funcs::of(
                                false,
                                Phase::Construct,
                                self.st.hand_state,
                            ))?
                        };
                        if c != Construct::Ask {
                            self.hs.sh.answers.clear();
                        }
                        match c {
                            Construct::Ask => return Ok(Sub::Yield),
                            Construct::Dummy | Construct::DontSend => {}
                            Construct::Send(body) => self.queue_handshake_message(p, mt, &body)?,
                        }
                        self.pending_construct = false;
                    }
                    self.st.write_state = WriteState::PostWork;
                    self.st.write_state_work = Work::MoreA;
                }
                WriteState::PostWork => {
                    let wst = self.st.write_state_work;
                    let w = if self.cfg.server {
                        server::post_work(self, p, wst).in_func(funcs::of(
                            true,
                            Phase::PostWork,
                            self.st.hand_state,
                        ))?
                    } else {
                        client::post_work(self, p, wst).in_func(funcs::of(
                            false,
                            Phase::PostWork,
                            self.st.hand_state,
                        ))?
                    };
                    self.st.write_state_work = w;
                    match w {
                        Work::Error => return Err(self.failed.unwrap_or_else(Error::internal)),
                        Work::MoreA | Work::MoreB | Work::MoreC => return Ok(Sub::Yield),
                        Work::FinishedContinue => self.st.write_state = WriteState::Transition,
                        Work::FinishedSwap => return Ok(Sub::Finished),
                        Work::FinishedStop => return Ok(Sub::EndHandshake),
                    }
                    if self.has_events() {
                        return Ok(Sub::Yield);
                    }
                }
            }
        }
    }

    /// Frames a handshake message, adds it to the transcript (`ssl_close_construct_packet`:
    /// all but HelloRequest, and TLS 1.3's post-handshake KeyUpdate and NewSessionTicket),
    /// reports it to the message callback, and writes it (`ssl_do_write`).
    pub(crate) fn queue_handshake_message(
        &mut self,
        p: &dyn Provider,
        mt: u8,
        body: &[u8],
    ) -> Result<()> {
        if self.cfg.dtls {
            return self.dtls_send_message(p, mt, body);
        }
        // Shared fix (tls-server): the CCS pseudo-type is 0 as an octet, HelloRequest's type,
        // so the state says which is meant.
        if mt == msgs_type(abi::SSL3_MT_CHANGE_CIPHER_SPEC)
            && (self.st.hand_state == st(abi::TLS_ST_SW_CHANGE)
                || self.st.hand_state == st(abi::TLS_ST_CW_CHANGE))
        {
            let ccs = [msgs_type(abi::SSL3_MT_CCS)];
            self.write_record(p, msgs_type(abi::SSL3_RT_CHANGE_CIPHER_SPEC), &ccs)?;
            self.report_message(true, abi::SSL3_RT_CHANGE_CIPHER_SPEC, &ccs);
            return Ok(());
        }
        let msg = msgs::frame(mt, body)?;
        let post_handshake_13 = self.is_tls13()
            && (mt == msgs_type(abi::SSL3_MT_NEWSESSION_TICKET)
                || mt == msgs_type(abi::SSL3_MT_KEY_UPDATE));
        if mt != msgs_type(abi::SSL3_MT_HELLO_REQUEST) && !post_handshake_13 {
            self.hs.transcript.add(&msg);
        }
        self.write_record(p, msgs_type(abi::SSL3_RT_HANDSHAKE), &msg)?;
        self.report_message(true, abi::SSL3_RT_HANDSHAKE, &msg);
        Ok(())
    }

    /// Reads a handshake message's header (`tls_get_message_header`): ignores a client's
    /// well-formed HelloRequests mid-handshake, takes a ChangeCipherSpec as a message of its
    /// own.
    fn get_message_header(&mut self, p: &dyn Provider) -> Result<Got> {
        self.get_message_header_inner(p)
            .in_func("tls_get_message_header")
    }

    /// See [`Connection::get_message_header`].
    fn get_message_header_inner(&mut self, p: &dyn Provider) -> Result<Got> {
        if self.cfg.dtls && self.hs_in.len() < msgs::HEADER_LEN {
            match self.dtls_get_message(p)? {
                super::dtls::DGot::Yield => return Ok(Got::Yield),
                super::dtls::DGot::Ccs(extra) => {
                    self.st.message_type = msgs_type(abi::SSL3_MT_CHANGE_CIPHER_SPEC);
                    self.st.ccs = true;
                    self.st.message_size = extra;
                    self.cur_msg = Some((self.st.message_type, vec![0; extra]));
                    return Ok(Got::Yes);
                }
                super::dtls::DGot::Message => {}
            }
        }
        loop {
            while self.hs_in.len() < msgs::HEADER_LEN {
                match self.read_handshake_bytes(p)? {
                    HsBytes::Got => {}
                    HsBytes::Ccs => {
                        if !self.hs_in.is_empty() {
                            return Err(Error::alert(
                                abi::SSL_AD_UNEXPECTED_MESSAGE,
                                abi::SSL_R_BAD_CHANGE_CIPHER_SPEC,
                            ));
                        }
                        self.st.message_type = msgs_type(abi::SSL3_MT_CHANGE_CIPHER_SPEC);
                        self.st.ccs = true;
                        self.st.message_size = 1;
                        self.cur_msg = Some((self.st.message_type, Vec::new()));
                        return Ok(Got::Yes);
                    }
                    HsBytes::Yield => return Ok(Got::Yield),
                }
            }
            let hello_request = !self.cfg.server
                && self.st.hand_state != st(abi::TLS_ST_OK)
                && self.hs_in.first() == Some(&msgs_type(abi::SSL3_MT_HELLO_REQUEST))
                && self.hs_in.get(1..4) == Some(&[0, 0, 0][..]);
            if hello_request {
                let h: Vec<u8> = self.hs_in.drain(..msgs::HEADER_LEN).collect();
                self.report_message(false, abi::SSL3_RT_HANDSHAKE, &h);
                continue;
            }
            break;
        }
        let Some(h) = msgs::Header::peek(&self.hs_in) else {
            return Err(Error::internal());
        };
        self.st.message_type = h.typ;
        self.st.ccs = false;
        if self.sslv2_record {
            // The rest of the SSLv2 record is the ClientHello (`tls_get_message_header`).
            self.st.message_size = self.hs_in.len();
        } else {
            let len = usize::try_from(h.len).map_err(|_| Error::internal())?;
            let limit = usize::try_from(i32::MAX)
                .unwrap_or(usize::MAX)
                .saturating_sub(msgs::HEADER_LEN);
            if len > limit {
                return Err(Error::alert(
                    abi::SSL_AD_ILLEGAL_PARAMETER,
                    abi::SSL_R_EXCESSIVE_MESSAGE_SIZE,
                ));
            }
            self.st.message_size = len;
        }
        Ok(Got::Yes)
    }

    /// Reads a handshake message's body (`tls_get_message_body`), takes the Finished MAC
    /// before a Finished, and adds the message to the transcript (all but TLS 1.3's
    /// post-handshake KeyUpdate and NewSessionTicket, and a HelloRetryRequest, which the
    /// client adds while processing it).
    fn get_message_body(&mut self, p: &dyn Provider) -> Result<Got> {
        self.get_message_body_inner(p)
            .in_func("tls_get_message_body")
    }

    /// See [`Connection::get_message_body`].
    fn get_message_body_inner(&mut self, p: &dyn Provider) -> Result<Got> {
        if self.st.message_type == msgs_type(abi::SSL3_MT_CHANGE_CIPHER_SPEC)
            && self.cur_msg.is_some()
        {
            return Ok(Got::Yes);
        }
        let total = if self.sslv2_record {
            self.st.message_size
        } else {
            msgs::HEADER_LEN.saturating_add(self.st.message_size)
        };
        while self.hs_in.len() < total {
            match self.read_handshake_bytes(p)? {
                HsBytes::Got => {}
                HsBytes::Ccs => {
                    return Err(Error::alert(
                        abi::SSL_AD_UNEXPECTED_MESSAGE,
                        abi::SSL_R_CCS_RECEIVED_EARLY,
                    ));
                }
                HsBytes::Yield => return Ok(Got::Yield),
            }
        }
        let raw: Vec<u8> = self.hs_in.drain(..total).collect();
        // A new message: what the last one collected and asked is done with.
        self.hs.sh.received.clear();
        self.hs.sh.answers.clear();
        if self.st.message_type == msgs_type(abi::SSL3_MT_FINISHED) {
            self.take_mac(p)?;
        }
        if self.sslv2_record {
            self.hs.transcript.add(&raw);
            self.report_message_v(false, i32::from(crate::record::SSL2_VERSION), 0, &raw);
            self.cur_msg = Some((self.st.message_type, raw));
            return Ok(Got::Yes);
        }
        let mt = self.st.message_type;
        let post13 = self.is_tls13()
            && (mt == msgs_type(abi::SSL3_MT_NEWSESSION_TICKET)
                || mt == msgs_type(abi::SSL3_MT_KEY_UPDATE));
        let hrr = mt == msgs_type(abi::SSL3_MT_SERVER_HELLO)
            && raw.get(msgs::HEADER_LEN.saturating_add(2)..msgs::HEADER_LEN.saturating_add(34))
                == Some(&crate::consts::HRR_RANDOM[..]);
        if self.cfg.dtls {
            let full = self.dtls_full_form(&raw);
            self.hs.transcript.add(&full);
            self.report_message(false, abi::SSL3_RT_HANDSHAKE, &full);
            let body = raw.get(msgs::HEADER_LEN..).unwrap_or_default().to_vec();
            self.cur_msg = Some((mt, body));
            return Ok(Got::Yes);
        }
        if !post13 && !hrr {
            self.hs.transcript.add(&raw);
        }
        self.report_message(false, abi::SSL3_RT_HANDSHAKE, &raw);
        let body = raw.get(msgs::HEADER_LEN..).unwrap_or_default().to_vec();
        self.cur_msg = Some((mt, body));
        Ok(Got::Yes)
    }
}

/// A sub-machine's outcome (`SUB_STATE_*`; errors are `Err`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sub {
    /// Switch direction.
    Finished,
    /// The handshake ended.
    EndHandshake,
    /// Stopped to report an event or wait for the caller.
    Yield,
}

/// Whether a read got what it wanted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Got {
    /// It did.
    Yes,
    /// Stopped to report an event or wait for input.
    Yield,
}

/// What reading handshake bytes found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HsBytes {
    /// Handshake octets were added to the buffer.
    Got,
    /// A ChangeCipherSpec record (TLS 1.2 and earlier).
    Ccs,
    /// Stopped to report an event or wait for input.
    Yield,
}

/// A handshake or record type constant as its octet.
pub(crate) fn msgs_type(v: core::ffi::c_int) -> u8 {
    u8::try_from(v).unwrap_or(0)
}
