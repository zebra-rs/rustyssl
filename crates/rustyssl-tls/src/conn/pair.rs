//! A client and a server [`Connection`] run against each other over in-memory buffers, for
//! tests: each steps until it waits for input, its output goes to the other, and requests are
//! answered by the caller's closure.

use super::{Answer, Connection, Event, Request};
use crate::crypto::Provider;
use crate::error::Error;

/// Which end an event or failure belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum End {
    /// The client.
    Client,
    /// The server.
    Server,
}

/// What a run saw: the events each end reported (requests and output excluded), in order.
#[derive(Debug, Default)]
pub(crate) struct Log {
    /// The client's events.
    pub client: Vec<Event>,
    /// The server's events.
    pub server: Vec<Event>,
}

/// Steps `c` until it needs input or idles; returns whether it finished a handshake on the
/// way, with its output moved to `out`.
fn run(
    c: &mut Connection,
    p: &dyn Provider,
    end: End,
    reading: bool,
    answer: &mut dyn FnMut(End, &Request) -> Answer,
    out: &mut Vec<u8>,
    log: &mut Vec<Event>,
) -> Result<bool, Error> {
    let mut done = false;
    for _ in 0..100_000 {
        match c.step(p, reading)? {
            Event::Request(r) => {
                let a = answer(end, &r);
                c.answer(a);
            }
            Event::Output => out.extend(c.take_output()),
            Event::HandshakeDone => {
                done = true;
                out.extend(c.take_output());
                log.push(Event::HandshakeDone);
            }
            Event::NeedInput
            | Event::Idle
            | Event::AppData
            | Event::Closed
            | Event::Interrupted => {
                out.extend(c.take_output());
                return Ok(done);
            }
            e => log.push(e),
        }
    }
    Ok(done)
}

/// Runs the handshake between `client` and `server` until both finished it (or one waits
/// with nothing left to read), answering requests with `answer`. `reading` keeps both ends
/// reading after their handshakes (for TLS 1.3's tickets).
///
/// # Errors
/// The end that failed, and why (its alert is in its output, already delivered).
pub(crate) fn handshake(
    p: &dyn Provider,
    client: &mut Connection,
    server: &mut Connection,
    reading: bool,
    answer: &mut dyn FnMut(End, &Request) -> Answer,
    log: &mut Log,
) -> Result<(), (End, Error)> {
    let (mut cdone, mut sdone) = (false, false);
    for _ in 0..64 {
        let mut to_server = Vec::new();
        cdone |= run(
            client,
            p,
            End::Client,
            reading,
            answer,
            &mut to_server,
            &mut log.client,
        )
        .map_err(|e| (End::Client, e))?;
        server.feed(&to_server);
        let mut to_client = Vec::new();
        sdone |= run(
            server,
            p,
            End::Server,
            reading,
            answer,
            &mut to_client,
            &mut log.server,
        )
        .map_err(|e| (End::Server, e))?;
        client.feed(&to_client);
        if cdone && sdone && to_server.is_empty() && to_client.is_empty() {
            return Ok(());
        }
        if to_server.is_empty() && to_client.is_empty() && client.buffered_input() == 0 {
            break;
        }
    }
    if cdone && sdone {
        Ok(())
    } else {
        Err((End::Client, Error::internal()))
    }
}

/// Steps a DTLS end like [`run`], collecting its datagrams.
fn run_dtls(
    c: &mut Connection,
    p: &dyn Provider,
    end: End,
    reading: bool,
    answer: &mut dyn FnMut(End, &Request) -> Answer,
    out: &mut Vec<Vec<u8>>,
    log: &mut Vec<Event>,
) -> Result<bool, Error> {
    let mut done = false;
    for _ in 0..100_000 {
        match c.step(p, reading)? {
            Event::Request(r) => {
                let a = answer(end, &r);
                c.answer(a);
            }
            Event::Output => out.extend(c.take_datagrams()),
            Event::HandshakeDone => {
                done = true;
                out.extend(c.take_datagrams());
                log.push(Event::HandshakeDone);
            }
            Event::NeedInput
            | Event::Idle
            | Event::AppData
            | Event::Closed
            | Event::Interrupted => {
                out.extend(c.take_datagrams());
                return Ok(done);
            }
            e => log.push(e),
        }
    }
    Ok(done)
}

/// A DTLS handshake between `client` and `server`; `keep` decides which datagrams arrive
/// (the end that sent it and its number in that end's output); when nothing moves, both
/// ends' timers fire, as many times as `timeouts` allows.
///
/// # Errors
/// The end that failed, and why.
#[allow(clippy::too_many_arguments, reason = "the run's knobs")]
pub(crate) fn handshake_dtls(
    p: &dyn Provider,
    client: &mut Connection,
    server: &mut Connection,
    answer: &mut dyn FnMut(End, &Request) -> Answer,
    keep: &mut dyn FnMut(End, usize) -> bool,
    timeouts: usize,
    log: &mut Log,
) -> Result<(), (End, Error)> {
    let mut fate = |e: End, n: usize| {
        if keep(e, n) {
            Fate::Deliver
        } else {
            Fate::Drop
        }
    };
    handshake_dtls_faults(p, client, server, answer, &mut fate, timeouts, log)
}

/// What happens to a datagram on its way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fate {
    Deliver,
    Drop,
    Duplicate,
    /// Held back until the next datagram from the same end has arrived (or the timers fire).
    Delay,
}

/// One direction's datagrams on their way: the one held back, if any.
#[derive(Default)]
struct Wire {
    held: Option<Vec<u8>>,
}

impl Wire {
    fn carry(&mut self, to: &mut Connection, d: Vec<u8>, fate: Fate) {
        match fate {
            Fate::Drop => {}
            Fate::Delay if self.held.is_none() => self.held = Some(d),
            Fate::Duplicate => {
                to.feed_datagram(&d);
                to.feed_datagram(&d);
                self.release(to);
            }
            Fate::Deliver | Fate::Delay => {
                to.feed_datagram(&d);
                self.release(to);
            }
        }
    }

    fn release(&mut self, to: &mut Connection) {
        if let Some(h) = self.held.take() {
            to.feed_datagram(&h);
        }
    }
}

/// [`handshake_dtls`] with each datagram's fate from `fate` (the end that sent it and its
/// number in that end's output).
///
/// # Errors
/// The end that failed, and why.
#[allow(clippy::too_many_arguments, reason = "the run's knobs")]
pub(crate) fn handshake_dtls_faults(
    p: &dyn Provider,
    client: &mut Connection,
    server: &mut Connection,
    answer: &mut dyn FnMut(End, &Request) -> Answer,
    fate: &mut dyn FnMut(End, usize) -> Fate,
    timeouts: usize,
    log: &mut Log,
) -> Result<(), (End, Error)> {
    let (mut cdone, mut sdone) = (false, false);
    let (mut cn, mut sn) = (0usize, 0usize);
    let (mut up, mut down) = (Wire::default(), Wire::default());
    let mut fired = 0usize;
    for _ in 0..1024 {
        let mut to_server = Vec::new();
        cdone |= run_dtls(
            client,
            p,
            End::Client,
            false,
            answer,
            &mut to_server,
            &mut log.client,
        )
        .map_err(|e| (End::Client, e))?;
        let sent_c = !to_server.is_empty();
        for d in to_server {
            up.carry(server, d, fate(End::Client, cn));
            cn = cn.saturating_add(1);
        }
        let mut to_client = Vec::new();
        sdone |= run_dtls(
            server,
            p,
            End::Server,
            false,
            answer,
            &mut to_client,
            &mut log.server,
        )
        .map_err(|e| (End::Server, e))?;
        let sent_s = !to_client.is_empty();
        for d in to_client {
            down.carry(client, d, fate(End::Server, sn));
            sn = sn.saturating_add(1);
        }
        let held = up.held.is_some() || down.held.is_some();
        if cdone && sdone && !sent_c && !sent_s && !held {
            return Ok(());
        }
        if !sent_c && !sent_s {
            // Nothing moves: what was held back arrives, else the timers fire.
            if held {
                up.release(server);
                down.release(client);
                continue;
            }
            if fired >= timeouts {
                break;
            }
            fired = fired.saturating_add(1);
            client
                .dtls_retransmit_on_timeout(p)
                .map_err(|e| (End::Client, e))?;
            server
                .dtls_retransmit_on_timeout(p)
                .map_err(|e| (End::Server, e))?;
        }
    }
    if cdone && sdone {
        Ok(())
    } else {
        Err((End::Client, Error::internal()))
    }
}
