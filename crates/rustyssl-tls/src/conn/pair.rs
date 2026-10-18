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
