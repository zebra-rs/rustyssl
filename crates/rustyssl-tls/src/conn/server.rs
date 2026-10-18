//! The server's state machine (OpenSSL's `statem_serv.c` and `extensions_serv.c`).

use super::Connection;
use super::statem::{Construct, MsgProcess, Work, WriteTran};
use crate::crypto::Provider;
use crate::error::{Error, Result};

/// The server's handshake state.
#[derive(Debug, Default)]
pub struct State {}

/// Sets up a handshake.
pub(crate) fn setup(_c: &mut Connection, _p: &dyn Provider) -> Result<()> {
    Err(Error::internal())
}

/// Takes the Finished MAC the peer must send.
pub(crate) fn take_mac(_c: &mut Connection, _p: &dyn Provider) -> Result<()> {
    Err(Error::internal())
}

/// The read transition for message type `mt`.
pub(crate) fn read_transition(_c: &mut Connection, _mt: u8) -> Result<()> {
    Err(Error::internal())
}

/// The largest message allowed in the current state.
pub(crate) fn max_message_size(_c: &Connection) -> usize {
    0
}

/// Processes a message's body.
pub(crate) fn process_message(
    _c: &mut Connection,
    _p: &dyn Provider,
    _body: &[u8],
) -> Result<MsgProcess> {
    Err(Error::internal())
}

/// The work after processing a message.
pub(crate) fn post_process_message(
    _c: &mut Connection,
    _p: &dyn Provider,
    _wst: Work,
) -> Result<Work> {
    Err(Error::internal())
}

/// The write transition.
pub(crate) fn write_transition(_c: &mut Connection) -> Result<WriteTran> {
    Err(Error::internal())
}

/// The work before constructing a message.
pub(crate) fn pre_work(_c: &mut Connection, _p: &dyn Provider, _wst: Work) -> Result<Work> {
    Err(Error::internal())
}

/// The work after sending a message.
pub(crate) fn post_work(_c: &mut Connection, _p: &dyn Provider, _wst: Work) -> Result<Work> {
    Err(Error::internal())
}

/// Constructs the message for the current state: its type and body.
pub(crate) fn construct_message(_c: &mut Connection, _p: &dyn Provider) -> Result<(u8, Construct)> {
    Err(Error::internal())
}
