//! TLS 1.2's key exchange on the server (`tls_construct_server_key_exchange`,
//! `tls_process_client_key_exchange`, `tls_post_process_client_key_exchange`).

use super::Connection;
use crate::conn::statem::{Construct, MsgProcess, Work};
use crate::crypto::Provider;
use crate::error::{Error, Result};

/// `tls_construct_server_key_exchange`. Not yet implemented (fails closed).
pub(crate) fn construct_server_key_exchange(
    _c: &mut Connection,
    _p: &dyn Provider,
) -> Result<Construct> {
    Err(Error::internal())
}

/// `tls_process_client_key_exchange`. Not yet implemented (fails closed).
pub(crate) fn process_client_key_exchange(
    _c: &mut Connection,
    _p: &dyn Provider,
    _body: &[u8],
) -> Result<MsgProcess> {
    Err(Error::internal())
}

/// `tls_post_process_client_key_exchange`. Not yet implemented (fails closed).
pub(crate) fn post_process_client_key_exchange(
    _c: &mut Connection,
    _p: &dyn Provider,
    _wst: Work,
) -> Result<Work> {
    Err(Error::internal())
}
