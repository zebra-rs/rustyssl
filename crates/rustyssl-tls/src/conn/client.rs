//! The client's state machine (OpenSSL's `statem_clie.c` and `extensions_clie.c`).

use super::Connection;
use super::common::ext::{self, ExtReturn, Step};
use super::statem::{Construct, MsgProcess, Work, WriteTran};
use crate::crypto::Provider;
use crate::error::{Error, Result};

/// The client's handshake state.
#[derive(Debug, Default)]
pub struct State {}

/// Sets up a handshake: the client's part of `tls_setup_handshake` (the common checks are
/// made first, in `common::setup_handshake`).
pub(crate) fn setup(_c: &mut Connection, _p: &dyn Provider) -> Result<()> {
    Ok(())
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

/// `tls_process_initial_server_flight`: the client's checks once the server's first flight is
/// complete (after its TLS 1.3 Finished, or TLS 1.2's ServerHelloDone): the OCSP status
/// callback and the CT validation callback. Not yet implemented (fails closed).
pub(crate) fn process_initial_server_flight(_c: &mut Connection, _p: &dyn Provider) -> Result<()> {
    Err(Error::internal())
}

/// Declares the client's extension handlers, each failing closed until implemented: the
/// constructors (`tls_construct_ctos_*`) and the parsers (`tls_parse_stoc_*`) that
/// `common::ext` dispatches to.
macro_rules! ext_handlers {
    (construct { $($c:ident => $cf:literal,)* } parse { $($pa:ident => $pf:literal,)* }) => {
        $(
            #[doc = concat!("`", $cf, "` (`extensions_clnt.c`). Not yet implemented (fails closed).")]
            pub(crate) fn $c(_c: &mut Connection, _p: &dyn Provider, _x: &ext::Ctx) -> Result<ExtReturn> {
                Err(Error::internal())
            }
        )*
        $(
            #[doc = concat!("`", $pf, "` (`extensions_clnt.c`). Not yet implemented (fails closed).")]
            pub(crate) fn $pa(_c: &mut Connection, _p: &dyn Provider, _body: &[u8], _x: &ext::Ctx) -> Result<Step> {
                Err(Error::internal())
            }
        )*
    };
}

ext_handlers! {
    construct {
        ext_construct_renegotiate => "tls_construct_ctos_renegotiate",
        ext_construct_server_name => "tls_construct_ctos_server_name",
        ext_construct_maxfragmentlen => "tls_construct_ctos_maxfragmentlen",
        ext_construct_srp => "tls_construct_ctos_srp",
        ext_construct_ec_pt_formats => "tls_construct_ctos_ec_pt_formats",
        ext_construct_supported_groups => "tls_construct_ctos_supported_groups",
        ext_construct_session_ticket => "tls_construct_ctos_session_ticket",
        ext_construct_status_request => "tls_construct_ctos_status_request",
        ext_construct_npn => "tls_construct_ctos_npn",
        ext_construct_alpn => "tls_construct_ctos_alpn",
        ext_construct_use_srtp => "tls_construct_ctos_use_srtp",
        ext_construct_etm => "tls_construct_ctos_etm",
        ext_construct_sct => "tls_construct_ctos_sct",
        ext_construct_ems => "tls_construct_ctos_ems",
        ext_construct_post_handshake_auth => "tls_construct_ctos_post_handshake_auth",
        ext_construct_client_cert_type => "tls_construct_ctos_client_cert_type",
        ext_construct_server_cert_type => "tls_construct_ctos_server_cert_type",
        ext_construct_supported_versions => "tls_construct_ctos_supported_versions",
        ext_construct_psk_kex_modes => "tls_construct_ctos_psk_kex_modes",
        ext_construct_key_share => "tls_construct_ctos_key_share",
        ext_construct_cookie => "tls_construct_ctos_cookie",
        ext_construct_early_data => "tls_construct_ctos_early_data",
        ext_construct_padding => "tls_construct_ctos_padding",
        ext_construct_psk => "tls_construct_ctos_psk",
    }
    parse {
        ext_parse_renegotiate => "tls_parse_stoc_renegotiate",
        ext_parse_server_name => "tls_parse_stoc_server_name",
        ext_parse_maxfragmentlen => "tls_parse_stoc_maxfragmentlen",
        ext_parse_ec_pt_formats => "tls_parse_stoc_ec_pt_formats",
        ext_parse_session_ticket => "tls_parse_stoc_session_ticket",
        ext_parse_status_request => "tls_parse_stoc_status_request",
        ext_parse_npn => "tls_parse_stoc_npn",
        ext_parse_alpn => "tls_parse_stoc_alpn",
        ext_parse_use_srtp => "tls_parse_stoc_use_srtp",
        ext_parse_etm => "tls_parse_stoc_etm",
        ext_parse_sct => "tls_parse_stoc_sct",
        ext_parse_ems => "tls_parse_stoc_ems",
        ext_parse_client_cert_type => "tls_parse_stoc_client_cert_type",
        ext_parse_server_cert_type => "tls_parse_stoc_server_cert_type",
        ext_parse_supported_versions => "tls_parse_stoc_supported_versions",
        ext_parse_key_share => "tls_parse_stoc_key_share",
        ext_parse_cookie => "tls_parse_stoc_cookie",
        ext_parse_early_data => "tls_parse_stoc_early_data",
        ext_parse_psk => "tls_parse_stoc_psk",
    }
}
