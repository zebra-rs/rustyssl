//! The Certificate Management Protocol (RFC 9810, RFC 9483, `crypto/cmp`): its messages and their
//! ASN.1, the client's context, headers, PKIStatusInfo, creating, protecting, and validating
//! messages, the client's transactions, the server's context, general messages, and the HTTP
//! transfer.
//!
//! The structures mirror OpenSSL's (`cmp_local.h`) with their C field names, since other code
//! (the template engine, CRMF) reaches into them by layout.

#![allow(
    non_snake_case,
    non_upper_case_globals,
    reason = "OpenSSL's field, parameter, and constant names"
)]

pub(crate) mod asn;
pub(crate) mod client;
pub(crate) mod ctx;
pub(crate) mod genm;
pub(crate) mod hdr;
pub(crate) mod http;
pub(crate) mod msg;
pub(crate) mod protect;
pub(crate) mod server;
pub(crate) mod status;
pub(crate) mod util;
pub(crate) mod vfy;
