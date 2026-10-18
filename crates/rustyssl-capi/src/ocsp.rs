//! OCSP (`crypto/ocsp`, RFC 6960): its structures ([`asn`]), certificate IDs ([`id`]), the
//! client ([`cl`]) and responder ([`srv`]) sides, extensions ([`ext`]), printing ([`prn`]),
//! verifying ([`vfy`]), and its X.509v3 extension methods ([`v3`]).
//!
//! Sending requests over HTTP (`OCSP_sendreq_*`) comes with the HTTP client (step 6.8).

pub(crate) mod asn;
pub(crate) mod cl;
pub(crate) mod ext;
pub(crate) mod http;
pub(crate) mod id;
pub(crate) mod prn;
pub(crate) mod srv;
pub(crate) mod v3;
pub(crate) mod vfy;
