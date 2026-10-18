//! The server's extension handlers (`extensions_srvr.c`): the parsers of the client's
//! extensions (`tls_parse_ctos_*`) and the constructors of the server's (`tls_construct_stoc_*`),
//! which `common::ext` dispatches to. The PSK parser is with the tickets ([`super::ticket`]).

use rustyssl_abi as abi;

use super::{octet, send_certificate_request, state, state_ref, ticket};
use crate::codec::Reader;
use crate::conn::common::ext::{Ctx, ExtReturn, Step};
use crate::conn::common::{
    self, CERT_TYPE_CTOS_ERROR, CERT_TYPE_CTOS_GOOD, CERT_TYPE_CTOS_NONE, Hrr, KEX_MODE_FLAG_KE,
    KEX_MODE_FLAG_KE_DHE, Pha, STATUSTYPE_NOTHING, ask_once, finished, groups,
};
use crate::conn::{Answer, Connection, Request};
use crate::consts::context as cx;
use crate::consts::version as v;
use crate::crypto::Provider;
use crate::error::{Error, Result};
use crate::msgs::ext as mx;
use crate::suites::masks::{
    SSL_AEAD, SSL_KUZNYECHIK, SSL_MAGMA, SSL_RC4, SSL_aECDSA, SSL_eGOST2814789CNT,
    SSL_eGOST2814789CNT12, SSL_kECDHE,
};

/// `TLSEXT_KEX_MODE_KE` (RFC 8446's psk_ke).
const KEX_MODE_KE: u8 = 0;
/// `TLSEXT_KEX_MODE_KE_DHE` (psk_dhe_ke).
const KEX_MODE_KE_DHE: u8 = 1;

/// `TLSEXT_cert_type_x509`.
fn x509() -> u8 {
    octet(abi::TLSEXT_cert_type_x509)
}

/// `tls_parse_ctos_renegotiate`: the client's renegotiation binding must be its last Finished
/// (`SSL_R_RENEGOTIATION_MISMATCH`, handshake-failure); then renegotiation_info is answered.
pub(crate) fn ext_parse_renegotiate(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    let data = mx::renegotiate::parse_client(body)?;
    if data != c.neg.client_finished {
        return Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_RENEGOTIATION_MISMATCH,
        ));
    }
    state(c)?.send_connection_binding = true;
    Ok(Step::Done)
}

/// `tls_parse_ctos_server_name`: one host name, at most 255 octets and without NULs
/// (`SSL_R_BAD_EXTENSION` with unrecognized-name), kept for the servername callback; resuming a
/// TLS 1.2 session, the name is only compared with the session's.
pub(crate) fn ext_parse_server_name(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    let host = mx::server_name::parse_client(body)?;
    if !c.neg.reused || c.is_tls13() {
        let max = usize::try_from(abi::TLSEXT_MAXLEN_host_name).unwrap_or(255);
        if host.len() > max || host.contains(&0) {
            return Err(Error::alert(
                abi::SSL_AD_UNRECOGNIZED_NAME,
                abi::SSL_R_BAD_EXTENSION,
            ));
        }
        c.neg.servername = Some(host);
        c.hs.sh.servername_done = true;
    } else {
        c.hs.sh.servername_done = c.neg.session.hostname.as_deref() == Some(&host[..]);
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_maxfragmentlen`: a valid mode becomes the session's, unless the session
/// (resumed) already has one.
pub(crate) fn ext_parse_maxfragmentlen(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    let mode = mx::max_fragment_length::parse(body)?;
    if c.neg.session.max_fragment_len_mode == octet(abi::TLSEXT_max_fragment_length_UNSPECIFIED) {
        c.neg.session.max_fragment_len_mode = mode;
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_srp`: the SRP login name.
pub(crate) fn ext_parse_srp(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    c.hs.sh.srp_login = Some(mx::srp::parse(body)?);
    Ok(Step::Done)
}

/// `tls_parse_ctos_ec_pt_formats`: the client's point formats, kept for a new session.
pub(crate) fn ext_parse_ec_pt_formats(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    let list = mx::ec_point_formats::parse_client(body)?;
    if !c.neg.reused {
        c.hs.sh.peer_ecpointformats = Some(list);
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_supported_groups`: the client's groups, kept for a new session (and always
/// in TLS 1.3).
pub(crate) fn ext_parse_supported_groups(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    let list = mx::supported_groups::parse(body)?;
    if !c.neg.reused || c.is_tls13() {
        c.neg.peer_groups = list;
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_session_ticket`: the ticket is read by the session lookup; the
/// `SSL_set_session_ticket_ext_cb` callback (EAP-FAST) has no request yet.
pub(crate) fn ext_parse_session_ticket(
    _c: &mut Connection,
    _p: &dyn Provider,
    _body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    Ok(Step::Done)
}

/// Whether `der` is one DER element of the given class and tag that fills it.
fn der_is(der: &[u8], class: u8, tags: &[i32], constructed: bool) -> bool {
    rustyssl_asn1::der::element(der).is_ok_and(|e| {
        e.raw.len() == der.len()
            && e.header.class == class
            && tags.contains(&e.header.tag)
            && e.header.constructed == constructed
    })
}

/// `tls_parse_ctos_status_request`: an OCSP request (ignored when resuming, in a client's
/// Certificate, or of another type), with its responder IDs (`d2i_OCSP_RESPID`: `byName [1]`
/// or `byKey [2]`, each filling its vector) and request extensions (`d2i_X509_EXTENSIONS`: a
/// SEQUENCE of SEQUENCEs filling the vector), all `SSL_R_BAD_EXTENSION` with decode-error when
/// they don't decode. The responder IDs and extensions are kept for the status callback
/// (`SSL_get_tlsext_status_ids`, `_exts`).
pub(crate) fn ext_parse_status_request(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    x: &Ctx,
) -> Result<Step> {
    if c.neg.reused || x.context != cx::CLIENT_HELLO {
        return Ok(Step::Done);
    }
    let bad = Error::decode(abi::SSL_R_BAD_EXTENSION);
    match mx::status_request::parse(body)? {
        mx::status_request::Request::Other(_) => {
            c.hs.sh.status_type = STATUSTYPE_NOTHING;
        }
        mx::status_request::Request::Ocsp {
            responder_ids,
            extensions,
        } => {
            c.hs.sh.status_type = abi::TLSEXT_STATUSTYPE_ocsp;
            for id in &responder_ids {
                if !der_is(id, 2, &[1, 2], true) {
                    return Err(bad);
                }
            }
            if !extensions.is_empty() {
                let ok = rustyssl_asn1::der::element(&extensions).is_ok_and(|e| {
                    e.raw.len() == extensions.len()
                        && e.header.class == 0
                        && e.header.tag == 16
                        && e.header.constructed
                        && every_sequence(e.content)
                });
                if !ok {
                    return Err(bad);
                }
            }
            let s = state(c)?;
            s.ocsp_ids = responder_ids;
            s.ocsp_exts = extensions;
        }
    }
    Ok(Step::Done)
}

/// Whether `b` is a run of DER SEQUENCEs.
fn every_sequence(mut b: &[u8]) -> bool {
    while !b.is_empty() {
        let Ok(e) = rustyssl_asn1::der::element(b) else {
            return false;
        };
        if !(e.header.class == 0 && e.header.tag == 16 && e.header.constructed) {
            return false;
        }
        b = b.get(e.raw.len()..).unwrap_or_default();
    }
    true
}

/// `tls_parse_ctos_npn`: NPN is seen (not on a renegotiation).
pub(crate) fn ext_parse_npn(
    c: &mut Connection,
    _p: &dyn Provider,
    _body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if finished::is_first_handshake(c) {
        c.hs.sh.npn_seen = true;
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_alpn`: the client's protocols, for the ALPN callback (not on a
/// renegotiation).
pub(crate) fn ext_parse_alpn(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if !finished::is_first_handshake(c) {
        return Ok(Step::Done);
    }
    c.hs.sh.alpn_proposed = Some(mx::alpn::parse_client(body)?);
    Ok(Step::Done)
}

/// `tls_parse_ctos_use_srtp`: with SRTP profiles configured, the first of this end's
/// preference the client offers.
pub(crate) fn ext_parse_use_srtp(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if c.cfg.srtp_profiles.is_empty() {
        return Ok(Step::Done);
    }
    let offer = mx::use_srtp::parse_client(body)?;
    let ours = &c.cfg.srtp_profiles;
    let mut pref = ours.len();
    let mut chosen = None;
    for id in &offer.profiles {
        if let Some(i) = ours.iter().take(pref).position(|x| x == id) {
            chosen = Some(*id);
            pref = i;
        }
    }
    c.hs.sh.srtp_profile = chosen;
    Ok(Step::Done)
}

/// `tls_parse_ctos_etm`: encrypt-then-MAC, unless `SSL_OP_NO_ENCRYPT_THEN_MAC`.
pub(crate) fn ext_parse_etm(
    c: &mut Connection,
    _p: &dyn Provider,
    _body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if c.cfg.options & abi::SSL_OP_NO_ENCRYPT_THEN_MAC == 0 {
        c.hs.sh.use_etm = true;
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_ems`: empty (`SSL_R_BAD_EXTENSION`, decode-error); received unless
/// `SSL_OP_NO_EXTENDED_MASTER_SECRET`.
pub(crate) fn ext_parse_ems(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    if c.cfg.options & abi::SSL_OP_NO_EXTENDED_MASTER_SECRET == 0 {
        c.hs.sh.flags |= abi::TLS1_FLAGS_RECEIVED_EXTMS;
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_post_handshake_auth`: empty (`SSL_R_POST_HANDSHAKE_AUTH_ENCODING_ERR`,
/// decode-error); the client accepts post-handshake authentication.
pub(crate) fn ext_parse_post_handshake_auth(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_POST_HANDSHAKE_AUTH_ENCODING_ERR));
    }
    c.hs.sh.pha = Pha::ExtReceived;
    Ok(Step::Done)
}

/// `reconcile_cert_type`: the first of `pref` that `other` has.
fn reconcile_cert_type(pref: &[u8], other: &[u8]) -> Option<u8> {
    pref.iter().copied().find(|t| other.contains(t))
}

/// `tls_parse_ctos_client_cert_type`: with client certificate types configured, the
/// client's first that this end accepts (none is only an error when a certificate is asked
/// for, in [`ext_construct_client_cert_type`]).
pub(crate) fn ext_parse_client_cert_type(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if c.cfg.client_cert_types.is_empty() {
        c.hs.sh.client_cert_type_ctos = CERT_TYPE_CTOS_NONE;
        c.neg.client_cert_type = x509();
        return Ok(Step::Done);
    }
    let list = match mx::cert_type::parse_client(body) {
        Ok(l) => l,
        Err(e) => {
            c.hs.sh.client_cert_type_ctos = CERT_TYPE_CTOS_ERROR;
            return Err(e);
        }
    };
    match reconcile_cert_type(&list, &c.cfg.client_cert_types) {
        Some(t) => {
            c.hs.sh.client_cert_type_ctos = CERT_TYPE_CTOS_GOOD;
            c.neg.client_cert_type = t;
        }
        None => c.hs.sh.client_cert_type_ctos = CERT_TYPE_CTOS_ERROR,
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_server_cert_type`: with server certificate types configured, this end's
/// first that the client accepts; none is `SSL_R_BAD_EXTENSION` with
/// unsupported-certificate.
pub(crate) fn ext_parse_server_cert_type(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if c.cfg.server_cert_types.is_empty() {
        c.hs.sh.server_cert_type_ctos = CERT_TYPE_CTOS_NONE;
        c.neg.server_cert_type = x509();
        return Ok(Step::Done);
    }
    let list = mx::cert_type::parse_client(body)?;
    if let Some(t) = reconcile_cert_type(&c.cfg.server_cert_types, &list) {
        c.hs.sh.server_cert_type_ctos = CERT_TYPE_CTOS_GOOD;
        c.neg.server_cert_type = t;
        return Ok(Step::Done);
    }
    c.hs.sh.server_cert_type_ctos = CERT_TYPE_CTOS_ERROR;
    Err(Error::alert(
        abi::SSL_AD_UNSUPPORTED_CERTIFICATE,
        abi::SSL_R_BAD_EXTENSION,
    ))
}

/// `tls_parse_ctos_psk_kex_modes`: psk_dhe_ke, and psk_ke with `SSL_OP_ALLOW_NO_DHE_KEX` (alone
/// with `SSL_OP_PREFER_NO_DHE_KEX`).
pub(crate) fn ext_parse_psk_kex_modes(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    let modes = mx::psk_key_exchange_modes::parse(body)?;
    let o = c.cfg.options;
    for m in modes {
        if m == KEX_MODE_KE_DHE {
            c.hs.sh.psk_kex_mode |= KEX_MODE_FLAG_KE_DHE;
        } else if m == KEX_MODE_KE && o & abi::SSL_OP_ALLOW_NO_DHE_KEX != 0 {
            c.hs.sh.psk_kex_mode |= KEX_MODE_FLAG_KE;
        }
    }
    if c.hs.sh.psk_kex_mode & KEX_MODE_FLAG_KE != 0 && o & abi::SSL_OP_PREFER_NO_DHE_KEX != 0 {
        c.hs.sh.psk_kex_mode = KEX_MODE_FLAG_KE;
    }
    Ok(Step::Done)
}

/// Whether group `g` is usable for TLS 1.3 here (`tls_group_allowed` for
/// `SSL_SECOP_CURVE_SUPPORTED` and `tls_valid_group`).
fn usable13(c: &Connection, g: u16) -> bool {
    groups::allowed(c, g, abi::SSL_SECOP_CURVE_SUPPORTED)
        && groups::valid(c, g, v::TLS1_3, v::TLS1_3, false).0
}

/// `check_overlap`: the candidate whose position in `prio` comes first (in `prio`, allowed
/// and usable); its index in `prio`, its index in `candidates`, and the group.
fn check_overlap(c: &Connection, prio: &[u16], candidates: &[u16]) -> Option<(usize, usize, u16)> {
    let mut best: Option<(usize, usize, u16)> = None;
    for (ci, &g) in candidates.iter().enumerate() {
        let Some(pi) = groups::check_in_list(c, g, prio, true) else {
            continue;
        };
        if !usable13(c, g) {
            continue;
        }
        if best.is_none_or(|(b, _, _)| pi < b) {
            best = Some((pi, ci, *prio.get(pi)?));
        }
    }
    best
}

/// `tls_accept_ksgroup`: the client's share for `group` is used; the server's own share (or a
/// KEM's ciphertext) and the shared secret are made now, so that a share that doesn't decode
/// fails here (`SSL_R_BAD_ECPOINT`, illegal-parameter), as `tls13_set_encoded_pub_key` does.
fn accept_ksgroup(c: &mut Connection, p: &dyn Provider, group: u16, key: &[u8]) -> Result<()> {
    c.hs.sh.group_id = group;
    c.hs.sh.group_id_candidate = group;
    c.neg.group = Some(group);
    c.hs.sh.peer_tmp = Some((group, key.to_vec()));
    let share = p
        .respond(group, key)
        .map_err(|_| Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_ECPOINT))?;
    // Shared addition (fork N): the server's own share is its temporary key
    // (`SSL_get_tmp_key`); a KEM's ciphertext isn't a key.
    let kem = groups::lookup(c, group).is_some_and(|g| g.is_kem);
    c.hs.sh.own_tmp = if kem {
        None
    } else {
        Some((group, share.0.clone()))
    };
    state(c)?.share = Some(share);
    Ok(())
}

/// `tls_parse_ctos_key_share`: the client's shares (`extract_keyshares`: each for a group it
/// listed in supported_groups, `SSL_R_BAD_KEY_SHARE` otherwise; after a HelloRetryRequest
/// exactly one, for the group asked for), then 3.5's selection by the server's group tuples:
/// in the first tuple that shares a group with the client, a group the client sent a share
/// for is accepted, or else a supported one is the candidate for a HelloRetryRequest. With
/// `SSL_OP_CIPHER_SERVER_PREFERENCE` this end's order within the tuple wins, otherwise the
/// client's. A resumption without psk_dhe_ke ignores the shares.
pub(crate) fn ext_parse_key_share(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    c.hs.sh.group_id_candidate = 0;
    if c.neg.reused && c.hs.sh.psk_kex_mode & KEX_MODE_FLAG_KE_DHE == 0 {
        return Ok(Step::Done);
    }
    if c.hs.sh.peer_tmp.is_some() {
        return Err(Error::internal());
    }
    let mm = Error::decode(abi::SSL_R_LENGTH_MISMATCH);
    let bad = Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_KEY_SHARE);
    let mut rd = Reader::new(body);
    let mut list = rd.vec16().map_err(|_| mm)?;
    rd.end().map_err(|_| mm)?;
    let srvr = groups::supported(c);
    let starts = groups::tuples(c);
    let clnt = c.neg.peer_groups.clone();
    if clnt.is_empty() {
        return Err(Error::alert(
            abi::SSL_AD_MISSING_EXTENSION,
            abi::SSL_R_MISSING_SUPPORTED_GROUPS_EXTENSION,
        ));
    }
    let hrr_group = c.hs.sh.group_id;
    if hrr_group != 0 && list.is_empty() {
        return Err(bad);
    }
    let mut shares: Vec<(u16, Vec<u8>)> = Vec::new();
    while !list.is_empty() {
        let group = list.u16().map_err(|_| mm)?;
        let key = list.vec16().map_err(|_| mm)?;
        if key.is_empty() {
            return Err(mm);
        }
        if hrr_group != 0 && (group != hrr_group || !list.is_empty()) {
            return Err(bad);
        }
        if groups::check_in_list(c, group, &clnt, false).is_none() {
            return Err(bad);
        }
        if hrr_group != 0 {
            accept_ksgroup(c, p, hrr_group, key.rest())?;
            return Ok(Step::Done);
        }
        if groups::check_in_list(c, group, &srvr, true).is_none() || !usable13(c, group) {
            continue;
        }
        shares.push((group, key.rest().to_vec()));
    }
    let share_groups: Vec<u16> = shares.iter().map(|s| s.0).collect();
    let server_pref = c.cfg.options & abi::SSL_OP_CIPHER_SERVER_PREFERENCE != 0;
    for (i, &start) in starts.iter().enumerate() {
        let end = starts
            .get(i.saturating_add(1))
            .copied()
            .unwrap_or(srvr.len());
        let tuple = srvr.get(start..end).unwrap_or_default();
        if server_pref {
            if let Some((_, ci, g)) = check_overlap(c, tuple, &share_groups) {
                let key = shares.get(ci).map(|s| s.1.clone()).unwrap_or_default();
                accept_ksgroup(c, p, g, &key)?;
                return Ok(Step::Done);
            }
            if let Some((_, _, g)) = check_overlap(c, tuple, &clnt) {
                c.hs.sh.group_id_candidate = g;
                return Ok(Step::Done);
            }
        } else {
            if let Some((pi, _, g)) = check_overlap(c, &share_groups, tuple) {
                let key = shares.get(pi).map(|s| s.1.clone()).unwrap_or_default();
                accept_ksgroup(c, p, g, &key)?;
                return Ok(Step::Done);
            }
            if let Some((_, _, g)) = check_overlap(c, &clnt, tuple) {
                c.hs.sh.group_id_candidate = g;
                return Ok(Step::Done);
            }
        }
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_cookie`: only a stateless server (`SSL_stateless`) reads its cookie,
/// which this port doesn't do yet: it fails closed (an internal error) rather than accept an
/// unchecked cookie.
pub(crate) fn ext_parse_cookie(
    c: &mut Connection,
    _p: &dyn Provider,
    _body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if !c.cfg.callbacks.cookie || c.hs.sh.flags & abi::TLS1_FLAGS_STATELESS == 0 {
        return Ok(Step::Done);
    }
    Err(Error::internal())
}

/// `tls_parse_ctos_early_data`: empty, and not after a HelloRetryRequest
/// (`SSL_R_BAD_EXTENSION`: decode-error, illegal-parameter).
pub(crate) fn ext_parse_early_data(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &Ctx,
) -> Result<Step> {
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    if c.hs.sh.hrr != Hrr::None {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    Ok(Step::Done)
}

/// `tls_parse_ctos_psk` ([`ticket::parse_psk`]).
pub(crate) fn ext_parse_psk(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
    x: &Ctx,
) -> Result<Step> {
    ticket::parse_psk(c, p, body, x)
}

/// `tls_construct_stoc_renegotiate`: both Finished values, once the client asked for the
/// binding (even with `SSL_OP_NO_RENEGOTIATION`).
pub(crate) fn ext_construct_renegotiate(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if !state_ref(c).is_some_and(|s| s.send_connection_binding) {
        return Ok(ExtReturn::NotSent);
    }
    let both = [
        c.neg.client_finished.as_slice(),
        c.neg.server_finished.as_slice(),
    ]
    .concat();
    Ok(ExtReturn::Sent(mx::renegotiate::encode(&both)?))
}

/// `tls_construct_stoc_server_name`: an empty acknowledgement of the name, unless resuming
/// TLS 1.2 (which keeps the session's).
pub(crate) fn ext_construct_server_name(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if !c.hs.sh.servername_done || (c.neg.reused && !c.is_tls13()) {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(Vec::new()))
}

/// `tls_construct_stoc_maxfragmentlen`: the session's mode, when it has one.
pub(crate) fn ext_construct_maxfragmentlen(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    let mode = c.neg.session.max_fragment_len_mode;
    if common::ext::max_fragment_length(mode).is_none() {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(vec![mode]))
}

/// `tls_construct_stoc_ec_pt_formats`: this end's formats, with an ECDHE or ECDSA suite and
/// the client's list received.
pub(crate) fn ext_construct_ec_pt_formats(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    let nc = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let using_ecc = (nc.mkey & SSL_kECDHE != 0 || nc.auth & SSL_aECDSA != 0)
        && c.hs.sh.peer_ecpointformats.is_some();
    if !using_ecc {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(mx::ec_point_formats::encode(
        &groups::formats(c),
    )?))
}

/// `tls_construct_stoc_supported_groups` (TLS 1.3): this end's groups, unless the client's
/// share is already for the most preferred one.
pub(crate) fn ext_construct_supported_groups(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    let id = c.hs.sh.group_id;
    if id == 0 {
        return Ok(ExtReturn::NotSent);
    }
    let all = groups::supported(c);
    if all.is_empty() {
        return Err(Error::internal());
    }
    let ver = c.neg.version;
    let usable: Vec<u16> = all
        .into_iter()
        .filter(|&g| {
            groups::valid(c, g, ver, ver, false).0
                && groups::allowed(c, g, abi::SSL_SECOP_CURVE_SUPPORTED)
        })
        .collect();
    match usable.first() {
        None => Ok(ExtReturn::NotSent),
        Some(&first) if first == id => Ok(ExtReturn::NotSent),
        Some(_) => Ok(ExtReturn::Sent(mx::supported_groups::encode(&usable)?)),
    }
}

/// `tls_construct_stoc_session_ticket`: empty, when a TLS 1.2 ticket will be sent.
pub(crate) fn ext_construct_session_ticket(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if !c.hs.sh.ticket_expected || !common::security::use_ticket(c) {
        c.hs.sh.ticket_expected = false;
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(Vec::new()))
}

/// `tls_construct_stoc_status_request`: when a response will be sent; TLS 1.2's is empty (the
/// response is a CertificateStatus), TLS 1.3's carries it, in the leaf's entry.
pub(crate) fn ext_construct_status_request(
    c: &mut Connection,
    _p: &dyn Provider,
    x: &Ctx,
) -> Result<ExtReturn> {
    if x.context == cx::TLS1_3_CERTIFICATE_REQUEST
        || !state_ref(c).is_some_and(|s| s.status_expected)
        || (c.is_tls13() && x.chainidx != 0)
    {
        return Ok(ExtReturn::NotSent);
    }
    if c.is_tls13() {
        return Ok(ExtReturn::Sent(super::cert_status_body(c)?));
    }
    Ok(ExtReturn::Sent(Vec::new()))
}

/// `tls_construct_stoc_next_proto_neg`: once NPN was seen, the protocols the advertisement
/// callback gives ([`Request::Npn`]).
pub(crate) fn ext_construct_next_proto_neg(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if !c.hs.sh.npn_seen || !c.cfg.callbacks.npn {
        c.hs.sh.npn_seen = false;
        return Ok(ExtReturn::NotSent);
    }
    match ask_once(c, Request::Npn { protos: Vec::new() }, 0) {
        None => Ok(ExtReturn::Wait),
        Some(Answer::Npn(Some(list))) => Ok(ExtReturn::Sent(list)),
        Some(_) => {
            c.hs.sh.npn_seen = false;
            Ok(ExtReturn::NotSent)
        }
    }
}

/// `tls_construct_stoc_alpn`: the protocol selected.
pub(crate) fn ext_construct_alpn(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    match &c.neg.alpn {
        None => Ok(ExtReturn::NotSent),
        Some(sel) => Ok(ExtReturn::Sent(mx::alpn::encode_server(sel)?)),
    }
}

/// `tls_construct_stoc_use_srtp`: the profile chosen.
pub(crate) fn ext_construct_use_srtp(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    match c.hs.sh.srtp_profile {
        None => Ok(ExtReturn::NotSent),
        Some(id) => Ok(ExtReturn::Sent(mx::use_srtp::encode_server(id)?)),
    }
}

/// `tls_construct_stoc_etm`: encrypt-then-MAC, unless the suite is an AEAD, RC4, or GOST's
/// stream modes (which turns it off).
pub(crate) fn ext_construct_etm(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if !c.hs.sh.use_etm {
        return Ok(ExtReturn::NotSent);
    }
    let nc = c.hs.new_cipher.ok_or_else(Error::internal)?;
    if nc.mac == SSL_AEAD
        || nc.enc == SSL_RC4
        || nc.enc == SSL_eGOST2814789CNT
        || nc.enc == SSL_eGOST2814789CNT12
        || nc.enc == SSL_MAGMA
        || nc.enc == SSL_KUZNYECHIK
    {
        c.hs.sh.use_etm = false;
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(Vec::new()))
}

/// `tls_construct_stoc_ems`: Extended Master Secret, when received.
pub(crate) fn ext_construct_ems(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if c.hs.sh.flags & abi::TLS1_FLAGS_RECEIVED_EXTMS == 0 {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(Vec::new()))
}

/// `tls_construct_stoc_client_cert_type`: the type the client's certificate must have, when
/// one is asked for (now, or later with post-handshake authentication). A client without an
/// acceptable type that would be asked fails (`SSL_R_BAD_EXTENSION`,
/// unsupported-certificate).
pub(crate) fn ext_construct_client_cert_type(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    let asks = send_certificate_request(c) || c.hs.sh.pha == Pha::ExtReceived;
    if c.hs.sh.client_cert_type_ctos == CERT_TYPE_CTOS_ERROR && asks {
        return Err(Error::alert(
            abi::SSL_AD_UNSUPPORTED_CERTIFICATE,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    if c.neg.client_cert_type == x509() {
        c.hs.sh.client_cert_type_ctos = CERT_TYPE_CTOS_NONE;
        return Ok(ExtReturn::NotSent);
    }
    if !asks
        || c.hs.sh.client_cert_type_ctos != CERT_TYPE_CTOS_GOOD
        || c.cfg.client_cert_types.is_empty()
    {
        c.hs.sh.client_cert_type_ctos = CERT_TYPE_CTOS_NONE;
        c.neg.client_cert_type = x509();
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(vec![c.neg.client_cert_type]))
}

/// `tls_construct_stoc_server_cert_type`: the type of the server's certificate, when the
/// client's list had one this end prefers to X.509.
pub(crate) fn ext_construct_server_cert_type(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if c.neg.server_cert_type == x509() {
        c.hs.sh.server_cert_type_ctos = CERT_TYPE_CTOS_NONE;
        return Ok(ExtReturn::NotSent);
    }
    if c.hs.sh.server_cert_type_ctos != CERT_TYPE_CTOS_GOOD || c.cfg.server_cert_types.is_empty() {
        c.hs.sh.server_cert_type_ctos = CERT_TYPE_CTOS_NONE;
        c.neg.server_cert_type = x509();
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(vec![c.neg.server_cert_type]))
}

/// `tls_construct_stoc_supported_versions`: TLS 1.3.
pub(crate) fn ext_construct_supported_versions(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if !c.is_tls13() {
        return Err(Error::internal());
    }
    Ok(ExtReturn::Sent(mx::supported_versions::encode_server(
        c.neg.version,
    )?))
}

/// `tls_construct_stoc_key_share`: a HelloRetryRequest names the group it wants (unless the
/// client's share was acceptable); a ServerHello carries the server's share (or a KEM's
/// ciphertext), and the handshake secret is derived from the shared secret, or (a resumption
/// with psk_ke) without one.
pub(crate) fn ext_construct_key_share(
    c: &mut Connection,
    p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if c.hs.sh.hrr == Hrr::Pending {
        if c.hs.sh.peer_tmp.is_some() {
            return Ok(ExtReturn::NotSent);
        }
        return Ok(ExtReturn::Sent(mx::key_share::encode_hrr(
            c.hs.sh.group_id,
        )?));
    }
    let did_kex = state_ref(c).is_some_and(|s| s.did_kex);
    if c.hs.sh.peer_tmp.is_none() {
        if !c.neg.reused {
            return Err(Error::internal());
        }
        if !did_kex {
            common::keys::generate_handshake_secret(c, p, None)?;
            state(c)?.did_kex = true;
        }
        return Ok(ExtReturn::NotSent);
    }
    if c.neg.reused && c.hs.sh.psk_kex_mode & KEX_MODE_FLAG_KE_DHE == 0 {
        return Ok(ExtReturn::NotSent);
    }
    let group = c.hs.sh.group_id;
    if groups::lookup(c, group).is_none() {
        return Err(Error::internal());
    }
    let (public, secret) = state(c)?.share.clone().ok_or_else(Error::internal)?;
    let body = mx::key_share::encode_server(&mx::key_share::Entry { group, key: public })?;
    if !did_kex {
        common::keys::generate_handshake_secret(c, p, Some(secret.bytes()))?;
        state(c)?.did_kex = true;
    }
    Ok(ExtReturn::Sent(body))
}

/// `tls_construct_stoc_cookie`: only a stateless server sends one, which this port doesn't do
/// yet (fails closed).
pub(crate) fn ext_construct_cookie(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if c.hs.sh.flags & abi::TLS1_FLAGS_STATELESS == 0 {
        return Ok(ExtReturn::NotSent);
    }
    Err(Error::alert(
        abi::SSL_AD_INTERNAL_ERROR,
        abi::SSL_R_NO_COOKIE_CALLBACK_SET,
    ))
}

/// The CryptoPro bug's extension body (`cryptopro_ext` without its type and length).
const CRYPTOPRO_BODY: [u8; 32] = [
    0x30, 0x1e, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x09, 0x30, 0x08, 0x06, 0x06,
    0x2a, 0x85, 0x03, 0x02, 0x02, 0x16, 0x30, 0x08, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x17,
];

/// `tls_construct_stoc_cryptopro_bug`: with `SSL_OP_CRYPTOPRO_TLSEXT_BUG` and a GOST suite
/// (0x0080, 0x0081), the fixed extension CryptoPro's clients expect.
pub(crate) fn ext_construct_cryptopro_bug(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    let id = c.hs.new_cipher.map_or(0, |x| x.id & 0xffff);
    if (id != 0x80 && id != 0x81) || c.cfg.options & abi::SSL_OP_CRYPTOPRO_TLSEXT_BUG == 0 {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(CRYPTOPRO_BODY.to_vec()))
}

/// `tls_construct_stoc_early_data`: a NewSessionTicket's limit (`SSL_set_max_early_data`), or
/// EncryptedExtensions' acceptance.
pub(crate) fn ext_construct_early_data(
    c: &mut Connection,
    _p: &dyn Provider,
    x: &Ctx,
) -> Result<ExtReturn> {
    if x.context == cx::TLS1_3_NEW_SESSION_TICKET {
        if c.cfg.max_early_data == 0 {
            return Ok(ExtReturn::NotSent);
        }
        return Ok(ExtReturn::Sent(mx::early_data::encode_ticket(
            c.cfg.max_early_data,
        )?));
    }
    if c.neg.early_data_status != abi::SSL_EARLY_DATA_ACCEPTED {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(Vec::new()))
}

/// `tls_construct_stoc_psk`: the identity resumed.
pub(crate) fn ext_construct_psk(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &Ctx,
) -> Result<ExtReturn> {
    if !c.neg.reused {
        return Ok(ExtReturn::NotSent);
    }
    let id = state_ref(c).map_or(0, |s| s.tick_identity);
    Ok(ExtReturn::Sent(mx::psk::encode_server(id)?))
}
