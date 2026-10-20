//! The client's extension handlers (`extensions_clnt.c`): the ClientHello's constructors
//! (`tls_construct_ctos_*`) and the parsers of the server's extensions (`tls_parse_stoc_*`),
//! which `common::ext` dispatches to in `ext_defs[]` order.
//!
//! A ClientHello's construction may run again after a request (a custom extension's or the
//! PSK callbacks'), so the constructors whose work must happen once per ClientHello (key
//! shares, the cookie, the PSK identities, early data) keep what they made in
//! [`super::State`] and give it again.

use core::ffi::c_int;

use rustyssl_abi as abi;

use super::{Connection, state};
use crate::codec::Reader;
use crate::conn::common::ext::{self, ExtReturn, Step};
use crate::conn::common::{
    CERT_TYPE_CTOS_GOOD, CERT_TYPE_CTOS_NONE, EarlyDataState, Hrr, KEX_MODE_FLAG_KE,
    KEX_MODE_FLAG_KE_DHE, Pha, ask_once, ciphers, finished, groups, keys, security, version,
};
use crate::conn::{Answer, Request, Session};
use crate::consts::context as cx;
use crate::consts::ext as t;
use crate::consts::version as v;
use crate::crypto::Provider;
use crate::error::{Error, Result};
use crate::msgs::ext as mx;
use crate::suites::{self, masks};

/// `TLSEXT_KEX_MODE_KE` (RFC 8446's psk_ke; `ssl_local.h`).
const KEX_MODE_KE: u8 = 0;
/// `TLSEXT_KEX_MODE_KE_DHE` (psk_dhe_ke).
const KEX_MODE_KE_DHE: u8 = 1;
/// `PSK_PRE_BINDER_OVERHEAD`: the pre_shared_key extension's octets besides the identity and
/// the binder.
const PSK_PRE_BINDER_OVERHEAD: usize = 2 + 2 + 2 + 2 + 4 + 2 + 1;

/// An empty extension body.
fn empty() -> ExtReturn {
    ExtReturn::Sent(Vec::new())
}

/// The memo of a constructor's result for this ClientHello.
fn memo(c: &mut Connection, typ: u16) -> Result<Option<ExtReturn>> {
    Ok(state(c)?
        .ext_memo
        .iter()
        .find(|(x, _)| *x == typ)
        .map(|(_, r)| r.clone()))
}

/// Keeps a constructor's result for this ClientHello.
fn remember(c: &mut Connection, typ: u16, r: ExtReturn) -> Result<ExtReturn> {
    if r != ExtReturn::Wait {
        state(c)?.ext_memo.push((typ, r.clone()));
    }
    Ok(r)
}

/// The versions the client may use, as `ssl_get_min_max_version` gives them.
fn min_max(c: &Connection) -> Result<(u16, u16)> {
    let (min, max, _) =
        version::min_max(c).map_err(|r| Error::alert(abi::SSL_AD_INTERNAL_ERROR, r))?;
    Ok((min, max))
}

/// `use_ecc`: whether the client offers an EC suite (or TLS 1.3) and has an EC group.
fn use_ecc(c: &Connection, min: u16, max: u16) -> bool {
    use masks::{SSL_aECDSA, SSL_kECDHE, SSL_kECDHEPSK};
    if c.neg.version == v::SSL3 {
        return false;
    }
    let any = c.cfg.ciphers.iter().any(|cp| {
        !ciphers::disabled(c, cp, abi::SSL_SECOP_CIPHER_SUPPORTED, false)
            && (cp.mkey & (SSL_kECDHE | SSL_kECDHEPSK) != 0
                || cp.auth & SSL_aECDSA != 0
                || cp.min_tls >= abi::TLS1_3_VERSION)
    });
    if !any {
        return false;
    }
    groups::supported(c).into_iter().any(|g| {
        groups::valid(c, g, min, max, true).0
            && groups::allowed(c, g, abi::SSL_SECOP_CURVE_SUPPORTED)
    })
}

/// `tls_construct_ctos_renegotiate`: renegotiation_info, empty on a first handshake (where
/// TLS 1.0's SCSV replaces it, and TLS 1.3 has none), the last Finished when renegotiating.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_renegotiate(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if !c.renegotiate {
        let min = c_int::from(c.cfg.min_version);
        if !c.cfg.dtls
            && (min >= abi::TLS1_3_VERSION
                || (security::check(
                    c,
                    abi::SSL_SECOP_VERSION,
                    0,
                    abi::TLS1_VERSION,
                    security::SecOther::None,
                ) && min <= abi::TLS1_VERSION))
        {
            return Ok(ExtReturn::NotSent);
        }
        return Ok(ExtReturn::Sent(mx::renegotiate::encode(&[])?));
    }
    Ok(ExtReturn::Sent(mx::renegotiate::encode(
        &c.neg.client_finished,
    )?))
}

/// `tls_construct_ctos_server_name`.
///
/// # Errors
/// The name is too long.
pub(crate) fn ext_construct_server_name(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    match &c.cfg.hostname {
        None => Ok(ExtReturn::NotSent),
        Some(h) => Ok(ExtReturn::Sent(mx::server_name::encode_client(h)?)),
    }
}

/// `tls_construct_ctos_maxfragmentlen`.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_maxfragmentlen(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    let mode = c.cfg.max_fragment_len_mode;
    if c_int::from(mode) == abi::TLSEXT_max_fragment_length_DISABLED {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(vec![mode]))
}

/// `tls_construct_ctos_srp`: the SRP login, when one is set.
///
/// # Errors
/// A login over 255 octets (internal-error).
pub(crate) fn ext_construct_srp(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    let Some(login) = &c.cfg.srp_login else {
        return Ok(ExtReturn::NotSent);
    };
    let mut w = crate::codec::Writer::new();
    w.vec(1, login).map_err(|_| Error::internal())?;
    Ok(ExtReturn::Sent(w.into_bytes()))
}

/// `tls_construct_ctos_ec_pt_formats`.
///
/// # Errors
/// No version (internal-error with the reason).
pub(crate) fn ext_construct_ec_pt_formats(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    let (min, max) = min_max(c)?;
    if !use_ecc(c, min, max) {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(mx::ec_point_formats::encode(
        &groups::formats(c),
    )?))
}

/// `tls_construct_ctos_supported_groups`.
///
/// # Errors
/// No group for the versions offered (`SSL_R_NO_SUITABLE_GROUPS`, internal-error).
pub(crate) fn ext_construct_supported_groups(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    let (min, max) = min_max(c)?;
    if !use_ecc(c, min, max) && (c.cfg.dtls || max < v::TLS1_3) {
        return Ok(ExtReturn::NotSent);
    }
    let (list, any13) = groups::offerable(c, min, max);
    if list.is_empty() || (!any13 && !c.cfg.dtls && max == v::TLS1_3) {
        return Err(
            Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_NO_SUITABLE_GROUPS)
                .with_data("No groups enabled for max supported SSL/TLS version"),
        );
    }
    Ok(ExtReturn::Sent(mx::supported_groups::encode(&list)?))
}

/// `tls_construct_ctos_session_ticket`: the session's TLS 1.2 ticket, or an empty extension
/// asking for one.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_session_ticket(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if !security::use_ticket(c) {
        return Ok(ExtReturn::NotSent);
    }
    let s = &c.neg.session;
    match &s.ticket {
        Some(tk) if !c.hs.sh.new_session && s.version != v::TLS1_3 => {
            Ok(ExtReturn::Sent(tk.clone()))
        }
        // `SSL_set_session_ticket_ext`'s contents become the session's ticket.
        _ => match c.cfg.session_ticket_ext.clone() {
            Some(Some(d)) if !d.is_empty() => {
                c.neg.session.ticket = Some(d.clone());
                Ok(ExtReturn::Sent(d))
            }
            Some(None) => Ok(ExtReturn::NotSent),
            _ => Ok(empty()),
        },
    }
}

/// `tls_construct_ctos_status_request`: an OCSP request with the configured responder IDs and
/// extensions, not for a client Certificate entry.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_status_request(
    c: &mut Connection,
    _p: &dyn Provider,
    x: &ext::Ctx,
) -> Result<ExtReturn> {
    if x.context & cx::TLS1_3_CERTIFICATE != 0 || c.hs.sh.status_type != abi::TLSEXT_STATUSTYPE_ocsp
    {
        return Ok(ExtReturn::NotSent);
    }
    Ok(ExtReturn::Sent(mx::status_request::encode(
        &mx::status_request::Request::Ocsp {
            responder_ids: c.cfg.ocsp_ids.clone(),
            extensions: c.cfg.ocsp_exts.clone(),
        },
    )?))
}

/// `tls_construct_ctos_npn`: empty, on a first handshake with an NPN select callback.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_npn(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if !c.cfg.callbacks.npn || !finished::is_first_handshake(c) {
        return Ok(ExtReturn::NotSent);
    }
    Ok(empty())
}

/// `tls_construct_ctos_alpn`: the protocols, on a first handshake.
///
/// # Errors
/// The list is too long.
pub(crate) fn ext_construct_alpn(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    state(c)?.alpn_sent = false;
    if c.cfg.alpn.is_empty() || !finished::is_first_handshake(c) {
        return Ok(ExtReturn::NotSent);
    }
    let body = mx::alpn::encode_wire(&c.cfg.alpn)?;
    state(c)?.alpn_sent = true;
    Ok(ExtReturn::Sent(body))
}

/// `tls_construct_ctos_use_srtp`: the configured SRTP profiles, with an empty MKI (fork M).
///
/// # Errors
/// Too many profiles (internal).
pub(crate) fn ext_construct_use_srtp(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if c.cfg.srtp_profiles.is_empty() {
        return Ok(ExtReturn::NotSent);
    }
    let offer = mx::use_srtp::Offer {
        profiles: c.cfg.srtp_profiles.clone(),
        mki: Vec::new(),
    };
    let body = mx::use_srtp::encode_client(&offer).map_err(|_| Error::internal())?;
    Ok(ExtReturn::Sent(body))
}

/// `tls_construct_ctos_etm`.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_etm(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if c.cfg.options & abi::SSL_OP_NO_ENCRYPT_THEN_MAC != 0 {
        return Ok(ExtReturn::NotSent);
    }
    Ok(empty())
}

/// `tls_construct_ctos_sct`: empty, with CT validation on (`SSL_enable_ct`), not for a client
/// Certificate entry.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_sct(
    c: &mut Connection,
    _p: &dyn Provider,
    x: &ext::Ctx,
) -> Result<ExtReturn> {
    if !c.cfg.request_scts || x.context & cx::TLS1_3_CERTIFICATE != 0 {
        return Ok(ExtReturn::NotSent);
    }
    Ok(empty())
}

/// `tls_construct_ctos_ems`.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_ems(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if c.cfg.options & abi::SSL_OP_NO_EXTENDED_MASTER_SECRET != 0 {
        return Ok(ExtReturn::NotSent);
    }
    Ok(empty())
}

/// `tls_construct_ctos_post_handshake_auth`: empty, when post-handshake authentication is on.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_post_handshake_auth(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if !c.cfg.post_handshake_auth {
        return Ok(ExtReturn::NotSent);
    }
    c.hs.sh.pha = Pha::ExtSent;
    Ok(empty())
}

/// `tls_construct_ctos_client_cert_type`.
///
/// # Errors
/// More than 255 types.
pub(crate) fn ext_construct_client_cert_type(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    c.hs.sh.client_cert_type_ctos = CERT_TYPE_CTOS_NONE;
    if c.cfg.client_cert_types.is_empty() {
        return Ok(ExtReturn::NotSent);
    }
    let body = mx::cert_type::encode_client(&c.cfg.client_cert_types)?;
    c.hs.sh.client_cert_type_ctos = CERT_TYPE_CTOS_GOOD;
    Ok(ExtReturn::Sent(body))
}

/// `tls_construct_ctos_server_cert_type`.
///
/// # Errors
/// More than 255 types.
pub(crate) fn ext_construct_server_cert_type(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    c.hs.sh.server_cert_type_ctos = CERT_TYPE_CTOS_NONE;
    if c.cfg.server_cert_types.is_empty() {
        return Ok(ExtReturn::NotSent);
    }
    let body = mx::cert_type::encode_client(&c.cfg.server_cert_types)?;
    c.hs.sh.server_cert_type_ctos = CERT_TYPE_CTOS_GOOD;
    Ok(ExtReturn::Sent(body))
}

/// `tls_construct_ctos_supported_versions`: the versions from the highest down, when TLS 1.3
/// may be negotiated.
///
/// # Errors
/// No version (internal-error with the reason).
pub(crate) fn ext_construct_supported_versions(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    let (min, max) = min_max(c)?;
    if c.cfg.dtls || max < v::TLS1_3 {
        return Ok(ExtReturn::NotSent);
    }
    let list: Vec<u16> = (min..=max).rev().collect();
    Ok(ExtReturn::Sent(mx::supported_versions::encode_client(
        &list,
    )?))
}

/// `tls_construct_ctos_psk_kex_modes`: psk_dhe_ke, and psk_ke with
/// `SSL_OP_ALLOW_NO_DHE_KEX`.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_psk_kex_modes(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    let nodhe = c.cfg.options & abi::SSL_OP_ALLOW_NO_DHE_KEX != 0;
    let mut modes = vec![KEX_MODE_KE_DHE];
    c.hs.sh.psk_kex_mode = KEX_MODE_FLAG_KE_DHE;
    if nodhe {
        modes.push(KEX_MODE_KE);
        c.hs.sh.psk_kex_mode |= KEX_MODE_FLAG_KE;
    }
    Ok(ExtReturn::Sent(mx::psk_key_exchange_modes::encode(&modes)?))
}

/// `add_key_share`: the share at position `i` for `group`: the one made before (a ClientHello
/// after a HelloRetryRequest that didn't ask for a group), or a new one.
fn add_key_share(c: &mut Connection, p: &dyn Provider, group: u16, i: usize) -> Result<Vec<u8>> {
    let reuse = state(c)?.ks.get(i).is_some_and(|k| k.0 == group);
    if !reuse {
        let share = p
            .key_share(group)
            .map_err(|_| Error::alert_lib(abi::SSL_AD_INTERNAL_ERROR, abi::ERR_R_EVP_LIB))?;
        let st = state(c)?;
        st.ks.truncate(i);
        st.ks.push((group, share));
    }
    let public = state(c)?
        .ks
        .get(i)
        .map(|k| k.1.public().to_vec())
        .unwrap_or_default();
    if i == 0 {
        state(c)?.pkey = true;
        c.hs.sh.group_id = group;
        // The first share is the client's temporary key (`s->s3.tmp.pkey`, `SSL_get_tmp_key`)
        // until a TLS 1.3 ServerHello picks one; a TLS 1.2 handshake keeps it.
        c.hs.sh.own_tmp = Some((group, public.clone()));
    }
    Ok(public)
}

/// `tls_construct_ctos_key_share`: shares for the groups marked for them (or, without marks,
/// the first usable group); after a HelloRetryRequest, one share for the group it asked for.
///
/// # Errors
/// No usable group (`SSL_R_NO_SUITABLE_KEY_SHARE`), or a share couldn't be made.
pub(crate) fn ext_construct_key_share(
    c: &mut Connection,
    p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if let Some(r) = memo(c, t::KEY_SHARE)? {
        return Ok(r);
    }
    let requested = groups::keyshare_groups(c);
    let (list, add_only_one) = if requested.is_empty() {
        (groups::supported(c), true)
    } else {
        (requested, false)
    };
    let none = || Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_NO_SUITABLE_KEY_SHARE);
    if list.is_empty() {
        return Err(none());
    }
    let mut entries = Vec::new();
    let group_id = c.hs.sh.group_id;
    if group_id != 0 && !state(c)?.pkey {
        state(c)?.ks.clear();
        let key = add_key_share(c, p, group_id, 0)?;
        entries.push(mx::key_share::Entry {
            group: group_id,
            key,
        });
    } else {
        for g in list {
            if !groups::allowed(c, g, abi::SSL_SECOP_CURVE_SUPPORTED)
                || !groups::valid(c, g, v::TLS1_3, v::TLS1_3, false).0
            {
                continue;
            }
            if g == 0 {
                return Err(none());
            }
            let key = add_key_share(c, p, g, entries.len())?;
            entries.push(mx::key_share::Entry { group: g, key });
            if add_only_one {
                break;
            }
        }
    }
    if entries.is_empty() {
        return Err(none());
    }
    let body = mx::key_share::encode_client(&entries)?;
    remember(c, t::KEY_SHARE, ExtReturn::Sent(body))
}

/// `tls_construct_ctos_cookie`: the HelloRetryRequest's cookie, sent once.
///
/// # Errors
/// The cookie is too long.
pub(crate) fn ext_construct_cookie(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if let Some(r) = memo(c, t::COOKIE)? {
        return Ok(r);
    }
    let cookie = core::mem::take(&mut state(c)?.cookie);
    let r = if cookie.is_empty() {
        ExtReturn::NotSent
    } else {
        ExtReturn::Sent(mx::cookie::encode(&cookie)?)
    };
    remember(c, t::COOKIE, r)
}

/// An external PSK's session and its identity.
type ExternalSession = (Session, Vec<u8>);

/// The external PSK the callbacks give for TLS 1.3 (`psk_use_session_cb`, or the TLS 1.2-style
/// `psk_client_callback` made into a TLS_AES_128_GCM_SHA256 session): the session and its
/// identity. A session answer's identity is its `ticket`. `None` while an answer is awaited.
fn external_psk(c: &mut Connection) -> Result<Option<Option<ExternalSession>>> {
    let bad = Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_BAD_PSK);
    let mut found = None;
    if c.cfg.callbacks.psk_session {
        let md = if c.hs.sh.hrr == Hrr::Pending {
            Some(keys::handshake_md(c)?)
        } else {
            None
        };
        let Some(a) = ask_once(
            c,
            Request::PskSession {
                identity: Vec::new(),
                md,
            },
            0,
        ) else {
            return Ok(None);
        };
        found = match a {
            Answer::Session(Some(s)) => {
                let id = s.ticket.clone().unwrap_or_default();
                Some((s, id))
            }
            Answer::Psk(Some(e)) => Some((
                Session {
                    version: v::TLS1_3,
                    cipher_id: e.cipher_id,
                    master_key: e.key,
                    ..Session::default()
                },
                e.identity,
            )),
            Answer::Session(None) | Answer::Psk(None) | Answer::Continue => None,
            _ => return Err(bad),
        };
        if found.as_ref().is_some_and(|(s, _)| s.version != v::TLS1_3) {
            return Err(bad);
        }
    }
    if found.is_none() && c.cfg.callbacks.psk {
        let Some(a) = ask_once(
            c,
            Request::Psk {
                hint_or_identity: Vec::new(),
            },
            1,
        ) else {
            return Ok(None);
        };
        if let Answer::Psk(Some(e)) = a
            && !e.key.is_empty()
        {
            let max_psk = usize::try_from(abi::PSK_MAX_PSK_LEN).unwrap_or(512);
            let max_id = usize::try_from(abi::PSK_MAX_IDENTITY_LEN).unwrap_or(128);
            if e.key.len() > max_psk {
                return Err(Error::alert_lib(
                    abi::SSL_AD_HANDSHAKE_FAILURE,
                    abi::ERR_R_INTERNAL_ERROR,
                ));
            }
            if e.identity.len() > max_id {
                return Err(Error::internal());
            }
            let cid = suites::cid(abi::TLS1_3_CK_AES_128_GCM_SHA256);
            found = Some((
                Session {
                    version: v::TLS1_3,
                    cipher_id: cid,
                    master_key: e.key,
                    ..Session::default()
                },
                e.identity,
            ));
        }
    }
    // `OPENSSL_memdup` of an empty identity is NULL (`CRYPTO_malloc(0)`), which OpenSSL takes
    // for an allocation failure: an external PSK with no identity fails the handshake.
    if found.as_ref().is_some_and(|(_, id)| id.is_empty()) {
        return Err(Error::internal());
    }
    Ok(Some(found))
}

/// `tls_construct_ctos_early_data`: finds an external PSK (the callbacks), then, when the
/// application is sending early data and a session allows it, the empty extension (early data
/// is "rejected" until the server's EncryptedExtensions accepts it). The session's name and
/// protocol must match what this ClientHello offers.
///
/// # Errors
/// OpenSSL's alert and reason.
pub(crate) fn ext_construct_early_data(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if let Some(r) = memo(c, t::EARLY_DATA)? {
        return Ok(r);
    }
    let Some(psk) = external_psk(c)? else {
        return Ok(ExtReturn::Wait);
    };
    let psk_max = psk.as_ref().map_or(0, |(s, _)| s.max_early_data);
    state(c)?.psk_session = psk;
    let session_max = c.neg.session.max_early_data;
    if c.hs.sh.early_data_state != EarlyDataState::Connecting || (session_max == 0 && psk_max == 0)
    {
        state(c)?.max_early_data = 0;
        return remember(c, t::EARLY_DATA, ExtReturn::NotSent);
    }
    let ed = if session_max != 0 {
        c.neg.session.clone()
    } else {
        state(c)?
            .psk_session
            .as_ref()
            .map(|(s, _)| s.clone())
            .ok_or_else(Error::internal)?
    };
    {
        let st = state(c)?;
        st.max_early_data = ed.max_early_data;
        st.early_cipher = suites::by_id(ed.cipher_id);
    }
    let inconsistent = |r| Error::alert(abi::SSL_AD_INTERNAL_ERROR, r);
    if let Some(h) = &ed.hostname
        && c.cfg.hostname.as_ref() != Some(h)
    {
        return Err(inconsistent(abi::SSL_R_INCONSISTENT_EARLY_DATA_SNI));
    }
    if let Some(a) = &ed.alpn {
        let offered = mx::alpn::names(&c.cfg.alpn);
        if c.cfg.alpn.is_empty() || !offered.contains(a) {
            return Err(inconsistent(abi::SSL_R_INCONSISTENT_EARLY_DATA_ALPN));
        }
    }
    c.neg.early_data_status = abi::SSL_EARLY_DATA_REJECTED;
    c.hs.sh.early_data_ok = true;
    remember(c, t::EARLY_DATA, empty())
}

/// The hash of a session's TLS 1.3 suite (`ssl_md` of its `algorithm2`), if the suite is
/// known.
fn session_hash(s: &Session) -> Option<crate::crypto::HashAlg> {
    suites::by_id(s.cipher_id)
        .filter(|cp| cp.handshake_hash().is_some())
        .map(super::hello::hash13)
}

/// `tls_construct_ctos_padding`: with `SSL_OP_TLSEXT_PADDING`, pads a ClientHello whose
/// length (with the PSK extension still to come) falls in 256..=511 octets to 512.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_construct_padding(
    c: &mut Connection,
    _p: &dyn Provider,
    x: &ext::Ctx,
) -> Result<ExtReturn> {
    if c.cfg.options & abi::SSL_OP_TLSEXT_PADDING == 0 {
        return Ok(ExtReturn::NotSent);
    }
    let prefix = state(c)?.hello_prefix_len;
    let mut hlen = 4usize
        .saturating_add(prefix)
        .saturating_add(2)
        .saturating_add(x.written);
    let s = &c.neg.session;
    if s.version == v::TLS1_3
        && let Some(tk) = s.ticket.as_ref().filter(|t| !t.is_empty())
        && let Some(h) = session_hash(s)
    {
        hlen = hlen
            .saturating_add(PSK_PRE_BINDER_OVERHEAD)
            .saturating_add(tk.len())
            .saturating_add(h.len());
    }
    Ok(match mx::padding::body_for(hlen) {
        Some(b) => ExtReturn::Sent(b),
        None => ExtReturn::NotSent,
    })
}

/// `tls_construct_ctos_psk`: the session's ticket (with its obfuscated age) and the external
/// PSK's identity, with zeroed binders that the ClientHello's construction fills in once the
/// message is complete.
///
/// # Errors
/// An external PSK whose suite is unknown or doesn't match the HelloRetryRequest's hash
/// (`SSL_R_BAD_PSK`).
pub(crate) fn ext_construct_psk(
    c: &mut Connection,
    _p: &dyn Provider,
    _x: &ext::Ctx,
) -> Result<ExtReturn> {
    if let Some(r) = memo(c, t::PRE_SHARED_KEY)? {
        return Ok(r);
    }
    state(c)?.tick_identity = 0;
    state(c)?.binders.clear();
    let s = c.neg.session.clone();
    let has_psk = state(c)?.psk_session.is_some();
    let ticket = s.ticket.clone().unwrap_or_default();
    if s.version != v::TLS1_3 || (ticket.is_empty() && !has_psk) {
        return remember(c, t::PRE_SHARED_KEY, ExtReturn::NotSent);
    }
    let handmd = if c.hs.sh.hrr == Hrr::Pending {
        Some(keys::handshake_md(c)?)
    } else {
        None
    };
    let mut res = None;
    if !ticket.is_empty() {
        if suites::by_id(s.cipher_id).is_none() {
            return Err(Error::internal());
        }
        if let Some(mdres) = session_hash(&s)
            && handmd.is_none_or(|h| h == mdres)
        {
            let age = super::now(c).saturating_sub(s.time).max(0);
            let mut agesec = u32::try_from(age).unwrap_or(u32::MAX);
            if agesec > 0 {
                agesec = agesec.saturating_sub(1);
            }
            if s.ticket_lifetime_hint >= u64::from(agesec)
                && let Some(agems) = agesec.checked_mul(1000)
            {
                res = Some((mdres, agems.wrapping_add(s.ticket_age_add)));
            }
        }
    }
    let psk = state(c)?.psk_session.clone();
    if res.is_none() && psk.is_none() {
        return remember(c, t::PRE_SHARED_KEY, ExtReturn::NotSent);
    }
    let bad = Error::alert(abi::SSL_AD_INTERNAL_ERROR, abi::SSL_R_BAD_PSK);
    let mut identities = Vec::new();
    let mut binders = Vec::new();
    let mut plan = Vec::new();
    if let Some((mdres, agems)) = res {
        identities.push(mx::psk::Identity {
            identity: ticket,
            obfuscated_ticket_age: agems,
        });
        binders.push(vec![0; mdres.len()]);
        plan.push((mdres, s.master_key.clone(), false));
    }
    if let Some((ps, id)) = &psk {
        let Some(mdpsk) = session_hash(ps) else {
            return Err(bad);
        };
        if handmd.is_some_and(|h| h != mdpsk) {
            return Err(bad);
        }
        identities.push(mx::psk::Identity {
            identity: id.clone(),
            obfuscated_ticket_age: 0,
        });
        binders.push(vec![0; mdpsk.len()]);
        plan.push((mdpsk, ps.master_key.clone(), true));
    }
    let body = mx::psk::Strict {
        identities,
        binders,
    }
    .encode()?;
    let st = state(c)?;
    st.tick_identity = u16::try_from(plan.len()).unwrap_or(0);
    st.binders = plan;
    remember(c, t::PRE_SHARED_KEY, ExtReturn::Sent(body))
}

/// `tls_parse_stoc_renegotiate`: the server's renegotiation_info must hold both last
/// Finished values (none on a first handshake).
///
/// # Errors
/// `SSL_R_RENEGOTIATION_ENCODING_ERR` (decode-error), `SSL_R_RENEGOTIATION_MISMATCH`
/// (illegal-parameter).
pub(crate) fn ext_parse_renegotiate(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let got = mx::renegotiate::parse_server(body)?;
    let mut expected = c.neg.client_finished.clone();
    expected.extend_from_slice(&c.neg.server_finished);
    if got != expected {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_RENEGOTIATION_MISMATCH,
        ));
    }
    c.neg.secure_renegotiation = true;
    Ok(Step::Done)
}

/// `tls_parse_stoc_server_name`: the server used the name; a new session records it.
///
/// # Errors
/// A body (`SSL_R_BAD_EXTENSION`), or no name sent (internal).
pub(crate) fn ext_parse_server_name(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let Some(h) = c.cfg.hostname.clone() else {
        return Err(Error::internal());
    };
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    if !c.neg.reused {
        if c.neg.session.hostname.is_some() {
            return Err(Error::internal());
        }
        c.neg.session.hostname = Some(h);
    }
    Ok(Step::Done)
}

/// `tls_parse_stoc_maxfragmentlen`: the mode asked for, which becomes binding.
///
/// # Errors
/// A malformed body (`SSL_R_BAD_EXTENSION`), or another mode
/// (`SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH`).
pub(crate) fn ext_parse_maxfragmentlen(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let m = mx::max_fragment_length::parse(body)?;
    if m != c.cfg.max_fragment_len_mode {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_SSL3_EXT_INVALID_MAX_FRAGMENT_LENGTH,
        ));
    }
    c.neg.session.max_fragment_len_mode = m;
    Ok(Step::Done)
}

/// `tls_parse_stoc_ec_pt_formats`: the server's formats (when not resuming).
///
/// # Errors
/// A malformed list (`SSL_R_BAD_EXTENSION`), an empty one (`SSL_R_BAD_LENGTH`).
pub(crate) fn ext_parse_ec_pt_formats(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let e = Error::decode(abi::SSL_R_BAD_EXTENSION);
    let mut rd = Reader::new(body);
    let list = rd.vec8().map_err(|_| e)?;
    rd.end().map_err(|_| e)?;
    if !c.neg.reused {
        if list.is_empty() {
            return Err(Error::decode(abi::SSL_R_BAD_LENGTH));
        }
        c.hs.sh.peer_ecpointformats = Some(list.rest().to_vec());
    }
    Ok(Step::Done)
}

/// `tls_parse_stoc_session_ticket`: the server will send a ticket.
///
/// # Errors
/// Tickets are off (`SSL_R_BAD_EXTENSION`, unsupported-extension), or a body.
pub(crate) fn ext_parse_session_ticket(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    if c.cfg.callbacks.session_ticket_ext {
        let r = Request::SessionTicketExt {
            data: body.to_vec(),
        };
        match ask_once(c, r, 0) {
            None => return Ok(Step::Wait),
            Some(Answer::Allowed(true)) => {}
            Some(_) => {
                return Err(Error::alert(
                    abi::SSL_AD_HANDSHAKE_FAILURE,
                    abi::SSL_R_BAD_EXTENSION,
                ));
            }
        }
    }
    if !security::use_ticket(c) {
        return Err(Error::alert(
            abi::SSL_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    c.hs.sh.ticket_expected = true;
    Ok(Step::Done)
}

/// `tls_parse_stoc_status_request`: TLS 1.2's promise of a CertificateStatus, or TLS 1.3's
/// stapled response for the leaf (others' are ignored, as is one in a CertificateRequest).
///
/// # Errors
/// Not asked for, a TLS 1.2 body (`SSL_R_BAD_EXTENSION`), or a malformed response.
pub(crate) fn ext_parse_status_request(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
    x: &ext::Ctx,
) -> Result<Step> {
    if x.context == cx::TLS1_3_CERTIFICATE_REQUEST {
        return Ok(Step::Done);
    }
    if c.hs.sh.status_type != abi::TLSEXT_STATUSTYPE_ocsp {
        return Err(Error::alert(
            abi::SSL_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    if !c.is_tls13() && !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    if c.is_tls13() {
        // 3.6 keeps every certificate's response.
        super::flight::store_cert_status(c, p, x.chainidx, body)?;
        return Ok(Step::Done);
    }
    state(c)?.status_expected = true;
    Ok(Step::Done)
}

/// `tls_parse_stoc_sct`: the SCTs, kept for CT validation when it is on; otherwise only a
/// custom extension may take them.
///
/// # Errors
/// Unsolicited (`SSL_R_BAD_EXTENSION`, unsupported-extension).
pub(crate) fn ext_parse_sct(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    x: &ext::Ctx,
) -> Result<Step> {
    if x.context == cx::TLS1_3_CERTIFICATE_REQUEST {
        return Ok(Step::Done);
    }
    if c.cfg.request_scts {
        c.neg.scts = Some(body.to_vec());
        return Ok(Step::Done);
    }
    let role_client = x.context & cx::TLS1_2_SERVER_HELLO != 0;
    let custom = c.cfg.custom_exts.iter().any(|m| {
        m.typ == t::SIGNED_CERTIFICATE_TIMESTAMP && (!role_client || m.server != Some(true))
    });
    if !custom {
        return Err(Error::alert(
            abi::TLS1_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    ext::custom_parse(
        c,
        x.context,
        t::SIGNED_CERTIFICATE_TIMESTAMP,
        body,
        x.chainidx,
    )
}

/// `tls_parse_stoc_npn`: the server's protocols, from which the NPN callback selects
/// ([`Request::Npn`]), on a first handshake.
///
/// # Errors
/// Not asked for, a malformed list, or no selection (`SSL_R_BAD_EXTENSION`).
pub(crate) fn ext_parse_npn(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    if !finished::is_first_handshake(c) {
        return Ok(Step::Done);
    }
    if !c.cfg.callbacks.npn {
        return Err(Error::alert(
            abi::SSL_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    mx::npn::parse_server(body)?;
    let Some(a) = ask_once(
        c,
        Request::Npn {
            protos: body.to_vec(),
        },
        0,
    ) else {
        return Ok(Step::Wait);
    };
    match a {
        Answer::Npn(Some(sel)) if !sel.is_empty() => {
            c.neg.npn = Some(sel);
            c.hs.sh.npn_seen = true;
            Ok(Step::Done)
        }
        _ => Err(Error::alert(
            abi::SSL_AD_HANDSHAKE_FAILURE,
            abi::SSL_R_BAD_EXTENSION,
        )),
    }
}

/// `tls_parse_stoc_alpn`: the protocol the server selected, which must be one offered; early
/// data needs it to be the session's.
///
/// # Errors
/// Not offered, malformed, or not one offered (`SSL_R_BAD_EXTENSION`).
pub(crate) fn ext_parse_alpn(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    if !state(c)?.alpn_sent {
        return Err(Error::alert(
            abi::SSL_AD_UNSUPPORTED_EXTENSION,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    let sel = mx::alpn::parse_server(body)?;
    if !mx::alpn::names(&c.cfg.alpn).contains(&sel) {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    c.neg.alpn = Some(sel.clone());
    if c.neg.session.alpn.as_ref() != Some(&sel) {
        c.hs.sh.early_data_ok = false;
    }
    if !c.neg.reused {
        if c.neg.session.alpn.is_some() {
            return Err(Error::internal());
        }
        c.neg.session.alpn = Some(sel);
    }
    Ok(Step::Done)
}

/// `tls_parse_stoc_use_srtp`: the server's profile, which must be one configured (fork M).
///
/// # Errors
/// A malformed body, `SSL_R_NO_SRTP_PROFILES` (none configured), or
/// `SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST` (not one configured).
pub(crate) fn ext_parse_use_srtp(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let id = mx::use_srtp::parse_server(body)?;
    if c.cfg.srtp_profiles.is_empty() {
        return Err(Error::decode(abi::SSL_R_NO_SRTP_PROFILES));
    }
    if !c.cfg.srtp_profiles.contains(&id) {
        return Err(Error::decode(abi::SSL_R_BAD_SRTP_PROTECTION_PROFILE_LIST));
    }
    c.hs.sh.srtp_profile = Some(id);
    Ok(Step::Done)
}

/// `tls_parse_stoc_etm`: encrypt-then-MAC, unless the suite is an AEAD or stream cipher.
///
/// # Errors
/// No suite yet (internal).
pub(crate) fn ext_parse_etm(
    c: &mut Connection,
    _p: &dyn Provider,
    _body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
    let stream = [
        masks::SSL_RC4,
        masks::SSL_eGOST2814789CNT,
        masks::SSL_eGOST2814789CNT12,
        masks::SSL_MAGMA,
        masks::SSL_KUZNYECHIK,
    ];
    if c.cfg.options & abi::SSL_OP_NO_ENCRYPT_THEN_MAC == 0
        && cp.mac != masks::SSL_AEAD
        && !stream.contains(&cp.enc)
    {
        c.hs.sh.use_etm = true;
    }
    Ok(Step::Done)
}

/// `tls_parse_stoc_ems`.
///
/// # Errors
/// Never; `Result` for the dispatch.
pub(crate) fn ext_parse_ems(
    c: &mut Connection,
    _p: &dyn Provider,
    _body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    if c.cfg.options & abi::SSL_OP_NO_EXTENDED_MASTER_SECRET != 0 {
        return Ok(Step::Done);
    }
    c.hs.sh.flags |= abi::TLS1_FLAGS_RECEIVED_EXTMS;
    if !c.neg.reused {
        c.neg.session.ems = true;
    }
    Ok(Step::Done)
}

/// `tls_parse_stoc_client_cert_type` and `_server_cert_type`: the type the server chose,
/// which must be one offered.
fn parse_cert_type(body: &[u8], ctos: u8, offered: &[u8]) -> Result<u8> {
    let e = Error::decode(abi::SSL_R_BAD_EXTENSION);
    let [ty] = body else { return Err(e) };
    if ctos != CERT_TYPE_CTOS_GOOD || offered.is_empty() {
        return Err(e);
    }
    if !offered.contains(ty) {
        return Err(Error::decode(abi::SSL_R_BAD_VALUE));
    }
    Ok(*ty)
}

/// `tls_parse_stoc_client_cert_type`.
///
/// # Errors
/// As [`parse_cert_type`].
pub(crate) fn ext_parse_client_cert_type(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let ty = parse_cert_type(
        body,
        c.hs.sh.client_cert_type_ctos,
        &c.cfg.client_cert_types,
    )?;
    c.neg.client_cert_type = ty;
    Ok(Step::Done)
}

/// `tls_parse_stoc_server_cert_type`.
///
/// # Errors
/// As [`parse_cert_type`].
pub(crate) fn ext_parse_server_cert_type(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let ty = parse_cert_type(
        body,
        c.hs.sh.server_cert_type_ctos,
        &c.cfg.server_cert_types,
    )?;
    c.neg.server_cert_type = ty;
    Ok(Step::Done)
}

/// `tls_parse_stoc_supported_versions`: TLS 1.3 (only checked in a HelloRetryRequest; in a
/// ServerHello it becomes the version, checked by `ssl_choose_client_version`).
///
/// # Errors
/// Malformed (`SSL_R_LENGTH_MISMATCH`), or another version
/// (`SSL_R_BAD_PROTOCOL_VERSION_NUMBER`).
pub(crate) fn ext_parse_supported_versions(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    x: &ext::Ctx,
) -> Result<Step> {
    let ver = mx::supported_versions::parse_server(body)?;
    if ver != v::TLS1_3 {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_BAD_PROTOCOL_VERSION_NUMBER,
        ));
    }
    if x.context == cx::TLS1_3_HELLO_RETRY_REQUEST {
        return Ok(Step::Done);
    }
    c.neg.version = ver;
    version::set_record_version(c, ver);
    Ok(Step::Done)
}

/// `tls_parse_stoc_key_share`: a HelloRetryRequest's group (a new one this end supports), or
/// the server's share for a group a share was sent for, which gives the handshake secret.
///
/// # Errors
/// OpenSSL's alert and reason (`SSL_R_BAD_KEY_SHARE`, `SSL_R_LENGTH_MISMATCH`,
/// `SSL_R_BAD_ECPOINT`).
pub(crate) fn ext_parse_key_share(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
    x: &ext::Ctx,
) -> Result<Step> {
    if !state(c)?.pkey || state(c)?.peer_share {
        return Err(Error::internal());
    }
    let group = mx::key_share::group(body)?;
    let bad = Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_KEY_SHARE);
    if x.context & cx::TLS1_3_HELLO_RETRY_REQUEST != 0 {
        mx::key_share::parse_hrr(body)?;
        if state(c)?.ks.iter().any(|k| k.0 == group) {
            return Err(bad);
        }
        if !groups::supported(c).contains(&group)
            || !groups::allowed(c, group, abi::SSL_SECOP_CURVE_SUPPORTED)
            || !groups::valid(c, group, v::TLS1_3, v::TLS1_3, false).0
        {
            return Err(bad);
        }
        c.hs.sh.group_id = group;
        let st = state(c)?;
        st.ks.clear();
        st.pkey = false;
        return Ok(Step::Done);
    }
    let Some(i) = state(c)?.ks.iter().position(|k| k.0 == group) else {
        return Err(bad);
    };
    c.hs.sh.group_id = group;
    c.neg.group = Some(group);
    let Some(info) = groups::lookup(c, group).cloned() else {
        return Err(bad);
    };
    let entry = mx::key_share::parse_server(body)?;
    let st = state(c)?;
    if i >= st.ks.len() {
        return Err(Error::internal());
    }
    let (_, share) = st.ks.swap_remove(i);
    st.ks.clear();
    // Shared addition (fork N): the client's own share stays its temporary key
    // (`SSL_get_tmp_key`), a KEM's encapsulation key included.
    c.hs.sh.own_tmp = Some((group, share.public().to_vec()));
    if !info.is_kem && !groups::encoded_share_ok(&info, &entry.key, share.public().len()) {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_BAD_ECPOINT,
        ));
    }
    let shared = share.derive(&entry.key).map_err(|_| {
        if info.is_kem {
            Error::internal()
        } else {
            Error::alert(abi::SSL_AD_ILLEGAL_PARAMETER, abi::SSL_R_BAD_ECPOINT)
        }
    })?;
    state(c)?.peer_share = true;
    // Shared fix (fork M): the server's share is the peer's temporary key
    // (`SSL_get_peer_tmp_key`), except for a KEM (`tls_parse_stoc_key_share`).
    if !info.is_kem {
        c.hs.sh.peer_tmp = Some((group, entry.key.clone()));
    }
    if !c.neg.reused {
        let cp = c.hs.new_cipher.ok_or_else(Error::internal)?;
        keys::generate_early(c, p, cp, None)?;
    }
    keys::generate_handshake_secret(c, p, Some(shared.bytes()))?;
    Ok(Step::Done)
}

/// `tls_parse_stoc_cookie`: the HelloRetryRequest's cookie, for the next ClientHello.
///
/// # Errors
/// Malformed (`SSL_R_LENGTH_MISMATCH`).
pub(crate) fn ext_parse_cookie(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let cookie = mx::cookie::parse(body)?;
    state(c)?.cookie = cookie;
    Ok(Step::Done)
}

/// `tls_parse_stoc_early_data`: a ticket's early data limit, or the server's acceptance of
/// the early data sent.
///
/// # Errors
/// A malformed limit (`SSL_R_INVALID_MAX_EARLY_DATA`), or an acceptance that can't be
/// (`SSL_R_BAD_EXTENSION`).
pub(crate) fn ext_parse_early_data(
    c: &mut Connection,
    _p: &dyn Provider,
    body: &[u8],
    x: &ext::Ctx,
) -> Result<Step> {
    if x.context == cx::TLS1_3_NEW_SESSION_TICKET {
        let max = mx::early_data::parse_ticket(body)?;
        c.neg.session.max_early_data = max;
        if c.cfg.quic.is_some() && max != u32::MAX {
            c.neg.session.max_early_data = 1;
            return Err(Error::alert(
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_INVALID_MAX_EARLY_DATA,
            ));
        }
        return Ok(Step::Done);
    }
    if !body.is_empty() {
        return Err(Error::decode(abi::SSL_R_BAD_EXTENSION));
    }
    if !c.hs.sh.early_data_ok || !c.neg.reused {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_BAD_EXTENSION,
        ));
    }
    c.neg.early_data_status = abi::SSL_EARLY_DATA_ACCEPTED;
    Ok(Step::Done)
}

/// `tls_parse_stoc_psk`: the identity the server chose: the session's ticket (the first), or
/// the external PSK, whose session and early secret take over.
///
/// # Errors
/// Malformed (`SSL_R_LENGTH_MISMATCH`), or an identity not offered (`SSL_R_BAD_PSK_IDENTITY`).
pub(crate) fn ext_parse_psk(
    c: &mut Connection,
    p: &dyn Provider,
    body: &[u8],
    _x: &ext::Ctx,
) -> Result<Step> {
    let identity = mx::psk::parse_server(body)?;
    let st = state(c)?;
    if identity >= st.tick_identity {
        return Err(Error::alert(
            abi::SSL_AD_ILLEGAL_PARAMETER,
            abi::SSL_R_BAD_PSK_IDENTITY,
        ));
    }
    if identity == 0 && (st.psk_session.is_none() || st.tick_identity == 2) {
        st.psk_session = None;
        c.hs.sh.keys.psk_early = None;
        c.neg.reused = true;
        return Ok(Step::Done);
    }
    let Some((ps, _)) = st.psk_session.take() else {
        return Err(Error::internal());
    };
    let eds = c.hs.sh.early_data_state;
    let wrote_early = eds == EarlyDataState::WriteRetry || eds == EarlyDataState::FinishedWriting;
    if !wrote_early || c.neg.session.max_early_data > 0 || ps.max_early_data == 0 {
        match c.hs.sh.keys.psk_early.take() {
            Some(s) => c.hs.sh.keys.schedule = Some(s),
            None => {
                let hash = session_hash(&ps).ok_or_else(Error::internal)?;
                c.hs.sh.keys.schedule = Some(crate::keysched::Schedule13::new(
                    p,
                    hash,
                    Some(&ps.master_key),
                )?);
            }
        }
    }
    c.neg.session = ps;
    c.neg.reused = true;
    if identity != 0 {
        c.hs.sh.early_data_ok = false;
    }
    Ok(Step::Done)
}
