//! Protocol versions (`statem_lib.c`): which versions the configuration enables, the client's
//! and server's choice, and the TLS 1.3 downgrade sentinels.
//!
//! The default build has TLS 1.0 through 1.3 and no SSLv3 (`OPENSSL_NO_SSL3`), and DTLS 1.0 and
//! 1.2 (`DTLS1_BAD_VER` only through `SSL_OP_CISCO_ANYCONNECT`, which isn't supported).

use core::cmp::Ordering;
use core::ffi::c_int;

use rustyssl_abi as abi;

use super::security::{self, SecOther};
use crate::conn::Connection;
use crate::consts::{TLS11_DOWNGRADE, TLS12_DOWNGRADE, version};
use crate::error::{Error, InFunc, Result};

/// The TLS versions the default build has, highest first, with the option that disables
/// each (`tls_version_table`). SSLv3's methods are compiled out.
const TABLE: [(u16, u64); 4] = [
    (version::TLS1_3, abi::SSL_OP_NO_TLSv1_3),
    (version::TLS1_2, abi::SSL_OP_NO_TLSv1_2),
    (version::TLS1_1, abi::SSL_OP_NO_TLSv1_1),
    (version::TLS1, abi::SSL_OP_NO_TLSv1),
];

/// The DTLS versions, highest first, with the option that disables each
/// (`dtls_version_table`).
const DTLS_TABLE: [(u16, u64); 3] = [
    (version::DTLS1_2, abi::SSL_OP_NO_DTLSv1_2),
    (version::DTLS1, abi::SSL_OP_NO_DTLSv1),
    // A client only (it has no server method).
    (version::DTLS1_BAD, abi::SSL_OP_NO_DTLSv1),
];

/// The version table of the connection's kind.
fn table(c: &Connection) -> &'static [(u16, u64)] {
    if c.cfg.dtls { &DTLS_TABLE } else { &TABLE }
}

/// Whether `v` is a DTLS version number.
#[must_use]
pub fn is_dtls(v: u16) -> bool {
    v >> 8 == version::DTLS1 >> 8 || v == version::DTLS1_BAD
}

/// The TLS version a DTLS version is built on (DTLS 1.0 on TLS 1.1, DTLS 1.2 on TLS 1.2, the
/// pre-standard version on TLS 1.0), and a TLS version itself: what decides the features a
/// version has (`SSL_USE_SIGALGS`, `SSL_USE_EXPLICIT_IV`, the PRF).
#[must_use]
pub fn tls_level(v: u16) -> u16 {
    match v {
        version::DTLS1_2 => version::TLS1_2,
        version::DTLS1 => version::TLS1_1,
        version::DTLS1_BAD => version::TLS1,
        _ => v,
    }
}

/// `TLS_ANY_VERSION`'s value in [`crate::conn::Config::method_version`].
pub const ANY: u16 = 0;

/// The downgrade signal a server puts in its random (`DOWNGRADE`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Downgrade {
    /// None.
    #[default]
    None,
    /// To TLS 1.2 (the TLS 1.3 server negotiated TLS 1.2).
    To12,
    /// To TLS 1.1 or below.
    To11,
}

/// `ssl_version_cmp`: TLS versions count up, DTLS versions down (`DTLS1_BAD_VER` below
/// DTLS 1.0).
#[must_use]
pub fn cmp(a: u16, b: u16) -> Ordering {
    if is_dtls(a) || is_dtls(b) {
        let rank = |v: u16| if v == version::DTLS1_BAD { 0xff00 } else { v };
        return rank(b).cmp(&rank(a));
    }
    a.cmp(&b)
}

/// A version's `c_int` constant as a `u16` (all fit).
fn v16(v: c_int) -> u16 {
    u16::try_from(v).unwrap_or(0)
}

/// `ssl_method_error` for version `v` (whose method's option mask is `mask`): `None` if
/// enabled, else the reason it isn't.
fn method_error(c: &Connection, v: u16, mask: u64) -> Option<c_int> {
    let cfg = &c.cfg;
    if (cfg.min_version != 0 && cmp(v, cfg.min_version) == Ordering::Less)
        || !security::check(c, abi::SSL_SECOP_VERSION, 0, c_int::from(v), SecOther::None)
    {
        return Some(abi::SSL_R_VERSION_TOO_LOW);
    }
    if cfg.max_version != 0 && cmp(v, cfg.max_version) == Ordering::Greater {
        return Some(abi::SSL_R_VERSION_TOO_HIGH);
    }
    if cfg.options & mask != 0 {
        return Some(abi::SSL_R_UNSUPPORTED_PROTOCOL);
    }
    // Only TLS 1.2 and later have Suite B (`SSL_METHOD_NO_SUITEB` on the older methods).
    if tls_level(v) < version::TLS1_2 && suiteb(c) != 0 {
        return Some(abi::SSL_R_AT_LEAST_TLS_1_2_NEEDED_IN_SUITEB_MODE);
    }
    None
}

/// `tls1_suiteb`: the Suite B mode (`SSL_CERT_FLAG_SUITEB_*`), or 0.
#[must_use]
pub fn suiteb(c: &Connection) -> u32 {
    let mask = u32::try_from(abi::SSL_CERT_FLAG_SUITEB_128_LOS).unwrap_or(0);
    c.cfg.cert_flags & mask
}

/// Whether the connection runs a version's own method (`s->ssl.method->version` isn't
/// `TLS_ANY_VERSION`): a fixed-version method's always, a flexible one's once the hellos
/// chose the version (`ssl_choose_server_version`, `ssl_choose_client_version` switch it), so
/// in a renegotiation too.
#[must_use]
pub fn method_fixed(c: &Connection) -> bool {
    c.cfg.method_version != ANY || (!c.before() && c.version_decided())
}

/// The versions a handshake may use (`ssl_get_min_max_version`): `(min, max, real_max)`,
/// where `real_max` is the highest version below the highest hole in the enabled range (for
/// the client's fallback check). A fixed-version method gives its version for both, and
/// `real_max` 0.
///
/// # Errors
/// Nothing is enabled: `SSL_R_NO_PROTOCOLS_AVAILABLE` (the caller adds the alert).
pub fn min_max(c: &Connection) -> core::result::Result<(u16, u16, u16), c_int> {
    if c.cfg.method_version != ANY {
        let v = c.neg.version;
        return Ok((v, v, 0));
    }
    let mut min = 0;
    let mut version = 0;
    let mut hole = true;
    let mut real_max = 0;
    let mut tmp_real_max = 0;
    for &(v, mask) in table(c) {
        if hole && tmp_real_max == 0 {
            tmp_real_max = v;
        }
        if method_error(c, v, mask).is_some() {
            hole = true;
        } else if !hole {
            min = v;
        } else {
            if tmp_real_max != 0 {
                real_max = tmp_real_max;
            }
            version = v;
            min = v;
            hole = false;
        }
    }
    if version == 0 {
        return Err(abi::SSL_R_NO_PROTOCOLS_AVAILABLE);
    }
    Ok((min, version, real_max))
}

/// `is_tls13_capable` (servers): a certificate TLS 1.3 can use, or a callback that may
/// provide one.
fn tls13_capable(c: &Connection) -> bool {
    let cb = &c.cfg.callbacks;
    if cb.servername || cb.psk || cb.psk_session || cb.cert {
        return true;
    }
    c.cfg
        .certs
        .iter()
        .filter(|k| super::sigalgs::has_cert(c, k.slot))
        .any(|k| match k.slot {
            super::sigalgs::PKEY_DSA_SIGN
            | super::sigalgs::PKEY_GOST01
            | super::sigalgs::PKEY_GOST12_256
            | super::sigalgs::PKEY_GOST12_512 => false,
            super::sigalgs::PKEY_ECC => super::sigalgs::check_sigalg_curve(c, k.curve_nid),
            _ => true,
        })
}

/// `ssl_version_supported`: whether this end could use `v`.
#[must_use]
pub fn supported(c: &Connection, v: u16) -> bool {
    if c.cfg.method_version != ANY {
        return v == c.neg.version;
    }
    table(c).iter().any(|&(tv, mask)| {
        tv == v
            && !(c.cfg.server && tv == version::DTLS1_BAD)
            && method_error(c, tv, mask).is_none()
            && (!c.cfg.server || v != version::TLS1_3 || tls13_capable(c))
    })
}

/// `ssl_check_version_downgrade` (servers, for `TLS_FALLBACK_SCSV`): whether the version in
/// use is the highest enabled.
#[must_use]
pub fn is_highest(c: &Connection) -> bool {
    if c.cfg.method_version != ANY {
        return c.neg.version == c.cfg.method_version;
    }
    table(c)
        .iter()
        .find(|&&(v, mask)| method_error(c, v, mask).is_none())
        .is_some_and(|&(v, _)| v == c.neg.version)
}

/// `check_for_downgrade`: the sentinel a server negotiating `v` must put in its random.
fn downgrade_for(c: &Connection, v: u16) -> Downgrade {
    if c.cfg.dtls {
        // No TLS 1.3 sentinels in DTLS 1.2 (`check_for_downgrade` has none for DTLS).
        return Downgrade::None;
    }
    if v == version::TLS1_2 && supported(c, version::TLS1_3) {
        Downgrade::To12
    } else if v < version::TLS1_2 && supported(c, version::TLS1_2) {
        Downgrade::To11
    } else {
        Downgrade::None
    }
}

/// Sets the record layer's version (`ssl_set_record_protocol_version`): what plaintext
/// records must carry and what this end writes (TLS 1.3 records say TLS 1.2).
pub fn set_record_version(c: &mut Connection, v: u16) {
    c.rr.set_plain_version(Some(v));
    c.rw.version = if !is_dtls(v) && v >= version::TLS1_3 {
        version::TLS1_2
    } else {
        v
    };
}

/// `ssl_choose_server_version`: the server's version for a ClientHello with `legacy_version`
/// and (if present) the supported_versions extension's body. Sets the connection's version
/// and the record layer's, and returns the downgrade signal for the random. `hrr`: a
/// HelloRetryRequest was sent.
///
/// # Errors
/// The reason, as OpenSSL returns it (the caller sends `protocol_version` with it, as
/// `tls_early_post_process_client_hello` does).
pub fn choose_server(
    c: &mut Connection,
    legacy_version: u16,
    supported_versions: Option<&[u8]>,
    hrr: bool,
) -> core::result::Result<Downgrade, c_int> {
    c.hs.sh.client_version = legacy_version;
    if c.cfg.method_version != ANY && !c.is_tls13() {
        if cmp(legacy_version, c.neg.version) == Ordering::Less {
            return Err(abi::SSL_R_WRONG_SSL_VERSION);
        }
        return Ok(Downgrade::None);
    }
    // DTLS has no supported_versions (`ssl_choose_server_version`).
    let supported_versions = supported_versions.filter(|_| !c.cfg.dtls);
    if supported_versions.is_none() && hrr {
        return Err(abi::SSL_R_UNSUPPORTED_PROTOCOL);
    }
    if let Some(body) = supported_versions {
        let mut rd = crate::codec::Reader::new(body);
        let list = rd.vec8().map_err(|_| abi::SSL_R_LENGTH_MISMATCH)?;
        if rd.end().is_err() {
            return Err(abi::SSL_R_LENGTH_MISMATCH);
        }
        if legacy_version <= version::SSL3 {
            return Err(abi::SSL_R_BAD_LEGACY_VERSION);
        }
        let mut best = 0u16;
        let mut l = list;
        while let Ok(cand) = l.u16() {
            if cmp(cand, best) != Ordering::Greater {
                continue;
            }
            if supported(c, cand) {
                best = cand;
            }
        }
        if !l.is_empty() {
            return Err(abi::SSL_R_LENGTH_MISMATCH);
        }
        if best == 0 {
            return Err(abi::SSL_R_UNSUPPORTED_PROTOCOL);
        }
        if hrr {
            if best != version::TLS1_3 {
                return Err(abi::SSL_R_UNSUPPORTED_PROTOCOL);
            }
            return Ok(Downgrade::None);
        }
        let d = downgrade_for(c, best);
        c.neg.version = best;
        // Shared fix (fork M): the version is decided (OpenSSL switches the method here).
        c.version_pending = false;
        set_record_version(c, best);
        return Ok(d);
    }
    // Without supported_versions, TLS 1.2 is the most a client can get.
    let client_version = if !c.cfg.dtls && cmp(legacy_version, version::TLS1_3) != Ordering::Less {
        version::TLS1_2
    } else {
        legacy_version
    };
    let mut disabled = false;
    for &(v, mask) in table(c) {
        if cmp(client_version, v) == Ordering::Less || v == version::DTLS1_BAD {
            continue;
        }
        if method_error(c, v, mask).is_none() {
            let d = downgrade_for(c, v);
            c.neg.version = v;
            c.version_pending = false;
            set_record_version(c, v);
            return Ok(d);
        }
        disabled = true;
    }
    Err(if disabled {
        abi::SSL_R_UNSUPPORTED_PROTOCOL
    } else {
        abi::SSL_R_VERSION_TOO_LOW
    })
}

/// `ssl_choose_client_version`, after the client parsed the ServerHello's supported_versions
/// (which may have replaced the legacy `version`): checks the version against what this end
/// enabled and the server's random against the downgrade sentinels, and sets the record
/// layer's version. `hrr`: after a HelloRetryRequest.
///
/// # Errors
/// OpenSSL's alert and reason.
pub fn choose_client(c: &mut Connection, version_chosen: u16, hrr: bool) -> Result<()> {
    choose_client_inner(c, version_chosen, hrr).in_func("ssl_choose_client_version")
}

/// See [`choose_client`].
fn choose_client_inner(c: &mut Connection, version_chosen: u16, hrr: bool) -> Result<()> {
    let origv = c.neg.version;
    let fail = |c: &mut Connection, alert: c_int, reason: c_int| {
        c.neg.version = origv;
        Err(Error::alert(alert, reason))
    };
    c.neg.version = version_chosen;
    if hrr && version_chosen != version::TLS1_3 {
        return fail(
            c,
            abi::SSL_AD_PROTOCOL_VERSION,
            abi::SSL_R_WRONG_SSL_VERSION,
        );
    }
    if c.cfg.method_version != ANY {
        if version_chosen != c.cfg.method_version {
            return fail(
                c,
                abi::SSL_AD_PROTOCOL_VERSION,
                abi::SSL_R_WRONG_SSL_VERSION,
            );
        }
        set_record_version(c, version_chosen);
        return Ok(());
    }
    let saved = c.neg.version;
    c.neg.version = origv;
    let mm = min_max(c);
    c.neg.version = saved;
    let (min, max, real_max) = match mm {
        Ok(v) => v,
        Err(r) => return fail(c, abi::SSL_AD_PROTOCOL_VERSION, r),
    };
    if cmp(version_chosen, min) == Ordering::Less || cmp(version_chosen, max) == Ordering::Greater {
        return fail(
            c,
            abi::SSL_AD_PROTOCOL_VERSION,
            abi::SSL_R_UNSUPPORTED_PROTOCOL,
        );
    }
    let fallback = c.cfg.mode & u64::from(abi::SSL_MODE_SEND_FALLBACK_SCSV) != 0;
    let real_max = if fallback { real_max } else { max };
    if !c.cfg.dtls && real_max > version_chosen {
        let tail = c.hs.server_random.get(24..).unwrap_or_default();
        if tail == TLS11_DOWNGRADE {
            return fail(
                c,
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_INAPPROPRIATE_FALLBACK,
            );
        }
        if real_max == version::TLS1_3 && tail == TLS12_DOWNGRADE {
            return fail(
                c,
                abi::SSL_AD_ILLEGAL_PARAMETER,
                abi::SSL_R_INAPPROPRIATE_FALLBACK,
            );
        }
    }
    if table(c).iter().any(|&(v, _)| v == version_chosen) {
        set_record_version(c, version_chosen);
        return Ok(());
    }
    fail(
        c,
        abi::SSL_AD_PROTOCOL_VERSION,
        abi::SSL_R_UNSUPPORTED_PROTOCOL,
    )
}

/// `ssl_set_client_hello_version`: on the first handshake, the client's version becomes the
/// highest enabled, and the ClientHello's legacy_version that (TLS 1.2 for TLS 1.3); a
/// renegotiation sends what it sent before.
///
/// # Errors
/// Nothing is enabled (the reason).
pub fn set_client_hello_version(c: &mut Connection) -> core::result::Result<(), c_int> {
    if !c.first_handshake {
        return Ok(());
    }
    let (_, max, _) = min_max(c)?;
    c.neg.version = max;
    if max == version::DTLS1_BAD {
        // Nothing else can be negotiated, and the ServerHello's record carries it: the
        // record layer learns it now (`ssl_set_client_hello_version`).
        set_record_version(c, max);
    }
    c.hs.sh.client_version = if !c.cfg.dtls && max > version::TLS1_2 {
        version::TLS1_2
    } else {
        max
    };
    Ok(())
}

/// The TLS 1.3 downgrade sentinel for the last eight octets of a server's random.
#[must_use]
pub fn sentinel(d: Downgrade) -> Option<[u8; 8]> {
    match d {
        Downgrade::None => None,
        Downgrade::To12 => Some(TLS12_DOWNGRADE),
        Downgrade::To11 => Some(TLS11_DOWNGRADE),
    }
}

/// A version constant as a `u16`.
#[must_use]
pub fn of(v: c_int) -> u16 {
    v16(v)
}
