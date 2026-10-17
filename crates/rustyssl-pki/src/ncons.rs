//! Name constraint matching (RFC 5280 4.2.1.10; the `nc_*` functions of OpenSSL's
//! `v3_ncons.c`): whether a name of a certificate lies within a constraint's subtree.
//!
//! As OpenSSL's:
//! - DNS names match a constraint equal to them or to a suffix of whole labels (a constraint
//!   starting with `.` matches only proper subdomains), ignoring ASCII case; an empty
//!   constraint matches everything.
//! - Email constraints are an address (exact local part), a host, or a domain (`.example`).
//!   SmtpUTF8Mailbox addresses compare against the constraint's U-label form.
//! - URIs match by their host, like DNS names but a host constraint must be the whole host.
//! - IP addresses match an address and mask of the same family.
//! - A common name counts as a DNS name only if it looks like one (`cn2dnsid`).

use crate::punycode;

/// A name's relation to a constraint: within, outside, or not comparable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Match {
    /// `X509_V_OK`.
    Within,
    /// `X509_V_ERR_PERMITTED_VIOLATION`.
    Outside,
    /// `X509_V_ERR_UNSUPPORTED_NAME_SYNTAX`.
    BadSyntax,
    /// `X509_V_ERR_UNSPECIFIED`.
    Unspecified,
}

/// `ia5ncasecmp`: ASCII case-insensitive equality.
fn eq_nocase(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// `nc_dns`.
pub fn dns(name: &[u8], base: &[u8]) -> Match {
    if base.is_empty() {
        return Match::Within;
    }
    if name.len() < base.len() {
        return Match::Outside;
    }
    let Some(start) = name.len().checked_sub(base.len()) else {
        return Match::Outside;
    };
    let Some(tail) = name.get(start..) else {
        return Match::Outside;
    };
    if start > 0 {
        let before = start.checked_sub(1).and_then(|i| name.get(i));
        if base.first() != Some(&b'.') && before != Some(&b'.') {
            return Match::Outside;
        }
    }
    if eq_nocase(base, tail) {
        Match::Within
    } else {
        Match::Outside
    }
}

/// `nc_email`.
pub fn email(name: &[u8], base: &[u8]) -> Match {
    let Some(emlat) = name.iter().rposition(|&c| c == b'@') else {
        return Match::BadSyntax;
    };
    let baseat = base.iter().rposition(|&c| c == b'@');
    if baseat.is_none() && base.first() == Some(&b'.') {
        if let Some(start) = name.len().checked_sub(base.len()).filter(|&s| s > 0)
            && name.get(start..).is_some_and(|t| eq_nocase(base, t))
        {
            return Match::Within;
        }
        return Match::Outside;
    }
    let mut base_host = base;
    if let Some(at) = baseat {
        if at != 0 {
            if at != emlat {
                return Match::Outside;
            }
            let (Some(bl), Some(el)) = (base.get(..at), name.get(..emlat)) else {
                return Match::Outside;
            };
            if bl.contains(&0) || el.contains(&0) {
                return Match::BadSyntax;
            }
            if bl != el {
                return Match::Outside;
            }
        }
        base_host = base.get(at.saturating_add(1)..).unwrap_or_default();
    }
    let name_host = name.get(emlat.saturating_add(1)..).unwrap_or_default();
    if base_host.len() != name_host.len() || !eq_nocase(base_host, name_host) {
        return Match::Outside;
    }
    Match::Within
}

/// `nc_email_eai`: an SmtpUTF8Mailbox address (UTF-8) against an email constraint, whose
/// host or domain is compared in its U-label form.
pub fn email_eai(name: &[u8], base: &[u8]) -> Match {
    const ULABEL: usize = 256;
    if base.contains(&0) {
        return Match::BadSyntax;
    }
    let Some(emlat) = name.iter().rposition(|&c| c == b'@') else {
        return Match::BadSyntax;
    };
    if base.first() == Some(&b'.') {
        let Ok(rest) = punycode::a2ulabel(base, ULABEL.saturating_sub(1)) else {
            return Match::Unspecified;
        };
        let mut ulabel = b".".to_vec();
        ulabel.extend_from_slice(&rest);
        if let Some(start) = name.len().checked_sub(ulabel.len()).filter(|&s| s > 0)
            && name.get(start..).is_some_and(|t| eq_nocase(&ulabel, t))
        {
            return Match::Within;
        }
        return Match::Outside;
    }
    let Ok(ulabel) = punycode::a2ulabel(base, ULABEL) else {
        return Match::Unspecified;
    };
    let host = name.get(emlat.saturating_add(1)..).unwrap_or_default();
    if host.len() != ulabel.len() || !eq_nocase(&ulabel, host) {
        return Match::Outside;
    }
    Match::Within
}

/// `nc_uri`'s comparison: a URI's host against a host or `.domain` constraint.
pub fn uri_host(host: &[u8], base: &[u8]) -> Match {
    if base.first() == Some(&b'.') {
        if let Some(start) = host.len().checked_sub(base.len()).filter(|&s| s > 0)
            && host.get(start..).is_some_and(|t| eq_nocase(t, base))
        {
            return Match::Within;
        }
        return Match::Outside;
    }
    if base.len() != host.len() || !eq_nocase(host, base) {
        return Match::Outside;
    }
    Match::Within
}

/// `nc_ip`: an address (4 or 16 octets) against an address and mask (8 or 32).
pub fn ip(addr: &[u8], base: &[u8]) -> Match {
    if !matches!(addr.len(), 4 | 16) || !matches!(base.len(), 8 | 32) {
        return Match::BadSyntax;
    }
    if addr.len().checked_mul(2) != Some(base.len()) {
        return Match::Outside;
    }
    let (net, mask) = base.split_at(addr.len());
    let within = addr
        .iter()
        .zip(net)
        .zip(mask)
        .all(|((&h, &b), &m)| h & m == b & m);
    if within {
        Match::Within
    } else {
        Match::Outside
    }
}

/// `cn2dnsid`: a common name (UTF-8, trailing NULs dropped) as a DNS name if it looks like
/// one (letters, digits, `_`, and inner `-` and single `.`s, at least one dot); `Ok(None)`
/// if not; `Err` for a NUL inside.
pub fn cn_as_dns(cn: &[u8]) -> Result<Option<&[u8]>, Match> {
    let end = cn
        .iter()
        .rposition(|&c| c != 0)
        .map_or(0, |i| i.saturating_add(1));
    let value = cn.get(..end).unwrap_or_default();
    if value.contains(&0) {
        return Err(Match::BadSyntax);
    }
    let mut isdnsname = false;
    for (i, &c) in value.iter().enumerate() {
        if c.is_ascii_alphanumeric() || c == b'_' {
            continue;
        }
        let next_i = i.saturating_add(1);
        if i > 0 && next_i < value.len() {
            if c == b'-' {
                continue;
            }
            let next = value.get(next_i).copied();
            let prev = i.checked_sub(1).and_then(|p| value.get(p)).copied();
            if c == b'.' && next != Some(b'.') && prev != Some(b'-') && next != Some(b'-') {
                isdnsname = true;
                continue;
            }
        }
        isdnsname = false;
        break;
    }
    Ok(isdnsname.then_some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names() {
        assert_eq!(dns(b"www.example.com", b"example.com"), Match::Within);
        assert_eq!(dns(b"wwwexample.com", b"example.com"), Match::Outside);
        assert_eq!(dns(b"example.com", b".example.com"), Match::Outside);
        assert_eq!(dns(b"a.example.com", b".example.com"), Match::Within);
        assert_eq!(dns(b"anything", b""), Match::Within);
    }

    #[test]
    fn emails() {
        assert_eq!(email(b"a@example.com", b"example.com"), Match::Within);
        assert_eq!(email(b"a@x.example.com", b".example.com"), Match::Within);
        assert_eq!(email(b"a@example.com", b"b@example.com"), Match::Outside);
        assert_eq!(email(b"noat", b"example.com"), Match::BadSyntax);
    }

    #[test]
    fn ips_and_cns() {
        assert_eq!(
            ip(&[10, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 0, 0]),
            Match::Within
        );
        assert_eq!(
            ip(&[11, 1, 2, 3], &[10, 0, 0, 0, 255, 0, 0, 0]),
            Match::Outside
        );
        assert_eq!(
            cn_as_dns(b"www.example.com"),
            Ok(Some(&b"www.example.com"[..]))
        );
        assert_eq!(cn_as_dns(b"John Smith"), Ok(None));
        assert_eq!(cn_as_dns(b"a\0b.com"), Err(Match::BadSyntax));
    }
}
