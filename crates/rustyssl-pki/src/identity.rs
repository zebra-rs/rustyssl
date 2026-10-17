//! Matching a certificate's names against an expected identity (the `equal_*`, wildcard, and
//! prefix functions of OpenSSL's `v3_utl.c`, behind `X509_check_host`, `X509_check_email`,
//! and `X509_check_ip`).
//!
//! As OpenSSL's:
//! - Host names compare ASCII case-insensitively, and a NUL in the certificate's name never
//!   matches.
//! - A wildcard is a single `*` in the first label, of a name with at least two dots, not in
//!   an IDNA (`xn--`) label; it matches one or more letters, digits, and hyphens (dots too,
//!   for a wildcard label with multi-label wildcards allowed), or anything for a whole `*`
//!   label. Partial wildcards (`f*o.example.com`) may be refused.
//! - An expected host starting with `.` matches the names of its subdomains (one label deep
//!   with single-label subdomains), and wildcards don't apply to it.
//! - Email addresses compare their domains case-insensitively and their local parts exactly.

/// How host names match (`X509_CHECK_FLAG_*`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostFlags {
    /// `X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS`: a wildcard must be the whole first label.
    pub no_partial_wildcards: bool,
    /// `X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS`: a whole-label wildcard may match several.
    pub multi_label_wildcards: bool,
    /// `X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS`: a `.example` match is one label deep.
    pub single_label_subdomains: bool,
    /// `_X509_CHECK_FLAG_DOT_SUBDOMAINS`: the expected host starts with `.` (set by the check
    /// itself, not by callers).
    pub dot_subdomains: bool,
}

/// `skip_prefix`: for an expected `.example`, the end of `pattern` as long as `subject`, if
/// leading octets (not past a NUL, nor a dot for single-label subdomains) can be skipped to
/// reach it; otherwise `pattern`.
fn skip_prefix(pattern: &[u8], subject_len: usize, flags: HostFlags) -> &[u8] {
    if !flags.dot_subdomains {
        return pattern;
    }
    let mut p = pattern;
    while p.len() > subject_len {
        let Some((&c, rest)) = p.split_first() else {
            break;
        };
        if c == 0 || (flags.single_label_subdomains && c == b'.') {
            break;
        }
        p = rest;
    }
    if p.len() == subject_len { p } else { pattern }
}

/// `equal_nocase`: whether the names are equal, ignoring ASCII case; a NUL in `pattern` never
/// matches.
pub fn equal_nocase(pattern: &[u8], subject: &[u8], flags: HostFlags) -> bool {
    let pattern = skip_prefix(pattern, subject.len(), flags);
    pattern.len() == subject.len()
        && pattern
            .iter()
            .zip(subject)
            .all(|(&l, &r)| l != 0 && l.eq_ignore_ascii_case(&r))
}

/// `equal_case`: whether the octets are equal (after `skip_prefix`).
pub fn equal_case(pattern: &[u8], subject: &[u8], flags: HostFlags) -> bool {
    skip_prefix(pattern, subject.len(), flags) == subject
}

/// `equal_email`: whether the addresses are equal: the part from the last `@` (of either)
/// ignoring case, the part before it exactly.
pub fn equal_email(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let none = HostFlags::default();
    let at = a.iter().zip(b).rposition(|(&x, &y)| x == b'@' || y == b'@');
    let i = match at {
        Some(i) => {
            let (Some(da), Some(db)) = (a.get(i..), b.get(i..)) else {
                return false;
            };
            if !equal_nocase(da, db, none) {
                return false;
            }
            if i == 0 { a.len() } else { i }
        }
        None => a.len(),
    };
    match (a.get(..i), b.get(..i)) {
        (Some(la), Some(lb)) => equal_case(la, lb, none),
        _ => false,
    }
}

/// Whether `s` starts with `xn--`, ignoring case (`HAS_CASE_PREFIX`).
fn idna_prefix(s: &[u8]) -> bool {
    s.get(..4).is_some_and(|p| p.eq_ignore_ascii_case(b"xn--"))
}

/// `wildcard_match`: whether `subject` is `prefix`, a wildcard's match, and `suffix`.
fn wildcard_match(prefix: &[u8], suffix: &[u8], subject: &[u8], flags: HostFlags) -> bool {
    let Some(min) = prefix.len().checked_add(suffix.len()) else {
        return false;
    };
    if subject.len() < min {
        return false;
    }
    let Some(end) = subject.len().checked_sub(suffix.len()) else {
        return false;
    };
    let (Some(start_part), Some(wildcard), Some(end_part)) = (
        subject.get(..prefix.len()),
        subject.get(prefix.len()..end),
        subject.get(end..),
    ) else {
        return false;
    };
    if !equal_nocase(prefix, start_part, flags) || !equal_nocase(end_part, suffix, flags) {
        return false;
    }
    let mut allow_multi = false;
    let mut allow_idna = false;
    if prefix.is_empty() && suffix.first() == Some(&b'.') {
        if wildcard.is_empty() {
            return false;
        }
        allow_idna = true;
        allow_multi = flags.multi_label_wildcards;
    }
    if !allow_idna && idna_prefix(subject) {
        return false;
    }
    if wildcard == b"*" {
        return true;
    }
    wildcard
        .iter()
        .all(|&c| c.is_ascii_alphanumeric() || c == b'-' || (allow_multi && c == b'.'))
}

/// `valid_star`: the index of the pattern's wildcard if it's a name with one usable wildcard
/// (see the module's comment); `None` otherwise.
fn valid_star(p: &[u8], flags: HostFlags) -> Option<usize> {
    const START: u8 = 1;
    const HYPHEN: u8 = 4;
    const IDNA: u8 = 8;
    let mut star = None;
    let mut state = START;
    let mut dots = 0usize;
    for (i, &c) in p.iter().enumerate() {
        match c {
            b'*' => {
                let atstart = state & START != 0;
                let next = i.checked_add(1).and_then(|n| p.get(n));
                let atend = next.is_none_or(|&n| n == b'.');
                if star.is_some() || state & IDNA != 0 || dots != 0 {
                    return None;
                }
                if flags.no_partial_wildcards && (!atstart || !atend) {
                    return None;
                }
                if !atstart && !atend {
                    return None;
                }
                star = Some(i);
                state &= !START;
            }
            c if c.is_ascii_alphanumeric() => {
                if state & START != 0 && p.get(i..).is_some_and(idna_prefix) {
                    state |= IDNA;
                }
                state &= !(HYPHEN | START);
            }
            b'.' => {
                if state & (HYPHEN | START) != 0 {
                    return None;
                }
                state = START;
                dots = dots.saturating_add(1);
            }
            b'-' => {
                if state & START != 0 {
                    return None;
                }
                state |= HYPHEN;
            }
            _ => return None,
        }
    }
    if state & (START | HYPHEN) != 0 || dots < 2 {
        return None;
    }
    star
}

/// `equal_wildcard`: whether the certificate's host name `pattern` (with a wildcard, if it has
/// a usable one) matches `subject`, the expected host.
pub fn equal_wildcard(pattern: &[u8], subject: &[u8], flags: HostFlags) -> bool {
    let dotted = subject.len() > 1 && subject.first() == Some(&b'.');
    let star = if dotted {
        None
    } else {
        valid_star(pattern, flags)
    };
    match star {
        None => equal_nocase(pattern, subject, flags),
        Some(i) => {
            let (Some(prefix), Some(suffix)) = (
                pattern.get(..i),
                i.checked_add(1).and_then(|n| pattern.get(n..)),
            ) else {
                return false;
            };
            wildcard_match(prefix, suffix, subject, flags)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: HostFlags = HostFlags {
        no_partial_wildcards: false,
        multi_label_wildcards: false,
        single_label_subdomains: false,
        dot_subdomains: false,
    };

    #[test]
    fn wildcards() {
        assert!(equal_wildcard(b"*.example.com", b"www.example.com", NONE));
        assert!(equal_wildcard(b"*.example.com", b"WWW.Example.COM", NONE));
        assert!(!equal_wildcard(b"*.example.com", b"a.b.example.com", NONE));
        assert!(!equal_wildcard(b"*.example.com", b".example.com", NONE));
        assert!(!equal_wildcard(b"*.com", b"example.com", NONE));
        assert!(equal_wildcard(b"f*.example.com", b"foo.example.com", NONE));
        let strict = HostFlags {
            no_partial_wildcards: true,
            ..NONE
        };
        assert!(!equal_wildcard(
            b"f*.example.com",
            b"foo.example.com",
            strict
        ));
        assert!(equal_wildcard(b"*.example.com", b"xn--a.example.com", NONE));
        assert!(!equal_wildcard(
            b"xn--*.example.com",
            b"xn--a.example.com",
            NONE
        ));
        let multi = HostFlags {
            multi_label_wildcards: true,
            ..NONE
        };
        assert!(equal_wildcard(b"*.example.com", b"a.b.example.com", multi));
    }

    #[test]
    fn subdomains_and_nuls() {
        let dot = HostFlags {
            dot_subdomains: true,
            ..NONE
        };
        assert!(equal_nocase(b"www.example.com", b".example.com", dot));
        assert!(equal_nocase(b"a.b.example.com", b".example.com", dot));
        let single = HostFlags {
            single_label_subdomains: true,
            ..dot
        };
        assert!(!equal_nocase(b"a.b.example.com", b".example.com", single));
        assert!(!equal_nocase(b"exa\0ple.com", b"exa\0ple.com", NONE));
    }

    #[test]
    fn emails() {
        assert!(equal_email(b"User@Example.COM", b"User@example.com"));
        assert!(!equal_email(b"user@example.com", b"User@example.com"));
        assert!(!equal_email(b"a@b", b"a@bc"));
    }
}
