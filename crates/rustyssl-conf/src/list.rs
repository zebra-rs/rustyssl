//! `CONF_parse_list`'s splitting.

/// Whether `c` is a space as the C library's `isspace` says in the "C" locale.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// The items of `list` (up to its first NUL) split at `sep`, as `CONF_parse_list` gives them
/// to its callback: `None` for an empty one (the callback's NULL, 0), and with `nospc` the
/// spaces around each trimmed (an item of spaces alone is then empty).
///
/// A NUL separator splits nowhere, so the list is one item (OpenSSL's `strchr` finds the
/// terminator and the loop then reads past the end of the string).
pub fn list_items(list: &[u8], sep: u8, nospc: bool) -> Vec<Option<&[u8]>> {
    let list = list.split(|&c| c == 0).next().unwrap_or_default();
    let mut items = Vec::new();
    let mut rest = list;
    loop {
        if nospc {
            let skip = rest.iter().take_while(|&&c| is_space(c)).count();
            rest = rest.get(skip..).unwrap_or_default();
        }
        let at = if sep == 0 {
            None
        } else {
            rest.iter().position(|&c| c == sep)
        };
        let item = match at {
            Some(i) => rest.get(..i).unwrap_or_default(),
            None => rest,
        };
        if item.is_empty() {
            items.push(None);
        } else {
            let mut item = item;
            if nospc {
                let keep = item
                    .len()
                    .saturating_sub(item.iter().rev().take_while(|&&c| is_space(c)).count());
                item = item.get(..keep).unwrap_or_default();
            }
            items.push(Some(item));
        }
        match at {
            Some(i) => rest = rest.get(i.saturating_add(1)..).unwrap_or_default(),
            None => return items,
        }
    }
}

/// Why `X509V3_parse_list` fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameValueError {
    /// A name of spaces alone (`X509V3_R_INVALID_EMPTY_NAME`).
    EmptyName,
    /// A value of spaces alone (`X509V3_R_INVALID_NULL_VALUE`).
    NullValue,
}

/// An item of [`name_value_list`]: its name, and its value if it has one.
pub type NameValue = (Vec<u8>, Option<Vec<u8>>);

/// `strip_spaces`: the token in `seg` without its surrounding spaces, or `None` if it's all
/// spaces. As in OpenSSL, a token of one character keeps the spaces after it.
fn strip_spaces(seg: &[u8]) -> Option<&[u8]> {
    let start = seg.iter().position(|&c| !is_space(c))?;
    let rest = seg.get(start..)?;
    let mut end = rest.len().checked_sub(1)?;
    while end != 0 && rest.get(end).is_some_and(|&c| is_space(c)) {
        end = end.saturating_sub(1);
    }
    if end == 0 {
        return Some(rest);
    }
    rest.get(..=end)
}

/// `X509V3_parse_list`: `name:value, name, ...` (up to the first NUL) as names and optional
/// values. The scan stops at a CR or LF, but the last item runs on to the end, as OpenSSL's
/// does.
pub fn name_value_list(line: &[u8]) -> Result<Vec<NameValue>, NameValueError> {
    let line = line.split(|&c| c == 0).next().unwrap_or_default();
    let mut out = Vec::new();
    let mut in_value = false;
    let mut name: Vec<u8> = Vec::new();
    let mut q = 0usize;
    for (p, &c) in line.iter().enumerate() {
        if c == b'\r' || c == b'\n' {
            break;
        }
        let seg = line.get(q..p).unwrap_or_default();
        if !in_value {
            if c == b':' {
                in_value = true;
                name = strip_spaces(seg).ok_or(NameValueError::EmptyName)?.to_vec();
                q = p.saturating_add(1);
            } else if c == b',' {
                let n = strip_spaces(seg).ok_or(NameValueError::EmptyName)?.to_vec();
                q = p.saturating_add(1);
                out.push((n, None));
            }
        } else if c == b',' {
            in_value = false;
            let v = strip_spaces(seg).ok_or(NameValueError::NullValue)?.to_vec();
            out.push((core::mem::take(&mut name), Some(v)));
            q = p.saturating_add(1);
        }
    }
    let last = line.get(q..).unwrap_or_default();
    if in_value {
        let v = strip_spaces(last)
            .ok_or(NameValueError::NullValue)?
            .to_vec();
        out.push((name, Some(v)));
    } else {
        let n = strip_spaces(last)
            .ok_or(NameValueError::EmptyName)?
            .to_vec();
        out.push((n, None));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items() {
        assert_eq!(
            list_items(b"a,,b", b',', false),
            [Some(&b"a"[..]), None, Some(b"b")]
        );
        assert_eq!(
            list_items(b" a , b ", b',', true),
            [Some(&b"a"[..]), Some(b"b")]
        );
        assert_eq!(
            list_items(b" a , b ", b',', false),
            [Some(&b" a "[..]), Some(b" b ")]
        );
        assert_eq!(list_items(b"", b',', false), [None]);
        assert_eq!(list_items(b",", b',', true), [None, None]);
        assert_eq!(list_items(b"   ", b',', true), [None]);
        assert_eq!(
            list_items(b"a,b\0,c", b',', false),
            [Some(&b"a"[..]), Some(b"b")]
        );
    }

    #[test]
    fn name_values() {
        let v = |n: &[u8], x: Option<&[u8]>| (n.to_vec(), x.map(<[u8]>::to_vec));
        assert_eq!(
            name_value_list(b" min:1, max : 8 ,flags:nomask"),
            Ok(vec![
                v(b"min", Some(b"1")),
                v(b"max", Some(b"8 ")),
                v(b"flags", Some(b"nomask"))
            ])
        );
        assert_eq!(
            name_value_list(b"a , bc ,d"),
            Ok(vec![v(b"a ", None), v(b"bc", None), v(b"d", None)])
        );
        assert_eq!(name_value_list(b"x:"), Err(NameValueError::NullValue));
        assert_eq!(name_value_list(b" ,a"), Err(NameValueError::EmptyName));
        assert_eq!(name_value_list(b"a\nb, c"), Ok(vec![v(b"a\nb, c", None)]));
    }

    /// docs/DEVIATIONS.md: a NUL separator splits nowhere (OpenSSL's `strchr` finds the
    /// string's terminator, and the loop goes on past it).
    #[test]
    fn a_nul_separator_splits_nowhere() {
        assert_eq!(list_items(b"a,b", 0, false), [Some(&b"a,b"[..])]);
        assert_eq!(list_items(b"", 0, false), [None]);
    }
}
