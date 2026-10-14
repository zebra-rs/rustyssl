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

    /// docs/DEVIATIONS.md: a NUL separator splits nowhere (OpenSSL's `strchr` finds the
    /// string's terminator, and the loop goes on past it).
    #[test]
    fn a_nul_separator_splits_nowhere() {
        assert_eq!(list_items(b"a,b", 0, false), [Some(&b"a,b"[..])]);
        assert_eq!(list_items(b"", 0, false), [None]);
    }
}
