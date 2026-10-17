//! IP addresses as text (`ossl_a2i_ipadd`, `ossl_ipaddr_to_asc` of `v3_utl.c`): the dotted IPv4
//! and colon-separated IPv6 forms OpenSSL reads in extensions and host checks, and the forms it
//! writes them in.
//!
//! As OpenSSL's:
//! - An IPv4 address is four decimal numbers of at most 255, without leading zeros (but `0`
//!   itself), separated by dots, with nothing else.
//! - An IPv6 address is up to eight groups of one to four hex digits, one `::` (or a leading or
//!   trailing one) for the zeros, and optionally a dotted IPv4 address as its last 32 bits. No
//!   spaces, no zone, no brackets.
//! - Written, IPv6 groups are upper-case hex without leading zeros and with no `::`
//!   compression.

use core::fmt::Write as _;

/// The octets of an address written as text: 4 for IPv4 (no `:` in it), 16 for IPv6, or `None`.
pub fn parse(text: &[u8]) -> Option<Vec<u8>> {
    if text.contains(&b':') {
        ipv6(text).map(|v| v.to_vec())
    } else {
        ipv4(text).map(|v| v.to_vec())
    }
}

/// A network address and its mask (`a2i_IPADDRESS_NC`): `address/mask`, both of the same
/// family, as their octets one after the other (8 or 32), or `None`.
pub fn parse_network(text: &[u8]) -> Option<Vec<u8>> {
    let slash = text.iter().position(|&c| c == b'/')?;
    let (addr, mask) = (text.get(..slash)?, text.get(slash.checked_add(1)?..)?);
    let mut out = parse(addr)?;
    let m = parse(mask)?;
    if m.len() != out.len() {
        return None;
    }
    out.extend(m);
    Some(out)
}

/// `ipv4_from_asc`.
fn ipv4(text: &[u8]) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = text.split(|&c| c == b'.');
    for slot in &mut out {
        *slot = ipv4_component(parts.next()?)?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// `get_ipv4_component`: a decimal number of at most 255, without leading zeros.
fn ipv4_component(digits: &[u8]) -> Option<u8> {
    let (&first, rest) = digits.split_first()?;
    if !first.is_ascii_digit() {
        return None;
    }
    if first == b'0' && !rest.is_empty() {
        return None;
    }
    let mut v: u32 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v
            .checked_mul(10)?
            .checked_add(u32::from(c.wrapping_sub(b'0')))?;
        if v > 255 {
            return None;
        }
    }
    u8::try_from(v).ok()
}

/// `ipv6_from_asc`, with `ipv6_cb` over the pieces between colons as `CONF_parse_list`
/// gives them (empty ones included, nothing trimmed).
fn ipv6(text: &[u8]) -> Option<[u8; 16]> {
    let mut tmp = [0u8; 16];
    let mut total: usize = 0;
    let mut zero_pos: Option<usize> = None;
    let mut zero_cnt = 0u32;
    let pieces: Vec<&[u8]> = text.split(|&c| c == b':').collect();
    let last = pieces.len().saturating_sub(1);
    for (i, elem) in pieces.iter().enumerate() {
        if total == 16 {
            return None;
        }
        if elem.is_empty() {
            match zero_pos {
                None => zero_pos = Some(total),
                Some(z) if z != total => return None,
                Some(_) => {}
            }
            zero_cnt = zero_cnt.checked_add(1)?;
        } else if elem.len() > 4 {
            // An IPv4 address, which must end the text.
            if total > 12 || i != last {
                return None;
            }
            let v4 = ipv4(elem)?;
            tmp.get_mut(total..total.checked_add(4)?)?
                .copy_from_slice(&v4);
            total = total.checked_add(4)?;
        } else {
            let mut num: u16 = 0;
            for &c in *elem {
                let x = char::from(c).to_digit(16)?;
                num = num.checked_shl(4)?.wrapping_add(u16::try_from(x).ok()?);
            }
            tmp.get_mut(total..total.checked_add(2)?)?
                .copy_from_slice(&num.to_be_bytes());
            total = total.checked_add(2)?;
        }
    }
    let mut out = [0u8; 16];
    match zero_pos {
        None => {
            if total != 16 {
                return None;
            }
            out = tmp;
        }
        Some(z) => {
            if total == 16 {
                return None;
            }
            match zero_cnt {
                3 if total > 0 => return None,
                3 => {}
                2 if z != 0 && z != total => return None,
                2 => {}
                1 if z == 0 || z == total => return None,
                1 => {}
                _ => return None,
            }
            out.get_mut(..z)?.copy_from_slice(tmp.get(..z)?);
            let tail = total.checked_sub(z)?;
            let start = 16usize.checked_sub(tail)?;
            out.get_mut(start..)?.copy_from_slice(tmp.get(z..total)?);
        }
    }
    Some(out)
}

/// `ossl_ipaddr_to_asc`: an address's octets as text: dotted IPv4 for 4, eight upper-case
/// hex groups for 16, `<invalid length=N>` otherwise.
pub fn to_text(octets: &[u8]) -> String {
    let mut s = String::new();
    match octets.len() {
        4 => {
            for (i, b) in octets.iter().enumerate() {
                if i > 0 {
                    s.push('.');
                }
                let _ = write!(s, "{b}");
            }
        }
        16 => {
            for (i, pair) in octets.as_chunks::<2>().0.iter().enumerate() {
                if i > 0 {
                    s.push(':');
                }
                let v = u16::from_be_bytes(*pair);
                let _ = write!(s, "{v:X}");
            }
        }
        n => {
            let _ = write!(s, "<invalid length={n}>");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_follows_openssl() {
        assert_eq!(parse(b"192.168.0.1"), Some(vec![192, 168, 0, 1]));
        assert_eq!(parse(b"0.0.0.0"), Some(vec![0, 0, 0, 0]));
        for bad in [
            &b"01.2.3.4"[..],
            b"256.1.1.1",
            b"1.2.3",
            b"1.2.3.4.5",
            b"1.2.3.",
            b"",
            b" 1.2.3.4",
            b"1.2.3.4 ",
            b"a.b.c.d",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn ipv6_follows_openssl() {
        let one = {
            let mut v = vec![0u8; 16];
            v[15] = 1;
            v
        };
        assert_eq!(parse(b"::1"), Some(one));
        assert_eq!(parse(b"::"), Some(vec![0u8; 16]));
        assert_eq!(
            parse(b"2001:db8::ff00:42:8329"),
            Some(vec![
                0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0xff, 0, 0, 0x42, 0x83, 0x29
            ])
        );
        assert_eq!(
            parse(b"::ffff:1.2.3.4"),
            Some(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4])
        );
        assert_eq!(parse(b"1:2:3:4:5:6:7:8").map(|v| v.len()), Some(16));
        for bad in [
            &b":1"[..],
            b"1:",
            b"1:::2",
            b"1::2::3",
            b"12345::",
            b"1:2:3:4:5:6:7:8:9",
            b"1:2:3:4:5:6:7:8::",
            b"g::",
            b"1.2.3.4::",
        ] {
            assert_eq!(parse(bad), None, "{:?}", core::str::from_utf8(bad));
        }
    }

    #[test]
    fn networks_need_the_same_family() {
        assert_eq!(
            parse_network(b"10.0.0.0/255.0.0.0"),
            Some(vec![10, 0, 0, 0, 255, 0, 0, 0])
        );
        assert_eq!(parse_network(b"10.0.0.0/::"), None);
        assert_eq!(parse_network(b"10.0.0.0"), None);
    }

    #[test]
    fn text_follows_openssl() {
        assert_eq!(to_text(&[127, 0, 0, 1]), "127.0.0.1");
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[15] = 0xab;
        assert_eq!(to_text(&v6), "2001:0:0:0:0:0:0:AB");
        assert_eq!(to_text(&[1, 2, 3]), "<invalid length=3>");
    }
}
