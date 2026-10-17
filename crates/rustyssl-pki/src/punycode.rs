//! Punycode (RFC 3492) decoding and A-label to U-label conversion (`ossl_punycode_decode`,
//! `ossl_a2ulabel` of OpenSSL's `punycode.c`), for email name constraints.
//!
//! OpenSSL's decoder overflowed its output buffer (CVE-2022-3602, CVE-2022-3786); this one
//! bounds every write by the output's capacity, and every sum by `u32`.
//!
//! As OpenSSL's:
//! - A label decodes to at most 512 code points.
//! - Code points past U+10FFFF fail the conversion.
//! - Only labels that start with `xn--` (case-sensitively) are decoded.

const BASE: u32 = 36;
const TMIN: u32 = 1;
const TMAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;
const DELIMITER: u8 = b'-';

/// The most code points a label decodes to (`LABEL_BUF_SIZE`).
pub const LABEL_MAX: usize = 512;

fn adapt(delta: u32, numpoints: u32, firsttime: bool) -> Option<u32> {
    let mut delta = delta.checked_div(if firsttime { DAMP } else { 2 })?;
    delta = delta.checked_add(delta.checked_div(numpoints.max(1))?)?;
    let mut k = 0u32;
    // (BASE - TMIN) * TMAX / 2, and BASE - TMIN: constants.
    const LIMIT: u32 = ((BASE - TMIN) * TMAX) / 2;
    const BT: u32 = BASE - TMIN;
    while delta > LIMIT {
        delta = delta.checked_div(BT)?;
        k = k.checked_add(BASE)?;
    }
    let num = (BT + 1).checked_mul(delta)?;
    k.checked_add(num.checked_div(delta.checked_add(SKEW)?)?)
}

fn digit(a: u8) -> Option<u32> {
    let d = match a {
        b'A'..=b'Z' => a.checked_sub(b'A')?,
        b'a'..=b'z' => a.checked_sub(b'a')?,
        b'0'..=b'9' => a.checked_sub(b'0')?.checked_add(26)?,
        _ => return None,
    };
    Some(u32::from(d))
}

/// `ossl_punycode_decode`: the code points `encoded` decodes to, at most `max_out` of them,
/// or `None`.
pub fn decode(encoded: &[u8], max_out: usize) -> Option<Vec<u32>> {
    let mut n = INITIAL_N;
    let mut i: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let mut out: Vec<u32> = Vec::new();
    let basic_count = encoded.iter().rposition(|&c| c == DELIMITER).unwrap_or(0);
    let mut pos = 0;
    if basic_count > 0 {
        if basic_count > max_out {
            return None;
        }
        for &c in encoded.get(..basic_count)? {
            if c >= 0x80 {
                return None;
            }
            out.push(u32::from(c));
        }
        pos = basic_count.checked_add(1)?;
    }
    while pos < encoded.len() {
        let oldi = i;
        let mut w: u32 = 1;
        let mut k = BASE;
        loop {
            let &c = encoded.get(pos)?;
            pos = pos.checked_add(1)?;
            let d = digit(c)?;
            if d > u32::MAX.checked_sub(i)?.checked_div(w)? {
                return None;
            }
            i = i.checked_add(d.checked_mul(w)?)?;
            let t = if k <= bias {
                TMIN
            } else if k >= bias.saturating_add(TMAX) {
                TMAX
            } else {
                k.checked_sub(bias)?
            };
            if d < t {
                break;
            }
            let bt = BASE.checked_sub(t)?;
            if w > u32::MAX.checked_div(bt)? {
                return None;
            }
            w = w.checked_mul(bt)?;
            k = k.checked_add(BASE)?;
        }
        let written = u32::try_from(out.len()).ok()?.checked_add(1)?;
        bias = adapt(i.checked_sub(oldi)?, written, oldi == 0)?;
        let step = i.checked_div(written)?;
        if step > u32::MAX.checked_sub(n)? {
            return None;
        }
        n = n.checked_add(step)?;
        i = i.checked_rem(written)?;
        if out.len() >= max_out {
            return None;
        }
        out.insert(usize::try_from(i).ok()?, n);
        i = i.checked_add(1)?;
    }
    Some(out)
}

/// `codepoint2utf8`: a code point's UTF-8 encoding, or `None` past U+10FFFF.
fn utf8(cp: u32) -> Option<Vec<u8>> {
    char::from_u32(cp)
        .map(|c| c.to_string().into_bytes())
        .or_else(|| {
            // Surrogates aren't `char`s but encode as three octets, as OpenSSL's encoder does.
            (0xD800..=0xDFFF).contains(&cp).then(|| {
                let b0 = u8::try_from(((cp >> 12) & 0x0F) | 0xE0).unwrap_or(0xED);
                let b1 = u8::try_from(((cp >> 6) & 0x3F) | 0x80).unwrap_or(0x80);
                let b2 = u8::try_from((cp & 0x3F) | 0x80).unwrap_or(0x80);
                vec![b0, b1, b2]
            })
        })
}

/// `ossl_a2ulabel`: the dotted name with each `xn--` label decoded to UTF-8, if it fits in
/// `outlen` octets with a NUL: `Ok` with the text, `Err(0)` if it doesn't fit, `Err(-1)` for a
/// label that doesn't decode.
pub fn a2ulabel(input: &[u8], outlen: usize) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    let mut fits = true;
    let mut push = |bytes: &[u8], out: &mut Vec<u8>| {
        if out.len().saturating_add(bytes.len()) > outlen {
            fits = false;
        } else {
            out.extend_from_slice(bytes);
        }
    };
    let mut labels = input.split(|&c| c == b'.').peekable();
    while let Some(label) = labels.next() {
        if let Some(encoded) = label.strip_prefix(b"xn--") {
            let points = decode(encoded, LABEL_MAX).ok_or(-1)?;
            for cp in points {
                let bytes = utf8(cp).ok_or(-1)?;
                push(&bytes, &mut out);
            }
        } else {
            push(label, &mut out);
        }
        if labels.peek().is_some() {
            push(b".", &mut out);
        }
    }
    push(b"\0", &mut out);
    if fits {
        out.pop();
        Ok(out)
    } else {
        Err(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3492_samples() {
        assert_eq!(
            a2ulabel(b"xn--bcher-kva.example", 256),
            Ok("bücher.example".as_bytes().to_vec())
        );
        assert_eq!(a2ulabel(b"example.com", 256), Ok(b"example.com".to_vec()));
        let points = decode(b"egbpdaj6bu4bxfgehfvwxn", 64);
        assert_eq!(points.map(|p| p.len()), Some(17));
    }

    #[test]
    fn overflows_are_refused() {
        // CVE-2022-3602: a label decoding to more than its output holds.
        let long = [b'a'; 600];
        let mut label = b"xn--".to_vec();
        label.extend_from_slice(&long);
        label.extend_from_slice(b"-a");
        assert_eq!(a2ulabel(&label, 256), Err(-1));
        assert_eq!(decode(b"99999999999", 8), None);
        assert_eq!(a2ulabel(b"xn--bcher-kva.example", 4), Err(0));
    }
}
