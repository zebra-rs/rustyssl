//! UTCTime and GeneralizedTime as OpenSSL reads, writes, and computes with them
//! (`ossl_asn1_time_to_tm`, `ossl_asn1_time_from_tm`, `OPENSSL_gmtime_adj`,
//! `OPENSSL_gmtime_diff`).
//!
//! Ports, step for step, since the leniencies are observable: without `strict` (RFC 5280's
//! form, which `ASN1_STRING_FLAG_X509_TIME` asks for) the seconds may be left out before a time
//! zone, a GeneralizedTime may have a fraction, and a `+hhmm`/`-hhmm` offset (hours up to 12)
//! is accepted and folded into the time. The weekday and day of the year are computed before
//! the offset is applied, and the date arithmetic keeps C's `int` and `long` widths.

/// The fields of C's `struct tm` that OpenSSL uses.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tm {
    pub sec: i32,
    pub min: i32,
    pub hour: i32,
    pub mday: i32,
    pub mon: i32,
    pub year: i32,
    pub wday: i32,
    pub yday: i32,
}

/// The time types (`V_ASN1_UTCTIME`, `V_ASN1_GENERALIZEDTIME`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Utc,
    Generalized,
}

/// Seconds in a day.
const SECS_PER_DAY: i64 = 24 * 60 * 60;

fn leap_year(year: i32) -> bool {
    year.wrapping_rem(400) == 0 || (year.wrapping_rem(100) != 0 && year.wrapping_rem(4) == 0)
}

/// `determine_days`: the day of the year and (Zeller's congruence) the weekday.
fn determine_days(tm: &mut Tm) {
    const YDAYS: [i32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut y = tm.year.wrapping_add(1900);
    let mut m = tm.mon;
    let d = tm.mday;
    tm.yday = usize::try_from(m)
        .ok()
        .and_then(|i| YDAYS.get(i))
        .copied()
        .unwrap_or(0)
        .wrapping_add(d)
        .wrapping_sub(1);
    if m >= 2 {
        tm.yday = tm.yday.wrapping_add(i32::from(leap_year(y)));
        m = m.wrapping_add(2);
    } else {
        m = m.wrapping_add(14);
        y = y.wrapping_sub(1);
    }
    let c = y.wrapping_div(100);
    let y = y.wrapping_rem(100);
    tm.wday = d
        .wrapping_add(m.wrapping_mul(13).wrapping_div(5))
        .wrapping_add(y)
        .wrapping_add(y.wrapping_div(4))
        .wrapping_add(c.wrapping_div(4))
        .wrapping_add(c.wrapping_mul(5))
        .wrapping_add(6)
        .wrapping_rem(7);
}

/// `ossl_asn1_time_to_tm`: the time `data` (of `kind`) holds, or `None` if it isn't one. With
/// `apply_offset` false (a check, without a `tm` to fill), a `+hhmm` offset isn't applied.
pub fn parse(data: &[u8], kind: Kind, strict: bool, apply_offset: bool) -> Option<Tm> {
    const MIN: [i32; 9] = [0, 0, 1, 1, 0, 0, 0, 0, 0];
    const MAX: [i32; 9] = [99, 99, 12, 31, 23, 59, 59, 12, 59];
    const MDAYS: [i32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let utc = kind == Kind::Utc;
    let (min_len, end, before_tz): (usize, usize, usize) =
        if utc { (13, 6, 5) } else { (15, 7, 6) };
    let l = data.len();
    if l < min_len {
        return None;
    }
    let at = |o: usize| data.get(o).copied().unwrap_or(0);
    let mut o = 0usize;
    let mut tmp = Tm::default();
    let digit = |c: u8| c.is_ascii_digit().then(|| i32::from(c.wrapping_sub(b'0')));
    let mut i: usize = 0;
    while i < end {
        if !strict && i == before_tz && matches!(at(o), b'Z' | b'+' | b'-') {
            break;
        }
        let high = digit(at(o))?;
        o = o.saturating_add(1);
        if o == l {
            return None;
        }
        let n = high.wrapping_mul(10).wrapping_add(digit(at(o))?);
        o = o.saturating_add(1);
        if o == l {
            return None;
        }
        let i2 = if utc { i.wrapping_add(1) } else { i };
        let range = MIN.get(i2).copied().unwrap_or(0)..=MAX.get(i2).copied().unwrap_or(0);
        if !range.contains(&n) {
            return None;
        }
        match i2 {
            0 => tmp.year = n.wrapping_mul(100).wrapping_sub(1900),
            1 => {
                if utc {
                    tmp.year = if n < 50 { n.wrapping_add(100) } else { n };
                } else {
                    tmp.year = tmp.year.wrapping_add(n);
                }
            }
            2 => tmp.mon = n.wrapping_sub(1),
            3 => {
                let month_days = if tmp.mon == 1 {
                    28i32.wrapping_add(i32::from(leap_year(tmp.year.wrapping_add(1900))))
                } else {
                    usize::try_from(tmp.mon)
                        .ok()
                        .and_then(|m| MDAYS.get(m))
                        .copied()
                        .unwrap_or(0)
                };
                if n > month_days {
                    return None;
                }
                tmp.mday = n;
                determine_days(&mut tmp);
            }
            4 => tmp.hour = n,
            5 => tmp.min = n,
            _ => tmp.sec = n,
        }
        i = i.wrapping_add(1);
    }
    if !utc && at(o) == b'.' {
        if strict {
            return None;
        }
        o = o.saturating_add(1);
        if o == l {
            return None;
        }
        let start = o;
        while o < l && at(o).is_ascii_digit() {
            o = o.saturating_add(1);
        }
        if o == start || o == l {
            return None;
        }
    }
    match at(o) {
        b'Z' => o = o.saturating_add(1),
        sign @ (b'+' | b'-') if !strict => {
            let offsign: i64 = if sign == b'-' { 1 } else { -1 };
            o = o.saturating_add(1);
            if o.saturating_add(4) != l {
                return None;
            }
            let mut offset: i64 = 0;
            for i in end..end.wrapping_add(2) {
                let high = digit(at(o))?;
                o = o.saturating_add(1);
                let n = high.wrapping_mul(10).wrapping_add(digit(at(o))?);
                let i2 = if utc { i.wrapping_add(1) } else { i };
                let range = MIN.get(i2).copied().unwrap_or(0)..=MAX.get(i2).copied().unwrap_or(0);
                if !range.contains(&n) {
                    return None;
                }
                if apply_offset {
                    if i == end {
                        offset = i64::from(n).wrapping_mul(3600);
                    } else {
                        offset = offset.wrapping_add(i64::from(n).wrapping_mul(60));
                    }
                }
                o = o.saturating_add(1);
            }
            if offset != 0 && !gmtime_adj(&mut tmp, 0, offset.wrapping_mul(offsign)) {
                return None;
            }
        }
        _ => return None,
    }
    (o == l).then_some(tmp)
}

/// Whether a `tm_year` (years since 1900) is one a UTCTime can hold (1950 to 2049).
pub fn is_utc(year: i32) -> bool {
    (50..=149).contains(&year)
}

/// `ossl_asn1_time_from_tm`'s text: `YYMMDDHHMMSSZ` or `YYYYMMDDHHMMSSZ`, as `BIO_snprintf`
/// writes it into 20 octets. When it doesn't fit, the octets that did and length -1, as there.
pub fn format(tm: &Tm, kind: Kind) -> (Vec<u8>, i32) {
    let text = match kind {
        Kind::Generalized => format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            i64::from(tm.year).wrapping_add(1900),
            i64::from(tm.mon).wrapping_add(1),
            tm.mday,
            tm.hour,
            tm.min,
            tm.sec
        ),
        Kind::Utc => format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            tm.year.wrapping_rem(100),
            i64::from(tm.mon).wrapping_add(1),
            tm.mday,
            tm.hour,
            tm.min,
            tm.sec
        ),
    };
    let mut bytes = text.into_bytes();
    if bytes.len() > 19 {
        bytes.truncate(19);
        return (bytes, -1);
    }
    let length = i32::try_from(bytes.len()).unwrap_or(-1);
    (bytes, length)
}

/// C's conversion of a `long` to `int`: the low 32 bits.
fn to_int(value: i64) -> i32 {
    let bytes = value.to_le_bytes();
    i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// `date_to_julian`, in C `int` arithmetic.
fn date_to_julian(y: i32, m: i32, d: i32) -> i64 {
    let a = m.wrapping_sub(14).wrapping_div(12);
    let part1 = 1461i32
        .wrapping_mul(y.wrapping_add(4800).wrapping_add(a))
        .wrapping_div(4);
    let part2 = 367i32
        .wrapping_mul(m.wrapping_sub(2).wrapping_sub(12i32.wrapping_mul(a)))
        .wrapping_div(12);
    let part3 = 3i32
        .wrapping_mul(y.wrapping_add(4900).wrapping_add(a).wrapping_div(100))
        .wrapping_div(4);
    i64::from(
        part1
            .wrapping_add(part2)
            .wrapping_sub(part3)
            .wrapping_add(d)
            .wrapping_sub(32075),
    )
}

/// `julian_to_date`, in C `long` arithmetic: (year, month, day).
fn julian_to_date(jd: i64) -> (i32, i32, i32) {
    let mut l = jd.wrapping_add(68569);
    let n = 4i64.wrapping_mul(l).wrapping_div(146_097);
    l = l.wrapping_sub(146_097i64.wrapping_mul(n).wrapping_add(3).wrapping_div(4));
    let i = 4000i64
        .wrapping_mul(l.wrapping_add(1))
        .wrapping_div(1_461_001);
    l = l
        .wrapping_sub(1461i64.wrapping_mul(i).wrapping_div(4))
        .wrapping_add(31);
    let j = 80i64.wrapping_mul(l).wrapping_div(2447);
    let d = to_int(l.wrapping_sub(2447i64.wrapping_mul(j).wrapping_div(80)));
    l = j.wrapping_div(11);
    let m = to_int(j.wrapping_add(2).wrapping_sub(12i64.wrapping_mul(l)));
    let y = to_int(
        100i64
            .wrapping_mul(n.wrapping_sub(49))
            .wrapping_add(i)
            .wrapping_add(l),
    );
    (y, m, d)
}

/// `julian_adj`: the Julian day and second of the day `off_day` days and `offset_sec` seconds
/// after `tm`, or `None` before day 0.
fn julian_adj(tm: &Tm, off_day: i32, offset_sec: i64) -> Option<(i64, i32)> {
    let mut offset_day = offset_sec.wrapping_div(SECS_PER_DAY);
    let mut offset_hms = to_int(offset_sec.wrapping_sub(offset_day.wrapping_mul(SECS_PER_DAY)));
    offset_day = offset_day.wrapping_add(i64::from(off_day));
    offset_hms = offset_hms
        .wrapping_add(tm.hour.wrapping_mul(3600))
        .wrapping_add(tm.min.wrapping_mul(60))
        .wrapping_add(tm.sec);
    let day = i32::try_from(SECS_PER_DAY).unwrap_or(i32::MAX);
    if offset_hms >= day {
        offset_day = offset_day.wrapping_add(1);
        offset_hms = offset_hms.wrapping_sub(day);
    } else if offset_hms < 0 {
        offset_day = offset_day.wrapping_sub(1);
        offset_hms = offset_hms.wrapping_add(day);
    }
    let jd = date_to_julian(tm.year.wrapping_add(1900), tm.mon.wrapping_add(1), tm.mday)
        .wrapping_add(offset_day);
    (jd >= 0).then_some((jd, offset_hms))
}

/// `OPENSSL_gmtime_adj`: moves `tm` by `off_day` days and `offset_sec` seconds (its date and
/// time fields only). False, leaving `tm`, if the result is before day 0 or outside the years
/// 1900 to 9999.
pub fn gmtime_adj(tm: &mut Tm, off_day: i32, offset_sec: i64) -> bool {
    let Some((jd, secs)) = julian_adj(tm, off_day, offset_sec) else {
        return false;
    };
    let (year, month, day) = julian_to_date(jd);
    if !(1900..=9999).contains(&year) {
        return false;
    }
    tm.year = year.wrapping_sub(1900);
    tm.mon = month.wrapping_sub(1);
    tm.mday = day;
    tm.hour = secs.wrapping_div(3600);
    tm.min = secs.wrapping_div(60).wrapping_rem(60);
    tm.sec = secs.wrapping_rem(60);
    true
}

/// `OPENSSL_gmtime_diff`: the days and seconds from `from` to `to`, both of one sign.
pub fn gmtime_diff(from: &Tm, to: &Tm) -> Option<(i32, i32)> {
    let (from_jd, from_sec) = julian_adj(from, 0, 0)?;
    let (to_jd, to_sec) = julian_adj(to, 0, 0)?;
    let mut days = to_jd.wrapping_sub(from_jd);
    let mut secs = to_sec.wrapping_sub(from_sec);
    let day = i32::try_from(SECS_PER_DAY).unwrap_or(i32::MAX);
    if days > 0 && secs < 0 {
        days = days.wrapping_sub(1);
        secs = secs.wrapping_add(day);
    }
    if days < 0 && secs > 0 {
        days = days.wrapping_add(1);
        secs = secs.wrapping_sub(day);
    }
    Some((to_int(days), secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tm(year: i32, mon: i32, mday: i32, hour: i32, min: i32, sec: i32) -> Tm {
        Tm {
            sec,
            min,
            hour,
            mday,
            mon,
            year,
            wday: 0,
            yday: 0,
        }
    }

    #[test]
    fn parses_as_openssl_does() {
        let t = parse(b"240229123456Z", Kind::Utc, false, true).unwrap();
        assert_eq!(
            (t.year, t.mon, t.mday, t.hour, t.min, t.sec),
            (124, 1, 29, 12, 34, 56)
        );
        assert_eq!((t.wday, t.yday), (4, 59));
        assert!(parse(b"230229123456Z", Kind::Utc, false, true).is_none());
        assert!(parse(b"2402291234Z", Kind::Utc, false, true).is_none());
        let t = parse(b"2402291234+0130", Kind::Utc, false, true).unwrap();
        assert_eq!((t.hour, t.min, t.sec), (11, 4, 0));
        assert!(parse(b"2402291234+0130", Kind::Utc, true, true).is_none());
        assert!(parse(b"240229123456+1300", Kind::Utc, false, true).is_none());
        let g = parse(b"20240229123456.789Z", Kind::Generalized, false, true).unwrap();
        assert_eq!(g.year, 124);
        assert!(parse(b"20240229123456.789Z", Kind::Generalized, true, true).is_none());
        assert!(parse(b"20240229123456.Z", Kind::Generalized, false, true).is_none());
    }

    #[test]
    fn julian_arithmetic() {
        let mut t = tm(124, 11, 31, 23, 59, 59);
        assert!(gmtime_adj(&mut t, 0, 1));
        assert_eq!(
            (t.year, t.mon, t.mday, t.hour, t.min, t.sec),
            (125, 0, 1, 0, 0, 0)
        );
        assert!(gmtime_adj(&mut t, -1, -1));
        assert_eq!((t.year, t.mon, t.mday, t.hour), (124, 11, 30, 23));
        let mut far = tm(8099, 11, 31, 0, 0, 0);
        assert!(!gmtime_adj(&mut far, 1, 0));
        assert_eq!(
            gmtime_diff(&tm(124, 0, 1, 12, 0, 0), &tm(124, 0, 3, 6, 0, 0)),
            Some((1, 64800))
        );
        assert_eq!(
            gmtime_diff(&tm(124, 0, 3, 6, 0, 0), &tm(124, 0, 1, 12, 0, 0)),
            Some((-1, -64800))
        );
    }

    #[test]
    fn formats_as_openssl_does() {
        let t = tm(124, 1, 29, 1, 2, 3);
        assert_eq!(format(&t, Kind::Utc), (b"240229010203Z".to_vec(), 13));
        assert_eq!(
            format(&t, Kind::Generalized),
            (b"20240229010203Z".to_vec(), 15)
        );
        let (text, length) = format(&tm(1_000_000_000, 0, 1, 0, 0, 0), Kind::Generalized);
        assert_eq!((text.len(), length), (19, -1));
    }
}
