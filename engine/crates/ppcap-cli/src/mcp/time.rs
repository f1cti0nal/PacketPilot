//! UTC timestamp formatting and parsing for tool I/O (agents read ISO-8601, the engine keeps
//! `i64` nanoseconds since the Unix epoch).

use serde_json::Value;

/// `2024-05-01T12:00:03.250Z` (millisecond precision; whole seconds drop the fraction).
pub fn fmt_ns(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let millis = ns.rem_euclid(1_000_000_000) / 1_000_000;
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let base = format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        tod / 3600,
        (tod / 60) % 60,
        tod % 60
    );
    if millis == 0 {
        format!("{base}Z")
    } else {
        format!("{base}.{millis:03}Z")
    }
}

/// `Some(ns)` formatted, `None` as JSON null.
pub fn fmt_opt(ns: Option<i64>) -> Value {
    ns.map(|n| Value::String(fmt_ns(n))).unwrap_or(Value::Null)
}

/// A time argument: an integer (nanoseconds since the epoch) or an ISO-8601 UTC string
/// (`2024-05-01T12:00:03Z`, optional fraction, `Z` or `+00:00`; a bare date means midnight).
pub fn parse_time(v: &Value) -> Result<i64, String> {
    if let Some(n) = v.as_i64() {
        return Ok(n);
    }
    let s = v
        .as_str()
        .ok_or("a time must be an ISO-8601 UTC string or integer nanoseconds")?
        .trim();
    parse_iso(s).ok_or_else(|| format!("cannot parse time {s:?}; use e.g. 2024-05-01T12:00:03Z"))
}

fn parse_iso(s: &str) -> Option<i64> {
    let s = s
        .strip_suffix('Z')
        .or_else(|| s.strip_suffix("+00:00"))
        .unwrap_or(s);
    let (date, clock) = match s.split_once(['T', ' ']) {
        Some((d, c)) => (d, Some(c)),
        None => (s, None),
    };
    let mut dp = date.splitn(3, '-');
    let y: i64 = dp.next()?.parse().ok()?;
    let m: u32 = dp.next()?.parse().ok()?;
    let d: u32 = dp.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut ns = days_from_civil(y, m, d) * 86_400 * 1_000_000_000;
    if let Some(c) = clock {
        let (hms, frac) = match c.split_once('.') {
            Some((a, b)) => (a, Some(b)),
            None => (c, None),
        };
        let mut tp = hms.splitn(3, ':');
        let h: i64 = tp.next()?.parse().ok()?;
        let mi: i64 = tp.next()?.parse().ok()?;
        let se: i64 = tp.next().unwrap_or("0").parse().ok()?;
        if h > 23 || mi > 59 || se > 60 {
            return None;
        }
        ns += (h * 3600 + mi * 60 + se) * 1_000_000_000;
        if let Some(f) = frac {
            if f.is_empty() || f.len() > 9 || !f.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let padded = format!("{f:0<9}");
            ns += padded.parse::<i64>().ok()?;
        }
    }
    Some(ns)
}

// Howard Hinnant's civil-calendar algorithms (proleptic Gregorian, days since 1970-01-01).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn formats_and_parses_round_trip() {
        let ns = 1_714_564_803_250_000_000; // 2024-05-01T12:00:03.250Z
        assert_eq!(fmt_ns(ns), "2024-05-01T12:00:03.250Z");
        assert_eq!(parse_time(&json!("2024-05-01T12:00:03.250Z")).unwrap(), ns);
        assert_eq!(
            parse_time(&json!("2024-05-01T12:00:03.25+00:00")).unwrap(),
            ns
        );
        assert_eq!(parse_time(&json!(ns)).unwrap(), ns);
        assert_eq!(fmt_ns(0), "1970-01-01T00:00:00Z");
        assert_eq!(
            parse_time(&json!("2024-05-01")).unwrap(),
            1_714_521_600_000_000_000
        );
        assert_eq!(fmt_ns(951_782_400_000_000_000), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_time(&json!("yesterday")).is_err());
        assert!(parse_time(&json!("2024-13-01")).is_err());
        assert!(parse_time(&json!("2024-05-01T25:00:00Z")).is_err());
        assert!(parse_time(&json!(true)).is_err());
    }
}
