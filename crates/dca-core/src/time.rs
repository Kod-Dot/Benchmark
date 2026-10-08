//! Minimal UTC date handling: Windows FILETIME and ISO 8601 to and from
//! Unix seconds. Enough for the directory's timestamps without pulling in a
//! date library.

/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 11_644_473_600;

pub const DAY: i64 = 86_400;

/// A FILETIME (100 ns intervals since 1601) as Unix seconds. 0 and
/// `i64::MAX` mean "never" in AD and return `None`.
pub fn from_filetime(ft: i64) -> Option<i64> {
    if ft <= 0 || ft == i64::MAX {
        return None;
    }
    Some(ft / 10_000_000 - FILETIME_UNIX_OFFSET)
}

/// A negative 100 ns interval (maxPwdAge, lockoutDuration) as whole seconds.
/// `i64::MIN` means "never" and returns `None`.
pub fn from_interval(v: i64) -> Option<i64> {
    if v == i64::MIN {
        return None;
    }
    Some(v.unsigned_abs() as i64 / 10_000_000)
}

// Howard Hinnant's days-from-civil and civil-from-days.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ`.
pub fn iso(secs: i64) -> String {
    let (y, m, d) = civil_from_days(secs.div_euclid(DAY));
    let s = secs.rem_euclid(DAY);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        s / 3600,
        s % 3600 / 60,
        s % 60
    )
}

/// Parses `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM:SSZ` or `...SS.fffZ` (UTC only).
pub fn parse_iso(text: &str) -> Option<i64> {
    let t = text.trim();
    let num = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let mut secs = days_from_civil(y, m, d) * DAY;
    if t.len() >= 19 {
        secs += num(11..13)? * 3600 + num(14..16)? * 60 + num(17..19)?;
    }
    Some(secs)
}

/// The current time as Unix seconds.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Whole days from `then` to `now`.
pub fn days_between(then: i64, now: i64) -> i64 {
    (now - then).div_euclid(DAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_round_trip() {
        // 2026-10-05T14:20:05Z
        let unix = parse_iso("2026-10-05T14:20:05Z").unwrap();
        let ft = (unix + FILETIME_UNIX_OFFSET) * 10_000_000;
        assert_eq!(from_filetime(ft), Some(unix));
        assert_eq!(iso(unix), "2026-10-05T14:20:05Z");
        assert_eq!(from_filetime(0), None);
        assert_eq!(from_filetime(i64::MAX), None);
    }

    #[test]
    fn intervals_and_dates() {
        // maxPwdAge of 42 days.
        assert_eq!(from_interval(-36_288_000_000_000), Some(42 * DAY));
        assert_eq!(from_interval(i64::MIN), None);
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(parse_iso("2000-02-29"), Some(951_782_400));
        assert_eq!(
            parse_iso("2026-10-05T14:20:05.1234567Z"),
            parse_iso("2026-10-05T14:20:05Z")
        );
        assert_eq!(parse_iso("nonsense"), None);
        assert_eq!(days_between(0, 3 * DAY + 5), 3);
    }
}
