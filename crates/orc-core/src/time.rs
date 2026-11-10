//! UTC timestamps for the snapshot rule: unix seconds <-> `YYYY-MM-DDTHH:MM:SSZ`.
//!
//! The snapshot is a unix time in `GuestInput` and `PublicValues`; the canonical
//! GraphQL body carries it as an ISO-8601 UTC string (`history(until: ...)`), and
//! the response's `viewer.createdAt` comes back in the same form. Both conversions
//! must be exact and deterministic inside the guest, so this is a tiny, dependency
//! free implementation of the proleptic Gregorian calendar (Howard Hinnant's
//! `days_from_civil` / `civil_from_days`). Unix time has no leap seconds, so
//! neither does this.
//!
//! Only one textual form is accepted and produced: exactly 20 bytes,
//! `YYYY-MM-DDTHH:MM:SSZ`, years 1970..=9999. That is what GitHub returns for
//! `DateTime` fields. Fractional seconds, offsets, lowercase `t`/`z` and leap
//! seconds are rejected.

/// `9999-12-31T23:59:59Z`, the last instant with a four-digit year.
pub const MAX_UNIX_SECONDS: u64 = 253_402_300_799;

const SECS_PER_DAY: u64 = 86_400;
/// Days from 0000-03-01 (the start of the shifted calendar) to 1970-01-01.
const UNIX_EPOCH_DAYS: u64 = 719_468;
/// Days in a 400-year era.
const DAYS_PER_ERA: u64 = 146_097;

/// Formats `secs` (unix seconds) as `YYYY-MM-DDTHH:MM:SSZ`, or `None` past
/// [`MAX_UNIX_SECONDS`].
pub fn format_utc(secs: u64) -> Option<String> {
    if secs > MAX_UNIX_SECONDS {
        return None;
    }
    let (year, month, day) = civil_from_days(secs / SECS_PER_DAY);
    let rem = secs % SECS_PER_DAY;
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    ))
}

/// Parses exactly `YYYY-MM-DDTHH:MM:SSZ` (years 1970..=9999, a real calendar
/// date, `HH <= 23`, `MM <= 59`, `SS <= 59`) into unix seconds.
pub fn parse_utc(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let year = digits(&b[0..4])?;
    let month = digits(&b[5..7])?;
    let day = digits(&b[8..10])?;
    let hour = digits(&b[11..13])?;
    let minute = digits(&b[14..16])?;
    let second = digits(&b[17..19])?;

    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * SECS_PER_DAY + hour * 3600 + minute * 60 + second)
}

/// ASCII decimal digits only (no sign, no whitespace).
fn digits(b: &[u8]) -> Option<u64> {
    b.iter().try_fold(0u64, |acc, &c| {
        c.is_ascii_digit().then(|| acc * 10 + u64::from(c - b'0'))
    })
}

fn is_leap(year: u64) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn days_in_month(year: u64, month: u64) -> u64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 for a valid date with `year >= 1970`.
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    // The shifted year starts in March, so February is the last month.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = if month > 2 { month - 3 } else { month + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5 + day - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * DAYS_PER_ERA + doe - UNIX_EPOCH_DAYS
}

/// `(year, month, day)` of the date `days` after 1970-01-01.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + UNIX_EPOCH_DAYS;
    let era = z / DAYS_PER_ERA;
    let doe = z - era * DAYS_PER_ERA; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from Python: `datetime.fromtimestamp(s, timezone.utc)` and
    /// `calendar.timegm(strptime(...))`.
    const KNOWN: &[(u64, &str)] = &[
        (0, "1970-01-01T00:00:00Z"),
        (86_399, "1970-01-01T23:59:59Z"),
        (68_169_600, "1972-02-29T00:00:00Z"),
        (94_694_399, "1972-12-31T23:59:59Z"),
        (951_782_400, "2000-02-29T00:00:00Z"),
        (951_868_800, "2000-03-01T00:00:00Z"),
        (978_307_199, "2000-12-31T23:59:59Z"),
        (1_207_785_600, "2008-04-10T00:00:00Z"),
        (1_234_567_890, "2009-02-13T23:31:30Z"),
        (1_660_707_081, "2022-08-17T03:31:21Z"),
        (1_709_164_800, "2024-02-29T00:00:00Z"),
        (1_767_225_600, "2026-01-01T00:00:00Z"),
        (1_794_322_800, "2026-11-10T15:00:00Z"),
        (4_107_542_399, "2100-02-28T23:59:59Z"),
        (4_107_542_400, "2100-03-01T00:00:00Z"),
        (MAX_UNIX_SECONDS, "9999-12-31T23:59:59Z"),
    ];

    #[test]
    fn known_vectors_format_and_parse() {
        for &(secs, text) in KNOWN {
            assert_eq!(format_utc(secs).as_deref(), Some(text), "format {secs}");
            assert_eq!(parse_utc(text), Some(secs), "parse {text}");
        }
    }

    #[test]
    fn beyond_year_9999_is_not_formatted() {
        assert_eq!(format_utc(MAX_UNIX_SECONDS + 1), None);
        assert_eq!(format_utc(u64::MAX), None);
    }

    /// Every day from 1970-01-01 to 9999-12-31: the conversions are inverse,
    /// and each date is the calendar successor of the previous one.
    #[test]
    fn every_day_round_trips_and_is_consecutive() {
        let last = MAX_UNIX_SECONDS / SECS_PER_DAY;
        let mut prev = civil_from_days(0);
        assert_eq!(prev, (1970, 1, 1));
        for days in 1..=last {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days, "{y}-{m}-{d}");
            let (py, pm, pd) = prev;
            let expected = if pd < days_in_month(py, pm) {
                (py, pm, pd + 1)
            } else if pm < 12 {
                (py, pm + 1, 1)
            } else {
                (py + 1, 1, 1)
            };
            assert_eq!((y, m, d), expected, "day {days}");
            prev = (y, m, d);
        }
        assert_eq!(prev, (9999, 12, 31));
    }

    #[test]
    fn sampled_seconds_round_trip() {
        let mut secs = 0u64;
        while secs <= MAX_UNIX_SECONDS {
            let text = format_utc(secs).expect("in range");
            assert_eq!(parse_utc(&text), Some(secs), "{text}");
            secs += 9_876_543; // prime-ish stride: hits every second-of-day class
        }
    }

    #[test]
    fn non_canonical_forms_are_rejected() {
        for bad in [
            "",
            "2022-08-17",
            "2022-08-17T03:31:21",       // no Z
            "2022-08-17T03:31:21z",      // lowercase z
            "2022-08-17t03:31:21Z",      // lowercase t
            "2022-08-17 03:31:21Z",      // space separator
            "2022-08-17T03:31:21.000Z",  // fractional seconds
            "2022-08-17T03:31:21+00:00", // offset
            "2022-08-17T03:31:21Z ",     // trailing space
            " 2022-08-17T03:31:21Z",     // leading space
            "+022-08-17T03:31:21Z",      // sign
            "2022-8-17T03:31:21Z ",      // unpadded month
            "2022/08/17T03:31:21Z",      // wrong separator
            "２022-08-17T03:31:21Z",     // non-ASCII digit
            "1969-12-31T23:59:59Z",      // before the unix epoch
            "0000-01-01T00:00:00Z",
            "2022-00-17T03:31:21Z",
            "2022-13-17T03:31:21Z",
            "2022-08-00T03:31:21Z",
            "2022-08-32T03:31:21Z",
            "2022-04-31T00:00:00Z",
            "2023-02-29T00:00:00Z", // not a leap year
            "2100-02-29T00:00:00Z", // century, not a leap year
            "2022-08-17T24:00:00Z",
            "2022-08-17T23:60:00Z",
            "2022-08-17T23:59:60Z", // leap second
        ] {
            assert_eq!(parse_utc(bad), None, "{bad:?}");
        }
        // Leap days that do exist.
        assert!(parse_utc("2000-02-29T00:00:00Z").is_some());
        assert!(parse_utc("2024-02-29T12:00:00Z").is_some());
    }
}
