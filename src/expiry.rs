//! Key expiration date parsing and validation.
//!
//! Supports absolute dates (`2026-12-31`) and relative durations
//! (`5y`, `12m`, `30d`) computed from the current time.

use anyhow::Result;

/// Default expiration: 5 years from now.
pub const DEFAULT_EXPIRATION: &str = "5y";

/// Parse an expiration string into an ISO 8601 UTC datetime.
///
/// Accepts:
/// - Relative: `<N>y` (years), `<N>m` (months), `<N>d` (days)
/// - Absolute: `YYYY-MM-DD` (assumes end of day UTC)
pub fn parse_expiration(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if let Some(ts) = parse_relative(trimmed) {
        return Ok(ts);
    }
    if let Some(ts) = parse_absolute_date(trimmed) {
        return Ok(ts);
    }
    anyhow::bail!(
        "invalid expiration format: {}. Use <N>y, <N>m, <N>d, or YYYY-MM-DD",
        input
    )
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn secs_to_iso8601(secs: u64) -> String {
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let remaining = remaining % 3600;
    let minutes = remaining / 60;
    let seconds = remaining % 60;
    let (year, month, day) = days_to_date(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn days_to_date(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let (m, y) = if mp < 10 {
        (mp + 3, y)
    } else {
        (mp - 9, y + 1)
    };
    (y, m, d)
}

fn parse_relative(input: &str) -> Option<String> {
    let (num_str, unit) = input.split_at(input.len().saturating_sub(1));
    let n: u64 = num_str.parse().ok()?;
    let now = now_secs();
    let secs = match unit {
        "y" => now.checked_add(n.checked_mul(365 * 86400)?)?,
        "m" => {
            let days = n.checked_mul(30)?;
            now.checked_add(days.checked_mul(86400)?)?
        }
        "d" => now.checked_add(n.checked_mul(86400)?)?,
        _ => return None,
    };
    Some(secs_to_iso8601(secs))
}

fn parse_absolute_date(input: &str) -> Option<String> {
    let parts: Vec<&str> = input.splitn(3, '-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: u64 = parts[0].parse().ok()?;
    let month: u64 = parts[1].parse().ok()?;
    let day: u64 = parts[2].parse().ok()?;
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let days = date_to_days(year, month, day);
    let secs = days * 86400 + 86399;
    Some(secs_to_iso8601(secs))
}

fn date_to_days(year: u64, month: u64, day: u64) -> u64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = if month <= 2 { month + 12 } else { month };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m - 3) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Check whether an ISO 8601 expiration timestamp is in the past.
pub fn is_expired(expiration_date: &str) -> bool {
    let now = now_secs();
    let exp_secs = iso8601_to_secs(expiration_date);
    match exp_secs {
        Some(secs) => now > secs,
        None => false,
    }
}

fn iso8601_to_secs(s: &str) -> Option<u64> {
    let s = s.trim_end_matches('Z');
    let mut parts = s.splitn(2, 'T');
    let date_part = parts.next()?;
    let time_part = parts.next().unwrap_or("00:00:00");
    let date_parts: Vec<&str> = date_part.splitn(3, '-').collect();
    if date_parts.len() != 3 {
        return None;
    }
    let year: u64 = date_parts[0].parse().ok()?;
    let month: u64 = date_parts[1].parse().ok()?;
    let day: u64 = date_parts[2].parse().ok()?;
    let time_parts: Vec<&str> = time_part.splitn(3, ':').collect();
    let hour: u64 = time_parts.first().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minute: u64 = time_parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let second: u64 = time_parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
    let days = date_to_days(year, month, day);
    Some(days * 86400 + hour * 3600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_years() {
        let result = parse_expiration("1y").unwrap();
        let secs = iso8601_to_secs(&result).unwrap();
        let now = now_secs();
        assert!(secs > now);
        let diff = secs - now;
        assert!(diff > 364 * 86400 && diff < 366 * 86400);
    }

    #[test]
    fn test_parse_days() {
        let result = parse_expiration("30d").unwrap();
        let secs = iso8601_to_secs(&result).unwrap();
        let now = now_secs();
        assert!(secs > now);
        let diff = secs - now;
        assert!(diff > 29 * 86400 && diff < 31 * 86400);
    }

    #[test]
    fn test_parse_months() {
        let result = parse_expiration("6m").unwrap();
        let secs = iso8601_to_secs(&result).unwrap();
        let now = now_secs();
        assert!(secs > now);
    }

    #[test]
    fn test_parse_absolute_date() {
        let result = parse_expiration("2099-12-31").unwrap();
        assert!(result.starts_with("2099-12-31"));
        let secs = iso8601_to_secs(&result).unwrap();
        assert!(secs > 4_000_000_000);
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_expiration("garbage").is_err());
        assert!(parse_expiration("").is_err());
    }

    #[test]
    fn test_default_is_valid() {
        let result = parse_expiration(DEFAULT_EXPIRATION).unwrap();
        let secs = iso8601_to_secs(&result).unwrap();
        let now = now_secs();
        assert!(secs > now);
        let diff = secs - now;
        assert!(diff > 4 * 365 * 86400 && diff < 6 * 365 * 86400);
    }

    #[test]
    fn test_is_expired_future() {
        let result = parse_expiration("100y").unwrap();
        assert!(!is_expired(&result));
    }

    #[test]
    fn test_is_expired_past() {
        assert!(is_expired("2020-01-01T00:00:00Z"));
    }

    #[test]
    fn test_default_is_not_expired() {
        let result = parse_expiration(DEFAULT_EXPIRATION).unwrap();
        assert!(!is_expired(&result));
    }

    #[test]
    fn test_parse_secs_roundtrip() {
        let result = parse_expiration("5y").unwrap();
        let secs = iso8601_to_secs(&result).unwrap();
        let reencoded = secs_to_iso8601(secs);
        assert_eq!(result, reencoded);
    }

    #[test]
    fn test_parse_absolute_edge() {
        let result = parse_expiration("1970-01-01").unwrap();
        assert!(result.starts_with("1970-01-01"));
    }
}
