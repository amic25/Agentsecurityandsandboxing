//! RFC 3339 timestamps without a date-time dependency.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn now_rfc3339() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format_rfc3339(d.as_secs(), d.subsec_millis())
}

/// Format a Unix timestamp. Uses the civil-from-days algorithm by Howard
/// Hinnant, valid for all dates in the i64 range we care about.
pub fn format_rfc3339(secs: u64, millis: u32) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// A compact, sortable session id: `YYYYMMDDTHHMMSS-<pid>`.
pub fn session_id(pid: u32) -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts = format_rfc3339(d.as_secs(), 0);
    let compact: String = ts
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T')
        .take(15)
        .collect();
    format!("{compact}-{pid}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_dates() {
        assert_eq!(format_rfc3339(0, 0), "1970-01-01T00:00:00.000Z");
        assert_eq!(format_rfc3339(951_782_400, 5), "2000-02-29T00:00:00.005Z");
        assert_eq!(format_rfc3339(1_761_264_000, 0), "2025-10-24T00:00:00.000Z");
        assert_eq!(
            format_rfc3339(4_102_444_799, 999),
            "2099-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn session_id_shape() {
        let id = session_id(42);
        assert!(id.ends_with("-42"));
        assert_eq!(id.len(), 15 + 3);
    }
}
