//! Parsing of human-readable sizes (`4G`, `512M`) and durations (`2h`,
//! `30s`, `1h30m`) as they appear in policy files.

use std::time::Duration;

use thiserror::Error;

/// Error for a size or duration that could not be parsed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UnitError {
    /// The input was empty.
    #[error("empty value")]
    Empty,
    /// A number was missing or malformed.
    #[error("invalid number in `{0}`")]
    Number(String),
    /// The unit suffix was not recognised.
    #[error("unknown unit `{unit}` in `{input}`")]
    Unit {
        /// Full input.
        input: String,
        /// The unrecognised suffix.
        unit: String,
    },
    /// The value does not fit in the target type.
    #[error("value `{0}` is too large")]
    Overflow(String),
}

/// Parse a byte size. Accepts a bare integer (bytes) or an integer followed
/// by `K`, `M`, `G`, `T` (binary multiples), optionally with `B` or `iB`.
/// Case-insensitive, whitespace between number and unit allowed.
pub fn parse_size(input: &str) -> Result<u64, UnitError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(UnitError::Empty);
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| UnitError::Number(input.to_string()))?;
    let unit = unit.trim().to_ascii_lowercase();
    let mult: u64 = match unit.as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        other => {
            return Err(UnitError::Unit {
                input: input.to_string(),
                unit: other.to_string(),
            });
        }
    };
    n.checked_mul(mult)
        .ok_or_else(|| UnitError::Overflow(input.to_string()))
}

/// Parse a duration such as `90s`, `15m`, `2h`, `1d` or a combination like
/// `1h30m`. A bare integer means seconds.
pub fn parse_duration(input: &str) -> Result<Duration, UnitError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(UnitError::Empty);
    }
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }
    let mut total: u64 = 0;
    let mut rest = s;
    while !rest.is_empty() {
        let split = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        let (num, tail) = rest.split_at(split);
        if num.is_empty() {
            return Err(UnitError::Number(input.to_string()));
        }
        let n: u64 = num
            .parse()
            .map_err(|_| UnitError::Number(input.to_string()))?;
        let unit_end = tail
            .find(|c: char| c.is_ascii_digit())
            .unwrap_or(tail.len());
        let (unit, next) = tail.split_at(unit_end);
        let mult = match unit.trim() {
            "s" | "sec" | "secs" => 1,
            "m" | "min" | "mins" => 60,
            "h" | "hr" | "hrs" => 3600,
            "d" | "day" | "days" => 86_400,
            other => {
                return Err(UnitError::Unit {
                    input: input.to_string(),
                    unit: other.to_string(),
                });
            }
        };
        total = n
            .checked_mul(mult)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(|| UnitError::Overflow(input.to_string()))?;
        rest = next;
    }
    Ok(Duration::from_secs(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes() {
        assert_eq!(parse_size("4G"), Ok(4 << 30));
        assert_eq!(parse_size("512 MiB"), Ok(512 << 20));
        assert_eq!(parse_size("1024"), Ok(1024));
        assert_eq!(parse_size("2kb"), Ok(2048));
        assert!(matches!(parse_size("4X"), Err(UnitError::Unit { .. })));
        assert!(matches!(parse_size(""), Err(UnitError::Empty)));
        assert!(matches!(
            parse_size("99999999999T"),
            Err(UnitError::Overflow(_))
        ));
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_duration("2h"), Ok(Duration::from_hours(2)));
        assert_eq!(parse_duration("1h30m"), Ok(Duration::from_mins(90)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_hours(24)));
        assert!(matches!(parse_duration("1x"), Err(UnitError::Unit { .. })));
        assert!(matches!(parse_duration("h"), Err(UnitError::Number(_))));
    }

    proptest::proptest! {
        #[test]
        fn size_parser_never_panics(s in "\\PC{0,16}") {
            let _ = parse_size(&s);
        }

        #[test]
        fn duration_parser_never_panics(s in "\\PC{0,16}") {
            let _ = parse_duration(&s);
        }

        #[test]
        fn size_roundtrip_bytes(n in 0u64..u64::MAX) {
            proptest::prop_assert_eq!(parse_size(&n.to_string()), Ok(n));
        }
    }
}
