//! Explicit valid and recorded time.
//!
//! Valid time describes when a claim applies in the modeled world. Recorded
//! time describes when the workspace accepted a revision and is ordered by the
//! coordinator's monotonic revision sequence, never by wall-clock comparison
//! alone. Unknown validity, an open lower bound, an open upper bound, and an
//! always-valid claim are distinct states; unknown validity is not the epoch.

use num_traits::ToPrimitive;

/// A UTC instant with nanosecond precision, stored as nanoseconds since the
/// Unix epoch. The `i64` range covers 1677-09-21 through 2262-04-11.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// Construct from nanoseconds since the Unix epoch.
    pub const fn from_nanos(nanos: i64) -> Self {
        Timestamp(nanos)
    }

    /// Nanoseconds since the Unix epoch.
    pub const fn nanos(self) -> i64 {
        self.0
    }

    /// The implementation's representable range.
    pub fn min() -> Self {
        Timestamp(i64::MIN)
    }

    /// The implementation's representable range.
    pub fn max() -> Self {
        Timestamp(i64::MAX)
    }

    /// Parse a strict RFC 3339 timestamp with a `Z` or numeric offset.
    pub fn parse(text: &str) -> Result<Self, &'static str> {
        let bytes = text.as_bytes();
        if bytes.len() < 20 {
            return Err("timestamp must be at least YYYY-MM-DDTHH:MM:SSZ");
        }
        let year = digits(bytes, 0, 4)?;
        expect(bytes, 4, b'-')?;
        let month = digits(bytes, 5, 2)?;
        expect(bytes, 7, b'-')?;
        let day = digits(bytes, 8, 2)?;
        expect(bytes, 10, b'T')?;
        let hour = digits(bytes, 11, 2)?;
        expect(bytes, 13, b':')?;
        let minute = digits(bytes, 14, 2)?;
        expect(bytes, 16, b':')?;
        let second = digits(bytes, 17, 2)?;

        let mut position = 19;
        let mut nanoseconds = 0_i64;
        if bytes.get(position) == Some(&b'.') {
            position += 1;
            let start = position;
            while position < bytes.len() && bytes[position].is_ascii_digit() {
                position += 1;
            }
            let count = position - start;
            if count == 0 || count > 9 {
                return Err("fractional seconds must contain 1 to 9 digits");
            }
            let fraction = digits(bytes, start, count)?;
            let exponent = u32::try_from(count)
                .map_err(|_| "fractional seconds must contain 1 to 9 digits")?;
            nanoseconds = i64::from(fraction) * 10_i64.pow(9 - exponent);
        }
        if position >= bytes.len() {
            return Err("timestamp is missing its offset");
        }
        let offset_seconds = match bytes[position] {
            b'Z' | b'z' => {
                position += 1;
                0_i64
            }
            sign @ (b'+' | b'-') => {
                position += 1;
                let offset_hour = digits(bytes, position, 2)?;
                position += 2;
                expect(bytes, position, b':')?;
                position += 1;
                let offset_minute = digits(bytes, position, 2)?;
                position += 2;
                if offset_hour > 23 || offset_minute > 59 {
                    return Err("offset is out of range");
                }
                let magnitude = i64::from(offset_hour) * 3600 + i64::from(offset_minute) * 60;
                if sign == b'-' { -magnitude } else { magnitude }
            }
            _ => return Err("timestamp offset must be Z or ±HH:MM"),
        };
        if position != bytes.len() {
            return Err("unexpected characters after the timestamp offset");
        }

        if !(1..=12).contains(&month) {
            return Err("month is out of range");
        }
        if day < 1 || day > days_in_month(year, month) {
            return Err("day is out of range");
        }
        if hour > 23 || minute > 59 || second > 59 {
            return Err("time of day is out of range");
        }

        let days = days_from_civil(year, month, day);
        let seconds = days
            .checked_mul(86_400)
            .and_then(|value| {
                value.checked_add(
                    i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second),
                )
            })
            .and_then(|value| value.checked_sub(offset_seconds))
            .ok_or("timestamp is outside the supported range")?;
        let total = seconds
            .checked_mul(1_000_000_000)
            .and_then(|value| value.checked_add(nanoseconds))
            .ok_or("timestamp is outside the supported range")?;
        Ok(Timestamp(total))
    }

    /// Render as RFC 3339 UTC with a `Z` suffix. Fractions are emitted only
    /// when non-zero, without trailing zeros.
    pub fn to_rfc3339(self) -> String {
        let nanoseconds_per_second = 1_000_000_000_i64;
        let seconds = self.0.div_euclid(nanoseconds_per_second);
        let nanos = self.0.rem_euclid(nanoseconds_per_second);
        let days = seconds.div_euclid(86_400);
        let seconds_of_day = seconds.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);
        let hour = seconds_of_day / 3600;
        let minute = (seconds_of_day % 3600) / 60;
        let second = seconds_of_day % 60;
        let mut output = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
        if nanos != 0 {
            let mut fraction = format!("{nanos:09}");
            while fraction.ends_with('0') {
                fraction.pop();
            }
            output.push('.');
            output.push_str(&fraction);
        }
        output.push('Z');
        output
    }

    /// The typed Preserves instant record `<instant nanos>`.
    pub fn to_value(self) -> crate::value::Value {
        crate::value::Value::record_named("instant", vec![crate::value::Value::integer(self.0)])
    }

    /// Decode `<instant nanos>`.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let Some(record) = value.as_record() else {
            return Err(type_error(path, "expected <instant nanoseconds>"));
        };
        if record.label() != &crate::value::Value::symbol("instant") || record.fields().len() != 1 {
            return Err(type_error(path, "expected <instant nanoseconds>"));
        }
        let Some(integer) = record.fields()[0].as_integer() else {
            return Err(type_error(
                path,
                "instant must carry an integer nanosecond count",
            ));
        };
        let Some(nanos) = integer.to_i64() else {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::InvalidTimestamp,
                path.clone(),
                "instant is outside the supported nanosecond range",
            ));
        };
        Ok(Timestamp(nanos))
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.to_rfc3339())
    }
}

fn type_error(path: &crate::error::Path, message: &'static str) -> crate::error::Diagnostic {
    crate::error::Diagnostic::new(
        crate::error::Stage::Domain,
        crate::error::ErrorCode::TypeMismatch,
        path.clone(),
        message,
    )
}

fn digits(bytes: &[u8], start: usize, count: usize) -> Result<u32, &'static str> {
    let end = start
        .checked_add(count)
        .ok_or("timestamp field overflows")?;
    let slice = bytes.get(start..end).ok_or("timestamp is truncated")?;
    let mut value = 0_u32;
    for byte in slice {
        if !byte.is_ascii_digit() {
            return Err("timestamp field contains a non-digit");
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Ok(value)
}

fn expect(bytes: &[u8], position: usize, expected: u8) -> Result<(), &'static str> {
    match bytes.get(position) {
        Some(byte) if *byte == expected => Ok(()),
        _ => Err("timestamp has an unexpected separator"),
    }
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

// Howard Hinnant's civil calendar algorithms, valid for the whole i64 range
// used here.
fn days_from_civil(year: u32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = (i64::from(month) + 9) % 12;
    let day_of_year = (153 * month_prime + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[allow(unknown_lints, unchecked_narrowing)] // month/day are bounded by calendar arithmetic
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    (year + i64::from(month <= 2), month as u32, day as u32)
}

/// Valid time for a claim or observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValidTime {
    /// The applicable period is not known.
    Unknown,
    /// An explicit interval. `None` means that bound is open.
    Bounded {
        start: Option<Timestamp>,
        end: Option<Timestamp>,
    },
}

impl ValidTime {
    /// An explicitly always-valid claim (both bounds open).
    pub fn always() -> Self {
        ValidTime::Bounded {
            start: None,
            end: None,
        }
    }

    /// Valid at exactly one instant.
    pub fn instant(at: Timestamp) -> Self {
        ValidTime::Bounded {
            start: Some(at),
            end: Some(at),
        }
    }

    /// Valid from an instant onwards.
    pub fn since(start: Timestamp) -> Self {
        ValidTime::Bounded {
            start: Some(start),
            end: None,
        }
    }

    /// Valid up to and including an instant.
    pub fn until(end: Timestamp) -> Self {
        ValidTime::Bounded {
            start: None,
            end: Some(end),
        }
    }

    /// An inclusive interval; the end must not precede the start.
    pub fn between(start: Timestamp, end: Timestamp) -> Result<Self, &'static str> {
        if end < start {
            return Err("valid-time end precedes its start");
        }
        Ok(ValidTime::Bounded {
            start: Some(start),
            end: Some(end),
        })
    }

    /// Validate an interval constructed through a decoder.
    pub fn validate(&self, path: &crate::error::Path) -> Result<(), crate::error::Diagnostic> {
        if let ValidTime::Bounded {
            start: Some(start),
            end: Some(end),
        } = self
            && end < start
        {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::InvalidInterval,
                path.clone(),
                "valid-time end precedes its start",
            ));
        }
        Ok(())
    }

    /// Encode as `<valid-time …>`.
    pub fn to_value(self) -> crate::value::Value {
        match self {
            ValidTime::Unknown => crate::value::Value::record_named(
                "valid-time",
                vec![crate::value::Value::symbol("unknown")],
            ),
            ValidTime::Bounded { start, end } => {
                let bound = |value: Option<Timestamp>| match value {
                    Some(timestamp) => timestamp.to_value(),
                    None => crate::value::Value::symbol("open"),
                };
                crate::value::Value::record_named("valid-time", vec![bound(start), bound(end)])
            }
        }
    }

    /// Decode `<valid-time unknown>` or `<valid-time start end>`.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let Some(record) = value.as_record() else {
            return Err(type_error(
                path,
                "expected <valid-time unknown> or <valid-time start end>",
            ));
        };
        if record.label() != &crate::value::Value::symbol("valid-time") {
            return Err(type_error(
                path,
                "expected <valid-time unknown> or <valid-time start end>",
            ));
        }
        match record.fields() {
            [only] if only.as_symbol().map(|symbol| symbol.as_str()) == Some("unknown") => {
                Ok(ValidTime::Unknown)
            }
            [start, end] => {
                let decode_bound = |value: &crate::value::Value| -> Result<Option<Timestamp>, crate::error::Diagnostic> {
                    if value.as_symbol().map(|symbol| symbol.as_str()) == Some("open") {
                        return Ok(None);
                    }
                    Timestamp::from_value(value, path).map(Some)
                };
                let start = decode_bound(start)?;
                let end = decode_bound(end)?;
                Ok(ValidTime::Bounded { start, end })
            }
            _ => Err(type_error(
                path,
                "expected <valid-time unknown> or <valid-time start end>",
            )),
        }
    }
}

/// Recorded transaction time plus the coordinator's revision order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordedTime {
    at: Timestamp,
    revision_order: u64,
}

impl RecordedTime {
    /// Construct an explicitly supplied recorded time.
    pub fn new(at: Timestamp, revision_order: u64) -> Self {
        RecordedTime { at, revision_order }
    }

    /// Wall-clock instant assigned by the coordinator.
    pub fn at(self) -> Timestamp {
        self.at
    }

    /// Monotonic revision order assigned by the coordinator.
    pub fn revision_order(self) -> u64 {
        self.revision_order
    }

    /// Encode as `<recorded-time <instant …> order>`.
    pub fn to_value(self) -> crate::value::Value {
        crate::value::Value::record_named(
            "recorded-time",
            vec![
                self.at.to_value(),
                crate::value::Value::integer(num_bigint::BigInt::from(self.revision_order)),
            ],
        )
    }

    /// Decode `<recorded-time <instant …> order>`.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let Some(record) = value.as_record() else {
            return Err(type_error(path, "expected <recorded-time instant order>"));
        };
        if record.label() != &crate::value::Value::symbol("recorded-time")
            || record.fields().len() != 2
        {
            return Err(type_error(path, "expected <recorded-time instant order>"));
        }
        let at = Timestamp::from_value(&record.fields()[0], path)?;
        let order = record.fields()[1]
            .as_integer()
            .and_then(|integer| integer.as_bigint().to_u64());
        let Some(order) = order else {
            return Err(type_error(
                path,
                "recorded-time order must be a non-negative u64",
            ));
        };
        Ok(RecordedTime {
            at,
            revision_order: order,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_rfc3339() {
        let epoch = Timestamp::parse("1970-01-01T00:00:00Z").expect("epoch");
        assert_eq!(epoch.nanos(), 0);
        assert_eq!(epoch.to_rfc3339(), "1970-01-01T00:00:00Z");

        let millis = Timestamp::parse("2026-11-10T00:00:00.500Z").expect("fraction");
        assert_eq!(millis.to_rfc3339(), "2026-11-10T00:00:00.5Z");

        let offset = Timestamp::parse("2026-11-10T01:00:00+01:00").expect("offset");
        assert_eq!(
            offset,
            Timestamp::parse("2026-11-10T00:00:00Z").expect("zulu")
        );

        let before_epoch = Timestamp::parse("1969-12-31T23:59:59.5Z").expect("negative");
        assert_eq!(before_epoch.nanos(), -500_000_000);
        assert_eq!(before_epoch.to_rfc3339(), "1969-12-31T23:59:59.5Z");
    }

    #[test]
    fn handles_leap_days_and_rejects_invalid_dates() {
        assert!(Timestamp::parse("2024-02-29T00:00:00Z").is_ok());
        assert!(Timestamp::parse("2023-02-29T00:00:00Z").is_err());
        assert!(Timestamp::parse("2024-13-01T00:00:00Z").is_err());
        assert!(Timestamp::parse("2024-01-01T24:00:00Z").is_err());
        assert!(Timestamp::parse("2024-01-01T00:00:00").is_err());
        assert!(Timestamp::parse("2024-01-01T00:00:00+24:00").is_err());
    }

    #[test]
    fn valid_time_states_remain_distinct() {
        let instant = Timestamp::from_nanos(1_000);
        let unknown = ValidTime::Unknown;
        let always = ValidTime::always();
        let open_end = ValidTime::since(instant);
        let open_start = ValidTime::until(instant);
        let closed = ValidTime::between(instant, instant).expect("valid interval");
        for (left, right) in [
            (unknown, always),
            (always, open_end),
            (open_end, open_start),
            (open_start, closed),
            (closed, unknown),
        ] {
            assert_ne!(left, right);
            assert_eq!(
                ValidTime::from_value(&left.to_value(), &crate::error::Path::root())
                    .expect("decode"),
                left
            );
        }
    }

    #[test]
    fn invalid_interval_is_rejected_at_its_field_path() {
        let start = Timestamp::from_nanos(2_000);
        let end = Timestamp::from_nanos(1_000);
        let value =
            crate::value::Value::record_named("valid-time", vec![start.to_value(), end.to_value()]);
        let decoded =
            ValidTime::from_value(&value, &crate::error::Path::root()).expect("structurally valid");
        let error = decoded
            .validate(
                &crate::error::Path::root()
                    .field("payload")
                    .field("valid-time"),
            )
            .expect_err("end precedes start");
        assert_eq!(error.code, crate::error::ErrorCode::InvalidInterval);
        assert_eq!(error.path.to_string(), "$.payload.valid-time");
    }

    #[test]
    fn recorded_time_keeps_wall_clock_and_order_separate() {
        let recorded = RecordedTime::new(Timestamp::from_nanos(5), 17);
        let decoded = RecordedTime::from_value(&recorded.to_value(), &crate::error::Path::root())
            .expect("decode");
        assert_eq!(decoded, recorded);
        assert_eq!(decoded.revision_order(), 17);
        assert_eq!(decoded.at().nanos(), 5);
    }
}
