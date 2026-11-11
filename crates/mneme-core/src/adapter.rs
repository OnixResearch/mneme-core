//! Adapter capability declarations and checked projection.
//!
//! A projection target (logic engine, external reader, JSON consumer) declares
//! which Preserves kinds it can represent and, when relevant, its inclusive
//! integer range. Conversion is all-or-nothing: an unsupported kind or an
//! out-of-range integer fails explicitly and is never replaced with a string,
//! float, atom, or null.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A Preserves value kind as seen by an adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueKind {
    Boolean,
    Double,
    SignedInteger,
    String,
    ByteString,
    Symbol,
    Record,
    Sequence,
    Set,
    Dictionary,
    Embedded,
}

impl ValueKind {
    /// The adapter-facing kind name.
    pub const fn name(self) -> &'static str {
        match self {
            ValueKind::Boolean => "boolean",
            ValueKind::Double => "double",
            ValueKind::SignedInteger => "signed-integer",
            ValueKind::String => "string",
            ValueKind::ByteString => "bytestring",
            ValueKind::Symbol => "symbol",
            ValueKind::Record => "record",
            ValueKind::Sequence => "sequence",
            ValueKind::Set => "set",
            ValueKind::Dictionary => "dictionary",
            ValueKind::Embedded => "embedded",
        }
    }

    /// The kind of a value.
    pub fn of(value: &crate::value::Value) -> Self {
        match value {
            crate::value::Value::Boolean(_) => ValueKind::Boolean,
            crate::value::Value::Double(_) => ValueKind::Double,
            crate::value::Value::SignedInteger(_) => ValueKind::SignedInteger,
            crate::value::Value::String(_) => ValueKind::String,
            crate::value::Value::ByteString(_) => ValueKind::ByteString,
            crate::value::Value::Symbol(_) => ValueKind::Symbol,
            crate::value::Value::Record(_) => ValueKind::Record,
            crate::value::Value::Sequence(_) => ValueKind::Sequence,
            crate::value::Value::Set(_) => ValueKind::Set,
            crate::value::Value::Dictionary(_) => ValueKind::Dictionary,
            crate::value::Value::Embedded(_) => ValueKind::Embedded,
        }
    }
}

/// The value kinds and numeric range an adapter declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterCapabilities {
    kinds: std::collections::BTreeSet<ValueKind>,
    integer_min: Option<num_bigint::BigInt>,
    integer_max: Option<num_bigint::BigInt>,
}

impl AdapterCapabilities {
    /// Declare the supported kinds.
    pub fn new(kinds: impl IntoIterator<Item = ValueKind>) -> Self {
        AdapterCapabilities {
            kinds: kinds.into_iter().collect(),
            integer_min: None,
            integer_max: None,
        }
    }

    /// Declare an inclusive integer range.
    #[must_use]
    pub fn with_integer_range(mut self, min: num_bigint::BigInt, max: num_bigint::BigInt) -> Self {
        self.integer_min = Some(min);
        self.integer_max = Some(max);
        self
    }

    /// Whether a kind is supported.
    pub fn supports(&self, kind: ValueKind) -> bool {
        self.kinds.contains(&kind)
    }

    /// The declared inclusive integer range.
    pub fn integer_range(&self) -> Option<(&num_bigint::BigInt, &num_bigint::BigInt)> {
        match (&self.integer_min, &self.integer_max) {
            (Some(min), Some(max)) => Some((min, max)),
            _ => None,
        }
    }
}

/// Project a value into an adapter, refusing every unrepresentable part.
#[allow(unknown_lints, no_recursion)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn project_value(
    value: &crate::value::Value,
    capabilities: &AdapterCapabilities,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    let kind = ValueKind::of(value);
    if !capabilities.supports(kind) {
        return Err(crate::error::Diagnostic::new(
            crate::error::Stage::Adapter,
            crate::error::ErrorCode::AdapterUnsupportedKind,
            path.clone(),
            format!("adapter cannot represent a {}", kind.name()),
        ));
    }
    match value {
        crate::value::Value::SignedInteger(integer) => {
            if let Some((min, max)) = capabilities.integer_range() {
                let value = integer.as_bigint();
                if value < min || value > max {
                    return Err(crate::error::Diagnostic::new(
                        crate::error::Stage::Adapter,
                        crate::error::ErrorCode::AdapterIntegerOutOfRange,
                        path.clone(),
                        format!(
                            "integer {value} is outside the adapter range [{min}, {max}]; no lossy conversion is applied"
                        ),
                    ));
                }
            }
            Ok(value.clone())
        }
        crate::value::Value::Record(record) => {
            let label = project_value(record.label(), capabilities, &path.field("label"))?;
            let mut fields = Vec::with_capacity(record.fields().len());
            for (index, field) in record.fields().iter().enumerate() {
                fields.push(project_value(field, capabilities, &path.index(index))?);
            }
            Ok(crate::value::Value::record(label, fields))
        }
        crate::value::Value::Sequence(items) => {
            let mut projected = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                projected.push(project_value(item, capabilities, &path.index(index))?);
            }
            Ok(crate::value::Value::sequence(projected))
        }
        crate::value::Value::Set(items) => {
            let mut projected = std::collections::BTreeSet::new();
            for (index, item) in items.iter().enumerate() {
                projected.insert(project_value(item, capabilities, &path.index(index))?);
            }
            Ok(crate::value::Value::set(projected))
        }
        crate::value::Value::Dictionary(entries) => {
            let mut projected = Vec::with_capacity(entries.len());
            for (index, (key, item)) in entries.iter().enumerate() {
                projected.push((
                    project_value(key, capabilities, &path.index(index).field("key"))?,
                    project_value(item, capabilities, &path.index(index).field("value"))?,
                ));
            }
            Ok(crate::value::Value::dictionary(projected))
        }
        crate::value::Value::Embedded(inner) => Err(crate::error::Diagnostic::new(
            crate::error::Stage::Adapter,
            crate::error::ErrorCode::AdapterUnsupportedKind,
            path.clone(),
            format!(
                "adapter cannot represent a live embedded value ({})",
                inner.kind_name()
            ),
        )),
        other => Ok(other.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> AdapterCapabilities {
        AdapterCapabilities::new([
            ValueKind::Boolean,
            ValueKind::Double,
            ValueKind::SignedInteger,
            ValueKind::String,
            ValueKind::Symbol,
            ValueKind::Record,
            ValueKind::Sequence,
            ValueKind::Set,
            ValueKind::Dictionary,
        ])
    }

    #[test]
    fn large_integers_fail_explicitly_without_coercion() {
        let large = crate::value::Value::integer(
            "87112285931760246646623899502532662132736"
                .parse::<num_bigint::BigInt>()
                .expect("integer"),
        );
        let capabilities = full().with_integer_range(
            num_bigint::BigInt::from(i64::MIN),
            num_bigint::BigInt::from(i64::MAX),
        );
        let error =
            project_value(&large, &capabilities, &crate::error::Path::root()).expect_err("range");
        assert_eq!(
            error.code,
            crate::error::ErrorCode::AdapterIntegerOutOfRange
        );
        assert_eq!(error.path.to_string(), "$");
        // No fallback value is produced: the error carries no replacement.
        assert!(!error.message.contains("string"));
    }

    #[test]
    fn unsupported_kinds_fail_without_partial_output() {
        let capabilities =
            AdapterCapabilities::new([ValueKind::SignedInteger, ValueKind::Sequence]);
        let value = crate::value::Value::sequence(vec![
            crate::value::Value::integer(1_i64),
            crate::value::Value::bytes([1_u8]),
        ]);
        let error =
            project_value(&value, &capabilities, &crate::error::Path::root()).expect_err("bytes");
        assert_eq!(error.code, crate::error::ErrorCode::AdapterUnsupportedKind);
        assert_eq!(error.path.to_string(), "$[1]");
    }

    #[test]
    fn supported_values_project_with_their_kinds() {
        let capabilities =
            full().with_integer_range(num_bigint::BigInt::from(-10), num_bigint::BigInt::from(10));
        let value = crate::value::Value::record_named(
            "sample",
            vec![
                crate::value::Value::integer(10_i64),
                crate::value::Value::symbol("s"),
                crate::value::Value::string("s"),
                crate::value::Value::set([crate::value::Value::integer(1_i64)]),
            ],
        );
        assert_eq!(
            project_value(&value, &capabilities, &crate::error::Path::root()).expect("projected"),
            value
        );
    }
}
