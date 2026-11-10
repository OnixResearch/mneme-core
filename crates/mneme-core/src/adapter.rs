//! Adapter capability declarations and checked projection.
//!
//! A projection target (logic engine, external reader, JSON consumer) declares
//! which Preserves kinds it can represent and, when relevant, its inclusive
//! integer range. Conversion is all-or-nothing: an unsupported kind or an
//! out-of-range integer fails explicitly and is never replaced with a string,
//! float, atom, or null.

use std::collections::BTreeSet;

use num_bigint::BigInt;

use crate::error::{Diagnostic, ErrorCode, Path, Stage};
use crate::value::Value;

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
    pub fn of(value: &Value) -> Self {
        match value {
            Value::Boolean(_) => ValueKind::Boolean,
            Value::Double(_) => ValueKind::Double,
            Value::SignedInteger(_) => ValueKind::SignedInteger,
            Value::String(_) => ValueKind::String,
            Value::ByteString(_) => ValueKind::ByteString,
            Value::Symbol(_) => ValueKind::Symbol,
            Value::Record(_) => ValueKind::Record,
            Value::Sequence(_) => ValueKind::Sequence,
            Value::Set(_) => ValueKind::Set,
            Value::Dictionary(_) => ValueKind::Dictionary,
            Value::Embedded(_) => ValueKind::Embedded,
        }
    }
}

/// The value kinds and numeric range an adapter declares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterCapabilities {
    kinds: BTreeSet<ValueKind>,
    integer_min: Option<BigInt>,
    integer_max: Option<BigInt>,
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
    pub fn with_integer_range(mut self, min: BigInt, max: BigInt) -> Self {
        self.integer_min = Some(min);
        self.integer_max = Some(max);
        self
    }

    /// Whether a kind is supported.
    pub fn supports(&self, kind: ValueKind) -> bool {
        self.kinds.contains(&kind)
    }

    /// The declared inclusive integer range.
    pub fn integer_range(&self) -> Option<(&BigInt, &BigInt)> {
        match (&self.integer_min, &self.integer_max) {
            (Some(min), Some(max)) => Some((min, max)),
            _ => None,
        }
    }
}

/// Project a value into an adapter, refusing every unrepresentable part.
pub fn project_value(
    value: &Value,
    capabilities: &AdapterCapabilities,
    path: &Path,
) -> Result<Value, Diagnostic> {
    let kind = ValueKind::of(value);
    if !capabilities.supports(kind) {
        return Err(Diagnostic::new(
            Stage::Adapter,
            ErrorCode::AdapterUnsupportedKind,
            path.clone(),
            format!("adapter cannot represent a {}", kind.name()),
        ));
    }
    match value {
        Value::SignedInteger(integer) => {
            if let Some((min, max)) = capabilities.integer_range() {
                let value = integer.as_bigint();
                if value < min || value > max {
                    return Err(Diagnostic::new(
                        Stage::Adapter,
                        ErrorCode::AdapterIntegerOutOfRange,
                        path.clone(),
                        format!(
                            "integer {value} is outside the adapter range [{min}, {max}]; no lossy conversion is applied"
                        ),
                    ));
                }
            }
            Ok(value.clone())
        }
        Value::Record(record) => {
            let label = project_value(record.label(), capabilities, &path.field("label"))?;
            let mut fields = Vec::with_capacity(record.fields().len());
            for (index, field) in record.fields().iter().enumerate() {
                fields.push(project_value(field, capabilities, &path.index(index))?);
            }
            Ok(Value::record(label, fields))
        }
        Value::Sequence(items) => {
            let mut projected = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                projected.push(project_value(item, capabilities, &path.index(index))?);
            }
            Ok(Value::sequence(projected))
        }
        Value::Set(items) => {
            let mut projected = BTreeSet::new();
            for (index, item) in items.iter().enumerate() {
                projected.insert(project_value(item, capabilities, &path.index(index))?);
            }
            Ok(Value::set(projected))
        }
        Value::Dictionary(entries) => {
            let mut projected = Vec::with_capacity(entries.len());
            for (index, (key, item)) in entries.iter().enumerate() {
                projected.push((
                    project_value(key, capabilities, &path.index(index).field("key"))?,
                    project_value(item, capabilities, &path.index(index).field("value"))?,
                ));
            }
            Ok(Value::dictionary(projected))
        }
        Value::Embedded(inner) => Err(Diagnostic::new(
            Stage::Adapter,
            ErrorCode::AdapterUnsupportedKind,
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
        let large = Value::integer(
            "87112285931760246646623899502532662132736"
                .parse::<BigInt>()
                .expect("integer"),
        );
        let capabilities =
            full().with_integer_range(BigInt::from(i64::MIN), BigInt::from(i64::MAX));
        let error = project_value(&large, &capabilities, &Path::root()).expect_err("range");
        assert_eq!(error.code, ErrorCode::AdapterIntegerOutOfRange);
        assert_eq!(error.path.to_string(), "$");
        // No fallback value is produced: the error carries no replacement.
        assert!(!error.message.contains("string"));
    }

    #[test]
    fn unsupported_kinds_fail_without_partial_output() {
        let capabilities =
            AdapterCapabilities::new([ValueKind::SignedInteger, ValueKind::Sequence]);
        let value = Value::sequence(vec![Value::integer(1_i64), Value::bytes([1_u8])]);
        let error = project_value(&value, &capabilities, &Path::root()).expect_err("bytes");
        assert_eq!(error.code, ErrorCode::AdapterUnsupportedKind);
        assert_eq!(error.path.to_string(), "$[1]");
    }

    #[test]
    fn supported_values_project_with_their_kinds() {
        let capabilities = full().with_integer_range(BigInt::from(-10), BigInt::from(10));
        let value = Value::record_named(
            "sample",
            vec![
                Value::integer(10_i64),
                Value::symbol("s"),
                Value::string("s"),
                Value::set([Value::integer(1_i64)]),
            ],
        );
        assert_eq!(
            project_value(&value, &capabilities, &Path::root()).expect("projected"),
            value
        );
    }
}
