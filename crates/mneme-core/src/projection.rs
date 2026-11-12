//! Adapter capability declarations and checked projection.
//!
//! A projection target (logic engine, external reader, JSON consumer) declares
//! which Preserves kinds it can represent and, when relevant, its inclusive
//! integer range. Conversion is all-or-nothing: an unsupported kind or an
//! out-of-range integer fails explicitly and is never replaced with a string,
//! float, atom, or null.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

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
    pub fn of(value: &crate::typed::Value) -> Self {
        match value {
            crate::typed::Value::Boolean(_) => ValueKind::Boolean,
            crate::typed::Value::Double(_) => ValueKind::Double,
            crate::typed::Value::SignedInteger(_) => ValueKind::SignedInteger,
            crate::typed::Value::String(_) => ValueKind::String,
            crate::typed::Value::ByteString(_) => ValueKind::ByteString,
            crate::typed::Value::Symbol(_) => ValueKind::Symbol,
            crate::typed::Value::Record(_) => ValueKind::Record,
            crate::typed::Value::Sequence(_) => ValueKind::Sequence,
            crate::typed::Value::Set(_) => ValueKind::Set,
            crate::typed::Value::Dictionary(_) => ValueKind::Dictionary,
            crate::typed::Value::Embedded(_) => ValueKind::Embedded,
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
enum ProjectTask<'a> {
    Visit(&'a crate::typed::Value, crate::problem::Path),
    Build(BuildKind, usize, crate::problem::Path),
}

enum BuildKind {
    Record,
    Sequence,
    Set,
    Dictionary,
}

/// Project a value into an adapter, refusing every unrepresentable part.
pub fn project_value(
    value: &crate::typed::Value,
    capabilities: &AdapterCapabilities,
    path: &crate::problem::Path,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    let mut tasks = vec![ProjectTask::Visit(value, path.clone())];
    let mut output = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            ProjectTask::Visit(value, path) => {
                visit_value(value, capabilities, path, &mut tasks, &mut output)?;
            }
            ProjectTask::Build(kind, count, path) => {
                let projected = build_value(kind, count, &path, &mut output)?;
                output.reserve(1);
                output.push(projected);
            }
        }
    }
    output
        .pop()
        .ok_or_else(|| adapter_error(crate::problem::Path::root(), "empty projection"))
}

fn visit_integer(
    integer: &num_bigint::BigInt,
    capabilities: &AdapterCapabilities,
    path: crate::problem::Path,
    output: &mut Vec<crate::typed::Value>,
) -> Result<(), crate::problem::Diagnostic> {
    if let Some((min, max)) = capabilities.integer_range() {
        let value = integer;
        if value < min || value > max {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Adapter,
                crate::problem::ErrorCode::AdapterIntegerOutOfRange,
                path,
                format!(
                    "integer {value} is outside the adapter range [{min}, {max}]; no lossy conversion is applied"
                ),
            ));
        }
    }
    output.push(crate::typed::Value::SignedInteger(
        crate::typed::SignedInteger::new(integer.clone()),
    ));
    Ok(())
}

fn visit_value<'a>(
    value: &'a crate::typed::Value,
    capabilities: &AdapterCapabilities,
    path: crate::problem::Path,
    tasks: &mut Vec<ProjectTask<'a>>,
    output: &mut Vec<crate::typed::Value>,
) -> Result<(), crate::problem::Diagnostic> {
    let kind = ValueKind::of(value);
    if !capabilities.supports(kind) {
        return Err(adapter_error(
            path,
            format!("adapter cannot represent a {}", kind.name()),
        ));
    }
    match value {
        crate::typed::Value::SignedInteger(integer) => {
            visit_integer(integer.as_bigint(), capabilities, path, output)?
        }
        crate::typed::Value::Record(record) => {
            tasks.push(ProjectTask::Build(
                BuildKind::Record,
                record.fields().len(),
                path.clone(),
            ));
            for (index, field) in record.fields().iter().enumerate().rev() {
                tasks.push(ProjectTask::Visit(field, path.index(index)));
            }
            tasks.push(ProjectTask::Visit(record.label(), path.field("label")));
        }
        crate::typed::Value::Sequence(items) => {
            tasks.push(ProjectTask::Build(
                BuildKind::Sequence,
                items.len(),
                path.clone(),
            ));
            for (index, item) in items.iter().enumerate().rev() {
                tasks.push(ProjectTask::Visit(item, path.index(index)));
            }
        }
        crate::typed::Value::Set(items) => {
            tasks.push(ProjectTask::Build(
                BuildKind::Set,
                items.len(),
                path.clone(),
            ));
            for (index, item) in items.iter().enumerate().rev() {
                tasks.push(ProjectTask::Visit(item, path.index(index)));
            }
        }
        crate::typed::Value::Dictionary(entries) => {
            tasks.push(ProjectTask::Build(
                BuildKind::Dictionary,
                entries.len(),
                path.clone(),
            ));
            for (index, (key, item)) in entries.iter().enumerate().rev() {
                tasks.push(ProjectTask::Visit(item, path.index(index).field("value")));
                tasks.push(ProjectTask::Visit(key, path.index(index).field("key")));
            }
        }
        crate::typed::Value::Embedded(inner) => {
            return Err(adapter_error(
                path,
                format!(
                    "adapter cannot represent a live embedded value ({})",
                    inner.kind_name()
                ),
            ));
        }
        other => output.push(other.clone()),
    }
    Ok(())
}

fn build_value(
    kind: BuildKind,
    count: usize,
    path: &crate::problem::Path,
    output: &mut Vec<crate::typed::Value>,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    let pop = |output: &mut Vec<crate::typed::Value>| {
        output
            .pop()
            .ok_or_else(|| adapter_error(path.clone(), "projection stack underflow"))
    };
    match kind {
        BuildKind::Record => {
            let mut fields = Vec::with_capacity(count);
            for _ in 0..count {
                fields.push(pop(output)?);
            }
            fields.reverse();
            let label = pop(output)?;
            Ok(crate::typed::Value::record(label, fields))
        }
        BuildKind::Sequence => {
            let mut items = Vec::with_capacity(count);
            for _ in 0..count {
                items.push(pop(output)?);
            }
            items.reverse();
            Ok(crate::typed::Value::sequence(items))
        }
        BuildKind::Set => {
            let mut items = std::collections::BTreeSet::new();
            for _ in 0..count {
                items.insert(pop(output)?);
            }
            Ok(crate::typed::Value::set(items))
        }
        BuildKind::Dictionary => {
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let value = pop(output)?;
                let key = pop(output)?;
                entries.push((key, value));
            }
            entries.reverse();
            Ok(crate::typed::Value::dictionary(entries))
        }
    }
}

fn adapter_error(
    path: crate::problem::Path,
    message: impl Into<String>,
) -> crate::problem::Diagnostic {
    crate::problem::Diagnostic::new(
        crate::problem::Stage::Adapter,
        crate::problem::ErrorCode::AdapterUnsupportedKind,
        path,
        message.into(),
    )
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
        let large = crate::typed::Value::integer(
            "87112285931760246646623899502532662132736"
                .parse::<num_bigint::BigInt>()
                .expect("integer"),
        );
        let capabilities = full().with_integer_range(
            num_bigint::BigInt::from(i64::MIN),
            num_bigint::BigInt::from(i64::MAX),
        );
        let error =
            project_value(&large, &capabilities, &crate::problem::Path::root()).expect_err("range");
        assert_eq!(
            error.code,
            crate::problem::ErrorCode::AdapterIntegerOutOfRange
        );
        assert_eq!(error.path.to_string(), "$");
        // No fallback value is produced: the error carries no replacement.
        assert!(!error.message.contains("string"));
    }

    #[test]
    fn unsupported_kinds_fail_without_partial_output() {
        let capabilities =
            AdapterCapabilities::new([ValueKind::SignedInteger, ValueKind::Sequence]);
        let value = crate::typed::Value::sequence(vec![
            crate::typed::Value::integer(1_i64),
            crate::typed::Value::bytes([1_u8]),
        ]);
        let error =
            project_value(&value, &capabilities, &crate::problem::Path::root()).expect_err("bytes");
        assert_eq!(
            error.code,
            crate::problem::ErrorCode::AdapterUnsupportedKind
        );
        assert_eq!(error.path.to_string(), "$[1]");
    }

    #[test]
    fn supported_values_project_with_their_kinds() {
        let capabilities =
            full().with_integer_range(num_bigint::BigInt::from(-10), num_bigint::BigInt::from(10));
        let value = crate::typed::Value::record_named(
            "sample",
            vec![
                crate::typed::Value::integer(10_i64),
                crate::typed::Value::symbol("s"),
                crate::typed::Value::string("s"),
                crate::typed::Value::set([crate::typed::Value::integer(1_i64)]),
            ],
        );
        assert_eq!(
            project_value(&value, &capabilities, &crate::problem::Path::root()).expect("projected"),
            value
        );
    }
}
