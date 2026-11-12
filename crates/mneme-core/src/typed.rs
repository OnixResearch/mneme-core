//! The Preserves value model used by every Mneme record and codec.
//!
//! Values follow the Preserves data model: booleans, doubles, arbitrary
//! precision signed integers, strings, byte strings, symbols, records,
//! sequences, sets, dictionaries, and embedded values. Sets and dictionaries
//! are stored sorted by the Preserves total order, which makes equality,
//! iteration, and duplicate detection deterministic.
//!
//! Annotations are not part of the value model. Mneme's decoding profile skips
//! them before building a value, and its encoder never emits them; no
//! authoritative field may depend on annotation content.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

use num_traits::{ToPrimitive, Zero};

/// A Preserves symbol: a sequence of Unicode scalar values denoting an
/// identifier. Distinguishable from a [`Value::String`] with equal text.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Symbol(String);

impl Symbol {
    /// Construct a symbol.
    pub fn new(text: impl Into<String>) -> Self {
        Symbol(text.into())
    }

    /// The symbol text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convert into a value.
    pub fn into_value(self) -> Value {
        Value::Symbol(self)
    }
}

impl From<&str> for Symbol {
    fn from(text: &str) -> Self {
        Symbol(text.to_owned())
    }
}

impl From<String> for Symbol {
    fn from(text: String) -> Self {
        Symbol(text)
    }
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        crate::text::write_symbol(formatter, &self.0)
    }
}

/// A Preserves byte string. Distinct from a text string with the same bytes.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteString(Vec<u8>);

impl ByteString {
    /// Construct a byte string.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        ByteString(bytes.into())
    }

    /// The bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Convert into a value.
    pub fn into_value(self) -> Value {
        Value::ByteString(self)
    }
}

/// A Preserves arbitrarily large signed integer.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SignedInteger(num_bigint::BigInt);

impl SignedInteger {
    /// Construct from a big integer.
    pub fn new(value: num_bigint::BigInt) -> Self {
        SignedInteger(value)
    }

    /// The underlying big integer.
    pub fn as_bigint(&self) -> &num_bigint::BigInt {
        &self.0
    }

    /// Convert with an explicit `i64` range check.
    pub fn to_i64(&self) -> Option<i64> {
        self.0.to_i64()
    }

    /// Whether this integer is zero.
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
}

impl From<i64> for SignedInteger {
    fn from(value: i64) -> Self {
        SignedInteger(num_bigint::BigInt::from(value))
    }
}

impl From<i32> for SignedInteger {
    fn from(value: i32) -> Self {
        SignedInteger(num_bigint::BigInt::from(value))
    }
}

impl From<u64> for SignedInteger {
    fn from(value: u64) -> Self {
        SignedInteger(num_bigint::BigInt::from(value))
    }
}

impl std::fmt::Display for SignedInteger {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// A Preserves double, compared by the IEEE 754 `totalOrder` predicate.
///
/// Equality and ordering use [`f64::total_cmp`], so every bit pattern has one
/// stable position and negative zero differs from positive zero.
#[derive(Clone, Copy)]
pub struct Double(f64);

impl Double {
    /// Construct a double.
    pub fn new(value: f64) -> Self {
        Double(value)
    }

    /// The raw IEEE-754 value.
    pub fn value(self) -> f64 {
        self.0
    }

    /// The exact 64-bit representation.
    pub fn bits(self) -> u64 {
        self.0.to_bits()
    }

    /// Reconstruct from an exact 64-bit representation.
    pub fn from_bits(bits: u64) -> Self {
        Double(f64::from_bits(bits))
    }
}

impl From<f64> for Double {
    fn from(value: f64) -> Self {
        Double(value)
    }
}

impl PartialEq for Double {
    fn eq(&self, other: &Self) -> bool {
        self.0.total_cmp(&other.0) == std::cmp::Ordering::Equal
    }
}

impl Eq for Double {}

impl PartialOrd for Double {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Double {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

impl std::fmt::Debug for Double {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Double({:016x})", self.bits())
    }
}

/// A labelled Preserves record. Fields are positional.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Record {
    label: Box<Value>,
    fields: Vec<Value>,
}

impl Record {
    /// Construct a record.
    pub fn new(label: Value, fields: Vec<Value>) -> Self {
        Record {
            label: Box::new(label),
            fields,
        }
    }

    /// The record label.
    pub fn label(&self) -> &Value {
        &self.label
    }

    /// The ordered record fields.
    pub fn fields(&self) -> &[Value] {
        &self.fields
    }
}

/// A Preserves value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Boolean(bool),
    Double(Double),
    SignedInteger(SignedInteger),
    String(String),
    ByteString(ByteString),
    Symbol(Symbol),
    Record(Record),
    Sequence(Vec<Value>),
    Set(std::collections::BTreeSet<Value>),
    Dictionary(std::collections::BTreeMap<Value, Value>),
    /// An embedded value marks a live, domain-specific object. Mneme decodes
    /// and transports this marker, but refuses it in durable records.
    Embedded(Box<Value>),
}

impl Value {
    /// Preserves kind rank used by the total order.
    fn rank(&self) -> u8 {
        match self {
            Value::Boolean(_) => 0,
            Value::Double(_) => 1,
            Value::SignedInteger(_) => 2,
            Value::String(_) => 3,
            Value::ByteString(_) => 4,
            Value::Symbol(_) => 5,
            Value::Record(_) => 6,
            Value::Sequence(_) => 7,
            Value::Set(_) => 8,
            Value::Dictionary(_) => 9,
            Value::Embedded(_) => 10,
        }
    }

    // The rank comparison establishes that both operands have the same kind,
    // so the wildcard arm is unreachable in a well-formed model. It keeps the
    // implementation total without panicking.
    fn cmp_same_kind(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (Value::Boolean(left), Value::Boolean(right)) => left.cmp(right),
            (Value::Double(left), Value::Double(right)) => left.cmp(right),
            (Value::SignedInteger(left), Value::SignedInteger(right)) => left.cmp(right),
            (Value::String(left), Value::String(right)) => left.cmp(right),
            (Value::ByteString(left), Value::ByteString(right)) => left.cmp(right),
            (Value::Symbol(left), Value::Symbol(right)) => left.cmp(right),
            (Value::Record(left), Value::Record(right)) => left.cmp(right),
            (Value::Sequence(left), Value::Sequence(right)) => seq_cmp(left, right),
            (Value::Set(left), Value::Set(right)) => iter_cmp(left.iter(), right.iter()),
            (Value::Dictionary(left), Value::Dictionary(right)) => dict_cmp(left, right),
            (Value::Embedded(left), Value::Embedded(right)) => left.cmp(right),
            _ => std::cmp::Ordering::Equal,
        }
    }

    /// A canonical Preserves symbol value.
    pub fn symbol(text: impl Into<String>) -> Self {
        Value::Symbol(Symbol::new(text))
    }

    /// A Preserves text string value.
    pub fn string(text: impl Into<String>) -> Self {
        Value::String(text.into())
    }

    /// A Preserves byte string value.
    pub fn bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Value::ByteString(ByteString::new(bytes))
    }

    /// A Preserves arbitrary-precision integer value.
    pub fn integer(value: impl Into<num_bigint::BigInt>) -> Self {
        Value::SignedInteger(SignedInteger::new(value.into()))
    }

    /// A Preserves double value.
    pub fn double(value: f64) -> Self {
        Value::Double(Double::new(value))
    }

    /// A Preserves record value.
    pub fn record(label: Value, fields: Vec<Value>) -> Self {
        Value::Record(Record::new(label, fields))
    }

    /// A record with a symbol label.
    pub fn record_named(label: impl Into<String>, fields: Vec<Value>) -> Self {
        Value::record(Value::symbol(label), fields)
    }

    /// A Preserves sequence value.
    pub fn sequence(items: Vec<Value>) -> Self {
        Value::Sequence(items)
    }

    /// A Preserves set value. Duplicate elements collapse.
    pub fn set(items: impl IntoIterator<Item = Value>) -> Self {
        Value::Set(items.into_iter().collect())
    }

    /// A Preserves dictionary value. Later duplicate keys replace earlier ones.
    pub fn dictionary(entries: impl IntoIterator<Item = (Value, Value)>) -> Self {
        Value::Dictionary(entries.into_iter().collect())
    }

    /// A dictionary with symbol keys.
    pub fn symbol_dictionary(entries: impl IntoIterator<Item = (Symbol, Value)>) -> Self {
        Value::dictionary(
            entries
                .into_iter()
                .map(|(key, value)| (Value::Symbol(key), value)),
        )
    }

    /// An embedded value marker.
    pub fn embedded(inner: Value) -> Self {
        Value::Embedded(Box::new(inner))
    }

    /// Human-readable Preserves text syntax, for diagnostics only.
    pub fn to_text(&self) -> String {
        crate::text::render(self)
    }

    /// Access a record, if this is one.
    pub fn as_record(&self) -> Option<&Record> {
        let Value::Record(record) = self else {
            return None;
        };
        Some(record)
    }

    /// Access a sequence, if this is one.
    pub fn as_sequence(&self) -> Option<&[Value]> {
        let Value::Sequence(items) = self else {
            return None;
        };
        Some(items)
    }

    /// Access a set, if this is one.
    pub fn as_set(&self) -> Option<&std::collections::BTreeSet<Value>> {
        let Value::Set(items) = self else {
            return None;
        };
        Some(items)
    }

    /// Access a dictionary, if this is one.
    pub fn as_dictionary(&self) -> Option<&std::collections::BTreeMap<Value, Value>> {
        let Value::Dictionary(entries) = self else {
            return None;
        };
        Some(entries)
    }

    /// Access a symbol, if this is one.
    pub fn as_symbol(&self) -> Option<&Symbol> {
        let Value::Symbol(symbol) = self else {
            return None;
        };
        Some(symbol)
    }

    /// Access a string, if this is one.
    pub fn as_string(&self) -> Option<&str> {
        let Value::String(text) = self else {
            return None;
        };
        Some(text)
    }

    /// Access bytes, if this is a byte string.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        let Value::ByteString(bytes) = self else {
            return None;
        };
        Some(bytes.as_slice())
    }

    /// Access an integer, if this is one.
    pub fn as_integer(&self) -> Option<&SignedInteger> {
        let Value::SignedInteger(integer) = self else {
            return None;
        };
        Some(integer)
    }

    /// Access a boolean, if this is one.
    pub fn as_boolean(&self) -> Option<bool> {
        let Value::Boolean(boolean) = self else {
            return None;
        };
        Some(*boolean)
    }

    /// Access a double, if this is one.
    pub fn as_double(&self) -> Option<Double> {
        let Value::Double(double) = self else {
            return None;
        };
        Some(*double)
    }

    /// The Preserves kind name, for diagnostics.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Value::Boolean(_) => "boolean",
            Value::Double(_) => "double",
            Value::SignedInteger(_) => "signed-integer",
            Value::String(_) => "string",
            Value::ByteString(_) => "bytestring",
            Value::Symbol(_) => "symbol",
            Value::Record(_) => "record",
            Value::Sequence(_) => "sequence",
            Value::Set(_) => "set",
            Value::Dictionary(_) => "dictionary",
            Value::Embedded(_) => "embedded",
        }
    }

    /// Whether this value, or any nested value, is an embedded marker.
    pub fn contains_embedded(&self) -> bool {
        let mut pending = vec![self];
        while let Some(value) = pending.pop() {
            match value {
                Value::Embedded(_) => return true,
                Value::Record(record) => {
                    for field in record.fields.iter().rev() {
                        pending.push(field);
                    }
                    pending.push(&record.label);
                }
                Value::Sequence(items) => {
                    for item in items.iter().rev() {
                        pending.push(item);
                    }
                }
                Value::Set(items) => {
                    for item in items.iter().rev() {
                        pending.push(item);
                    }
                }
                Value::Dictionary(entries) => {
                    for (key, value) in entries.iter().rev() {
                        pending.push(value);
                        pending.push(key);
                    }
                }
                Value::Boolean(_)
                | Value::Double(_)
                | Value::SignedInteger(_)
                | Value::Symbol(_)
                | Value::String(_)
                | Value::ByteString(_) => {}
            }
        }
        false
    }
}

impl Ord for Value {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let rank_order = self.rank().cmp(&other.rank());
        if rank_order != std::cmp::Ordering::Equal {
            return rank_order;
        }
        self.cmp_same_kind(other)
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn seq_cmp(left: &[Value], right: &[Value]) -> std::cmp::Ordering {
    iter_cmp(left.iter(), right.iter())
}

fn iter_cmp<'a, L, R>(left: L, right: R) -> std::cmp::Ordering
where
    L: Iterator<Item = &'a Value>,
    R: Iterator<Item = &'a Value>,
{
    let mut left = left;
    let mut right = right;
    loop {
        match (left.next(), right.next()) {
            (Some(left_value), Some(right_value)) => {
                let order = left_value.cmp(right_value);
                if order != std::cmp::Ordering::Equal {
                    return order;
                }
            }
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

fn dict_cmp(
    left: &std::collections::BTreeMap<Value, Value>,
    right: &std::collections::BTreeMap<Value, Value>,
) -> std::cmp::Ordering {
    let mut left = left.iter();
    let mut right = right.iter();
    loop {
        match (left.next(), right.next()) {
            (Some((left_key, left_value)), Some((right_key, right_value))) => {
                let order = left_key
                    .cmp(right_key)
                    .then_with(|| left_value.cmp(right_value));
                if order != std::cmp::Ordering::Equal {
                    return order;
                }
            }
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_kind_order_matches_specification() {
        let ordered = [
            Value::Boolean(false),
            Value::double(3.0),
            Value::integer(3_i64),
            Value::string("3"),
            Value::symbol("3"),
            Value::sequence(vec![]),
            Value::embedded(Value::Boolean(true)),
        ];
        for window in ordered.windows(2) {
            assert!(window[0] < window[1], "{:?} < {:?}", window[0], window[1]);
        }
    }

    #[test]
    fn sets_compare_by_sorted_elements() {
        let left = Value::set([Value::integer(2_i64), Value::integer(1_i64)]);
        let right = Value::set([Value::integer(1_i64), Value::integer(2_i64)]);
        assert_eq!(left, right);
    }

    #[test]
    fn dictionaries_compare_by_sorted_pairs() {
        let left = Value::dictionary([
            (Value::symbol("b"), Value::integer(2_i64)),
            (Value::symbol("a"), Value::integer(1_i64)),
        ]);
        let right = Value::dictionary([
            (Value::symbol("a"), Value::integer(1_i64)),
            (Value::symbol("b"), Value::integer(2_i64)),
        ]);
        assert_eq!(left, right);
        assert_eq!(
            left.as_dictionary().map(std::collections::BTreeMap::len),
            Some(2)
        );
    }

    #[test]
    fn negative_zero_differs_from_positive_zero() {
        assert_ne!(Value::double(0.0), Value::double(-0.0));
        assert!(Value::double(-0.0) < Value::double(0.0));
    }

    #[test]
    fn symbols_and_strings_with_equal_text_differ() {
        assert_ne!(Value::symbol("alpha"), Value::string("alpha"));
    }

    #[test]
    fn large_integers_are_arbitrary_precision() {
        let decimal = "87112285931760246646623899502532662132736";
        let parsed = decimal
            .parse::<num_bigint::BigInt>()
            .expect("valid decimal integer");
        let value = Value::integer(parsed);
        assert_eq!(
            value.as_integer().map(ToString::to_string),
            Some(decimal.to_owned())
        );
        assert_eq!(value.as_integer().and_then(SignedInteger::to_i64), None);
    }

    #[test]
    fn sequences_with_a_shared_prefix_have_distinct_lengths() {
        let short = Value::sequence(vec![Value::integer(1_i64)]);
        let long = Value::sequence(vec![Value::integer(1_i64), Value::integer(2_i64)]);
        assert!(short < long);
        assert_ne!(short, long);
    }
}
