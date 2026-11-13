//! Versioned, type-tagged JSON transport for crate::typed::Value values.
//!
//! Every supported value kind has an explicit tag. A symbol and a string with
//! equal text remain distinct, integers are decimal strings, doubles carry
//! their exact IEEE-754 bits, bytes use strict Base64, and dictionary keys may
//! be any encoded value. A versioned document envelope wraps the tagged value
//! so a decoder never guesses the format. Unsupported or malformed payloads
//! fail before any domain mutation.
//!
//! Decoding text is strict in three ways the JSON data model alone does not
//! give: a repeated object member is refused instead of letting the last
//! spelling win, nesting is bounded by [`crate::binary::MAX_DEPTH`] so both
//! codecs accept the same values, and integers are bounded by
//! [`MAX_INTEGER_DIGITS`] before any conversion runs.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// The tagged JSON document format name.
pub const TRANSPORT_FORMAT: &str = "mneme.preserves-tagged-json";
/// The tagged JSON document version.
pub const TRANSPORT_VERSION: u32 = 1;
/// Maximum decimal digits in a transport integer.
///
/// Derived from [`crate::binary::MAX_INTEGER_BYTES`]: the largest magnitude a
/// 4096-byte two's-complement integer can hold has 9864 decimal digits, so
/// this bound lets the transport read back every integer the binary codec
/// accepts. The digit count is checked before the text is converted, so
/// decoding an integer stays linear in the input size.
pub const MAX_INTEGER_DIGITS: usize = 9864;

/// JSON containers from the envelope down to the top-level value object.
const ENVELOPE_NESTING: usize = 2;
/// JSON containers each dictionary level adds: the entries array, the entry
/// object, and the nested value object.
const DICTIONARY_NESTING: usize = 3;
/// Maximum JSON container nesting in a transport document.
///
/// The deepest document that nests `crate::binary::MAX_DEPTH` values is a
/// chain of dictionaries. Keeping the bound below the 128-container recursion
/// limit of the JSON parser means an over-deep document is reported as a depth
/// limit rather than as malformed JSON.
const MAX_JSON_NESTING: usize = ENVELOPE_NESTING + DICTIONARY_NESTING * crate::binary::MAX_DEPTH;

const TAG: &str = "t";
const VALUE: &str = "v";

/// Wrap one encoded value in the versioned transport document.
pub fn encode_document(value: &crate::typed::Value) -> serde_json::Value {
    let mut document = serde_json::Map::new();
    document.insert(
        "format".to_owned(),
        serde_json::Value::String(TRANSPORT_FORMAT.to_owned()),
    );
    document.insert(
        "version".to_owned(),
        serde_json::Value::from(u64::from(TRANSPORT_VERSION)),
    );
    document.insert("value".to_owned(), encode_value(value));
    serde_json::Value::Object(document)
}

/// Render a transport document as compact JSON text.
pub fn encode_document_string(value: &crate::typed::Value) -> String {
    encode_document(value).to_string()
}

/// Decode a transport document from text.
///
/// A repeated object member is refused: the JSON data model collapses repeats
/// to the last spelling, which would let a reader that keeps the first one see
/// a different value, version or kind from the one Mneme validates.
pub fn decode_document(text: &str) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    decode_document_value(&parse_document_text(text)?)
}

/// Decode a transport document from an already parsed JSON value.
///
/// This entry point cannot see repeated members, because a parsed
/// [`serde_json::Value`] has already collapsed them. Use [`decode_document`]
/// for untrusted text.
pub fn decode_document_value(
    json: &serde_json::Value,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    let Some(document) = json.as_object() else {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidTaggedJson,
            crate::problem::Path::root(),
            "transport document must be a JSON object",
        ));
    };
    reject_extra(
        document,
        &["format", "version", "value"],
        &crate::problem::Path::root(),
    )?;
    let format = string_member(document, "format", &crate::problem::Path::root())?;
    if format != TRANSPORT_FORMAT {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidTaggedJson,
            crate::problem::Path::root().named("format"),
            format!("unsupported transport format {format:?}"),
        ));
    }
    let version = document
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Transport,
                crate::problem::ErrorCode::InvalidTaggedJson,
                crate::problem::Path::root().named("version"),
                "transport version must be a non-negative integer",
            )
        })?;
    if version != u64::from(TRANSPORT_VERSION) {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidTaggedJson,
            crate::problem::Path::root().named("version"),
            format!(
                "unsupported transport version {version}; this build reads version {TRANSPORT_VERSION}"
            ),
        ));
    }
    let value = document.get("value").ok_or_else(|| {
        crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidTaggedJson,
            crate::problem::Path::root().named("value"),
            "transport document is missing its value",
        )
    })?;
    decode_value(value, &crate::problem::Path::root().named("value"))
}

/// Encode one crate::typed::Value value with explicit type tags.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn encode_value(value: &crate::typed::Value) -> serde_json::Value {
    match value {
        crate::typed::Value::Boolean(boolean) => {
            tagged("bool", [("v", serde_json::Value::Bool(*boolean))])
        }
        crate::typed::Value::Double(double) => tagged(
            "double",
            [(
                "bits",
                serde_json::Value::String(format!("{:016x}", double.bits())),
            )],
        ),
        crate::typed::Value::SignedInteger(integer) => tagged(
            "int",
            [(
                "v",
                serde_json::Value::String(integer.as_bigint().to_string()),
            )],
        ),
        crate::typed::Value::String(text) => {
            tagged("string", [("v", serde_json::Value::String(text.clone()))])
        }
        crate::typed::Value::ByteString(bytes) => tagged(
            "bytes",
            [(
                "v",
                serde_json::Value::String(crate::base64::encode(bytes.as_slice())),
            )],
        ),
        crate::typed::Value::Symbol(symbol) => tagged(
            "symbol",
            [("v", serde_json::Value::String(symbol.as_str().to_owned()))],
        ),
        crate::typed::Value::Record(record) => encode_record(record),
        crate::typed::Value::Sequence(items) => encode_sequence(items),
        crate::typed::Value::Set(items) => encode_set(items),
        crate::typed::Value::Dictionary(entries) => encode_dictionary(entries),
        crate::typed::Value::Embedded(inner) => encode_embedded(inner),
    }
}

fn encode_record(record: &crate::typed::Record) -> serde_json::Value {
    tagged(
        "record",
        [
            ("label", encode_value(record.label())),
            (
                "fields",
                serde_json::Value::Array(record.fields().iter().map(encode_value).collect()),
            ),
        ],
    )
}

fn encode_sequence(items: &[crate::typed::Value]) -> serde_json::Value {
    tagged(
        "sequence",
        [(
            "items",
            serde_json::Value::Array(items.iter().map(encode_value).collect()),
        )],
    )
}

fn encode_set(items: &std::collections::BTreeSet<crate::typed::Value>) -> serde_json::Value {
    tagged(
        "set",
        [(
            "items",
            serde_json::Value::Array(items.iter().map(encode_value).collect()),
        )],
    )
}

fn encode_dictionary(
    entries: &std::collections::BTreeMap<crate::typed::Value, crate::typed::Value>,
) -> serde_json::Value {
    tagged(
        "dictionary",
        [(
            "entries",
            serde_json::Value::Array(
                entries
                    .iter()
                    .map(|(key, item)| {
                        tagged(
                            "entry",
                            [("key", encode_value(key)), ("value", encode_value(item))],
                        )
                    })
                    .collect(),
            ),
        )],
    )
}

fn encode_embedded(inner: &crate::typed::Value) -> serde_json::Value {
    tagged("embedded", [("value", encode_value(inner))])
}

fn tagged<const N: usize>(tag: &str, members: [(&str, serde_json::Value); N]) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    object.insert(TAG.to_owned(), serde_json::Value::String(tag.to_owned()));
    for (name, value) in members {
        object.insert(name.to_owned(), value);
    }
    serde_json::Value::Object(object)
}

/// Decode one tagged value. No coercion or fallback is applied.
pub fn decode_value(
    json: &serde_json::Value,
    path: &crate::problem::Path,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    decode_value_at(json, path, 0)
}

/// Decode one tagged value nested `depth` values deep.
///
/// `depth` is the number of compound values already open, so a compound value
/// here would sit at nesting level `depth + 1`; the bound is
/// [`crate::binary::MAX_DEPTH`], the same one the binary decoder applies.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
fn decode_value_at(
    json: &serde_json::Value,
    path: &crate::problem::Path,
    depth: usize,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    let object = json
        .as_object()
        .ok_or_else(|| invalid(path, "tagged value must be a JSON object"))?;
    let tag = string_member(object, TAG, path)?;
    match tag {
        "bool" => decode_boolean(object, path),
        "double" => decode_double(object, path),
        "int" => decode_integer(object, path),
        "string" => decode_string(object, path),
        "symbol" => decode_symbol(object, path),
        "bytes" => decode_bytes(object, path),
        "record" => {
            enter_value(path, depth)?;
            decode_record(object, path, depth)
        }
        "sequence" | "set" => {
            enter_value(path, depth)?;
            decode_collection(tag, object, path, depth)
        }
        "dictionary" => {
            enter_value(path, depth)?;
            decode_dictionary(object, path, depth)
        }
        "embedded" => {
            enter_value(path, depth)?;
            decode_embedded(object, path, depth)
        }
        other => Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::UnsupportedValueKind,
            path.clone(),
            format!("unsupported tagged value type {other:?}"),
        )),
    }
}

/// Refuse a compound value nested deeper than [`crate::binary::MAX_DEPTH`].
fn enter_value(
    path: &crate::problem::Path,
    depth: usize,
) -> Result<(), crate::problem::Diagnostic> {
    if depth >= crate::binary::MAX_DEPTH {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::DepthLimitExceeded,
            path.clone(),
            format!("value nesting exceeds {} levels", crate::binary::MAX_DEPTH),
        ));
    }
    Ok(())
}

fn decode_boolean(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    let is_boolean = object
        .get(VALUE)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| invalid(&path.named(VALUE), "bool value must be a JSON boolean"))?;
    Ok(crate::typed::Value::Boolean(is_boolean))
}

fn decode_double(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, "bits"], path)?;
    let bits = string_member(object, "bits", path)?;
    // One spelling per bit pattern: uppercase digits would make two documents
    // that render differently produce the same value and the same digest.
    if bits.len() != 16 || !mneme_kernel::text::is_lower_hex(bits.as_bytes()) {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidFloatBits,
            path.named("bits"),
            "double bits must be exactly 16 lowercase hexadecimal digits",
        ));
    }
    let bits = u64::from_str_radix(bits, 16).map_err(|_| {
        crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidFloatBits,
            path.named("bits"),
            "double bits are not valid hexadecimal",
        )
    })?;
    Ok(crate::typed::Value::Double(
        crate::typed::Double::from_bits(bits),
    ))
}

fn decode_integer(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    let text = string_member(object, VALUE, path)?;
    let digits = check_decimal_text(text).map_err(|message| {
        crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidIntegerText,
            path.named(VALUE),
            message,
        )
    })?;
    // The size bound is applied before the digits are converted, so a hostile
    // integer costs one linear spelling check and no conversion at all.
    if digits > MAX_INTEGER_DIGITS {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::LimitExceeded,
            path.named(VALUE),
            format!("integer of {digits} digit(s) exceeds the {MAX_INTEGER_DIGITS}-digit limit"),
        ));
    }
    let integer = text.parse::<num_bigint::BigInt>().map_err(|_| {
        crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidIntegerText,
            path.named(VALUE),
            "integer text is out of range",
        )
    })?;
    if !crate::binary::integer_within_byte_limit(&integer) {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::LimitExceeded,
            path.named(VALUE),
            format!(
                "integer exceeds the {}-byte two's-complement limit",
                crate::binary::MAX_INTEGER_BYTES
            ),
        ));
    }
    Ok(crate::typed::Value::SignedInteger(
        crate::typed::SignedInteger::new(integer),
    ))
}

fn decode_string(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    Ok(crate::typed::Value::String(
        string_member(object, VALUE, path)?.to_owned(),
    ))
}

fn decode_symbol(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    Ok(crate::typed::Value::Symbol(crate::typed::Symbol::new(
        string_member(object, VALUE, path)?.to_owned(),
    )))
}

fn decode_bytes(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    let text = string_member(object, VALUE, path)?;
    let bytes = crate::base64::decode(text).map_err(|message| {
        crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidBase64,
            path.named(VALUE),
            message,
        )
    })?;
    Ok(crate::typed::Value::ByteString(
        crate::typed::ByteString::new(bytes),
    ))
}

fn decode_record(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
    depth: usize,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, "label", "fields"], path)?;
    let label_json = object
        .get("label")
        .ok_or_else(|| invalid(&path.named("label"), "record is missing its label"))?;
    let label = decode_value_at(label_json, &path.named("label"), depth + 1)?;
    let fields_json = object
        .get("fields")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid(&path.named("fields"), "record fields must be an array"))?;
    let mut fields = Vec::with_capacity(fields_json.len());
    for (index, field) in fields_json.iter().enumerate() {
        fields.push(decode_value_at(
            field,
            &path.named("fields").index(index),
            depth + 1,
        )?);
    }
    Ok(crate::typed::Value::Record(crate::typed::Record::new(
        label, fields,
    )))
}

fn decode_collection(
    tag: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
    depth: usize,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, "items"], path)?;
    let items_json = object
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid(&path.named("items"), "items must be an array"))?;
    if tag == "sequence" {
        let mut items = Vec::with_capacity(items_json.len());
        for (index, item) in items_json.iter().enumerate() {
            items.push(decode_value_at(
                item,
                &path.named("items").index(index),
                depth + 1,
            )?);
        }
        Ok(crate::typed::Value::Sequence(items))
    } else {
        let mut items = std::collections::BTreeSet::new();
        for (index, item) in items_json.iter().enumerate() {
            let item = decode_value_at(item, &path.named("items").index(index), depth + 1)?;
            if !items.insert(item) {
                return Err(crate::problem::Diagnostic::new(
                    crate::problem::Stage::Transport,
                    crate::problem::ErrorCode::DuplicateSetElement,
                    path.named("items").index(index),
                    "set contains a duplicate element",
                ));
            }
        }
        Ok(crate::typed::Value::Set(items))
    }
}

fn decode_dictionary(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
    depth: usize,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, "entries"], path)?;
    let entries_json = object
        .get("entries")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid(&path.named("entries"), "entries must be an array"))?;
    let mut entries = std::collections::BTreeMap::new();
    for (index, entry) in entries_json.iter().enumerate() {
        let entry_path = path.named("entries").index(index);
        let entry_object = entry
            .as_object()
            .ok_or_else(|| invalid(&entry_path, "dictionary entry must be a JSON object"))?;
        reject_extra(entry_object, &["t", "key", "value"], &entry_path)?;
        if string_member(entry_object, TAG, &entry_path)? != "entry" {
            return Err(invalid(
                &entry_path,
                "dictionary entry tag must be \"entry\"",
            ));
        }
        let key_json = entry_object
            .get("key")
            .ok_or_else(|| invalid(&entry_path.named("key"), "entry is missing its key"))?;
        let value_json = entry_object
            .get("value")
            .ok_or_else(|| invalid(&entry_path.named("value"), "entry is missing its value"))?;
        let key = decode_value_at(key_json, &entry_path.named("key"), depth + 1)?;
        let value = decode_value_at(value_json, &entry_path.named("value"), depth + 1)?;
        if entries.insert(key, value).is_some() {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Transport,
                crate::problem::ErrorCode::DuplicateDictionaryKey,
                entry_path,
                "dictionary contains a duplicate key",
            ));
        }
    }
    Ok(crate::typed::Value::Dictionary(entries))
}

fn decode_embedded(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::problem::Path,
    depth: usize,
) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    reject_extra(object, &[TAG, "value"], path)?;
    let inner = object
        .get("value")
        .ok_or_else(|| invalid(&path.named("value"), "embedded value is missing"))?;
    Ok(crate::typed::Value::embedded(decode_value_at(
        inner,
        &path.named("value"),
        depth + 1,
    )?))
}

/// Validate the spelling of a decimal integer and report its digit count.
///
/// The count is what the size bound is applied to, so the conversion never
/// runs on text longer than [`MAX_INTEGER_DIGITS`].
fn check_decimal_text(text: &str) -> Result<usize, &'static str> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("integer must be an optional minus sign and decimal digits");
    }
    if digits.len() > 1 && digits.starts_with('0') {
        return Err("integer must not have leading zeros");
    }
    if text == "-0" {
        return Err("negative zero is not a canonical integer spelling");
    }
    Ok(digits.len())
}

/// Parse transport text into a JSON value, refusing repeated object members.
///
/// [`serde_json::Value`] collapses a repeated member to its last spelling, so
/// the tree is built here member by member while the repeats are still visible.
fn parse_document_text(text: &str) -> Result<serde_json::Value, crate::problem::Diagnostic> {
    check_json_nesting(text)?;
    let repeated = std::cell::RefCell::new(None);
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let parsed = serde::de::DeserializeSeed::deserialize(
        StrictJson {
            repeated: &repeated,
        },
        &mut deserializer,
    );
    let value = match parsed {
        Ok(value) => value,
        Err(error) => return Err(json_error(&repeated, &error)),
    };
    deserializer
        .end()
        .map_err(|error| json_error(&repeated, &error))?;
    Ok(value)
}

/// Reject text whose JSON container nesting exceeds [`MAX_JSON_NESTING`].
///
/// The scan is linear and runs before the parser, so an over-deep document is
/// reported as a depth limit instead of as the parser's own recursion error.
fn check_json_nesting(text: &str) -> Result<(), crate::problem::Diagnostic> {
    let mut depth: usize = 0;
    let mut is_in_string = false;
    let mut is_escaped = false;
    for byte in text.bytes() {
        if is_in_string {
            if is_escaped {
                is_escaped = false;
            } else if byte == b'\\' {
                is_escaped = true;
            } else if byte == b'"' {
                is_in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => is_in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_JSON_NESTING {
                    return Err(crate::problem::Diagnostic::new(
                        crate::problem::Stage::Transport,
                        crate::problem::ErrorCode::DepthLimitExceeded,
                        crate::problem::Path::root(),
                        format!(
                            "JSON nesting exceeds {MAX_JSON_NESTING} levels, the bound implied by {} nested values",
                            crate::binary::MAX_DEPTH
                        ),
                    ));
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

/// Build the diagnostic for a failed strict parse.
fn json_error(
    repeated: &std::cell::RefCell<Option<String>>,
    error: &serde_json::Error,
) -> crate::problem::Diagnostic {
    let repeated = repeated.borrow();
    match repeated.as_deref() {
        Some(name) => crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidTaggedJson,
            crate::problem::Path::root().named(name),
            format!("repeated JSON object member {name:?}"),
        ),
        None => crate::problem::Diagnostic::new(
            crate::problem::Stage::Transport,
            crate::problem::ErrorCode::InvalidTaggedJson,
            crate::problem::Path::root(),
            format!("invalid JSON: {error}"),
        ),
    }
}

/// Deserializes one JSON value while recording a repeated object member.
struct StrictJson<'a> {
    repeated: &'a std::cell::RefCell<Option<String>>,
}

impl<'de, 'a> serde::de::DeserializeSeed<'de> for StrictJson<'a> {
    type Value = serde_json::Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor {
            repeated: self.repeated,
        })
    }
}

/// Visitor that builds a [`serde_json::Value`] and refuses repeated members.
struct StrictJsonVisitor<'a> {
    repeated: &'a std::cell::RefCell<Option<String>>,
}

impl<'de, 'a> serde::de::Visitor<'de> for StrictJsonVisitor<'a> {
    type Value = serde_json::Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::from(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::from(value))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| E::custom("number is not representable in JSON"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::String(value))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(serde_json::Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let repeated = self.repeated;
        // A self-describing sequence reports how many elements remain, so the
        // buffer is reserved once instead of growing under the loop; a
        // non-self-describing one reports nothing and the loop grows it.
        let capacity = serde::de::SeqAccess::size_hint(&sequence).unwrap_or(0);
        let mut items = Vec::with_capacity(capacity);
        while let Some(item) = sequence.next_element_seed(StrictJson { repeated })? {
            items.push(item);
        }
        Ok(serde_json::Value::Array(items))
    }

    fn visit_map<A>(self, mut members: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let repeated = self.repeated;
        let mut object = serde_json::Map::new();
        while let Some(name) = members.next_key::<String>()? {
            if object.contains_key(&name) {
                *repeated.borrow_mut() = Some(name);
                return Err(<A::Error as serde::de::Error>::custom(
                    "repeated JSON object member",
                ));
            }
            let value = members.next_value_seed(StrictJson { repeated })?;
            object.insert(name, value);
        }
        Ok(serde_json::Value::Object(object))
    }
}

fn invalid(path: &crate::problem::Path, message: &'static str) -> crate::problem::Diagnostic {
    crate::problem::Diagnostic::new(
        crate::problem::Stage::Transport,
        crate::problem::ErrorCode::InvalidTaggedJson,
        path.clone(),
        message,
    )
}

fn string_member<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
    path: &crate::problem::Path,
) -> Result<&'a str, crate::problem::Diagnostic> {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Transport,
                crate::problem::ErrorCode::InvalidTaggedJson,
                path.named(name),
                format!("member {name:?} must be a string"),
            )
        })
}

fn reject_extra(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    path: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Transport,
                crate::problem::ErrorCode::InvalidTaggedJson,
                path.named(key.clone()),
                format!("unexpected member {key:?}"),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: crate::typed::Value) -> crate::typed::Value {
        let document = encode_document_string(&value);
        decode_document(&document).expect("roundtrip")
    }

    #[test]
    fn rich_values_survive_the_json_boundary() {
        let values = [
            crate::typed::Value::symbol("same-text"),
            crate::typed::Value::string("same-text"),
            crate::typed::Value::integer(
                "1234567890123456789012345678901234567890"
                    .parse::<num_bigint::BigInt>()
                    .expect("valid integer"),
            ),
            crate::typed::Value::double(-0.0),
            crate::typed::Value::double(f64::NAN),
            crate::typed::Value::double(1.202e300),
            crate::typed::Value::bytes([0_u8, 1, 2, 250, 255]),
            crate::typed::Value::record_named(
                "capture",
                vec![crate::typed::Value::sequence(vec![
                    crate::typed::Value::symbol("nested"),
                ])],
            ),
            crate::typed::Value::set([
                crate::typed::Value::integer(2_i64),
                crate::typed::Value::integer(1_i64),
            ]),
            crate::typed::Value::dictionary([
                (
                    crate::typed::Value::integer(1_i64),
                    crate::typed::Value::string("integer key"),
                ),
                (
                    crate::typed::Value::bytes([9_u8]),
                    crate::typed::Value::symbol("byte key"),
                ),
            ]),
            crate::typed::Value::embedded(crate::typed::Value::symbol("marker")),
            crate::typed::Value::Boolean(false),
        ];
        for value in values {
            assert_eq!(roundtrip(value.clone()), value);
        }
        // Symbols and strings with equal text remain distinguishable.
        assert_ne!(
            crate::typed::Value::symbol("x"),
            crate::typed::Value::string("x")
        );
        // Exact NaN payloads survive.
        let nan_bits = f64::NAN.to_bits();
        let decoded = roundtrip(crate::typed::Value::double(f64::from_bits(nan_bits)));
        assert_eq!(
            decoded.as_double().map(crate::typed::Double::bits),
            Some(nan_bits)
        );
    }

    #[test]
    fn document_envelope_is_versioned_and_strict() {
        let document = encode_document(&crate::typed::Value::integer(1_i64));
        assert_eq!(
            document.get("format").and_then(serde_json::Value::as_str),
            Some(TRANSPORT_FORMAT)
        );

        let wrong_format = serde_json::Value::Object(serde_json::Map::from_iter([
            (
                "format".to_owned(),
                serde_json::Value::String("other".to_owned()),
            ),
            ("version".to_owned(), serde_json::Value::from(1)),
            (
                "value".to_owned(),
                encode_value(&crate::typed::Value::Boolean(true)),
            ),
        ]));
        assert!(decode_document_value(&wrong_format).is_err());

        let wrong_version = serde_json::Value::Object(serde_json::Map::from_iter([
            (
                "format".to_owned(),
                serde_json::Value::String(TRANSPORT_FORMAT.to_owned()),
            ),
            ("version".to_owned(), serde_json::Value::from(2)),
            (
                "value".to_owned(),
                encode_value(&crate::typed::Value::Boolean(true)),
            ),
        ]));
        assert_eq!(
            decode_document_value(&wrong_version)
                .expect_err("version")
                .code,
            crate::problem::ErrorCode::InvalidTaggedJson
        );

        assert!(decode_document("not json").is_err());
    }

    #[test]
    fn malformed_values_fail_before_domain_use() {
        for (json, code) in [
            (
                serde_json::json!({"t": "mystery"}),
                crate::problem::ErrorCode::UnsupportedValueKind,
            ),
            (
                serde_json::json!({"t": "string"}),
                crate::problem::ErrorCode::InvalidTaggedJson,
            ),
            (
                serde_json::json!({"t": "int", "v": "+1"}),
                crate::problem::ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "int", "v": "01"}),
                crate::problem::ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "int", "v": "-0"}),
                crate::problem::ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "double", "bits": "zz"}),
                crate::problem::ErrorCode::InvalidFloatBits,
            ),
            (
                serde_json::json!({"t": "bytes", "v": "!!!"}),
                crate::problem::ErrorCode::InvalidBase64,
            ),
            (
                serde_json::json!({"t": "set", "items": [
                    {"t": "int", "v": "1"},
                    {"t": "int", "v": "1"}
                ]}),
                crate::problem::ErrorCode::DuplicateSetElement,
            ),
            (
                serde_json::json!({"t": "dictionary", "entries": [
                    {"t": "entry", "key": {"t": "string", "v": "k"}, "value": {"t": "int", "v": "1"}},
                    {"t": "entry", "key": {"t": "string", "v": "k"}, "value": {"t": "int", "v": "2"}}
                ]}),
                crate::problem::ErrorCode::DuplicateDictionaryKey,
            ),
            (
                serde_json::json!({"t": "bool", "v": true, "extra": 1}),
                crate::problem::ErrorCode::InvalidTaggedJson,
            ),
        ] {
            let error =
                decode_value(&json, &crate::problem::Path::root()).expect_err("must reject");
            assert_eq!(error.code, code, "{json}");
        }
    }

    #[test]
    fn user_data_cannot_impersonate_codec_control_members() {
        // A user dictionary is itself a tagged value; its members are data.
        let value = crate::typed::Value::dictionary([(
            crate::typed::Value::symbol("t"),
            crate::typed::Value::string("string"),
        )]);
        let encoded = encode_value(&value);
        assert_eq!(
            encoded.get("t").and_then(serde_json::Value::as_str),
            Some("dictionary")
        );
        assert_eq!(
            decode_value(&encoded, &crate::problem::Path::root()).expect("decode"),
            value
        );
    }
}
