//! Versioned, type-tagged JSON transport for crate::value::Value values.
//!
//! Every supported value kind has an explicit tag. A symbol and a string with
//! equal text remain distinct, integers are decimal strings of arbitrary
//! precision, doubles carry their exact IEEE-754 bits, bytes use strict Base64,
//! and dictionary keys may be any encoded value. A versioned document envelope
//! wraps the tagged value so a decoder never guesses the format. Unsupported or
//! malformed payloads fail before any domain mutation.
#![allow(path_segment_repetition, no_recursion)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// The tagged JSON document format name.
pub const TRANSPORT_FORMAT: &str = "mneme.preserves-tagged-json";
/// The tagged JSON document version.
pub const TRANSPORT_VERSION: u32 = 1;

const TAG: &str = "t";
const VALUE: &str = "v";

/// Wrap one encoded value in the versioned transport document.
pub fn encode_document(value: &crate::value::Value) -> serde_json::Value {
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
pub fn encode_document_string(value: &crate::value::Value) -> String {
    encode_document(value).to_string()
}

/// Decode a transport document from text.
pub fn decode_document(text: &str) -> Result<crate::value::Value, crate::error::Diagnostic> {
    let json: serde_json::Value = serde_json::from_str(text).map_err(|error| {
        crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidTaggedJson,
            crate::error::Path::root(),
            format!("invalid JSON: {error}"),
        )
    })?;
    decode_document_value(&json)
}

/// Decode a transport document from an already parsed JSON value.
pub fn decode_document_value(
    json: &serde_json::Value,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    let Some(document) = json.as_object() else {
        return Err(crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidTaggedJson,
            crate::error::Path::root(),
            "transport document must be a JSON object",
        ));
    };
    reject_extra(
        document,
        &["format", "version", "value"],
        &crate::error::Path::root(),
    )?;
    let format = string_member(document, "format", &crate::error::Path::root())?;
    if format != TRANSPORT_FORMAT {
        return Err(crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidTaggedJson,
            crate::error::Path::root().named("format"),
            format!("unsupported transport format {format:?}"),
        ));
    }
    let version = document
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            crate::error::Diagnostic::new(
                crate::error::Stage::Transport,
                crate::error::ErrorCode::InvalidTaggedJson,
                crate::error::Path::root().named("version"),
                "transport version must be a non-negative integer",
            )
        })?;
    if version != u64::from(TRANSPORT_VERSION) {
        return Err(crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidTaggedJson,
            crate::error::Path::root().named("version"),
            format!(
                "unsupported transport version {version}; this build reads version {TRANSPORT_VERSION}"
            ),
        ));
    }
    let value = document.get("value").ok_or_else(|| {
        crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidTaggedJson,
            crate::error::Path::root().named("value"),
            "transport document is missing its value",
        )
    })?;
    decode_value(value, &crate::error::Path::root().named("value"))
}

/// Encode one crate::value::Value value with explicit type tags.
#[allow(unknown_lints, no_recursion)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn encode_value(value: &crate::value::Value) -> serde_json::Value {
    match value {
        crate::value::Value::Boolean(boolean) => {
            tagged("bool", [("v", serde_json::Value::Bool(*boolean))])
        }
        crate::value::Value::Double(double) => tagged(
            "double",
            [(
                "bits",
                serde_json::Value::String(format!("{:016x}", double.bits())),
            )],
        ),
        crate::value::Value::SignedInteger(integer) => tagged(
            "int",
            [(
                "v",
                serde_json::Value::String(integer.as_bigint().to_string()),
            )],
        ),
        crate::value::Value::String(text) => {
            tagged("string", [("v", serde_json::Value::String(text.clone()))])
        }
        crate::value::Value::ByteString(bytes) => tagged(
            "bytes",
            [(
                "v",
                serde_json::Value::String(crate::base64::encode(bytes.as_slice())),
            )],
        ),
        crate::value::Value::Symbol(symbol) => tagged(
            "symbol",
            [("v", serde_json::Value::String(symbol.as_str().to_owned()))],
        ),
        crate::value::Value::Record(record) => encode_record(record),
        crate::value::Value::Sequence(items) => encode_sequence(items),
        crate::value::Value::Set(items) => encode_set(items),
        crate::value::Value::Dictionary(entries) => encode_dictionary(entries),
        crate::value::Value::Embedded(inner) => encode_embedded(inner),
    }
}

fn encode_record(record: &crate::value::Record) -> serde_json::Value {
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

fn encode_sequence(items: &[crate::value::Value]) -> serde_json::Value {
    tagged(
        "sequence",
        [(
            "items",
            serde_json::Value::Array(items.iter().map(encode_value).collect()),
        )],
    )
}

fn encode_set(items: &std::collections::BTreeSet<crate::value::Value>) -> serde_json::Value {
    tagged(
        "set",
        [(
            "items",
            serde_json::Value::Array(items.iter().map(encode_value).collect()),
        )],
    )
}

fn encode_dictionary(
    entries: &std::collections::BTreeMap<crate::value::Value, crate::value::Value>,
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

fn encode_embedded(inner: &crate::value::Value) -> serde_json::Value {
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
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn decode_value(
    json: &serde_json::Value,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
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
        "record" => decode_record(object, path),
        "sequence" | "set" => decode_collection(tag, object, path),
        "dictionary" => decode_dictionary(object, path),
        "embedded" => decode_embedded(object, path),
        other => Err(crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::UnsupportedValueKind,
            path.clone(),
            format!("unsupported tagged value type {other:?}"),
        )),
    }
}

fn decode_boolean(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    let is_boolean = object
        .get(VALUE)
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| invalid(&path.named(VALUE), "bool value must be a JSON boolean"))?;
    Ok(crate::value::Value::Boolean(is_boolean))
}

fn decode_double(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, "bits"], path)?;
    let bits = string_member(object, "bits", path)?;
    if bits.len() != 16 || !bits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidFloatBits,
            path.named("bits"),
            "double bits must be exactly 16 hexadecimal digits",
        ));
    }
    let bits = u64::from_str_radix(bits, 16).map_err(|_| {
        crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidFloatBits,
            path.named("bits"),
            "double bits are not valid hexadecimal",
        )
    })?;
    Ok(crate::value::Value::Double(
        crate::value::Double::from_bits(bits),
    ))
}

fn decode_integer(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    let text = string_member(object, VALUE, path)?;
    let integer = parse_decimal_integer(text).map_err(|message| {
        crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidIntegerText,
            path.named(VALUE),
            message,
        )
    })?;
    Ok(crate::value::Value::SignedInteger(
        crate::value::SignedInteger::new(integer),
    ))
}

fn decode_string(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    Ok(crate::value::Value::String(
        string_member(object, VALUE, path)?.to_owned(),
    ))
}

fn decode_symbol(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    Ok(crate::value::Value::Symbol(crate::value::Symbol::new(
        string_member(object, VALUE, path)?.to_owned(),
    )))
}

fn decode_bytes(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, VALUE], path)?;
    let text = string_member(object, VALUE, path)?;
    let bytes = crate::base64::decode(text).map_err(|message| {
        crate::error::Diagnostic::new(
            crate::error::Stage::Transport,
            crate::error::ErrorCode::InvalidBase64,
            path.named(VALUE),
            message,
        )
    })?;
    Ok(crate::value::Value::ByteString(
        crate::value::ByteString::new(bytes),
    ))
}

fn decode_record(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, "label", "fields"], path)?;
    let label_json = object
        .get("label")
        .ok_or_else(|| invalid(&path.named("label"), "record is missing its label"))?;
    let label = decode_value(label_json, &path.named("label"))?;
    let fields_json = object
        .get("fields")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid(&path.named("fields"), "record fields must be an array"))?;
    let mut fields = Vec::with_capacity(fields_json.len());
    for (index, field) in fields_json.iter().enumerate() {
        fields.push(decode_value(field, &path.named("fields").index(index))?);
    }
    Ok(crate::value::Value::Record(crate::value::Record::new(
        label, fields,
    )))
}

fn decode_collection(
    tag: &str,
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, "items"], path)?;
    let items_json = object
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid(&path.named("items"), "items must be an array"))?;
    if tag == "sequence" {
        let mut items = Vec::with_capacity(items_json.len());
        for (index, item) in items_json.iter().enumerate() {
            items.push(decode_value(item, &path.named("items").index(index))?);
        }
        Ok(crate::value::Value::Sequence(items))
    } else {
        let mut items = std::collections::BTreeSet::new();
        for (index, item) in items_json.iter().enumerate() {
            let item = decode_value(item, &path.named("items").index(index))?;
            if !items.insert(item) {
                return Err(crate::error::Diagnostic::new(
                    crate::error::Stage::Transport,
                    crate::error::ErrorCode::DuplicateSetElement,
                    path.named("items").index(index),
                    "set contains a duplicate element",
                ));
            }
        }
        Ok(crate::value::Value::Set(items))
    }
}

fn decode_dictionary(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
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
        let key = decode_value(key_json, &entry_path.named("key"))?;
        let value = decode_value(value_json, &entry_path.named("value"))?;
        if entries.insert(key, value).is_some() {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Transport,
                crate::error::ErrorCode::DuplicateDictionaryKey,
                entry_path,
                "dictionary contains a duplicate key",
            ));
        }
    }
    Ok(crate::value::Value::Dictionary(entries))
}

fn decode_embedded(
    object: &serde_json::Map<String, serde_json::Value>,
    path: &crate::error::Path,
) -> Result<crate::value::Value, crate::error::Diagnostic> {
    reject_extra(object, &[TAG, "value"], path)?;
    let inner = object
        .get("value")
        .ok_or_else(|| invalid(&path.named("value"), "embedded value is missing"))?;
    Ok(crate::value::Value::embedded(decode_value(
        inner,
        &path.named("value"),
    )?))
}

fn parse_decimal_integer(text: &str) -> Result<num_bigint::BigInt, &'static str> {
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
    text.parse::<num_bigint::BigInt>()
        .map_err(|_| "integer text is out of range")
}

fn invalid(path: &crate::error::Path, message: &'static str) -> crate::error::Diagnostic {
    crate::error::Diagnostic::new(
        crate::error::Stage::Transport,
        crate::error::ErrorCode::InvalidTaggedJson,
        path.clone(),
        message,
    )
}

fn string_member<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
    path: &crate::error::Path,
) -> Result<&'a str, crate::error::Diagnostic> {
    object
        .get(name)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            crate::error::Diagnostic::new(
                crate::error::Stage::Transport,
                crate::error::ErrorCode::InvalidTaggedJson,
                path.named(name),
                format!("member {name:?} must be a string"),
            )
        })
}

fn reject_extra(
    object: &serde_json::Map<String, serde_json::Value>,
    allowed: &[&str],
    path: &crate::error::Path,
) -> Result<(), crate::error::Diagnostic> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(crate::error::Diagnostic::new(
                crate::error::Stage::Transport,
                crate::error::ErrorCode::InvalidTaggedJson,
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

    fn roundtrip(value: crate::value::Value) -> crate::value::Value {
        let document = encode_document_string(&value);
        decode_document(&document).expect("roundtrip")
    }

    #[test]
    fn rich_values_survive_the_json_boundary() {
        let values = [
            crate::value::Value::symbol("same-text"),
            crate::value::Value::string("same-text"),
            crate::value::Value::integer(
                "1234567890123456789012345678901234567890"
                    .parse::<num_bigint::BigInt>()
                    .expect("valid integer"),
            ),
            crate::value::Value::double(-0.0),
            crate::value::Value::double(f64::NAN),
            crate::value::Value::double(1.202e300),
            crate::value::Value::bytes([0_u8, 1, 2, 250, 255]),
            crate::value::Value::record_named(
                "capture",
                vec![crate::value::Value::sequence(vec![
                    crate::value::Value::symbol("nested"),
                ])],
            ),
            crate::value::Value::set([
                crate::value::Value::integer(2_i64),
                crate::value::Value::integer(1_i64),
            ]),
            crate::value::Value::dictionary([
                (
                    crate::value::Value::integer(1_i64),
                    crate::value::Value::string("integer key"),
                ),
                (
                    crate::value::Value::bytes([9_u8]),
                    crate::value::Value::symbol("byte key"),
                ),
            ]),
            crate::value::Value::embedded(crate::value::Value::symbol("marker")),
            crate::value::Value::Boolean(false),
        ];
        for value in values {
            assert_eq!(roundtrip(value.clone()), value);
        }
        // Symbols and strings with equal text remain distinguishable.
        assert_ne!(
            crate::value::Value::symbol("x"),
            crate::value::Value::string("x")
        );
        // Exact NaN payloads survive.
        let nan_bits = f64::NAN.to_bits();
        let decoded = roundtrip(crate::value::Value::double(f64::from_bits(nan_bits)));
        assert_eq!(
            decoded.as_double().map(crate::value::Double::bits),
            Some(nan_bits)
        );
    }

    #[test]
    fn document_envelope_is_versioned_and_strict() {
        let document = encode_document(&crate::value::Value::integer(1_i64));
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
                encode_value(&crate::value::Value::Boolean(true)),
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
                encode_value(&crate::value::Value::Boolean(true)),
            ),
        ]));
        assert_eq!(
            decode_document_value(&wrong_version)
                .expect_err("version")
                .code,
            crate::error::ErrorCode::InvalidTaggedJson
        );

        assert!(decode_document("not json").is_err());
    }

    #[test]
    fn malformed_values_fail_before_domain_use() {
        for (json, code) in [
            (
                serde_json::json!({"t": "mystery"}),
                crate::error::ErrorCode::UnsupportedValueKind,
            ),
            (
                serde_json::json!({"t": "string"}),
                crate::error::ErrorCode::InvalidTaggedJson,
            ),
            (
                serde_json::json!({"t": "int", "v": "+1"}),
                crate::error::ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "int", "v": "01"}),
                crate::error::ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "int", "v": "-0"}),
                crate::error::ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "double", "bits": "zz"}),
                crate::error::ErrorCode::InvalidFloatBits,
            ),
            (
                serde_json::json!({"t": "bytes", "v": "!!!"}),
                crate::error::ErrorCode::InvalidBase64,
            ),
            (
                serde_json::json!({"t": "set", "items": [
                    {"t": "int", "v": "1"},
                    {"t": "int", "v": "1"}
                ]}),
                crate::error::ErrorCode::DuplicateSetElement,
            ),
            (
                serde_json::json!({"t": "dictionary", "entries": [
                    {"t": "entry", "key": {"t": "string", "v": "k"}, "value": {"t": "int", "v": "1"}},
                    {"t": "entry", "key": {"t": "string", "v": "k"}, "value": {"t": "int", "v": "2"}}
                ]}),
                crate::error::ErrorCode::DuplicateDictionaryKey,
            ),
            (
                serde_json::json!({"t": "bool", "v": true, "extra": 1}),
                crate::error::ErrorCode::InvalidTaggedJson,
            ),
        ] {
            let error = decode_value(&json, &crate::error::Path::root()).expect_err("must reject");
            assert_eq!(error.code, code, "{json}");
        }
    }

    #[test]
    fn user_data_cannot_impersonate_codec_control_members() {
        // A user dictionary is itself a tagged value; its members are data.
        let value = crate::value::Value::dictionary([(
            crate::value::Value::symbol("t"),
            crate::value::Value::string("string"),
        )]);
        let encoded = encode_value(&value);
        assert_eq!(
            encoded.get("t").and_then(serde_json::Value::as_str),
            Some("dictionary")
        );
        assert_eq!(
            decode_value(&encoded, &crate::error::Path::root()).expect("decode"),
            value
        );
    }
}
