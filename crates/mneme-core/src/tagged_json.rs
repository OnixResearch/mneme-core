//! Versioned, type-tagged JSON transport for Preserves values.
//!
//! Every supported value kind has an explicit tag. A symbol and a string with
//! equal text remain distinct, integers are decimal strings of arbitrary
//! precision, doubles carry their exact IEEE-754 bits, bytes use strict Base64,
//! and dictionary keys may be any encoded value. A versioned document envelope
//! wraps the tagged value so a decoder never guesses the format. Unsupported or
//! malformed payloads fail before any domain mutation.

use std::collections::{BTreeMap, BTreeSet};

use num_bigint::BigInt;
use serde_json::{Map, Value as Json};

use crate::base64;
use crate::error::{Diagnostic, ErrorCode, Path, Stage};
use crate::value::{ByteString, Double, Record, SignedInteger, Symbol, Value as Preserves};

/// The tagged JSON document format name.
pub const TRANSPORT_FORMAT: &str = "mneme.preserves-tagged-json";
/// The tagged JSON document version.
pub const TRANSPORT_VERSION: u32 = 1;

const TAG: &str = "t";
const VALUE: &str = "v";

/// Wrap one encoded value in the versioned transport document.
pub fn encode_document(value: &Preserves) -> Json {
    let mut document = Map::new();
    document.insert(
        "format".to_owned(),
        Json::String(TRANSPORT_FORMAT.to_owned()),
    );
    document.insert(
        "version".to_owned(),
        Json::from(u64::from(TRANSPORT_VERSION)),
    );
    document.insert("value".to_owned(), encode_value(value));
    Json::Object(document)
}

/// Render a transport document as compact JSON text.
pub fn encode_document_string(value: &Preserves) -> String {
    encode_document(value).to_string()
}

/// Decode a transport document from text.
pub fn decode_document(text: &str) -> Result<Preserves, Diagnostic> {
    let json: Json = serde_json::from_str(text).map_err(|error| {
        Diagnostic::new(
            Stage::Transport,
            ErrorCode::InvalidTaggedJson,
            Path::root(),
            format!("invalid JSON: {error}"),
        )
    })?;
    decode_document_value(&json)
}

/// Decode a transport document from an already parsed JSON value.
pub fn decode_document_value(json: &Json) -> Result<Preserves, Diagnostic> {
    let Some(document) = json.as_object() else {
        return Err(Diagnostic::new(
            Stage::Transport,
            ErrorCode::InvalidTaggedJson,
            Path::root(),
            "transport document must be a JSON object",
        ));
    };
    reject_extra(document, &["format", "version", "value"], &Path::root())?;
    let format = string_member(document, "format", &Path::root())?;
    if format != TRANSPORT_FORMAT {
        return Err(Diagnostic::new(
            Stage::Transport,
            ErrorCode::InvalidTaggedJson,
            Path::root().named("format"),
            format!("unsupported transport format {format:?}"),
        ));
    }
    let version = document
        .get("version")
        .and_then(Json::as_u64)
        .ok_or_else(|| {
            Diagnostic::new(
                Stage::Transport,
                ErrorCode::InvalidTaggedJson,
                Path::root().named("version"),
                "transport version must be a non-negative integer",
            )
        })?;
    if version != u64::from(TRANSPORT_VERSION) {
        return Err(Diagnostic::new(
            Stage::Transport,
            ErrorCode::InvalidTaggedJson,
            Path::root().named("version"),
            format!(
                "unsupported transport version {version}; this build reads version {TRANSPORT_VERSION}"
            ),
        ));
    }
    let value = document.get("value").ok_or_else(|| {
        Diagnostic::new(
            Stage::Transport,
            ErrorCode::InvalidTaggedJson,
            Path::root().named("value"),
            "transport document is missing its value",
        )
    })?;
    decode_value(value, &Path::root().named("value"))
}

/// Encode one Preserves value with explicit type tags.
pub fn encode_value(value: &Preserves) -> Json {
    match value {
        Preserves::Boolean(boolean) => tagged("bool", [("v", Json::Bool(*boolean))]),
        Preserves::Double(double) => tagged(
            "double",
            [("bits", Json::String(format!("{:016x}", double.bits())))],
        ),
        Preserves::SignedInteger(integer) => tagged(
            "int",
            [("v", Json::String(integer.as_bigint().to_string()))],
        ),
        Preserves::String(text) => tagged("string", [("v", Json::String(text.clone()))]),
        Preserves::ByteString(bytes) => tagged(
            "bytes",
            [("v", Json::String(base64::encode(bytes.as_slice())))],
        ),
        Preserves::Symbol(symbol) => {
            tagged("symbol", [("v", Json::String(symbol.as_str().to_owned()))])
        }
        Preserves::Record(record) => tagged(
            "record",
            [
                ("label", encode_value(record.label())),
                (
                    "fields",
                    Json::Array(record.fields().iter().map(encode_value).collect()),
                ),
            ],
        ),
        Preserves::Sequence(items) => tagged(
            "sequence",
            [(
                "items",
                Json::Array(items.iter().map(encode_value).collect()),
            )],
        ),
        Preserves::Set(items) => tagged(
            "set",
            [(
                "items",
                Json::Array(items.iter().map(encode_value).collect()),
            )],
        ),
        Preserves::Dictionary(entries) => tagged(
            "dictionary",
            [(
                "entries",
                Json::Array(
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
        ),
        Preserves::Embedded(inner) => tagged("embedded", [("value", encode_value(inner))]),
    }
}

fn tagged<const N: usize>(tag: &str, members: [(&str, Json); N]) -> Json {
    let mut object = Map::new();
    object.insert(TAG.to_owned(), Json::String(tag.to_owned()));
    for (name, value) in members {
        object.insert(name.to_owned(), value);
    }
    Json::Object(object)
}

/// Decode one tagged value. No coercion or fallback is applied.
pub fn decode_value(json: &Json, path: &Path) -> Result<Preserves, Diagnostic> {
    let object = json
        .as_object()
        .ok_or_else(|| invalid(path, "tagged value must be a JSON object"))?;
    let tag = string_member(object, TAG, path)?;
    match tag {
        "bool" => {
            reject_extra(object, &[TAG, VALUE], path)?;
            let boolean = object
                .get(VALUE)
                .and_then(Json::as_bool)
                .ok_or_else(|| invalid(&path.named(VALUE), "bool value must be a JSON boolean"))?;
            Ok(Preserves::Boolean(boolean))
        }
        "double" => {
            reject_extra(object, &[TAG, "bits"], path)?;
            let bits = string_member(object, "bits", path)?;
            if bits.len() != 16 || !bits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(Diagnostic::new(
                    Stage::Transport,
                    ErrorCode::InvalidFloatBits,
                    path.named("bits"),
                    "double bits must be exactly 16 hexadecimal digits",
                ));
            }
            let bits = u64::from_str_radix(bits, 16).map_err(|_| {
                Diagnostic::new(
                    Stage::Transport,
                    ErrorCode::InvalidFloatBits,
                    path.named("bits"),
                    "double bits are not valid hexadecimal",
                )
            })?;
            Ok(Preserves::Double(Double::from_bits(bits)))
        }
        "int" => {
            reject_extra(object, &[TAG, VALUE], path)?;
            let text = string_member(object, VALUE, path)?;
            let integer = parse_decimal_integer(text).map_err(|message| {
                Diagnostic::new(
                    Stage::Transport,
                    ErrorCode::InvalidIntegerText,
                    path.named(VALUE),
                    message,
                )
            })?;
            Ok(Preserves::SignedInteger(SignedInteger::new(integer)))
        }
        "string" => {
            reject_extra(object, &[TAG, VALUE], path)?;
            Ok(Preserves::String(
                string_member(object, VALUE, path)?.to_owned(),
            ))
        }
        "symbol" => {
            reject_extra(object, &[TAG, VALUE], path)?;
            Ok(Preserves::Symbol(Symbol::new(
                string_member(object, VALUE, path)?.to_owned(),
            )))
        }
        "bytes" => {
            reject_extra(object, &[TAG, VALUE], path)?;
            let text = string_member(object, VALUE, path)?;
            let bytes = base64::decode(text).map_err(|message| {
                Diagnostic::new(
                    Stage::Transport,
                    ErrorCode::InvalidBase64,
                    path.named(VALUE),
                    message,
                )
            })?;
            Ok(Preserves::ByteString(ByteString::new(bytes)))
        }
        "record" => {
            reject_extra(object, &[TAG, "label", "fields"], path)?;
            let label_json = object
                .get("label")
                .ok_or_else(|| invalid(&path.named("label"), "record is missing its label"))?;
            let label = decode_value(label_json, &path.named("label"))?;
            let fields_json = object
                .get("fields")
                .and_then(Json::as_array)
                .ok_or_else(|| invalid(&path.named("fields"), "record fields must be an array"))?;
            let mut fields = Vec::with_capacity(fields_json.len());
            for (index, field) in fields_json.iter().enumerate() {
                fields.push(decode_value(field, &path.named("fields").index(index))?);
            }
            Ok(Preserves::Record(Record::new(label, fields)))
        }
        "sequence" | "set" => {
            reject_extra(object, &[TAG, "items"], path)?;
            let items_json = object
                .get("items")
                .and_then(Json::as_array)
                .ok_or_else(|| invalid(&path.named("items"), "items must be an array"))?;
            if tag == "sequence" {
                let mut items = Vec::with_capacity(items_json.len());
                for (index, item) in items_json.iter().enumerate() {
                    items.push(decode_value(item, &path.named("items").index(index))?);
                }
                Ok(Preserves::Sequence(items))
            } else {
                let mut items = BTreeSet::new();
                for (index, item) in items_json.iter().enumerate() {
                    let item = decode_value(item, &path.named("items").index(index))?;
                    if !items.insert(item) {
                        return Err(Diagnostic::new(
                            Stage::Transport,
                            ErrorCode::DuplicateSetElement,
                            path.named("items").index(index),
                            "set contains a duplicate element",
                        ));
                    }
                }
                Ok(Preserves::Set(items))
            }
        }
        "dictionary" => {
            reject_extra(object, &[TAG, "entries"], path)?;
            let entries_json = object
                .get("entries")
                .and_then(Json::as_array)
                .ok_or_else(|| invalid(&path.named("entries"), "entries must be an array"))?;
            let mut entries = BTreeMap::new();
            for (index, entry) in entries_json.iter().enumerate() {
                let entry_path = path.named("entries").index(index);
                let entry_object = entry.as_object().ok_or_else(|| {
                    invalid(&entry_path, "dictionary entry must be a JSON object")
                })?;
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
                let value_json = entry_object.get("value").ok_or_else(|| {
                    invalid(&entry_path.named("value"), "entry is missing its value")
                })?;
                let key = decode_value(key_json, &entry_path.named("key"))?;
                let value = decode_value(value_json, &entry_path.named("value"))?;
                if entries.insert(key, value).is_some() {
                    return Err(Diagnostic::new(
                        Stage::Transport,
                        ErrorCode::DuplicateDictionaryKey,
                        entry_path,
                        "dictionary contains a duplicate key",
                    ));
                }
            }
            Ok(Preserves::Dictionary(entries))
        }
        "embedded" => {
            reject_extra(object, &[TAG, "value"], path)?;
            let inner = object
                .get("value")
                .ok_or_else(|| invalid(&path.named("value"), "embedded value is missing"))?;
            Ok(Preserves::embedded(decode_value(
                inner,
                &path.named("value"),
            )?))
        }
        other => Err(Diagnostic::new(
            Stage::Transport,
            ErrorCode::UnsupportedValueKind,
            path.clone(),
            format!("unsupported tagged value type {other:?}"),
        )),
    }
}

fn parse_decimal_integer(text: &str) -> Result<BigInt, &'static str> {
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
    text.parse::<BigInt>()
        .map_err(|_| "integer text is out of range")
}

fn invalid(path: &Path, message: &'static str) -> Diagnostic {
    Diagnostic::new(
        Stage::Transport,
        ErrorCode::InvalidTaggedJson,
        path.clone(),
        message,
    )
}

fn string_member<'a>(
    object: &'a Map<String, Json>,
    name: &str,
    path: &Path,
) -> Result<&'a str, Diagnostic> {
    object.get(name).and_then(Json::as_str).ok_or_else(|| {
        Diagnostic::new(
            Stage::Transport,
            ErrorCode::InvalidTaggedJson,
            path.named(name),
            format!("member {name:?} must be a string"),
        )
    })
}

fn reject_extra(
    object: &Map<String, Json>,
    allowed: &[&str],
    path: &Path,
) -> Result<(), Diagnostic> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(Diagnostic::new(
                Stage::Transport,
                ErrorCode::InvalidTaggedJson,
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

    fn roundtrip(value: Preserves) -> Preserves {
        let document = encode_document_string(&value);
        decode_document(&document).expect("roundtrip")
    }

    #[test]
    fn rich_values_survive_the_json_boundary() {
        let values = [
            Preserves::symbol("same-text"),
            Preserves::string("same-text"),
            Preserves::integer(
                "1234567890123456789012345678901234567890"
                    .parse::<BigInt>()
                    .expect("valid integer"),
            ),
            Preserves::double(-0.0),
            Preserves::double(f64::NAN),
            Preserves::double(1.202e300),
            Preserves::bytes([0_u8, 1, 2, 250, 255]),
            Preserves::record_named(
                "capture",
                vec![Preserves::sequence(vec![Preserves::symbol("nested")])],
            ),
            Preserves::set([Preserves::integer(2_i64), Preserves::integer(1_i64)]),
            Preserves::dictionary([
                (Preserves::integer(1_i64), Preserves::string("integer key")),
                (Preserves::bytes([9_u8]), Preserves::symbol("byte key")),
            ]),
            Preserves::embedded(Preserves::symbol("marker")),
            Preserves::Boolean(false),
        ];
        for value in values {
            assert_eq!(roundtrip(value.clone()), value);
        }
        // Symbols and strings with equal text remain distinguishable.
        assert_ne!(Preserves::symbol("x"), Preserves::string("x"));
        // Exact NaN payloads survive.
        let nan_bits = f64::NAN.to_bits();
        let decoded = roundtrip(Preserves::double(f64::from_bits(nan_bits)));
        assert_eq!(decoded.as_double().map(Double::bits), Some(nan_bits));
    }

    #[test]
    fn document_envelope_is_versioned_and_strict() {
        let document = encode_document(&Preserves::integer(1_i64));
        assert_eq!(
            document.get("format").and_then(Json::as_str),
            Some(TRANSPORT_FORMAT)
        );

        let wrong_format = Json::Object(Map::from_iter([
            ("format".to_owned(), Json::String("other".to_owned())),
            ("version".to_owned(), Json::from(1)),
            ("value".to_owned(), encode_value(&Preserves::Boolean(true))),
        ]));
        assert!(decode_document_value(&wrong_format).is_err());

        let wrong_version = Json::Object(Map::from_iter([
            (
                "format".to_owned(),
                Json::String(TRANSPORT_FORMAT.to_owned()),
            ),
            ("version".to_owned(), Json::from(2)),
            ("value".to_owned(), encode_value(&Preserves::Boolean(true))),
        ]));
        assert_eq!(
            decode_document_value(&wrong_version)
                .expect_err("version")
                .code,
            ErrorCode::InvalidTaggedJson
        );

        assert!(decode_document("not json").is_err());
    }

    #[test]
    fn malformed_values_fail_before_domain_use() {
        for (json, code) in [
            (
                serde_json::json!({"t": "mystery"}),
                ErrorCode::UnsupportedValueKind,
            ),
            (
                serde_json::json!({"t": "string"}),
                ErrorCode::InvalidTaggedJson,
            ),
            (
                serde_json::json!({"t": "int", "v": "+1"}),
                ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "int", "v": "01"}),
                ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "int", "v": "-0"}),
                ErrorCode::InvalidIntegerText,
            ),
            (
                serde_json::json!({"t": "double", "bits": "zz"}),
                ErrorCode::InvalidFloatBits,
            ),
            (
                serde_json::json!({"t": "bytes", "v": "!!!"}),
                ErrorCode::InvalidBase64,
            ),
            (
                serde_json::json!({"t": "set", "items": [
                    {"t": "int", "v": "1"},
                    {"t": "int", "v": "1"}
                ]}),
                ErrorCode::DuplicateSetElement,
            ),
            (
                serde_json::json!({"t": "dictionary", "entries": [
                    {"t": "entry", "key": {"t": "string", "v": "k"}, "value": {"t": "int", "v": "1"}},
                    {"t": "entry", "key": {"t": "string", "v": "k"}, "value": {"t": "int", "v": "2"}}
                ]}),
                ErrorCode::DuplicateDictionaryKey,
            ),
            (
                serde_json::json!({"t": "bool", "v": true, "extra": 1}),
                ErrorCode::InvalidTaggedJson,
            ),
        ] {
            let error = decode_value(&json, &Path::root()).expect_err("must reject");
            assert_eq!(error.code, code, "{json}");
        }
    }

    #[test]
    fn user_data_cannot_impersonate_codec_control_members() {
        // A user dictionary is itself a tagged value; its members are data.
        let value = Preserves::dictionary([(Preserves::symbol("t"), Preserves::string("string"))]);
        let encoded = encode_value(&value);
        assert_eq!(encoded.get("t").and_then(Json::as_str), Some("dictionary"));
        assert_eq!(
            decode_value(&encoded, &Path::root()).expect("decode"),
            value
        );
    }
}
