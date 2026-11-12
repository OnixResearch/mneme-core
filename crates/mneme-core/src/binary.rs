//! Canonical Preserves binary encoding and strict decoding.
//!
//! Encoding follows the Preserves binary syntax and its canonical form:
//! annotations are never emitted, set elements and dictionary entries are
//! ordered by their encoded representation, integers use minimal two's
//! complement bytes, and length varints use their shortest form. Decoding
//! rejects non-canonical spellings, duplicate set elements or dictionary keys,
//! trailing bytes, and inputs that exceed the declared nesting bound.
//!
//! The decoder skips annotations, which are presentation metadata under the
//! Mneme profile. A decoder is therefore value-preserving for every
//! authoritative field while never letting annotation content influence one.

use num_traits::Zero;

const TAG_FALSE: u8 = 0x80;
const TAG_TRUE: u8 = 0x81;
const TAG_END: u8 = 0x84;
const TAG_ANNOTATION: u8 = 0x85;
const TAG_EMBEDDED: u8 = 0x86;
const TAG_DOUBLE: u8 = 0x87;
const TAG_INTEGER: u8 = 0xB0;
const TAG_STRING: u8 = 0xB1;
const TAG_BYTESTRING: u8 = 0xB2;
const TAG_SYMBOL: u8 = 0xB3;
const TAG_RECORD: u8 = 0xB4;
const TAG_SEQUENCE: u8 = 0xB5;
const TAG_SET: u8 = 0xB6;
const TAG_DICTIONARY: u8 = 0xB7;

/// Maximum compound nesting accepted by the decoder.
pub const MAX_DEPTH: usize = 256;
/// Maximum number of annotations skipped around a single value.
pub const MAX_ANNOTATIONS: usize = 10_000;

/// Encode a value in canonical Preserves binary form.
pub fn encode(value: &crate::typed::Value) -> Vec<u8> {
    let mut output = Vec::new();
    encode_into(value, &mut output);
    output
}

enum EncodeTask<'a> {
    Visit(&'a crate::typed::Value),
    Record(usize),
    Sequence(usize),
    Set(usize),
    Dictionary(usize),
    Embedded,
}

fn encode_into(value: &crate::typed::Value, output: &mut Vec<u8>) {
    let mut tasks = vec![EncodeTask::Visit(value)];
    let mut values: Vec<Vec<u8>> = Vec::new();
    while let Some(task) = tasks.pop() {
        match task {
            EncodeTask::Visit(value) => match value {
                crate::typed::Value::Record(record) => {
                    tasks.push(EncodeTask::Record(record.fields().len()));
                    for field in record.fields().iter().rev() {
                        tasks.push(EncodeTask::Visit(field));
                    }
                    tasks.push(EncodeTask::Visit(record.label()));
                }
                crate::typed::Value::Sequence(items) => {
                    tasks.push(EncodeTask::Sequence(items.len()));
                    for item in items.iter().rev() {
                        tasks.push(EncodeTask::Visit(item));
                    }
                }
                crate::typed::Value::Set(items) => {
                    tasks.push(EncodeTask::Set(items.len()));
                    for item in items.iter().rev() {
                        tasks.push(EncodeTask::Visit(item));
                    }
                }
                crate::typed::Value::Dictionary(entries) => {
                    tasks.push(EncodeTask::Dictionary(entries.len()));
                    for (key, item) in entries.iter().rev() {
                        tasks.push(EncodeTask::Visit(item));
                        tasks.push(EncodeTask::Visit(key));
                    }
                }
                crate::typed::Value::Embedded(inner) => {
                    tasks.push(EncodeTask::Embedded);
                    tasks.push(EncodeTask::Visit(inner));
                }
                scalar => {
                    values.reserve(1);
                    values.push(encode_scalar(scalar));
                }
            },
            task => {
                let encoded = build_encoded(task, &mut values);
                values.reserve(1);
                values.push(encoded);
            }
        }
    }
    if let Some(encoded) = values.pop() {
        output.extend_from_slice(&encoded);
    }
}

fn encode_scalar(value: &crate::typed::Value) -> Vec<u8> {
    let mut output = Vec::new();
    match value {
        crate::typed::Value::Boolean(false) => output.push(TAG_FALSE),
        crate::typed::Value::Boolean(true) => output.push(TAG_TRUE),
        crate::typed::Value::Double(double) => {
            output.push(TAG_DOUBLE);
            output.push(0x08);
            output.extend_from_slice(&double.bits().to_be_bytes());
        }
        crate::typed::Value::SignedInteger(integer) => {
            output.push(TAG_INTEGER);
            let bytes = minimal_signed_bytes(integer.as_bigint());
            write_varint(&mut output, bytes.len() as u64);
            output.extend_from_slice(&bytes);
        }
        crate::typed::Value::String(text) => {
            output.push(TAG_STRING);
            write_varint(&mut output, text.len() as u64);
            output.extend_from_slice(text.as_bytes());
        }
        crate::typed::Value::ByteString(bytes) => {
            output.push(TAG_BYTESTRING);
            write_varint(&mut output, bytes.as_slice().len() as u64);
            output.extend_from_slice(bytes.as_slice());
        }
        crate::typed::Value::Symbol(symbol) => {
            output.push(TAG_SYMBOL);
            write_varint(&mut output, symbol.as_str().len() as u64);
            output.extend_from_slice(symbol.as_str().as_bytes());
        }
        _ => {}
    }
    output
}

fn build_encoded(task: EncodeTask<'_>, values: &mut Vec<Vec<u8>>) -> Vec<u8> {
    let take = |values: &mut Vec<Vec<u8>>| values.pop().unwrap_or_default();
    match task {
        EncodeTask::Record(count) => {
            let mut fields: Vec<Vec<u8>> = (0..count).map(|_| take(values)).collect();
            fields.reverse();
            let label = take(values);
            let mut output = vec![TAG_RECORD];
            output.extend_from_slice(&label);
            for field in fields {
                output.extend_from_slice(&field);
            }
            output.push(TAG_END);
            output
        }
        EncodeTask::Sequence(count) => {
            let mut items: Vec<Vec<u8>> = (0..count).map(|_| take(values)).collect();
            items.reverse();
            let mut output = vec![TAG_SEQUENCE];
            for item in items {
                output.extend_from_slice(&item);
            }
            output.push(TAG_END);
            output
        }
        EncodeTask::Set(count) => {
            let mut items: Vec<Vec<u8>> = (0..count).map(|_| take(values)).collect();
            items.sort();
            let mut output = vec![TAG_SET];
            for item in items {
                output.extend_from_slice(&item);
            }
            output.push(TAG_END);
            output
        }
        EncodeTask::Dictionary(count) => {
            let mut entries: Vec<(Vec<u8>, Vec<u8>)> = (0..count)
                .map(|_| {
                    let value = take(values);
                    let key = take(values);
                    (key, value)
                })
                .collect();
            entries.reverse();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            let mut output = vec![TAG_DICTIONARY];
            for (key, value) in entries {
                output.extend_from_slice(&key);
                output.extend_from_slice(&value);
            }
            output.push(TAG_END);
            output
        }
        EncodeTask::Embedded => {
            let inner = take(values);
            let mut output = vec![TAG_EMBEDDED];
            output.extend_from_slice(&inner);
            output
        }
        EncodeTask::Visit(_) => Vec::new(),
    }
}

/// Decode one complete value and reject trailing bytes.
pub fn decode(bytes: &[u8]) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    let mut decoder = Decoder {
        bytes,
        position: 0,
        annotations: 0,
    };
    let value = decoder.value(&crate::problem::Path::root(), 0)?;
    if decoder.position != bytes.len() {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Syntax,
            crate::problem::ErrorCode::TrailingBytes,
            crate::problem::Path::root(),
            format!(
                "{} trailing byte(s) after the top-level value",
                bytes.len() - decoder.position
            ),
        ));
    }
    Ok(value)
}

/// Decode and verify that the input is the canonical encoding of its value.
pub fn decode_canonical(bytes: &[u8]) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
    let value = decode(bytes)?;
    if encode(&value) != bytes {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Syntax,
            crate::problem::ErrorCode::NonCanonicalEncoding,
            crate::problem::Path::root(),
            "input is not the canonical encoding of its value",
        ));
    }
    Ok(value)
}

fn write_varint(output: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F).to_le_bytes()[0];
        value >>= 7;
        if value == 0 {
            output.push(byte);
            return;
        }
        output.push(byte | 0x80);
    }
}

fn minimal_signed_bytes(value: &num_bigint::BigInt) -> Vec<u8> {
    if value.is_zero() {
        return Vec::new();
    }
    let mut bytes = value.to_signed_bytes_be();
    while bytes.len() > 1 {
        let first = bytes[0];
        let second = bytes[1];
        let is_redundant_positive = first == 0x00 && second & 0x80 == 0;
        let is_redundant_negative = first == 0xFF && second & 0x80 != 0;
        if is_redundant_positive || is_redundant_negative {
            bytes.remove(0);
        } else {
            break;
        }
    }
    bytes
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
    annotations: usize,
}

impl Decoder<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn next_byte(&mut self, path: &crate::problem::Path) -> Result<u8, crate::problem::Diagnostic> {
        match self.bytes.get(self.position) {
            Some(byte) => {
                self.position += 1;
                Ok(*byte)
            }
            None => Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                "unexpected end of input",
            )),
        }
    }

    fn take(
        &mut self,
        length: usize,
        path: &crate::problem::Path,
    ) -> Result<&[u8], crate::problem::Diagnostic> {
        let end = self.position.checked_add(length).ok_or_else(|| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                "length overflows the address space",
            )
        })?;
        if end > self.bytes.len() {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                format!(
                    "declared length {length} exceeds the {} remaining byte(s)",
                    self.bytes.len() - self.position
                ),
            ));
        }
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    fn varint(&mut self, path: &crate::problem::Path) -> Result<u64, crate::problem::Diagnostic> {
        let mut result: u64 = 0;
        for index in 0..10 {
            let byte = self.next_byte(path)?;
            if index == 9 {
                // Only the low bit of the tenth group fits in a u64.
                if byte & 0x80 != 0 || byte > 1 {
                    return Err(crate::problem::Diagnostic::new(
                        crate::problem::Stage::Syntax,
                        crate::problem::ErrorCode::MalformedEncoding,
                        path.clone(),
                        "length varint exceeds the supported range",
                    ));
                }
            }
            result |= u64::from(byte & 0x7F) << (index * 7);
            if byte & 0x80 == 0 {
                if index > 0 && byte == 0 {
                    return Err(crate::problem::Diagnostic::new(
                        crate::problem::Stage::Syntax,
                        crate::problem::ErrorCode::NonCanonicalEncoding,
                        path.clone(),
                        "length varint is not minimally encoded",
                    ));
                }
                return Ok(result);
            }
        }
        Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Syntax,
            crate::problem::ErrorCode::MalformedEncoding,
            path.clone(),
            "length varint is unterminated",
        ))
    }

    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn value(
        &mut self,
        path: &crate::problem::Path,
        depth: usize,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        if depth > MAX_DEPTH {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::DepthLimitExceeded,
                path.clone(),
                format!("compound nesting exceeds {MAX_DEPTH} levels"),
            ));
        }
        self.skip_annotations(path, depth)?;
        let tag = self.next_byte(path)?;
        self.decode_tag(tag, path, depth)
    }

    fn skip_annotations(
        &mut self,
        path: &crate::problem::Path,
        depth: usize,
    ) -> Result<(), crate::problem::Diagnostic> {
        loop {
            match self.peek() {
                Some(TAG_ANNOTATION) => {
                    self.position += 1;
                    self.annotations += 1;
                    if self.annotations > MAX_ANNOTATIONS {
                        return Err(crate::problem::Diagnostic::new(
                            crate::problem::Stage::Syntax,
                            crate::problem::ErrorCode::AnnotationLimitExceeded,
                            path.clone(),
                            format!("more than {MAX_ANNOTATIONS} annotations around one value"),
                        ));
                    }
                    // Decode and discard the annotation value. Authoritative
                    // fields never depend on annotation content.
                    let _annotation = self.value(path, depth + 1)?;
                }
                Some(_) => return Ok(()),
                None => {
                    return Err(crate::problem::Diagnostic::new(
                        crate::problem::Stage::Syntax,
                        crate::problem::ErrorCode::MalformedEncoding,
                        path.clone(),
                        "unexpected end of input while reading a value",
                    ));
                }
            }
        }
    }

    fn decode_tag(
        &mut self,
        tag: u8,
        path: &crate::problem::Path,
        depth: usize,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        match tag {
            TAG_FALSE => Ok(crate::typed::Value::Boolean(false)),
            TAG_TRUE => Ok(crate::typed::Value::Boolean(true)),
            TAG_DOUBLE => self.decode_double(path),
            TAG_INTEGER => self.decode_integer(path),
            TAG_STRING => self.decode_string(path),
            TAG_BYTESTRING => self.decode_bytes(path),
            TAG_SYMBOL => self.decode_symbol(path),
            TAG_RECORD => self.record(path, depth),
            TAG_SEQUENCE => self.sequence(path, depth),
            TAG_SET => self.set(path, depth),
            TAG_DICTIONARY => self.dictionary(path, depth),
            TAG_EMBEDDED => self.decode_embedded(path, depth),
            TAG_END => Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                "unexpected end marker",
            )),
            other => Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::UnsupportedTag,
                path.clone(),
                format!("unsupported or reserved tag 0x{other:02x}"),
            )),
        }
    }

    fn decode_double(
        &mut self,
        path: &crate::problem::Path,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let length = self.next_byte(path)?;
        if length != 8 {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                format!("double length must be 8, found {length}"),
            ));
        }
        let bytes = self.take(8, path)?;
        let mut bits = [0_u8; 8];
        bits.copy_from_slice(bytes);
        Ok(crate::typed::Value::Double(
            crate::typed::Double::from_bits(u64::from_be_bytes(bits)),
        ))
    }

    fn decode_integer(
        &mut self,
        path: &crate::problem::Path,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let length = usize::try_from(self.varint(path)?).map_err(|_| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                "integer length exceeds the address space",
            )
        })?;
        let bytes = self.take(length, path)?;
        let integer = if bytes.is_empty() {
            num_bigint::BigInt::from(0)
        } else {
            num_bigint::BigInt::from_signed_bytes_be(bytes)
        };
        if minimal_signed_bytes(&integer) != bytes {
            return Err(crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::NonCanonicalEncoding,
                path.clone(),
                "integer bytes are not a minimal two's-complement encoding",
            ));
        }
        Ok(crate::typed::Value::SignedInteger(
            crate::typed::SignedInteger::new(integer),
        ))
    }

    fn decode_string(
        &mut self,
        path: &crate::problem::Path,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let length = self.length(path)?;
        let bytes = self.take(length, path)?;
        let text = String::from_utf8(bytes.to_vec()).map_err(|_| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                "string bytes are not valid UTF-8",
            )
        })?;
        Ok(crate::typed::Value::String(text))
    }

    fn decode_bytes(
        &mut self,
        path: &crate::problem::Path,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let length = self.length(path)?;
        Ok(crate::typed::Value::ByteString(
            crate::typed::ByteString::new(self.take(length, path)?.to_vec()),
        ))
    }

    fn decode_symbol(
        &mut self,
        path: &crate::problem::Path,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let length = self.length(path)?;
        let bytes = self.take(length, path)?;
        let text = String::from_utf8(bytes.to_vec()).map_err(|_| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                "symbol bytes are not valid UTF-8",
            )
        })?;
        Ok(crate::typed::Value::Symbol(crate::typed::Symbol::new(text)))
    }

    fn decode_embedded(
        &mut self,
        path: &crate::problem::Path,
        depth: usize,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let inner = self.value(&path.field("embedded"), depth + 1)?;
        Ok(crate::typed::Value::embedded(inner))
    }

    fn length(&mut self, path: &crate::problem::Path) -> Result<usize, crate::problem::Diagnostic> {
        usize::try_from(self.varint(path)?).map_err(|_| {
            crate::problem::Diagnostic::new(
                crate::problem::Stage::Syntax,
                crate::problem::ErrorCode::MalformedEncoding,
                path.clone(),
                "length exceeds the address space",
            )
        })
    }

    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn record(
        &mut self,
        path: &crate::problem::Path,
        depth: usize,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let label = self.value(&path.field("label"), depth + 1)?;
        let mut fields = Vec::new();
        let max_fields = self.bytes.len().saturating_sub(self.position);
        loop {
            match self.peek() {
                Some(TAG_END) => {
                    self.position += 1;
                    break;
                }
                Some(_) => {
                    if fields.len() >= max_fields {
                        return Err(unterminated(path, "record"));
                    }
                    let field = self.value(&path.index(fields.len()), depth + 1)?;
                    fields.push(field);
                }
                None => return Err(unterminated(path, "record")),
            }
        }
        Ok(crate::typed::Value::Record(crate::typed::Record::new(
            label, fields,
        )))
    }

    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn sequence(
        &mut self,
        path: &crate::problem::Path,
        depth: usize,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let mut items = Vec::new();
        let max_items = self.bytes.len().saturating_sub(self.position);
        loop {
            match self.peek() {
                Some(TAG_END) => {
                    self.position += 1;
                    break;
                }
                Some(_) => {
                    if items.len() >= max_items {
                        return Err(unterminated(path, "sequence"));
                    }
                    items.push(self.value(&path.index(items.len()), depth + 1)?);
                }
                None => return Err(unterminated(path, "sequence")),
            }
        }
        Ok(crate::typed::Value::Sequence(items))
    }

    fn set(
        &mut self,
        path: &crate::problem::Path,
        depth: usize,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let mut items = std::collections::BTreeSet::new();
        loop {
            match self.peek() {
                Some(TAG_END) => {
                    self.position += 1;
                    break;
                }
                Some(_) => {
                    let item = self.value(&path.index(items.len()), depth + 1)?;
                    if !items.insert(item) {
                        return Err(crate::problem::Diagnostic::new(
                            crate::problem::Stage::Syntax,
                            crate::problem::ErrorCode::DuplicateSetElement,
                            path.clone(),
                            "set contains a duplicate element",
                        ));
                    }
                }
                None => return Err(unterminated(path, "set")),
            }
        }
        Ok(crate::typed::Value::Set(items))
    }

    fn dictionary(
        &mut self,
        path: &crate::problem::Path,
        depth: usize,
    ) -> Result<crate::typed::Value, crate::problem::Diagnostic> {
        let mut entries = std::collections::BTreeMap::new();
        loop {
            match self.peek() {
                Some(TAG_END) => {
                    self.position += 1;
                    break;
                }
                Some(_) => {
                    let key = self.value(&path.index(entries.len()), depth + 1)?;
                    let value = self.value(&path.index(entries.len()).field("value"), depth + 1)?;
                    if entries.insert(key, value).is_some() {
                        return Err(crate::problem::Diagnostic::new(
                            crate::problem::Stage::Syntax,
                            crate::problem::ErrorCode::DuplicateDictionaryKey,
                            path.clone(),
                            "dictionary contains a duplicate key",
                        ));
                    }
                }
                None => return Err(unterminated(path, "dictionary")),
            }
        }
        Ok(crate::typed::Value::Dictionary(entries))
    }
}

fn unterminated(path: &crate::problem::Path, compound: &'static str) -> crate::problem::Diagnostic {
    crate::problem::Diagnostic::new(
        crate::problem::Stage::Syntax,
        crate::problem::ErrorCode::MalformedEncoding,
        path.clone(),
        format!("unterminated {compound}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn encodes_specification_examples() {
        assert_eq!(
            hex(&encode(&crate::typed::Value::integer(-257_i64))),
            "b002feff"
        );
        assert_eq!(
            hex(&encode(&crate::typed::Value::integer(-1_i64))),
            "b001ff"
        );
        assert_eq!(hex(&encode(&crate::typed::Value::integer(0_i64))), "b000");
        assert_eq!(
            hex(&encode(&crate::typed::Value::integer(255_i64))),
            "b00200ff"
        );
        assert_eq!(
            hex(&encode(&crate::typed::Value::string("hello"))),
            "b10568656c6c6f"
        );
        assert_eq!(
            hex(&encode(&crate::typed::Value::sequence(vec![
                crate::typed::Value::integer(1_i64),
                crate::typed::Value::integer(2_i64),
                crate::typed::Value::integer(3_i64),
                crate::typed::Value::integer(4_i64)
            ]))),
            "b5b00101b00102b00103b0010484"
        );
        assert_eq!(
            hex(&encode(&crate::typed::Value::double(1.0))),
            "87083ff0000000000000"
        );
    }

    #[test]
    fn encodes_large_integer_example() {
        let value = crate::typed::Value::integer(
            "87112285931760246646623899502532662132736"
                .parse::<num_bigint::BigInt>()
                .expect("valid integer"),
        );
        // B0 12 followed by 18 bytes: 01 and seventeen zero bytes.
        let expected = format!("b01201{}", "00".repeat(17));
        assert_eq!(hex(&encode(&value)), expected);
        assert_eq!(decode(&encode(&value)).expect("roundtrip"), value);
    }

    #[test]
    fn roundtrips_every_kind() {
        let values = vec![
            crate::typed::Value::Boolean(true),
            crate::typed::Value::Boolean(false),
            crate::typed::Value::double(-1.202e300),
            crate::typed::Value::double(f64::NEG_INFINITY),
            crate::typed::Value::integer(0_i64),
            crate::typed::Value::string("z水𝄞"),
            crate::typed::Value::symbol("sym"),
            crate::typed::Value::bytes([0_u8, 255, 1]),
            crate::typed::Value::record_named(
                "capture",
                vec![crate::typed::Value::sequence(vec![])],
            ),
            crate::typed::Value::set([
                crate::typed::Value::integer(3_i64),
                crate::typed::Value::integer(1_i64),
            ]),
            crate::typed::Value::dictionary([
                (
                    crate::typed::Value::string("key"),
                    crate::typed::Value::integer(1_i64),
                ),
                (
                    crate::typed::Value::integer(2_i64),
                    crate::typed::Value::string("non-string key"),
                ),
            ]),
            crate::typed::Value::embedded(crate::typed::Value::symbol("live")),
        ];
        for value in values {
            let encoded = encode(&value);
            assert_eq!(decode(&encoded).expect("decode"), value);
            assert_eq!(decode_canonical(&encoded).expect("canonical"), value);
        }
    }

    #[test]
    fn set_and_dictionary_encoding_is_order_independent() {
        let ordered = crate::typed::Value::dictionary([
            (
                crate::typed::Value::symbol("a"),
                crate::typed::Value::integer(1_i64),
            ),
            (
                crate::typed::Value::symbol("b"),
                crate::typed::Value::integer(2_i64),
            ),
        ]);
        let shuffled = crate::typed::Value::dictionary([
            (
                crate::typed::Value::symbol("b"),
                crate::typed::Value::integer(2_i64),
            ),
            (
                crate::typed::Value::symbol("a"),
                crate::typed::Value::integer(1_i64),
            ),
        ]);
        assert_eq!(encode(&ordered), encode(&shuffled));
        assert_eq!(
            encode(&crate::typed::Value::set([
                crate::typed::Value::integer(1_i64),
                crate::typed::Value::integer(2_i64)
            ])),
            encode(&crate::typed::Value::set([
                crate::typed::Value::integer(2_i64),
                crate::typed::Value::integer(1_i64)
            ]))
        );
    }

    #[test]
    fn skips_annotations() {
        // @a []  =  0x85 «a» «[]»
        let bytes = [0x85, 0xB3, 0x01, b'a', 0xB5, 0x84];
        assert_eq!(
            decode(&bytes).expect("annotated sequence"),
            crate::typed::Value::sequence(vec![])
        );
        let mut output = Vec::new();
        encode_into(&crate::typed::Value::sequence(vec![]), &mut output);
        assert!(!output.contains(&TAG_ANNOTATION));
    }

    #[test]
    fn rejects_duplicate_set_elements_and_keys() {
        let duplicate_set = [0xB6, 0xB0, 0x01, 0x01, 0xB0, 0x01, 0x01, 0x84];
        assert!(decode(&duplicate_set).is_err());
        let duplicate_key = [
            0xB7, 0xB1, 0x01, b'k', 0xB0, 0x01, 0x01, 0xB1, 0x01, b'k', 0xB0, 0x01, 0x02, 0x84,
        ];
        assert!(decode(&duplicate_key).is_err());
    }

    #[test]
    fn rejects_nonminimal_integer_and_varint() {
        // 1 encoded with a redundant leading sign byte.
        let nonminimal = [0xB0, 0x02, 0x00, 0x01];
        assert!(decode(&nonminimal).is_err());
        // Sequence length varint is not used, but a two-byte zero varint is.
        let nonminimal_varint = [0xB1, 0x80, 0x00];
        assert!(decode(&nonminimal_varint).is_err());
    }

    #[test]
    fn rejects_trailing_bytes_and_reserved_tags() {
        assert_eq!(
            decode(&[0x80, 0x80]).expect_err("trailing").code,
            crate::problem::ErrorCode::TrailingBytes
        );
        assert_eq!(
            decode(&[0x82]).expect_err("reserved tag").code,
            crate::problem::ErrorCode::UnsupportedTag
        );
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut value = crate::typed::Value::sequence(vec![]);
        for _ in 0..(MAX_DEPTH + 2) {
            value = crate::typed::Value::sequence(vec![value]);
        }
        let encoded = encode(&value);
        assert_eq!(
            decode(&encoded).expect_err("too deep").code,
            crate::problem::ErrorCode::DepthLimitExceeded
        );
    }

    #[test]
    fn decode_canonical_rejects_noncanonical_set_order() {
        // Set with two elements encoded in descending byte order.
        let mut bytes = vec![TAG_SET];
        bytes.extend_from_slice(&encode(&crate::typed::Value::integer(2_i64)));
        bytes.extend_from_slice(&encode(&crate::typed::Value::integer(1_i64)));
        bytes.push(TAG_END);
        assert!(decode(&bytes).is_ok());
        assert_eq!(
            decode_canonical(&bytes).expect_err("noncanonical").code,
            crate::problem::ErrorCode::NonCanonicalEncoding
        );
    }
}
