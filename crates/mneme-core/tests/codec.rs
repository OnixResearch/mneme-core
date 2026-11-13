//! Regression tests for the codec audit findings (CodecAudit-1, -2, -4, -5, -7, -8).
#![allow(unknown_lints, no_unwrap)] // test code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn varint(mut value: u64) -> Vec<u8> {
    // The decoder accepts at most ten bytes, and a u64 needs at most ten
    // seven-bit groups, so that bounds the encoding.
    let mut bytes = Vec::with_capacity(10);
    loop {
        let byte = u8::try_from(value & 0x7F).expect("seven bits");
        value >>= 7;
        if value == 0 {
            bytes.push(byte);
            return bytes;
        }
        bytes.push(byte | 0x80);
    }
}

/// A transport document whose value member is `value`.
fn document(value: &str) -> String {
    let transport_format = mneme_core::transport::TRANSPORT_FORMAT;
    let transport_version = mneme_core::transport::TRANSPORT_VERSION;
    format!("{{\"format\":{transport_format:?},\"version\":{transport_version},\"value\":{value}}}")
}

/// A transport document with `members` appended after the version member.
fn envelope(members: &str) -> String {
    let transport_format = mneme_core::transport::TRANSPORT_FORMAT;
    let transport_version = mneme_core::transport::TRANSPORT_VERSION;
    format!("{{\"format\":{transport_format:?},\"version\":{transport_version},{members}}}")
}

fn nested_sequences(depth: usize) -> mneme_core::Value {
    let mut value = mneme_core::Value::integer(0_i64);
    for _ in 0..depth {
        value = mneme_core::Value::sequence(vec![value]);
    }
    value
}

fn nested_dictionaries(depth: usize) -> mneme_core::Value {
    let mut value = mneme_core::Value::integer(0_i64);
    for _ in 0..depth {
        value = mneme_core::Value::dictionary([(mneme_core::Value::symbol("k"), value)]);
    }
    value
}

// CodecAudit-1: integer size is bounded before any conversion.
#[test]
fn binary_integer_limit_is_checked_before_the_bytes_are_read() {
    // Only the header is present: the limit must fire before `take`, so the
    // error is about the declared size rather than the missing bytes.
    let bytes_limit = mneme_core::binary::MAX_INTEGER_BYTES;
    let limit = u64::try_from(bytes_limit).expect("byte limit fits in u64");
    let mut header = vec![0xB0_u8];
    header.extend(varint(limit + 1));
    let error = mneme_core::decode(&header).expect_err("oversized integer");
    assert_eq!(error.code, mneme_core::ErrorCode::LimitExceeded);
    assert!(
        error
            .message
            .contains(&mneme_core::binary::MAX_INTEGER_BYTES.to_string()),
        "{}",
        error.message
    );

    // The largest accepted integer is exactly the declared bound, its decimal
    // spelling is exactly the transport's digit bound, and both codecs read it
    // back.
    let mut largest = vec![0xB0_u8];
    largest.extend(varint(limit));
    largest.push(0x7F);
    largest.extend(std::iter::repeat_n(
        0xFF_u8,
        mneme_core::binary::MAX_INTEGER_BYTES - 1,
    ));
    let value = mneme_core::decode(&largest).expect("largest integer");
    assert_eq!(mneme_core::encode(&value), largest);
    let digits = value.as_integer().expect("integer").to_string();
    assert_eq!(digits.len(), mneme_core::transport::MAX_INTEGER_DIGITS);
    assert_eq!(
        mneme_core::decode_document(&mneme_core::encode_document_string(&value))
            .expect("transport roundtrip"),
        value
    );
}

#[test]
fn transport_integer_limit_is_checked_before_conversion() {
    let too_many_digits = format!("1{}", "0".repeat(mneme_core::transport::MAX_INTEGER_DIGITS));
    let member = format!("{{\"t\":\"int\",\"v\":{too_many_digits:?}}}");
    let error = mneme_core::decode_document(&document(&member)).expect_err("digit limit");
    assert_eq!(error.code, mneme_core::ErrorCode::LimitExceeded);
    assert!(
        error
            .message
            .contains(&mneme_core::transport::MAX_INTEGER_DIGITS.to_string()),
        "{}",
        error.message
    );

    // A million digits is refused without being converted; the old decoder
    // spent seconds parsing it and then accepted it.
    let huge = format!("1{}", "0".repeat(1_000_000));
    let member = format!("{{\"t\":\"int\",\"v\":{huge:?}}}");
    let error = mneme_core::decode_document(&document(&member)).expect_err("huge integer");
    assert_eq!(error.code, mneme_core::ErrorCode::LimitExceeded);

    // The digit bound alone would admit 9864-digit values that need 4097
    // two's-complement bytes, so the parsed magnitude is checked as well.
    let widest = "9".repeat(mneme_core::transport::MAX_INTEGER_DIGITS);
    let member = format!("{{\"t\":\"int\",\"v\":{widest:?}}}");
    let error = mneme_core::decode_document(&document(&member)).expect_err("too wide");
    assert_eq!(error.code, mneme_core::ErrorCode::LimitExceeded);
}

// CodecAudit-2: a repeated JSON member is refused at every nesting level.
#[test]
fn repeated_json_members_are_refused_at_every_nesting_level() {
    let cases = [
        (
            envelope(
                "\"value\":{\"t\":\"symbol\",\"v\":\"first\",\"t\":\"string\",\"v\":\"second\"}",
            ),
            "t",
        ),
        (
            envelope("\"version\":2,\"value\":{\"t\":\"bool\",\"v\":true}"),
            "version",
        ),
        (
            envelope(
                "\"value\":{\"t\":\"bool\",\"v\":true},\"value\":{\"t\":\"bool\",\"v\":false}",
            ),
            "value",
        ),
        (
            envelope(
                "\"value\":{\"t\":\"sequence\",\"items\":[{\"t\":\"bool\",\"v\":true,\"v\":false}]}",
            ),
            "v",
        ),
        (
            envelope(
                "\"value\":{\"t\":\"dictionary\",\"entries\":[{\"t\":\"entry\",\"key\":{\"t\":\"string\",\"v\":\"k\",\"v\":\"j\"},\"value\":{\"t\":\"int\",\"v\":\"1\"}}]}",
            ),
            "v",
        ),
    ];
    for (text, member) in cases {
        let error = mneme_core::decode_document(&text).expect_err("repeated member");
        assert_eq!(
            error.code,
            mneme_core::ErrorCode::InvalidTaggedJson,
            "{text}"
        );
        assert!(
            error.message.contains(&format!("{member:?}")),
            "{}",
            error.message
        );
        assert_eq!(error.path.to_string(), format!("$[{member:?}]"), "{text}");
    }

    // Distinct members still decode.
    let value = mneme_core::decode_document(&document("{\"t\":\"bool\",\"v\":true}"))
        .expect("distinct members");
    assert_eq!(value, mneme_core::Value::Boolean(true));
}

// CodecAudit-4: both codecs accept and refuse the same nesting depths.
#[test]
fn both_codecs_share_one_nesting_limit() {
    for depth in 1..=mneme_core::binary::MAX_DEPTH {
        for value in [nested_sequences(depth), nested_dictionaries(depth)] {
            let bytes = mneme_core::encode(&value);
            assert_eq!(mneme_core::decode(&bytes).expect("binary roundtrip"), value);
            let text = mneme_core::encode_document_string(&value);
            assert_eq!(
                mneme_core::decode_document(&text).expect("transport roundtrip"),
                value
            );
        }
    }

    for value in [
        nested_sequences(mneme_core::binary::MAX_DEPTH + 1),
        nested_dictionaries(mneme_core::binary::MAX_DEPTH + 1),
    ] {
        let error = mneme_core::decode(&mneme_core::encode(&value)).expect_err("binary depth");
        assert_eq!(error.code, mneme_core::ErrorCode::DepthLimitExceeded);
        let error = mneme_core::decode_document(&mneme_core::encode_document_string(&value))
            .expect_err("transport depth");
        assert_eq!(error.code, mneme_core::ErrorCode::DepthLimitExceeded);
    }
}

#[test]
fn over_deep_json_text_is_a_depth_diagnostic() {
    let mut text = String::from("{\"format\":");
    text.push_str(&format!("{:?}", mneme_core::transport::TRANSPORT_FORMAT));
    text.push_str(",\"version\":");
    text.push_str(&mneme_core::transport::TRANSPORT_VERSION.to_string());
    text.push_str(",\"value\":");
    for _ in 0..200 {
        text.push_str("{\"t\":\"embedded\",\"value\":");
    }
    text.push_str("{\"t\":\"bool\",\"v\":true}");
    for _ in 0..200 {
        text.push('}');
    }
    text.push('}');
    // The parser's own recursion error would claim malformed JSON; the depth
    // limit is reported instead.
    let error = mneme_core::decode_document(&text).expect_err("deep text");
    assert_eq!(error.code, mneme_core::ErrorCode::DepthLimitExceeded);
}

// CodecAudit-5: hexadecimal double bits have one lowercase spelling.
#[test]
fn double_bits_must_be_lowercase() {
    let path = mneme_core::Path::root();
    let upper = serde_json::json!({"t": "double", "bits": "3FF0000000000000"});
    let error = mneme_core::decode_value(&upper, &path).expect_err("uppercase bits");
    assert_eq!(error.code, mneme_core::ErrorCode::InvalidFloatBits);

    let lower = serde_json::json!({"t": "double", "bits": "3ff0000000000000"});
    let value = mneme_core::decode_value(&lower, &path).expect("lowercase bits");
    assert_eq!(value, mneme_core::Value::double(1.0));
    let encoded = mneme_core::encode_value(&value);
    assert_eq!(
        encoded.get("bits").and_then(serde_json::Value::as_str),
        Some("3ff0000000000000")
    );
}

// CodecAudit-7: canonical set and dictionary order is pinned by literal bytes.
#[test]
fn canonical_set_and_dictionary_order_is_pinned_by_bytes() {
    // `label` sorts after `evidence` by value but before it by encoded bytes
    // (length byte 05 before 08), so the goldens pin ordering by encoding.
    let dictionary = mneme_core::Value::dictionary([
        (
            mneme_core::Value::symbol("label"),
            mneme_core::Value::integer(1_i64),
        ),
        (
            mneme_core::Value::symbol("evidence"),
            mneme_core::Value::integer(2_i64),
        ),
    ]);
    assert_eq!(
        hex(&mneme_core::encode(&dictionary)),
        "b7b3056c6162656cb00101b30865766964656e6365b0010284"
    );

    // -1 sorts before 1 by value but after it by bytes (01 01 before 01 ff).
    let set = mneme_core::Value::set([
        mneme_core::Value::integer(-1_i64),
        mneme_core::Value::integer(1_i64),
    ]);
    assert_eq!(hex(&mneme_core::encode(&set)), "b6b00101b001ff84");

    assert_eq!(
        mneme_core::decode_canonical(&mneme_core::encode(&dictionary)).expect("dictionary"),
        dictionary
    );
    assert_eq!(
        mneme_core::decode_canonical(&mneme_core::encode(&set)).expect("set"),
        set
    );
}

// CodecAudit-8: the annotation limit counts annotations around one value.
#[test]
fn annotation_limit_counts_annotations_around_one_value() {
    // Each element carries one annotation: the document total is far above the
    // limit, but no single value is.
    let mut bytes = vec![0xB5_u8];
    for _ in 0..=mneme_core::binary::MAX_ANNOTATIONS {
        bytes.extend_from_slice(&[0x85, 0x80, 0x81]);
    }
    bytes.push(0x84);
    let value = mneme_core::decode(&bytes).expect("one annotation per element");
    assert_eq!(
        value.as_sequence().map(<[mneme_core::Value]>::len),
        Some(mneme_core::binary::MAX_ANNOTATIONS + 1)
    );

    // The same count around one value is refused at that value's path.
    let mut bytes = vec![0xB5_u8];
    for _ in 0..=mneme_core::binary::MAX_ANNOTATIONS {
        bytes.extend_from_slice(&[0x85, 0x80]);
    }
    bytes.extend_from_slice(&[0x81, 0x84]);
    let error = mneme_core::decode(&bytes).expect_err("annotation limit");
    assert_eq!(error.code, mneme_core::ErrorCode::AnnotationLimitExceeded);
    assert_eq!(error.path.to_string(), "$[0]");
}

// CodecAudit-6: record content cannot drive the terminal through diagnostics.
#[test]
fn symbol_rendering_escapes_control_and_bidi_characters() {
    let text = "safe\u{1b}[2J\u{1b}[31mFAKE OK\nvalid entity\u{202e}";
    // Symbol Display is the diagnostic path used by validation messages.
    let displayed = mneme_core::Symbol::from(text).to_string();
    assert_eq!(
        displayed,
        "|safe\\u001b[2J\\u001b[31mFAKE OK\\nvalid entity\\u202e|"
    );
    assert!(!displayed.contains('\u{1b}'));
    assert!(!displayed.contains('\n'));
    assert!(!displayed.contains('\u{202e}'));

    // The text renderer escapes the same way; printable symbols are unchanged.
    assert_eq!(
        mneme_core::text::render(&mneme_core::Value::symbol(text)),
        displayed
    );
    assert_eq!(
        mneme_core::text::render(&mneme_core::Value::symbol("plain-name")),
        "plain-name"
    );
    assert_eq!(
        mneme_core::text::render(&mneme_core::Value::symbol("two words")),
        "|two words|"
    );
    assert_eq!(
        mneme_core::text::render(&mneme_core::Value::symbol("z水")),
        "|z水|"
    );
}

#[test]
fn string_rendering_escapes_control_and_bidi_characters() {
    let text = "safe\u{1b}[2J\u{1b}[31mFAKE OK\nvalid entity\u{202e}";
    let rendered = mneme_core::text::render(&mneme_core::Value::string(text));
    assert_eq!(
        rendered,
        "\"safe\\u001b[2J\\u001b[31mFAKE OK\\nvalid entity\\u202e\""
    );
    assert!(!rendered.contains('\u{1b}'));
    assert!(!rendered.contains('\n'));
    assert!(!rendered.contains('\u{202e}'));

    // DEL and the C1 controls are escaped too, and printable text is unchanged.
    assert_eq!(
        mneme_core::text::render(&mneme_core::Value::string("a\u{7f}b\u{9b}c")),
        "\"a\\u007fb\\u009bc\""
    );
    assert_eq!(
        mneme_core::text::render(&mneme_core::Value::string("Cedar Notes")),
        "\"Cedar Notes\""
    );

    // A rendered string is a Preserves text string, whose escapes are the JSON
    // escapes: it parses back to the same text.
    assert_eq!(
        serde_json::from_str::<String>(&rendered).expect("string literal"),
        text
    );
}

#[test]
fn diagnostic_rendering_escapes_symbol_content() {
    // The audit's reproduction: a crafted record kind reaches the operator
    // through a validation diagnostic.
    let symbol = mneme_core::Symbol::from("x\u{1b}[2J\u{1b}[31mFAKE OK\nvalid entity");
    let diagnostic = mneme_core::Diagnostic::new(
        mneme_core::Stage::Envelope,
        mneme_core::ErrorCode::UnknownRecordKind,
        mneme_core::Path::root(),
        format!("unknown record kind {symbol}"),
    );
    let rendered = mneme_core::render_diagnostics(&[diagnostic]);
    assert!(!rendered.contains('\u{1b}'));
    assert!(!rendered.contains('\n'));
    assert!(rendered.contains("\\u001b[2J"));
    assert!(rendered.contains("FAKE OK"));
}
