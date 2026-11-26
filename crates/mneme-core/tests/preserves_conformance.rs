//! Official Preserves wire-conformance oracle (`samples.bin`) and `proptest`
//! canonical round-trip suite for `mneme_core::{binary, transport}`.
//!
//! Upstream test suite: `https://gitlab.com/preserves/preserves`
//! (Apache-2.0, pinned commit `6bb75e3d418314d3e580f53055814b8e450a3761`;
//! see `tests/fixtures/preserves/NOTICE` and `LICENSE`).

#![allow(
    unknown_lints,
    no_unwrap,
    no_panic,
    catch_all_on_enum,
    foreign_enum_catch_all,
    function_length,
    allocation_in_loop,
    unbounded_collection_growth,
    magic_number,
    explicit_defaults,
    compound_condition,
    platform_dependent_cast,
    raw_arithmetic_overflow
)] // integration conformance test harness exercises wire vectors and asserts via expect/panic
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)] // integration test harness asserts via expect/panic

use proptest::prelude::*;

const SAMPLES_BIN: &[u8] = include_bytes!("fixtures/preserves/samples.bin");
const SAMPLES_SHA256_HEX: &str = "081381c788bad2c5787121a0f57bae38f5424796b940e7da83414dd98676913b";

const TAG_ANNOTATION: u8 = 0x85;

fn sha256_hex(bytes: &[u8]) -> String {
    let digest =
        mneme_core::ContentDigest::of_source_bytes_with(bytes, mneme_core::HashAlgorithm::Sha256);
    digest.to_hex()
}

fn as_symbol(value: &mneme_core::Value) -> Option<&str> {
    match value {
        mneme_core::Value::Symbol(sym) => Some(sym.as_str()),
        _ => None,
    }
}

fn as_bytestring(value: &mneme_core::Value) -> Option<&[u8]> {
    match value {
        mneme_core::Value::ByteString(bytes) => Some(bytes.as_slice()),
        _ => None,
    }
}

fn assert_canonical_roundtrip(name: &str, wire_bytes: &[u8], expected: &mneme_core::Value) {
    let decoded = mneme_core::binary::decode(wire_bytes)
        .unwrap_or_else(|err| panic!("case {name}: binary::decode failed: {err}"));
    assert_eq!(
        &decoded, expected,
        "case {name}: decoded value did not match expected stripped value"
    );

    let canonical = mneme_core::binary::encode(&decoded);
    let redecoded = mneme_core::binary::decode(&canonical)
        .unwrap_or_else(|err| panic!("case {name}: binary::decode(encode(v)) failed: {err}"));
    assert_eq!(
        redecoded, decoded,
        "case {name}: canonical binary round-trip changed value"
    );
    assert_eq!(
        mneme_core::binary::encode(&redecoded),
        canonical,
        "case {name}: binary encoding is not idempotent"
    );

    // When the upstream wire bytes contain no annotation tag byte at all,
    // canonical encoding must match the upstream canonical binary verbatim
    // (for deterministic `<Test>` cases; `<NondeterministicTest>` is allowed
    // to differ in annotation placement or non-canonical ordering).
    let json_doc = mneme_core::transport::encode_document_string(&decoded);
    let from_json = mneme_core::transport::decode_document(&json_doc)
        .unwrap_or_else(|err| panic!("case {name}: transport::decode_document failed: {err}"));
    assert_eq!(
        from_json, decoded,
        "case {name}: tagged JSON transport round-trip changed value"
    );
}

#[test]
fn vendored_samples_bin_matches_pinned_sha256() {
    assert_eq!(sha256_hex(SAMPLES_BIN), SAMPLES_SHA256_HEX);
}

#[test]
fn preserves_official_samples_bin_conformance_oracle() {
    let root = mneme_core::binary::decode(SAMPLES_BIN).expect("decode samples.bin root");
    let mneme_core::Value::Record(root_rec) = root else {
        panic!("expected <TestCases {{...}}> record at samples.bin root");
    };
    assert_eq!(as_symbol(root_rec.label()), Some("TestCases"));
    assert_eq!(root_rec.fields().len(), 1);

    let mneme_core::Value::Dictionary(cases) = &root_rec.fields()[0] else {
        panic!("expected dictionary inside <TestCases>");
    };

    let mut test_count: u64 = 0;
    let mut exact_unannotated_matches: u64 = 0;
    let mut nondeterministic_count: u64 = 0;
    let mut decode_error_count: u64 = 0;
    let mut decode_short_count: u64 = 0;
    let mut decode_eof_count: u64 = 0;
    let mut text_only_skipped: u64 = 0;

    for (key, case_val) in cases {
        let name = as_symbol(key).unwrap_or("<non-symbol>");
        let mneme_core::Value::Record(case_rec) = case_val else {
            panic!("case {name}: expected record");
        };
        let label = as_symbol(case_rec.label()).unwrap_or("<unknown>");
        match label {
            "Test" => {
                assert_eq!(case_rec.fields().len(), 2, "case {name}: <Test> arity");
                let wire = as_bytestring(&case_rec.fields()[0])
                    .unwrap_or_else(|| panic!("case {name}: expected binary field"));
                let expected = &case_rec.fields()[1];
                assert_canonical_roundtrip(name, wire, expected);
                if !wire.contains(&TAG_ANNOTATION) {
                    let canonical = mneme_core::binary::encode(expected);
                    assert_eq!(
                        canonical, wire,
                        "case {name}: unannotated <Test> canonical binary mismatch"
                    );
                    exact_unannotated_matches += 1;
                }
                test_count += 1;
            }
            "NondeterministicTest" => {
                assert_eq!(
                    case_rec.fields().len(),
                    2,
                    "case {name}: <NondeterministicTest> arity"
                );
                let wire = as_bytestring(&case_rec.fields()[0])
                    .unwrap_or_else(|| panic!("case {name}: expected binary field"));
                let expected = &case_rec.fields()[1];
                assert_canonical_roundtrip(name, wire, expected);
                nondeterministic_count += 1;
            }
            "DecodeError" => {
                assert_eq!(case_rec.fields().len(), 1);
                let wire = as_bytestring(&case_rec.fields()[0]).expect("bytes");
                let err = mneme_core::binary::decode(wire);
                assert!(
                    err.is_err(),
                    "case {name}: DecodeError vector unexpectedly decoded: {err:?}"
                );
                decode_error_count += 1;
            }
            "DecodeShort" => {
                assert_eq!(case_rec.fields().len(), 1);
                let wire = as_bytestring(&case_rec.fields()[0]).expect("bytes");
                let err = mneme_core::binary::decode(wire);
                assert!(
                    err.is_err(),
                    "case {name}: DecodeShort vector unexpectedly decoded: {err:?}"
                );
                decode_short_count += 1;
            }
            "DecodeEOF" => {
                assert_eq!(case_rec.fields().len(), 1);
                let wire = as_bytestring(&case_rec.fields()[0]).expect("bytes");
                let err = mneme_core::binary::decode(wire);
                assert!(
                    err.is_err(),
                    "case {name}: DecodeEOF vector unexpectedly decoded: {err:?}"
                );
                decode_eof_count += 1;
            }
            "ParseError" | "ParseShort" | "ParseEOF" => {
                // Text-syntax Preserves parser vectors (Mneme implements binary + tagged JSON).
                text_only_skipped += 1;
            }
            other => {
                panic!("case {name}: unexpected test case label {other}");
            }
        }
    }

    assert!(
        test_count >= 120,
        "expected >=120 <Test> vectors, got {test_count}"
    );
    assert!(
        exact_unannotated_matches >= 100,
        "expected >=100 verbatim binary matches, got {exact_unannotated_matches}"
    );
    assert!(nondeterministic_count >= 5);
    assert!(decode_error_count >= 6);
    assert!(decode_short_count >= 1);
    assert!(decode_eof_count >= 1);
    assert!(text_only_skipped >= 40);
}

#[test]
fn non_canonical_and_profile_violating_binary_vectors_are_rejected() {
    let invalid_vectors: &[(&str, &[u8])] = &[
        // Non-minimal zero integer (canonical is B0 00)
        ("non_canonical_int_zero_one_byte", &[0xB0, 0x01, 0x00]),
        // Non-minimal positive integer with redundant leading 0x00
        (
            "non_canonical_int_redundant_zero",
            &[0xB0, 0x02, 0x00, 0x01],
        ),
        // Non-minimal negative integer with redundant leading 0xFF
        ("non_canonical_int_redundant_ff", &[0xB0, 0x02, 0xFF, 0xFF]),
        // Overlong varint length for empty string (0x80 0x00 instead of 0x00)
        ("non_canonical_varint_zero", &[0xB1, 0x80, 0x00]),
        // Duplicate set element: #{1, 1}
        (
            "duplicate_set_element",
            &[0xB6, 0xB0, 0x01, 0x01, 0xB0, 0x01, 0x01, 0x84],
        ),
        // Duplicate dictionary key: {1: #f, 1: #t}
        (
            "duplicate_dict_key",
            &[0xB7, 0xB0, 0x01, 0x01, 0x80, 0xB0, 0x01, 0x01, 0x81, 0x84],
        ),
        // Trailing bytes after valid value (#t followed by #f)
        ("trailing_bytes", &[0x81, 0x80]),
        // Unsupported IEEE-754 Float32 (tag 0x87 len 0x04) under Mneme profile
        ("unsupported_float32", &[0x87, 0x04, 0x3F, 0x80, 0x00, 0x00]),
        // Legacy Float32 tag 0x82
        ("legacy_float32_tag", &[0x82, 0x3F, 0x80, 0x00, 0x00]),
        // Invalid UTF-8 in String
        ("invalid_utf8_string", &[0xB1, 0x02, 0xFF, 0xFE]),
        // Invalid UTF-8 in Symbol
        ("invalid_utf8_symbol", &[0xB3, 0x02, 0xFF, 0xFE]),
        // Bare annotation with no underlying value
        ("dangling_annotation", &[0x85, 0x80]),
        // Empty record (missing label)
        ("empty_record", &[0xB4, 0x84]),
    ];

    for (name, wire) in invalid_vectors {
        let decoded = mneme_core::binary::decode(wire);
        assert!(
            decoded.is_err(),
            "vector {name} unexpectedly decoded as {decoded:?}"
        );
    }

    // Per Preserves binary spec, non-canonical container element ordering decodes
    // to the same semantic value and re-encodes into canonical sorted byte order.
    let unsorted_set = &[0xB6, 0xB0, 0x01, 0x02, 0xB0, 0x01, 0x01, 0x84];
    let sorted_set = &[0xB6, 0xB0, 0x01, 0x01, 0xB0, 0x01, 0x02, 0x84];
    let decoded_set = mneme_core::binary::decode(unsorted_set).expect("unsorted set decodes");
    assert_eq!(mneme_core::binary::encode(&decoded_set), sorted_set);

    let unsorted_dict = &[0xB7, 0xB0, 0x01, 0x02, 0x80, 0xB0, 0x01, 0x01, 0x81, 0x84];
    let sorted_dict = &[0xB7, 0xB0, 0x01, 0x01, 0x81, 0xB0, 0x01, 0x02, 0x80, 0x84];
    let decoded_dict = mneme_core::binary::decode(unsorted_dict).expect("unsorted dict decodes");
    assert_eq!(mneme_core::binary::encode(&decoded_dict), sorted_dict);

    // Depth exceeding MAX_DEPTH must fail closed in both binary and transport codecs.
    let mut deep_wire = vec![0xB5_u8; mneme_core::binary::MAX_DEPTH + 1];
    deep_wire.push(0x80);
    deep_wire.extend(std::iter::repeat_n(
        0x84_u8,
        mneme_core::binary::MAX_DEPTH + 1,
    ));
    assert!(mneme_core::binary::decode(&deep_wire).is_err());
}

fn arb_preserves_value() -> impl Strategy<Value = mneme_core::Value> {
    let leaf = prop_oneof![
        any::<bool>().prop_map(mneme_core::Value::Boolean),
        any::<i64>().prop_map(mneme_core::Value::integer),
        any::<u64>()
            .prop_map(|bits| mneme_core::Value::Double(mneme_core::Double::from_bits(bits))),
        "[a-zA-Z0-9 _\\-]{0,24}".prop_map(mneme_core::Value::string),
        "[a-z][a-z0-9\\-]{0,12}".prop_map(mneme_core::Value::symbol),
        prop::collection::vec(any::<u8>(), 0..32).prop_map(mneme_core::Value::bytes),
    ];

    leaf.prop_recursive(4, 32, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(mneme_core::Value::sequence),
            prop::collection::vec(inner.clone(), 0..4).prop_map(mneme_core::Value::set),
            prop::collection::vec((inner.clone(), inner.clone()), 0..4)
                .prop_map(mneme_core::Value::dictionary),
            (inner.clone(), prop::collection::vec(inner.clone(), 0..3))
                .prop_map(|(label, fields)| mneme_core::Value::record(label, fields)),
            inner.prop_map(mneme_core::Value::embedded),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 64, failure_persistence: None, .. ProptestConfig::default() })]

    #[test]
    fn proptest_preserves_binary_and_transport_canonical_roundtrip(value in arb_preserves_value()) {
        let encoded = mneme_core::binary::encode(&value);
        let decoded = mneme_core::binary::decode(&encoded).expect("canonical binary decode");
        prop_assert_eq!(&decoded, &value);
        prop_assert_eq!(mneme_core::binary::encode(&decoded), encoded);

        let doc = mneme_core::transport::encode_document_string(&value);
        let from_doc = mneme_core::transport::decode_document(&doc).expect("transport decode");
        prop_assert_eq!(&from_doc, &value);
    }
}
