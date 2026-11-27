//! Unit and cross-format tests for typed Preserves reproducibility receipts,
//! oracle verdicts, signed receipt envelopes, erasure compliance receipts,
//! and BLAKE3 source-tree Merkle roots.

#[test]
fn reproducibility_receipt_and_oracle_verdict_round_trip() -> Result<(), Box<dyn std::error::Error>>
{
    let receipt = mneme_core::ReproducibilityReceipt {
        subject_digest: "aa".repeat(32),
        git_rev: "6a6c0bf8".to_owned(),
        flake_lock_digest: "bb".repeat(32),
        command_spec_digest: "cc".repeat(32),
        seed_class: "deterministic".to_owned(),
        boundary_conditions: vec!["no-std".to_owned(), "lean-4.35.0".to_owned()],
        outcome: "verified".to_owned(),
        metrics_digest: "dd".repeat(32),
    };
    let encoded_receipt = receipt.to_value();
    let decoded_receipt = mneme_core::ReproducibilityReceipt::from_value(&encoded_receipt)?;
    assert_eq!(decoded_receipt, receipt);
    let canonical = receipt.canonical_bytes();
    let decoded_canonical = mneme_core::binary::decode_canonical(&canonical)?;
    assert_eq!(
        mneme_core::ReproducibilityReceipt::from_value(&decoded_canonical)?,
        receipt
    );

    let verdict = mneme_core::OracleVerdict {
        tool: "just-proofs".to_owned(),
        target: "crates/mneme-kernel".to_owned(),
        outcome: "verified".to_owned(),
        artifact_digest: "aa".repeat(32),
        toolchain_digest: "bb".repeat(32),
        eval_rev: "6a6c0bf8".to_owned(),
        receipt: Some(receipt),
    };
    let encoded_verdict = verdict.to_value();
    let decoded_verdict = mneme_core::OracleVerdict::from_value(&encoded_verdict)?;
    assert_eq!(decoded_verdict, verdict);
    Ok(())
}

#[test]
fn signed_receipt_envelope_and_erasure_receipt_round_trip() -> Result<(), Box<dyn std::error::Error>>
{
    let erasure = mneme_core::ErasureComplianceReceipt {
        operation_id: "ret-op-42".to_owned(),
        eligibility_generation: 7,
        erased_count: 19,
        manifest_digest: "11".repeat(32),
        workspace_revision: "22".repeat(16),
    };
    let payload_bytes = erasure.canonical_bytes();
    let envelope = mneme_core::SignedReceiptEnvelope {
        schema: mneme_core::ERASURE_COMPLIANCE_RECEIPT_FORMAT.to_owned(),
        canonical_payload: payload_bytes,
        public_key: [0x33; 32],
        signature: [0x44; 64],
    };
    let encoded = envelope.to_value();
    let decoded = mneme_core::SignedReceiptEnvelope::from_value(&encoded)?;
    assert_eq!(decoded, envelope);
    let inner = decoded.decode_payload()?;
    let decoded_erasure = mneme_core::ErasureComplianceReceipt::from_value(&inner)?;
    assert_eq!(decoded_erasure, erasure);
    Ok(())
}

#[test]
fn source_tree_merkle_root_is_order_independent_and_tamper_sensitive()
-> Result<(), Box<dyn std::error::Error>> {
    let a = ("crates/mneme-kernel/src/a.rs", b"pub fn a() {}".as_slice());
    let b = ("crates/mneme-kernel/src/b.rs", b"pub fn b() {}".as_slice());
    let c = ("proofs/kernel/inventory.json", b"{}".as_slice());

    let root_abc = mneme_core::compute_source_tree_merkle_root(&[a, b, c]);
    let root_cba = mneme_core::compute_source_tree_merkle_root(&[c, b, a]);
    assert_eq!(root_abc, root_cba);

    let tampered_b = ("crates/mneme-kernel/src/b.rs", b"pub fn b() { }".as_slice());
    let root_tampered = mneme_core::compute_source_tree_merkle_root(&[a, tampered_b, c]);
    assert_ne!(root_abc, root_tampered);

    let hex = mneme_core::encode_hex_bytes(&root_abc);
    let roundtrip = mneme_core::decode_hex_32(&hex)?;
    assert_eq!(roundtrip, root_abc);
    Ok(())
}
