//! Projection of typed `OracleVerdict` / `ReproducibilityReceipt` episodes into
//! canonical Datalog `verdict/6` (`verdict(V, Target, Outcome, ArtifactDigest,
//! ToolchainDigest, EvalRev)`).

const VERDICT_ARITY: usize = 6;
const LOCAL_REF_LABEL: &str = "local-ref";
const RECORD_ID_LABEL: &str = "record-id";

/// Extract the 6 canonical `verdict/6` terms from an `oracle_verdict` [`mneme_core::RecordEnvelope`].
///
/// Returns `None` for episodes that are not oracle verdicts.
pub(crate) fn extract_terms(record: &mneme_core::RecordEnvelope) -> Option<Vec<mneme_core::Value>> {
    if record.kind != mneme_core::RecordKind::Episode {
        return None;
    }
    let typed_verdict = record
        .payload
        .get("oracle-verdict")
        .and_then(|val| mneme_core::OracleVerdict::from_value(val).ok());
    let typed_receipt = record
        .payload
        .get("reproducibility-receipt")
        .and_then(|val| mneme_core::ReproducibilityReceipt::from_value(val).ok())
        .or_else(|| typed_verdict.as_ref().and_then(|v| v.receipt.clone()));
    let is_oracle_episode = record
        .payload
        .get("episode-type")
        .and_then(mneme_core::Value::as_symbol)
        .is_some_and(|sym| sym.as_str() == "oracle_verdict");
    if !is_oracle_episode && typed_verdict.is_none() && typed_receipt.is_none() {
        return None;
    }

    let target = extract_target(record, typed_verdict.as_ref());
    let outcome_text = extract_outcome(record, typed_verdict.as_ref(), typed_receipt.as_ref())?;
    let artifact_digest =
        extract_artifact_digest(record, typed_verdict.as_ref(), typed_receipt.as_ref());
    let toolchain_digest =
        extract_toolchain_digest(record, typed_verdict.as_ref(), typed_receipt.as_ref());
    let eval_rev = extract_eval_rev(record, typed_verdict.as_ref(), typed_receipt.as_ref());

    let terms = vec![
        record.record_id.to_value(),
        target,
        mneme_core::Value::symbol(outcome_text),
        mneme_core::Value::string(artifact_digest),
        mneme_core::Value::string(toolchain_digest),
        mneme_core::Value::string(eval_rev),
    ];
    debug_assert_eq!(terms.len(), VERDICT_ARITY);
    Some(terms)
}

fn extract_target(
    record: &mneme_core::RecordEnvelope,
    typed_verdict: Option<&mneme_core::OracleVerdict>,
) -> mneme_core::Value {
    for key in ["target-entity", "target"] {
        if let Some(value) = record.payload.get(key)
            && let Some(id_val) = extract_record_id_value(value)
        {
            return id_val;
        }
    }
    if let Some(ov) = typed_verdict {
        if let Ok(id) = mneme_core::RecordId::from_hex(&ov.target) {
            return id.to_value();
        }
        if !ov.target.is_empty() {
            return mneme_core::Value::string(ov.target.clone());
        }
    }
    if let Some(file) = record
        .payload
        .get("target-file")
        .and_then(mneme_core::Value::as_string)
    {
        return mneme_core::Value::string(file.to_owned());
    }
    mneme_core::Value::symbol("unbound")
}

fn extract_record_id_value(value: &mneme_core::Value) -> Option<mneme_core::Value> {
    let mut current = value;
    for _ in 0..2 {
        let rec = current.as_record()?;
        let label = rec.label().as_symbol()?.as_str();
        if label == RECORD_ID_LABEL && rec.fields().len() == 1 {
            return Some(current.clone());
        }
        if label == LOCAL_REF_LABEL
            && let Some(first) = rec.fields().first()
        {
            current = first;
            continue;
        }
        return None;
    }
    None
}

fn extract_outcome(
    record: &mneme_core::RecordEnvelope,
    typed_verdict: Option<&mneme_core::OracleVerdict>,
    typed_receipt: Option<&mneme_core::ReproducibilityReceipt>,
) -> Option<String> {
    if let Some(ov) = typed_verdict
        && !ov.outcome.is_empty()
    {
        return Some(ov.outcome.clone());
    }
    if let Some(receipt) = typed_receipt
        && !receipt.outcome.is_empty()
    {
        return Some(receipt.outcome.clone());
    }
    let val = record.payload.get("verdict")?;
    if let Some(sym) = val.as_symbol() {
        return Some(sym.as_str().to_owned());
    }
    val.as_string().map(str::to_owned)
}

fn extract_artifact_digest(
    record: &mneme_core::RecordEnvelope,
    typed_verdict: Option<&mneme_core::OracleVerdict>,
    typed_receipt: Option<&mneme_core::ReproducibilityReceipt>,
) -> String {
    if let Some(ov) = typed_verdict
        && !ov.artifact_digest.is_empty()
    {
        return ov.artifact_digest.clone();
    }
    if let Some(receipt) = typed_receipt
        && !receipt.subject_digest.is_empty()
    {
        return receipt.subject_digest.clone();
    }
    record
        .payload
        .get("subject-digest")
        .and_then(mneme_core::Value::as_string)
        .unwrap_or("")
        .to_owned()
}

fn extract_toolchain_digest(
    record: &mneme_core::RecordEnvelope,
    typed_verdict: Option<&mneme_core::OracleVerdict>,
    typed_receipt: Option<&mneme_core::ReproducibilityReceipt>,
) -> String {
    if let Some(ov) = typed_verdict
        && !ov.toolchain_digest.is_empty()
    {
        return ov.toolchain_digest.clone();
    }
    if let Some(receipt) = typed_receipt
        && !receipt.flake_lock_digest.is_empty()
    {
        return receipt.flake_lock_digest.clone();
    }
    record
        .payload
        .get("flake-lock-digest")
        .and_then(mneme_core::Value::as_string)
        .unwrap_or("")
        .to_owned()
}

fn extract_eval_rev(
    record: &mneme_core::RecordEnvelope,
    typed_verdict: Option<&mneme_core::OracleVerdict>,
    typed_receipt: Option<&mneme_core::ReproducibilityReceipt>,
) -> String {
    if let Some(ov) = typed_verdict
        && !ov.eval_rev.is_empty()
    {
        return ov.eval_rev.clone();
    }
    if let Some(receipt) = typed_receipt
        && !receipt.git_rev.is_empty()
    {
        return receipt.git_rev.clone();
    }
    record
        .payload
        .get("git-rev")
        .and_then(mneme_core::Value::as_string)
        .unwrap_or("")
        .to_owned()
}
