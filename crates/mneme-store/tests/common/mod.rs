//! Fixtures and helpers shared by the store integration-test binaries.
//
// `workspace.rs` and `facts.rs` cover different areas of the coordinator, so
// each binary uses a different subset of these helpers.
#![allow(dead_code)] // each test binary uses a subset of the shared helpers

pub fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

pub fn config(at: i64) -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(at),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

pub fn draft(envelope: &mneme_core::RecordEnvelope) -> mneme_store::RecordDraft {
    mneme_store::RecordDraft {
        schema_version: envelope.schema_version,
        kind: envelope.kind,
        record_id: envelope.record_id,
        revision_id: envelope.revision_id,
        predecessor: envelope.predecessor,
        scope: envelope.scope.clone(),
        payload: envelope.payload.clone(),
    }
}

pub fn fixture_command(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
) -> mneme_store::CommitCommand {
    mneme_store::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: scope(),
        idempotency_key: key.to_owned(),
        records: mneme_core::fixtures::fixture_batch()
            .iter()
            .map(draft)
            .collect(),
        source_blobs: vec![mneme_store::SourceBlobDraft {
            bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes().to_vec(),
            media_type: mneme_core::Symbol::from("text/asciidoc"),
        }],
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: None,
    }
}

pub fn open(root: &std::path::Path, at: i64) -> mneme_store::Workspace {
    mneme_store::Workspace::open(root, config(at)).expect("open workspace")
}

pub fn retained_source_record(
    record_id: mneme_core::RecordId,
    revision_id: mneme_core::RevisionId,
    scope: &mneme_core::ScopeId,
    bytes: &[u8],
    path: Option<&str>,
) -> mneme_store::RecordDraft {
    let retained = mneme_core::RetainedSource::new(
        mneme_core::ContentDigest::of_source_bytes(bytes),
        bytes.len() as u64,
        "text/asciidoc",
    )
    .expect("retained source");
    let mut entries = vec![
        (
            mneme_core::Symbol::from("content"),
            mneme_core::SourceContent::Retained(retained).to_value(),
        ),
        (
            mneme_core::Symbol::from("acquisition"),
            mneme_core::Value::symbol("authored"),
        ),
    ];
    if let Some(path) = path {
        entries.push((
            mneme_core::Symbol::from("path-hint"),
            mneme_core::Value::string(path),
        ));
    }
    mneme_store::RecordDraft {
        schema_version: 1,
        kind: mneme_core::RecordKind::SourceRevision,
        record_id,
        revision_id,
        predecessor: None,
        scope: scope.clone(),
        payload: mneme_core::Payload::new(entries),
    }
}

pub fn publication_command(
    base: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    key: &str,
    path: &str,
    bytes: &[u8],
) -> mneme_store::CommitCommand {
    mneme_store::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: key.to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: vec![mneme_store::PublicationDraft {
            path: path.to_owned(),
            expected_previous: None,
            bytes: bytes.to_vec(),
        }],
        import_candidates: Vec::new(),
        retention: None,
    }
}

#[allow(unknown_lints, too_many_parameters)] // every membership fixture passes the three target fields positionally
pub fn record_command(
    base: mneme_core::WorkspaceRevisionId,
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    blobs: Vec<mneme_store::SourceBlobDraft>,
    candidates: Vec<mneme_store::ImportCandidateDraft>,
) -> mneme_store::CommitCommand {
    mneme_store::CommitCommand {
        base,
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: blobs,
        publications: Vec::new(),
        import_candidates: candidates,
        retention: None,
    }
}

pub fn source_blob(bytes: &[u8]) -> mneme_store::SourceBlobDraft {
    mneme_store::SourceBlobDraft {
        bytes: bytes.to_vec(),
        media_type: mneme_core::Symbol::from("text/asciidoc"),
    }
}

pub fn forget_content_barrier(
    target: mneme_core::RecordId,
    bytes: &[u8],
    generation: u64,
    operation_id: &str,
) -> mneme_store::RetentionCommit {
    mneme_store::RetentionCommit {
        operation_id: operation_id.to_owned(),
        operation_kind: "forget".to_owned(),
        policy_version: "1".to_owned(),
        selectors: Vec::new(),
        suppressions: vec![mneme_store::RetentionSuppression {
            operation_id: operation_id.to_owned(),
            target,
            revision: None,
            target_kind: "source-revision".to_owned(),
            mode: mneme_store::SuppressionMode::Forgotten,
            content_digest: Some(mneme_core::ContentDigest::of_source_bytes(bytes)),
            generation,
        }],
        locations: Vec::new(),
        retained_metadata: Vec::new(),
    }
}

/// A barrier commit that carries only a retention plan.
pub fn audit_barrier_command(
    base: mneme_core::WorkspaceRevisionId,
    key: &str,
    retention: mneme_store::RetentionCommit,
) -> mneme_store::CommitCommand {
    mneme_store::CommitCommand {
        base,
        actor: "retention-author".to_owned(),
        scope: scope(),
        idempotency_key: key.to_owned(),
        records: Vec::new(),
        source_blobs: Vec::new(),
        publications: Vec::new(),
        import_candidates: Vec::new(),
        retention: Some(retention),
    }
}

pub fn audit_blob_location(
    location_kind: &str,
    digest: mneme_core::ContentDigest,
) -> mneme_store::RetentionLocationPlan {
    mneme_store::RetentionLocationPlan {
        location_id: format!("{location_kind}:{}", digest.to_hex()),
        location_kind: location_kind.to_owned(),
        locator: digest.to_hex(),
    }
}
