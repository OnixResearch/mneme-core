//! Helpers shared by the evidence-memory integration tests.

pub fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

pub fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

pub fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(1_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

pub fn engine(workspace: &mut mneme_store::Workspace) -> mneme_memory::Engine<'_> {
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
}

pub fn batch(
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    sources: Vec<mneme_store::SourceBlobDraft>,
) -> mneme_memory::Batch {
    batch_in(&scope(), key, records, sources)
}

pub fn batch_in(
    scope: &mneme_core::ScopeId,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    sources: Vec<mneme_store::SourceBlobDraft>,
) -> mneme_memory::Batch {
    mneme_memory::Batch {
        actor: "test-author".to_owned(),
        scope: scope.clone(),
        idempotency_key: key.to_owned(),
        records,
        source_blobs: sources,
        publications: Vec::new(),
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

pub const SOURCE_ID: mneme_core::RecordId = mneme_core::RecordId::from_bytes([0x02; 16]);
pub const SOURCE_REV: mneme_core::RevisionId = mneme_core::RevisionId::from_bytes([0x52; 16]);

pub fn setup() -> (tempfile::TempDir, mneme_store::Workspace) {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config()).expect("create");
    {
        let mut memory = engine(&mut workspace);
        memory
            .commit(batch(
                "entity",
                vec![draft(&mneme_core::fixtures::entity())],
                Vec::new(),
            ))
            .expect("entity");
        let (source, blob) = mneme_memory::build_source(
            SOURCE_ID,
            SOURCE_REV,
            &scope(),
            mneme_memory::SourceOptions {
                bytes: mneme_core::fixtures::SOURCE_TEXT.as_bytes(),
                media_type: "text/asciidoc",
                entity: Some(mneme_core::fixtures::entity_id()),
                path_hint: Some("project.adoc"),
            },
        )
        .expect("source");
        memory
            .commit(batch("source", vec![source], vec![blob]))
            .expect("source commit");
    }
    (temp, workspace)
}

pub fn latest(
    workspace: &mneme_store::Workspace,
    record: mneme_core::RecordId,
) -> mneme_core::RecordEnvelope {
    workspace
        .record_revisions(record)
        .expect("history")
        .last()
        .cloned()
        .expect("revision")
}

pub struct ProposalInput<'a> {
    pub evidence_id: mneme_core::RecordId,
    pub evidence_revision: mneme_core::RevisionId,
    pub assertion_id: mneme_core::RecordId,
    pub assertion_revision: mneme_core::RevisionId,
    pub predicate: &'a str,
    pub value: mneme_core::Value,
    pub stance: mneme_memory::Stance,
    pub valid_time: mneme_core::ValidTime,
    pub span: Option<mneme_core::SourceSpan>,
    pub ancestry: &'a [mneme_core::Reference],
    pub extraction: Option<(&'a str, &'a str)>,
}

pub fn propose(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    scope: &mneme_core::ScopeId,
    input: ProposalInput<'_>,
) -> mneme_core::RecordId {
    let ProposalInput {
        evidence_id,
        evidence_revision,
        assertion_id,
        assertion_revision,
        predicate,
        value,
        stance,
        valid_time,
        span,
        ancestry,
        extraction,
    } = input;
    let evidence = mneme_memory::build_evidence(
        evidence_id,
        evidence_revision,
        scope,
        mneme_memory::EvidenceOptions {
            assertion: assertion_id,
            source: SOURCE_ID,
            source_revision: SOURCE_REV,
            span,
            anchor: Some("storage-decision"),
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::AuthoredStatement,
            ancestry,
        },
    );
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        assertion_revision,
        scope,
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate,
            value,
            stance,
            origin: if extraction.is_some() {
                mneme_core::Origin::ModelExtraction
            } else {
                mneme_core::Origin::AuthoredStatement
            },
            asserted_by: "synthetic author",
            valid_time,
            evidence: &[mneme_core::Reference::local(
                evidence_id,
                mneme_core::RecordKind::Evidence,
            )],
            extraction,
            superseded_by: None,
        },
    );
    {
        let mut memory = engine(workspace);
        memory
            .commit(batch_in(scope, key, vec![evidence, assertion], Vec::new()))
            .expect("proposal commit");
    }
    assertion_id
}

pub struct BareProposalInput<'a> {
    pub assertion_id: mneme_core::RecordId,
    pub assertion_revision: mneme_core::RevisionId,
    pub predicate: &'a str,
    pub value: mneme_core::Value,
}

pub fn propose_bare(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    scope: &mneme_core::ScopeId,
    input: BareProposalInput<'_>,
) -> mneme_core::RecordId {
    let BareProposalInput {
        assertion_id,
        assertion_revision,
        predicate,
        value,
    } = input;
    let assertion = mneme_memory::build_proposed_assertion(
        assertion_id,
        assertion_revision,
        scope,
        mneme_memory::ProposedAssertionOptions {
            subject: mneme_core::fixtures::entity_id(),
            predicate,
            value,
            stance: mneme_memory::Stance::Affirm,
            origin: mneme_core::Origin::AuthoredStatement,
            asserted_by: "author",
            valid_time: mneme_core::ValidTime::always(),
            evidence: &[],
            extraction: None,
            superseded_by: None,
        },
    );
    let mut memory = engine(workspace);
    memory
        .commit(batch_in(scope, key, vec![assertion], Vec::new()))
        .expect("bare proposal");
    assertion_id
}

pub fn project_scope(name: &str) -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, name).expect("project scope")
}

pub fn hypothesis_scope(name: &str) -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Hypothesis, name).expect("hypothesis scope")
}
