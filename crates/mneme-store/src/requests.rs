//! Commands submitted to the workspace coordinator.
//!
//! A command names its base revision, actor, scope, idempotency key, new record
//! revisions, exact source bytes, working-file publication intents, and external
//! import candidates. The normalized request digest binds actor, scope, and
//! content without including the caller's recorded time, which the coordinator
//! assigns.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A record revision proposed for the next snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordDraft {
    pub schema_version: u32,
    pub kind: mneme_core::RecordKind,
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub predecessor: Option<mneme_core::RevisionId>,
    pub scope: mneme_core::ScopeId,
    pub payload: mneme_core::Payload,
}

impl RecordDraft {
    /// Build the immutable envelope with coordinator-assigned recorded time.
    pub fn into_envelope(self, recorded: mneme_core::RecordedTime) -> mneme_core::RecordEnvelope {
        mneme_core::RecordEnvelope {
            schema_version: self.schema_version,
            kind: self.kind,
            record_id: self.record_id,
            revision_id: self.revision_id,
            predecessor: self.predecessor,
            scope: self.scope,
            recorded,
            payload: self.payload,
        }
    }

    fn request_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "draft-record",
            vec![
                mneme_core::Value::integer(i64::from(self.schema_version)),
                self.kind.to_value(),
                self.record_id.to_value(),
                self.revision_id.to_value(),
                match self.predecessor {
                    Some(revision) => revision.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                self.scope.to_value(),
                self.payload.to_value(),
            ],
        )
    }
}

/// Exact source bytes supplied for a committed source revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceBlobDraft {
    pub bytes: Vec<u8>,
    pub media_type: mneme_core::Symbol,
}

impl SourceBlobDraft {
    /// The raw-source digest of these bytes.
    pub fn digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_source_bytes(&self.bytes)
    }
}

/// A working-file publication intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationDraft {
    /// Path relative to the workspace's `working/` directory.
    pub path: String,
    /// Exact digest expected in the working file before replacement.
    pub expected_previous: Option<mneme_core::ContentDigest>,
    /// Desired committed bytes.
    pub bytes: Vec<u8>,
}

impl PublicationDraft {
    /// The raw-source digest of the desired bytes.
    pub fn desired_digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_source_bytes(&self.bytes)
    }

    fn request_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "publication",
            vec![
                mneme_core::Value::string(self.path.clone()),
                match self.expected_previous {
                    Some(digest) => digest.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                self.desired_digest().to_value(),
            ],
        )
    }
}

/// An externally edited file offered for import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportCandidateDraft {
    /// Path relative to `working/`.
    pub path: String,
    /// Exact candidate bytes observed by the importer.
    pub bytes: Vec<u8>,
}

impl ImportCandidateDraft {
    /// The raw-source digest of the candidate bytes.
    pub fn digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_source_bytes(&self.bytes)
    }

    fn request_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "import-candidate",
            vec![
                mneme_core::Value::string(self.path.clone()),
                self.digest().to_value(),
            ],
        )
    }
}

/// A complete mutation command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitCommand {
    pub base: mneme_core::WorkspaceRevisionId,
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub idempotency_key: String,
    pub records: Vec<RecordDraft>,
    pub source_blobs: Vec<SourceBlobDraft>,
    pub publications: Vec<PublicationDraft>,
    pub import_candidates: Vec<ImportCandidateDraft>,
    /// An atomically committed retention barrier and cleanup plan.
    pub retention: Option<crate::lifecycle::RetentionCommit>,
}

impl CommitCommand {
    /// The normalized command identity bound to actor and scope.
    pub fn request_digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_payload(&self.request_value())
    }

    fn request_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "commit-request",
            vec![
                self.base.to_value(),
                mneme_core::Value::string(self.actor.clone()),
                self.scope.to_value(),
                mneme_core::Value::set(self.records.iter().map(RecordDraft::request_value)),
                mneme_core::Value::set(
                    self.source_blobs
                        .iter()
                        .map(|blob| blob.digest().to_value()),
                ),
                mneme_core::Value::set(
                    self.publications
                        .iter()
                        .map(PublicationDraft::request_value),
                ),
                mneme_core::Value::set(
                    self.import_candidates
                        .iter()
                        .map(ImportCandidateDraft::request_value),
                ),
                match &self.retention {
                    Some(retention) => retention.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
            ],
        )
    }
}
