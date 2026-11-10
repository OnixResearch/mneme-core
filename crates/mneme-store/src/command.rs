//! Commands submitted to the workspace coordinator.
//!
//! A command names its base revision, actor, scope, idempotency key, new record
//! revisions, exact source bytes, working-file publication intents, and external
//! import candidates. The normalized request digest binds actor, scope, and
//! content without including the caller's recorded time, which the coordinator
//! assigns.

use mneme_core::{
    ContentDigest, Payload, RecordEnvelope, RecordId, RecordKind, RecordedTime, RevisionId,
    ScopeId, Symbol, Value, WorkspaceRevisionId,
};

/// A record revision proposed for the next snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordDraft {
    pub schema_version: u32,
    pub kind: RecordKind,
    pub record_id: RecordId,
    pub revision_id: RevisionId,
    pub predecessor: Option<RevisionId>,
    pub scope: ScopeId,
    pub payload: Payload,
}

impl RecordDraft {
    /// Build the immutable envelope with coordinator-assigned recorded time.
    pub fn into_envelope(self, recorded: RecordedTime) -> RecordEnvelope {
        RecordEnvelope {
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

    fn request_value(&self) -> Value {
        Value::record_named(
            "draft-record",
            vec![
                Value::integer(i64::from(self.schema_version)),
                self.kind.to_value(),
                self.record_id.to_value(),
                self.revision_id.to_value(),
                match self.predecessor {
                    Some(revision) => revision.to_value(),
                    None => Value::symbol("none"),
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
    pub media_type: Symbol,
}

impl SourceBlobDraft {
    /// The raw-source digest of these bytes.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::of_source_bytes(&self.bytes)
    }
}

/// A working-file publication intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationDraft {
    /// Path relative to the workspace's `working/` directory.
    pub path: String,
    /// Exact digest expected in the working file before replacement.
    pub expected_previous: Option<ContentDigest>,
    /// Desired committed bytes.
    pub bytes: Vec<u8>,
}

impl PublicationDraft {
    /// The raw-source digest of the desired bytes.
    pub fn desired_digest(&self) -> ContentDigest {
        ContentDigest::of_source_bytes(&self.bytes)
    }

    fn request_value(&self) -> Value {
        Value::record_named(
            "publication",
            vec![
                Value::string(self.path.clone()),
                match self.expected_previous {
                    Some(digest) => digest.to_value(),
                    None => Value::symbol("none"),
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
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::of_source_bytes(&self.bytes)
    }

    fn request_value(&self) -> Value {
        Value::record_named(
            "import-candidate",
            vec![Value::string(self.path.clone()), self.digest().to_value()],
        )
    }
}

/// A complete mutation command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitCommand {
    pub base: WorkspaceRevisionId,
    pub actor: String,
    pub scope: ScopeId,
    pub idempotency_key: String,
    pub records: Vec<RecordDraft>,
    pub source_blobs: Vec<SourceBlobDraft>,
    pub publications: Vec<PublicationDraft>,
    pub import_candidates: Vec<ImportCandidateDraft>,
}

impl CommitCommand {
    /// The normalized command identity bound to actor and scope.
    pub fn request_digest(&self) -> ContentDigest {
        ContentDigest::of_payload(&self.request_value())
    }

    fn request_value(&self) -> Value {
        Value::record_named(
            "commit-request",
            vec![
                self.base.to_value(),
                Value::string(self.actor.clone()),
                self.scope.to_value(),
                Value::set(self.records.iter().map(RecordDraft::request_value)),
                Value::set(
                    self.source_blobs
                        .iter()
                        .map(|blob| blob.digest().to_value()),
                ),
                Value::set(
                    self.publications
                        .iter()
                        .map(PublicationDraft::request_value),
                ),
                Value::set(
                    self.import_candidates
                        .iter()
                        .map(ImportCandidateDraft::request_value),
                ),
            ],
        )
    }
}
