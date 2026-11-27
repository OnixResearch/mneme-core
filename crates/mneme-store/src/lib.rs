//! Mneme's durable workspace.
//!
//! The store owns the SQLite ledger, immutable content-addressed blobs, one
//! serialized commit coordinator, base-revision compare-and-swap, scoped
//! idempotency, publication intents, and startup recovery. It consumes
//! `mneme-core` records and never duplicates their schema or transport policy.

#![allow(unknown_lints, module_file_count, type_accumulation)] // intentional top-level store module layout and public re-exports
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod catalog;
pub mod coordinator;
pub mod dedup;
pub mod error;
pub mod injectors;
pub mod keytree;
pub mod lifecycle;
pub mod outboard;
pub mod payload;
pub mod portability;
pub mod requests;
pub mod timekeeper;
#[cfg(feature = "trace-spec")]
pub mod trace;

pub use catalog::{Manifest, ManifestRecord};
pub use coordinator::verify::{
    IssueKind, OrphanBlob, OrphanReason, VerifyIssue, VerifyMode, VerifyReport, verify_workspace,
};
pub use coordinator::{
    CommitOutcome, ConsistencyProof, DocumentMetadata, DocumentQuery, EntityMetadata, EntityQuery,
    FOLDER_WORKSPACE_DIRECTORY, HistoryTreeDb, HistoryTreeHead, InclusionProof, JobClaim,
    LAYOUT_VERSION, LEDGER_FILE, MAX_METADATA_PAGE_SIZE, MergeDecisionPresence, MetadataPage,
    ProjectionRegistration, ProjectionResolution, ProjectionState, PublicationOutcome,
    PublicationState, RecordRevisionCommit, RecordRevisionCommitPage, RecoveryReport,
    RelationMetadata, RelationQuery, RevisionCommit, RevisionDelta, SharedRecordCache, Snapshot,
    Workspace, WorkspaceConfig, WorkspaceStatus, digest_to_kernel, hash_history_interior,
    hash_history_leaf,
};
pub use dedup::{BlobChunking, FastCdcConfig};
pub use error::{Failure, Result};
pub use injectors::{FaultAt, FaultInjector, FaultPoint, NoFaults};
pub use keytree::{KeyPunctureBarrier, PuncturableTree, PunctureReport};
pub use lifecycle::{
    BlobPurgeOutcome, RetentionCommit, RetentionJobState, RetentionLocationPlan,
    RetentionLocationState, RetentionLocationStateRecord, RetentionOperation, RetentionParticipant,
    RetentionSelector, RetentionSuppression, SuppressionMode,
};
pub use outboard::verify_span_range;
pub use payload::BlobCompression;

/// Ensure a `bao-tree` outboard sidecar exists for a large BLAKE3 blob.
pub fn ensure_outboard(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> error::Result<bool> {
    outboard::ensure(root, digest)
}

/// Deterministically rebuild the `bao-tree` outboard sidecar from the canonical blob.
pub fn rebuild_outboard(
    root: &std::path::Path,
    digest: mneme_core::ContentDigest,
) -> error::Result<bool> {
    outboard::rebuild(root, digest)
}
pub use requests::{
    CommitCommand, ImportCandidateDraft, PublicationDraft, RecordDraft, SourceBlobDraft,
};
pub use timekeeper::{Clock, FixedClock, SystemClock};
