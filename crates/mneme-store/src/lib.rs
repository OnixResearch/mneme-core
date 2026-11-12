//! Mneme's durable workspace.
//!
//! The store owns the SQLite ledger, immutable content-addressed blobs, one
//! serialized commit coordinator, base-revision compare-and-swap, scoped
//! idempotency, publication intents, and startup recovery. It consumes
//! `mneme-core` records and never duplicates their schema or transport policy.

#![allow(unknown_lints, module_file_count)] // intentional top-level store module layout
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod catalog;
pub mod coordinator;
pub mod error;
pub mod injectors;
pub mod lifecycle;
pub mod payload;
pub mod requests;
pub mod timekeeper;

pub use catalog::{Manifest, ManifestRecord};
pub use coordinator::{
    CommitOutcome, LAYOUT_VERSION, LEDGER_FILE, ProjectionRegistration, ProjectionResolution,
    ProjectionState, PublicationOutcome, PublicationState, RecoveryReport, Snapshot, Workspace,
    WorkspaceConfig, WorkspaceStatus,
};
pub use error::{Failure, Result};
pub use injectors::{FaultAt, FaultInjector, FaultPoint, NoFaults};
pub use lifecycle::{
    BlobPurgeOutcome, RetentionCommit, RetentionJobState, RetentionLocationPlan,
    RetentionLocationState, RetentionLocationStateRecord, RetentionOperation, RetentionParticipant,
    RetentionSelector, RetentionSuppression, SuppressionMode,
};
pub use requests::{
    CommitCommand, ImportCandidateDraft, PublicationDraft, RecordDraft, SourceBlobDraft,
};
pub use timekeeper::{Clock, FixedClock, SystemClock};
