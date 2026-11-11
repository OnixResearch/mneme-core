//! Mneme's durable workspace.
//!
//! The store owns the SQLite ledger, immutable content-addressed blobs, one
//! serialized commit coordinator, base-revision compare-and-swap, scoped
//! idempotency, publication intents, and startup recovery. It consumes
//! `mneme-core` records and never duplicates their schema or transport policy.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod blob;
pub mod clock;
pub mod command;
pub mod error;
pub mod faults;
pub mod manifest;
pub mod retention;
pub mod workspace;

pub use clock::{Clock, FixedClock, SystemClock};
pub use command::{
    CommitCommand, ImportCandidateDraft, PublicationDraft, RecordDraft, SourceBlobDraft,
};
pub use error::{Result, StoreError};
pub use faults::{FaultAt, FaultInjector, FaultPoint, NoFaults};
pub use manifest::{Manifest, ManifestRecord};
pub use retention::{
    BlobPurgeOutcome, RetentionCommit, RetentionJobState, RetentionLocationPlan,
    RetentionLocationState, RetentionLocationStateRecord, RetentionOperation, RetentionParticipant,
    RetentionSelector, RetentionSuppression, SuppressionMode,
};
pub use workspace::{
    CommitOutcome, LAYOUT_VERSION, LEDGER_FILE, ProjectionRegistration, ProjectionResolution,
    ProjectionState, PublicationOutcome, PublicationState, RecoveryReport, Snapshot, Workspace,
    WorkspaceConfig, WorkspaceStatus,
};
