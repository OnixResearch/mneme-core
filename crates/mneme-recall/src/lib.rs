//! Authorized, bounded, attributed memory recall.
//!
//! Lexical and local token-vector candidates come from one pinned scoped
//! snapshot. Optional structured candidates retain Datalog coverage and
//! derivations. Ranking is non-exhaustive by construction: no recall response
//! establishes factual absence.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(unknown_lints)] // Octet custom lint names are unknown to rustc

pub mod error;
pub mod index;
pub mod model;
pub mod service;

pub use error::{RecallError, Result};
pub use index::{LEXICAL_INDEX_VERSION, VECTOR_INDEX_VERSION};
pub use model::{
    ClaimStatus, ContentKind, DataBoundary, IndexCoverage, ModeReport, ModeStatus, Omission,
    RecallCandidate, RecallContext, RecallEvidence, RecallExecution, RecallMode, RecallRequest,
    RecallResponse, StructuredRequest, TemporalMode,
};
pub use service::{FUSION_POLICY_VERSION, RecallService};

/// Recall contract/index schema version.
pub const INDEX_SCHEMA_VERSION: u32 = 1;
