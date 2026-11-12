//! Authorized, bounded, attributed memory recall.
//!
//! Lexical and local token-vector candidates come from one pinned scoped
//! snapshot. Optional structured candidates retain Datalog coverage and
//! derivations. Ranking is non-exhaustive by construction: no recall response
//! establishes factual absence.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(unknown_lints)] // Octet custom lint names are unknown to rustc

pub mod engine;
pub mod failure;
pub mod lookup;
pub mod model;

pub use engine::{FUSION_POLICY_VERSION, Service};
pub use failure::{QueryError, Result};
pub use lookup::{LEXICAL_INDEX_VERSION, VECTOR_INDEX_VERSION};
pub use model::{
    Candidate, ClaimStatus, ContentKind, Context, DataBoundary, Evidence, Execution, IndexCoverage,
    Mode, ModeReport, ModeStatus, Omission, Request, Response, StructuredRequest, TemporalMode,
};

/// Recall contract/index schema version.
pub const INDEX_SCHEMA_VERSION: u32 = 1;
