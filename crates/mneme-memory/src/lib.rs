//! Attributed evidence and belief semantics over the committed workspace.
//!
//! This crate consumes `mneme-core` records and `mneme-store` snapshots. It does
//! not define a second store or query engine: source spans, lifecycle decisions,
//! support eligibility, conflicts, ancestry, and explanations are derived from
//! the one committed revision. Recording, promotion, retraction, and correction
//! go through the workspace coordinator with the caller's base revision and
//! idempotency key.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![allow(unknown_lints)] // Octet custom lint names are unknown to rustc

pub mod error;
pub mod model;
pub mod policy;
pub mod service;

pub use error::{MemoryError, Result};
pub use mneme_core::Origin;
pub use model::{
    AssertionView, DecisionKind, DecisionView, DerivationView, EpisodeType, EpisodeView,
    EvidenceView, SourceAvailability, SourceView, Stance, SupportRelation,
};
pub use policy::{
    BeliefView, ConflictGroup, Corroboration, DerivationAlternative, EXPLICIT_AUTHORED_PREDICATE,
    EvidenceExplanation, Explanation, MemoryView, Policy, SourceExcerpt, SourceStatus,
    ValidatedEvidence,
};
pub use service::{
    Memory, MemoryBatch, build_assertion_revision, build_checkpoint, build_decision,
    build_derivation, build_episode, build_evidence, build_proposed_assertion, build_source,
    build_unavailable_source, build_unavailable_source_with_digest,
};
