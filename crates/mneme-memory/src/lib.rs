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

pub mod authorization;
pub mod beliefs;
pub mod failure;
pub mod model;
pub mod service;

pub use authorization::Access;
pub use beliefs::{
    BeliefView, ConflictGroup, Corroboration, DerivationAlternative, EXPLICIT_AUTHORED_PREDICATE,
    EvidenceExplanation, Explanation, Policy, SourceExcerpt, SourceStatus, ValidatedEvidence, View,
};
pub use failure::{EvidenceError, Result};
pub use mneme_core::Origin;
pub use model::{
    AssertionView, ClaimType, DecisionKind, DecisionView, DerivationView, EpisodeType, EpisodeView,
    EvidenceView, SourceAvailability, SourceView, Stance, SupportRelation,
};
pub use service::{
    Batch, CheckpointOptions, DecisionOptions, DerivationOptions, Engine, EpisodeOptions,
    EvidenceOptions, ProposedAssertionOptions, SourceOptions, UnavailableSourceOptions,
    UnavailableSourceWithDigestOptions, ViewContext, build_assertion_revision, build_checkpoint,
    build_decision, build_derivation, build_episode, build_evidence, build_proposed_assertion,
    build_source, build_unavailable_source, build_unavailable_source_with_digest, view_context,
};
