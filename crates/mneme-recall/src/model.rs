//! Recall request, context, candidate, and response contracts.
//!
//! The response keeps execution, corpus coverage, and result exhaustiveness
//! separate. A ranked candidate set is never evidence of absence.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A candidate-generation mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecallMode {
    Lexical,
    Structured,
    Vector,
}

impl RecallMode {
    /// Stable mode name used in reports.
    pub const fn name(self) -> &'static str {
        match self {
            RecallMode::Lexical => "lexical",
            RecallMode::Structured => "structured",
            RecallMode::Vector => "vector",
        }
    }
}

/// How retained assertion status and valid time are selected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TemporalMode {
    /// Accepted (or explicitly disputed) current claims at `at`, plus episodes
    /// and typed fields from the same scope.
    Current,
    /// Retained accepted, disputed, superseded, and retracted claims without
    /// substituting recorded time for valid time.
    Historical,
    /// Every retained claim, including proposed and hypothetical material.
    Inspection,
}

impl TemporalMode {
    /// Stable name.
    pub const fn name(self) -> &'static str {
        match self {
            TemporalMode::Current => "current",
            TemporalMode::Historical => "historical",
            TemporalMode::Inspection => "inspection",
        }
    }
}

/// Structured candidate expansion supplied by the caller.
#[derive(Clone, Debug)]
pub struct StructuredRequest {
    /// Versioned Datalog profile.
    pub bundle: mneme_datalog::RuleBundle,
    /// Query over one declared relation.
    pub query: mneme_datalog::Query,
    /// Evaluation bounds.
    pub limits: mneme_datalog::Limits,
    /// Explicitly incomplete inputs, such as a prior top-k candidate set.
    pub incomplete_extents: std::collections::BTreeSet<String>,
}

/// One recall operation.
#[derive(Clone, Debug)]
pub struct RecallRequest {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub query: String,
    /// Instant used by `TemporalMode::Current` for valid-time eligibility.
    pub at: mneme_core::Timestamp,
    pub temporal: TemporalMode,
    /// Explicit candidate modes. The lexical mode is independently usable.
    pub modes: std::collections::BTreeSet<RecallMode>,
    pub structured: Option<StructuredRequest>,
    /// Permit an older served revision when explicitly requested.
    pub allow_stale: bool,
    /// Permit other explicitly requested modes to continue when one mode is
    /// unavailable or fails.
    pub allow_fallback: bool,
    /// Permit qualified positive candidates from successful modes when another
    /// requested mode times out or fails.
    pub allow_partial: bool,
    pub include_disputed: bool,
    pub include_hypothetical: bool,
    pub max_items: usize,
    /// Maximum bytes of item text (not counting structured attribution fields).
    pub max_context_bytes: usize,
    /// Maximum bytes for any one excerpt.
    pub max_quote_bytes: usize,
    /// Maximum elapsed time for candidate generation and packing.
    pub max_time_ms: u128,
    pub cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl RecallRequest {
    /// A current-mode, lexical-only request with conservative budgets.
    pub fn lexical(
        actor: impl Into<String>,
        scope: mneme_core::ScopeId,
        revision: mneme_core::WorkspaceRevisionId,
        at: mneme_core::Timestamp,
        query: impl Into<String>,
    ) -> Self {
        RecallRequest {
            actor: actor.into(),
            scope,
            revision,
            query: query.into(),
            at,
            temporal: TemporalMode::Current,
            modes: std::collections::BTreeSet::from([RecallMode::Lexical]),
            structured: None,
            allow_stale: false,
            allow_fallback: true,
            allow_partial: true,
            include_disputed: false,
            include_hypothetical: false,
            max_items: 8,
            max_context_bytes: 4096,
            max_quote_bytes: 1024,
            max_time_ms: 500,
            cancellation: None,
        }
    }
}

/// Execution outcome of the recall operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecallExecution {
    Complete,
    Partial,
    Timeout,
    Cancelled,
    Failed,
}

impl RecallExecution {
    pub const fn name(self) -> &'static str {
        match self {
            RecallExecution::Complete => "complete",
            RecallExecution::Partial => "partial",
            RecallExecution::Timeout => "timeout",
            RecallExecution::Cancelled => "cancelled",
            RecallExecution::Failed => "failed",
        }
    }
}

/// Whether a requested mode contributed candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeStatus {
    Used,
    Unavailable,
    Omitted,
    TimedOut,
    Failed,
}

impl ModeStatus {
    pub const fn name(self) -> &'static str {
        match self {
            ModeStatus::Used => "used",
            ModeStatus::Unavailable => "unavailable",
            ModeStatus::Omitted => "omitted",
            ModeStatus::TimedOut => "timed_out",
            ModeStatus::Failed => "failed",
        }
    }
}

/// Coverage of the eligible corpus by one index or relation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexCoverage {
    /// All eligible in-scope text was indexable. This is not result exhaustiveness.
    pub complete: bool,
    pub documents_indexed: usize,
    pub documents_skipped: usize,
    pub reason: Option<String>,
}

impl IndexCoverage {
    pub(crate) fn complete(indexed: usize) -> Self {
        IndexCoverage {
            complete: true,
            documents_indexed: indexed,
            documents_skipped: 0,
            reason: None,
        }
    }

    pub(crate) fn incomplete(indexed: usize, skipped: usize, reason: impl Into<String>) -> Self {
        IndexCoverage {
            complete: false,
            documents_indexed: indexed,
            documents_skipped: skipped,
            reason: Some(reason.into()),
        }
    }
}

/// One mode's contribution and limitations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeReport {
    pub mode: RecallMode,
    pub status: ModeStatus,
    pub index_version: Option<String>,
    pub revision: Option<mneme_core::WorkspaceRevisionId>,
    pub coverage: IndexCoverage,
    pub candidates: usize,
    /// A structured relationship result may be exhaustive independently; ranked
    /// recall overall remains non-exhaustive.
    pub relation_exhaustive: Option<bool>,
    pub reason: Option<String>,
}

/// The exact context of one recall result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallContext {
    pub schema_version: u32,
    pub scope: mneme_core::ScopeId,
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
    pub eligibility_generation: u64,
    pub temporal: TemporalMode,
    pub index_versions: std::collections::BTreeMap<String, String>,
    pub fusion_policy: String,
}

/// Where candidate text came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentKind {
    SourceExcerpt,
    Claim,
    EpisodeSummary,
    TypedField,
    StructuredRow,
}

impl ContentKind {
    pub const fn name(self) -> &'static str {
        match self {
            ContentKind::SourceExcerpt => "source-excerpt",
            ContentKind::Claim => "claim",
            ContentKind::EpisodeSummary => "episode-summary",
            ContentKind::TypedField => "typed-field",
            ContentKind::StructuredRow => "structured-row",
        }
    }
}

/// Assertion lifecycle and time fields retained with a claim candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimStatus {
    pub lifecycle: String,
    pub stance: String,
    pub valid_time: mneme_core::ValidTime,
    pub recorded: mneme_core::RecordedTime,
    pub superseded_by: Option<mneme_core::RecordId>,
    pub decision: Option<mneme_core::RecordId>,
    pub asserted_by: String,
}

impl ClaimStatus {
    pub(crate) fn from_assertion(assertion: &mneme_memory::AssertionView) -> Self {
        ClaimStatus {
            lifecycle: assertion.lifecycle.symbol().to_owned(),
            stance: match assertion.stance {
                mneme_memory::Stance::Affirm => "affirm",
                mneme_memory::Stance::Deny => "deny",
                mneme_memory::Stance::Hypothesis => "hypothesis",
            }
            .to_owned(),
            valid_time: assertion.valid_time,
            recorded: assertion.record.recorded,
            superseded_by: assertion.superseded_by,
            decision: assertion.decision,
            asserted_by: assertion.asserted_by.clone(),
        }
    }
}

/// Evidence attribution retained independently of whether a quote is available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallEvidence {
    pub evidence: mneme_core::RecordId,
    pub source: mneme_core::RecordId,
    pub source_revision: Option<mneme_core::RevisionId>,
    pub span: Option<mneme_core::SourceSpan>,
    pub availability: mneme_memory::SourceAvailability,
    pub ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
}

/// One ranked item before or after context packing.
#[derive(Clone, Debug)]
pub struct RecallCandidate {
    pub id: String,
    pub content_kind: ContentKind,
    pub text: String,
    pub text_truncated: bool,
    pub source: Option<mneme_core::RecordId>,
    pub source_revision: Option<mneme_core::RevisionId>,
    pub span: Option<mneme_core::SourceSpan>,
    pub field_path: String,
    pub assertion: Option<mneme_core::RecordId>,
    pub episode: Option<mneme_core::RecordId>,
    pub entity: Option<mneme_core::RecordId>,
    pub claim_status: Option<ClaimStatus>,
    /// Exact attribution for a source excerpt; claims and summaries are not quotes.
    pub quote: bool,
    pub evidence: Vec<RecallEvidence>,
    pub derivations: Vec<mneme_datalog::Derivation>,
    pub ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
    /// False when another selected candidate shares this candidate's ancestry.
    pub independent_support: bool,
    pub origins: std::collections::BTreeSet<RecallMode>,
    pub score: f64,
    pub score_components: std::collections::BTreeMap<String, f64>,
}

/// Why a candidate was not returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Omission {
    pub candidate: String,
    pub reason: String,
}

/// Explicit data-only boundary for retrieved material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataBoundary {
    pub kind: String,
    pub instructions_are_data: bool,
    pub may_change_scope: bool,
    pub may_execute_code: bool,
    pub may_register_rules: bool,
}

impl Default for DataBoundary {
    fn default() -> Self {
        DataBoundary {
            kind: "untrusted-retrieved-data".to_owned(),
            instructions_are_data: true,
            may_change_scope: false,
            may_execute_code: false,
            may_register_rules: false,
        }
    }
}

/// One recall response.
#[derive(Clone, Debug)]
pub struct RecallResponse {
    pub context: RecallContext,
    pub status: RecallExecution,
    pub modes: Vec<ModeReport>,
    pub candidates: Vec<RecallCandidate>,
    /// Whether this ranked result is exhaustive. Always false for recall.
    pub exhaustive: bool,
    /// Whether recall established a factual absence. Always false.
    pub absence_established: bool,
    pub truncated: bool,
    pub omissions: Vec<Omission>,
    pub reason: Option<String>,
    pub boundary: DataBoundary,
}

/// Indexing levels stored with a cached index.
#[derive(Clone, Debug)]
pub(crate) struct CachedIndex {
    pub revision: mneme_core::WorkspaceRevisionId,
    pub coverage: IndexCoverage,
    pub(crate) documents: Vec<IndexedDocument>,
}

/// A text document in the built lexical/vector index.
#[derive(Clone, Debug)]
pub(crate) struct IndexedDocument {
    pub id: String,
    pub kind: ContentKind,
    pub text: String,
    pub normalized: String,
    pub terms: std::collections::BTreeSet<String>,
    pub trigrams: std::collections::BTreeMap<u64, u32>,
    pub trigram_norm: f64,
    pub field_path: String,
    pub source: Option<mneme_core::RecordId>,
    pub source_revision: Option<mneme_core::RevisionId>,
    pub span: Option<mneme_core::SourceSpan>,
    pub assertion: Option<mneme_core::RecordId>,
    pub episode: Option<mneme_core::RecordId>,
    pub entity: Option<mneme_core::RecordId>,
    pub claim_status: Option<ClaimStatus>,
    pub evidence: Vec<RecallEvidence>,
    pub ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
}

/// Constants exported for evaluation and cache identity.
pub const RECALL_CONTEXT_SCHEMA_VERSION: u32 = crate::INDEX_SCHEMA_VERSION;
