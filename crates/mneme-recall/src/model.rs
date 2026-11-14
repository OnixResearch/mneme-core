//! Recall request, context, candidate, and response contracts.
//!
//! The response keeps execution, corpus coverage, and result exhaustiveness
//! separate. A ranked candidate set is never evidence of absence.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// A candidate-generation mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    Lexical,
    Structured,
    Vector,
    Semantic,
}

impl Mode {
    /// Stable mode name used in reports.
    pub const fn name(self) -> &'static str {
        match self {
            Mode::Lexical => "lexical",
            Mode::Structured => "structured",
            Mode::Vector => "vector",
            Mode::Semantic => "semantic",
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
    /// Every retained claim visible to the caller, including proposed material
    /// and hypothetical claims in authorized hypothesis scopes.
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
pub struct Request {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    /// The caller's scope authorization.
    ///
    /// The request scope is always readable; `include_hypothetical` widens the
    /// view only to hypothesis scopes listed here.
    pub access: mneme_memory::Access,
    pub revision: mneme_core::WorkspaceRevisionId,
    pub query: String,
    /// Instant used by `TemporalMode::Current` for valid-time eligibility.
    pub at: mneme_core::Timestamp,
    pub temporal: TemporalMode,
    /// Explicit candidate modes. The lexical mode is independently usable.
    pub modes: std::collections::BTreeSet<Mode>,
    pub structured: Option<StructuredRequest>,
    /// Operator-configured semantic adapter. It is used only when `modes`
    /// explicitly contains [`Mode::Semantic`].
    pub semantic: Option<crate::semantic::SemanticRequest>,
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

impl Request {
    /// A current-mode, lexical-only request with conservative budgets.
    ///
    /// The caller is authorized for exactly the requested scope; a session that
    /// may read further scopes must build the request with its own
    /// [`mneme_memory::Access`].
    pub fn lexical(
        actor: impl Into<String>,
        scope: mneme_core::ScopeId,
        revision: mneme_core::WorkspaceRevisionId,
        at: mneme_core::Timestamp,
        query: impl Into<String>,
    ) -> Self {
        Request {
            actor: actor.into(),
            access: mneme_memory::Access::scopes([scope.clone()]),
            scope,
            revision,
            query: query.into(),
            at,
            temporal: TemporalMode::Current,
            modes: std::collections::BTreeSet::from([Mode::Lexical]),
            structured: None,
            semantic: None,
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

    /// The authorization a memory view is built with.
    ///
    /// A caller asking for a scope is reading it, so the request scope joins the
    /// explicit set; every other scope still needs `access`.
    pub(crate) fn view_access(&self) -> mneme_memory::Access {
        match &self.access {
            mneme_memory::Access::Operator => mneme_memory::Access::Operator,
            mneme_memory::Access::Scopes(scopes) => {
                let mut scopes = scopes.clone();
                scopes.insert(self.scope.clone());
                mneme_memory::Access::Scopes(scopes)
            }
        }
    }
}

/// Execution outcome of the recall operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Execution {
    Complete,
    Partial,
    Timeout,
    Cancelled,
    Failed,
}

impl Execution {
    pub const fn name(self) -> &'static str {
        match self {
            Execution::Complete => "complete",
            Execution::Partial => "partial",
            Execution::Timeout => "timeout",
            Execution::Cancelled => "cancelled",
            Execution::Failed => "failed",
        }
    }
}

/// Whether a requested mode contributed candidates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeStatus {
    Used,
    /// The mode ran and contributed candidates under declared incomplete
    /// coverage. This is not a failure of the mode.
    Partial,
    Unavailable,
    Omitted,
    TimedOut,
    Failed,
}

impl ModeStatus {
    pub const fn name(self) -> &'static str {
        match self {
            ModeStatus::Used => "used",
            ModeStatus::Partial => "partial",
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
    pub mode: Mode,
    pub status: ModeStatus,
    pub index_version: Option<String>,
    pub revision: Option<mneme_core::WorkspaceRevisionId>,
    pub coverage: IndexCoverage,
    pub candidates: usize,
    /// A structured relationship result may be exhaustive independently; ranked
    /// recall overall remains non-exhaustive.
    pub relation_exhaustive: Option<bool>,
    pub reason: Option<String>,
    /// Content-free embedding invocation evidence, present only for semantic
    /// requests that reached adapter execution.
    pub semantic_observation: Option<SemanticObservation>,
}

/// Host-measured, content-free evidence for one or more model invocations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationObservation {
    pub invocation_count: u64,
    /// Digests of the exact JSON inputs sent on stdin, never the source text.
    pub input_digests: Vec<String>,
    /// Host-measured monotonic elapsed time, in microseconds.
    pub elapsed_micros: u64,
    /// Missing endpoint telemetry stays unavailable rather than becoming zero.
    pub usage: crate::inference::UsageTelemetry,
}

/// Semantic-mode identity and cold/warm invocation measurements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticObservation {
    pub model_id: String,
    pub configuration_digest: String,
    pub cache_hit: bool,
    /// Present only when this request actually built the document vectors.
    pub document_build: Option<InvocationObservation>,
    /// Present only when this request actually embedded its query.
    pub query: Option<InvocationObservation>,
}

/// The exact context of one recall result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub schema_version: u32,
    pub scope: mneme_core::ScopeId,
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
    /// The workspace head observed while serving.
    pub current_revision: mneme_core::WorkspaceRevisionId,
    /// The served revision is older than `current_revision`, which the caller
    /// explicitly permitted with `allow_stale`.
    pub stale: bool,
    pub eligibility_generation: u64,
    pub temporal: TemporalMode,
    /// The instant the request was evaluated at, copied from the request.
    ///
    /// Results depend on it: `Current` valid-time eligibility, and therefore
    /// every candidate and coverage decision drawn from this context, is
    /// decided at this instant rather than at delivery time.
    pub at: mneme_core::Timestamp,
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
pub struct Evidence {
    pub evidence: mneme_core::RecordId,
    pub source: mneme_core::RecordId,
    pub source_revision: Option<mneme_core::RevisionId>,
    pub span: Option<mneme_core::SourceSpan>,
    pub availability: mneme_memory::SourceAvailability,
    /// Whether the record supports or challenges the claim. A challenge is
    /// never counted as independent support.
    pub relation: mneme_memory::SupportRelation,
    /// A withdrawal suppression covers this record, so it no longer grounds
    /// the claim it belongs to.
    pub withdrawn: bool,
    /// The memory engine judges this citation eligible to contribute to current
    /// support: its declared ancestry resolved, nothing withdrew it, and every
    /// record it needs is readable. `false` is the fail-closed default, and the
    /// flag is only raised by the support walk over a ranked claim.
    pub eligible: bool,
    /// The resolved, readable roots the memory engine derives for this
    /// citation. A citation that declares ancestry roots at its ancestors'
    /// roots, so this is empty when that ancestry could not be resolved and it
    /// never falls back to the cited source.
    pub ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
}

/// One ranked item before or after context packing.
#[derive(Clone, Debug)]
pub struct Candidate {
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
    pub evidence: Vec<Evidence>,
    pub derivations: Vec<mneme_datalog::Derivation>,
    pub ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
    /// False when another selected candidate shares this candidate's ancestry.
    pub independent_support: bool,
    /// The support set is incomplete: a declared citation could not be resolved
    /// to a root (unresolved ancestry, a withdrawal, unreadable records) or the
    /// bounded support walk truncated. Such a candidate is never counted or
    /// labelled as independent support, because an empty root set cannot be
    /// read as "no ancestry declared".
    pub support_limited: bool,
    pub origins: std::collections::BTreeSet<Mode>,
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

/// Used and allowed amounts of every limit one recall request carries.
///
/// A limit is reported as a pair: `*_allowed` is the limit that applied, and
/// `*_used` is what the response actually returned or spent, so a caller can
/// verify the amount by counting the response. A response whose status is
/// complete never reports a used amount above its allowed amount; a timeout,
/// cancellation or failure may, because the stop itself is what ended work that
/// was already in progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BudgetUse {
    /// Candidates returned, against the request's item limit.
    pub items_used: u64,
    pub items_allowed: u64,
    /// Bytes of returned candidate text, against the request's context budget.
    /// Attribution fields are not counted, exactly as the limit counts them.
    pub text_bytes_used: u64,
    pub text_bytes_allowed: u64,
    /// Bytes of the longest returned excerpt, against the per-excerpt limit.
    pub excerpt_bytes_used: u64,
    pub excerpt_bytes_allowed: u64,
    /// Whole milliseconds elapsed, against the request's time budget, as the
    /// last budget observation measured them.
    pub elapsed_ms_used: u64,
    pub elapsed_ms_allowed: u64,
    /// Work units charged, against the deterministic recall work limit, which
    /// is the crate's own bound rather than a request field.
    pub work_used: u64,
    pub work_allowed: u64,
}

/// One recall response.
#[derive(Clone, Debug)]
pub struct Response {
    pub context: Context,
    pub status: Execution,
    pub modes: Vec<ModeReport>,
    pub candidates: Vec<Candidate>,
    /// Whether this answer is complete, decided by
    /// [`mneme_kernel::completeness::answer_complete`]. A ranked result is
    /// never exhaustive; only an exhaustive structured relation can be.
    pub exhaustive: bool,
    /// Whether an empty answer establishes absence, decided by
    /// [`mneme_kernel::completeness::absence_established`].
    pub absence_established: bool,
    pub truncated: bool,
    /// What this answer returned and spent, against every limit the request
    /// carries.
    pub budget: BudgetUse,
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
    /// Lexical weighting statistics over exactly `documents`.
    pub(crate) lexical: LexicalStatistics,
    /// One model/configuration's vectors, held only for this in-memory index.
    pub(crate) semantic: Option<crate::semantic::Index>,
    /// Document position by candidate identity, so a ranking result never
    /// copies the corpus it was computed from.
    positions: std::collections::BTreeMap<String, usize>,
}

impl CachedIndex {
    /// Build an index from its documents and the lexical statistics they
    /// determine.
    pub(crate) fn new(
        revision: mneme_core::WorkspaceRevisionId,
        coverage: IndexCoverage,
        documents: Vec<IndexedDocument>,
    ) -> Self {
        let positions = documents
            .iter()
            .enumerate()
            .map(|(position, document)| (document.id.clone(), position))
            .collect();
        let lexical = LexicalStatistics::of(&documents);
        CachedIndex {
            revision,
            coverage,
            documents,
            lexical,
            semantic: None,
            positions,
        }
    }

    /// The document with this candidate identity.
    pub(crate) fn document(&self, id: &str) -> Option<&IndexedDocument> {
        self.positions
            .get(id)
            .and_then(|position| self.documents.get(*position))
    }
}

/// The corpus statistics lexical ranking weights terms with.
///
/// They are computed from the documents of one index and nothing else. An index
/// holds only records the request may read and sources that are still
/// available, and it is cached under the request's revision, scope,
/// authorization and eligibility generation, so a document outside the
/// authorization or a forgotten source never changes a weight.
#[derive(Clone, Debug)]
pub(crate) struct LexicalStatistics {
    documents: usize,
    /// Number of documents that contain each stem.
    frequencies: std::collections::BTreeMap<String, usize>,
    /// Mean number of stems per document.
    average_length: f64,
}

impl LexicalStatistics {
    fn of(documents: &[IndexedDocument]) -> Self {
        // Every document lists each of its stems once, so after sorting the
        // run length of a stem is the number of documents that contain it.
        let mut stems: Vec<&String> = documents
            .iter()
            .flat_map(|document| document.term_counts.keys())
            .collect();
        stems.sort_unstable();
        let frequencies = stems
            .chunk_by(|left, right| left == right)
            .filter_map(|run| run.first().map(|stem| ((*stem).clone(), run.len())))
            .collect();
        let total_length = documents.iter().fold(0_usize, |total, document| {
            total.saturating_add(document.term_total)
        });
        let average_length = if documents.is_empty() {
            0.0
        } else {
            count(total_length) / count(documents.len())
        };
        LexicalStatistics {
            documents: documents.len(),
            frequencies,
            average_length,
        }
    }

    /// Inverse document frequency, `ln(1 + (N - n + 0.5) / (n + 0.5))`.
    ///
    /// It is positive for every term, so any shared term contributes, and it
    /// falls as more documents contain the term.
    pub(crate) fn idf(&self, term: &str) -> f64 {
        let containing = count(self.frequencies.get(term).copied().unwrap_or(0));
        ((count(self.documents) - containing + 0.5) / (containing + 0.5)).ln_1p()
    }

    /// A document's length relative to the mean, for length normalisation.
    /// An index whose documents hold no terms has no length to normalise.
    pub(crate) fn relative_length(&self, document: &IndexedDocument) -> f64 {
        if self.average_length > 0.0 {
            count(document.term_total) / self.average_length
        } else {
            1.0
        }
    }
}

/// A count as a float. Counts of indexed documents and terms stay far below
/// 2^53, where every integer is exact.
fn count(value: usize) -> f64 {
    value as f64
}

/// A text document in the built lexical/vector index.
#[derive(Clone, Debug)]
pub(crate) struct IndexedDocument {
    pub id: String,
    pub kind: ContentKind,
    pub text: String,
    pub normalized: String,
    /// Occurrences of each lexical stem.
    pub term_counts: std::collections::BTreeMap<String, u32>,
    /// Number of lexical stems, repeats included.
    pub term_total: usize,
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
    pub evidence: Vec<Evidence>,
    pub ancestry_roots: std::collections::BTreeSet<(mneme_core::RecordId, mneme_core::RevisionId)>,
}

/// Constants exported for evaluation and cache identity.
pub const RECALL_CONTEXT_SCHEMA_VERSION: u32 = crate::INDEX_SCHEMA_VERSION;

#[cfg(test)]
mod idf_tests {
    fn corpus(documents: usize, frequencies: &[(&str, usize)]) -> super::LexicalStatistics {
        super::LexicalStatistics {
            documents,
            frequencies: frequencies
                .iter()
                .map(|(term, containing)| ((*term).to_owned(), *containing))
                .collect(),
            average_length: 4.0,
        }
    }

    #[test]
    fn rarer_terms_weigh_more_and_every_weight_is_positive() {
        let statistics = corpus(4, &[("everywhere", 4), ("common", 3), ("rare", 1)]);
        let everywhere = statistics.idf("everywhere");
        let common = statistics.idf("common");
        let rare = statistics.idf("rare");
        let absent = statistics.idf("absent");
        // A term every document contains still counts, or a match on it would
        // lower a score.
        assert!(everywhere > 0.0, "{everywhere}");
        assert!(common > everywhere);
        assert!(rare > common);
        assert!(absent > rare);
        assert!((rare - (3.5_f64 / 1.5).ln_1p()).abs() < 1e-12);
    }
}
