//! Bounded consolidation job, batch, proposal, disposition, and acceptance
//! contracts.
//!
//! These types deliberately separate observations, proposed interpretations,
//! accepted assertions, and procedural suggestions. A job producing proposals
//! never accepts them; acceptance is a separate compare-and-swap precondition
//! evaluated by a later command.
#![allow(unknown_lints)] // Octet structural exception: domain-qualified names and macro-only imports are intentional
#![cfg_attr(test, allow(clippy::expect_used))]

pub mod adapter;
pub mod commands;
pub mod flow;
#[path = "extractor.rs"]
mod supervised;
#[allow(unknown_lints, path_segment_repetition)] // preserve the canonical public model-extractor contract path
pub mod model_extractor {
    pub use crate::supervised::{ModelExtractor, PreparedModelRequest};
}
pub mod proposals;
pub mod runner;

/// Saturate elapsed nanoseconds for the fixed-width telemetry receipt.
#[allow(unknown_lints, unchecked_narrowing)] // guarded conversion; telemetry cannot represent durations above u64 nanoseconds
pub(crate) fn elapsed_ns_telemetry(elapsed: std::time::Duration) -> u64 {
    let nanos = elapsed.as_nanos();
    if nanos > u128::from(u64::MAX) {
        u64::MAX
    } else {
        nanos as u64
    }
}

/// The text a redacted proposal carries in place of content it may no longer show.
const SUPPRESSED_MARKER: &str = "suppressed";

/// Resource limits for one consolidation job.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JobLimits {
    pub max_inputs: usize,
    pub max_proposals: usize,
    pub max_time_ms: u64,
    pub max_model_calls: u32,
}

impl JobLimits {
    /// Check that all limits are usable.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_inputs == 0 || self.max_proposals == 0 || self.max_time_ms == 0 {
            return Err("job limits must be positive".to_owned());
        }
        Ok(())
    }
}

/// An optional extractor/model identity. It is metadata, never evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractorDescriptor {
    pub identity: String,
    pub revision: String,
    pub prompt_digest: String,
}

impl ExtractorDescriptor {
    fn validate(&self) -> Result<(), String> {
        if self.identity.trim().is_empty()
            || self.revision.trim().is_empty()
            || self.prompt_digest.trim().is_empty()
        {
            return Err("extractor identity, revision, and prompt digest are required".to_owned());
        }
        Ok(())
    }
}

/// An exact input record revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputKey {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
}

/// The record family of one input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputKind {
    Episode,
    SourceRevision,
    Assertion,
    Document,
}

impl InputKind {
    /// Stable name for reports and run identity.
    pub fn name(self) -> &'static str {
        match self {
            InputKind::Episode => "episode",
            InputKind::SourceRevision => "source-revision",
            InputKind::Assertion => "assertion",
            InputKind::Document => "document",
        }
    }
}

/// Whether input bytes remain available for quotation/extraction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputAvailability {
    /// The exact bytes are retained and readable.
    Retained,
    /// An authorized pruning step removed the bytes.
    Pruned { reason: String },
    /// An authorized forget (erasure) removed the bytes.
    Forgotten { reason: String },
    /// The bytes cannot be read: corrupt, inaccessible, or no longer present.
    Unavailable { reason: String },
}

impl InputAvailability {
    /// Stable name for reports.
    pub fn name(&self) -> &'static str {
        match self {
            InputAvailability::Retained => "retained",
            InputAvailability::Pruned { .. } => "pruned",
            InputAvailability::Forgotten { .. } => "forgotten",
            InputAvailability::Unavailable { .. } => "unavailable",
        }
    }

    /// Whether the exact bytes may be quoted or re-extracted.
    pub fn is_retained(&self) -> bool {
        matches!(self, InputAvailability::Retained)
    }

    /// The recorded reason, when the bytes are not retained.
    pub fn reason(&self) -> Option<&str> {
        match self {
            InputAvailability::Retained => None,
            InputAvailability::Pruned { reason }
            | InputAvailability::Forgotten { reason }
            | InputAvailability::Unavailable { reason } => Some(reason),
        }
    }

    /// Map a memory-layer source status onto a batch availability.
    ///
    /// Anything other than an exact retained read is unavailable: a pruned,
    /// erased, corrupt or inaccessible source can never be quoted again.
    pub fn from_source_availability(availability: &mneme_memory::SourceAvailability) -> Self {
        match availability {
            mneme_memory::SourceAvailability::Retained => InputAvailability::Retained,
            mneme_memory::SourceAvailability::Pruned => InputAvailability::Pruned {
                reason: "source bytes were pruned".to_owned(),
            },
            mneme_memory::SourceAvailability::Erased => InputAvailability::Forgotten {
                reason: "source bytes were forgotten".to_owned(),
            },
            mneme_memory::SourceAvailability::Corrupt { reason } => {
                InputAvailability::Unavailable {
                    reason: format!("source bytes are corrupt: {reason}"),
                }
            }
            mneme_memory::SourceAvailability::Inaccessible => InputAvailability::Unavailable {
                reason: "source bytes are inaccessible".to_owned(),
            },
            mneme_memory::SourceAvailability::Unavailable { reason } => {
                InputAvailability::Unavailable {
                    reason: reason.clone(),
                }
            }
        }
    }
}

/// One exact input unit and its source availability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputUnit {
    pub key: InputKey,
    pub kind: InputKind,
    pub availability: InputAvailability,
    /// The authority this unit's content carries.
    pub authority: ProposalAuthority,
    /// The derivation record a derived unit came from, when recall names one.
    pub derivation: Option<mneme_core::RecordId>,
    /// The distinct ancestry roots this unit stands for.
    pub ancestry_roots: std::collections::BTreeSet<InputKey>,
}

impl InputUnit {
    /// A unit whose only ancestry root is its own exact revision.
    pub fn new(key: InputKey, kind: InputKind, availability: InputAvailability) -> Self {
        InputUnit {
            key,
            kind,
            availability,
            authority: ProposalAuthority::Observed,
            derivation: None,
            ancestry_roots: std::collections::BTreeSet::from([key]),
        }
    }

    /// Replace the ancestry roots this unit stands for.
    pub fn with_ancestry(mut self, ancestry_roots: std::collections::BTreeSet<InputKey>) -> Self {
        if !ancestry_roots.is_empty() {
            self.ancestry_roots = ancestry_roots;
        }
        self
    }

    /// Record the authority this unit's content carries.
    pub fn with_authority(mut self, authority: ProposalAuthority) -> Self {
        self.authority = authority;
        self
    }

    /// Record the derivation record this unit came from.
    pub fn with_derivation(mut self, derivation: mneme_core::RecordId) -> Self {
        self.derivation = Some(derivation);
        self
    }
}

/// Retained limitations from the recall result that selected a batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallModeLimitation {
    pub mode: String,
    pub status: String,
    pub complete: bool,
    pub reason: Option<String>,
}

/// Recall status and coverage retained with a pinned batch. Absence/cleanup
/// conclusions are never permitted from a ranked or incomplete result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecallLimitations {
    pub status: String,
    pub exhaustive: bool,
    pub absence_established: bool,
    pub truncated: bool,
    pub omissions: Vec<String>,
    pub modes: Vec<RecallModeLimitation>,
    pub unpinned_candidates: usize,
}

impl RecallLimitations {
    /// Limitations for an explicitly complete, non-recall fixture extent.
    pub fn complete() -> Self {
        RecallLimitations {
            status: "complete".to_owned(),
            exhaustive: true,
            absence_established: false,
            truncated: false,
            omissions: Vec::new(),
            modes: Vec::new(),
            unpinned_candidates: 0,
        }
    }
}

/// Coverage claimed by one bounded batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchCoverage {
    Complete,
    Partial { reason: String },
    Unknown { reason: String },
}

/// A bounded input batch. A complete claim must enumerate its reviewed extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputBatch {
    pub scope: mneme_core::ScopeId,
    pub requested_revision: mneme_core::WorkspaceRevisionId,
    pub served_revision: mneme_core::WorkspaceRevisionId,
    pub eligibility_generation: u64,
    pub units: Vec<InputUnit>,
    pub reviewed: std::collections::BTreeSet<InputKey>,
    pub declared_extent: Option<std::collections::BTreeSet<InputKey>>,
    pub coverage: BatchCoverage,
    pub limitations: RecallLimitations,
}

impl InputBatch {
    /// Build a pinned batch from an authorized recall response.
    ///
    /// The response remains a ranked, non-exhaustive source selection. Its
    /// omissions, truncation, mode failures, and unpinned candidates are
    /// retained so proposals cannot infer absence or cleanup.
    ///
    /// Availability is read from the source's own status in `view`, not from
    /// the candidate's evidence list: a pruned, erased or corrupt source keeps
    /// its candidate in a ranked result, so trusting the candidate would let a
    /// generator quote bytes that are gone.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn from_recall(
        scope: mneme_core::ScopeId,
        expected_revision: mneme_core::WorkspaceRevisionId,
        response: &mneme_recall::Response,
        view: &mneme_memory::View,
    ) -> Result<Self, String> {
        Self::from_recall_with(scope, expected_revision, response, |source, revision| {
            source_availability(view, source, revision)
        })
    }

    /// Build a pinned batch from a recall response and an availability source.
    ///
    /// The resolver is the caller's authority on whether exact bytes still
    /// exist; production callers pass the pinned view, tests pass the state
    /// they are exercising.
    pub fn from_recall_with<F>(
        scope: mneme_core::ScopeId,
        expected_revision: mneme_core::WorkspaceRevisionId,
        response: &mneme_recall::Response,
        availability: F,
    ) -> Result<Self, String>
    where
        F: Fn(mneme_core::RecordId, mneme_core::RevisionId) -> InputAvailability,
    {
        Self::validate_recall_response(&scope, expected_revision, response)?;
        let (units, unpinned_candidates) = Self::recall_units(response, availability);
        let reviewed = units
            .iter()
            .map(|unit| unit.key)
            .collect::<std::collections::BTreeSet<_>>();
        let limitations = Self::recall_limitations(response, unpinned_candidates);
        Ok(InputBatch {
            scope,
            requested_revision: response.context.requested_revision,
            served_revision: response.context.served_revision,
            eligibility_generation: response.context.eligibility_generation,
            units,
            reviewed,
            declared_extent: None,
            coverage: BatchCoverage::Partial {
                reason: "ranked recall is not a complete source extent".to_owned(),
            },
            limitations,
        })
    }

    fn validate_recall_response(
        scope: &mneme_core::ScopeId,
        expected_revision: mneme_core::WorkspaceRevisionId,
        response: &mneme_recall::Response,
    ) -> Result<(), String> {
        if &response.context.scope != scope {
            return Err("recall scope does not match the consolidation scope".to_owned());
        }
        if response.context.requested_revision != expected_revision {
            return Err("recall request is not pinned to the expected revision".to_owned());
        }
        if response.absence_established {
            return Err("ranked recall must not establish absence".to_owned());
        }
        if !response.boundary.instructions_are_data
            || response.boundary.may_change_scope
            || response.boundary.may_execute_code
            || response.boundary.may_register_rules
        {
            return Err("recall boundary is not data-only".to_owned());
        }
        Ok(())
    }

    fn recall_units<F>(
        response: &mneme_recall::Response,
        availability: F,
    ) -> (Vec<InputUnit>, usize)
    where
        F: Fn(mneme_core::RecordId, mneme_core::RevisionId) -> InputAvailability,
    {
        let mut units = Vec::with_capacity(response.candidates.len());
        let mut seen = std::collections::BTreeSet::new();
        let mut unpinned_candidates = 0;
        for candidate in &response.candidates {
            let (Some(source), Some(revision)) = (candidate.source, candidate.source_revision)
            else {
                unpinned_candidates += 1;
                continue;
            };
            let key = InputKey {
                record_id: source,
                revision_id: revision,
            };
            if !seen.insert(key) {
                continue;
            }
            let ancestry = candidate
                .ancestry_roots
                .iter()
                .map(|(record_id, revision_id)| InputKey {
                    record_id: *record_id,
                    revision_id: *revision_id,
                })
                .collect::<std::collections::BTreeSet<_>>();
            units.push(
                InputUnit::new(
                    key,
                    InputKind::SourceRevision,
                    availability(source, revision),
                )
                .with_ancestry(ancestry)
                .with_authority(unit_authority(candidate.content_kind)),
            );
        }
        (units, unpinned_candidates)
    }

    fn recall_limitations(
        response: &mneme_recall::Response,
        unpinned_candidates: usize,
    ) -> RecallLimitations {
        RecallLimitations {
            status: response.status.name().to_owned(),
            exhaustive: response.exhaustive,
            absence_established: response.absence_established,
            truncated: response.truncated,
            omissions: response
                .omissions
                .iter()
                .map(|omission| format!("{}: {}", omission.candidate, omission.reason))
                .collect(),
            modes: response
                .modes
                .iter()
                .map(|mode| RecallModeLimitation {
                    mode: mode.mode.name().to_owned(),
                    status: mode.status.name().to_owned(),
                    complete: mode.coverage.complete && mode.relation_exhaustive != Some(false),
                    reason: mode.reason.clone(),
                })
                .collect(),
            unpinned_candidates,
        }
    }

    /// Whether a batch may support an absence or cleanup conclusion.
    pub fn allows_absence_or_cleanup(&self) -> bool {
        matches!(self.coverage, BatchCoverage::Complete)
            && self.limitations.exhaustive
            && !self.limitations.truncated
            && self.limitations.omissions.is_empty()
            && self.limitations.unpinned_candidates == 0
            && self.limitations.modes.iter().all(|mode| mode.complete)
    }

    /// Keep at most `max_inputs` units, returning the units that did not fit.
    ///
    /// The review cursor must never claim an extent that was not reviewed, so a
    /// dropped unit leaves both the unit list and the reviewed set.
    #[allow(unknown_lints, usize_in_public_api)] // matches `JobLimits::max_inputs` and indexes the unit collection
    pub fn limit_inputs(&self, max_inputs: usize) -> (Self, Vec<InputKey>) {
        if self.units.len() <= max_inputs {
            return (self.clone(), Vec::new());
        }
        let mut kept = self.clone();
        let dropped = kept.units.split_off(max_inputs);
        let dropped = dropped.into_iter().map(|unit| unit.key).collect::<Vec<_>>();
        for key in &dropped {
            kept.reviewed.remove(key);
        }
        if let Some(extent) = &mut kept.declared_extent {
            for key in &dropped {
                extent.remove(key);
            }
        }
        (kept, dropped)
    }

    /// A digest binding every input that changes a proposal derived from it.
    ///
    /// Run identity and progress are both keyed by it, so a batch whose units,
    /// availability, ancestry, coverage or limitations changed can never resume
    /// another batch's work.
    pub fn digest(&self) -> mneme_core::ContentDigest {
        let units = self.units.iter().map(unit_identity);
        mneme_core::ContentDigest::of_payload(&mneme_core::Value::record_named(
            "input-batch",
            vec![
                self.scope.to_value(),
                self.requested_revision.to_value(),
                self.served_revision.to_value(),
                mneme_core::Value::string(self.eligibility_generation.to_string()),
                mneme_core::Value::set(units),
                mneme_core::Value::set(self.reviewed.iter().map(|key| {
                    mneme_core::Value::record_named(
                        "input-key",
                        vec![key.record_id.to_value(), key.revision_id.to_value()],
                    )
                })),
                mneme_core::Value::set(self.declared_extent.iter().flat_map(|extent| {
                    extent.iter().map(|key| {
                        mneme_core::Value::record_named(
                            "input-key",
                            vec![key.record_id.to_value(), key.revision_id.to_value()],
                        )
                    })
                })),
                coverage_value(&self.coverage),
                mneme_core::Value::string(self.limitations.status.clone()),
                mneme_core::Value::integer(i64::from(u8::from(self.limitations.exhaustive))),
                mneme_core::Value::integer(i64::from(u8::from(
                    self.limitations.absence_established,
                ))),
                mneme_core::Value::integer(i64::from(u8::from(self.limitations.truncated))),
                mneme_core::Value::set(
                    self.limitations
                        .omissions
                        .iter()
                        .cloned()
                        .map(mneme_core::Value::string),
                ),
                mneme_core::Value::set(self.limitations.modes.iter().map(|mode| {
                    mneme_core::Value::record_named(
                        "recall-mode",
                        vec![
                            mneme_core::Value::string(mode.mode.clone()),
                            mneme_core::Value::string(mode.status.clone()),
                            mneme_core::Value::integer(i64::from(u8::from(mode.complete))),
                            mode.reason.clone().map_or_else(
                                || mneme_core::Value::symbol("none"),
                                mneme_core::Value::string,
                            ),
                        ],
                    )
                })),
                mneme_core::Value::string(self.limitations.unpinned_candidates.to_string()),
            ],
        ))
    }

    /// Validate identity, reviewed extent, and coverage claims.
    pub fn validate(&self) -> Result<(), String> {
        let mut keys = std::collections::BTreeSet::new();
        for unit in &self.units {
            if !keys.insert(unit.key) {
                return Err("input batch contains a duplicate unit".to_owned());
            }
            if let Some(reason) = unit.availability.reason()
                && reason.trim().is_empty()
            {
                return Err("unavailable input needs a reason".to_owned());
            }
            if unit.ancestry_roots.is_empty() {
                return Err("each input unit needs ancestry roots".to_owned());
            }
        }
        if !self.reviewed.is_subset(&keys) {
            return Err("reviewed units are not all in the batch".to_owned());
        }
        match &self.coverage {
            BatchCoverage::Complete => {
                let Some(extent) = &self.declared_extent else {
                    return Err("complete coverage needs a declared extent".to_owned());
                };
                if !extent.is_subset(&keys) || &self.reviewed != extent {
                    return Err("complete coverage must review the declared extent".to_owned());
                }
            }
            BatchCoverage::Partial { reason } | BatchCoverage::Unknown { reason } => {
                if reason.trim().is_empty() {
                    return Err("incomplete coverage needs a reason".to_owned());
                }
            }
        }
        Ok(())
    }
}

/// The digest value of one input unit.
///
/// Every field a generator reads is bound: identity, kind, availability and its
/// reason, authority, derivation and ancestry roots.
fn unit_identity(unit: &InputUnit) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "input-unit",
        vec![
            unit.key.record_id.to_value(),
            unit.key.revision_id.to_value(),
            mneme_core::Value::symbol(unit.kind.name()),
            mneme_core::Value::symbol(unit.availability.name()),
            unit.availability.reason().map_or_else(
                || mneme_core::Value::symbol("none"),
                mneme_core::Value::string,
            ),
            mneme_core::Value::symbol(unit.authority.name()),
            unit.derivation.map_or_else(
                || mneme_core::Value::symbol("none"),
                mneme_core::RecordId::to_value,
            ),
            mneme_core::Value::set(unit.ancestry_roots.iter().map(|root| {
                mneme_core::Value::record_named(
                    "input-key",
                    vec![root.record_id.to_value(), root.revision_id.to_value()],
                )
            })),
        ],
    )
}

/// The digest value of a batch's coverage claim.
fn coverage_value(coverage: &BatchCoverage) -> mneme_core::Value {
    match coverage {
        BatchCoverage::Complete => {
            mneme_core::Value::record_named("coverage", vec![mneme_core::Value::symbol("complete")])
        }
        BatchCoverage::Partial { reason } | BatchCoverage::Unknown { reason } => {
            mneme_core::Value::record_named(
                "coverage",
                vec![mneme_core::Value::string(reason.clone())],
            )
        }
    }
}

/// The availability in force for one pinned source revision.
///
/// A suppression, a pruned revision and a corrupt blob all resolve to an
/// unavailable unit: retention decisions reach every older revision of the
/// record, so blob presence never outranks them.
fn source_availability(
    view: &mneme_memory::View,
    source: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
) -> InputAvailability {
    let Ok(pinned) = view.source_at(source, revision) else {
        return InputAvailability::Unavailable {
            reason: "source revision is not retained".to_owned(),
        };
    };
    if let Some(suppression) = view.suppression_for(&pinned.record) {
        return match suppression.mode {
            mneme_store::SuppressionMode::Forgotten => InputAvailability::Forgotten {
                reason: "source was explicitly forgotten".to_owned(),
            },
            mneme_store::SuppressionMode::Withdrawn => InputAvailability::Unavailable {
                reason: "source was withdrawn".to_owned(),
            },
        };
    }
    match view.source_status_for(&pinned) {
        Ok(mneme_memory::SourceStatus::Retained(_)) => InputAvailability::Retained,
        Ok(status) => InputAvailability::from_source_availability(&status.availability()),
        Err(_) => InputAvailability::Unavailable {
            reason: "source bytes could not be read".to_owned(),
        },
    }
}

/// The authority a candidate's content carries.
fn unit_authority(kind: mneme_recall::ContentKind) -> ProposalAuthority {
    match kind {
        mneme_recall::ContentKind::StructuredRow => ProposalAuthority::Derived,
        mneme_recall::ContentKind::SourceExcerpt
        | mneme_recall::ContentKind::Claim
        | mneme_recall::ContentKind::EpisodeSummary
        | mneme_recall::ContentKind::TypedField => ProposalAuthority::Observed,
    }
}

/// Job execution status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobStatus {
    Running,
    Complete,
    Partial,
    Timeout,
    Cancelled,
    Failed,
}

/// One consolidation job over a pinned batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    pub job_id: String,
    pub recorded_at: mneme_core::Timestamp,
    pub idempotency_key: String,
    pub scope: mneme_core::ScopeId,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub policy_version: String,
    pub extractor: Option<ExtractorDescriptor>,
    pub batch: InputBatch,
    pub limits: JobLimits,
    pub status: JobStatus,
}

impl Job {
    /// Validate the job envelope and its batch.
    pub fn validate(&self) -> Result<(), String> {
        if self.job_id.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || self.policy_version.trim().is_empty()
        {
            return Err(
                "job identity, idempotency key, and policy version are required".to_owned(),
            );
        }
        self.limits.validate()?;
        self.batch.validate()?;
        if self.batch.scope != self.scope {
            return Err("batch scope does not match the job scope".to_owned());
        }
        if self.batch.requested_revision != self.base_revision {
            return Err("batch requested revision does not match the job base".to_owned());
        }
        if let Some(extractor) = &self.extractor {
            extractor.validate()?;
        }
        if self.status == JobStatus::Complete
            && !matches!(self.batch.coverage, BatchCoverage::Complete)
        {
            return Err("complete job cannot have incomplete batch coverage".to_owned());
        }
        Ok(())
    }
}

/// One exact source or derivation premise for a proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalPremise {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub span: Option<mneme_core::SourceSpan>,
    pub derivation: Option<mneme_core::RecordId>,
    pub ancestry_roots: std::collections::BTreeSet<InputKey>,
    pub authority: ProposalAuthority,
}

/// The authority of one premise. Ingestion order is not authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalAuthority {
    Authored,
    Observed,
    Derived,
    ModelExtracted,
}

impl ProposalAuthority {
    /// Stable name for reports and run identity.
    pub fn name(self) -> &'static str {
        match self {
            ProposalAuthority::Authored => "authored",
            ProposalAuthority::Observed => "observed",
            ProposalAuthority::Derived => "derived",
            ProposalAuthority::ModelExtracted => "model-extracted",
        }
    }
}

/// A summary candidate. Its text remains an interpretation, not a quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryProposal {
    pub text: String,
}

/// A proposed assertion. It is not accepted until a separate command succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionProposal {
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub value: mneme_core::Value,
    pub stance: ProposalStance,
    pub valid_time: mneme_core::ValidTime,
    /// Explicit uncertainty preserved from model output, when supplied.
    pub uncertainty: Option<String>,
    /// Runtime and input provenance for supervised model extraction.
    pub extraction: Option<ExtractionProvenance>,
}

/// Content-free provenance for one model-produced claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractionProvenance {
    pub input_digest: String,
    pub configuration_digest: String,
    pub reported_model: Option<String>,
    pub elapsed_ns: u64,
    pub usage: mneme_recall::inference::UsageTelemetry,
}

/// Assertion stance inside a consolidation proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalStance {
    Affirm,
    Deny,
    Hypothesis,
}

/// A visible conflict proposal against an existing assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisputeProposal {
    pub assertion: mneme_core::RecordId,
    pub reason: String,
}

/// A proposed supersession of an existing assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupersessionProposal {
    pub prior: mneme_core::RecordId,
    pub prior_authority: ProposalAuthority,
    pub replacement: mneme_core::Value,
    pub reason: String,
    pub basis: SupersessionBasis,
}

/// Why a supersession was proposed. Ingestion order alone is never enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupersessionBasis {
    ExplicitCorrection,
    EvidenceConflict,
    LaterIngestion,
}

/// A proposed absence conclusion. It requires a complete declared extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbsenceProposal {
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub reason: String,
}

/// A proposed cleanup/retraction of records. It requires a complete extent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CleanupProposal {
    pub records: std::collections::BTreeSet<mneme_core::RecordId>,
    pub reason: String,
}

/// A procedural lesson kind. No variant is executable by consolidation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcedureKind {
    Runbook,
    Prompt,
    DatalogRule,
    Rule,
}

/// A procedural suggestion that requires its own validator/command path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureProposal {
    pub kind: ProcedureKind,
    pub content: String,
    pub validator: String,
}

impl ProcedureProposal {
    fn validate(&self) -> Result<(), String> {
        if self.content.trim().is_empty() || self.validator.trim().is_empty() {
            return Err("procedural proposal needs content and a validator".to_owned());
        }
        Ok(())
    }
}

/// The requested interpretation of a proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalOperation {
    Summary(SummaryProposal),
    Assertion(AssertionProposal),
    Dispute(DisputeProposal),
    Supersession(SupersessionProposal),
    Absence(AbsenceProposal),
    Cleanup(CleanupProposal),
    Procedure(ProcedureProposal),
}

/// An attributed review of whether cited evidence semantically supports a claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SupportOutcome {
    Supported,
    Rejected,
    UnsupportedHypothesis,
}

/// An attributed semantic-support review.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupportReview {
    pub actor: String,
    pub policy: String,
    pub outcome: SupportOutcome,
    pub detail: String,
}

impl SupportReview {
    pub fn validate(&self) -> Result<(), String> {
        if self.actor.trim().is_empty()
            || self.policy.trim().is_empty()
            || self.detail.trim().is_empty()
        {
            return Err("support review needs actor, policy, and detail".to_owned());
        }
        Ok(())
    }
}

/// Review disposition. Acceptance is never inferred from job completion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalDisposition {
    Pending,
    Accepted { decision: mneme_core::RecordId },
    Rejected { reason: String },
    Blocked { reason: String },
}

/// One typed consolidation proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub proposal_id: String,
    pub job_id: String,
    pub recorded_at: mneme_core::Timestamp,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    /// The consolidation policy the proposal was derived under.
    pub policy_version: String,
    /// The eligibility generation the input batch was pinned to.
    pub eligibility_generation: u64,
    pub operation: ProposalOperation,
    pub premises: Vec<ProposalPremise>,
    pub rationale: String,
    pub support: SupportReview,
    pub disposition: ProposalDisposition,
}

impl Proposal {
    /// Distinct ancestry roots, not repeated summary count.
    #[allow(unknown_lints, usize_in_public_api)] // support counts mirror collection lengths
    pub fn independent_support_count(&self) -> usize {
        self.premises
            .iter()
            .flat_map(|premise| premise.ancestry_roots.iter().copied())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// The records whose current revision this proposal depends on.
    ///
    /// An acceptance precondition must pin each of them, so a supersession of a
    /// rewritten prior, a dispute of a retracted assertion, or a cleanup of a
    /// record that changed since review is never silently accepted.
    pub fn operation_targets(&self) -> std::collections::BTreeSet<mneme_core::RecordId> {
        match &self.operation {
            ProposalOperation::Supersession(supersession) => {
                std::collections::BTreeSet::from([supersession.prior])
            }
            ProposalOperation::Dispute(dispute) => {
                std::collections::BTreeSet::from([dispute.assertion])
            }
            ProposalOperation::Cleanup(cleanup) => cleanup.records.clone(),
            ProposalOperation::Absence(_)
            | ProposalOperation::Assertion(_)
            | ProposalOperation::Summary(_)
            | ProposalOperation::Procedure(_) => std::collections::BTreeSet::new(),
        }
    }

    /// Redact a proposal whose source content was forgotten.
    ///
    /// The operation keeps its kind but loses the text, value, rationale, support
    /// review and citations derived from the forgotten bytes, and the disposition
    /// becomes terminal so no acceptance or retry can restore forbidden content.
    /// What remains is the proposal identity, its run identity, the operation
    /// kind with record identifiers, and the blocking reason — enough to answer a
    /// later command without retaining derived content.
    pub fn suppress(&mut self, reason: &str) {
        let operation = match &self.operation {
            ProposalOperation::Summary(_) => ProposalOperation::Summary(SummaryProposal {
                text: String::new(),
            }),
            ProposalOperation::Assertion(assertion) => {
                ProposalOperation::Assertion(AssertionProposal {
                    subject: assertion.subject,
                    predicate: assertion.predicate.clone(),
                    value: mneme_core::Value::symbol("redacted"),
                    stance: assertion.stance,
                    valid_time: mneme_core::ValidTime::Unknown,
                    uncertainty: None,
                    extraction: None,
                })
            }
            ProposalOperation::Dispute(dispute) => ProposalOperation::Dispute(DisputeProposal {
                assertion: dispute.assertion,
                reason: SUPPRESSED_MARKER.to_owned(),
            }),
            ProposalOperation::Supersession(supersession) => {
                ProposalOperation::Supersession(SupersessionProposal {
                    prior: supersession.prior,
                    prior_authority: supersession.prior_authority,
                    replacement: mneme_core::Value::symbol("redacted"),
                    reason: SUPPRESSED_MARKER.to_owned(),
                    basis: supersession.basis,
                })
            }
            ProposalOperation::Absence(absence) => ProposalOperation::Absence(AbsenceProposal {
                subject: absence.subject,
                predicate: absence.predicate.clone(),
                reason: SUPPRESSED_MARKER.to_owned(),
            }),
            ProposalOperation::Cleanup(cleanup) => ProposalOperation::Cleanup(CleanupProposal {
                records: cleanup.records.clone(),
                reason: SUPPRESSED_MARKER.to_owned(),
            }),
            ProposalOperation::Procedure(procedure) => {
                ProposalOperation::Procedure(ProcedureProposal {
                    kind: procedure.kind,
                    content: String::new(),
                    validator: procedure.validator.clone(),
                })
            }
        };
        self.operation = operation;
        self.premises.clear();
        self.rationale = "suppressed: source content was forgotten".to_owned();
        // A support review quotes the cited bytes it judged, so it is derived
        // content too: the redacted review records only that the claim is no
        // longer supportable.
        self.support = SupportReview {
            actor: SUPPRESSED_MARKER.to_owned(),
            policy: SUPPRESSED_MARKER.to_owned(),
            outcome: SupportOutcome::Rejected,
            detail: "suppressed: the source content was forgotten".to_owned(),
        };
        self.disposition = ProposalDisposition::Blocked {
            reason: reason.to_owned(),
        };
    }

    /// Validate proposal identity, support, and disposition.
    pub fn validate(&self) -> Result<(), String> {
        if self.proposal_id.trim().is_empty()
            || self.job_id.trim().is_empty()
            || self.rationale.trim().is_empty()
            || self.policy_version.trim().is_empty()
        {
            return Err(
                "proposal identity, job identity, policy, and rationale are required".to_owned(),
            );
        }
        if self.premises.is_empty()
            && !matches!(self.disposition, ProposalDisposition::Blocked { .. })
        {
            return Err("proposal needs at least one source or derivation premise".to_owned());
        }
        if self
            .premises
            .iter()
            .any(|premise| premise.ancestry_roots.is_empty())
        {
            return Err("each proposal premise needs ancestry roots".to_owned());
        }
        self.support.validate()?;
        match &self.operation {
            ProposalOperation::Procedure(procedure) => procedure.validate()?,
            ProposalOperation::Absence(absence)
                if absence.predicate.trim().is_empty() || absence.reason.trim().is_empty() =>
            {
                return Err("absence proposal needs a predicate and reason".to_owned());
            }
            ProposalOperation::Cleanup(cleanup)
                if cleanup.records.is_empty() || cleanup.reason.trim().is_empty() =>
            {
                return Err("cleanup proposal needs records and a reason".to_owned());
            }
            ProposalOperation::Supersession(supersession)
                if supersession.basis == SupersessionBasis::LaterIngestion =>
            {
                return Err("ingestion order alone never supersedes an assertion".to_owned());
            }
            ProposalOperation::Supersession(supersession)
                if supersession.reason.trim().is_empty() =>
            {
                return Err("a supersession needs an evidence-based reason".to_owned());
            }
            ProposalOperation::Dispute(dispute) if dispute.reason.trim().is_empty() => {
                return Err("a dispute needs an evidence-based reason".to_owned());
            }
            _ => {}
        }
        match (&self.support.outcome, &self.disposition) {
            (SupportOutcome::Supported, ProposalDisposition::Accepted { .. }) => {}
            (SupportOutcome::Supported, _) => {}
            (_, ProposalDisposition::Accepted { .. }) => {
                return Err(
                    "unsupported or rejected support cannot be accepted as supported".to_owned(),
                );
            }
            _ => {}
        }
        if let ProposalDisposition::Rejected { reason } | ProposalDisposition::Blocked { reason } =
            &self.disposition
            && reason.trim().is_empty()
        {
            return Err("rejected/blocked disposition needs a reason".to_owned());
        }
        Ok(())
    }
}

/// Reject absence/cleanup conclusions from ranked, truncated, or incomplete input
/// coverage. Other proposal kinds may still use individually validated units.
pub fn validate_proposal_against_batch(
    proposal: &Proposal,
    batch: &InputBatch,
) -> Result<(), String> {
    if matches!(
        proposal.operation,
        ProposalOperation::Absence(_) | ProposalOperation::Cleanup(_)
    ) && !batch.allows_absence_or_cleanup()
    {
        return Err(format!(
            "proposal {} cannot conclude absence or cleanup from incomplete recall coverage",
            proposal.proposal_id
        ));
    }
    Ok(())
}

/// An existing accepted assertion, kept distinct from proposals and observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedAssertionRef {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub lifecycle: mneme_core::Lifecycle,
}

impl AcceptedAssertionRef {
    /// Validate that this reference names an accepted assertion.
    pub fn validate(&self) -> Result<(), String> {
        if self.lifecycle != mneme_core::Lifecycle::Accepted {
            return Err("accepted assertion reference is not accepted".to_owned());
        }
        Ok(())
    }
}

/// Compare-and-swap acceptance preconditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptancePrecondition {
    pub proposal_id: String,
    pub proposal_revision: u64,
    pub expected_base_revision: mneme_core::WorkspaceRevisionId,
    pub expected_targets: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RevisionId>,
    pub required_sources: std::collections::BTreeSet<InputKey>,
    pub policy_version: String,
    pub scope: mneme_core::ScopeId,
}

impl AcceptancePrecondition {
    /// Validate that the acceptance names a proposal and pinned premises.
    pub fn validate(&self) -> Result<(), String> {
        if self.proposal_id.trim().is_empty()
            || self.proposal_revision == 0
            || self.policy_version.trim().is_empty()
        {
            return Err(
                "acceptance identity, revision, and policy version are required".to_owned(),
            );
        }
        if self.required_sources.is_empty() {
            return Err("acceptance needs at least one required source".to_owned());
        }
        Ok(())
    }
}

/// A fixture bundle that keeps the four artifact classes distinct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixture {
    pub observations: Vec<InputUnit>,
    pub job: Job,
    pub proposals: Vec<Proposal>,
    pub accepted_assertions: Vec<AcceptedAssertionRef>,
    pub acceptance: AcceptancePrecondition,
}

impl Fixture {
    /// Validate every component of a type-contract fixture.
    pub fn validate(&self) -> Result<(), String> {
        self.job.validate()?;
        for proposal in &self.proposals {
            proposal.validate()?;
            validate_proposal_against_batch(proposal, &self.job.batch)?;
        }
        for assertion in &self.accepted_assertions {
            assertion.validate()?;
        }
        self.acceptance.validate()?;
        Ok(())
    }
}

/// Construct sample fixture data used by the type-contract tests.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn fixture() -> Result<Fixture, String> {
    let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar")?;
    let base = mneme_core::WorkspaceRevisionId::from_bytes([0xb0; 16]);
    let source = InputKey {
        record_id: mneme_core::RecordId::from_bytes([0x20; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([0x21; 16]),
    };
    let observation = InputUnit::new(
        InputKey {
            record_id: mneme_core::RecordId::from_bytes([0x10; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0x11; 16]),
        },
        InputKind::Episode,
        InputAvailability::Retained,
    )
    .with_authority(ProposalAuthority::Authored);
    let accepted = AcceptedAssertionRef {
        record_id: mneme_core::RecordId::from_bytes([0x40; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([0x41; 16]),
        lifecycle: mneme_core::Lifecycle::Accepted,
    };
    let proposals = fixture_proposals(&scope, base, source);
    let batch = fixture_batch(&scope, base, &observation, source);
    Ok(Fixture {
        observations: vec![observation],
        job: fixture_job(scope.clone(), base, batch),
        proposals,
        accepted_assertions: vec![accepted],
        acceptance: fixture_acceptance(scope, base, source),
    })
}

fn fixture_proposals(
    scope: &mneme_core::ScopeId,
    base: mneme_core::WorkspaceRevisionId,
    source: InputKey,
) -> Vec<Proposal> {
    let premise = ProposalPremise {
        record_id: source.record_id,
        revision_id: source.revision_id,
        span: mneme_core::SourceSpan::new(0, 4).ok(),
        derivation: None,
        ancestry_roots: std::collections::BTreeSet::from([source]),
        authority: ProposalAuthority::Observed,
    };
    vec![
        fixture_summary_proposal(scope, base, premise.clone()),
        fixture_assertion_proposal(scope, base, premise.clone()),
        fixture_procedure_proposal(scope, base, premise),
    ]
}

fn fixture_support(detail: &str) -> SupportReview {
    SupportReview {
        actor: "reviewer".to_owned(),
        policy: "support-review/v1".to_owned(),
        outcome: SupportOutcome::Supported,
        detail: detail.to_owned(),
    }
}

fn fixture_summary_proposal(
    scope: &mneme_core::ScopeId,
    base: mneme_core::WorkspaceRevisionId,
    premise: ProposalPremise,
) -> Proposal {
    Proposal {
        proposal_id: "proposal-summary".to_owned(),
        job_id: "job-1".to_owned(),
        recorded_at: mneme_core::Timestamp::from_nanos(1_000),
        base_revision: base,
        scope: scope.clone(),
        policy_version: "consolidation-policy/v1".to_owned(),
        eligibility_generation: 0,
        operation: ProposalOperation::Summary(SummaryProposal {
            text: "Cedar uses SQLite.".to_owned(),
        }),
        premises: vec![premise],
        rationale: "summarize pinned evidence".to_owned(),
        support: fixture_support("cited span states the claim"),
        disposition: ProposalDisposition::Pending,
    }
}

fn fixture_assertion_proposal(
    scope: &mneme_core::ScopeId,
    base: mneme_core::WorkspaceRevisionId,
    premise: ProposalPremise,
) -> Proposal {
    Proposal {
        proposal_id: "proposal-assertion".to_owned(),
        job_id: "job-1".to_owned(),
        recorded_at: mneme_core::Timestamp::from_nanos(1_000),
        base_revision: base,
        scope: scope.clone(),
        policy_version: "consolidation-policy/v1".to_owned(),
        eligibility_generation: 0,
        operation: ProposalOperation::Assertion(AssertionProposal {
            subject: mneme_core::RecordId::from_bytes([0x10; 16]),
            predicate: "storage-engine".to_owned(),
            value: mneme_core::Value::string("SQLite"),
            stance: ProposalStance::Affirm,
            valid_time: mneme_core::ValidTime::Unknown,
            uncertainty: None,
            extraction: None,
        }),
        premises: vec![premise],
        rationale: "extract an explicitly proposed claim".to_owned(),
        support: fixture_support("cited span supports the storage engine"),
        disposition: ProposalDisposition::Pending,
    }
}

fn fixture_procedure_proposal(
    scope: &mneme_core::ScopeId,
    base: mneme_core::WorkspaceRevisionId,
    premise: ProposalPremise,
) -> Proposal {
    Proposal {
        proposal_id: "proposal-procedure".to_owned(),
        job_id: "job-1".to_owned(),
        recorded_at: mneme_core::Timestamp::from_nanos(1_000),
        base_revision: base,
        scope: scope.clone(),
        policy_version: "consolidation-policy/v1".to_owned(),
        eligibility_generation: 0,
        operation: ProposalOperation::Procedure(ProcedureProposal {
            kind: ProcedureKind::Rule,
            content: "grant_scope(user).".to_owned(),
            validator: "prolog-policy/v1".to_owned(),
        }),
        premises: vec![premise],
        rationale: "episode suggests a rule".to_owned(),
        support: fixture_support("source contains the suggested text"),
        disposition: ProposalDisposition::Blocked {
            reason: "requires separate procedural validation".to_owned(),
        },
    }
}

fn fixture_batch(
    scope: &mneme_core::ScopeId,
    base: mneme_core::WorkspaceRevisionId,
    observation: &InputUnit,
    source: InputKey,
) -> InputBatch {
    InputBatch {
        scope: scope.clone(),
        requested_revision: base,
        served_revision: base,
        eligibility_generation: 0,
        units: vec![
            observation.clone(),
            InputUnit::new(
                source,
                InputKind::SourceRevision,
                InputAvailability::Retained,
            ),
        ],
        reviewed: std::collections::BTreeSet::from([observation.key, source]),
        declared_extent: Some(std::collections::BTreeSet::from([observation.key, source])),
        coverage: BatchCoverage::Complete,
        limitations: RecallLimitations::complete(),
    }
}

fn fixture_job(
    scope: mneme_core::ScopeId,
    base: mneme_core::WorkspaceRevisionId,
    batch: InputBatch,
) -> Job {
    Job {
        job_id: "job-1".to_owned(),
        recorded_at: mneme_core::Timestamp::from_nanos(1_000),
        idempotency_key: "consolidate-1".to_owned(),
        scope,
        base_revision: base,
        policy_version: "consolidation-policy/v1".to_owned(),
        extractor: None,
        batch,
        limits: JobLimits {
            max_inputs: 8,
            max_proposals: 8,
            max_time_ms: 1_000,
            max_model_calls: 0,
        },
        status: JobStatus::Complete,
    }
}

fn fixture_acceptance(
    scope: mneme_core::ScopeId,
    base: mneme_core::WorkspaceRevisionId,
    source: InputKey,
) -> AcceptancePrecondition {
    AcceptancePrecondition {
        proposal_id: "proposal-summary".to_owned(),
        proposal_revision: 1,
        expected_base_revision: base,
        expected_targets: std::collections::BTreeMap::new(),
        required_sources: std::collections::BTreeSet::from([source]),
        policy_version: "consolidation-policy/v1".to_owned(),
        scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_keeps_observations_proposals_and_acceptances_distinct() {
        let fixture = fixture().expect("fixture");
        fixture.validate().expect("valid fixture");
        assert_eq!(fixture.observations[0].kind, InputKind::Episode);
        assert_eq!(
            fixture.accepted_assertions[0].lifecycle,
            mneme_core::Lifecycle::Accepted
        );
        assert!(matches!(
            fixture.proposals[0].disposition,
            ProposalDisposition::Pending
        ));
        assert!(matches!(
            fixture.proposals[1].operation,
            ProposalOperation::Assertion(_)
        ));
        assert!(matches!(
            fixture.proposals[1].disposition,
            ProposalDisposition::Pending
        ));
        assert!(matches!(
            fixture.proposals[2].operation,
            ProposalOperation::Procedure(_)
        ));
        assert!(matches!(
            fixture.proposals[2].disposition,
            ProposalDisposition::Blocked { .. }
        ));
    }

    #[test]
    fn unsupported_support_cannot_be_accepted() {
        let mut fixture = fixture().expect("fixture");
        fixture.proposals[0].support.outcome = SupportOutcome::UnsupportedHypothesis;
        fixture.proposals[0].disposition = ProposalDisposition::Accepted {
            decision: mneme_core::RecordId::from_bytes([0x50; 16]),
        };
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn complete_coverage_needs_a_declared_extent() {
        let mut fixture = fixture().expect("fixture");
        fixture.job.batch.declared_extent = None;
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn accepted_assertion_must_have_accepted_lifecycle() {
        let mut fixture = fixture().expect("fixture");
        fixture.accepted_assertions[0].lifecycle = mneme_core::Lifecycle::Proposed;
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn incomplete_job_keeps_limited_coverage() {
        let mut fixture = fixture().expect("fixture");
        fixture.job.status = JobStatus::Timeout;
        fixture.job.batch.coverage = BatchCoverage::Partial {
            reason: "timed out after one unit".to_owned(),
        };
        fixture.job.batch.declared_extent = Some(std::collections::BTreeSet::from([
            fixture.observations[0].key,
            InputKey {
                record_id: mneme_core::RecordId::from_bytes([0x20; 16]),
                revision_id: mneme_core::RevisionId::from_bytes([0x21; 16]),
            },
        ]));
        assert!(fixture.validate().is_ok());
    }

    #[test]
    fn ranked_recall_batch_retains_limitations_and_blocks_cleanup() {
        let fixture = fixture().expect("fixture");
        let scope = fixture.job.scope.clone();
        let revision = fixture.job.base_revision;
        let response = mneme_recall::Response {
            context: mneme_recall::Context {
                schema_version: 1,
                scope: scope.clone(),
                requested_revision: revision,
                served_revision: revision,
                current_revision: revision,
                stale: false,
                eligibility_generation: 3,
                temporal: mneme_recall::TemporalMode::Current,
                at: mneme_core::Timestamp::from_nanos(0),
                index_versions: std::collections::BTreeMap::new(),
                fusion_policy: "test/v1".to_owned(),
            },
            status: mneme_recall::Execution::Partial,
            modes: vec![mneme_recall::ModeReport {
                mode: mneme_recall::Mode::Lexical,
                status: mneme_recall::ModeStatus::Used,
                index_version: Some("test".to_owned()),
                revision: Some(revision),
                coverage: mneme_recall::IndexCoverage {
                    complete: false,
                    documents_indexed: 1,
                    documents_skipped: 3,
                    reason: Some("top-k limited".to_owned()),
                },
                candidates: 0,
                relation_exhaustive: None,
                reason: None,
                semantic_observation: None,
            }],
            candidates: Vec::new(),
            exhaustive: false,
            absence_established: false,
            truncated: true,
            omissions: vec![mneme_recall::Omission {
                candidate: "older-support".to_owned(),
                reason: "outside top-k".to_owned(),
            }],
            reason: Some("ranked recall".to_owned()),
            boundary: mneme_recall::DataBoundary::default(),
            budget: mneme_recall::BudgetUse {
                items_used: 0,
                items_allowed: 8,
                text_bytes_used: 0,
                text_bytes_allowed: 4096,
                excerpt_bytes_used: 0,
                excerpt_bytes_allowed: 256,
                elapsed_ms_used: 0,
                elapsed_ms_allowed: 500,
                work_used: 0,
                work_allowed: 1,
            },
        };
        let batch = InputBatch::from_recall_with(scope.clone(), revision, &response, |_, _| {
            InputAvailability::Retained
        })
        .expect("pinned recall batch");
        assert!(matches!(batch.coverage, BatchCoverage::Partial { .. }));
        assert_eq!(batch.eligibility_generation, 3);
        assert_eq!(batch.limitations.omissions.len(), 1);
        assert!(batch.limitations.truncated);
        assert!(!batch.allows_absence_or_cleanup());

        let mut fixture = fixture;
        let mut proposal = fixture.proposals[0].clone();
        proposal.operation = ProposalOperation::Cleanup(CleanupProposal {
            records: std::collections::BTreeSet::from([mneme_core::RecordId::from_bytes(
                [0x40; 16],
            )]),
            reason: "remove stale memory".to_owned(),
        });
        fixture.proposals = vec![proposal];
        fixture.job.batch = batch;
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn cleanup_requires_complete_coverage() {
        let mut fixture = fixture().expect("fixture");
        let mut proposal = fixture.proposals[0].clone();
        proposal.operation = ProposalOperation::Cleanup(CleanupProposal {
            records: std::collections::BTreeSet::from([mneme_core::RecordId::from_bytes(
                [0x40; 16],
            )]),
            reason: "remove stale memory".to_owned(),
        });
        fixture.proposals = vec![proposal];
        fixture.validate().expect("complete extent permits cleanup");
        fixture.job.batch.coverage = BatchCoverage::Partial {
            reason: "one input missing".to_owned(),
        };
        fixture.job.status = JobStatus::Partial;
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn copied_summaries_share_one_independent_root() {
        let mut fixture = fixture().expect("fixture");
        let base_premise = fixture.proposals[0].premises[0].clone();
        fixture.proposals[0].premises =
            vec![base_premise.clone(), base_premise.clone(), base_premise];
        fixture.validate().expect("shared ancestry remains valid");
        assert_eq!(fixture.proposals[0].independent_support_count(), 1);
    }

    #[test]
    fn later_ingestion_cannot_supersede_authored_fact() {
        let mut fixture = fixture().expect("fixture");
        fixture.proposals[0].operation = ProposalOperation::Supersession(SupersessionProposal {
            prior: mneme_core::RecordId::from_bytes([0x40; 16]),
            prior_authority: ProposalAuthority::Authored,
            replacement: mneme_core::Value::string("PostgreSQL"),
            reason: "newer import".to_owned(),
            basis: SupersessionBasis::LaterIngestion,
        });
        assert!(fixture.validate().is_err());
        if let ProposalOperation::Supersession(supersession) = &mut fixture.proposals[0].operation {
            supersession.basis = SupersessionBasis::ExplicitCorrection;
        }
        fixture
            .validate()
            .expect("explicit correction can supersede");
    }

    #[test]
    fn dispute_remains_pending_and_does_not_rewrite_accepted_assertion() {
        let mut fixture = fixture().expect("fixture");
        fixture.proposals[0].operation = ProposalOperation::Dispute(DisputeProposal {
            assertion: mneme_core::RecordId::from_bytes([0x40; 16]),
            reason: "source contradicts the authored claim".to_owned(),
        });
        fixture.validate().expect("visible dispute");
        assert!(matches!(
            fixture.proposals[0].disposition,
            ProposalDisposition::Pending
        ));
        assert_eq!(
            fixture.accepted_assertions[0].lifecycle,
            mneme_core::Lifecycle::Accepted
        );
    }

    #[test]
    fn valid_and_recorded_times_are_separate() {
        let fixture = fixture().expect("fixture");
        assert_eq!(
            fixture.proposals[1].recorded_at,
            mneme_core::Timestamp::from_nanos(1_000)
        );
        let assertion = match &fixture.proposals[1].operation {
            ProposalOperation::Assertion(assertion) => assertion,
            _ => return,
        };
        assert_eq!(assertion.valid_time, mneme_core::ValidTime::Unknown);
    }
}
