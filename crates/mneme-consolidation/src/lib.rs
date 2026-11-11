//! Bounded consolidation job, batch, proposal, disposition, and acceptance
//! contracts.
//!
//! These types deliberately separate observations, proposed interpretations,
//! accepted assertions, and procedural suggestions. A job producing proposals
//! never accepts them; acceptance is a separate compare-and-swap precondition
//! evaluated by a later command.
#![allow(unknown_lints, path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional
#![cfg_attr(test, allow(clippy::expect_used))]

pub mod commands;
pub mod generator;
pub mod job;
pub mod procedure;

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

/// Whether input bytes remain available for quotation/extraction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InputAvailability {
    Retained,
    Pruned { reason: String },
    Forgotten { reason: String },
}

/// One exact input unit and its source availability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputUnit {
    pub key: InputKey,
    pub kind: InputKind,
    pub availability: InputAvailability,
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
    #[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn from_recall(
        scope: mneme_core::ScopeId,
        expected_revision: mneme_core::WorkspaceRevisionId,
        response: &mneme_recall::RecallResponse,
    ) -> Result<Self, String> {
        if response.context.scope != scope {
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
            let availability = candidate
                .evidence
                .iter()
                .find(|evidence| evidence.source == source)
                .map(|evidence| {
                    if evidence.availability.name() == "pruned" {
                        InputAvailability::Pruned {
                            reason: "source bytes were pruned".to_owned(),
                        }
                    } else {
                        InputAvailability::Retained
                    }
                })
                .unwrap_or(InputAvailability::Retained);
            units.push(InputUnit {
                key,
                kind: InputKind::SourceRevision,
                availability,
            });
        }
        let reviewed = units
            .iter()
            .map(|unit| unit.key)
            .collect::<std::collections::BTreeSet<_>>();
        let limitations = RecallLimitations {
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
        };
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

    /// Whether a batch may support an absence or cleanup conclusion.
    pub fn allows_absence_or_cleanup(&self) -> bool {
        matches!(self.coverage, BatchCoverage::Complete)
            && self.limitations.exhaustive
            && !self.limitations.truncated
            && self.limitations.omissions.is_empty()
            && self.limitations.unpinned_candidates == 0
            && self.limitations.modes.iter().all(|mode| mode.complete)
    }

    /// Validate identity, reviewed extent, and coverage claims.
    pub fn validate(&self) -> Result<(), String> {
        let mut keys = std::collections::BTreeSet::new();
        for unit in &self.units {
            if !keys.insert(unit.key) {
                return Err("input batch contains a duplicate unit".to_owned());
            }
            if let InputAvailability::Pruned { reason } | InputAvailability::Forgotten { reason } =
                &unit.availability
                && reason.trim().is_empty()
            {
                return Err("unavailable input needs a reason".to_owned());
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
pub struct ConsolidationJob {
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

impl ConsolidationJob {
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
    PrologRule,
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
pub struct ConsolidationProposal {
    pub proposal_id: String,
    pub job_id: String,
    pub recorded_at: mneme_core::Timestamp,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    pub scope: mneme_core::ScopeId,
    pub operation: ProposalOperation,
    pub premises: Vec<ProposalPremise>,
    pub rationale: String,
    pub support: SupportReview,
    pub disposition: ProposalDisposition,
}

impl ConsolidationProposal {
    /// Distinct ancestry roots, not repeated summary count.
    #[allow(unknown_lints, usize_in_public_api)] // support counts mirror collection lengths
    pub fn independent_support_count(&self) -> usize {
        self.premises
            .iter()
            .flat_map(|premise| premise.ancestry_roots.iter().copied())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    }

    /// Validate proposal identity, support, and disposition.
    pub fn validate(&self) -> Result<(), String> {
        if self.proposal_id.trim().is_empty()
            || self.job_id.trim().is_empty()
            || self.rationale.trim().is_empty()
        {
            return Err("proposal identity, job identity, and rationale are required".to_owned());
        }
        if self.premises.is_empty() {
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
                if supersession.basis == SupersessionBasis::LaterIngestion
                    && supersession.prior_authority == ProposalAuthority::Authored =>
            {
                return Err("later ingestion cannot supersede an authored assertion".to_owned());
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
    proposal: &ConsolidationProposal,
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
pub struct ConsolidationFixture {
    pub observations: Vec<InputUnit>,
    pub job: ConsolidationJob,
    pub proposals: Vec<ConsolidationProposal>,
    pub accepted_assertions: Vec<AcceptedAssertionRef>,
    pub acceptance: AcceptancePrecondition,
}

impl ConsolidationFixture {
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
#[allow(unknown_lints, function_length)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn fixture() -> Result<ConsolidationFixture, String> {
    let scope = mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar")?;
    let base = mneme_core::WorkspaceRevisionId::from_bytes([0xb0; 16]);
    let source = InputKey {
        record_id: mneme_core::RecordId::from_bytes([0x20; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([0x21; 16]),
    };
    let observation = InputUnit {
        key: InputKey {
            record_id: mneme_core::RecordId::from_bytes([0x10; 16]),
            revision_id: mneme_core::RevisionId::from_bytes([0x11; 16]),
        },
        kind: InputKind::Episode,
        availability: InputAvailability::Retained,
    };
    let accepted = AcceptedAssertionRef {
        record_id: mneme_core::RecordId::from_bytes([0x40; 16]),
        revision_id: mneme_core::RevisionId::from_bytes([0x41; 16]),
        lifecycle: mneme_core::Lifecycle::Accepted,
    };
    let premise = ProposalPremise {
        record_id: source.record_id,
        revision_id: source.revision_id,
        span: mneme_core::SourceSpan::new(0, 4).ok(),
        derivation: None,
        ancestry_roots: std::collections::BTreeSet::from([source]),
        authority: ProposalAuthority::Observed,
    };
    let proposals = vec![
        ConsolidationProposal {
            proposal_id: "proposal-summary".to_owned(),
            job_id: "job-1".to_owned(),
            recorded_at: mneme_core::Timestamp::from_nanos(1_000),
            base_revision: base,
            scope: scope.clone(),
            operation: ProposalOperation::Summary(SummaryProposal {
                text: "Cedar uses SQLite.".to_owned(),
            }),
            premises: vec![premise.clone()],
            rationale: "summarize pinned evidence".to_owned(),
            support: SupportReview {
                actor: "reviewer".to_owned(),
                policy: "support-review/v1".to_owned(),
                outcome: SupportOutcome::Supported,
                detail: "cited span states the claim".to_owned(),
            },
            disposition: ProposalDisposition::Pending,
        },
        ConsolidationProposal {
            proposal_id: "proposal-assertion".to_owned(),
            job_id: "job-1".to_owned(),
            recorded_at: mneme_core::Timestamp::from_nanos(1_000),
            base_revision: base,
            scope: scope.clone(),
            operation: ProposalOperation::Assertion(AssertionProposal {
                subject: mneme_core::RecordId::from_bytes([0x10; 16]),
                predicate: "storage-engine".to_owned(),
                value: mneme_core::Value::string("SQLite"),
                stance: ProposalStance::Affirm,
                valid_time: mneme_core::ValidTime::Unknown,
            }),
            premises: vec![premise.clone()],
            rationale: "extract an explicitly proposed claim".to_owned(),
            support: SupportReview {
                actor: "reviewer".to_owned(),
                policy: "support-review/v1".to_owned(),
                outcome: SupportOutcome::Supported,
                detail: "cited span supports the storage engine".to_owned(),
            },
            disposition: ProposalDisposition::Pending,
        },
        ConsolidationProposal {
            proposal_id: "proposal-procedure".to_owned(),
            job_id: "job-1".to_owned(),
            recorded_at: mneme_core::Timestamp::from_nanos(1_000),
            base_revision: base,
            scope: scope.clone(),
            operation: ProposalOperation::Procedure(ProcedureProposal {
                kind: ProcedureKind::PrologRule,
                content: "grant_scope(user).".to_owned(),
                validator: "prolog-policy/v1".to_owned(),
            }),
            premises: vec![premise],
            rationale: "episode suggests a rule".to_owned(),
            support: SupportReview {
                actor: "reviewer".to_owned(),
                policy: "support-review/v1".to_owned(),
                outcome: SupportOutcome::Supported,
                detail: "source contains the suggested text".to_owned(),
            },
            disposition: ProposalDisposition::Blocked {
                reason: "requires separate procedural validation".to_owned(),
            },
        },
    ];
    let batch = InputBatch {
        scope: scope.clone(),
        requested_revision: base,
        served_revision: base,
        eligibility_generation: 0,
        units: vec![
            observation.clone(),
            InputUnit {
                key: source,
                kind: InputKind::SourceRevision,
                availability: InputAvailability::Retained,
            },
        ],
        reviewed: std::collections::BTreeSet::from([observation.key, source]),
        declared_extent: Some(std::collections::BTreeSet::from([observation.key, source])),
        coverage: BatchCoverage::Complete,
        limitations: RecallLimitations::complete(),
    };
    Ok(ConsolidationFixture {
        observations: vec![observation],
        job: ConsolidationJob {
            job_id: "job-1".to_owned(),
            recorded_at: mneme_core::Timestamp::from_nanos(1_000),
            idempotency_key: "consolidate-1".to_owned(),
            scope: scope.clone(),
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
        },
        proposals,
        accepted_assertions: vec![accepted],
        acceptance: AcceptancePrecondition {
            proposal_id: "proposal-summary".to_owned(),
            proposal_revision: 1,
            expected_base_revision: base,
            expected_targets: std::collections::BTreeMap::new(),
            required_sources: std::collections::BTreeSet::from([source]),
            policy_version: "consolidation-policy/v1".to_owned(),
            scope,
        },
    })
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
        let response = mneme_recall::RecallResponse {
            context: mneme_recall::RecallContext {
                schema_version: 1,
                scope: scope.clone(),
                requested_revision: revision,
                served_revision: revision,
                eligibility_generation: 3,
                temporal: mneme_recall::TemporalMode::Current,
                index_versions: std::collections::BTreeMap::new(),
                fusion_policy: "test/v1".to_owned(),
            },
            status: mneme_recall::RecallExecution::Partial,
            modes: vec![mneme_recall::ModeReport {
                mode: mneme_recall::RecallMode::Lexical,
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
        };
        let batch = InputBatch::from_recall(scope.clone(), revision, &response)
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
