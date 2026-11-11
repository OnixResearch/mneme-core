//! Bounded consolidation job, batch, proposal, disposition, and acceptance
//! contracts.
//!
//! These types deliberately separate observations, proposed interpretations,
//! accepted assertions, and procedural suggestions. A job producing proposals
//! never accepts them; acceptance is a separate compare-and-swap precondition
//! evaluated by a later command.

#![cfg_attr(test, allow(clippy::expect_used))]

use std::collections::{BTreeMap, BTreeSet};

use mneme_core::{
    Lifecycle, RecordId, RevisionId, ScopeId, SourceSpan, ValidTime, Value, WorkspaceRevisionId,
};

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
    pub record_id: RecordId,
    pub revision_id: RevisionId,
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
}

/// One exact input unit and its source availability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputUnit {
    pub key: InputKey,
    pub kind: InputKind,
    pub availability: InputAvailability,
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
    pub units: Vec<InputUnit>,
    pub reviewed: BTreeSet<InputKey>,
    pub declared_extent: Option<BTreeSet<InputKey>>,
    pub coverage: BatchCoverage,
}

impl InputBatch {
    /// Validate identity, reviewed extent, and coverage claims.
    pub fn validate(&self) -> Result<(), String> {
        let mut keys = BTreeSet::new();
        for unit in &self.units {
            if !keys.insert(unit.key) {
                return Err("input batch contains a duplicate unit".to_owned());
            }
            if let InputAvailability::Pruned { reason } = &unit.availability
                && reason.trim().is_empty()
            {
                return Err("pruned input needs a reason".to_owned());
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
    pub idempotency_key: String,
    pub scope: ScopeId,
    pub base_revision: WorkspaceRevisionId,
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
    pub record_id: RecordId,
    pub revision_id: RevisionId,
    pub span: Option<SourceSpan>,
    pub derivation: Option<RecordId>,
}

/// A summary candidate. Its text remains an interpretation, not a quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryProposal {
    pub text: String,
}

/// A proposed assertion. It is not accepted until a separate command succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssertionProposal {
    pub subject: RecordId,
    pub predicate: String,
    pub value: Value,
    pub stance: ProposalStance,
    pub valid_time: ValidTime,
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
    pub assertion: RecordId,
    pub reason: String,
}

/// A proposed supersession of an existing assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupersessionProposal {
    pub prior: RecordId,
    pub replacement: Value,
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
    fn validate(&self) -> Result<(), String> {
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
    Accepted { decision: RecordId },
    Rejected { reason: String },
    Blocked { reason: String },
}

/// One typed consolidation proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationProposal {
    pub proposal_id: String,
    pub job_id: String,
    pub base_revision: WorkspaceRevisionId,
    pub scope: ScopeId,
    pub operation: ProposalOperation,
    pub premises: Vec<ProposalPremise>,
    pub rationale: String,
    pub support: SupportReview,
    pub disposition: ProposalDisposition,
}

impl ConsolidationProposal {
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
        self.support.validate()?;
        if let ProposalOperation::Procedure(procedure) = &self.operation {
            procedure.validate()?;
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

/// An existing accepted assertion, kept distinct from proposals and observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedAssertionRef {
    pub record_id: RecordId,
    pub revision_id: RevisionId,
    pub lifecycle: Lifecycle,
}

impl AcceptedAssertionRef {
    /// Validate that this reference names an accepted assertion.
    pub fn validate(&self) -> Result<(), String> {
        if self.lifecycle != Lifecycle::Accepted {
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
    pub expected_base_revision: WorkspaceRevisionId,
    pub expected_targets: BTreeMap<RecordId, RevisionId>,
    pub required_sources: BTreeSet<InputKey>,
    pub policy_version: String,
    pub scope: ScopeId,
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
        }
        for assertion in &self.accepted_assertions {
            assertion.validate()?;
        }
        self.acceptance.validate()?;
        Ok(())
    }
}

/// Construct sample fixture data used by the type-contract tests.
pub fn fixture() -> Result<ConsolidationFixture, String> {
    let scope = ScopeId::new(mneme_core::ScopeClass::Project, "cedar")?;
    let base = WorkspaceRevisionId::from_bytes([0xb0; 16]);
    let source = InputKey {
        record_id: RecordId::from_bytes([0x20; 16]),
        revision_id: RevisionId::from_bytes([0x21; 16]),
    };
    let observation = InputUnit {
        key: InputKey {
            record_id: RecordId::from_bytes([0x10; 16]),
            revision_id: RevisionId::from_bytes([0x11; 16]),
        },
        kind: InputKind::Episode,
        availability: InputAvailability::Retained,
    };
    let accepted = AcceptedAssertionRef {
        record_id: RecordId::from_bytes([0x40; 16]),
        revision_id: RevisionId::from_bytes([0x41; 16]),
        lifecycle: Lifecycle::Accepted,
    };
    let premise = ProposalPremise {
        record_id: source.record_id,
        revision_id: source.revision_id,
        span: SourceSpan::new(0, 4).ok(),
        derivation: None,
    };
    let proposals = vec![
        ConsolidationProposal {
            proposal_id: "proposal-summary".to_owned(),
            job_id: "job-1".to_owned(),
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
            base_revision: base,
            scope: scope.clone(),
            operation: ProposalOperation::Assertion(AssertionProposal {
                subject: RecordId::from_bytes([0x10; 16]),
                predicate: "storage-engine".to_owned(),
                value: Value::string("SQLite"),
                stance: ProposalStance::Affirm,
                valid_time: ValidTime::Unknown,
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
        units: vec![
            observation.clone(),
            InputUnit {
                key: source,
                kind: InputKind::SourceRevision,
                availability: InputAvailability::Retained,
            },
        ],
        reviewed: BTreeSet::from([observation.key, source]),
        declared_extent: Some(BTreeSet::from([observation.key, source])),
        coverage: BatchCoverage::Complete,
    };
    Ok(ConsolidationFixture {
        observations: vec![observation],
        job: ConsolidationJob {
            job_id: "job-1".to_owned(),
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
            expected_targets: BTreeMap::new(),
            required_sources: BTreeSet::from([source]),
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
            Lifecycle::Accepted
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
            decision: RecordId::from_bytes([0x50; 16]),
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
        fixture.accepted_assertions[0].lifecycle = Lifecycle::Proposed;
        assert!(fixture.validate().is_err());
    }

    #[test]
    fn incomplete_job_keeps_limited_coverage() {
        let mut fixture = fixture().expect("fixture");
        fixture.job.status = JobStatus::Timeout;
        fixture.job.batch.coverage = BatchCoverage::Partial {
            reason: "timed out after one unit".to_owned(),
        };
        fixture.job.batch.declared_extent = Some(BTreeSet::from([
            fixture.observations[0].key,
            InputKey {
                record_id: RecordId::from_bytes([0x20; 16]),
                revision_id: RevisionId::from_bytes([0x21; 16]),
            },
        ]));
        assert!(fixture.validate().is_ok());
    }
}
