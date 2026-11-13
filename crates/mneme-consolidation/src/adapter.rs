//! The workspace entry point for consolidation.
//!
//! [`consolidate_workspace`] runs one consolidation job against a committed
//! workspace: it pins a view, selects the reviewed extent with authorized
//! recall, generates proposals under the job's limits, and commits each
//! generated proposal as a *proposed* assertion with pinned evidence through
//! the memory engine. Nothing on this path accepts a proposal or rewrites an
//! accepted assertion; acceptance stays with the separate acceptance command.
//!
//! The job is idempotent per request: a retry of the same request replays the
//! recorded commit and reports it as replayed, and a run whose record identities
//! already exist never commits a second copy. A retry under a different policy,
//! limit, extractor or input revision is a different run with different record
//! identities, never a silent reuse of the earlier one.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// Declared cost of processing one input unit, in milliseconds.
///
/// This layer reads no clock, so the job's time budget is charged in declared
/// units: one millisecond per reviewed input. A caller that needs a tighter or
/// looser budget bounds the work with `max_inputs`, `max_proposals` and
/// `max_model_calls`.
const UNIT_COST_MS: u64 = 1;

/// Bounds for the recall that selects the reviewed extent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecallBounds {
    pub max_items: usize,
    pub max_context_bytes: usize,
    pub max_quote_bytes: usize,
    pub max_time_ms: u128,
}

impl RecallBounds {
    /// Conservative budgets for one consolidation job.
    pub fn conservative() -> Self {
        RecallBounds {
            max_items: 32,
            max_context_bytes: 32_768,
            max_quote_bytes: 4_096,
            max_time_ms: 500,
        }
    }
}

/// One workspace-backed consolidation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceJob {
    /// The principal committing the proposals.
    pub actor: String,
    /// The one scope this job consolidates.
    pub scope: mneme_core::ScopeId,
    /// The caller's scope authorization.
    pub access: mneme_memory::Access,
    pub job_id: String,
    /// The request identity; a retry under the same key and content replays.
    pub idempotency_key: String,
    pub policy_version: String,
    /// The extractor configuration this run is attributed to, when any.
    pub extractor: Option<crate::ExtractorDescriptor>,
    /// The recall query that selects the reviewed extent.
    pub query: String,
    /// The valid-time instant current-mode recall selects claims at.
    pub at: mneme_core::Timestamp,
    /// The recorded time carried by the job envelope.
    pub recorded_at: mneme_core::Timestamp,
    pub limits: crate::JobLimits,
    pub recall: RecallBounds,
}

/// Who is asking for one consolidation run, and when.
///
/// These are the caller-supplied facts about the request itself rather than
/// about the work: every one of them is part of the run identity, so a retry
/// differs from a new run exactly when one of them differs.
#[derive(Clone, Copy, Debug)]
pub struct JobRequest<'a> {
    /// The principal committing the proposals.
    pub actor: &'a str,
    /// The job identity carried by the run and its proposals.
    pub job_id: &'a str,
    /// The request identity; a retry under the same key and content replays.
    pub idempotency_key: &'a str,
    /// The recall query that selects the reviewed extent.
    pub query: &'a str,
    /// The valid-time instant current-mode recall selects claims at.
    pub at: mneme_core::Timestamp,
    /// The recorded time carried by the job envelope.
    pub recorded_at: mneme_core::Timestamp,
}

impl WorkspaceJob {
    /// A conservative request over one scope.
    pub fn new(
        scope: mneme_core::ScopeId,
        access: mneme_memory::Access,
        request: JobRequest<'_>,
    ) -> Self {
        WorkspaceJob {
            actor: request.actor.to_owned(),
            scope,
            access,
            job_id: request.job_id.to_owned(),
            idempotency_key: request.idempotency_key.to_owned(),
            policy_version: "consolidation-policy/v1".to_owned(),
            extractor: None,
            query: request.query.to_owned(),
            at: request.at,
            recorded_at: request.recorded_at,
            limits: crate::JobLimits {
                max_inputs: 8,
                max_proposals: 8,
                max_time_ms: 1_000,
                max_model_calls: 0,
            },
            recall: RecallBounds::conservative(),
        }
    }

    /// Validate the request envelope before any work is done.
    pub fn validate(&self) -> Result<(), Failure> {
        for (name, value) in [
            ("actor", self.actor.as_str()),
            ("job", self.job_id.as_str()),
            ("idempotency key", self.idempotency_key.as_str()),
            ("policy version", self.policy_version.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(Failure::Invalid(format!("{name} is required")));
            }
        }
        self.limits.validate().map_err(Failure::Invalid)?;
        if !self.access.allows(&self.scope) {
            return Err(Failure::Invalid(
                "the caller is not authorized for the requested scope".to_owned(),
            ));
        }
        if self.recall.max_items == 0
            || self.recall.max_context_bytes == 0
            || self.recall.max_quote_bytes == 0
            || self.recall.max_time_ms == 0
        {
            return Err(Failure::Invalid(
                "recall bounds must be positive".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One proposal committed as a proposed assertion with pinned evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedProposal {
    pub proposal_id: String,
    pub assertion: mneme_core::RecordId,
    pub assertion_revision: mneme_core::RevisionId,
    pub evidence: mneme_core::RecordId,
    pub evidence_revision: mneme_core::RevisionId,
}

/// A reviewed input the job did not commit a proposal for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SkippedUnit {
    pub key: crate::InputKey,
    pub reason: String,
}

/// The outcome of one workspace-backed consolidation job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceReceipt {
    pub job_id: String,
    pub status: crate::JobStatus,
    pub base_revision: mneme_core::WorkspaceRevisionId,
    /// The workspace revision when the job finished.
    pub revision: mneme_core::WorkspaceRevisionId,
    pub committed: Vec<CommittedProposal>,
    pub skipped: Vec<SkippedUnit>,
    /// The commit was already recorded and was not written twice.
    pub replayed: bool,
}

/// Why a workspace-backed consolidation job did not complete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The request envelope or the generated proposal is invalid.
    Invalid(String),
    /// Recall over the pinned view failed.
    Recall(String),
    /// The pinned base revision is no longer current.
    StaleBase,
    /// The memory layer refused the commit.
    Memory(String),
    /// A workspace read failed.
    Store(String),
}

impl Failure {
    /// The failure detail, without foreign identifiers.
    pub fn detail(&self) -> &str {
        match self {
            Failure::Invalid(detail)
            | Failure::Recall(detail)
            | Failure::Memory(detail)
            | Failure::Store(detail) => detail,
            Failure::StaleBase => "the pinned base revision is no longer current",
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.detail())
    }
}

impl std::error::Error for Failure {}

/// Consolidate one scope of a committed workspace into proposed assertions.
///
/// The reviewed extent comes from authorized recall at the pinned revision, so
/// ranked recall never certifies absence or cleanup. Only the deterministic
/// generator runs on this path: without a configured extractor the job declares
/// no model, and the job envelope records that. Each generated proposal becomes
/// one evidence record pinning the exact cited revision and bytes plus one
/// proposed assertion citing it. Nothing is accepted, and a proposal whose
/// premise is no longer retained is skipped with the reason rather than quoted.
pub fn consolidate_workspace(
    workspace: &mut mneme_store::Workspace,
    request: &WorkspaceJob,
) -> Result<WorkspaceReceipt, Failure> {
    request.validate()?;
    let view = mneme_memory::Engine::new(workspace, request.access.clone())
        .view()
        .map_err(|error| Failure::Memory(describe_memory_error(&error)))?;
    let base = view.revision();
    let response = recall(workspace, request, base)?;
    let batch = crate::InputBatch::from_recall(request.scope.clone(), base, &response, &view)
        .map_err(Failure::Invalid)?;
    let (batch, dropped) = batch.limit_inputs(request.limits.max_inputs);
    let mut skipped = dropped
        .into_iter()
        .map(|key| SkippedUnit {
            key,
            reason: "the job's input limit was reached".to_owned(),
        })
        .collect::<Vec<_>>();
    // Ranked recall returns no candidate for a source it cannot quote, so the
    // unavailable sources of the scope are accounted for from the pinned view
    // before the per-unit skips: a receipt that silently omitted them would
    // report a complete review of an extent the job partly could not use.
    skipped.extend(unavailable_sources(&view, &request.scope));
    let inputs = reviewed_inputs(&view, &response, &batch, &mut skipped);
    let job = job_envelope(request, base, &batch, &inputs);
    let mut executor = crate::runner::Executor::start(job).map_err(Failure::Invalid)?;
    let proposals = run_job(&mut executor, &batch, &inputs, &mut skipped);
    let drafts = commit_drafts(&view, request, &proposals, &mut skipped);
    let committed = commit(workspace, request, base, drafts)?;
    Ok(WorkspaceReceipt {
        job_id: request.job_id.clone(),
        status: finished_status(executor.progress().status),
        base_revision: base,
        revision: committed.revision,
        committed: committed.proposals,
        skipped: dedupe_skips(skipped),
        replayed: committed.replayed,
    })
}

/// Every source of the scope whose exact bytes the pinned view cannot quote.
///
/// A source the view no longer holds at all (a forgotten identity) is never
/// listed: naming it would disclose an identity the suppression hides. A source
/// that is still in the view but pruned, erased, inaccessible or corrupt is
/// listed with its availability, so the receipt never claims to have reviewed
/// bytes the job could not read.
fn unavailable_sources(view: &mneme_memory::View, scope: &mneme_core::ScopeId) -> Vec<SkippedUnit> {
    let records = &view.snapshot().records;
    let mut skipped = Vec::with_capacity(records.len());
    for record in records {
        if &record.scope != scope || record.kind != mneme_core::RecordKind::SourceRevision {
            continue;
        }
        let availability = crate::source_availability(view, record.record_id, record.revision_id);
        if availability.is_retained() {
            continue;
        }
        skipped.push(SkippedUnit {
            key: crate::InputKey {
                record_id: record.record_id,
                revision_id: record.revision_id,
            },
            reason: format!("source is {}", availability.name()),
        });
    }
    skipped
}

/// Keep one entry per unit, preferring the first (most specific) reason.
fn dedupe_skips(skipped: Vec<SkippedUnit>) -> Vec<SkippedUnit> {
    let mut seen = std::collections::BTreeSet::new();
    skipped
        .into_iter()
        .filter(|unit| seen.insert(unit.key))
        .collect()
}

/// The status a finished call reports.
///
/// A run that reviewed no unit, or that stopped before processing one, reports
/// a partial extent: it never claims a terminal completion it did not reach.
fn finished_status(status: crate::JobStatus) -> crate::JobStatus {
    if matches!(status, crate::JobStatus::Running) {
        crate::JobStatus::Partial
    } else {
        status
    }
}

/// Recall the reviewed extent from the pinned view.
fn recall(
    workspace: &mut mneme_store::Workspace,
    request: &WorkspaceJob,
    revision: mneme_core::WorkspaceRevisionId,
) -> Result<mneme_recall::Response, Failure> {
    let recall = mneme_recall::Request {
        actor: request.actor.clone(),
        scope: request.scope.clone(),
        access: request.access.clone(),
        revision,
        query: request.query.clone(),
        at: request.at,
        temporal: mneme_recall::TemporalMode::Current,
        modes: std::collections::BTreeSet::from([mneme_recall::Mode::Lexical]),
        structured: None,
        allow_stale: false,
        allow_fallback: true,
        allow_partial: true,
        include_disputed: false,
        include_hypothetical: false,
        max_items: request.recall.max_items,
        max_context_bytes: request.recall.max_context_bytes,
        max_quote_bytes: request.recall.max_quote_bytes,
        max_time_ms: request.recall.max_time_ms,
        cancellation: None,
    };
    mneme_recall::Service::new(workspace)
        .recall(recall)
        .map_err(|error| Failure::Recall(error.to_string()))
}

/// The reviewed text of every batch unit that can still be quoted.
fn reviewed_inputs(
    view: &mneme_memory::View,
    response: &mneme_recall::Response,
    batch: &crate::InputBatch,
    skipped: &mut Vec<SkippedUnit>,
) -> Vec<crate::proposals::GeneratorInput> {
    let mut inputs = Vec::with_capacity(batch.units.len());
    for unit in &batch.units {
        if !unit.availability.is_retained() {
            skipped.push(SkippedUnit {
                key: unit.key,
                reason: format!("source is {}", unit.availability.name()),
            });
            continue;
        }
        match reviewed_input(view, response, unit) {
            Ok(input) => inputs.push(input),
            Err(reason) => skipped.push(SkippedUnit {
                key: unit.key,
                reason,
            }),
        }
    }
    inputs
}

/// The exact reviewed text of one unit, bound to the retained source bytes.
fn reviewed_input(
    view: &mneme_memory::View,
    response: &mneme_recall::Response,
    unit: &crate::InputUnit,
) -> Result<crate::proposals::GeneratorInput, String> {
    let candidate = response
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.source == Some(unit.key.record_id)
                && candidate.source_revision == Some(unit.key.revision_id)
        })
        .min_by_key(|candidate| match candidate.content_kind {
            mneme_recall::ContentKind::SourceExcerpt => 0,
            _ => 1,
        })
        .ok_or_else(|| "no recalled item names this input".to_owned())?;
    if candidate.text_truncated {
        return Err("the recalled item was truncated".to_owned());
    }
    let pinned = view
        .source_at(unit.key.record_id, unit.key.revision_id)
        .map_err(|_| "the source revision is not retained".to_owned())?;
    let bytes = match view.source_status_for(&pinned) {
        Ok(mneme_memory::SourceStatus::Retained(bytes)) => bytes,
        Ok(status) => {
            return Err(format!("source is {}", status.availability().name()));
        }
        Err(_) => return Err("the source bytes could not be read".to_owned()),
    };
    let span = match candidate.span {
        Some(span) => {
            if !cited_exactly(&bytes, span, &candidate.text) {
                return Err("the recalled text does not match the cited bytes".to_owned());
            }
            Some(span)
        }
        None => {
            if bytes != candidate.text.as_bytes() {
                return Err("the recalled text is not the whole source extent".to_owned());
            }
            None
        }
    };
    Ok(crate::proposals::GeneratorInput::from_unit(
        unit,
        candidate.text.clone(),
        span,
    ))
}

/// Whether `span` of `bytes` is exactly the offered text.
fn cited_exactly(bytes: &[u8], span: mneme_core::SourceSpan, text: &str) -> bool {
    let Ok(start) = usize::try_from(span.start()) else {
        return false;
    };
    let Some(end) = usize::try_from(span.end())
        .ok()
        .and_then(|end| end.checked_add(1))
    else {
        return false;
    };
    bytes.get(start..end) == Some(text.as_bytes())
}

/// The job envelope the executor runs under.
fn job_envelope(
    request: &WorkspaceJob,
    base: mneme_core::WorkspaceRevisionId,
    batch: &crate::InputBatch,
    inputs: &[crate::proposals::GeneratorInput],
) -> crate::Job {
    let mut batch = batch.clone();
    // Only reviewed units belong to this job; a unit that produced no text was
    // never reviewed, so the cursor must not claim it.
    let reviewed = inputs
        .iter()
        .map(|input| input.key)
        .collect::<std::collections::BTreeSet<_>>();
    batch.units.retain(|unit| reviewed.contains(&unit.key));
    batch.reviewed = reviewed;
    if batch.declared_extent.is_some() {
        batch.declared_extent = Some(batch.reviewed.clone());
    }
    crate::Job {
        job_id: request.job_id.clone(),
        recorded_at: request.recorded_at,
        idempotency_key: request.idempotency_key.clone(),
        scope: request.scope.clone(),
        base_revision: base,
        policy_version: request.policy_version.clone(),
        extractor: request.extractor.clone(),
        batch,
        limits: request.limits,
        status: crate::JobStatus::Running,
    }
}

/// Run the job over its reviewed inputs.
fn run_job(
    executor: &mut crate::runner::Executor,
    batch: &crate::InputBatch,
    inputs: &[crate::proposals::GeneratorInput],
    skipped: &mut Vec<SkippedUnit>,
) -> Vec<crate::Proposal> {
    let control = crate::runner::JobControl::new();
    let mut proposals = Vec::with_capacity(inputs.len());
    for input in inputs {
        let is_unavailable = batch
            .units
            .iter()
            .find(|unit| unit.key == input.key)
            .is_some_and(|unit| !unit.availability.is_retained());
        if is_unavailable {
            skipped.push(SkippedUnit {
                key: input.key,
                reason: "the source is no longer retained".to_owned(),
            });
            continue;
        }
        match executor.process_summary(input, &control, UNIT_COST_MS) {
            Ok(generated) => proposals.extend(generated),
            Err(reason) => {
                skipped.push(SkippedUnit {
                    key: input.key,
                    reason,
                });
                break;
            }
        }
    }
    proposals
}

/// One proposal's evidence and assertion drafts.
struct ProposalDrafts {
    evidence: mneme_store::RecordDraft,
    assertion: mneme_store::RecordDraft,
    committed: CommittedProposal,
}

/// Build the drafts that record one proposal as a proposed assertion.
fn commit_drafts(
    view: &mneme_memory::View,
    request: &WorkspaceJob,
    proposals: &[crate::Proposal],
    skipped: &mut Vec<SkippedUnit>,
) -> Vec<ProposalDrafts> {
    let mut drafts = Vec::with_capacity(proposals.len());
    let mut identities = std::collections::BTreeSet::new();
    for proposal in proposals {
        let key = proposal.premises.first().map(|premise| crate::InputKey {
            record_id: premise.record_id,
            revision_id: premise.revision_id,
        });
        match proposal_drafts(view, request, proposal) {
            Ok(draft) => {
                let is_unique = identities.insert(draft.committed.assertion)
                    && identities.insert(draft.committed.evidence);
                if !is_unique {
                    if let Some(key) = key {
                        skipped.push(SkippedUnit {
                            key,
                            reason: "two proposals share one record identity".to_owned(),
                        });
                    }
                    continue;
                }
                drafts.push(draft);
            }
            Err(reason) => {
                if let Some(key) = key {
                    skipped.push(SkippedUnit { key, reason });
                }
            }
        }
    }
    drafts
}

/// Build the evidence and assertion drafts for one proposal.
fn proposal_drafts(
    view: &mneme_memory::View,
    request: &WorkspaceJob,
    proposal: &crate::Proposal,
) -> Result<ProposalDrafts, String> {
    proposal.validate()?;
    let premise = proposal
        .premises
        .first()
        .ok_or_else(|| "the proposal has no premise".to_owned())?;
    let span = premise
        .span
        .ok_or_else(|| "the proposal cites no exact bytes".to_owned())?;
    let claim = proposed_claim(view, proposal)?;
    let identities = DraftIdentities::for_proposal(request, &proposal.proposal_id);
    let evidence = evidence_draft(request, &identities, premise, span);
    let assertion = assertion_draft(request, &identities, claim);
    Ok(ProposalDrafts {
        evidence,
        assertion,
        committed: CommittedProposal {
            proposal_id: proposal.proposal_id.clone(),
            assertion: identities.assertion.record_id,
            assertion_revision: identities.assertion.revision_id,
            evidence: identities.evidence.record_id,
            evidence_revision: identities.evidence.revision_id,
        },
    })
}

/// The record identities one proposal's drafts are recorded under.
struct DraftIdentities {
    evidence: crate::InputKey,
    assertion: crate::InputKey,
}

impl DraftIdentities {
    /// Derive the evidence and assertion identities for one proposal.
    fn for_proposal(request: &WorkspaceJob, proposal_id: &str) -> Self {
        let (evidence, evidence_revision) = record_identity(request, proposal_id, "evidence");
        let (assertion, assertion_revision) = record_identity(request, proposal_id, "assertion");
        DraftIdentities {
            evidence: crate::InputKey {
                record_id: evidence,
                revision_id: evidence_revision,
            },
            assertion: crate::InputKey {
                record_id: assertion,
                revision_id: assertion_revision,
            },
        }
    }
}

/// The evidence draft that supports one proposal's cited premise.
fn evidence_draft(
    request: &WorkspaceJob,
    identities: &DraftIdentities,
    premise: &crate::ProposalPremise,
    span: mneme_core::SourceSpan,
) -> mneme_store::RecordDraft {
    let ancestry = premise
        .derivation
        .map(|derivation| {
            vec![mneme_core::Reference::local(
                derivation,
                mneme_core::RecordKind::Derivation,
            )]
        })
        .unwrap_or_default();
    mneme_memory::build_evidence(
        identities.evidence.record_id,
        identities.evidence.revision_id,
        &request.scope,
        mneme_memory::EvidenceOptions {
            assertion: identities.assertion.record_id,
            source: premise.record_id,
            source_revision: premise.revision_id,
            span: Some(span),
            anchor: None,
            relation: mneme_memory::SupportRelation::Supports,
            origin: mneme_core::Origin::Inference,
            ancestry: &ancestry,
        },
    )
}

/// The proposed-assertion draft for one proposal's claim.
fn assertion_draft(
    request: &WorkspaceJob,
    identities: &DraftIdentities,
    claim: ProposedClaim,
) -> mneme_store::RecordDraft {
    let ProposedClaim {
        subject,
        predicate,
        value,
        stance,
    } = claim;
    let extraction = request.extractor.as_ref().map(|extractor| {
        (
            extractor.identity.as_str(),
            extractor.prompt_digest.as_str(),
        )
    });
    mneme_memory::build_proposed_assertion(
        identities.assertion.record_id,
        identities.assertion.revision_id,
        &request.scope,
        mneme_memory::ProposedAssertionOptions {
            subject,
            predicate: &predicate,
            value,
            stance,
            origin: if extraction.is_some() {
                mneme_core::Origin::ModelExtraction
            } else {
                mneme_core::Origin::Inference
            },
            asserted_by: &request.actor,
            valid_time: mneme_core::ValidTime::Unknown,
            evidence: &[mneme_core::Reference::local(
                identities.evidence.record_id,
                mneme_core::RecordKind::Evidence,
            )],
            extraction,
            superseded_by: None,
        },
    )
}

/// The claim one proposal asks to record as a proposed assertion.
struct ProposedClaim {
    subject: mneme_core::RecordId,
    predicate: String,
    value: mneme_core::Value,
    stance: mneme_memory::Stance,
}

/// The claim one proposal asks to record.
fn proposed_claim(
    view: &mneme_memory::View,
    proposal: &crate::Proposal,
) -> Result<ProposedClaim, String> {
    match &proposal.operation {
        crate::ProposalOperation::Summary(summary) => {
            let premise = proposal
                .premises
                .first()
                .ok_or_else(|| "the summary has no premise".to_owned())?;
            Ok(ProposedClaim {
                subject: summary_subject(view, premise.record_id)?,
                predicate: SUMMARY_PREDICATE.to_owned(),
                value: mneme_core::Value::string(summary.text.clone()),
                stance: mneme_memory::Stance::Hypothesis,
            })
        }
        crate::ProposalOperation::Assertion(assertion) => {
            entity_subject(view, assertion.subject)?;
            Ok(ProposedClaim {
                subject: assertion.subject,
                predicate: assertion.predicate.clone(),
                value: assertion.value.clone(),
                stance: match assertion.stance {
                    crate::ProposalStance::Affirm => mneme_memory::Stance::Affirm,
                    crate::ProposalStance::Deny => mneme_memory::Stance::Deny,
                    crate::ProposalStance::Hypothesis => mneme_memory::Stance::Hypothesis,
                },
            })
        }
        crate::ProposalOperation::Dispute(_)
        | crate::ProposalOperation::Supersession(_)
        | crate::ProposalOperation::Absence(_)
        | crate::ProposalOperation::Cleanup(_)
        | crate::ProposalOperation::Procedure(_) => {
            Err("this proposal kind is not recorded as a proposed assertion".to_owned())
        }
    }
}

/// The entity a summary proposal is an interpretation of.
///
/// A summary says something about the subject its source names; a source that
/// names no entity cannot carry one, so no assertion is recorded for it.
fn summary_subject(
    view: &mneme_memory::View,
    source: mneme_core::RecordId,
) -> Result<mneme_core::RecordId, String> {
    let source = view
        .source(source)
        .map_err(|_| "the summary source is not readable".to_owned())?;
    let entity = source
        .entity
        .ok_or_else(|| "the summary source names no entity".to_owned())?;
    entity_subject(view, entity)?;
    Ok(entity)
}

/// Check that one proposed subject is a readable entity record.
fn entity_subject(view: &mneme_memory::View, subject: mneme_core::RecordId) -> Result<(), String> {
    let record = view
        .record(subject)
        .map_err(|_| "the proposal subject is not readable".to_owned())?;
    if record.kind != mneme_core::RecordKind::Entity {
        return Err("the proposal subject is not an entity record".to_owned());
    }
    Ok(())
}

/// The predicate a deterministic summary proposal records.
///
/// A summary is an interpretation of the bytes it cites, so it is recorded as a
/// hypothesis about its source rather than as a claim about the world.
const SUMMARY_PREDICATE: &str = "summary";

/// The record and revision identity derived for one run's proposal record.
///
/// Identities are bound to the run (job, request key, policy and extractor) and
/// to the proposal, whose own identity already names the exact input revisions it
/// was generated from. A retry of the same request therefore derives the same
/// records and is detected as a replay even though the job's own commit advanced
/// the head, while a different run can never overwrite or silently reuse another
/// run's records. Reusing a key for different inputs yields different identities,
/// and the store's idempotency rule refuses that key reuse.
fn record_identity(
    request: &WorkspaceJob,
    proposal_id: &str,
    label: &str,
) -> (mneme_core::RecordId, mneme_core::RevisionId) {
    let identity = mneme_core::Value::record_named(
        "consolidation-record",
        vec![
            mneme_core::Value::symbol(label),
            mneme_core::Value::string(request.job_id.clone()),
            mneme_core::Value::string(request.idempotency_key.clone()),
            mneme_core::Value::string(request.policy_version.clone()),
            request.extractor.as_ref().map_or_else(
                || mneme_core::Value::symbol("none"),
                |extractor| {
                    mneme_core::Value::record_named(
                        "extractor",
                        vec![
                            mneme_core::Value::string(extractor.identity.clone()),
                            mneme_core::Value::string(extractor.revision.clone()),
                            mneme_core::Value::string(extractor.prompt_digest.clone()),
                        ],
                    )
                },
            ),
            mneme_core::Value::string(proposal_id),
        ],
    );
    let record = mneme_core::ContentDigest::of_payload(&identity);
    let revision = mneme_core::ContentDigest::of_payload(&mneme_core::Value::record_named(
        "consolidation-revision",
        vec![identity, record.to_value()],
    ));
    (
        mneme_core::RecordId::from_bytes(leading_bytes(record)),
        mneme_core::RevisionId::from_bytes(leading_bytes(revision)),
    )
}

/// The first sixteen digest bytes, as an identity-sized key.
fn leading_bytes(digest: mneme_core::ContentDigest) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    for (target, source) in bytes.iter_mut().zip(digest.as_bytes()) {
        *target = *source;
    }
    bytes
}

/// The committed state a job reports.
struct CommitReport {
    revision: mneme_core::WorkspaceRevisionId,
    proposals: Vec<CommittedProposal>,
    replayed: bool,
}

/// Commit the drafts, replaying a commit this run already recorded.
fn commit(
    workspace: &mut mneme_store::Workspace,
    request: &WorkspaceJob,
    base: mneme_core::WorkspaceRevisionId,
    drafts: Vec<ProposalDrafts>,
) -> Result<CommitReport, Failure> {
    let mut proposals = Vec::with_capacity(drafts.len());
    let mut records = Vec::with_capacity(drafts.len().saturating_mul(2));
    let mut already = 0_usize;
    for draft in drafts {
        let existing = workspace
            .record_revisions(draft.committed.assertion)
            .map_err(|error| Failure::Store(error.to_string()))?;
        if existing.is_empty() {
            records.push(draft.evidence);
            records.push(draft.assertion);
        } else {
            already = already.saturating_add(1);
        }
        proposals.push(draft.committed);
    }
    if proposals.is_empty() {
        return Ok(CommitReport {
            revision: workspace
                .current_revision()
                .map_err(|error| Failure::Store(error.to_string()))?,
            proposals,
            replayed: false,
        });
    }
    if already == proposals.len() {
        return Ok(CommitReport {
            revision: workspace
                .current_revision()
                .map_err(|error| Failure::Store(error.to_string()))?,
            proposals,
            replayed: true,
        });
    }
    if already != 0 {
        return Err(Failure::Store(
            "the consolidation run is partially committed".to_owned(),
        ));
    }
    let batch = mneme_memory::Batch {
        actor: request.actor.clone(),
        scope: request.scope.clone(),
        idempotency_key: request.idempotency_key.clone(),
        records,
        source_blobs: Vec::new(),
        publications: Vec::new(),
    };
    let outcome = mneme_memory::Engine::new(workspace, request.access.clone())
        .commit_at_base(batch, base)
        .map_err(|error| match error {
            mneme_memory::EvidenceError::Store(mneme_store::Failure::StaleBase { .. }) => {
                Failure::StaleBase
            }
            other => Failure::Memory(describe_memory_error(&other)),
        })?;
    Ok(CommitReport {
        revision: outcome.revision,
        proposals,
        replayed: false,
    })
}

/// A memory failure message that names no foreign record.
fn describe_memory_error(error: &mneme_memory::EvidenceError) -> String {
    match error {
        mneme_memory::EvidenceError::Validation(diagnostics) => format!(
            "evidence validation failed: {}",
            diagnostics
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ),
        other => other.to_string(),
    }
}
