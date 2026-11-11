//! Evidence policy: span validation, belief views, conflicts, support,
//! ancestry, and bounded explanations.
//!
//! Everything here is computed from one pinned store snapshot. No method mutates
//! canonical state or promotes a proposed assertion.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use mneme_core::{
    Lifecycle, RecordId, RecordKind, Reference, RevisionId, ScopeClass, ScopeId, SnapshotIndex,
    Timestamp, ValidTime, Value, WorkspaceRevisionId,
};
use mneme_store::{RetentionSuppression, Snapshot, SuppressionMode, blob};

use crate::error::{MemoryError, Result};
use crate::model::{
    AssertionView, DecisionKind, DecisionView, DerivationView, EpisodeType, EpisodeView,
    EvidenceView, SourceAvailability, SourceView, Stance, SupportRelation,
};

/// The policy predicate used for action-completion claims.
pub const ACTION_COMPLETED_PREDICATE: &str = "action-completed";

/// Root identity of source evidence: the source record and exact revision.
pub type SourceRevisionKey = (RecordId, RevisionId);

/// Bounding policy for explanations and excerpts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    pub max_explanation_nodes: usize,
    pub max_excerpt_bytes: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            max_explanation_nodes: 64,
            max_excerpt_bytes: 4096,
        }
    }
}

/// A current-belief selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeliefView {
    /// Operational scope (project, workspace, agent, task, user).
    pub scope: ScopeId,
    /// Instant at which valid time is evaluated.
    pub at: Timestamp,
    /// Include hypothetical scopes in this explicitly planner-oriented view.
    pub include_hypothetical: bool,
    /// Include claims marked disputed by an explicit decision.
    pub include_disputed: bool,
}

/// Incompatible claims retained under one subject/predicate and scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictGroup {
    pub subject: RecordId,
    pub predicate: String,
    pub assertions: Vec<AssertionView>,
}

/// Whether newly cited evidence must still have retained source bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedRequirement {
    Required,
    Optional,
}

/// Evidence whose span and source revision were validated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedEvidence {
    pub evidence: EvidenceView,
    pub source: SourceView,
    pub availability: SourceAvailability,
    pub excerpt: Option<Vec<u8>>,
}

/// A bounded excerpt of exact retained source bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceExcerpt {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

/// One evidence item in an explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceExplanation {
    pub evidence: RecordId,
    pub source: RecordId,
    pub source_revision: RevisionId,
    pub availability: SourceAvailability,
    pub span_start: Option<u64>,
    pub span_end: Option<u64>,
    pub excerpt: Option<SourceExcerpt>,
    pub ancestry_roots: BTreeSet<SourceRevisionKey>,
    /// The evidence is retained for inspection but cannot support a claim.
    pub withdrawn: bool,
    /// The evidence may contribute to current support and corroboration.
    pub eligible: bool,
}

/// One alternative derivation and whether it currently supports its conclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationAlternative {
    pub derivation: RecordId,
    pub rule_id: String,
    pub rule_version: i64,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

/// Root-evidence corroboration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Corroboration {
    pub roots: BTreeSet<SourceRevisionKey>,
    pub independent_supports: usize,
    pub shared_ancestry: bool,
}

/// A bounded explanation of one current assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation {
    pub assertion: AssertionView,
    pub workspace_revision: WorkspaceRevisionId,
    pub decisions: Vec<DecisionView>,
    pub evidence: Vec<EvidenceExplanation>,
    pub derivations: Vec<DerivationAlternative>,
    pub corroboration: Corroboration,
    pub truncated: bool,
}

/// The exact source state observed while building an explanation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceStatus {
    Retained(Vec<u8>),
    Pruned,
    Erased,
    Inaccessible(String),
    Corrupt(String),
}

impl SourceStatus {
    /// The external availability label.
    pub fn availability(&self) -> SourceAvailability {
        match self {
            SourceStatus::Retained(_) => SourceAvailability::Retained,
            SourceStatus::Pruned => SourceAvailability::Pruned,
            SourceStatus::Erased => SourceAvailability::Erased,
            SourceStatus::Inaccessible(reason) => SourceAvailability::Unavailable {
                reason: reason.clone(),
            },
            SourceStatus::Corrupt(reason) => SourceAvailability::Corrupt {
                reason: reason.clone(),
            },
        }
    }
}

/// A read-only policy view over one committed snapshot.
#[derive(Clone, Debug)]
pub struct MemoryView {
    snapshot: Snapshot,
    root: PathBuf,
    records: BTreeMap<RecordId, mneme_core::RecordEnvelope>,
    history: BTreeMap<(RecordId, RevisionId), mneme_core::RecordEnvelope>,
    revision_sequences: BTreeMap<WorkspaceRevisionId, u64>,
    suppressions: Vec<RetentionSuppression>,
}

impl MemoryView {
    /// Construct a view over a pinned snapshot and workspace root.
    pub fn new(snapshot: Snapshot, root: impl Into<PathBuf>) -> Self {
        Self::with_history(snapshot, root, BTreeMap::new())
    }

    /// Construct a view with retained record-revision history available for
    /// resolving pinned citations.
    pub fn with_history(
        snapshot: Snapshot,
        root: impl Into<PathBuf>,
        history: BTreeMap<(RecordId, RevisionId), mneme_core::RecordEnvelope>,
    ) -> Self {
        let sequences = BTreeMap::from([(snapshot.revision, snapshot.sequence)]);
        Self::with_context(snapshot, root, history, sequences)
    }

    /// Construct a view with retained history and committed revision sequences.
    pub fn with_context(
        snapshot: Snapshot,
        root: impl Into<PathBuf>,
        history: BTreeMap<(RecordId, RevisionId), mneme_core::RecordEnvelope>,
        revision_sequences: BTreeMap<WorkspaceRevisionId, u64>,
    ) -> Self {
        Self::with_retention(snapshot, root, history, revision_sequences, Vec::new())
    }

    /// Construct a view with the current retention suppressions in force.
    pub fn with_retention(
        snapshot: Snapshot,
        root: impl Into<PathBuf>,
        history: BTreeMap<(RecordId, RevisionId), mneme_core::RecordEnvelope>,
        revision_sequences: BTreeMap<WorkspaceRevisionId, u64>,
        suppressions: Vec<RetentionSuppression>,
    ) -> Self {
        let records = snapshot
            .records
            .iter()
            .map(|record| (record.record_id, record.clone()))
            .collect();
        MemoryView {
            snapshot,
            root: root.into(),
            records,
            history,
            revision_sequences,
            suppressions,
        }
    }

    /// The current suppression for a record revision, if any.
    pub fn suppression_for(
        &self,
        record: &mneme_core::RecordEnvelope,
    ) -> Option<&RetentionSuppression> {
        self.suppressions.iter().find(|suppression| {
            suppression.target == record.record_id
                && suppression
                    .revision
                    .is_none_or(|revision| revision == record.revision_id)
        })
    }

    /// Whether a record identity has a withdrawn or forgotten suppression.
    pub fn is_withdrawn(&self, record: RecordId) -> bool {
        self.suppressions.iter().any(|suppression| {
            suppression.target == record && suppression.mode == SuppressionMode::Withdrawn
        })
    }

    /// The pinned revision.
    pub fn revision(&self) -> WorkspaceRevisionId {
        self.snapshot.revision
    }

    /// The pinned snapshot's index.
    pub fn index(&self) -> &SnapshotIndex {
        &self.snapshot.index
    }

    /// The underlying snapshot.
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    pub(crate) fn envelope(&self, record: RecordId) -> Result<&mneme_core::RecordEnvelope> {
        self.records
            .get(&record)
            .ok_or(MemoryError::Missing { record })
    }

    /// Read one envelope from the pinned view.
    pub fn record(&self, record: RecordId) -> Result<&mneme_core::RecordEnvelope> {
        self.envelope(record)
    }

    /// Parse an assertion.
    pub fn assertion(&self, record: RecordId) -> Result<AssertionView> {
        AssertionView::parse(self.envelope(record)?.clone())
    }

    /// Parse a source revision.
    pub fn source(&self, record: RecordId) -> Result<SourceView> {
        SourceView::parse(self.envelope(record)?.clone())
    }

    /// Parse the exact source revision named by evidence.
    pub fn evidence_source(&self, evidence: &EvidenceView) -> Result<SourceView> {
        let mut resolved = if let Reference::Pinned { revision, .. } = evidence.source_reference {
            if let Some(record) = self.history.get(&(evidence.source, revision)) {
                SourceView::parse(record.clone())?
            } else if let Ok(current) = self.source(evidence.source)
                && current.record.revision_id == revision
            {
                current
            } else {
                return Err(MemoryError::Missing {
                    record: evidence.source,
                });
            }
        } else {
            self.source(evidence.source)?
        };
        // Current retention/erasure availability overlays historical revisions.
        if let Ok(current) = self.source(evidence.source)
            && current.availability != SourceAvailability::Retained
        {
            resolved.availability = current.availability;
        }
        Ok(resolved)
    }

    /// Resolve one pinned source revision and overlay current availability.
    pub fn source_at(&self, source: RecordId, revision: RevisionId) -> Result<SourceView> {
        let mut resolved = if let Some(record) = self.history.get(&(source, revision)) {
            SourceView::parse(record.clone())?
        } else if let Ok(current) = self.source(source)
            && current.record.revision_id == revision
        {
            current
        } else {
            return Err(MemoryError::Missing { record: source });
        };
        if let Ok(current) = self.source(source)
            && current.availability != SourceAvailability::Retained
        {
            resolved.availability = current.availability;
        }
        Ok(resolved)
    }

    /// The current source record revision.
    pub fn current_source_revision(&self, source: RecordId) -> Result<RevisionId> {
        Ok(self.source(source)?.record.revision_id)
    }

    /// The source availability currently in force for a source record.
    pub fn current_source_availability(&self, source: RecordId) -> Result<SourceAvailability> {
        Ok(self.source(source)?.availability)
    }

    /// Parse a checkpoint's revision and related references.
    pub fn checkpoint_revision(
        &self,
        record: RecordId,
    ) -> Result<(WorkspaceRevisionId, BTreeSet<RecordId>, BTreeSet<RecordId>)> {
        let envelope = self.envelope(record)?;
        if envelope.kind != RecordKind::Checkpoint {
            return Err(MemoryError::invalid(
                record,
                "checkpoint",
                "not a checkpoint record",
            ));
        }
        let revision = WorkspaceRevisionId::from_value(
            envelope
                .payload
                .get("revision")
                .ok_or_else(|| MemoryError::invalid(record, "checkpoint", "missing revision"))?,
            &mneme_core::Path::root().field("revision"),
        )
        .map_err(|diagnostic| MemoryError::invalid(record, "checkpoint", diagnostic.to_string()))?;
        let episodes = crate::model::required_reference_set(envelope, "episodes")?;
        let verified = crate::model::required_reference_set(envelope, "verified-outcomes")?;
        Ok((revision, episodes, verified))
    }

    /// Parse evidence.
    pub fn evidence(&self, record: RecordId) -> Result<EvidenceView> {
        EvidenceView::parse(self.envelope(record)?.clone())
    }

    /// Parse a decision.
    pub fn decision(&self, record: RecordId) -> Result<DecisionView> {
        DecisionView::parse(self.envelope(record)?.clone())
    }

    /// Parse a derivation.
    pub fn derivation(&self, record: RecordId) -> Result<DerivationView> {
        DerivationView::parse(self.envelope(record)?.clone())
    }

    /// Parse an episode.
    pub fn episode(&self, record: RecordId) -> Result<EpisodeView> {
        EpisodeView::parse(self.envelope(record)?.clone())
    }

    /// Every current assertion.
    pub fn assertions(&self) -> Result<Vec<AssertionView>> {
        self.records
            .values()
            .filter(|record| record.kind == RecordKind::Assertion)
            .cloned()
            .map(AssertionView::parse)
            .collect()
    }

    /// Evidence records for one assertion.
    pub fn evidence_for(&self, assertion: RecordId) -> Result<Vec<EvidenceView>> {
        Ok(self
            .records
            .values()
            .filter(|record| record.kind == RecordKind::Evidence)
            .cloned()
            .filter_map(|record| EvidenceView::parse(record).ok())
            .filter(|evidence| evidence.assertion == assertion)
            .collect())
    }

    /// Derivation records for one conclusion.
    pub fn derivations_for(&self, conclusion: RecordId) -> Result<Vec<DerivationView>> {
        Ok(self
            .records
            .values()
            .filter(|record| record.kind == RecordKind::Derivation)
            .cloned()
            .filter_map(|record| DerivationView::parse(record).ok())
            .filter(|derivation| derivation.conclusion == conclusion)
            .collect())
    }

    /// Decision records targeting one record.
    pub fn decisions_for(&self, target: RecordId) -> Result<Vec<DecisionView>> {
        Ok(self
            .records
            .values()
            .filter(|record| record.kind == RecordKind::Decision)
            .cloned()
            .filter_map(|record| DecisionView::parse(record).ok())
            .filter(|decision| decision.target == target)
            .collect())
    }

    /// Read the exact source bytes and their availability.
    pub fn source_status(&self, source: RecordId) -> Result<SourceStatus> {
        let view = self.source(source)?;
        self.source_status_for(&view)
    }

    /// Read the exact source bytes and their availability for a parsed source.
    pub fn source_status_for(&self, view: &SourceView) -> Result<SourceStatus> {
        match &view.availability {
            SourceAvailability::Retained => {
                let Some(digest) = view.digest() else {
                    return Ok(SourceStatus::Corrupt(
                        "retained source has no digest".to_owned(),
                    ));
                };
                match blob::read(&self.root, digest) {
                    Ok(bytes) => Ok(SourceStatus::Retained(bytes)),
                    Err(mneme_store::StoreError::MissingBlob { .. }) => Ok(SourceStatus::Corrupt(
                        "committed source blob is missing".to_owned(),
                    )),
                    Err(mneme_store::StoreError::CorruptBlob { reason, .. }) => {
                        Ok(SourceStatus::Corrupt(reason))
                    }
                    Err(error) => Err(error.into()),
                }
            }
            SourceAvailability::Pruned => Ok(SourceStatus::Pruned),
            SourceAvailability::Erased => Ok(SourceStatus::Erased),
            SourceAvailability::Inaccessible => Ok(SourceStatus::Inaccessible(
                "source is marked inaccessible".to_owned(),
            )),
            SourceAvailability::Corrupt { reason } => Ok(SourceStatus::Corrupt(reason.clone())),
            SourceAvailability::Unavailable { reason } => {
                Ok(SourceStatus::Inaccessible(reason.clone()))
            }
        }
    }

    /// Validate one evidence record's source revision, span, and excerpt.
    pub fn validate_evidence(
        &self,
        evidence: RecordId,
        requirement: RetainedRequirement,
    ) -> Result<ValidatedEvidence> {
        let evidence = self.evidence(evidence)?;
        let source = self.evidence_source(&evidence)?;
        if let Reference::Pinned { revision, .. } = evidence.source_reference
            && revision != source.record.revision_id
        {
            return Err(MemoryError::policy(format!(
                "evidence pins source revision {revision}, but the retained source record is {}",
                source.record.revision_id
            )));
        }
        if evidence.span.is_none() && evidence.anchor.is_none() {
            return Err(MemoryError::policy(
                "evidence requires an exact span or a stable anchor",
            ));
        }
        if let Some(anchor) = &evidence.anchor
            && anchor.trim().is_empty()
        {
            return Err(MemoryError::policy("evidence anchor must not be empty"));
        }
        let status = self.source_status_for(&source)?;
        if requirement == RetainedRequirement::Required
            && !matches!(status, SourceStatus::Retained(_))
        {
            return Err(MemoryError::policy(format!(
                "evidence source is {} and cannot be newly cited",
                status.availability().name()
            )));
        }
        let excerpt = match (&evidence.span, &status) {
            (Some(span), SourceStatus::Retained(bytes)) => {
                let end = span.end();
                if end >= bytes.len() as u64 {
                    return Err(MemoryError::policy(format!(
                        "evidence span ends at byte {end}, beyond the {} retained bytes",
                        bytes.len()
                    )));
                }
                Some(bytes[span.start() as usize..=end as usize].to_vec())
            }
            _ => None,
        };
        Ok(ValidatedEvidence {
            evidence,
            source,
            availability: status.availability(),
            excerpt,
        })
    }

    fn valid_time_applies(valid_time: ValidTime, at: Timestamp) -> bool {
        match valid_time {
            ValidTime::Unknown => false,
            ValidTime::Bounded { start, end } => {
                start.is_none_or(|start| start <= at) && end.is_none_or(|end| at <= end)
            }
        }
    }

    fn in_scope(&self, assertion: &AssertionView, view: &BeliefView) -> bool {
        if assertion.record.scope == view.scope {
            return true;
        }
        view.include_hypothetical && assertion.record.scope.class() == ScopeClass::Hypothesis
    }

    /// Assertions eligible for the requested current-belief view.
    pub fn current_beliefs(&self, view: &BeliefView) -> Result<Vec<AssertionView>> {
        let mut beliefs = Vec::new();
        for assertion in self.assertions()? {
            if !self.in_scope(&assertion, view) {
                continue;
            }
            if !Self::valid_time_applies(assertion.valid_time, view.at) {
                continue;
            }
            match assertion.lifecycle {
                Lifecycle::Accepted if self.accepted_decision(&assertion).unwrap_or(false) => {
                    if self.assertion_has_current_basis(&assertion) {
                        beliefs.push(assertion);
                    }
                }
                Lifecycle::Disputed
                    if view.include_disputed
                        && self.lifecycle_decision_valid(&assertion).unwrap_or(false) =>
                {
                    beliefs.push(assertion);
                }
                _ => {}
            }
        }
        beliefs.sort_by_key(|assertion| (assertion.subject, assertion.predicate.clone()));
        Ok(beliefs)
    }

    fn validity_overlaps(left: ValidTime, right: ValidTime) -> bool {
        match (left, right) {
            (ValidTime::Unknown, _) | (_, ValidTime::Unknown) => true,
            (
                ValidTime::Bounded {
                    start: left_start,
                    end: left_end,
                },
                ValidTime::Bounded {
                    start: right_start,
                    end: right_end,
                },
            ) => {
                let left_start_before_right_end = match (left_start, right_end) {
                    (Some(left), Some(right)) => left <= right,
                    _ => true,
                };
                let right_start_before_left_end = match (right_start, left_end) {
                    (Some(right), Some(left)) => right <= left,
                    _ => true,
                };
                left_start_before_right_end && right_start_before_left_end
            }
        }
    }

    /// Detected conflicts among accepted/disputed claims in a belief view.
    pub fn conflicts(&self, view: &BeliefView) -> Result<Vec<ConflictGroup>> {
        let mut candidates = Vec::new();
        for assertion in self.assertions()? {
            if !self.in_scope(&assertion, view) {
                continue;
            }
            if assertion.lifecycle == Lifecycle::Accepted
                && !self.accepted_decision(&assertion).unwrap_or(false)
            {
                continue;
            }
            if !matches!(
                assertion.lifecycle,
                Lifecycle::Accepted | Lifecycle::Disputed
            ) {
                continue;
            }
            candidates.push(assertion);
        }
        let mut groups: BTreeMap<(RecordId, String), Vec<AssertionView>> = BTreeMap::new();
        for (index, left) in candidates.iter().enumerate() {
            for right in candidates.iter().skip(index + 1) {
                if left.subject != right.subject || left.predicate != right.predicate {
                    continue;
                }
                if !Self::validity_overlaps(left.valid_time, right.valid_time) {
                    continue;
                }
                let incompatible = match (left.stance, right.stance) {
                    (Stance::Affirm, Stance::Deny) | (Stance::Deny, Stance::Affirm) => true,
                    (Stance::Affirm, Stance::Affirm) => left.value != right.value,
                    (Stance::Deny, Stance::Deny) => false,
                    (Stance::Hypothesis, _) | (_, Stance::Hypothesis) => false,
                };
                if incompatible {
                    let group = groups
                        .entry((left.subject, left.predicate.clone()))
                        .or_default();
                    if !group
                        .iter()
                        .any(|assertion| assertion.record.record_id == left.record.record_id)
                    {
                        group.push(left.clone());
                    }
                    if !group
                        .iter()
                        .any(|assertion| assertion.record.record_id == right.record.record_id)
                    {
                        group.push(right.clone());
                    }
                }
            }
        }
        Ok(groups
            .into_iter()
            .map(|((subject, predicate), assertions)| ConflictGroup {
                subject,
                predicate,
                assertions,
            })
            .collect())
    }

    /// Whether an assertion has a valid acceptance decision.
    pub fn accepted_decision(&self, assertion: &AssertionView) -> Result<bool> {
        let Some(decision_id) = assertion.decision else {
            return Ok(false);
        };
        let decision = self.decision(decision_id)?;
        Ok(decision.decision_kind == DecisionKind::Acceptance
            && decision.outcome == "accepted"
            && decision.target == assertion.record.record_id)
    }

    /// Whether an assertion's current lifecycle is backed by its decision record.
    pub fn lifecycle_decision_valid(&self, assertion: &AssertionView) -> Result<bool> {
        match assertion.lifecycle {
            Lifecycle::Accepted => self.accepted_decision(assertion),
            Lifecycle::Retracted => {
                let Some(decision_id) = assertion.decision else {
                    return Ok(false);
                };
                let decision = self.decision(decision_id)?;
                Ok(decision.decision_kind == DecisionKind::Retraction
                    && decision.outcome == "retracted")
            }
            Lifecycle::Superseded => {
                let Some(decision_id) = assertion.decision else {
                    return Ok(false);
                };
                let decision = self.decision(decision_id)?;
                Ok(decision.decision_kind == DecisionKind::Supersession
                    && decision.outcome == "superseded")
            }
            Lifecycle::Disputed => {
                let Some(decision_id) = assertion.decision else {
                    return Ok(false);
                };
                let decision = self.decision(decision_id)?;
                Ok(decision.decision_kind == DecisionKind::ConflictResolution
                    && decision.outcome == "disputed")
            }
            Lifecycle::Proposed => Ok(assertion.decision.is_none()),
        }
    }

    /// Whether an assertion has an observed outcome episode in its evidence ancestry.
    pub fn has_observed_outcome(&self, assertion: &AssertionView) -> Result<bool> {
        for evidence_id in &assertion.evidence {
            if let Ok(evidence) = self.evidence(*evidence_id) {
                for ancestor in &evidence.ancestry {
                    if let Ok(episode) = self.episode(*ancestor)
                        && matches!(
                            episode.episode_type,
                            EpisodeType::Outcome | EpisodeType::Observation
                        )
                    {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// Root source revisions supporting one evidence record.
    pub fn evidence_roots(&self, evidence: RecordId) -> Result<BTreeSet<SourceRevisionKey>> {
        let mut roots = BTreeSet::new();
        let mut visiting = BTreeSet::new();
        self.collect_roots(evidence, &mut roots, &mut visiting)?;
        Ok(roots)
    }

    fn collect_roots(
        &self,
        record: RecordId,
        roots: &mut BTreeSet<SourceRevisionKey>,
        visiting: &mut BTreeSet<RecordId>,
    ) -> Result<()> {
        if !visiting.insert(record) {
            return Err(MemoryError::policy(format!(
                "evidence ancestry contains a cycle at {record}"
            )));
        }
        let Some(envelope) = self.records.get(&record) else {
            visiting.remove(&record);
            return Ok(());
        };
        match envelope.kind {
            RecordKind::Evidence => {
                let evidence = EvidenceView::parse(envelope.clone())?;
                if evidence.ancestry.is_empty() {
                    let source = self.evidence_source(&evidence)?;
                    roots.insert((evidence.source, source.record.revision_id));
                } else {
                    for ancestor in &evidence.ancestry {
                        self.collect_roots(*ancestor, roots, visiting)?;
                    }
                }
            }
            RecordKind::Episode => {
                let episode = EpisodeView::parse(envelope.clone())?;
                if let Some(source) = episode.source {
                    let revision = self
                        .records
                        .get(&source)
                        .map(|record| record.revision_id)
                        .unwrap_or(envelope.revision_id);
                    roots.insert((source, revision));
                } else {
                    roots.insert((record, envelope.revision_id));
                }
            }
            RecordKind::Assertion => {
                let assertion = AssertionView::parse(envelope.clone())?;
                for evidence in &assertion.evidence {
                    self.collect_roots(*evidence, roots, visiting)?;
                }
            }
            RecordKind::Derivation => {
                let derivation = DerivationView::parse(envelope.clone())?;
                for premise in &derivation.premises {
                    self.collect_roots(*premise, roots, visiting)?;
                }
            }
            _ => {
                roots.insert((record, envelope.revision_id));
            }
        }
        visiting.remove(&record);
        Ok(())
    }

    /// Corroboration roots and independence for one assertion.
    pub fn corroboration(&self, assertion: RecordId) -> Result<Corroboration> {
        let assertion = self.assertion(assertion)?;
        let mut roots = BTreeSet::new();
        let mut supporting = 0;
        for evidence_id in &assertion.evidence {
            let evidence = self.evidence(*evidence_id)?;
            if evidence.relation != SupportRelation::Supports {
                continue;
            }
            if self
                .suppression_for(&evidence.record)
                .is_some_and(|suppression| suppression.mode == SuppressionMode::Withdrawn)
            {
                continue;
            }
            supporting += 1;
            roots.extend(self.evidence_roots(*evidence_id)?);
        }
        Ok(Corroboration {
            independent_supports: roots.len(),
            shared_ancestry: supporting > 1 && roots.len() == 1,
            roots,
        })
    }

    fn assertion_grounded(&self, assertion: &AssertionView) -> bool {
        assertion
            .evidence
            .iter()
            .any(|evidence_id| match self.evidence(*evidence_id) {
                Ok(evidence) => {
                    evidence.relation == SupportRelation::Supports
                        && self.records.contains_key(&evidence.source)
                        && self
                            .suppression_for(&evidence.record)
                            .is_none_or(|suppression| {
                                suppression.mode != SuppressionMode::Withdrawn
                            })
                }
                Err(_) => false,
            })
    }

    fn assertion_eligible_inner(
        &self,
        assertion_id: RecordId,
        visiting: &mut BTreeSet<RecordId>,
    ) -> bool {
        if !visiting.insert(assertion_id) {
            return false;
        }
        let result = (|| {
            let assertion = self.assertion(assertion_id).ok()?;
            if self
                .suppression_for(&assertion.record)
                .is_some_and(|suppression| suppression.mode == SuppressionMode::Withdrawn)
            {
                return Some(false);
            }
            if assertion.lifecycle != Lifecycle::Accepted {
                return Some(false);
            }
            if !self.accepted_decision(&assertion).ok()? {
                return Some(false);
            }
            if self.assertion_grounded(&assertion) {
                return Some(true);
            }
            let derivations = self.derivations_for(assertion_id).ok()?;
            Some(
                derivations
                    .iter()
                    .any(|derivation| self.derivation_eligible_inner(derivation, visiting)),
            )
        })()
        .unwrap_or(false);
        visiting.remove(&assertion_id);
        result
    }

    fn derivation_eligible_inner(
        &self,
        derivation: &DerivationView,
        visiting: &mut BTreeSet<RecordId>,
    ) -> bool {
        if !visiting.insert(derivation.record.record_id) {
            return false;
        }
        let result = self.derivation_eligible_inner_body(derivation, visiting);
        visiting.remove(&derivation.record.record_id);
        result
    }

    fn derivation_revision_matches(&self, derivation: &DerivationView) -> bool {
        let Some(evaluated) = self.revision_sequences.get(&derivation.evaluation_revision) else {
            return false;
        };
        *evaluated <= self.snapshot.sequence
    }

    fn derivation_eligible_inner_body(
        &self,
        derivation: &DerivationView,
        visiting: &mut BTreeSet<RecordId>,
    ) -> bool {
        if !self.derivation_revision_matches(derivation) {
            return false;
        }
        if derivation.premises.is_empty() {
            return false;
        }
        for premise in &derivation.premises {
            let Some(envelope) = self.records.get(premise) else {
                return false;
            };
            let eligible = match envelope.kind {
                RecordKind::Assertion => self.assertion_eligible_inner(*premise, visiting),
                RecordKind::Derivation => match self.derivation(*premise) {
                    Ok(premise_derivation) => {
                        self.derivation_eligible_inner(&premise_derivation, visiting)
                    }
                    Err(_) => false,
                },
                RecordKind::Episode => self
                    .suppression_for(envelope)
                    .is_none_or(|suppression| suppression.mode != SuppressionMode::Withdrawn),
                _ => false,
            };
            if !eligible {
                return false;
            }
        }
        true
    }

    /// Whether one assertion currently has a complete grounded justification.
    pub fn assertion_eligible(&self, assertion: RecordId) -> bool {
        let mut visiting = BTreeSet::new();
        self.assertion_eligible_inner(assertion, &mut visiting)
    }

    /// Whether an accepted assertion has a surviving proof or an explicitly
    /// complete absence basis.
    pub fn assertion_has_current_basis(&self, assertion: &AssertionView) -> bool {
        if self.assertion_eligible(assertion.record.record_id) {
            return true;
        }
        assertion.evidence.is_empty()
            && assertion
                .record
                .payload
                .get("completeness")
                .and_then(Value::as_symbol)
                .is_some_and(|symbol| symbol.as_str() == "declared-complete")
    }

    /// Alternative derivations for one conclusion with eligibility reasons.
    pub fn derivation_alternatives(
        &self,
        conclusion: RecordId,
    ) -> Result<Vec<DerivationAlternative>> {
        let mut alternatives = Vec::new();
        for derivation in self.derivations_for(conclusion)? {
            let mut visiting = BTreeSet::new();
            let eligible = self.derivation_eligible_inner(&derivation, &mut visiting);
            let mut reasons = Vec::new();
            if !self.derivation_revision_matches(&derivation) {
                reasons.push(
                    "derivation evaluation revision is not the pinned revision or its parent"
                        .to_owned(),
                );
            }
            for premise in &derivation.premises {
                let Some(envelope) = self.records.get(premise) else {
                    reasons.push(format!("premise {premise} is missing"));
                    continue;
                };
                if envelope.kind == RecordKind::Assertion && !self.assertion_eligible(*premise) {
                    reasons.push(format!("premise {premise} is not currently eligible"));
                }
            }
            alternatives.push(DerivationAlternative {
                derivation: derivation.record.record_id,
                rule_id: derivation.rule_id,
                rule_version: derivation.rule_version,
                eligible,
                reasons,
            });
        }
        Ok(alternatives)
    }

    /// Build a bounded explanation for one current assertion.
    pub fn explain(&self, assertion: RecordId, policy: Policy) -> Result<Explanation> {
        let assertion = self.assertion(assertion)?;
        let mut nodes = 1;
        let mut truncated = false;
        let decisions = self.decisions_for(assertion.record.record_id)?;
        let mut evidence_explanations = Vec::new();
        let mut roots = BTreeSet::new();
        for evidence_id in &assertion.evidence {
            if nodes >= policy.max_explanation_nodes {
                truncated = true;
                break;
            }
            let evidence = self.evidence(*evidence_id)?;
            let source = self.evidence_source(&evidence)?;
            let status = self.source_status_for(&source)?;
            let availability = status.availability();
            let excerpt = match (&evidence.span, &status) {
                (Some(span), SourceStatus::Retained(bytes)) => {
                    let start = span.start() as usize;
                    let end = (span.end() as usize + 1).min(bytes.len());
                    if start <= end {
                        let truncated_excerpt = end - start > policy.max_excerpt_bytes;
                        let end = start + (end - start).min(policy.max_excerpt_bytes);
                        Some(SourceExcerpt {
                            bytes: bytes[start..end].to_vec(),
                            truncated: truncated_excerpt,
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };
            let evidence_roots = self.evidence_roots(*evidence_id).unwrap_or_default();
            let withdrawn = self
                .suppression_for(&evidence.record)
                .is_some_and(|suppression| suppression.mode == SuppressionMode::Withdrawn);
            let eligible = !withdrawn;
            if eligible && evidence.relation == SupportRelation::Supports {
                roots.extend(evidence_roots.iter().copied());
            }
            evidence_explanations.push(EvidenceExplanation {
                evidence: evidence.record.record_id,
                source: evidence.source,
                source_revision: source.record.revision_id,
                availability,
                span_start: evidence.span.map(|span| span.start()),
                span_end: evidence.span.map(|span| span.end()),
                excerpt,
                ancestry_roots: evidence_roots,
                withdrawn,
                eligible,
            });
            nodes += 1;
        }
        let derivations = self.derivation_alternatives(assertion.record.record_id)?;
        nodes += derivations.len();
        let supporting =
            assertion
                .evidence
                .iter()
                .filter(|evidence_id| {
                    self.evidence(**evidence_id)
                        .map(|evidence| {
                            evidence.relation == SupportRelation::Supports
                                && self.suppression_for(&evidence.record).is_none_or(
                                    |suppression| suppression.mode != SuppressionMode::Withdrawn,
                                )
                        })
                        .unwrap_or(false)
                })
                .count();
        let corroboration = Corroboration {
            independent_supports: roots.len(),
            shared_ancestry: supporting > 1 && roots.len() == 1,
            roots,
        };
        Ok(Explanation {
            assertion,
            workspace_revision: self.snapshot.revision,
            decisions,
            evidence: evidence_explanations,
            derivations,
            corroboration,
            truncated: truncated || nodes > policy.max_explanation_nodes,
        })
    }
}

/// Explicit authored-premise predicate convention for derivations.
pub const EXPLICIT_AUTHORED_PREDICATE: &str = "explicit-authored-premise";
