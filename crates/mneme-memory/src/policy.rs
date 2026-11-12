//! Evidence policy: span validation, belief views, conflicts, support,
//! ancestry, and bounded explanations.
//!
//! Everything here is computed from one pinned store snapshot. No method mutates
//! canonical state or promotes a proposed assertion.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// The policy predicate used for action-completion claims.
pub const ACTION_COMPLETED_PREDICATE: &str = "action-completed";

/// Root identity of source evidence: the source record and exact revision.
pub type SourceRevisionKey = (mneme_core::RecordId, mneme_core::RevisionId);

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
    pub scope: mneme_core::ScopeId,
    /// Instant at which valid time is evaluated.
    pub at: mneme_core::Timestamp,
    /// Include hypothetical scopes in this explicitly planner-oriented view.
    pub include_hypothetical: bool,
    /// Include claims marked disputed by an explicit decision.
    pub include_disputed: bool,
}

/// Incompatible claims retained under one subject/predicate and scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictGroup {
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub assertions: Vec<crate::model::AssertionView>,
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
    pub evidence: crate::model::EvidenceView,
    pub source: crate::model::SourceView,
    pub availability: crate::model::SourceAvailability,
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
    pub evidence: mneme_core::RecordId,
    pub source: mneme_core::RecordId,
    pub source_revision: mneme_core::RevisionId,
    pub availability: crate::model::SourceAvailability,
    pub span_start: Option<u64>,
    pub span_end: Option<u64>,
    pub excerpt: Option<SourceExcerpt>,
    pub ancestry_roots: std::collections::BTreeSet<SourceRevisionKey>,
    /// The evidence is retained for inspection but cannot support a claim.
    pub withdrawn: bool,
    /// The evidence may contribute to current support and corroboration.
    pub eligible: bool,
}

/// One alternative derivation and whether it currently supports its conclusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivationAlternative {
    pub derivation: mneme_core::RecordId,
    pub rule_id: String,
    pub rule_version: i64,
    pub eligible: bool,
    pub reasons: Vec<String>,
}

/// Root-evidence corroboration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Corroboration {
    pub roots: std::collections::BTreeSet<SourceRevisionKey>,
    pub independent_supports: usize,
    pub shared_ancestry: bool,
}

/// A bounded explanation of one current assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation {
    pub assertion: crate::model::AssertionView,
    pub workspace_revision: mneme_core::WorkspaceRevisionId,
    pub decisions: Vec<crate::model::DecisionView>,
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
    pub fn availability(&self) -> crate::model::SourceAvailability {
        match self {
            SourceStatus::Retained(_) => crate::model::SourceAvailability::Retained,
            SourceStatus::Pruned => crate::model::SourceAvailability::Pruned,
            SourceStatus::Erased => crate::model::SourceAvailability::Erased,
            SourceStatus::Inaccessible(reason) => crate::model::SourceAvailability::Unavailable {
                reason: reason.clone(),
            },
            SourceStatus::Corrupt(reason) => crate::model::SourceAvailability::Corrupt {
                reason: reason.clone(),
            },
        }
    }
}

/// A read-only policy view over one committed snapshot.
#[derive(Clone, Debug)]
pub struct MemoryView {
    snapshot: mneme_store::Snapshot,
    root: std::path::PathBuf,
    records: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    history: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    revision_sequences: std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    suppressions: Vec<mneme_store::RetentionSuppression>,
}

impl MemoryView {
    /// Construct a view over a pinned snapshot and workspace root.
    pub fn new(snapshot: mneme_store::Snapshot, root: impl Into<std::path::PathBuf>) -> Self {
        Self::with_history(snapshot, root, std::collections::BTreeMap::new())
    }

    /// Construct a view with retained record-revision history available for
    /// resolving pinned citations.
    pub fn with_history(
        snapshot: mneme_store::Snapshot,
        root: impl Into<std::path::PathBuf>,
        history: std::collections::BTreeMap<
            (mneme_core::RecordId, mneme_core::RevisionId),
            mneme_core::RecordEnvelope,
        >,
    ) -> Self {
        let sequences = std::collections::BTreeMap::from([(snapshot.revision, snapshot.sequence)]);
        Self::with_context(snapshot, root, history, sequences)
    }

    /// Construct a view with retained history and committed revision sequences.
    pub fn with_context(
        snapshot: mneme_store::Snapshot,
        root: impl Into<std::path::PathBuf>,
        history: std::collections::BTreeMap<
            (mneme_core::RecordId, mneme_core::RevisionId),
            mneme_core::RecordEnvelope,
        >,
        revision_sequences: std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    ) -> Self {
        Self::with_retention(snapshot, root, history, revision_sequences, Vec::new())
    }

    /// Construct a view with the current retention suppressions in force.
    pub fn with_retention(
        snapshot: mneme_store::Snapshot,
        root: impl Into<std::path::PathBuf>,
        history: std::collections::BTreeMap<
            (mneme_core::RecordId, mneme_core::RevisionId),
            mneme_core::RecordEnvelope,
        >,
        revision_sequences: std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
        suppressions: Vec<mneme_store::RetentionSuppression>,
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
    ) -> Option<&mneme_store::RetentionSuppression> {
        self.suppressions.iter().find(|suppression| {
            suppression.target == record.record_id
                && suppression
                    .revision
                    .is_none_or(|revision| revision == record.revision_id)
        })
    }

    /// Whether a record identity has a withdrawn or forgotten suppression.
    pub fn is_withdrawn(&self, record: mneme_core::RecordId) -> bool {
        self.suppressions.iter().any(|suppression| {
            suppression.target == record
                && suppression.mode == mneme_store::SuppressionMode::Withdrawn
        })
    }

    /// The pinned revision.
    pub fn revision(&self) -> mneme_core::WorkspaceRevisionId {
        self.snapshot.revision
    }

    /// The pinned snapshot's index.
    pub fn index(&self) -> &mneme_core::SnapshotIndex {
        &self.snapshot.index
    }

    /// The underlying snapshot.
    pub fn snapshot(&self) -> &mneme_store::Snapshot {
        &self.snapshot
    }

    pub(crate) fn envelope(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<&mneme_core::RecordEnvelope> {
        self.records
            .get(&record)
            .ok_or(crate::error::MemoryError::Missing { record })
    }

    /// Read one envelope from the pinned view.
    pub fn record(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<&mneme_core::RecordEnvelope> {
        self.envelope(record)
    }

    /// Parse an assertion.
    pub fn assertion(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<crate::model::AssertionView> {
        crate::model::AssertionView::parse(self.envelope(record)?.clone())
    }

    /// Parse a source revision.
    pub fn source(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<crate::model::SourceView> {
        crate::model::SourceView::parse(self.envelope(record)?.clone())
    }

    /// Parse the exact source revision named by evidence.
    pub fn evidence_source(
        &self,
        evidence: &crate::model::EvidenceView,
    ) -> crate::error::Result<crate::model::SourceView> {
        let mut resolved =
            if let mneme_core::Reference::Pinned { revision, .. } = evidence.source_reference {
                if let Some(record) = self.history.get(&(evidence.source, revision)) {
                    crate::model::SourceView::parse(record.clone())?
                } else if let Ok(current) = self.source(evidence.source)
                    && current.record.revision_id == revision
                {
                    current
                } else {
                    return Err(crate::error::MemoryError::Missing {
                        record: evidence.source,
                    });
                }
            } else {
                self.source(evidence.source)?
            };
        // Current retention/erasure availability overlays historical revisions.
        if let Ok(current) = self.source(evidence.source)
            && current.availability != crate::model::SourceAvailability::Retained
        {
            resolved.availability = current.availability;
        }
        Ok(resolved)
    }

    /// Resolve one pinned source revision and overlay current availability.
    pub fn source_at(
        &self,
        source: mneme_core::RecordId,
        revision: mneme_core::RevisionId,
    ) -> crate::error::Result<crate::model::SourceView> {
        let mut resolved = if let Some(record) = self.history.get(&(source, revision)) {
            crate::model::SourceView::parse(record.clone())?
        } else if let Ok(current) = self.source(source)
            && current.record.revision_id == revision
        {
            current
        } else {
            return Err(crate::error::MemoryError::Missing { record: source });
        };
        if let Ok(current) = self.source(source)
            && current.availability != crate::model::SourceAvailability::Retained
        {
            resolved.availability = current.availability;
        }
        Ok(resolved)
    }

    /// The current source record revision.
    pub fn current_source_revision(
        &self,
        source: mneme_core::RecordId,
    ) -> crate::error::Result<mneme_core::RevisionId> {
        Ok(self.source(source)?.record.revision_id)
    }

    /// The source availability currently in force for a source record.
    pub fn current_source_availability(
        &self,
        source: mneme_core::RecordId,
    ) -> crate::error::Result<crate::model::SourceAvailability> {
        Ok(self.source(source)?.availability)
    }

    /// Parse a checkpoint's revision and related references.
    pub fn checkpoint_revision(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<(
        mneme_core::WorkspaceRevisionId,
        std::collections::BTreeSet<mneme_core::RecordId>,
        std::collections::BTreeSet<mneme_core::RecordId>,
    )> {
        let envelope = self.envelope(record)?;
        if envelope.kind != mneme_core::RecordKind::Checkpoint {
            return Err(crate::error::MemoryError::invalid(
                record,
                "checkpoint",
                "not a checkpoint record",
            ));
        }
        let revision = mneme_core::WorkspaceRevisionId::from_value(
            envelope.payload.get("revision").ok_or_else(|| {
                crate::error::MemoryError::invalid(record, "checkpoint", "missing revision")
            })?,
            &mneme_core::Path::root().field("revision"),
        )
        .map_err(|diagnostic| {
            crate::error::MemoryError::invalid(record, "checkpoint", diagnostic.to_string())
        })?;
        let episodes = crate::model::required_reference_set(envelope, "episodes")?;
        let verified = crate::model::required_reference_set(envelope, "verified-outcomes")?;
        Ok((revision, episodes, verified))
    }

    /// Parse evidence.
    pub fn evidence(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<crate::model::EvidenceView> {
        crate::model::EvidenceView::parse(self.envelope(record)?.clone())
    }

    /// Parse a decision.
    pub fn decision(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<crate::model::DecisionView> {
        crate::model::DecisionView::parse(self.envelope(record)?.clone())
    }

    /// Parse a derivation.
    pub fn derivation(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<crate::model::DerivationView> {
        crate::model::DerivationView::parse(self.envelope(record)?.clone())
    }

    /// Parse an episode.
    pub fn episode(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::error::Result<crate::model::EpisodeView> {
        crate::model::EpisodeView::parse(self.envelope(record)?.clone())
    }

    /// Every current assertion.
    pub fn assertions(&self) -> crate::error::Result<Vec<crate::model::AssertionView>> {
        self.records
            .values()
            .filter(|record| record.kind == mneme_core::RecordKind::Assertion)
            .cloned()
            .map(crate::model::AssertionView::parse)
            .collect()
    }

    /// Evidence records for one assertion.
    pub fn evidence_for(
        &self,
        assertion: mneme_core::RecordId,
    ) -> crate::error::Result<Vec<crate::model::EvidenceView>> {
        Ok(self
            .records
            .values()
            .filter(|record| record.kind == mneme_core::RecordKind::Evidence)
            .cloned()
            .filter_map(|record| crate::model::EvidenceView::parse(record).ok())
            .filter(|evidence| evidence.assertion == assertion)
            .collect())
    }

    /// Derivation records for one conclusion.
    pub fn derivations_for(
        &self,
        conclusion: mneme_core::RecordId,
    ) -> crate::error::Result<Vec<crate::model::DerivationView>> {
        Ok(self
            .records
            .values()
            .filter(|record| record.kind == mneme_core::RecordKind::Derivation)
            .cloned()
            .filter_map(|record| crate::model::DerivationView::parse(record).ok())
            .filter(|derivation| derivation.conclusion == conclusion)
            .collect())
    }

    /// Decision records targeting one record.
    pub fn decisions_for(
        &self,
        target: mneme_core::RecordId,
    ) -> crate::error::Result<Vec<crate::model::DecisionView>> {
        Ok(self
            .records
            .values()
            .filter(|record| record.kind == mneme_core::RecordKind::Decision)
            .cloned()
            .filter_map(|record| crate::model::DecisionView::parse(record).ok())
            .filter(|decision| decision.target == target)
            .collect())
    }

    /// Read the exact source bytes and their availability.
    pub fn source_status(
        &self,
        source: mneme_core::RecordId,
    ) -> crate::error::Result<SourceStatus> {
        let view = self.source(source)?;
        self.source_status_for(&view)
    }

    /// Read the exact source bytes and their availability for a parsed source.
    pub fn source_status_for(
        &self,
        view: &crate::model::SourceView,
    ) -> crate::error::Result<SourceStatus> {
        match &view.availability {
            crate::model::SourceAvailability::Retained => {
                let Some(digest) = view.digest() else {
                    return Ok(SourceStatus::Corrupt(
                        "retained source has no digest".to_owned(),
                    ));
                };
                match mneme_store::blob::read(&self.root, digest) {
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
            crate::model::SourceAvailability::Pruned => Ok(SourceStatus::Pruned),
            crate::model::SourceAvailability::Erased => Ok(SourceStatus::Erased),
            crate::model::SourceAvailability::Inaccessible => Ok(SourceStatus::Inaccessible(
                "source is marked inaccessible".to_owned(),
            )),
            crate::model::SourceAvailability::Corrupt { reason } => {
                Ok(SourceStatus::Corrupt(reason.clone()))
            }
            crate::model::SourceAvailability::Unavailable { reason } => {
                Ok(SourceStatus::Inaccessible(reason.clone()))
            }
        }
    }

    /// Validate one evidence record's source revision, span, and excerpt.
    pub fn validate_evidence(
        &self,
        evidence: mneme_core::RecordId,
        requirement: RetainedRequirement,
    ) -> crate::error::Result<ValidatedEvidence> {
        let evidence = self.evidence(evidence)?;
        let source = self.evidence_source(&evidence)?;
        if let mneme_core::Reference::Pinned { revision, .. } = evidence.source_reference
            && revision != source.record.revision_id
        {
            return Err(crate::error::MemoryError::policy(format!(
                "evidence pins source revision {revision}, but the retained source record is {}",
                source.record.revision_id
            )));
        }
        if evidence.span.is_none() && evidence.anchor.is_none() {
            return Err(crate::error::MemoryError::policy(
                "evidence requires an exact span or a stable anchor",
            ));
        }
        if let Some(anchor) = &evidence.anchor
            && anchor.trim().is_empty()
        {
            return Err(crate::error::MemoryError::policy(
                "evidence anchor must not be empty",
            ));
        }
        let status = self.source_status_for(&source)?;
        if requirement == RetainedRequirement::Required
            && !matches!(status, SourceStatus::Retained(_))
        {
            return Err(crate::error::MemoryError::policy(format!(
                "evidence source is {} and cannot be newly cited",
                status.availability().name()
            )));
        }
        let excerpt = match (&evidence.span, &status) {
            (Some(span), SourceStatus::Retained(bytes)) => {
                let end = span.end();
                if end >= bytes.len() as u64 {
                    return Err(crate::error::MemoryError::policy(format!(
                        "evidence span ends at byte {end}, beyond the {} retained bytes",
                        bytes.len()
                    )));
                }
                let start = usize::try_from(span.start())
                    .map_err(|_| crate::error::MemoryError::policy("span start exceeds usize"))?;
                let end = usize::try_from(end)
                    .map_err(|_| crate::error::MemoryError::policy("span end exceeds usize"))?;
                Some(bytes[start..=end].to_vec())
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

    fn valid_time_applies(valid_time: mneme_core::ValidTime, at: mneme_core::Timestamp) -> bool {
        match valid_time {
            mneme_core::ValidTime::Unknown => false,
            mneme_core::ValidTime::Bounded { start, end } => {
                start.is_none_or(|start| start <= at) && end.is_none_or(|end| at <= end)
            }
        }
    }

    fn in_scope(&self, assertion: &crate::model::AssertionView, view: &BeliefView) -> bool {
        if assertion.record.scope == view.scope {
            return true;
        }
        view.include_hypothetical
            && assertion.record.scope.class() == mneme_core::ScopeClass::Hypothesis
    }

    pub fn current_beliefs(
        &self,
        view: &BeliefView,
    ) -> crate::error::Result<Vec<crate::model::AssertionView>> {
        let assertions = self.assertions()?;
        let mut beliefs = Vec::with_capacity(assertions.len());
        for assertion in assertions {
            if !self.in_scope(&assertion, view) {
                continue;
            }
            if !Self::valid_time_applies(assertion.valid_time, view.at) {
                continue;
            }
            match assertion.lifecycle {
                mneme_core::Lifecycle::Accepted
                    if self.accepted_decision(&assertion).unwrap_or(false) =>
                {
                    if self.assertion_has_current_basis(&assertion) {
                        beliefs.push(assertion);
                    }
                }
                mneme_core::Lifecycle::Disputed
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

    fn validity_overlaps(left: mneme_core::ValidTime, right: mneme_core::ValidTime) -> bool {
        match (left, right) {
            (mneme_core::ValidTime::Unknown, _) | (_, mneme_core::ValidTime::Unknown) => true,
            (
                mneme_core::ValidTime::Bounded {
                    start: left_start,
                    end: left_end,
                },
                mneme_core::ValidTime::Bounded {
                    start: right_start,
                    end: right_end,
                },
            ) => {
                let is_left_start_before_right_end = match (left_start, right_end) {
                    (Some(left), Some(right)) => left <= right,
                    _ => true,
                };
                let is_right_start_before_left_end = match (right_start, left_end) {
                    (Some(right), Some(left)) => right <= left,
                    _ => true,
                };
                is_left_start_before_right_end && is_right_start_before_left_end
            }
        }
    }

    pub fn conflicts(&self, view: &BeliefView) -> crate::error::Result<Vec<ConflictGroup>> {
        let assertions = self.assertions()?;
        let mut candidates = Vec::with_capacity(assertions.len());
        for assertion in assertions {
            if !self.in_scope(&assertion, view) {
                continue;
            }
            if assertion.lifecycle == mneme_core::Lifecycle::Accepted
                && !self.accepted_decision(&assertion).unwrap_or(false)
            {
                continue;
            }
            if !matches!(
                assertion.lifecycle,
                mneme_core::Lifecycle::Accepted | mneme_core::Lifecycle::Disputed
            ) {
                continue;
            }
            candidates.push(assertion);
        }
        let mut groups: std::collections::BTreeMap<
            (mneme_core::RecordId, String),
            Vec<crate::model::AssertionView>,
        > = std::collections::BTreeMap::new();
        for (index, left) in candidates.iter().enumerate() {
            for right in candidates.iter().skip(index + 1) {
                if left.subject != right.subject || left.predicate != right.predicate {
                    continue;
                }
                if !Self::validity_overlaps(left.valid_time, right.valid_time) {
                    continue;
                }
                let is_incompatible = match (left.stance, right.stance) {
                    (crate::model::Stance::Affirm, crate::model::Stance::Deny)
                    | (crate::model::Stance::Deny, crate::model::Stance::Affirm) => true,
                    (crate::model::Stance::Affirm, crate::model::Stance::Affirm) => {
                        left.value != right.value
                    }
                    (crate::model::Stance::Deny, crate::model::Stance::Deny) => false,
                    (crate::model::Stance::Hypothesis, _)
                    | (_, crate::model::Stance::Hypothesis) => false,
                };
                if is_incompatible {
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
    pub fn accepted_decision(
        &self,
        assertion: &crate::model::AssertionView,
    ) -> crate::error::Result<bool> {
        let Some(decision_id) = assertion.decision else {
            return Ok(false);
        };
        let decision = self.decision(decision_id)?;
        Ok(
            decision.decision_kind == crate::model::DecisionKind::Acceptance
                && decision.outcome == "accepted"
                && decision.target == assertion.record.record_id,
        )
    }

    /// Whether an assertion's current lifecycle is backed by its decision record.
    pub fn lifecycle_decision_valid(
        &self,
        assertion: &crate::model::AssertionView,
    ) -> crate::error::Result<bool> {
        match assertion.lifecycle {
            mneme_core::Lifecycle::Accepted => self.accepted_decision(assertion),
            mneme_core::Lifecycle::Retracted => {
                let Some(decision_id) = assertion.decision else {
                    return Ok(false);
                };
                let decision = self.decision(decision_id)?;
                Ok(
                    decision.decision_kind == crate::model::DecisionKind::Retraction
                        && decision.outcome == "retracted",
                )
            }
            mneme_core::Lifecycle::Superseded => {
                let Some(decision_id) = assertion.decision else {
                    return Ok(false);
                };
                let decision = self.decision(decision_id)?;
                Ok(
                    decision.decision_kind == crate::model::DecisionKind::Supersession
                        && decision.outcome == "superseded",
                )
            }
            mneme_core::Lifecycle::Disputed => {
                let Some(decision_id) = assertion.decision else {
                    return Ok(false);
                };
                let decision = self.decision(decision_id)?;
                Ok(
                    decision.decision_kind == crate::model::DecisionKind::ConflictResolution
                        && decision.outcome == "disputed",
                )
            }
            mneme_core::Lifecycle::Proposed => Ok(assertion.decision.is_none()),
        }
    }

    /// Whether an assertion has an observed outcome episode in its evidence ancestry.
    pub fn has_observed_outcome(
        &self,
        assertion: &crate::model::AssertionView,
    ) -> crate::error::Result<bool> {
        for evidence_id in &assertion.evidence {
            if let Ok(evidence) = self.evidence(*evidence_id) {
                for ancestor in &evidence.ancestry {
                    if let Ok(episode) = self.episode(*ancestor)
                        && matches!(
                            episode.episode_type,
                            crate::model::EpisodeType::Outcome
                                | crate::model::EpisodeType::Observation
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
    pub fn evidence_roots(
        &self,
        evidence: mneme_core::RecordId,
    ) -> crate::error::Result<std::collections::BTreeSet<SourceRevisionKey>> {
        let mut roots = std::collections::BTreeSet::new();
        let mut visiting = std::collections::BTreeSet::new();
        self.collect_roots(evidence, &mut roots, &mut visiting)?;
        Ok(roots)
    }

    #[allow(unknown_lints, no_recursion)] // Octet structural exception: cohesive state-machine code; split tracked separately
    fn collect_roots(
        &self,
        record: mneme_core::RecordId,
        roots: &mut std::collections::BTreeSet<SourceRevisionKey>,
        visiting: &mut std::collections::BTreeSet<mneme_core::RecordId>,
    ) -> crate::error::Result<()> {
        if !visiting.insert(record) {
            return Err(crate::error::MemoryError::policy(format!(
                "evidence ancestry contains a cycle at {record}"
            )));
        }
        let Some(envelope) = self.records.get(&record) else {
            visiting.remove(&record);
            return Ok(());
        };
        match envelope.kind {
            mneme_core::RecordKind::Evidence => {
                let evidence = crate::model::EvidenceView::parse(envelope.clone())?;
                if evidence.ancestry.is_empty() {
                    let source = self.evidence_source(&evidence)?;
                    roots.insert((evidence.source, source.record.revision_id));
                } else {
                    for ancestor in &evidence.ancestry {
                        self.collect_roots(*ancestor, roots, visiting)?;
                    }
                }
            }
            mneme_core::RecordKind::Episode => {
                let episode = crate::model::EpisodeView::parse(envelope.clone())?;
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
            mneme_core::RecordKind::Assertion => {
                let assertion = crate::model::AssertionView::parse(envelope.clone())?;
                for evidence in &assertion.evidence {
                    self.collect_roots(*evidence, roots, visiting)?;
                }
            }
            mneme_core::RecordKind::Derivation => {
                let derivation = crate::model::DerivationView::parse(envelope.clone())?;
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
    pub fn corroboration(
        &self,
        assertion: mneme_core::RecordId,
    ) -> crate::error::Result<Corroboration> {
        let assertion = self.assertion(assertion)?;
        let mut roots = std::collections::BTreeSet::new();
        let mut supporting = 0;
        for evidence_id in &assertion.evidence {
            let evidence = self.evidence(*evidence_id)?;
            if evidence.relation != crate::model::SupportRelation::Supports {
                continue;
            }
            if self
                .suppression_for(&evidence.record)
                .is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                })
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

    fn assertion_grounded(&self, assertion: &crate::model::AssertionView) -> bool {
        assertion
            .evidence
            .iter()
            .any(|evidence_id| match self.evidence(*evidence_id) {
                Ok(evidence) => {
                    evidence.relation == crate::model::SupportRelation::Supports
                        && self.records.contains_key(&evidence.source)
                        && self
                            .suppression_for(&evidence.record)
                            .is_none_or(|suppression| {
                                suppression.mode != mneme_store::SuppressionMode::Withdrawn
                            })
                }
                Err(_) => false,
            })
    }

    fn assertion_eligible_inner(
        &self,
        assertion_id: mneme_core::RecordId,
        visiting: &mut std::collections::BTreeSet<mneme_core::RecordId>,
    ) -> bool {
        if !visiting.insert(assertion_id) {
            return false;
        }
        let is_result = (|| {
            let assertion = self.assertion(assertion_id).ok()?;
            if self
                .suppression_for(&assertion.record)
                .is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                })
            {
                return Some(false);
            }
            if assertion.lifecycle != mneme_core::Lifecycle::Accepted {
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
        is_result
    }

    fn derivation_eligible_inner(
        &self,
        derivation: &crate::model::DerivationView,
        visiting: &mut std::collections::BTreeSet<mneme_core::RecordId>,
    ) -> bool {
        if !visiting.insert(derivation.record.record_id) {
            return false;
        }
        let is_result = self.derivation_eligible_inner_body(derivation, visiting);
        visiting.remove(&derivation.record.record_id);
        is_result
    }

    fn derivation_revision_matches(&self, derivation: &crate::model::DerivationView) -> bool {
        let Some(evaluated) = self.revision_sequences.get(&derivation.evaluation_revision) else {
            return false;
        };
        *evaluated <= self.snapshot.sequence
    }

    fn derivation_eligible_inner_body(
        &self,
        derivation: &crate::model::DerivationView,
        visiting: &mut std::collections::BTreeSet<mneme_core::RecordId>,
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
            let is_eligible = match envelope.kind {
                mneme_core::RecordKind::Assertion => {
                    self.assertion_eligible_inner(*premise, visiting)
                }
                mneme_core::RecordKind::Derivation => match self.derivation(*premise) {
                    Ok(premise_derivation) => {
                        self.derivation_eligible_inner(&premise_derivation, visiting)
                    }
                    Err(_) => false,
                },
                mneme_core::RecordKind::Episode => {
                    self.suppression_for(envelope).is_none_or(|suppression| {
                        suppression.mode != mneme_store::SuppressionMode::Withdrawn
                    })
                }
                mneme_core::RecordKind::Entity
                | mneme_core::RecordKind::Relation
                | mneme_core::RecordKind::Document
                | mneme_core::RecordKind::SourceRevision
                | mneme_core::RecordKind::Evidence
                | mneme_core::RecordKind::Checkpoint
                | mneme_core::RecordKind::Proposal
                | mneme_core::RecordKind::Decision
                | mneme_core::RecordKind::RetentionDirective
                | mneme_core::RecordKind::DocumentBinding
                | mneme_core::RecordKind::DocumentAnchor => false,
            };
            if !is_eligible {
                return false;
            }
        }
        true
    }

    /// Whether one assertion currently has a complete grounded justification.
    pub fn assertion_eligible(&self, assertion: mneme_core::RecordId) -> bool {
        let mut visiting = std::collections::BTreeSet::new();
        self.assertion_eligible_inner(assertion, &mut visiting)
    }

    /// Whether an accepted assertion has a surviving proof or an explicitly
    /// complete absence basis.
    pub fn assertion_has_current_basis(&self, assertion: &crate::model::AssertionView) -> bool {
        if self.assertion_eligible(assertion.record.record_id) {
            return true;
        }
        assertion.evidence.is_empty()
            && assertion
                .record
                .payload
                .get("completeness")
                .and_then(mneme_core::Value::as_symbol)
                .is_some_and(|symbol| symbol.as_str() == "declared-complete")
    }

    /// Alternative derivations for one conclusion with eligibility reasons.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn derivation_alternatives(
        &self,
        conclusion: mneme_core::RecordId,
    ) -> crate::error::Result<Vec<DerivationAlternative>> {
        let max_derivation_records = 1_000_000;
        if self.records.len() > max_derivation_records {
            return Err(crate::error::MemoryError::policy(
                "derivation traversal exceeds the 1M record bound",
            ));
        }
        let derivations = self.derivations_for(conclusion)?;
        let mut alternatives = Vec::with_capacity(derivations.len());
        for derivation in derivations {
            let mut visiting = std::collections::BTreeSet::new();
            let is_eligible = self.derivation_eligible_inner(&derivation, &mut visiting);
            let mut reasons = Vec::with_capacity(derivation.premises.len().saturating_add(1));
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
                if envelope.kind == mneme_core::RecordKind::Assertion
                    && !self.assertion_eligible(*premise)
                {
                    reasons.push(format!("premise {premise} is not currently eligible"));
                }
            }
            alternatives.push(DerivationAlternative {
                derivation: derivation.record.record_id,
                rule_id: derivation.rule_id,
                rule_version: derivation.rule_version,
                eligible: is_eligible,
                reasons,
            });
        }
        Ok(alternatives)
    }

    /// Build a bounded explanation for one current assertion.
    #[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
    pub fn explain(
        &self,
        assertion: mneme_core::RecordId,
        policy: Policy,
    ) -> crate::error::Result<Explanation> {
        let assertion = self.assertion(assertion)?;
        let decisions = self.decisions_for(assertion.record.record_id)?;
        let (evidence_explanations, roots, evidence_nodes, is_truncated) =
            self.explain_evidence(&assertion, policy)?;
        let derivations = self.derivation_alternatives(assertion.record.record_id)?;
        let nodes = evidence_nodes + derivations.len();
        let supporting = self.supporting_evidence_count(&assertion);
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
            truncated: is_truncated || nodes > policy.max_explanation_nodes,
        })
    }

    fn explain_evidence(
        &self,
        assertion: &crate::model::AssertionView,
        policy: Policy,
    ) -> crate::error::Result<(
        Vec<EvidenceExplanation>,
        std::collections::BTreeSet<SourceRevisionKey>,
        usize,
        bool,
    )> {
        let mut nodes = 1;
        let mut is_truncated = false;
        let mut evidence_explanations = Vec::with_capacity(assertion.evidence.len());
        let mut roots = std::collections::BTreeSet::new();
        for evidence_id in &assertion.evidence {
            if nodes >= policy.max_explanation_nodes {
                is_truncated = true;
                break;
            }
            let evidence = self.evidence(*evidence_id)?;
            let source = self.evidence_source(&evidence)?;
            let status = self.source_status_for(&source)?;
            let availability = status.availability();
            let excerpt = match (&evidence.span, &status) {
                (Some(span), SourceStatus::Retained(bytes)) => {
                    let start = usize::try_from(span.start()).map_err(|_| {
                        crate::error::MemoryError::policy("span start exceeds usize")
                    })?;
                    let end = usize::try_from(span.end())
                        .map_err(|_| crate::error::MemoryError::policy("span end exceeds usize"))?
                        .saturating_add(1)
                        .min(bytes.len());
                    if start <= end {
                        let is_truncated_excerpt = end - start > policy.max_excerpt_bytes;
                        let end = start + (end - start).min(policy.max_excerpt_bytes);
                        Some(SourceExcerpt {
                            bytes: bytes[start..end].to_vec(),
                            truncated: is_truncated_excerpt,
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };
            let evidence_roots = self.evidence_roots(*evidence_id).unwrap_or_default();
            let is_withdrawn = self
                .suppression_for(&evidence.record)
                .is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                });
            let is_eligible = !is_withdrawn;
            if is_eligible && evidence.relation == crate::model::SupportRelation::Supports {
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
                withdrawn: is_withdrawn,
                eligible: is_eligible,
            });
            nodes += 1;
        }
        Ok((evidence_explanations, roots, nodes, is_truncated))
    }

    fn supporting_evidence_count(&self, assertion: &crate::model::AssertionView) -> usize {
        assertion
            .evidence
            .iter()
            .filter(|evidence_id| {
                self.evidence(**evidence_id)
                    .map(|evidence| {
                        evidence.relation == crate::model::SupportRelation::Supports
                            && self
                                .suppression_for(&evidence.record)
                                .is_none_or(|suppression| {
                                    suppression.mode != mneme_store::SuppressionMode::Withdrawn
                                })
                    })
                    .unwrap_or(false)
            })
            .count()
    }
}

/// Explicit authored-premise predicate convention for derivations.
pub const EXPLICIT_AUTHORED_PREDICATE: &str = "explicit-authored-premise";
