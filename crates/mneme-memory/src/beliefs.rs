//! Evidence policy: span validation, belief views, conflicts, support,
//! ancestry, and bounded explanations.
//!
//! Everything here is computed from one pinned store snapshot. No method mutates
//! canonical state or promotes a proposed assertion.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

pub mod antichain;
pub mod aspic;
pub mod calculus;
pub mod captures;
pub mod traits;

/// The policy predicate used for action-completion claims.
pub const ACTION_COMPLETED_PREDICATE: &str = "action-completed";

/// Root identity of source evidence: the source record and exact revision.
pub type SourceRevisionKey = (mneme_core::RecordId, mneme_core::RevisionId);

/// Hard bound on graph nodes one ancestry, belief or explanation query may
/// visit. A query that needs more reports truncation instead of walking a
/// hostile graph without limit.
pub const MAX_ANCESTRY_NODES: u64 = 1_000_000;

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

/// Incompatible or challenged claims retained under one subject/predicate and scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictGroup {
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub assertions: Vec<crate::model::AssertionView>,
    pub argumentation: aspic::ArgumentationVerdict,
    pub opinion: aspic::Opinion,
}

/// Classification of an assertion change between two workspace revisions within
/// a valid-time window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitemporalChangeKind {
    /// New fact at a later valid time, or clean closing of an open-ended fact.
    WorldEvolution,
    /// Retroactive modification, retraction, backdated insertion, or overlapping
    /// revision affecting previously recorded valid time.
    RetroactiveCorrection,
}

/// One assertion-level difference between two revisions within a valid-time window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitemporalChange {
    pub assertion_id: mneme_core::RecordId,
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub kind: BitemporalChangeKind,
    pub before: Option<crate::model::AssertionView>,
    pub after: Option<crate::model::AssertionView>,
    pub before_status: traits::SlotStatus,
    pub after_status: traits::SlotStatus,
    /// Half-open valid-time period affected inside the requested window.
    pub affected_period: mneme_kernel::temporal::Period,
}

/// Bitemporal diff between two committed snapshots over a half-open valid-time window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BitemporalDiff {
    pub rev_a: mneme_core::WorkspaceRevisionId,
    pub rev_b: mneme_core::WorkspaceRevisionId,
    pub layer: traits::QueryLayer,
    pub valid_window: mneme_kernel::temporal::Period,
    pub changes: Vec<BitemporalChange>,
    pub slots: Vec<traits::SlotDiffEntry>,
}

/// Request parameters for comparing explicit `(subject, predicate)` slots across
/// two committed snapshots at an instant `at` and layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotDiffRequest {
    pub scope: mneme_core::ScopeId,
    pub at: mneme_core::Timestamp,
    pub layer: traits::QueryLayer,
    pub slots: Vec<(mneme_core::RecordId, String)>,
}

impl BitemporalDiff {
    /// Changes classified as [`BitemporalChangeKind::WorldEvolution`].
    pub fn world_evolutions(&self) -> impl Iterator<Item = &BitemporalChange> {
        self.changes
            .iter()
            .filter(|change| change.kind == BitemporalChangeKind::WorldEvolution)
    }

    /// Changes classified as [`BitemporalChangeKind::RetroactiveCorrection`].
    pub fn retroactive_corrections(&self) -> impl Iterator<Item = &BitemporalChange> {
        self.changes
            .iter()
            .filter(|change| change.kind == BitemporalChangeKind::RetroactiveCorrection)
    }
}

/// Convert a canonical [`mneme_core::ValidTime`] into the verified half-open
/// [`mneme_kernel::temporal::Validity`] representation.
///
/// Legacy point-instant valid times (`start == Some(t) && end == Some(t)`)
/// decode to `[t, t + 1ns)`; all other bounded intervals use half-open
/// `[start, end)` semantics. `ValidTime::Unknown` maps to fail-closed `Unknown`.
pub fn valid_time_to_kernel(valid_time: mneme_core::ValidTime) -> mneme_kernel::temporal::Validity {
    match valid_time {
        mneme_core::ValidTime::Unknown => mneme_kernel::temporal::Validity::Unknown,
        mneme_core::ValidTime::Bounded { start, end } => {
            match mneme_kernel::temporal::from_legacy_bounds(
                start.map(mneme_core::Timestamp::nanos),
                end.map(mneme_core::Timestamp::nanos),
            ) {
                Some(period) => mneme_kernel::temporal::Validity::Known(period),
                None => mneme_kernel::temporal::Validity::Unknown,
            }
        }
    }
}

/// Whether newly cited evidence must still have retained source bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetainedRequirement {
    Required,
    Optional,
}

/// Evidence whose span and source revision were validated.
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatedEvidence {
    pub evidence: crate::model::EvidenceView,
    pub source: crate::model::SourceView,
    pub availability: crate::model::SourceAvailability,
    /// Bounded excerpt of the cited span and whether the bound cut it.
    pub excerpt: Option<SourceExcerpt>,
}

/// A bounded excerpt of exact retained source bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceExcerpt {
    pub bytes: Vec<u8>,
    /// The excerpt is shorter than the cited span.
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
    /// The evidence or its source lies outside the readable scopes, so every
    /// identity above is withheld (zeroed) and no span, excerpt or root is
    /// reported.
    pub inaccessible: bool,
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
    pub opinion: aspic::Opinion,
}

/// A bounded explanation of one current assertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Explanation {
    pub assertion: crate::model::AssertionView,
    pub workspace_revision: mneme_core::WorkspaceRevisionId,
    pub decisions: Vec<crate::model::DecisionView>,
    pub evidence: Vec<EvidenceExplanation>,
    pub derivations: Vec<DerivationAlternative>,
    /// Minimal-support antichain (`PosBool(X)` DNF absorption) over leaf root
    /// supports of this assertion and its eligible derivations.
    pub minimal_supports: Vec<std::collections::BTreeSet<mneme_core::RecordId>>,
    pub corroboration: Corroboration,
    pub argumentation: aspic::ArgumentationVerdict,
    pub opinion: aspic::Opinion,
    pub truncated: bool,
    /// Graph nodes the bounded walk visited while building this explanation.
    pub visited_nodes: u64,
    /// Decisions that target this assertion but lie outside the readable
    /// scopes; only the count is reported.
    pub inaccessible_decisions: usize,
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
pub struct View {
    snapshot: mneme_store::Snapshot,
    root: std::path::PathBuf,
    records: std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    history: std::collections::BTreeMap<
        (mneme_core::RecordId, mneme_core::RevisionId),
        mneme_core::RecordEnvelope,
    >,
    revision_sequences: std::collections::BTreeMap<mneme_core::WorkspaceRevisionId, u64>,
    suppressions: Vec<mneme_store::RetentionSuppression>,
    access: crate::authorization::Access,
}

impl View {
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
        View {
            snapshot,
            root: root.into(),
            records,
            history,
            revision_sequences,
            suppressions,
            // A view built without an explicit grant reads only its own scope.
            access: crate::authorization::Access::Scopes(std::collections::BTreeSet::new()),
        }
    }

    /// Attach the caller's scope authorization to this view.
    pub fn with_access(mut self, access: crate::authorization::Access) -> Self {
        self.access = access;
        self
    }

    /// The caller's scope authorization for this view.
    pub fn access(&self) -> &crate::authorization::Access {
        &self.access
    }

    /// Whether content held in `scope` may be shown to a caller working in
    /// `base`. The kernel owns the rule; the base scope is always readable.
    pub(crate) fn content_readable_in(
        &self,
        scope: &mneme_core::ScopeId,
        base: &mneme_core::ScopeId,
    ) -> bool {
        mneme_kernel::isolation::content_readable(&mneme_kernel::isolation::ContentFacts {
            same_scope: scope == base,
            target_authorized: self.access.allows(scope),
        })
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
    ) -> crate::failure::Result<&mneme_core::RecordEnvelope> {
        self.records
            .get(&record)
            .ok_or(crate::failure::EvidenceError::Missing { record })
    }

    /// Read one envelope from the pinned view.
    pub fn record(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<&mneme_core::RecordEnvelope> {
        self.envelope(record)
    }

    /// Parse an assertion.
    pub fn assertion(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::AssertionView> {
        crate::model::AssertionView::parse(self.envelope(record)?.clone())
    }

    /// Parse a source revision.
    pub fn source(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::SourceView> {
        crate::model::SourceView::parse(self.envelope(record)?.clone())
    }

    /// Parse one recognition-run record.
    pub fn recognition_run(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::RecognitionRunView> {
        crate::model::RecognitionRunView::parse(self.envelope(record)?.clone())
    }

    /// Parse one recognition-segment record.
    pub fn recognition_segment(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::RecognitionSegmentView> {
        crate::model::RecognitionSegmentView::parse(self.envelope(record)?.clone())
    }

    /// Current, unsuppressed segments aligned to one exact text revision.
    pub fn recognition_segments_for_source(
        &self,
        source: mneme_core::RecordId,
        revision: mneme_core::RevisionId,
    ) -> Vec<crate::model::RecognitionSegmentView> {
        self.records
            .values()
            .filter(|record| {
                record.kind == mneme_core::RecordKind::RecognitionSegment
                    && self.suppression_for(record).is_none()
            })
            .filter_map(|record| crate::model::RecognitionSegmentView::parse(record.clone()).ok())
            .filter(|segment| segment.text_source == mneme_core::SourcePin::new(source, revision))
            .collect()
    }

    /// Root source revisions for an exact source pin, following immutable
    /// `derived-from` edges and refusing forgotten ancestors or cycles.
    pub fn source_roots(
        &self,
        pin: mneme_core::SourcePin,
    ) -> crate::failure::Result<std::collections::BTreeSet<SourceRevisionKey>> {
        let mut pending = vec![pin];
        let mut visited = std::collections::BTreeSet::new();
        let mut roots = std::collections::BTreeSet::new();
        while let Some(current) = pending.pop() {
            if visited.contains(&current) {
                return Err(crate::failure::EvidenceError::policy(
                    "source transformation ancestry contains a cycle",
                ));
            }
            if visited.len() as u64 >= MAX_ANCESTRY_NODES {
                return Err(crate::failure::EvidenceError::policy(
                    "source transformation ancestry exceeds its bound",
                ));
            }
            visited.insert(current);
            let source = self.source_at(current.source(), current.revision())?;
            if self
                .suppression_for(&source.record)
                .is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Forgotten
                })
            {
                return Err(crate::failure::EvidenceError::policy(
                    "source transformation ancestry was forgotten",
                ));
            }
            match source.derived_from {
                Some(parent) => pending.push(parent),
                None => {
                    roots.insert((current.source(), current.revision()));
                }
            }
        }
        if roots.is_empty() {
            return Err(crate::failure::EvidenceError::policy(
                "source transformation ancestry has no evidence root",
            ));
        }
        Ok(roots)
    }

    /// Parse the exact source revision named by evidence.
    pub fn evidence_source(
        &self,
        evidence: &crate::model::EvidenceView,
    ) -> crate::failure::Result<crate::model::SourceView> {
        let mut resolved =
            if let mneme_core::Reference::Pinned { revision, .. } = evidence.source_reference {
                if let Some(record) = self.history.get(&(evidence.source, revision)) {
                    crate::model::SourceView::parse(record.clone())?
                } else if let Ok(current) = self.source(evidence.source)
                    && current.record.revision_id == revision
                {
                    current
                } else {
                    return Err(crate::failure::EvidenceError::Missing {
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
    ) -> crate::failure::Result<crate::model::SourceView> {
        let mut resolved = if let Some(record) = self.history.get(&(source, revision)) {
            crate::model::SourceView::parse(record.clone())?
        } else if let Ok(current) = self.source(source)
            && current.record.revision_id == revision
        {
            current
        } else {
            return Err(crate::failure::EvidenceError::Missing { record: source });
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
    ) -> crate::failure::Result<mneme_core::RevisionId> {
        Ok(self.source(source)?.record.revision_id)
    }

    /// The source availability currently in force for a source record.
    pub fn current_source_availability(
        &self,
        source: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::SourceAvailability> {
        Ok(self.source(source)?.availability)
    }

    /// Parse a checkpoint's revision and related references.
    pub fn checkpoint_revision(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<(
        mneme_core::WorkspaceRevisionId,
        std::collections::BTreeSet<mneme_core::RecordId>,
        std::collections::BTreeSet<mneme_core::RecordId>,
    )> {
        let envelope = self.envelope(record)?;
        if envelope.kind != mneme_core::RecordKind::Checkpoint {
            return Err(crate::failure::EvidenceError::invalid(
                record,
                "checkpoint",
                "not a checkpoint record",
            ));
        }
        let revision = mneme_core::WorkspaceRevisionId::from_value(
            envelope.payload.get("revision").ok_or_else(|| {
                crate::failure::EvidenceError::invalid(record, "checkpoint", "missing revision")
            })?,
            &mneme_core::Path::root().field("revision"),
        )
        .map_err(|diagnostic| {
            crate::failure::EvidenceError::invalid(record, "checkpoint", diagnostic.to_string())
        })?;
        let episodes = crate::model::required_reference_set(envelope, "episodes")?;
        let verified = crate::model::required_reference_set(envelope, "verified-outcomes")?;
        Ok((revision, episodes, verified))
    }

    /// Parse evidence.
    pub fn evidence(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::EvidenceView> {
        crate::model::EvidenceView::parse(self.envelope(record)?.clone())
    }

    /// Parse a decision.
    pub fn decision(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::DecisionView> {
        crate::model::DecisionView::parse(self.envelope(record)?.clone())
    }

    /// Parse a derivation.
    pub fn derivation(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::DerivationView> {
        crate::model::DerivationView::parse(self.envelope(record)?.clone())
    }

    /// Parse an episode.
    pub fn episode(
        &self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<crate::model::EpisodeView> {
        crate::model::EpisodeView::parse(self.envelope(record)?.clone())
    }

    /// Every current assertion.
    pub fn assertions(&self) -> crate::failure::Result<Vec<crate::model::AssertionView>> {
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
    ) -> crate::failure::Result<Vec<crate::model::EvidenceView>> {
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
    ) -> crate::failure::Result<Vec<crate::model::DerivationView>> {
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
    ) -> crate::failure::Result<Vec<crate::model::DecisionView>> {
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
    ) -> crate::failure::Result<SourceStatus> {
        let view = self.source(source)?;
        self.source_status_for(&view)
    }

    /// Read the exact source bytes and their availability for a parsed source.
    pub fn source_status_for(
        &self,
        view: &crate::model::SourceView,
    ) -> crate::failure::Result<SourceStatus> {
        let pin = mneme_core::SourcePin::new(view.record.record_id, view.record.revision_id);
        if self.source_roots(pin).is_err() {
            return Ok(SourceStatus::Erased);
        }
        match &view.availability {
            crate::model::SourceAvailability::Retained => {
                let Some(digest) = view.digest() else {
                    return Ok(SourceStatus::Corrupt(
                        "retained source has no digest".to_owned(),
                    ));
                };
                match mneme_store::payload::read(&self.root, digest) {
                    Ok(bytes) => Ok(SourceStatus::Retained(bytes)),
                    Err(mneme_store::Failure::MissingBlob { .. }) => {
                        // A pinned revision keeps its retention outcome even
                        // after the record gains a newer retained revision, so
                        // absence brought by pruning is never mislabelled as
                        // corruption.
                        Ok(self
                            .retention_status_for(view.record.record_id, digest)
                            .unwrap_or_else(|| {
                                SourceStatus::Corrupt("committed source blob is missing".to_owned())
                            }))
                    }
                    Err(mneme_store::Failure::CorruptBlob { reason, .. }) => {
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

    /// The newest retention outcome that removed a digest from this record.
    fn retention_status_for(
        &self,
        source: mneme_core::RecordId,
        digest: mneme_core::ContentDigest,
    ) -> Option<SourceStatus> {
        let mut newest: Option<(u64, SourceStatus)> = None;
        let candidates = self
            .history
            .iter()
            .filter(|((record, _), _)| *record == source)
            .map(|(_, envelope)| envelope)
            .chain(self.records.get(&source));
        for envelope in candidates {
            let Ok(view) = crate::model::SourceView::parse(envelope.clone()) else {
                continue;
            };
            if view.prior_digest != Some(digest) {
                continue;
            }
            let status = match view.availability {
                crate::model::SourceAvailability::Pruned => SourceStatus::Pruned,
                crate::model::SourceAvailability::Erased => SourceStatus::Erased,
                _ => continue,
            };
            let order = envelope.recorded.revision_order();
            if newest
                .as_ref()
                .is_none_or(|(newest_order, _)| order >= *newest_order)
            {
                newest = Some((order, status));
            }
        }
        newest.map(|(_, status)| status)
    }

    /// Validate one evidence record's source revision, span, and excerpt.
    pub fn validate_evidence(
        &self,
        evidence: mneme_core::RecordId,
        requirement: RetainedRequirement,
    ) -> crate::failure::Result<ValidatedEvidence> {
        let evidence = self.evidence(evidence)?;
        // Decide readability before resolving the source revision so a foreign
        // record's identity or history never reaches the error text.
        match self.records.get(&evidence.source) {
            Some(record) if self.content_readable_in(&record.scope, &evidence.record.scope) => {}
            Some(_) => {
                return Err(crate::failure::EvidenceError::policy(
                    "evidence source is outside the readable scopes",
                ));
            }
            None => {
                return Err(crate::failure::EvidenceError::policy(
                    "evidence source is unavailable",
                ));
            }
        }
        let source = self.evidence_source(&evidence).map_err(|_| {
            crate::failure::EvidenceError::policy("evidence source revision is unavailable")
        })?;
        self.source_roots(mneme_core::SourcePin::new(
            source.record.record_id,
            source.record.revision_id,
        ))
        .map_err(|_| {
            crate::failure::EvidenceError::policy("evidence source ancestry is unavailable")
        })?;
        if let mneme_core::Reference::Pinned { revision, .. } = evidence.source_reference
            && revision != source.record.revision_id
        {
            return Err(crate::failure::EvidenceError::policy(format!(
                "evidence pins source revision {revision}, but the retained source record is {}",
                source.record.revision_id
            )));
        }
        if evidence.span.is_none() && evidence.anchor.is_none() {
            return Err(crate::failure::EvidenceError::policy(
                "evidence requires an exact span or a stable anchor",
            ));
        }
        if let Some(anchor) = &evidence.anchor
            && anchor.trim().is_empty()
        {
            return Err(crate::failure::EvidenceError::policy(
                "evidence anchor must not be empty",
            ));
        }
        let (availability, excerpt) =
            self.validate_evidence_span(&source, evidence.span, requirement)?;
        Ok(ValidatedEvidence {
            evidence,
            source,
            availability,
            excerpt,
        })
    }

    fn validate_evidence_span(
        &self,
        source: &crate::model::SourceView,
        span: Option<mneme_core::SourceSpan>,
        requirement: RetainedRequirement,
    ) -> crate::failure::Result<(crate::model::SourceAvailability, Option<SourceExcerpt>)> {
        let Some(span) = span else {
            let status = self.source_status_for(source)?;
            let availability = status.availability();
            require_retained_availability(&availability, requirement)?;
            return Ok((availability, None));
        };
        let (availability, excerpt, retained_bytes) =
            self.source_span_excerpt_for(source, span, u64::MAX)?;
        require_retained_availability(&availability, requirement)?;
        if let Some(text_bytes) = retained_bytes {
            check_span_within_retained(span, text_bytes)?;
        }
        Ok((availability, excerpt))
    }

    /// Verify and slice `span` (bounded by `max_bytes`) using `bao-tree` range
    /// verification when available, without reading unrelated blob chunks.
    fn source_span_excerpt_for(
        &self,
        view: &crate::model::SourceView,
        span: mneme_core::SourceSpan,
        max_bytes: u64,
    ) -> crate::failure::Result<(
        crate::model::SourceAvailability,
        Option<SourceExcerpt>,
        Option<u64>,
    )> {
        let pin = mneme_core::SourcePin::new(view.record.record_id, view.record.revision_id);
        if self.source_roots(pin).is_err() {
            return Ok((crate::model::SourceAvailability::Erased, None, None));
        }
        if view.availability != crate::model::SourceAvailability::Retained {
            return Ok((unavailable_source_label(&view.availability), None, None));
        }
        let mneme_core::SourceContent::Retained(retained) = &view.content else {
            return Ok((
                crate::model::SourceAvailability::Corrupt {
                    reason: "retained source has no digest".to_owned(),
                },
                None,
                None,
            ));
        };
        self.verify_retained_span_excerpt(view.record.record_id, retained, span, max_bytes)
    }

    fn verify_retained_span_excerpt(
        &self,
        source_id: mneme_core::RecordId,
        retained: &mneme_core::RetainedSource,
        span: mneme_core::SourceSpan,
        max_bytes: u64,
    ) -> crate::failure::Result<(
        crate::model::SourceAvailability,
        Option<SourceExcerpt>,
        Option<u64>,
    )> {
        let digest = retained.digest();
        let text_bytes = retained.byte_length();
        debug_assert_eq!(text_bytes, retained.byte_length());
        debug_assert!(span.start() <= span.end());
        let window = span.end().checked_add(1).and_then(|stop| {
            mneme_kernel::extent::excerpt_window(&mneme_kernel::extent::ExcerptRequest {
                start: span.start(),
                stop,
                text_len: text_bytes,
                max_bytes,
            })
        });
        let (read_range, read_start) = match window {
            Some(window) => {
                let start = window.start.saturating_sub(3);
                let end = window.stop.saturating_add(1).min(text_bytes);
                (start..end, start)
            }
            None => (0_u64..0_u64, 0),
        };
        match mneme_store::verify_span_range(&self.root, digest, read_range) {
            Ok(slice) => {
                let excerpt = window.and_then(|win| {
                    excerpt_from_window_slice(
                        &slice,
                        &ExcerptWindowSlice {
                            read_start_bytes: read_start,
                            window: win,
                            text_bytes,
                            span,
                        },
                    )
                });
                Ok((
                    crate::model::SourceAvailability::Retained,
                    excerpt,
                    Some(text_bytes),
                ))
            }
            Err(error) => self.map_span_read_error(source_id, digest, error),
        }
    }

    fn map_span_read_error(
        &self,
        source_id: mneme_core::RecordId,
        digest: mneme_core::ContentDigest,
        error: mneme_store::Failure,
    ) -> crate::failure::Result<(
        crate::model::SourceAvailability,
        Option<SourceExcerpt>,
        Option<u64>,
    )> {
        match error {
            mneme_store::Failure::MissingBlob { .. } => Ok((
                self.retention_status_for(source_id, digest)
                    .unwrap_or_else(|| {
                        SourceStatus::Corrupt("committed source blob is missing".to_owned())
                    })
                    .availability(),
                None,
                None,
            )),
            mneme_store::Failure::CorruptBlob { reason, .. } => Ok((
                crate::model::SourceAvailability::Corrupt { reason },
                None,
                None,
            )),
            other => Err(other.into()),
        }
    }

    /// Whether a claim's valid time covers `at` under half-open `[start, end)`
    /// semantics (with legacy point-instant compatibility `[t, t + 1ns)`).
    ///
    /// This is the one temporal rule of a belief view: an unknown valid time
    /// never answers a requested instant, and an open bound is unbounded on
    /// that side. Belief and conflict selection both use it, so the two views
    /// can never disagree about which claims apply at an instant.
    pub(crate) fn all_envelopes(&self) -> impl Iterator<Item = &mneme_core::RecordEnvelope> {
        self.records.values()
    }

    pub(crate) fn valid_time_applies(
        valid_time: mneme_core::ValidTime,
        at: mneme_core::Timestamp,
    ) -> bool {
        mneme_kernel::temporal::validity_contains(
            valid_time_to_kernel(valid_time),
            i128::from(at.nanos()),
        )
    }

    fn in_scope(&self, assertion: &crate::model::AssertionView, view: &BeliefView) -> bool {
        mneme_kernel::isolation::record_visible(&mneme_kernel::isolation::VisibilityFacts {
            same_scope: assertion.record.scope == view.scope,
            record_class: assertion.record.scope.class().to_kernel(),
            include_hypothetical: view.include_hypothetical,
            record_scope_authorized: self.access.allows(&assertion.record.scope)
                || assertion.record.scope == view.scope,
        })
    }

    /// Every assertion that is a current belief in this view.
    pub fn current_beliefs(
        &self,
        view: &BeliefView,
    ) -> crate::failure::Result<Vec<crate::model::AssertionView>> {
        let assertions = self.assertions()?;
        let mut ancestry = Ancestry::new(self, MAX_ANCESTRY_NODES, false);
        let mut beliefs = Vec::with_capacity(assertions.len());
        for assertion in assertions {
            if !self.in_scope(&assertion, view) {
                continue;
            }
            if !Self::valid_time_applies(assertion.valid_time, view.at) {
                continue;
            }
            let is_current = match assertion.lifecycle {
                mneme_core::Lifecycle::Accepted => {
                    self.lifecycle_decision_valid(&assertion).unwrap_or(false)
                        && self.assertion_has_basis(&assertion, &mut ancestry)
                }
                mneme_core::Lifecycle::Disputed if view.include_disputed => {
                    self.lifecycle_decision_valid(&assertion).unwrap_or(false)
                }
                mneme_core::Lifecycle::Proposed
                | mneme_core::Lifecycle::Disputed
                | mneme_core::Lifecycle::Superseded
                | mneme_core::Lifecycle::Retracted => false,
            };
            if is_current {
                beliefs.push(assertion);
            }
        }
        if ancestry.exhausted {
            return Err(crate::failure::EvidenceError::Truncated);
        }
        beliefs.sort_by_key(|assertion| (assertion.subject, assertion.predicate.clone()));
        Ok(beliefs)
    }

    /// Current beliefs evaluated in an explicit `certain` or `shadow` layer.
    ///
    /// - `Certain`: strictly `Accepted` (and optionally `Disputed`) beliefs.
    /// - `Shadow`: `Certain` beliefs plus valid, unsuppressed `Proposed`
    ///   assertions tagged as `QueryLayer::Shadow` (never promoted to `Certain`).
    pub fn current_beliefs_in_layer(
        &self,
        view: &BeliefView,
        layer: traits::QueryLayer,
    ) -> crate::failure::Result<Vec<(crate::model::AssertionView, traits::QueryLayer)>> {
        let certain = self.current_beliefs(view)?;
        let mut results: Vec<(crate::model::AssertionView, traits::QueryLayer)> = certain
            .into_iter()
            .map(|assertion| (assertion, traits::QueryLayer::Certain))
            .collect();
        if matches!(layer, traits::QueryLayer::Certain) {
            return Ok(results);
        }
        let mut seen: std::collections::BTreeSet<mneme_core::RecordId> = results
            .iter()
            .map(|(assertion, _)| assertion.record.record_id)
            .collect();
        for assertion in self.assertions()? {
            if !self.in_scope(&assertion, view) {
                continue;
            }
            if !Self::valid_time_applies(assertion.valid_time, view.at) {
                continue;
            }
            if !matches!(assertion.lifecycle, mneme_core::Lifecycle::Proposed) {
                continue;
            }
            if is_suppressed_record(self, &assertion.record) {
                continue;
            }
            if seen.insert(assertion.record.record_id) {
                results.push((assertion, traits::QueryLayer::Shadow));
            }
        }
        results.sort_by_key(|(assertion, _)| (assertion.subject, assertion.predicate.clone()));
        Ok(results)
    }

    /// Active predicate traits declared in `scope` under `layer`.
    pub fn predicate_traits(
        &self,
        scope: &mneme_core::ScopeId,
        layer: traits::QueryLayer,
    ) -> crate::failure::Result<
        std::collections::BTreeMap<String, std::collections::BTreeSet<traits::PredicateTrait>>,
    > {
        traits::declared_in_view(self, scope, layer)
    }

    /// Functional-predicate overlap violations in `scope` under `layer`,
    /// with grounded ASPIC+ verdicts wired via `mneme_kernel::argumentation`.
    pub fn functional_violations(
        &self,
        scope: &mneme_core::ScopeId,
        layer: traits::QueryLayer,
    ) -> crate::failure::Result<Vec<traits::FunctionalViolation>> {
        traits::functional_violations_in_view(self, scope, layer)
    }

    /// Projected half-open `[start, end)` intervals for `Inertial` fluents in
    /// `scope` under `layer`, enforcing strict `#71` non-promotion.
    pub fn inertial_fluents(
        &self,
        scope: &mneme_core::ScopeId,
        layer: traits::QueryLayer,
    ) -> crate::failure::Result<Vec<calculus::InertialFluent>> {
        calculus::inertial_in_view(self, scope, layer)
    }

    /// Classify one `(subject, predicate)` slot at instant `query.at` under
    /// `query.layer` as `Active`, `Dead { reason, since_rev }`, or `Absent`.
    pub fn slot_status(
        &self,
        query: &traits::SlotQuery,
    ) -> crate::failure::Result<traits::SlotStatus> {
        traits::slot_status_in_view(self, query)
    }

    /// Compare explicit `(subject, predicate)` slots across two committed views
    /// at `request.at` and `request.layer`.
    pub fn slot_diff(
        rev_a: &View,
        rev_b: &View,
        request: &SlotDiffRequest,
    ) -> crate::failure::Result<Vec<traits::SlotDiffEntry>> {
        let mut entries = Vec::with_capacity(request.slots.len());
        for (subject, predicate) in &request.slots {
            let query = traits::SlotQuery {
                scope: request.scope.clone(),
                subject: *subject,
                predicate: predicate.clone(),
                at: request.at,
                layer: request.layer,
            };
            let before = rev_a.slot_status(&query)?;
            let after = rev_b.slot_status(&query)?;
            entries.push(traits::SlotDiffEntry {
                subject: *subject,
                predicate: predicate.clone(),
                before,
                after,
            });
        }
        Ok(entries)
    }

    fn conflict_candidates(
        &self,
        view: &BeliefView,
    ) -> crate::failure::Result<Vec<crate::model::AssertionView>> {
        let assertions = self.assertions()?;
        let mut candidates = Vec::with_capacity(assertions.len());
        for assertion in assertions {
            if !self.in_scope(&assertion, view) {
                continue;
            }
            if !Self::valid_time_applies(assertion.valid_time, view.at) {
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
        Ok(candidates)
    }

    /// Incompatible currently eligible claims that apply at the view instant,
    /// grouped by subject and predicate.
    ///
    /// Two claims can only conflict where both answer the requested instant, so
    /// the candidates are filtered by the same valid-time rule beliefs use
    /// before any pair is compared.
    pub fn conflicts(&self, view: &BeliefView) -> crate::failure::Result<Vec<ConflictGroup>> {
        let candidates = self.conflict_candidates(view)?;
        let verdicts = aspic::evaluate_assertions_at(self, &candidates, view.at);
        let mut groups: std::collections::BTreeMap<
            (mneme_core::RecordId, String),
            Vec<crate::model::AssertionView>,
        > = std::collections::BTreeMap::new();
        for (index, left) in candidates.iter().enumerate() {
            for right in candidates.iter().skip(index.saturating_add(1)) {
                if aspic::assertions_incompatible(left, right) {
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
        // Surface assertions undercut by retained `SupportRelation::Challenges`
        // evidence or defeated via derivation chains even without a rival claim.
        for candidate in &candidates {
            let is_defeated = verdicts.get(&candidate.record.record_id).is_some_and(|v| {
                !matches!(v.status, aspic::ArgumentationStatus::In) || !v.defeats.is_empty()
            });
            if is_defeated {
                let group = groups
                    .entry((candidate.subject, candidate.predicate.clone()))
                    .or_default();
                if !group
                    .iter()
                    .any(|assertion| assertion.record.record_id == candidate.record.record_id)
                {
                    group.push(candidate.clone());
                }
            }
        }
        let mut out = Vec::with_capacity(groups.len());
        for ((subject, predicate), assertions) in groups {
            let argumentation = aspic::summarize_conflict_group_verdict(&assertions, &verdicts);
            let opinion = aspic::compute_conflict_group_opinion(self, &assertions)?;
            out.push(ConflictGroup {
                subject,
                predicate,
                assertions,
                argumentation,
                opinion,
            });
        }
        Ok(out)
    }

    /// Evaluate the grounded ASPIC+ argumentation verdict for one assertion.
    pub fn argumentation_verdict(
        &self,
        assertion: mneme_core::RecordId,
    ) -> crate::failure::Result<aspic::ArgumentationVerdict> {
        let assertion = self.assertion(assertion)?;
        Ok(aspic::evaluate_assertion_verdict(self, &assertion))
    }

    /// Compute the read-only `RootIdentity`-partitioned Subjective Logic opinion
    /// for one assertion.
    pub fn opinion(
        &self,
        assertion: mneme_core::RecordId,
    ) -> crate::failure::Result<aspic::Opinion> {
        let assertion = self.assertion(assertion)?;
        aspic::compute_assertion_opinion(self, &assertion)
    }

    /// Compare two committed snapshots over a half-open `valid_window`,
    /// classifying each assertion change as [`BitemporalChangeKind::WorldEvolution`]
    /// or [`BitemporalChangeKind::RetroactiveCorrection`] along with 3-way
    /// `Active` / `Dead` / `Absent` slot statuses.
    pub fn bitemporal_diff(
        rev_a: &View,
        rev_b: &View,
        valid_window: mneme_kernel::temporal::Period,
    ) -> crate::failure::Result<BitemporalDiff> {
        Self::bitemporal_diff_in_layer(rev_a, rev_b, valid_window, traits::QueryLayer::Shadow)
    }

    /// Layer-aware bitemporal diff (`Certain` or `Shadow`) between two
    /// committed snapshots over a half-open `valid_window`, including 3-way
    /// `Active` / `Dead { reason, since_rev }` / `Absent` classification.
    pub fn bitemporal_diff_in_layer(
        rev_a: &View,
        rev_b: &View,
        valid_window: mneme_kernel::temporal::Period,
        layer: traits::QueryLayer,
    ) -> crate::failure::Result<BitemporalDiff> {
        if !mneme_kernel::temporal::is_valid(valid_window) {
            return Ok(BitemporalDiff {
                rev_a: rev_a.revision(),
                rev_b: rev_b.revision(),
                layer,
                valid_window,
                changes: Vec::new(),
                slots: Vec::new(),
            });
        }
        let before_map = active_window_assertions_in_layer(rev_a, valid_window, layer)?;
        let after_map = active_window_assertions_in_layer(rev_b, valid_window, layer)?;
        let baseline_periods = build_prior_subject_periods(&before_map, &after_map, valid_window);
        let diff_views = DiffViews {
            rev_a,
            rev_b,
            layer,
        };
        let mut changes = collect_before_changes(&diff_views, &before_map, &after_map);
        changes.extend(collect_added_changes(
            &diff_views,
            &before_map,
            &after_map,
            &baseline_periods,
        ));
        changes.sort_by_key(|change| {
            (
                change.affected_period.start,
                change.affected_period.stop,
                change.assertion_id,
            )
        });
        let slots = summarize_slot_diff_entries(&changes);
        Ok(BitemporalDiff {
            rev_a: rev_a.revision(),
            rev_b: rev_b.revision(),
            layer,
            valid_window,
            changes,
            slots,
        })
    }

    /// Whether an assertion has a valid acceptance decision.
    pub fn accepted_decision(
        &self,
        assertion: &crate::model::AssertionView,
    ) -> crate::failure::Result<bool> {
        self.lifecycle_backed(assertion, mneme_core::Lifecycle::Accepted)
    }

    /// Whether an assertion's current lifecycle is backed by its decision record.
    pub fn lifecycle_decision_valid(
        &self,
        assertion: &crate::model::AssertionView,
    ) -> crate::failure::Result<bool> {
        self.lifecycle_backed(assertion, assertion.lifecycle)
    }

    fn lifecycle_backed(
        &self,
        assertion: &crate::model::AssertionView,
        lifecycle: mneme_core::Lifecycle,
    ) -> crate::failure::Result<bool> {
        let cited = self.cited_decision(assertion)?;
        Ok(mneme_kernel::claim::decision_backs(
            lifecycle.to_kernel(),
            &cited,
        ))
    }

    /// The decision facts a lifecycle check needs, as the kernel sees them.
    fn cited_decision(
        &self,
        assertion: &crate::model::AssertionView,
    ) -> crate::failure::Result<Option<mneme_kernel::claim::CitedDecision>> {
        let Some(decision_id) = assertion.decision else {
            return Ok(None);
        };
        let decision = self.decision(decision_id)?;
        let Some(kind) = kernel_decision_kind(&decision.decision_kind) else {
            // An unrecognized kind can never back a lifecycle.
            return Ok(Some(mneme_kernel::claim::CitedDecision {
                kind: mneme_kernel::claim::DecisionKind::Acceptance,
                outcome_matches: false,
                targets_assertion: false,
                binds_replaced_revision: false,
            }));
        };
        let expected = expected_outcome(assertion.lifecycle);
        Ok(Some(mneme_kernel::claim::CitedDecision {
            kind,
            outcome_matches: expected.is_some_and(|word| decision.outcome == word),
            targets_assertion: decision.target == assertion.record.record_id,
            binds_replaced_revision: self.decision_binds_replaced_revision(assertion, &decision),
        }))
    }

    /// Whether the decision's input revision is the revision this assertion
    /// revision replaced. A decision reused from an earlier commit binds an
    /// older revision and never backs later content.
    fn decision_binds_replaced_revision(
        &self,
        assertion: &crate::model::AssertionView,
        decision: &crate::model::DecisionView,
    ) -> bool {
        let mut current = assertion.clone();
        let mut steps = 0_u64;
        loop {
            if steps > MAX_ANCESTRY_NODES {
                return false;
            }
            steps = steps.saturating_add(1);
            if self.decision_input_replaces(&current, decision) {
                return true;
            }
            // A revision that only re-enacts its predecessor's lifecycle (for
            // example a retention rewrite that drops a forgotten citation)
            // keeps the decision that already backed that lifecycle.
            let Some(predecessor_revision) = current.record.predecessor else {
                return false;
            };
            let Some(predecessor) =
                self.assertion_revision(current.record.record_id, predecessor_revision)
            else {
                return false;
            };
            if predecessor.lifecycle != current.lifecycle
                || predecessor.decision != current.decision
                || !rewrites_only_evidence(&predecessor.record, &current.record)
            {
                return false;
            }
            current = predecessor;
        }
    }

    /// Whether the decision was committed against exactly the base revision
    /// this assertion revision replaced.
    fn decision_input_replaces(
        &self,
        assertion: &crate::model::AssertionView,
        decision: &crate::model::DecisionView,
    ) -> bool {
        let Some(input_sequence) = self
            .revision_sequences
            .get(&decision.input_revision)
            .copied()
        else {
            return false;
        };
        let recorded = assertion.record.recorded.revision_order();
        if recorded == 0 {
            // A record examined before the coordinator assigns its sequence is
            // committed in the next revision, replacing the pinned one.
            return decision.input_revision == self.snapshot.revision
                && input_sequence == self.snapshot.sequence;
        }
        recorded
            .checked_sub(1)
            .is_some_and(|expected| input_sequence == expected)
    }

    /// One retained assertion revision, from the pinned snapshot or history.
    fn assertion_revision(
        &self,
        record: mneme_core::RecordId,
        revision: mneme_core::RevisionId,
    ) -> Option<crate::model::AssertionView> {
        let envelope = self.history.get(&(record, revision)).or_else(|| {
            self.records
                .get(&record)
                .filter(|envelope| envelope.revision_id == revision)
        })?;
        crate::model::AssertionView::parse(envelope.clone()).ok()
    }

    /// Whether an assertion has an observed outcome episode in its evidence ancestry.
    pub fn has_observed_outcome(
        &self,
        assertion: &crate::model::AssertionView,
    ) -> crate::failure::Result<bool> {
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
    ///
    /// Roots are the exact source revisions reachable through declared
    /// ancestry; each record is visited once and the walk is bounded.
    pub fn evidence_roots(
        &self,
        evidence: mneme_core::RecordId,
    ) -> crate::failure::Result<std::collections::BTreeSet<SourceRevisionKey>> {
        let mut ancestry = Ancestry::new(self, MAX_ANCESTRY_NODES, true);
        let facts = ancestry.evaluate(evidence)?;
        if ancestry.exhausted {
            return Err(crate::failure::EvidenceError::Truncated);
        }
        Ok(facts.roots.into_values().collect())
    }

    /// Fan-out of one assertion's support, computed from the full support set.
    pub fn corroboration(
        &self,
        assertion: mneme_core::RecordId,
    ) -> crate::failure::Result<Corroboration> {
        let assertion = self.assertion(assertion)?;
        let (corroboration, _complete, over_budget) = self.corroboration_inner(&assertion)?;
        if over_budget {
            return Err(crate::failure::EvidenceError::Truncated);
        }
        Ok(corroboration)
    }

    fn corroboration_inner(
        &self,
        assertion: &crate::model::AssertionView,
    ) -> crate::failure::Result<(Corroboration, bool, bool)> {
        let base = assertion.record.scope.clone();
        let mut ancestry = Ancestry::new(self, MAX_ANCESTRY_NODES, true);
        let mut visible_supports = Vec::with_capacity(assertion.evidence.len());
        let mut content_roots: std::collections::BTreeSet<RootIdentity> =
            std::collections::BTreeSet::new();
        let mut supporting = 0usize;
        let mut is_complete = true;
        for evidence_id in &assertion.evidence {
            let Ok(evidence) = self.evidence(*evidence_id) else {
                is_complete = false;
                continue;
            };
            if evidence.assertion != assertion.record.record_id
                || evidence.relation != crate::model::SupportRelation::Supports
            {
                continue;
            }
            if !self.content_readable_in(&evidence.record.scope, &base) {
                is_complete = false;
                continue;
            }
            let facts = ancestry.evaluate(evidence.record.record_id)?;
            if !facts.complete || !facts.eligible {
                is_complete = false;
                continue;
            }
            let (visible, is_all_readable) = self.visible_roots(&facts.roots, &base);
            if !is_all_readable {
                is_complete = false;
            }
            supporting = supporting.saturating_add(1);
            for (identity, key) in &visible {
                if self.is_content_root(identity, *key) {
                    content_roots.insert(identity.clone());
                }
            }
            visible_supports.push(visible);
        }
        let roots: std::collections::BTreeMap<RootIdentity, SourceRevisionKey> =
            visible_supports.into_iter().flatten().collect();
        let is_complete = is_complete && !ancestry.exhausted;
        let independent_supports = content_roots.len();
        let opinion = aspic::compute_assertion_opinion(self, assertion)?;
        Ok((
            Corroboration {
                shared_ancestry: is_complete && supporting > 1 && independent_supports == 1,
                roots: roots.into_values().collect(),
                independent_supports,
                opinion,
            },
            is_complete,
            ancestry.exhausted,
        ))
    }

    /// Keep only the ancestry roots a caller working in `base` may inspect.
    /// The second value is false when a root had to be withheld.
    pub(crate) fn visible_roots(
        &self,
        roots: &std::collections::BTreeMap<RootIdentity, SourceRevisionKey>,
        base: &mneme_core::ScopeId,
    ) -> (
        std::collections::BTreeMap<RootIdentity, SourceRevisionKey>,
        bool,
    ) {
        let mut is_all_readable = true;
        let visible: std::collections::BTreeMap<RootIdentity, SourceRevisionKey> = roots
            .iter()
            .filter(|(_, key)| {
                let is_readable = self
                    .root_scope(**key)
                    .is_some_and(|scope| self.content_readable_in(&scope, base));
                if !is_readable {
                    is_all_readable = false;
                }
                is_readable
            })
            .map(|(identity, key)| (identity.clone(), *key))
            .collect();
        (visible, is_all_readable)
    }

    /// The scope of the record that owns a root source revision.
    fn root_scope(&self, key: SourceRevisionKey) -> Option<mneme_core::ScopeId> {
        if let Some(record) = self.records.get(&key.0) {
            return Some(record.scope.clone());
        }
        self.history.get(&key).map(|record| record.scope.clone())
    }

    /// Whether a corroboration root is exact source content rather than the
    /// provenance record that introduced it.
    pub(crate) fn is_content_root(&self, identity: &RootIdentity, key: SourceRevisionKey) -> bool {
        if matches!(identity, RootIdentity::Digest(_)) {
            return true;
        }
        let kind = self
            .records
            .get(&key.0)
            .map(|record| record.kind)
            .or_else(|| self.history.get(&key).map(|record| record.kind));
        kind == Some(mneme_core::RecordKind::SourceRevision)
    }

    pub(crate) fn derivation_revision_matches(
        &self,
        derivation: &crate::model::DerivationView,
    ) -> bool {
        let Some(evaluated) = self.revision_sequences.get(&derivation.evaluation_revision) else {
            return false;
        };
        *evaluated <= self.snapshot.sequence
    }

    /// Whether one assertion currently has a complete grounded justification.
    pub fn assertion_eligible(&self, assertion: mneme_core::RecordId) -> bool {
        let mut ancestry = Ancestry::new(self, MAX_ANCESTRY_NODES, false);
        match ancestry.evaluate(assertion) {
            Ok(facts) if !ancestry.exhausted => facts.complete && facts.eligible,
            _ => false,
        }
    }

    /// Whether an accepted assertion has a surviving proof or an explicit
    /// complete absence basis.
    pub fn assertion_has_current_basis(&self, assertion: &crate::model::AssertionView) -> bool {
        let mut ancestry = Ancestry::new(self, MAX_ANCESTRY_NODES, false);
        self.assertion_has_basis(assertion, &mut ancestry)
    }

    fn assertion_has_basis(
        &self,
        assertion: &crate::model::AssertionView,
        ancestry: &mut Ancestry<'_>,
    ) -> bool {
        if let Ok(facts) = ancestry.evaluate(assertion.record.record_id)
            && !ancestry.exhausted
            && facts.complete
            && facts.eligible
        {
            return true;
        }
        self.declared_absence(assertion)
    }

    /// A bare completeness symbol may only establish the absence of a denied
    /// claim; it never turns an unsupported affirmative claim into a belief.
    fn declared_absence(&self, assertion: &crate::model::AssertionView) -> bool {
        assertion.lifecycle == mneme_core::Lifecycle::Accepted
            && self.lifecycle_decision_valid(assertion).unwrap_or(false)
            && assertion.stance == crate::model::Stance::Deny
            && assertion.evidence.is_empty()
            && !self
                .suppression_for(&assertion.record)
                .is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                })
            && assertion
                .record
                .payload
                .get("completeness")
                .and_then(mneme_core::Value::as_symbol)
                .is_some_and(|symbol| symbol.as_str() == "declared-complete")
    }

    /// Alternative derivations for one conclusion with eligibility reasons.
    pub fn derivation_alternatives(
        &self,
        conclusion: mneme_core::RecordId,
    ) -> crate::failure::Result<Vec<DerivationAlternative>> {
        let assertion = self.assertion(conclusion)?;
        let base = assertion.record.scope.clone();
        let mut ancestry = Ancestry::new(self, MAX_ANCESTRY_NODES, false);
        let derivation_ids = ancestry.derivations_for_conclusion(conclusion);
        let mut alternatives = Vec::with_capacity(derivation_ids.len());
        for derivation_id in derivation_ids {
            let Ok(derivation) = self.derivation(derivation_id) else {
                continue;
            };
            if !self.content_readable_in(&derivation.record.scope, &base) {
                continue;
            }
            ancestry.evaluate(derivation_id)?;
            alternatives.push(self.derivation_alternative(&derivation, &base, &ancestry));
        }
        if ancestry.exhausted {
            return Err(crate::failure::EvidenceError::Truncated);
        }
        Ok(alternatives)
    }

    /// One derivation alternative with the reasons it does not support its
    /// conclusion for this caller.
    fn derivation_alternative(
        &self,
        derivation: &crate::model::DerivationView,
        base: &mneme_core::ScopeId,
        ancestry: &Ancestry<'_>,
    ) -> DerivationAlternative {
        // The loop pushes at most one reason for each premise.
        let mut reasons = Vec::with_capacity(derivation.premises.len());
        let mut is_premises_ok = true;
        if derivation.completeness != "complete" {
            reasons.push(format!(
                "the derivation completeness is {}",
                derivation.completeness
            ));
        }
        if !self.derivation_revision_matches(derivation) {
            reasons.push(
                "derivation evaluation revision is not the pinned revision or its parent"
                    .to_owned(),
            );
        }
        if derivation.premises.is_empty() {
            reasons.push("the derivation has no premises".to_owned());
        }
        for (position, premise) in derivation.premises.iter().enumerate() {
            let ordinal = position.saturating_add(1);
            let Some(envelope) = self.records.get(premise) else {
                reasons.push(format!("premise {ordinal} is missing"));
                is_premises_ok = false;
                continue;
            };
            if !self.content_readable_in(&envelope.scope, base) {
                reasons.push(format!("premise {ordinal} is outside the readable scopes"));
                is_premises_ok = false;
                continue;
            }
            if !matches!(
                envelope.kind,
                mneme_core::RecordKind::Assertion
                    | mneme_core::RecordKind::Derivation
                    | mneme_core::RecordKind::Episode
            ) {
                reasons.push(format!(
                    "premise {ordinal} is not a claim, episode or derivation"
                ));
                is_premises_ok = false;
                continue;
            }
            match ancestry.facts(premise) {
                Some(facts) if facts.complete && facts.eligible => {}
                Some(facts) if !facts.complete => {
                    reasons.push(format!("premise {ordinal} is unresolved"));
                    is_premises_ok = false;
                }
                _ => {
                    reasons.push(format!("premise {ordinal} is not currently eligible"));
                    is_premises_ok = false;
                }
            }
        }
        let is_eligible = ancestry
            .facts(&derivation.record.record_id)
            .is_some_and(|facts| facts.complete && facts.eligible)
            && is_premises_ok;
        DerivationAlternative {
            derivation: derivation.record.record_id,
            rule_id: derivation.rule_id.clone(),
            rule_version: derivation.rule_version,
            eligible: is_eligible,
            reasons,
        }
    }

    /// Build a bounded explanation for one current assertion.
    pub fn explain(
        &self,
        assertion: mneme_core::RecordId,
        policy: Policy,
    ) -> crate::failure::Result<Explanation> {
        let assertion = self.assertion(assertion)?;
        let base = assertion.record.scope.clone();
        let decisions_for_assertion = self.decisions_for(assertion.record.record_id)?;
        let mut decisions = Vec::with_capacity(decisions_for_assertion.len());
        let mut inaccessible_decisions = 0usize;
        for decision in decisions_for_assertion {
            if self.content_readable_in(&decision.record.scope, &base) {
                decisions.push(decision);
            } else {
                inaccessible_decisions = inaccessible_decisions.saturating_add(1);
            }
        }
        // `usize` is at most 64 bits on every supported target, so widening the
        // node budget to the counter type is exact.
        let limit = (policy.max_explanation_nodes as u64).max(1);
        let mut ancestry = Ancestry::new(self, limit, true);
        ancestry.charge(1);
        let mut is_truncated = ancestry.exhausted;
        let evidence = if is_truncated {
            Vec::new()
        } else {
            self.explain_evidence(&assertion, policy, &mut ancestry)?
        };
        if ancestry.exhausted {
            is_truncated = true;
        }
        let derivations = if is_truncated {
            Vec::new()
        } else {
            self.explain_derivations(&assertion, &base, &mut ancestry)?
        };
        if ancestry.exhausted {
            is_truncated = true;
        }
        let (minimal_supports, is_antichain_truncated) = antichain::compute_minimal_supports(
            self,
            &assertion,
            limit,
            antichain::MAX_ANTICHAIN_SETS,
        );
        // Corroboration comes from the full support set, as the corroboration
        // query does, so a truncated evidence list never fabricates it.
        let (corroboration, corroboration_complete, over_budget) =
            self.corroboration_inner(&assertion)?;
        let argumentation = aspic::evaluate_assertion_verdict(self, &assertion);
        let opinion = corroboration.opinion;
        let is_arg_truncated = argumentation.is_truncated;
        Ok(Explanation {
            assertion,
            workspace_revision: self.snapshot.revision,
            decisions,
            evidence,
            derivations,
            minimal_supports,
            corroboration,
            argumentation,
            opinion,
            truncated: is_truncated
                || ancestry.incomplete
                || ancestry.exhausted
                || !corroboration_complete
                || over_budget
                || is_arg_truncated
                || is_antichain_truncated,
            visited_nodes: ancestry.used,
            inaccessible_decisions,
        })
    }

    fn explain_evidence(
        &self,
        assertion: &crate::model::AssertionView,
        policy: Policy,
        ancestry: &mut Ancestry<'_>,
    ) -> crate::failure::Result<Vec<EvidenceExplanation>> {
        let base = assertion.record.scope.clone();
        // Widening the excerpt budget to the counter type is exact.
        let max_excerpt = policy.max_excerpt_bytes as u64;
        let mut items = Vec::with_capacity(assertion.evidence.len());
        for evidence_id in &assertion.evidence {
            if ancestry.exhausted {
                break;
            }
            let evidence = self.evidence(*evidence_id)?;
            let source_envelope = self.envelope(evidence.source)?;
            let is_readable = self.content_readable_in(&evidence.record.scope, &base)
                && self.content_readable_in(&source_envelope.scope, &base);
            if !is_readable {
                if !ancestry.charge(1) {
                    break;
                }
                items.push(inaccessible_evidence_explanation());
                continue;
            }
            let facts = ancestry.evaluate(evidence.record.record_id)?;
            if ancestry.exhausted {
                break;
            }
            let source = self.evidence_source(&evidence)?;
            let (availability, excerpt) = match evidence.span {
                Some(span) => {
                    let (availability, excerpt, _) =
                        self.source_span_excerpt_for(&source, span, max_excerpt)?;
                    (availability, excerpt)
                }
                None => (self.source_status_for(&source)?.availability(), None),
            };
            let (visible, all_readable) = self.visible_roots(&facts.roots, &base);
            let is_withdrawn = self
                .suppression_for(&evidence.record)
                .is_some_and(|suppression| {
                    suppression.mode == mneme_store::SuppressionMode::Withdrawn
                });
            items.push(EvidenceExplanation {
                evidence: evidence.record.record_id,
                source: evidence.source,
                source_revision: source.record.revision_id,
                availability,
                span_start: evidence.span.map(|span| span.start()),
                span_end: evidence.span.map(|span| span.end()),
                excerpt,
                ancestry_roots: visible.into_values().collect(),
                withdrawn: is_withdrawn,
                eligible: facts.complete && facts.eligible && all_readable,
                inaccessible: false,
            });
        }
        Ok(items)
    }

    fn explain_derivations(
        &self,
        assertion: &crate::model::AssertionView,
        base: &mneme_core::ScopeId,
        ancestry: &mut Ancestry<'_>,
    ) -> crate::failure::Result<Vec<DerivationAlternative>> {
        let derivation_ids = ancestry.derivations_for_conclusion(assertion.record.record_id);
        let mut alternatives = Vec::with_capacity(derivation_ids.len());
        for derivation_id in derivation_ids {
            if ancestry.exhausted {
                break;
            }
            let Ok(derivation) = self.derivation(derivation_id) else {
                continue;
            };
            if !self.content_readable_in(&derivation.record.scope, base) {
                continue;
            }
            if !ancestry.charge(1) {
                break;
            }
            ancestry.evaluate(derivation_id)?;
            alternatives.push(self.derivation_alternative(&derivation, base, ancestry));
        }
        Ok(alternatives)
    }
}

/// Whether two assertion revisions differ only in their cited evidence.
///
/// Retention rewrites an assertion this way when it drops a forgotten
/// citation; such a revision keeps the decision that already backed its
/// lifecycle. No other content may change without a fresh decision.
fn rewrites_only_evidence(
    predecessor: &mneme_core::RecordEnvelope,
    current: &mneme_core::RecordEnvelope,
) -> bool {
    let mut before = predecessor.payload.clone();
    let mut after = current.payload.clone();
    before.remove("evidence");
    after.remove("evidence");
    before == after
}

/// The kernel decision kind of a recorded decision, or `None` when the kind is
/// not one the lifecycle rules understand.
fn kernel_decision_kind(
    kind: &crate::model::DecisionKind,
) -> Option<mneme_kernel::claim::DecisionKind> {
    match kind {
        crate::model::DecisionKind::Acceptance => {
            Some(mneme_kernel::claim::DecisionKind::Acceptance)
        }
        crate::model::DecisionKind::ConflictResolution => {
            Some(mneme_kernel::claim::DecisionKind::ConflictResolution)
        }
        crate::model::DecisionKind::Retraction => {
            Some(mneme_kernel::claim::DecisionKind::Retraction)
        }
        crate::model::DecisionKind::Supersession => {
            Some(mneme_kernel::claim::DecisionKind::Supersession)
        }
        crate::model::DecisionKind::Other(_) => None,
    }
}

/// The outcome word a decision must state to back this lifecycle.
const fn expected_outcome(lifecycle: mneme_core::Lifecycle) -> Option<&'static str> {
    match lifecycle {
        mneme_core::Lifecycle::Proposed => None,
        mneme_core::Lifecycle::Accepted => Some("accepted"),
        mneme_core::Lifecycle::Disputed => Some("disputed"),
        mneme_core::Lifecycle::Superseded => Some("superseded"),
        mneme_core::Lifecycle::Retracted => Some("retracted"),
    }
}

fn require_retained_availability(
    availability: &crate::model::SourceAvailability,
    requirement: RetainedRequirement,
) -> crate::failure::Result<()> {
    if requirement == RetainedRequirement::Required
        && *availability != crate::model::SourceAvailability::Retained
    {
        return Err(crate::failure::EvidenceError::policy(format!(
            "evidence source is {} and cannot be newly cited",
            availability.name()
        )));
    }
    Ok(())
}

fn check_span_within_retained(
    span: mneme_core::SourceSpan,
    text_bytes: u64,
) -> crate::failure::Result<()> {
    let stop = span
        .end()
        .checked_add(1)
        .ok_or_else(|| crate::failure::EvidenceError::policy("span end exceeds u64"))?;
    if !mneme_kernel::extent::span_in_text(span.start(), stop, text_bytes) {
        return Err(crate::failure::EvidenceError::policy(format!(
            "evidence span ends at byte {}, beyond the retained bytes",
            span.end()
        )));
    }
    Ok(())
}

/// Map non-retained `SourceAvailability` into the explanation availability label.
fn unavailable_source_label(
    availability: &crate::model::SourceAvailability,
) -> crate::model::SourceAvailability {
    match availability {
        crate::model::SourceAvailability::Inaccessible => {
            crate::model::SourceAvailability::Unavailable {
                reason: "source is marked inaccessible".to_owned(),
            }
        }
        other => other.clone(),
    }
}

struct ExcerptWindowSlice {
    read_start_bytes: u64,
    window: mneme_kernel::extent::Window,
    text_bytes: u64,
    span: mneme_core::SourceSpan,
}

/// Slice a pre-verified `[read_start..)` range returned by `verify_span_range`
/// at UTF-8 character boundaries matching the cited window.
fn excerpt_from_window_slice(slice: &[u8], spec: &ExcerptWindowSlice) -> Option<SourceExcerpt> {
    let lead = usize::try_from(spec.window.start.checked_sub(spec.read_start_bytes)?).ok()?;
    let stop_idx = usize::try_from(spec.window.stop.checked_sub(spec.read_start_bytes)?).ok()?;
    let start = mneme_kernel::extent::floor_boundary(slice, lead);
    let stop = if spec.window.stop >= spec.text_bytes {
        stop_idx.min(slice.len())
    } else {
        mneme_kernel::extent::floor_boundary(slice, stop_idx)
    };
    if start > stop {
        return None;
    }
    let covered = u64::try_from(stop.saturating_sub(start)).ok()?;
    let cited = spec.span.length()?;
    Some(SourceExcerpt {
        bytes: slice.get(start..stop)?.to_vec(),
        truncated: spec.window.truncated || covered < cited,
    })
}

/// An evidence item whose record or source is outside the readable scopes.
/// Every identity is withheld so the report discloses nothing about it.
fn inaccessible_evidence_explanation() -> EvidenceExplanation {
    let withheld_bytes = [0_u8; 16];
    EvidenceExplanation {
        evidence: mneme_core::RecordId::from_bytes(withheld_bytes),
        source: mneme_core::RecordId::from_bytes(withheld_bytes),
        source_revision: mneme_core::RevisionId::from_bytes(withheld_bytes),
        availability: SourceStatus::Inaccessible(
            "evidence source is outside the readable scopes".to_owned(),
        )
        .availability(),
        span_start: None,
        span_end: None,
        excerpt: None,
        ancestry_roots: std::collections::BTreeSet::new(),
        withdrawn: false,
        eligible: false,
        inaccessible: true,
    }
}

/// Identity a corroboration root is counted by: the exact content when known,
/// so the same bytes imported under two records are one root.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RootIdentity {
    Digest(mneme_core::ContentDigest),
    Revision(SourceRevisionKey),
}

/// What one graph node contributes to support and ancestry.
#[derive(Clone, Default)]
pub(crate) struct NodeFacts {
    /// Every child of the node was resolved.
    pub(crate) complete: bool,
    /// The node may ground or back a claim.
    pub(crate) eligible: bool,
    pub(crate) roots: std::collections::BTreeMap<RootIdentity, SourceRevisionKey>,
}

/// One node's parsed shape, decided once per query.
enum NodePlan {
    Evidence {
        view: Box<crate::model::EvidenceView>,
        source: SourceRevisionKey,
        identity: RootIdentity,
        withdrawn: bool,
    },
    Assertion {
        view: Box<crate::model::AssertionView>,
        derivations: Vec<mneme_core::RecordId>,
    },
    Derivation {
        view: Box<crate::model::DerivationView>,
    },
    Leaf {
        source: SourceRevisionKey,
        identity: RootIdentity,
        withdrawn: bool,
    },
    /// The record cannot be interpreted; it grounds nothing but does not make
    /// its ancestors incomplete.
    Broken,
}

impl NodePlan {
    fn children(&self) -> Vec<mneme_core::RecordId> {
        match self {
            NodePlan::Evidence { view, .. } => view.ancestry.iter().copied().collect(),
            NodePlan::Assertion { view, derivations } => view
                .evidence
                .iter()
                .copied()
                .chain(derivations.iter().copied())
                .collect(),
            NodePlan::Derivation { view } => view.premises.iter().copied().collect(),
            NodePlan::Leaf { .. } | NodePlan::Broken => Vec::new(),
        }
    }
}

/// One bounded, memoized walk of the evidence graph.
///
/// Each record is planned once and finished once, so a shared sub-graph costs
/// one visit, not one visit per path. The work budget is charged with
/// [`mneme_kernel::budget::charge`]; an exhausted budget marks the result
/// incomplete instead of walking on.
pub(crate) struct Ancestry<'v> {
    view: &'v View,
    limit: u64,
    used: u64,
    pub(crate) exhausted: bool,
    /// A visited node could not resolve its full ancestry.
    incomplete: bool,
    /// Integrity errors abort the walk instead of marking the node unusable.
    strict: bool,
    facts: std::collections::BTreeMap<mneme_core::RecordId, NodeFacts>,
    active: std::collections::BTreeSet<mneme_core::RecordId>,
    plans: std::collections::BTreeMap<mneme_core::RecordId, NodePlan>,
    derivations:
        Option<std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordId>>>,
}

impl<'v> Ancestry<'v> {
    pub(crate) fn new(view: &'v View, limit: u64, strict: bool) -> Self {
        Ancestry {
            view,
            limit,
            used: 0,
            exhausted: false,
            incomplete: false,
            strict,
            facts: std::collections::BTreeMap::new(),
            active: std::collections::BTreeSet::new(),
            plans: std::collections::BTreeMap::new(),
            derivations: None,
        }
    }

    fn facts(&self, record: &mneme_core::RecordId) -> Option<&NodeFacts> {
        self.facts.get(record)
    }

    fn charge(&mut self, cost: u64) -> bool {
        match mneme_kernel::budget::charge(self.used, cost, self.limit) {
            Some(used) => {
                self.used = used;
                true
            }
            None => {
                self.exhausted = true;
                false
            }
        }
    }

    fn derivations_for_conclusion(
        &mut self,
        conclusion: mneme_core::RecordId,
    ) -> Vec<mneme_core::RecordId> {
        if self.derivations.is_none() {
            self.derivations = Some(Self::build_derivations(self.view));
        }
        self.derivations
            .as_ref()
            .and_then(|index| index.get(&conclusion))
            .cloned()
            .unwrap_or_default()
    }

    fn build_derivations(
        view: &View,
    ) -> std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordId>> {
        let mut index: std::collections::BTreeMap<mneme_core::RecordId, Vec<mneme_core::RecordId>> =
            std::collections::BTreeMap::new();
        for envelope in view.records.values() {
            if envelope.kind != mneme_core::RecordKind::Derivation {
                continue;
            }
            if let Ok(derivation) = crate::model::DerivationView::parse(envelope.clone()) {
                index
                    .entry(derivation.conclusion)
                    .or_default()
                    .push(derivation.record.record_id);
            }
        }
        index
    }

    /// Facts for one record, evaluating only the nodes not yet memoized.
    pub(crate) fn evaluate(
        &mut self,
        record: mneme_core::RecordId,
    ) -> crate::failure::Result<NodeFacts> {
        enum Step {
            Enter(mneme_core::RecordId),
            Finish(mneme_core::RecordId),
        }
        let mut stack = vec![Step::Enter(record)];
        while let Some(step) = stack.pop() {
            match step {
                Step::Enter(record) => {
                    if self.facts.contains_key(&record) {
                        continue;
                    }
                    if self.active.contains(&record) {
                        if self.strict {
                            return Err(crate::failure::EvidenceError::policy(
                                "evidence ancestry contains a cycle",
                            ));
                        }
                        // The back edge makes the ancestor unusable, which its
                        // dependents observe as an incomplete child.
                        continue;
                    }
                    if !self.charge(1) {
                        self.facts.insert(record, NodeFacts::default());
                        continue;
                    }
                    let Some(envelope) = self.view.records.get(&record) else {
                        self.facts.insert(record, broken_facts());
                        continue;
                    };
                    let plan = match self.plan(record, envelope) {
                        Ok(plan) => plan,
                        Err(error) if self.strict => return Err(error),
                        Err(_) => NodePlan::Broken,
                    };
                    let children = plan.children();
                    self.active.insert(record);
                    self.plans.insert(record, plan);
                    if children.is_empty() {
                        self.active.remove(&record);
                        let facts = self.finish_node(record);
                        if !facts.complete {
                            self.incomplete = true;
                        }
                        self.facts.insert(record, facts);
                    } else {
                        stack.push(Step::Finish(record));
                        for child in children.into_iter().rev() {
                            stack.push(Step::Enter(child));
                        }
                    }
                }
                Step::Finish(record) => {
                    let facts = self.finish_node(record);
                    if !facts.complete {
                        self.incomplete = true;
                    }
                    self.active.remove(&record);
                    self.facts.insert(record, facts);
                }
            }
        }
        Ok(self.facts.get(&record).cloned().unwrap_or_default())
    }

    fn plan(
        &mut self,
        record: mneme_core::RecordId,
        envelope: &mneme_core::RecordEnvelope,
    ) -> crate::failure::Result<NodePlan> {
        let is_withdrawn = self
            .view
            .suppression_for(envelope)
            .is_some_and(|suppression| suppression.mode == mneme_store::SuppressionMode::Withdrawn);
        match envelope.kind {
            mneme_core::RecordKind::Evidence => {
                let view = crate::model::EvidenceView::parse(envelope.clone())?;
                let source = self.view.evidence_source(&view)?;
                let (root, identity) =
                    source_root_of(self.view, view.source, source.record.revision_id)?;
                Ok(NodePlan::Evidence {
                    source: root,
                    view: Box::new(view),
                    identity,
                    withdrawn: is_withdrawn,
                })
            }
            mneme_core::RecordKind::Assertion => {
                let view = crate::model::AssertionView::parse(envelope.clone())?;
                let derivations = self.derivations_for_conclusion(record);
                Ok(NodePlan::Assertion {
                    view: Box::new(view),
                    derivations,
                })
            }
            mneme_core::RecordKind::Derivation => {
                let view = crate::model::DerivationView::parse(envelope.clone())?;
                Ok(NodePlan::Derivation {
                    view: Box::new(view),
                })
            }
            mneme_core::RecordKind::Episode => {
                let view = crate::model::EpisodeView::parse(envelope.clone())?;
                let source = self.episode_root(record, envelope, view.source)?;
                Ok(NodePlan::Leaf {
                    source: source.0,
                    identity: source.1,
                    withdrawn: is_withdrawn,
                })
            }
            _ => {
                let source = source_root_of(self.view, record, envelope.revision_id)?;
                Ok(NodePlan::Leaf {
                    source: source.0,
                    identity: source.1,
                    withdrawn: is_withdrawn,
                })
            }
        }
    }

    fn episode_root(
        &self,
        record: mneme_core::RecordId,
        envelope: &mneme_core::RecordEnvelope,
        source: Option<mneme_core::RecordId>,
    ) -> crate::failure::Result<(SourceRevisionKey, RootIdentity)> {
        match source {
            Some(source) => {
                let revision = self
                    .view
                    .records
                    .get(&source)
                    .map_or(envelope.revision_id, |record| record.revision_id);
                source_root_of(self.view, source, revision)
            }
            None => Ok({
                let key = (record, envelope.revision_id);
                let identity = RootIdentity::Revision(key);
                (key, identity)
            }),
        }
    }

    fn finish_node(&self, record: mneme_core::RecordId) -> NodeFacts {
        let Some(plan) = self.plans.get(&record) else {
            return NodeFacts::default();
        };
        match plan {
            NodePlan::Evidence {
                view,
                source,
                identity,
                withdrawn,
            } => {
                let mut facts = NodeFacts {
                    complete: true,
                    eligible: !*withdrawn,
                    roots: std::collections::BTreeMap::new(),
                };
                // A citation with no declared ancestry is an observation of
                // its own source. A citation that declares ancestry is derived
                // from those ancestors, so it must not also root at the source
                // it merely restates; otherwise three summaries of one origin
                // would look like independent observations.
                if view.ancestry.is_empty() {
                    facts.roots.insert(identity.clone(), *source);
                }
                for ancestor in &view.ancestry {
                    let child = self.facts.get(ancestor).cloned().unwrap_or_default();
                    if !child.complete {
                        facts.complete = false;
                        facts.eligible = false;
                    } else if child.eligible {
                        facts.roots.extend(child.roots);
                    } else {
                        facts.eligible = false;
                    }
                }
                if !view.ancestry.is_empty() && facts.roots.is_empty() {
                    // Declared ancestry that resolves to no root (withdrawn,
                    // missing, unreadable or out of budget) is neither an
                    // independent observation nor a fallback to its own
                    // source; report the limitation instead.
                    facts.complete = false;
                    facts.eligible = false;
                }
                facts
            }
            NodePlan::Assertion { view, derivations } => self.finish_assertion(view, derivations),
            NodePlan::Derivation { view } => self.finish_derivation(view),
            NodePlan::Leaf {
                source,
                identity,
                withdrawn,
            } => NodeFacts {
                complete: true,
                eligible: !*withdrawn,
                roots: std::collections::BTreeMap::from([(identity.clone(), *source)]),
            },
            NodePlan::Broken => broken_facts(),
        }
    }

    fn finish_assertion(
        &self,
        view: &crate::model::AssertionView,
        derivations: &[mneme_core::RecordId],
    ) -> NodeFacts {
        let mut facts = NodeFacts {
            complete: true,
            eligible: true,
            roots: std::collections::BTreeMap::new(),
        };
        if self
            .view
            .suppression_for(&view.record)
            .is_some_and(|suppression| suppression.mode == mneme_store::SuppressionMode::Withdrawn)
            || view.lifecycle != mneme_core::Lifecycle::Accepted
            || !self.view.accepted_decision(view).unwrap_or(false)
        {
            facts.eligible = false;
        }
        let mut is_grounded = false;
        for evidence_id in &view.evidence {
            let child = self.facts.get(evidence_id).cloned().unwrap_or_default();
            if !child.complete {
                facts.complete = false;
                continue;
            }
            if child.eligible {
                facts.roots.extend(child.roots);
                if self.view.evidence(*evidence_id).is_ok_and(|evidence| {
                    evidence.assertion == view.record.record_id
                        && evidence.relation == crate::model::SupportRelation::Supports
                }) {
                    is_grounded = true;
                }
            }
        }
        for derivation in derivations {
            let child = self.facts.get(derivation).cloned().unwrap_or_default();
            if !child.complete {
                facts.complete = false;
                continue;
            }
            if child.eligible {
                is_grounded = true;
            }
        }
        if !facts.complete || !is_grounded {
            facts.eligible = false;
        }
        facts
    }

    fn finish_derivation(&self, view: &crate::model::DerivationView) -> NodeFacts {
        let mut facts = NodeFacts {
            complete: true,
            eligible: true,
            roots: std::collections::BTreeMap::new(),
        };
        let is_withdrawn = self
            .view
            .suppression_for(&view.record)
            .is_some_and(|suppression| suppression.mode == mneme_store::SuppressionMode::Withdrawn);
        let is_incomplete = view.completeness != "complete" || view.premises.is_empty();
        if is_withdrawn || is_incomplete || !self.view.derivation_revision_matches(view) {
            facts.eligible = false;
        }
        for premise in &view.premises {
            let child = self.facts.get(premise).cloned().unwrap_or_default();
            if !child.complete {
                facts.complete = false;
                facts.eligible = false;
                continue;
            }
            let is_admissible = self.view.records.get(premise).is_some_and(|envelope| {
                matches!(
                    envelope.kind,
                    mneme_core::RecordKind::Assertion
                        | mneme_core::RecordKind::Derivation
                        | mneme_core::RecordKind::Episode
                )
            });
            if is_admissible && child.eligible {
                facts.roots.extend(child.roots);
            } else {
                facts.eligible = false;
            }
        }
        facts
    }
}

/// Facts for a node that exists but cannot be interpreted or was never
/// recorded: it grounds nothing.
fn broken_facts() -> NodeFacts {
    NodeFacts {
        complete: true,
        eligible: false,
        roots: std::collections::BTreeMap::new(),
    }
}

/// The corroboration identity of one source revision.
fn source_identity(source: &crate::model::SourceView) -> RootIdentity {
    source.digest().or(source.prior_digest).map_or(
        RootIdentity::Revision((source.record.record_id, source.record.revision_id)),
        RootIdentity::Digest,
    )
}

/// The root pair and identity of a record that is not itself a claim.
fn source_root_of(
    view: &View,
    record: mneme_core::RecordId,
    revision: mneme_core::RevisionId,
) -> crate::failure::Result<(SourceRevisionKey, RootIdentity)> {
    if let Some(envelope) = view.records.get(&record) {
        match envelope.kind {
            mneme_core::RecordKind::SourceRevision => {
                return root_source_pin(view, mneme_core::SourcePin::new(record, revision));
            }
            mneme_core::RecordKind::RecognitionRun => {
                let run = view.recognition_run(record)?;
                return root_source_pin(view, run.input);
            }
            mneme_core::RecordKind::RecognitionSegment => {
                let segment = view.recognition_segment(record)?;
                return root_source_pin(view, segment.media_source);
            }
            _ => {}
        }
    }
    let key = (record, revision);
    let identity = view
        .records
        .get(&record)
        .and_then(|envelope| crate::model::SourceView::parse(envelope.clone()).ok())
        .and_then(|source| source.digest().or(source.prior_digest))
        .map_or(RootIdentity::Revision(key), RootIdentity::Digest);
    Ok((key, identity))
}

fn root_source_pin(
    view: &View,
    pin: mneme_core::SourcePin,
) -> crate::failure::Result<(SourceRevisionKey, RootIdentity)> {
    let roots = view.source_roots(pin)?;
    let key = roots.iter().next().copied().ok_or_else(|| {
        crate::failure::EvidenceError::policy("source transformation ancestry has no evidence root")
    })?;
    let source = view.source_at(key.0, key.1)?;
    Ok((key, source_identity(&source)))
}

/// Explicit authored-premise predicate convention for derivations.
pub const EXPLICIT_AUTHORED_PREDICATE: &str = "explicit-authored-premise";

type WindowAssertions = std::collections::BTreeMap<
    mneme_core::RecordId,
    (crate::model::AssertionView, mneme_kernel::temporal::Period),
>;

type PriorSubjectPeriods =
    std::collections::BTreeMap<(mneme_core::RecordId, String), Vec<mneme_kernel::temporal::Period>>;

fn is_suppressed_record(view: &View, record: &mneme_core::RecordEnvelope) -> bool {
    view.suppression_for(record).is_some_and(|suppression| {
        matches!(
            suppression.mode,
            mneme_store::SuppressionMode::Withdrawn | mneme_store::SuppressionMode::Forgotten
        )
    })
}

struct DiffViews<'a> {
    rev_a: &'a View,
    rev_b: &'a View,
    layer: traits::QueryLayer,
}

fn active_window_assertions_in_layer(
    view: &View,
    valid_window: mneme_kernel::temporal::Period,
    layer: traits::QueryLayer,
) -> crate::failure::Result<WindowAssertions> {
    let is_shadow = matches!(layer, traits::QueryLayer::Shadow);
    let map = view
        .assertions()?
        .into_iter()
        .filter(|assertion| {
            let is_layer_visible =
                is_shadow || !matches!(assertion.lifecycle, mneme_core::Lifecycle::Proposed);
            is_layer_visible
                && view.access.allows(&assertion.record.scope)
                && !is_suppressed_record(view, &assertion.record)
        })
        .filter_map(|assertion| {
            let mneme_kernel::temporal::Validity::Known(period) =
                valid_time_to_kernel(assertion.valid_time)
            else {
                return None;
            };
            let clipped = mneme_kernel::temporal::intersect(period, valid_window)?;
            Some((assertion.record.record_id, (assertion, clipped)))
        })
        .collect();
    Ok(map)
}

fn collect_before_changes(
    views: &DiffViews<'_>,
    before_map: &WindowAssertions,
    after_map: &WindowAssertions,
) -> Vec<BitemporalChange> {
    before_map
        .iter()
        .filter_map(|(id, (before_assertion, before_period))| {
            let before_status =
                traits::classify_assertion_status(views.rev_a, before_assertion, views.layer);
            match after_map.get(id) {
                Some((after_assertion, after_period)) => {
                    let after_status = traits::classify_assertion_status(
                        views.rev_b,
                        after_assertion,
                        views.layer,
                    );
                    diff_existing_assertion(
                        *id,
                        DiffExistingInputs {
                            before: before_assertion,
                            before_period: *before_period,
                            before_status,
                            after: after_assertion,
                            after_period: *after_period,
                            after_status,
                        },
                    )
                }
                None => {
                    let after_status = views
                        .rev_b
                        .assertion(*id)
                        .map(|after_a| {
                            traits::classify_assertion_status(views.rev_b, &after_a, views.layer)
                        })
                        .unwrap_or(traits::SlotStatus::Absent);
                    Some(BitemporalChange {
                        assertion_id: *id,
                        subject: before_assertion.subject,
                        predicate: before_assertion.predicate.clone(),
                        kind: BitemporalChangeKind::RetroactiveCorrection,
                        before: Some(before_assertion.clone()),
                        after: None,
                        before_status,
                        after_status,
                        affected_period: *before_period,
                    })
                }
            }
        })
        .collect()
}

fn collect_added_changes(
    views: &DiffViews<'_>,
    before_map: &WindowAssertions,
    after_map: &WindowAssertions,
    baseline_periods: &PriorSubjectPeriods,
) -> Vec<BitemporalChange> {
    after_map
        .iter()
        .filter(|(id, _)| !before_map.contains_key(*id))
        .map(|(id, (after_assertion, after_period))| {
            let kind = classify_added_assertion(after_assertion, *after_period, baseline_periods);
            let before_status = views
                .rev_a
                .assertion(*id)
                .map(|before_a| {
                    traits::classify_assertion_status(views.rev_a, &before_a, views.layer)
                })
                .unwrap_or(traits::SlotStatus::Absent);
            let after_status =
                traits::classify_assertion_status(views.rev_b, after_assertion, views.layer);
            BitemporalChange {
                assertion_id: *id,
                subject: after_assertion.subject,
                predicate: after_assertion.predicate.clone(),
                kind,
                before: None,
                after: Some(after_assertion.clone()),
                before_status,
                after_status,
                affected_period: *after_period,
            }
        })
        .collect()
}

fn summarize_slot_diff_entries(changes: &[BitemporalChange]) -> Vec<traits::SlotDiffEntry> {
    let mut entries: std::collections::BTreeMap<
        (mneme_core::RecordId, String),
        traits::SlotDiffEntry,
    > = std::collections::BTreeMap::new();
    for change in changes {
        let key = (change.subject, change.predicate.clone());
        entries
            .entry(key)
            .and_modify(|existing| {
                if matches!(existing.before, traits::SlotStatus::Absent) {
                    existing.before = change.before_status.clone();
                }
                if !matches!(change.after_status, traits::SlotStatus::Absent) {
                    existing.after = change.after_status.clone();
                }
            })
            .or_insert_with(|| traits::SlotDiffEntry {
                subject: change.subject,
                predicate: change.predicate.clone(),
                before: change.before_status.clone(),
                after: change.after_status.clone(),
            });
    }
    entries.into_values().collect()
}

fn is_same_assertion_core(
    before: &crate::model::AssertionView,
    after: &crate::model::AssertionView,
) -> bool {
    let is_same_key = before.subject == after.subject && before.predicate == after.predicate;
    let is_same_claim = before.value == after.value && before.stance == after.stance;
    is_same_key && is_same_claim && before.lifecycle == after.lifecycle
}

fn is_clean_open_ended_expiry(
    before: &crate::model::AssertionView,
    after: &crate::model::AssertionView,
) -> bool {
    if !is_same_assertion_core(before, after) {
        return false;
    }
    matches!(
        (before.valid_time, after.valid_time),
        (
            mneme_core::ValidTime::Bounded {
                start: start_a,
                end: None,
            },
            mneme_core::ValidTime::Bounded {
                start: start_b,
                end: Some(_),
            },
        ) if start_a == start_b
    )
}

fn build_prior_subject_periods(
    before_map: &WindowAssertions,
    after_map: &WindowAssertions,
    valid_window: mneme_kernel::temporal::Period,
) -> PriorSubjectPeriods {
    let mut prior: PriorSubjectPeriods = std::collections::BTreeMap::new();
    for (id, (before_assertion, before_period)) in before_map {
        let effective_period = after_map
            .get(id)
            .filter(|(after_assertion, _)| {
                is_clean_open_ended_expiry(before_assertion, after_assertion)
            })
            .map_or(*before_period, |(_, after_period)| *after_period);
        if let Some(clipped) = mneme_kernel::temporal::intersect(effective_period, valid_window) {
            prior
                .entry((before_assertion.subject, before_assertion.predicate.clone()))
                .or_default()
                .push(clipped);
        }
    }
    prior
}

struct DiffExistingInputs<'a> {
    before: &'a crate::model::AssertionView,
    before_period: mneme_kernel::temporal::Period,
    before_status: traits::SlotStatus,
    after: &'a crate::model::AssertionView,
    after_period: mneme_kernel::temporal::Period,
    after_status: traits::SlotStatus,
}

fn diff_existing_assertion(
    assertion_id: mneme_core::RecordId,
    inputs: DiffExistingInputs<'_>,
) -> Option<BitemporalChange> {
    let is_same_status_kind = inputs.before_status.kind_name() == inputs.after_status.kind_name();
    let is_unchanged_claim = is_same_assertion_core(inputs.before, inputs.after)
        && inputs.before.valid_time == inputs.after.valid_time
        && is_same_status_kind;
    if is_unchanged_claim {
        return None;
    }
    let kind = if is_clean_open_ended_expiry(inputs.before, inputs.after) && is_same_status_kind {
        BitemporalChangeKind::WorldEvolution
    } else {
        BitemporalChangeKind::RetroactiveCorrection
    };
    let affected_period =
        mneme_kernel::temporal::coalesce_pair(inputs.before_period, inputs.after_period)
            .unwrap_or(inputs.after_period);
    Some(BitemporalChange {
        assertion_id,
        subject: inputs.after.subject,
        predicate: inputs.after.predicate.clone(),
        kind,
        before: Some(inputs.before.clone()),
        after: Some(inputs.after.clone()),
        before_status: inputs.before_status,
        after_status: inputs.after_status,
        affected_period,
    })
}

fn classify_added_assertion(
    after: &crate::model::AssertionView,
    after_period: mneme_kernel::temporal::Period,
    baseline_periods: &PriorSubjectPeriods,
) -> BitemporalChangeKind {
    let Some(prior_periods) = baseline_periods.get(&(after.subject, after.predicate.clone()))
    else {
        return BitemporalChangeKind::WorldEvolution;
    };
    let is_retroactive = prior_periods.iter().any(|prior| {
        mneme_kernel::temporal::intersect(after_period, *prior).is_some()
            || after_period.stop <= prior.start
    });
    if is_retroactive {
        BitemporalChangeKind::RetroactiveCorrection
    } else {
        BitemporalChangeKind::WorldEvolution
    }
}
