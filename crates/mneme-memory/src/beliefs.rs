//! Evidence policy: span validation, belief views, conflicts, support,
//! ancestry, and bounded explanations.
//!
//! Everything here is computed from one pinned store snapshot. No method mutates
//! canonical state or promotes a proposed assertion.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

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
    fn content_readable_in(&self, scope: &mneme_core::ScopeId, base: &mneme_core::ScopeId) -> bool {
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
        let status = self.source_status_for(&source)?;
        if requirement == RetainedRequirement::Required
            && !matches!(status, SourceStatus::Retained(_))
        {
            return Err(crate::failure::EvidenceError::policy(format!(
                "evidence source is {} and cannot be newly cited",
                status.availability().name()
            )));
        }
        let excerpt = Self::evidence_excerpt(evidence.span.as_ref(), &status)?;
        Ok(ValidatedEvidence {
            evidence,
            source,
            availability: status.availability(),
            excerpt,
        })
    }

    /// The excerpt a retained source yields for an evidence span, if any.
    fn evidence_excerpt(
        span: Option<&mneme_core::SourceSpan>,
        status: &SourceStatus,
    ) -> crate::failure::Result<Option<SourceExcerpt>> {
        let (Some(span), SourceStatus::Retained(bytes)) = (span, status) else {
            return Ok(None);
        };
        let text_len = u64::try_from(bytes.len())
            .map_err(|_| crate::failure::EvidenceError::policy("source length exceeds u64"))?;
        let stop = span
            .end()
            .checked_add(1)
            .ok_or_else(|| crate::failure::EvidenceError::policy("span end exceeds u64"))?;
        if !mneme_kernel::extent::span_in_text(span.start(), stop, text_len) {
            return Err(crate::failure::EvidenceError::policy(format!(
                "evidence span ends at byte {}, beyond the retained bytes",
                span.end()
            )));
        }
        Ok(excerpt_of(bytes, *span, text_len))
    }

    /// Whether a claim's valid time covers `at`.
    ///
    /// This is the one temporal rule of a belief view: an unknown valid time
    /// never answers a requested instant, and an open bound is unbounded on
    /// that side. Belief and conflict selection both use it, so the two views
    /// can never disagree about which claims apply at an instant.
    fn valid_time_applies(valid_time: mneme_core::ValidTime, at: mneme_core::Timestamp) -> bool {
        match valid_time {
            mneme_core::ValidTime::Unknown => false,
            mneme_core::ValidTime::Bounded { start, end } => {
                start.is_none_or(|start| start <= at) && end.is_none_or(|at_bound| at <= at_bound)
            }
        }
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

    /// Incompatible currently eligible claims that apply at the view instant,
    /// grouped by subject and predicate.
    ///
    /// Two claims can only conflict where both answer the requested instant, so
    /// the candidates are filtered by the same valid-time rule beliefs use
    /// before any pair is compared.
    pub fn conflicts(&self, view: &BeliefView) -> crate::failure::Result<Vec<ConflictGroup>> {
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
        let mut groups: std::collections::BTreeMap<
            (mneme_core::RecordId, String),
            Vec<crate::model::AssertionView>,
        > = std::collections::BTreeMap::new();
        for (index, left) in candidates.iter().enumerate() {
            for right in candidates.iter().skip(index + 1) {
                if left.subject != right.subject || left.predicate != right.predicate {
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
        Ok((
            Corroboration {
                shared_ancestry: is_complete && supporting > 1 && independent_supports == 1,
                roots: roots.into_values().collect(),
                independent_supports,
            },
            is_complete,
            ancestry.exhausted,
        ))
    }

    /// Keep only the ancestry roots a caller working in `base` may inspect.
    /// The second value is false when a root had to be withheld.
    fn visible_roots(
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
    fn is_content_root(&self, identity: &RootIdentity, key: SourceRevisionKey) -> bool {
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

    fn derivation_revision_matches(&self, derivation: &crate::model::DerivationView) -> bool {
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
        // Corroboration comes from the full support set, as the corroboration
        // query does, so a truncated evidence list never fabricates it.
        let (corroboration, corroboration_complete, over_budget) =
            self.corroboration_inner(&assertion)?;
        Ok(Explanation {
            assertion,
            workspace_revision: self.snapshot.revision,
            decisions,
            evidence,
            derivations,
            corroboration,
            truncated: is_truncated
                || ancestry.incomplete
                || ancestry.exhausted
                || !corroboration_complete
                || over_budget,
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
            let status = self.source_status_for(&source)?;
            let excerpt = match (&evidence.span, &status) {
                (Some(span), SourceStatus::Retained(bytes)) => {
                    excerpt_of(bytes, *span, max_excerpt)
                }
                _ => None,
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
                availability: status.availability(),
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

/// The exact span of `bytes` the caller asked for, cut to `max_bytes` and to
/// character boundaries so it is always sliceable text.
fn excerpt_of(bytes: &[u8], span: mneme_core::SourceSpan, max_bytes: u64) -> Option<SourceExcerpt> {
    let text_len = u64::try_from(bytes.len()).ok()?;
    let stop = span.end().checked_add(1)?;
    let window = mneme_kernel::extent::excerpt_window(&mneme_kernel::extent::ExcerptRequest {
        start: span.start(),
        stop,
        text_len,
        max_bytes,
    })?;
    let raw_start = usize::try_from(window.start).ok()?;
    let raw_stop = usize::try_from(window.stop).ok()?;
    let start = mneme_kernel::extent::floor_boundary(bytes, raw_start);
    let stop = mneme_kernel::extent::floor_boundary(bytes, raw_stop);
    if start > stop {
        return None;
    }
    let covered = u64::try_from(stop.saturating_sub(start)).ok()?;
    let cited = span.length()?;
    Some(SourceExcerpt {
        bytes: bytes[start..stop].to_vec(),
        truncated: window.truncated || covered < cited,
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
enum RootIdentity {
    Digest(mneme_core::ContentDigest),
    Revision(SourceRevisionKey),
}

/// What one graph node contributes to support and ancestry.
#[derive(Clone, Default)]
struct NodeFacts {
    /// Every child of the node was resolved.
    complete: bool,
    /// The node may ground or back a claim.
    eligible: bool,
    roots: std::collections::BTreeMap<RootIdentity, SourceRevisionKey>,
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
struct Ancestry<'v> {
    view: &'v View,
    limit: u64,
    used: u64,
    exhausted: bool,
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
    fn new(view: &'v View, limit: u64, strict: bool) -> Self {
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
    fn evaluate(&mut self, record: mneme_core::RecordId) -> crate::failure::Result<NodeFacts> {
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
                let identity = source_identity(&source);
                Ok(NodePlan::Evidence {
                    source: (view.source, source.record.revision_id),
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
                let source = self.episode_root(record, envelope, view.source);
                Ok(NodePlan::Leaf {
                    source: source.0,
                    identity: source.1,
                    withdrawn: is_withdrawn,
                })
            }
            _ => {
                let source = source_root_of(self.view, record, envelope.revision_id);
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
    ) -> (SourceRevisionKey, RootIdentity) {
        match source {
            Some(source) => {
                let revision = self
                    .view
                    .records
                    .get(&source)
                    .map_or(envelope.revision_id, |record| record.revision_id);
                let identity = self
                    .view
                    .records
                    .get(&source)
                    .and_then(|record| crate::model::SourceView::parse(record.clone()).ok())
                    .and_then(|view| view.digest().or(view.prior_digest))
                    .map_or(
                        RootIdentity::Revision((source, revision)),
                        RootIdentity::Digest,
                    );
                ((source, revision), identity)
            }
            None => (
                (record, envelope.revision_id),
                RootIdentity::Revision((record, envelope.revision_id)),
            ),
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
        if self
            .view
            .suppression_for(&view.record)
            .is_some_and(|suppression| suppression.mode == mneme_store::SuppressionMode::Withdrawn)
            || view.completeness != "complete"
            || !self.view.derivation_revision_matches(view)
            || view.premises.is_empty()
        {
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
) -> (SourceRevisionKey, RootIdentity) {
    let key = (record, revision);
    let identity = view
        .records
        .get(&record)
        .and_then(|envelope| crate::model::SourceView::parse(envelope.clone()).ok())
        .and_then(|source| source.digest().or(source.prior_digest))
        .map_or(RootIdentity::Revision(key), RootIdentity::Digest);
    (key, identity)
}

/// Explicit authored-premise predicate convention for derivations.
pub const EXPLICIT_AUTHORED_PREDICATE: &str = "explicit-authored-premise";
