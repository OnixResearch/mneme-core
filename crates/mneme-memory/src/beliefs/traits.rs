//! Predicate traits (`Functional`, `Inertial`), Event-Calculus fluent interval
//! clipping, `certain` vs `shadow` query layers, and 3-way `Active` / `Dead` /
//! `Absent` slot classification.
//!
//! Predicate traits are stored as ordinary versioned assertions under
//! [`PREDICATE_TRAIT_PREDICATE`] so they participate in revision history,
//! scoping, and sync with zero side-channel state.

/// Canonical schema predicate used to persist predicate traits as ordinary
/// versioned assertions.
pub const PREDICATE_TRAIT_PREDICATE: &str = "mneme:predicate_trait";

const TRAIT_RECORD_LABEL: &str = "predicate-trait";
const TRAIT_RECORD_ARITY: usize = 2;
const MAX_VIOLATION_RESULTS: usize = 100_000;

/// Declarative schema trait attached to a predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PredicateTrait {
    /// Single-valued predicate: distinct values overlapping in half-open
    /// `[start, end)` `ValidTime` automatically register ASPIC+ rebuttal edges.
    Functional,
    /// Event-Calculus persistent fluent: an event asserting `(s, p, o)` at
    /// `t_start` projects `[t_start, t_end)` until the earliest subsequent
    /// terminating or conflicting event at the same or strictly higher
    /// authority stratum.
    Inertial,
}

impl PredicateTrait {
    /// Stable lowercase wire label.
    pub const fn name(self) -> &'static str {
        if matches!(self, PredicateTrait::Functional) {
            "functional"
        } else {
            "inertial"
        }
    }

    /// Parse a wire label (`"functional"` or `"inertial"`).
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "functional" => Some(PredicateTrait::Functional),
            "inertial" => Some(PredicateTrait::Inertial),
            _ => None,
        }
    }
}

/// Epistemic evaluation layer selector (`certain` vs `shadow`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueryLayer {
    /// Evaluates strictly over `Accepted` (and `ConflictResolution`) revisions.
    Certain,
    /// Evaluates `Accepted` plus `Proposed` overlay without promoting `Proposed`
    /// claims into `Certain`.
    Shadow,
}

impl QueryLayer {
    /// Stable lowercase wire label.
    pub const fn name(self) -> &'static str {
        if matches!(self, QueryLayer::Certain) {
            "certain"
        } else {
            "shadow"
        }
    }

    /// Parse a wire label (`"certain"` or `"shadow"`).
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "certain" => Some(QueryLayer::Certain),
            "shadow" => Some(QueryLayer::Shadow),
            _ => None,
        }
    }
}

/// Why a previously asserted `(subject, predicate)` slot is no longer active.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DeadReason {
    /// Explicitly retracted or withdrawn by retention.
    Retracted,
    /// Explicitly superseded by a newer claim revision.
    Superseded,
    /// Defeated to `Out` in the Dung grounded ASPIC+ fixpoint.
    Defeated,
}

impl DeadReason {
    /// Stable lowercase wire label.
    pub const fn name(self) -> &'static str {
        if matches!(self, DeadReason::Retracted) {
            "retracted"
        } else if matches!(self, DeadReason::Superseded) {
            "superseded"
        } else {
            "defeated"
        }
    }
}

/// 3-way epistemic slot classification at a queried cut instant and layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlotStatus {
    /// Currently active in the requested layer.
    Active {
        assertion_id: mneme_core::RecordId,
        value: mneme_core::Value,
        layer: QueryLayer,
        verdict: crate::beliefs::aspic::ArgumentationVerdict,
    },
    /// Previously asserted in this scope up to the cut, now inactive for a
    /// known reason (never conflated with [`SlotStatus::Absent`]).
    Dead {
        assertion_id: mneme_core::RecordId,
        value: mneme_core::Value,
        reason: DeadReason,
        since_rev: mneme_core::RevisionId,
    },
    /// Never asserted in this scope up to the cut.
    Absent,
}

impl SlotStatus {
    /// Stable lowercase kind name (`"active"`, `"dead"`, `"absent"`).
    pub const fn kind_name(&self) -> &'static str {
        if matches!(self, SlotStatus::Active { .. }) {
            "active"
        } else if matches!(self, SlotStatus::Dead { .. }) {
            "dead"
        } else {
            "absent"
        }
    }
}

/// One `(subject, predicate)` slot comparison between two workspace views.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotDiffEntry {
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub before: SlotStatus,
    pub after: SlotStatus,
}

/// One functional-predicate conflict where two distinct values for
/// `(subject, predicate)` overlap in half-open `[start, end)` `ValidTime`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalViolation {
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub left: mneme_core::RecordId,
    pub right: mneme_core::RecordId,
    pub overlap: mneme_kernel::temporal::Period,
    pub left_verdict: crate::beliefs::aspic::ArgumentationVerdict,
    pub right_verdict: crate::beliefs::aspic::ArgumentationVerdict,
}

/// Encode `(predicate, trait)` into the canonical Preserves value stored under
/// [`PREDICATE_TRAIT_PREDICATE`].
pub fn predicate_trait_value(predicate: &str, kind: PredicateTrait) -> mneme_core::Value {
    mneme_core::Value::record_named(
        TRAIT_RECORD_LABEL,
        vec![
            mneme_core::Value::string(predicate.to_owned()),
            mneme_core::Value::symbol(kind.name()),
        ],
    )
}

/// Decode a canonical (or dictionary/string shorthand) predicate trait value.
pub fn parse_predicate_trait_value(value: &mneme_core::Value) -> Option<(String, PredicateTrait)> {
    if let Some(record) = value.as_record()
        && record.label() == &mneme_core::Value::symbol(TRAIT_RECORD_LABEL)
        && record.fields().len() == TRAIT_RECORD_ARITY
    {
        let predicate = record.fields().first()?.as_string()?.trim();
        let trait_sym = record.fields().get(1)?.as_symbol()?.as_str();
        let kind = PredicateTrait::parse(trait_sym)?;
        if !predicate.is_empty() {
            return Some((predicate.to_owned(), kind));
        }
    }
    if let Some(dict) = value.as_dictionary() {
        let pred_key = mneme_core::Value::symbol("predicate");
        let trait_key = mneme_core::Value::symbol("trait");
        let predicate = dict.get(&pred_key).and_then(mneme_core::Value::as_string)?;
        let kind_text = dict.get(&trait_key).and_then(|v| {
            v.as_symbol()
                .map(mneme_core::Symbol::as_str)
                .or_else(|| v.as_string())
        })?;
        let kind = PredicateTrait::parse(kind_text)?;
        if !predicate.trim().is_empty() {
            return Some((predicate.trim().to_owned(), kind));
        }
    }
    if let Some(text) = value.as_string()
        && let Some((prefix, pred)) = text.split_once(':')
    {
        let kind = PredicateTrait::parse(prefix)?;
        let trimmed = pred.trim();
        if !trimmed.is_empty() {
            return Some((trimmed.to_owned(), kind));
        }
    }
    None
}

pub(crate) fn is_assertion_in_layer(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
    layer: QueryLayer,
) -> bool {
    let is_suppressed = view.suppression_for(&assertion.record).is_some_and(|s| {
        matches!(
            s.mode,
            mneme_store::SuppressionMode::Withdrawn | mneme_store::SuppressionMode::Forgotten
        )
    });
    if is_suppressed {
        return false;
    }
    match assertion.lifecycle {
        mneme_core::Lifecycle::Accepted => view.accepted_decision(assertion).unwrap_or(false),
        mneme_core::Lifecycle::Disputed => {
            view.lifecycle_decision_valid(assertion).unwrap_or(false)
        }
        mneme_core::Lifecycle::Proposed => matches!(layer, QueryLayer::Shadow),
        mneme_core::Lifecycle::Retracted | mneme_core::Lifecycle::Superseded => false,
    }
}

pub(crate) fn declared_in_view(
    view: &crate::beliefs::View,
    scope: &mneme_core::ScopeId,
    layer: QueryLayer,
) -> crate::failure::Result<
    std::collections::BTreeMap<String, std::collections::BTreeSet<PredicateTrait>>,
> {
    let mut map: std::collections::BTreeMap<String, std::collections::BTreeSet<PredicateTrait>> =
        std::collections::BTreeMap::new();
    for assertion in view.assertions()? {
        if assertion.predicate != PREDICATE_TRAIT_PREDICATE {
            continue;
        }
        if !view.content_readable_in(&assertion.record.scope, scope) {
            continue;
        }
        if !matches!(assertion.stance, crate::model::Stance::Affirm) {
            continue;
        }
        if !is_assertion_in_layer(view, &assertion, layer) {
            continue;
        }
        if let Some((predicate, kind)) = parse_predicate_trait_value(&assertion.value) {
            map.entry(predicate).or_default().insert(kind);
        }
    }
    Ok(map)
}

fn is_defeated_by_undercut_or_undermine(
    verdict: &crate::beliefs::aspic::ArgumentationVerdict,
) -> bool {
    if !matches!(
        verdict.status,
        crate::beliefs::aspic::ArgumentationStatus::Out
    ) {
        return false;
    }
    verdict.defeats.iter().any(|reason| {
        matches!(
            reason.kind,
            crate::beliefs::aspic::DefeatKind::Undercut
                | crate::beliefs::aspic::DefeatKind::Undermine
        )
    })
}

pub(crate) fn functional_violations_in_view(
    view: &crate::beliefs::View,
    scope: &mneme_core::ScopeId,
    layer: QueryLayer,
) -> crate::failure::Result<Vec<FunctionalViolation>> {
    let declared = declared_in_view(view, scope, layer)?;
    let functional_preds: std::collections::BTreeSet<String> = declared
        .into_iter()
        .filter(|(_, kinds)| kinds.contains(&PredicateTrait::Functional))
        .map(|(pred, _)| pred)
        .collect();
    if functional_preds.is_empty() {
        return Ok(Vec::new());
    }

    let active: Vec<crate::model::AssertionView> = view
        .assertions()?
        .into_iter()
        .filter(|a| {
            functional_preds.contains(&a.predicate)
                && view.content_readable_in(&a.record.scope, scope)
                && is_assertion_in_layer(view, a, layer)
        })
        .collect();

    let mut violations = Vec::new();
    for (idx, left) in active.iter().enumerate() {
        let mneme_kernel::temporal::Validity::Known(left_period) =
            crate::beliefs::valid_time_to_kernel(left.valid_time)
        else {
            continue;
        };
        for right in active.iter().skip(idx.saturating_add(1)) {
            if violations.len() >= MAX_VIOLATION_RESULTS {
                break;
            }
            if left.subject != right.subject || left.predicate != right.predicate {
                continue;
            }
            let is_conflict = left.value != right.value
                || (matches!(left.stance, crate::model::Stance::Affirm)
                    && matches!(right.stance, crate::model::Stance::Deny))
                || (matches!(left.stance, crate::model::Stance::Deny)
                    && matches!(right.stance, crate::model::Stance::Affirm));
            if !is_conflict {
                continue;
            }
            let mneme_kernel::temporal::Validity::Known(right_period) =
                crate::beliefs::valid_time_to_kernel(right.valid_time)
            else {
                continue;
            };
            let Some(overlap) = mneme_kernel::temporal::intersect(left_period, right_period) else {
                continue;
            };
            let left_verdict = crate::beliefs::aspic::evaluate_assertion_verdict(view, left);
            let right_verdict = crate::beliefs::aspic::evaluate_assertion_verdict(view, right);
            if is_defeated_by_undercut_or_undermine(&left_verdict)
                || is_defeated_by_undercut_or_undermine(&right_verdict)
            {
                continue;
            }
            violations.push(FunctionalViolation {
                subject: left.subject,
                predicate: left.predicate.clone(),
                left: left.record.record_id,
                right: right.record.record_id,
                overlap,
                left_verdict,
                right_verdict,
            });
        }
    }
    Ok(violations)
}

const RANK_ABSENT: u8 = 0;
const RANK_DEAD: u8 = 1;
const RANK_REASON_RETRACTED: u8 = 1;
const RANK_REASON_SUPERSEDED: u8 = 2;
const RANK_REASON_DEFEATED: u8 = 3;
const RANK_VERDICT_OUT: u8 = 1;
const RANK_VERDICT_UNDEC: u8 = 2;
const RANK_VERDICT_IN: u8 = 3;
const RANK_LAYER_SHADOW: u8 = 3;
const RANK_LAYER_CERTAIN: u8 = 4;

const fn dead_reason_rank(reason: DeadReason) -> u8 {
    if matches!(reason, DeadReason::Defeated) {
        RANK_REASON_DEFEATED
    } else if matches!(reason, DeadReason::Superseded) {
        RANK_REASON_SUPERSEDED
    } else {
        RANK_REASON_RETRACTED
    }
}

fn dead_slot(assertion: &crate::model::AssertionView, reason: DeadReason) -> SlotStatus {
    SlotStatus::Dead {
        assertion_id: assertion.record.record_id,
        value: assertion.value.clone(),
        reason,
        since_rev: assertion.record.revision_id,
    }
}

fn classify_active_or_defeated(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
    resolved_layer: QueryLayer,
) -> SlotStatus {
    let verdict = crate::beliefs::aspic::evaluate_assertion_verdict(view, assertion);
    if matches!(
        verdict.status,
        crate::beliefs::aspic::ArgumentationStatus::Out
    ) {
        dead_slot(assertion, DeadReason::Defeated)
    } else {
        SlotStatus::Active {
            assertion_id: assertion.record.record_id,
            value: assertion.value.clone(),
            layer: resolved_layer,
            verdict,
        }
    }
}

/// Classify a single assertion into [`SlotStatus`] for a given `layer`.
pub(crate) fn classify_assertion_status(
    view: &crate::beliefs::View,
    assertion: &crate::model::AssertionView,
    layer: QueryLayer,
) -> SlotStatus {
    let is_withdrawn = view.is_withdrawn(assertion.record.record_id)
        || view.suppression_for(&assertion.record).is_some_and(|s| {
            matches!(
                s.mode,
                mneme_store::SuppressionMode::Withdrawn | mneme_store::SuppressionMode::Forgotten
            )
        });
    if is_withdrawn {
        return dead_slot(assertion, DeadReason::Retracted);
    }
    match assertion.lifecycle {
        mneme_core::Lifecycle::Retracted => dead_slot(assertion, DeadReason::Retracted),
        mneme_core::Lifecycle::Superseded => dead_slot(assertion, DeadReason::Superseded),
        mneme_core::Lifecycle::Proposed => {
            if matches!(layer, QueryLayer::Certain) {
                SlotStatus::Absent
            } else {
                classify_active_or_defeated(view, assertion, QueryLayer::Shadow)
            }
        }
        mneme_core::Lifecycle::Accepted | mneme_core::Lifecycle::Disputed => {
            let is_backed = view.lifecycle_decision_valid(assertion).unwrap_or(false);
            if !is_backed {
                return if matches!(layer, QueryLayer::Certain) {
                    SlotStatus::Absent
                } else {
                    classify_active_or_defeated(view, assertion, QueryLayer::Shadow)
                };
            }
            classify_active_or_defeated(view, assertion, QueryLayer::Certain)
        }
    }
}

const fn slot_priority(status: &SlotStatus) -> (u8, u8) {
    if let SlotStatus::Active { layer, verdict, .. } = status {
        let layer_rank = if matches!(layer, QueryLayer::Certain) {
            RANK_LAYER_CERTAIN
        } else {
            RANK_LAYER_SHADOW
        };
        let status_rank = if matches!(
            verdict.status,
            crate::beliefs::aspic::ArgumentationStatus::In
        ) {
            RANK_VERDICT_IN
        } else if matches!(
            verdict.status,
            crate::beliefs::aspic::ArgumentationStatus::Undec
        ) {
            RANK_VERDICT_UNDEC
        } else {
            RANK_VERDICT_OUT
        };
        (layer_rank, status_rank)
    } else if let SlotStatus::Dead { reason, .. } = status {
        (RANK_DEAD, dead_reason_rank(*reason))
    } else {
        (RANK_ABSENT, RANK_ABSENT)
    }
}

/// Request parameters for querying a single `(subject, predicate)` slot status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotQuery {
    pub scope: mneme_core::ScopeId,
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub at: mneme_core::Timestamp,
    pub layer: QueryLayer,
}

pub(crate) fn slot_status_in_view(
    view: &crate::beliefs::View,
    query: &SlotQuery,
) -> crate::failure::Result<SlotStatus> {
    let mut best = SlotStatus::Absent;
    for assertion in view.assertions()? {
        if assertion.subject != query.subject || assertion.predicate != query.predicate {
            continue;
        }
        if !view.content_readable_in(&assertion.record.scope, &query.scope) {
            continue;
        }
        let is_time_ok = crate::beliefs::View::valid_time_applies(assertion.valid_time, query.at);
        let is_terminal = matches!(
            assertion.lifecycle,
            mneme_core::Lifecycle::Retracted | mneme_core::Lifecycle::Superseded
        );
        if !is_time_ok && !is_terminal {
            continue;
        }
        let status = classify_assertion_status(view, &assertion, query.layer);
        if slot_priority(&status) > slot_priority(&best) {
            best = status;
        }
    }
    Ok(best)
}
