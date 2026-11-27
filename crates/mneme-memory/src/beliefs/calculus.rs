//! Event-Calculus `Inertial` fluent interval clipping over half-open
//! `[start, end)` `ValidTime`, strictly enforcing `#71` non-promotion
//! (`Proposed` events never clip `Accepted` fluents).

/// Direction of an Event-Calculus fluent transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FluentTransitionKind {
    /// Initiates `(subject, predicate, value)` at `at`.
    Initiates,
    /// Terminates `(subject, predicate, value)` at `at`.
    Terminates,
}

/// One Event-Calculus fluent transition with explicit authority stratum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FluentEvent {
    pub event_id: mneme_core::RecordId,
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub value: mneme_core::Value,
    pub kind: FluentTransitionKind,
    pub at: mneme_core::Timestamp,
    pub authority: mneme_kernel::argumentation::Authority,
}

/// One projected half-open `[start, stop)` inertial fluent interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InertialFluent {
    pub initiated_by: mneme_core::RecordId,
    pub terminated_by: Option<mneme_core::RecordId>,
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub value: mneme_core::Value,
    pub period: mneme_kernel::temporal::Period,
    pub authority: mneme_kernel::argumentation::Authority,
}

/// Project half-open `[start, end)` intervals for `Inertial` fluent transitions.
///
/// An `Initiates(s, p, o)` event at `t_start` with authority `auth` projects
/// `[t_start, t_end)` where `t_end` is the earliest strictly later timestamp
/// (`t_clip > t_start`) of an event with
/// `authority_rank(clip.authority) >= authority_rank(auth)` that either:
/// - `Terminates(s, p, o)`, or
/// - `Initiates(s, p, o')` with `o' != o` when `p` is also `Functional`.
///
/// Strictly enforces `#71` non-promotion: `Proposed` events never clip
/// `Accepted` or `ConflictResolution` fluents.
pub fn clip_inertial_fluents(
    events: &[FluentEvent],
    functional_predicates: &std::collections::BTreeSet<String>,
) -> Vec<InertialFluent> {
    let mut ordered: Vec<&FluentEvent> = events.iter().collect();
    ordered.sort_by(|left, right| {
        left.at
            .nanos()
            .cmp(&right.at.nanos())
            .then_with(|| left.event_id.cmp(&right.event_id))
    });

    let mut fluents = Vec::with_capacity(ordered.len());
    for candidate in &ordered {
        if !matches!(candidate.kind, FluentTransitionKind::Initiates) {
            continue;
        }
        let is_functional = functional_predicates.contains(&candidate.predicate);
        let init_rank = mneme_kernel::argumentation::authority_rank(candidate.authority);
        let start = i128::from(candidate.at.nanos());
        let mut stop = mneme_kernel::temporal::POS_INF;
        let mut terminated_by: Option<mneme_core::RecordId> = None;

        for later in &ordered {
            if later.at.nanos() <= candidate.at.nanos() {
                continue;
            }
            if later.subject != candidate.subject || later.predicate != candidate.predicate {
                continue;
            }
            let later_rank = mneme_kernel::argumentation::authority_rank(later.authority);
            if later_rank < init_rank {
                // Non-promotion (#71): lower-authority events never clip higher-authority fluents.
                continue;
            }
            let is_matching_terminate = matches!(later.kind, FluentTransitionKind::Terminates)
                && later.value == candidate.value;
            let is_functional_override = is_functional
                && matches!(later.kind, FluentTransitionKind::Initiates)
                && later.value != candidate.value;
            if is_matching_terminate || is_functional_override {
                stop = i128::from(later.at.nanos());
                terminated_by = Some(later.event_id);
                break;
            }
        }

        fluents.push(InertialFluent {
            initiated_by: candidate.event_id,
            terminated_by,
            subject: candidate.subject,
            predicate: candidate.predicate.clone(),
            value: candidate.value.clone(),
            period: mneme_kernel::temporal::Period { start, stop },
            authority: candidate.authority,
        });
    }
    fluents
}

pub(crate) fn inertial_in_view(
    view: &crate::beliefs::View,
    scope: &mneme_core::ScopeId,
    layer: crate::beliefs::traits::QueryLayer,
) -> crate::failure::Result<Vec<InertialFluent>> {
    let declared = crate::beliefs::traits::declared_in_view(view, scope, layer)?;
    let inertial_preds: std::collections::BTreeSet<String> = declared
        .iter()
        .filter(|(_, kinds)| kinds.contains(&crate::beliefs::traits::PredicateTrait::Inertial))
        .map(|(pred, _)| pred.clone())
        .collect();
    if inertial_preds.is_empty() {
        return Ok(Vec::new());
    }
    let functional_preds: std::collections::BTreeSet<String> = declared
        .into_iter()
        .filter(|(_, kinds)| kinds.contains(&crate::beliefs::traits::PredicateTrait::Functional))
        .map(|(pred, _)| pred)
        .collect();

    let all_assertions = view.assertions()?;
    let mut events = Vec::with_capacity(all_assertions.len());
    for assertion in all_assertions {
        if !inertial_preds.contains(&assertion.predicate) {
            continue;
        }
        if !view.content_readable_in(&assertion.record.scope, scope) {
            continue;
        }
        if !crate::beliefs::traits::is_assertion_in_layer(view, &assertion, layer) {
            continue;
        }
        let mneme_core::ValidTime::Bounded {
            start: Some(at), ..
        } = assertion.valid_time
        else {
            continue;
        };
        let kind = if matches!(assertion.stance, crate::model::Stance::Affirm) {
            FluentTransitionKind::Initiates
        } else if matches!(assertion.stance, crate::model::Stance::Deny) {
            FluentTransitionKind::Terminates
        } else {
            continue;
        };
        let authority = crate::beliefs::aspic::assertion_authority_of(view, &assertion);
        events.push(FluentEvent {
            event_id: assertion.record.record_id,
            subject: assertion.subject,
            predicate: assertion.predicate,
            value: assertion.value,
            kind,
            at,
            authority,
        });
    }
    Ok(clip_inertial_fluents(&events, &functional_preds))
}
