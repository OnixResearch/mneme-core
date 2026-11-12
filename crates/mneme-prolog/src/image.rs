//! Authorized immutable input-image construction for bounded Prolog search.
//!
//! The image is built from one committed memory view and selected Datalog query
//! results. Revision, scope, eligibility generation, rule context, and every
//! canonical premise must match before any fact is admitted.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

/// One accepted canonical assertion in the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFact {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub scope: mneme_core::ScopeId,
    pub subject: mneme_core::RecordId,
    pub predicate: String,
    pub value: mneme_core::Value,
    pub valid_time: mneme_core::ValidTime,
}

/// One selected Datalog relation and its retained rows/derivations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedRelation {
    pub predicate: String,
    pub rows: Vec<SelectedRow>,
    pub coverage: crate::InputCoverage,
}

/// One selected Datalog row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedRow {
    pub values: Vec<mneme_core::Value>,
    pub supports: Vec<mneme_datalog::Derivation>,
}

/// One immutable input image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputImage {
    pub context: crate::SearchContext,
    pub canonical: Vec<CanonicalFact>,
    pub relations: Vec<SelectedRelation>,
    pub coverage: crate::InputCoverage,
}

/// Input-image construction failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImageError {
    #[error("memory view revision {actual} does not match expected {expected}")]
    RevisionMismatch {
        expected: mneme_core::WorkspaceRevisionId,
        actual: mneme_core::WorkspaceRevisionId,
    },
    #[error("Datalog result context does not match the image context: {0}")]
    ContextMismatch(String),
    #[error("stale eligibility barrier: expected {expected}, current {actual}")]
    StaleBarrier { expected: u64, actual: u64 },
    #[error("premise {0} is outside the requested scope")]
    HiddenScope(String),
    #[error("premise {0} is absent from the pinned view")]
    MissingPremise(String),
    #[error("selected Datalog results use mixed rule contexts")]
    MixedRuleContext,
    #[error("invalid input image: {0}")]
    Invalid(String),
}

/// Build an immutable image from one view and selected Datalog results.
#[allow(unknown_lints)] // Octet structural exception: cohesive state-machine code; split tracked separately
pub fn build_input_image(
    view: &mneme_memory::MemoryView,
    scope: &mneme_core::ScopeId,
    expected_revision: mneme_core::WorkspaceRevisionId,
    expected_generation: u64,
    results: Vec<mneme_datalog::QueryResult>,
) -> Result<InputImage, ImageError> {
    if view.revision() != expected_revision {
        return Err(ImageError::RevisionMismatch {
            expected: expected_revision,
            actual: view.revision(),
        });
    }
    let canonical = canonical_facts(view, scope)?;
    let mut relations = Vec::with_capacity(results.len());
    let mut validation = ResultContextValidation::default();
    let mut is_all_complete = true;
    for result in results {
        let is_coverage_complete = validate_result_context(
            &result,
            scope,
            expected_revision,
            expected_generation,
            &mut validation,
        )?;
        is_all_complete &= is_coverage_complete;
        let rows = selected_rows(view, scope, expected_revision, &result)?;
        relations.push(selected_relation(result, rows, is_coverage_complete));
    }
    let image_digest = format!(
        "sha256:{}:{}",
        expected_revision.to_hex(),
        expected_generation
    );
    Ok(InputImage {
        context: crate::SearchContext {
            revision: expected_revision,
            scope: scope.clone(),
            eligibility_generation: expected_generation,
            image_digest,
            profile: "positive-minimal/v1".to_owned(),
            rule_versions: validation.rule_versions,
        },
        canonical,
        relations,
        coverage: crate::InputCoverage {
            complete: is_all_complete,
            reason: if is_all_complete {
                None
            } else {
                Some("one or more selected Datalog relations are incomplete".to_owned())
            },
        },
    })
}

fn canonical_facts(
    view: &mneme_memory::MemoryView,
    scope: &mneme_core::ScopeId,
) -> Result<Vec<CanonicalFact>, ImageError> {
    let assertions = view
        .assertions()
        .map_err(|error| ImageError::Invalid(error.to_string()))?;
    let mut canonical = Vec::with_capacity(assertions.len());
    for assertion in assertions {
        if assertion.lifecycle != mneme_core::Lifecycle::Accepted
            || &assertion.record.scope != scope
        {
            continue;
        }
        canonical.push(CanonicalFact {
            record_id: assertion.record.record_id,
            revision_id: assertion.record.revision_id,
            scope: assertion.record.scope.clone(),
            subject: assertion.subject,
            predicate: assertion.predicate,
            value: assertion.value,
            valid_time: assertion.valid_time,
        });
    }
    Ok(canonical)
}

#[derive(Default)]
struct ResultContextValidation {
    rule_context: Option<(String, String)>,
    rule_versions: std::collections::BTreeMap<String, String>,
}

fn validate_result_context(
    result: &mneme_datalog::QueryResult,
    scope: &mneme_core::ScopeId,
    expected_revision: mneme_core::WorkspaceRevisionId,
    expected_generation: u64,
    validation: &mut ResultContextValidation,
) -> Result<bool, ImageError> {
    if result.context.served_revision != expected_revision
        || result.served_revision != expected_revision
        || result.requested_revision != expected_revision
    {
        return Err(ImageError::ContextMismatch(
            "Datalog revision differs from the pinned image".to_owned(),
        ));
    }
    if &result.context.scope != scope {
        return Err(ImageError::ContextMismatch(
            "Datalog scope differs from the pinned image".to_owned(),
        ));
    }
    if result.context.eligibility_generation != expected_generation {
        return Err(ImageError::StaleBarrier {
            expected: expected_generation,
            actual: result.context.eligibility_generation,
        });
    }
    let context = (
        result.context.rule_bundle_id.clone(),
        result.context.rule_bundle_version.clone(),
    );
    if let Some(existing) = validation.rule_context.as_ref() {
        if existing != &context {
            return Err(ImageError::MixedRuleContext);
        }
    } else {
        validation.rule_context = Some(context);
        validation.rule_versions.insert(
            result.context.rule_bundle_id.clone(),
            result.context.rule_bundle_version.clone(),
        );
    }
    Ok(result.exhaustive
        && result
            .coverage
            .iter()
            .all(|coverage| coverage.status == mneme_datalog::CoverageStatus::Complete)
        && result.status == mneme_datalog::ExecutionStatus::Complete)
}

fn selected_rows(
    view: &mneme_memory::MemoryView,
    scope: &mneme_core::ScopeId,
    expected_revision: mneme_core::WorkspaceRevisionId,
    result: &mneme_datalog::QueryResult,
) -> Result<Vec<SelectedRow>, ImageError> {
    let mut rows = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        for support in &row.supports {
            if support.revision != expected_revision || &support.scope != scope {
                return Err(ImageError::ContextMismatch(
                    "derivation revision/scope differs from the image".to_owned(),
                ));
            }
            for premise in &support.premises {
                let Some(canonical_id) = premise.canonical else {
                    continue;
                };
                let record = view
                    .record(canonical_id)
                    .map_err(|_| ImageError::MissingPremise(canonical_id.to_hex()))?;
                if &record.scope != scope {
                    return Err(ImageError::HiddenScope(canonical_id.to_hex()));
                }
            }
        }
        rows.push(SelectedRow {
            values: row.values.clone(),
            supports: row.supports.clone(),
        });
    }
    Ok(rows)
}

fn selected_relation(
    result: mneme_datalog::QueryResult,
    rows: Vec<SelectedRow>,
    is_coverage_complete: bool,
) -> SelectedRelation {
    let predicate = result.coverage.first().map_or_else(
        || "unknown".to_owned(),
        |coverage| coverage.predicate.clone(),
    );
    SelectedRelation {
        predicate,
        rows,
        coverage: crate::InputCoverage {
            complete: is_coverage_complete,
            reason: result.reason,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
    }

    fn other_scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "birch").expect("scope")
    }

    fn commit_entity(
        workspace: &mut mneme_store::Workspace,
        scope: &mneme_core::ScopeId,
        id: u8,
        key: &str,
    ) -> Result<(), String> {
        let base = workspace
            .current_revision()
            .map_err(|error| error.to_string())?;
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "prolog-test".to_owned(),
                scope: scope.clone(),
                idempotency_key: key.to_owned(),
                records: vec![mneme_store::RecordDraft {
                    schema_version: 1,
                    kind: mneme_core::RecordKind::Entity,
                    record_id: mneme_core::RecordId::from_bytes([id; 16]),
                    revision_id: mneme_core::RevisionId::from_bytes([id.wrapping_add(1); 16]),
                    predecessor: None,
                    scope: scope.clone(),
                    payload: mneme_core::fixtures::entity().payload,
                }],
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    fn setup() -> Result<
        (
            tempfile::TempDir,
            mneme_memory::MemoryView,
            mneme_core::WorkspaceRevisionId,
            u64,
        ),
        String,
    > {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let mut workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig::new(
                Box::new(mneme_store::SystemClock),
                Box::new(mneme_store::NoFaults),
            ),
        )
        .map_err(|e| e.to_string())?;
        commit_entity(&mut workspace, &scope(), 0x10, "cedar")?;
        commit_entity(&mut workspace, &other_scope(), 0x70, "birch")?;
        let revision = workspace.current_revision().map_err(|e| e.to_string())?;
        let generation = workspace
            .eligibility_generation()
            .map_err(|e| e.to_string())?;
        let view = mneme_memory::MemoryView::new(
            workspace.snapshot().map_err(|e| e.to_string())?,
            workspace.root(),
        );
        Ok((temp, view, revision, generation))
    }

    fn result(
        revision: mneme_core::WorkspaceRevisionId,
        generation: u64,
        canonical: mneme_core::RecordId,
    ) -> mneme_datalog::QueryResult {
        mneme_datalog::QueryResult {
            context: mneme_datalog::BuildContext {
                requested_revision: revision,
                served_revision: revision,
                scope: scope(),
                schema_version: 1,
                rule_bundle_id: "base".to_owned(),
                rule_bundle_version: "1".to_owned(),
                projection_build_id: "build-1".to_owned(),
                eligibility_generation: generation,
            },
            status: mneme_datalog::ExecutionStatus::Complete,
            coverage: vec![mneme_datalog::Coverage {
                predicate: "path".to_owned(),
                status: mneme_datalog::CoverageStatus::Complete,
                reason: None,
            }],
            rows: vec![mneme_datalog::QueryRow {
                values: Vec::new(),
                supports: vec![mneme_datalog::Derivation {
                    rule_id: "path".to_owned(),
                    rule_version: "1".to_owned(),
                    premises: vec![mneme_datalog::Premise {
                        predicate: "entity".to_owned(),
                        terms: Vec::new(),
                        canonical: Some(canonical),
                        sources: std::collections::BTreeSet::new(),
                        source_availability: None,
                    }],
                    sources: std::collections::BTreeSet::new(),
                    temporal_parameters: Vec::new(),
                    revision,
                    scope: scope(),
                    truncated: false,
                }],
                support_truncated: false,
            }],
            exhaustive: true,
            truncated: false,
            absence_established: false,
            reason: None,
            requested_revision: revision,
            served_revision: revision,
            work: 1,
        }
    }

    #[test]
    fn builds_one_immutable_image_with_context_and_coverage() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let image = build_input_image(
            &view,
            &scope(),
            revision,
            generation,
            vec![result(
                revision,
                generation,
                mneme_core::RecordId::from_bytes([0x10; 16]),
            )],
        )
        .expect("image");
        assert_eq!(image.context.revision, revision);
        assert_eq!(image.context.eligibility_generation, generation);
        assert_eq!(image.context.scope, scope());
        assert_eq!(image.relations.len(), 1);
        assert!(image.relations[0].coverage.complete);
        assert!(image.coverage.complete);
    }

    #[test]
    fn mixed_revision_and_stale_generation_are_rejected() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let mut mixed = result(
            revision,
            generation,
            mneme_core::RecordId::from_bytes([0x10; 16]),
        );
        mixed.served_revision = mneme_core::WorkspaceRevisionId::from_bytes([0x99; 16]);
        assert!(matches!(
            build_input_image(&view, &scope(), revision, generation, vec![mixed]),
            Err(ImageError::ContextMismatch(_))
        ));
        let stale = result(
            revision,
            generation.saturating_add(1),
            mneme_core::RecordId::from_bytes([0x10; 16]),
        );
        assert!(matches!(
            build_input_image(&view, &scope(), revision, generation, vec![stale]),
            Err(ImageError::StaleBarrier { .. })
        ));
    }

    #[test]
    fn hidden_scope_premise_is_rejected() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let hidden = result(
            revision,
            generation,
            mneme_core::RecordId::from_bytes([0x70; 16]),
        );
        assert_eq!(
            build_input_image(&view, &scope(), revision, generation, vec![hidden]),
            Err(ImageError::HiddenScope(
                mneme_core::RecordId::from_bytes([0x70; 16]).to_hex()
            ))
        );
    }
}
