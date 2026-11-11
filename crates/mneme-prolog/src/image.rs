//! Authorized immutable input-image construction for bounded Prolog search.
//!
//! The image is built from one committed memory view and selected Datalog query
//! results. Revision, scope, eligibility generation, rule context, and every
//! canonical premise must match before any fact is admitted.

use std::collections::BTreeMap;

use mneme_core::{Lifecycle, RecordId, RevisionId, ScopeId, ValidTime, Value, WorkspaceRevisionId};
use mneme_datalog::{Derivation, ExecutionStatus, QueryResult};
use mneme_memory::MemoryView;

use crate::{InputCoverage, SearchContext};

/// One accepted canonical assertion in the image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFact {
    pub record_id: RecordId,
    pub revision_id: RevisionId,
    pub scope: ScopeId,
    pub subject: RecordId,
    pub predicate: String,
    pub value: Value,
    pub valid_time: ValidTime,
}

/// One selected Datalog relation and its retained rows/derivations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedRelation {
    pub predicate: String,
    pub rows: Vec<SelectedRow>,
    pub coverage: InputCoverage,
}

/// One selected Datalog row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelectedRow {
    pub values: Vec<Value>,
    pub supports: Vec<Derivation>,
}

/// One immutable input image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InputImage {
    pub context: SearchContext,
    pub canonical: Vec<CanonicalFact>,
    pub relations: Vec<SelectedRelation>,
    pub coverage: InputCoverage,
}

/// Input-image construction failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImageError {
    #[error("memory view revision {actual} does not match expected {expected}")]
    RevisionMismatch {
        expected: WorkspaceRevisionId,
        actual: WorkspaceRevisionId,
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
pub fn build_input_image(
    view: &MemoryView,
    scope: &ScopeId,
    expected_revision: WorkspaceRevisionId,
    expected_generation: u64,
    results: Vec<QueryResult>,
) -> Result<InputImage, ImageError> {
    if view.revision() != expected_revision {
        return Err(ImageError::RevisionMismatch {
            expected: expected_revision,
            actual: view.revision(),
        });
    }
    let mut canonical = Vec::new();
    for assertion in view
        .assertions()
        .map_err(|error| ImageError::Invalid(error.to_string()))?
    {
        if assertion.lifecycle != Lifecycle::Accepted {
            continue;
        }
        if &assertion.record.scope != scope {
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
    let mut relations = Vec::new();
    let mut rule_versions = BTreeMap::new();
    let mut rule_context: Option<(String, String)> = None;
    let mut is_all_complete = true;
    for result in results {
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
        if let Some(existing) = &rule_context {
            if existing != &context {
                return Err(ImageError::MixedRuleContext);
            }
        } else {
            rule_context = Some(context);
            rule_versions.insert(
                result.context.rule_bundle_id.clone(),
                result.context.rule_bundle_version.clone(),
            );
        }
        let is_coverage_complete = result.exhaustive
            && result
                .coverage
                .iter()
                .all(|coverage| coverage.status == mneme_datalog::CoverageStatus::Complete)
            && result.status == ExecutionStatus::Complete;
        is_all_complete &= is_coverage_complete;
        let mut rows = Vec::new();
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
        let predicate = result.coverage.first().map_or_else(
            || "unknown".to_owned(),
            |coverage| coverage.predicate.clone(),
        );
        relations.push(SelectedRelation {
            predicate,
            rows,
            coverage: InputCoverage {
                complete: is_coverage_complete,
                reason: result.reason.clone(),
            },
        });
    }
    let image_digest = format!(
        "sha256:{}:{}",
        expected_revision.to_hex(),
        expected_generation
    );
    Ok(InputImage {
        context: SearchContext {
            revision: expected_revision,
            scope: scope.clone(),
            eligibility_generation: expected_generation,
            image_digest,
            profile: "positive-minimal/v1".to_owned(),
            rule_versions,
        },
        canonical,
        relations,
        coverage: InputCoverage {
            complete: is_all_complete,
            reason: if is_all_complete {
                None
            } else {
                Some("one or more selected Datalog relations are incomplete".to_owned())
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use mneme_core::{RecordId, RevisionId, ScopeClass, WorkspaceRevisionId};
    use mneme_datalog::{
        BuildContext, Coverage, CoverageStatus, ExecutionStatus, Premise, QueryResult, QueryRow,
    };
    use mneme_memory::MemoryView;
    use mneme_store::{CommitCommand, RecordDraft, Workspace, WorkspaceConfig};
    use tempfile::TempDir;

    fn scope() -> ScopeId {
        ScopeId::new(ScopeClass::Project, "cedar").expect("scope")
    }

    fn other_scope() -> ScopeId {
        ScopeId::new(ScopeClass::Project, "birch").expect("scope")
    }

    fn commit_entity(
        workspace: &mut Workspace,
        scope: &ScopeId,
        id: u8,
        key: &str,
    ) -> Result<(), String> {
        let base = workspace
            .current_revision()
            .map_err(|error| error.to_string())?;
        workspace
            .commit(CommitCommand {
                base,
                actor: "prolog-test".to_owned(),
                scope: scope.clone(),
                idempotency_key: key.to_owned(),
                records: vec![RecordDraft {
                    schema_version: 1,
                    kind: mneme_core::RecordKind::Entity,
                    record_id: RecordId::from_bytes([id; 16]),
                    revision_id: RevisionId::from_bytes([id.wrapping_add(1); 16]),
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

    fn setup() -> Result<(TempDir, MemoryView, WorkspaceRevisionId, u64), String> {
        let temp = tempfile::tempdir().map_err(|error| error.to_string())?;
        let mut workspace = Workspace::create(temp.path(), WorkspaceConfig::default())
            .map_err(|e| e.to_string())?;
        commit_entity(&mut workspace, &scope(), 0x10, "cedar")?;
        commit_entity(&mut workspace, &other_scope(), 0x70, "birch")?;
        let revision = workspace.current_revision().map_err(|e| e.to_string())?;
        let generation = workspace
            .eligibility_generation()
            .map_err(|e| e.to_string())?;
        let view = MemoryView::new(
            workspace.snapshot().map_err(|e| e.to_string())?,
            workspace.root(),
        );
        Ok((temp, view, revision, generation))
    }

    fn result(revision: WorkspaceRevisionId, generation: u64, canonical: RecordId) -> QueryResult {
        QueryResult {
            context: BuildContext {
                requested_revision: revision,
                served_revision: revision,
                scope: scope(),
                schema_version: 1,
                rule_bundle_id: "base".to_owned(),
                rule_bundle_version: "1".to_owned(),
                projection_build_id: "build-1".to_owned(),
                eligibility_generation: generation,
            },
            status: ExecutionStatus::Complete,
            coverage: vec![Coverage {
                predicate: "path".to_owned(),
                status: CoverageStatus::Complete,
                reason: None,
            }],
            rows: vec![QueryRow {
                values: Vec::new(),
                supports: vec![Derivation {
                    rule_id: "path".to_owned(),
                    rule_version: "1".to_owned(),
                    premises: vec![Premise {
                        predicate: "entity".to_owned(),
                        terms: Vec::new(),
                        canonical: Some(canonical),
                        sources: BTreeSet::new(),
                        source_availability: None,
                    }],
                    sources: BTreeSet::new(),
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
                RecordId::from_bytes([0x10; 16]),
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
        let mut mixed = result(revision, generation, RecordId::from_bytes([0x10; 16]));
        mixed.served_revision = WorkspaceRevisionId::from_bytes([0x99; 16]);
        assert!(matches!(
            build_input_image(&view, &scope(), revision, generation, vec![mixed]),
            Err(ImageError::ContextMismatch(_))
        ));
        let stale = result(
            revision,
            generation.saturating_add(1),
            RecordId::from_bytes([0x10; 16]),
        );
        assert!(matches!(
            build_input_image(&view, &scope(), revision, generation, vec![stale]),
            Err(ImageError::StaleBarrier { .. })
        ));
    }

    #[test]
    fn hidden_scope_premise_is_rejected() {
        let (_temp, view, revision, generation) = setup().expect("setup");
        let hidden = result(revision, generation, RecordId::from_bytes([0x70; 16]));
        assert_eq!(
            build_input_image(&view, &scope(), revision, generation, vec![hidden]),
            Err(ImageError::HiddenScope(
                RecordId::from_bytes([0x70; 16]).to_hex()
            ))
        );
    }
}
