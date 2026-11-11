//! Explicit, versioned schema migration over record revisions.
//!
//! A migration is a named payload transformation between two registered schema
//! versions. Execution never mutates the source revision: it transforms a copy,
//! builds a new immutable revision whose predecessor is the source, validates
//! the target under its own schema version, and returns the lineage. Any failure
//! leaves the committed source readable and reports the failed transformation.

/// A payload transformation for one migration step.
pub type PayloadTransform = Box<
    dyn Fn(&crate::envelope::Payload) -> Result<crate::envelope::Payload, crate::error::Diagnostic>
        + Send
        + Sync,
>;

/// One named, versioned payload transformation.
pub struct Migration {
    name: String,
    from_version: u32,
    to_version: u32,
    transform: PayloadTransform,
}

impl std::fmt::Debug for Migration {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Migration")
            .field("name", &self.name)
            .field("from_version", &self.from_version)
            .field("to_version", &self.to_version)
            .finish_non_exhaustive()
    }
}

impl Migration {
    /// Define a migration step.
    pub fn new(
        name: impl Into<String>,
        from_version: u32,
        to_version: u32,
        transform: impl Fn(
            &crate::envelope::Payload,
        ) -> Result<crate::envelope::Payload, crate::error::Diagnostic>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Migration {
            name: name.into(),
            from_version,
            to_version,
            transform: Box::new(transform),
        }
    }

    /// The migration name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The source schema version.
    pub const fn from_version(&self) -> u32 {
        self.from_version
    }

    /// The target schema version.
    pub const fn to_version(&self) -> u32 {
        self.to_version
    }

    /// Plan this migration for one record without transforming it.
    pub fn plan(
        &self,
        source: &crate::envelope::RecordEnvelope,
    ) -> Result<MigrationPlan, MigrationFailure> {
        if source.schema_version != self.from_version {
            return Err(MigrationFailure {
                migration: self.name.clone(),
                source_record: source.record_id,
                source_revision: source.revision_id,
                diagnostics: vec![crate::error::Diagnostic::new(
                    crate::error::Stage::Migration,
                    crate::error::ErrorCode::MigrationFailed,
                    crate::error::Path::root().field("schema-version"),
                    format!(
                        "migration {} expects schema version {}, found {}",
                        self.name, self.from_version, source.schema_version
                    ),
                )],
            });
        }
        if self.to_version <= self.from_version {
            return Err(MigrationFailure {
                migration: self.name.clone(),
                source_record: source.record_id,
                source_revision: source.revision_id,
                diagnostics: vec![crate::error::Diagnostic::new(
                    crate::error::Stage::Migration,
                    crate::error::ErrorCode::MigrationFailed,
                    crate::error::Path::root(),
                    "migration target version must be newer than its source version",
                )],
            });
        }
        Ok(MigrationPlan {
            migration: self.name.clone(),
            source_record: source.record_id,
            source_revision: source.revision_id,
            from_version: self.from_version,
            to_version: self.to_version,
        })
    }

    /// Execute this migration into a new validated record revision.
    pub fn execute(
        &self,
        registry: &crate::schema::SchemaRegistry,
        source: &crate::envelope::RecordEnvelope,
        target_revision: crate::ids::RevisionId,
        recorded: crate::time::RecordedTime,
    ) -> Result<MigrationOutcome, MigrationFailure> {
        self.plan(source)?;
        if registry.schema(self.to_version).is_none() {
            return Err(MigrationFailure {
                migration: self.name.clone(),
                source_record: source.record_id,
                source_revision: source.revision_id,
                diagnostics: vec![crate::error::Diagnostic::new(
                    crate::error::Stage::Migration,
                    crate::error::ErrorCode::UnsupportedSchemaVersion,
                    crate::error::Path::root().field("schema-version"),
                    format!(
                        "migration target version {} is not registered",
                        self.to_version
                    ),
                )],
            });
        }
        let payload = (self.transform)(&source.payload).map_err(|diagnostic| MigrationFailure {
            migration: self.name.clone(),
            source_record: source.record_id,
            source_revision: source.revision_id,
            diagnostics: vec![diagnostic],
        })?;
        let target = crate::envelope::RecordEnvelope {
            schema_version: self.to_version,
            kind: source.kind,
            record_id: source.record_id,
            revision_id: target_revision,
            predecessor: Some(source.revision_id),
            scope: source.scope.clone(),
            recorded,
            payload,
        };
        let context = crate::envelope::RecordContext::isolated(registry);
        let diagnostics =
            crate::envelope::validate_record(&target, &context, &crate::error::Path::root());
        if !diagnostics.is_empty() {
            return Err(MigrationFailure {
                migration: self.name.clone(),
                source_record: source.record_id,
                source_revision: source.revision_id,
                diagnostics,
            });
        }
        Ok(MigrationOutcome {
            source_record: source.record_id,
            source_revision: source.revision_id,
            lineage: MigrationLineage {
                migration: self.name.clone(),
                from_version: self.from_version,
                to_version: self.to_version,
                source_revision: source.revision_id,
                target_revision,
            },
            target,
        })
    }
}

/// A planned migration step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationPlan {
    pub migration: String,
    pub source_record: crate::ids::RecordId,
    pub source_revision: crate::ids::RevisionId,
    pub from_version: u32,
    pub to_version: u32,
}

/// The lineage of one successful migration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationLineage {
    pub migration: String,
    pub from_version: u32,
    pub to_version: u32,
    pub source_revision: crate::ids::RevisionId,
    pub target_revision: crate::ids::RevisionId,
}

/// A successful migration: the source stays untouched and the target carries
/// its predecessor lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationOutcome {
    pub source_record: crate::ids::RecordId,
    pub source_revision: crate::ids::RevisionId,
    pub target: crate::envelope::RecordEnvelope,
    pub lineage: MigrationLineage,
}

/// A refused migration with source-identifying diagnostics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationFailure {
    pub migration: String,
    pub source_record: crate::ids::RecordId,
    pub source_revision: crate::ids::RevisionId,
    pub diagnostics: Vec<crate::error::Diagnostic>,
}

impl std::fmt::Display for MigrationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "migration {} failed for record {} revision {}: {}",
            self.migration,
            self.source_record,
            self.source_revision,
            crate::error::render_diagnostics(&self.diagnostics)
        )
    }
}

impl std::error::Error for MigrationFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    fn assertion() -> crate::envelope::RecordEnvelope {
        crate::envelope::RecordEnvelope {
            schema_version: 1,
            kind: crate::schema::RecordKind::Assertion,
            record_id: crate::ids::RecordId::from_bytes([1; 16]),
            revision_id: crate::ids::RevisionId::from_bytes([1; 16]),
            predecessor: None,
            scope: crate::scope::ScopeId::new(crate::scope::ScopeClass::Project, "cedar")
                .expect("scope"),
            recorded: crate::time::RecordedTime::new(crate::time::Timestamp::from_nanos(1), 1),
            payload: crate::envelope::Payload::new([
                (
                    crate::value::Symbol::from("subject"),
                    crate::reference::Reference::local(
                        crate::ids::RecordId::from_bytes([2; 16]),
                        crate::schema::RecordKind::Entity,
                    )
                    .to_value(),
                ),
                (
                    crate::value::Symbol::from("predicate"),
                    crate::value::Value::symbol("storage-engine"),
                ),
                (
                    crate::value::Symbol::from("value"),
                    crate::value::Value::string("SQLite"),
                ),
                (
                    crate::value::Symbol::from("stance"),
                    crate::value::Value::symbol("affirm"),
                ),
                (
                    crate::value::Symbol::from("lifecycle"),
                    crate::value::Value::symbol("proposed"),
                ),
                (
                    crate::value::Symbol::from("origin"),
                    crate::value::Value::symbol("authored-statement"),
                ),
                (
                    crate::value::Symbol::from("asserted-by"),
                    crate::value::Value::string("author"),
                ),
                (
                    crate::value::Symbol::from("valid-time"),
                    crate::time::ValidTime::Unknown.to_value(),
                ),
                (
                    crate::value::Symbol::from("evidence"),
                    crate::value::Value::set([]),
                ),
            ]),
        }
    }

    fn registry() -> crate::schema::SchemaRegistry {
        crate::schema::SchemaRegistry::v1()
            .with_version(crate::schema::RecordSchema::synthetic_migration_v2())
    }

    fn add_extraction(
        payload: &crate::envelope::Payload,
    ) -> Result<crate::envelope::Payload, crate::error::Diagnostic> {
        let mut output = payload.clone();
        output.insert(
            crate::value::Symbol::from("extraction"),
            crate::value::Value::string("synthetic-v2"),
        );
        Ok(output)
    }

    #[test]
    fn successful_migration_records_lineage_and_leaves_source_intact() {
        let source = assertion();
        let original = source.clone();
        let migration = Migration::new("synthetic-v1-to-v2", 1, 2, add_extraction);
        let outcome = migration
            .execute(
                &registry(),
                &source,
                crate::ids::RevisionId::from_bytes([9; 16]),
                crate::time::RecordedTime::new(crate::time::Timestamp::from_nanos(2), 2),
            )
            .expect("migration");
        assert_eq!(source, original, "source revision is immutable");
        assert_eq!(outcome.source_revision, original.revision_id);
        assert_eq!(outcome.target.record_id, original.record_id);
        assert_eq!(outcome.target.schema_version, 2);
        assert_eq!(outcome.target.predecessor, Some(original.revision_id));
        assert_eq!(outcome.lineage.target_revision, outcome.target.revision_id);
        assert_eq!(
            outcome.target.assertion_lifecycle(),
            Some(crate::schema::Lifecycle::Proposed)
        );
        crate::envelope::validate_record_value(&outcome.target.to_value(), &registry(), None)
            .expect("target validates under version 2");
    }

    #[test]
    fn failing_transformation_leaves_source_and_reports_identity() {
        let source = assertion();
        let original = source.clone();
        let migration = Migration::new("synthetic-failure", 1, 2, |_payload| {
            Err(crate::error::Diagnostic::new(
                crate::error::Stage::Migration,
                crate::error::ErrorCode::MigrationFailed,
                crate::error::Path::root().field("payload"),
                "synthetic transformation refused",
            ))
        });
        let failure = migration
            .execute(
                &registry(),
                &source,
                crate::ids::RevisionId::from_bytes([9; 16]),
                crate::time::RecordedTime::new(crate::time::Timestamp::from_nanos(2), 2),
            )
            .expect_err("must fail");
        assert_eq!(source, original);
        assert_eq!(failure.source_revision, original.revision_id);
        assert_eq!(failure.migration, "synthetic-failure");
        assert!(
            failure
                .to_string()
                .contains(&original.revision_id.to_string())
        );
    }

    #[test]
    fn target_validation_failure_commits_nothing() {
        let source = assertion();
        let migration = Migration::new("synthetic-incomplete", 1, 2, |payload| Ok(payload.clone()));
        let failure = migration
            .execute(
                &registry(),
                &source,
                crate::ids::RevisionId::from_bytes([9; 16]),
                crate::time::RecordedTime::new(crate::time::Timestamp::from_nanos(2), 2),
            )
            .expect_err("target misses the v2 field");
        assert!(failure.diagnostics.iter().any(|diagnostic| diagnostic.code
            == crate::error::ErrorCode::MissingField
            && diagnostic.path.to_string() == "$.payload.extraction"));
        // The source record is never rewritten.
        assert_eq!(
            source.assertion_lifecycle(),
            Some(crate::schema::Lifecycle::Proposed)
        );
    }

    #[test]
    fn unregistered_target_version_is_refused() {
        let source = assertion();
        let migration = Migration::new("synthetic-v1-to-v3", 1, 3, add_extraction);
        let failure = migration
            .execute(
                &crate::schema::SchemaRegistry::v1(),
                &source,
                crate::ids::RevisionId::from_bytes([9; 16]),
                crate::time::RecordedTime::new(crate::time::Timestamp::from_nanos(2), 2),
            )
            .expect_err("no v3");
        assert_eq!(
            failure.diagnostics[0].code,
            crate::error::ErrorCode::UnsupportedSchemaVersion
        );
    }
}
