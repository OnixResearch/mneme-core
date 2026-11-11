//! Explicit typed references and the snapshot index used to validate them.
//!
//! A reference names a target record identity and its expected kind. It may pin
//! an exact revision, name an external target explicitly, or carry a typed
//! unresolved state when the owning schema permits one. Validation against a
//! snapshot index rejects missing targets, kind mismatches, and pinned
//! revisions the snapshot does not contain.
#![allow(path_segment_repetition)] // Octet structural exception: domain-qualified names and macro-only imports are intentional

const LOCAL_REF: &str = "local-ref";
const PINNED_REF: &str = "pinned-ref";
const EXTERNAL_REF: &str = "external-ref";
const UNRESOLVED_REF: &str = "unresolved-ref";

/// The current kind and revision of one record in a validated snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RevisionEntry {
    pub kind: crate::schema::RecordKind,
    pub revision: crate::ids::RevisionId,
}

/// Record identities and revisions known to one validated snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotIndex {
    current: std::collections::BTreeMap<crate::ids::RecordId, RevisionEntry>,
    revisions: std::collections::BTreeSet<(crate::ids::RecordId, crate::ids::RevisionId)>,
}

impl SnapshotIndex {
    /// An empty index.
    pub fn new() -> Self {
        SnapshotIndex::default()
    }

    /// Insert a current record. Returns `false` when the identity is already
    /// present; a snapshot cannot contain two current revisions of one record.
    pub fn insert(
        &mut self,
        record: crate::ids::RecordId,
        kind: crate::schema::RecordKind,
        revision: crate::ids::RevisionId,
    ) -> bool {
        if self.current.contains_key(&record) {
            return false;
        }
        self.current
            .insert(record, RevisionEntry { kind, revision });
        self.revisions.insert((record, revision));
        true
    }

    /// Replace the current entry for a record while retaining its previous
    /// revision in the snapshot history.
    pub fn upsert(
        &mut self,
        record: crate::ids::RecordId,
        kind: crate::schema::RecordKind,
        revision: crate::ids::RevisionId,
    ) -> Option<RevisionEntry> {
        let previous = self
            .current
            .insert(record, RevisionEntry { kind, revision });
        if let Some(previous) = previous {
            self.revisions.insert((record, previous.revision));
        }
        self.revisions.insert((record, revision));
        previous
    }

    /// Record an additional retained revision of a known record.
    pub fn record_revision(
        &mut self,
        record: crate::ids::RecordId,
        revision: crate::ids::RevisionId,
    ) {
        self.revisions.insert((record, revision));
    }

    /// The current entry for a record identity.
    pub fn get(&self, record: &crate::ids::RecordId) -> Option<&RevisionEntry> {
        self.current.get(record)
    }

    /// Number of current records.
    #[allow(unknown_lints, usize_in_public_api)] // std-shaped collection length
    pub fn len(&self) -> usize {
        self.current.len()
    }

    /// Whether the index has no current records.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }

    /// Whether an exact record revision is known to this snapshot.
    pub fn knows_revision(
        &self,
        record: &crate::ids::RecordId,
        revision: &crate::ids::RevisionId,
    ) -> bool {
        self.revisions.contains(&(*record, *revision))
    }

    /// Iterate over current records.
    pub fn iter(&self) -> impl Iterator<Item = (&crate::ids::RecordId, &RevisionEntry)> + '_ {
        self.current.iter()
    }
}

/// An explicit application reference.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reference {
    /// A target resolved within the pinned snapshot, without a revision pin.
    Local {
        target: crate::ids::RecordId,
        kind: crate::schema::RecordKind,
    },
    /// A target pinned to one immutable record revision.
    Pinned {
        target: crate::ids::RecordId,
        revision: crate::ids::RevisionId,
        kind: crate::schema::RecordKind,
    },
    /// A target outside the local workspace, explicitly marked external.
    External {
        locator: String,
        kind: crate::schema::RecordKind,
    },
    /// A typed unresolved state permitted only where the schema says so.
    Unresolved {
        target: crate::ids::RecordId,
        kind: crate::schema::RecordKind,
        reason: String,
    },
}

impl Reference {
    /// A snapshot-local reference.
    pub fn local(target: crate::ids::RecordId, kind: crate::schema::RecordKind) -> Self {
        Reference::Local { target, kind }
    }

    /// A revision-pinned reference.
    pub fn pinned(
        target: crate::ids::RecordId,
        revision: crate::ids::RevisionId,
        kind: crate::schema::RecordKind,
    ) -> Self {
        Reference::Pinned {
            target,
            revision,
            kind,
        }
    }

    /// An explicitly external reference.
    pub fn external(
        locator: impl Into<String>,
        kind: crate::schema::RecordKind,
    ) -> Result<Self, &'static str> {
        let locator = locator.into();
        if locator.trim().is_empty() {
            return Err("external reference requires a non-empty locator");
        }
        Ok(Reference::External { locator, kind })
    }

    /// A typed unresolved reference with an explicit reason.
    pub fn unresolved(
        target: crate::ids::RecordId,
        kind: crate::schema::RecordKind,
        reason: impl Into<String>,
    ) -> Result<Self, &'static str> {
        let reason = reason.into();
        if reason.trim().is_empty() {
            return Err("an unresolved reference must state a reason");
        }
        Ok(Reference::Unresolved {
            target,
            kind,
            reason,
        })
    }

    /// The referenced kind.
    pub const fn kind(&self) -> crate::schema::RecordKind {
        match self {
            Reference::Local { kind, .. }
            | Reference::Pinned { kind, .. }
            | Reference::External { kind, .. }
            | Reference::Unresolved { kind, .. } => *kind,
        }
    }

    /// The target identity, if the reference names a local record.
    pub fn target(&self) -> Option<crate::ids::RecordId> {
        match self {
            Reference::Local { target, .. }
            | Reference::Pinned { target, .. }
            | Reference::Unresolved { target, .. } => Some(*target),
            Reference::External { .. } => None,
        }
    }

    /// Whether this reference is explicitly external.
    pub const fn is_external(&self) -> bool {
        matches!(self, Reference::External { .. })
    }

    /// Whether this reference is a typed unresolved state.
    pub const fn is_unresolved(&self) -> bool {
        matches!(self, Reference::Unresolved { .. })
    }

    /// Encode as one of the declared reference records.
    pub fn to_value(&self) -> crate::value::Value {
        match self {
            Reference::Local { target, kind } => crate::value::Value::record_named(
                LOCAL_REF,
                vec![target.to_value(), kind.to_value()],
            ),
            Reference::Pinned {
                target,
                revision,
                kind,
            } => crate::value::Value::record_named(
                PINNED_REF,
                vec![target.to_value(), revision.to_value(), kind.to_value()],
            ),
            Reference::External { locator, kind } => crate::value::Value::record_named(
                EXTERNAL_REF,
                vec![
                    crate::value::Value::string(locator.clone()),
                    kind.to_value(),
                ],
            ),
            Reference::Unresolved {
                target,
                kind,
                reason,
            } => crate::value::Value::record_named(
                UNRESOLVED_REF,
                vec![
                    target.to_value(),
                    kind.to_value(),
                    crate::value::Value::string(reason.clone()),
                ],
            ),
        }
    }

    /// Decode a reference record.
    pub fn from_value(
        value: &crate::value::Value,
        path: &crate::error::Path,
    ) -> Result<Self, crate::error::Diagnostic> {
        let type_error = || {
            crate::error::Diagnostic::new(
                crate::error::Stage::Domain,
                crate::error::ErrorCode::TypeMismatch,
                path.clone(),
                "expected a declared reference record",
            )
        };
        let record = value.as_record().ok_or_else(type_error)?;
        let Some(label) = record.label().as_symbol() else {
            return Err(type_error());
        };
        match label.as_str() {
            LOCAL_REF if record.fields().len() == 2 => {
                let target = crate::ids::RecordId::from_value(&record.fields()[0], &path.index(0))?;
                let kind =
                    crate::schema::RecordKind::from_value(&record.fields()[1], &path.index(1))?;
                Ok(Reference::local(target, kind))
            }
            PINNED_REF if record.fields().len() == 3 => {
                let target = crate::ids::RecordId::from_value(&record.fields()[0], &path.index(0))?;
                let revision =
                    crate::ids::RevisionId::from_value(&record.fields()[1], &path.index(1))?;
                let kind =
                    crate::schema::RecordKind::from_value(&record.fields()[2], &path.index(2))?;
                Ok(Reference::pinned(target, revision, kind))
            }
            EXTERNAL_REF if record.fields().len() == 2 => {
                let locator = record.fields()[0].as_string().ok_or_else(type_error)?;
                let kind =
                    crate::schema::RecordKind::from_value(&record.fields()[1], &path.index(1))?;
                Reference::external(locator, kind).map_err(|message| {
                    crate::error::Diagnostic::new(
                        crate::error::Stage::Domain,
                        crate::error::ErrorCode::InvalidIdentifier,
                        path.clone(),
                        message,
                    )
                })
            }
            UNRESOLVED_REF if record.fields().len() == 3 => {
                let target = crate::ids::RecordId::from_value(&record.fields()[0], &path.index(0))?;
                let kind =
                    crate::schema::RecordKind::from_value(&record.fields()[1], &path.index(1))?;
                let reason = record.fields()[2].as_string().ok_or_else(type_error)?;
                Reference::unresolved(target, kind, reason).map_err(|message| {
                    crate::error::Diagnostic::new(
                        crate::error::Stage::Domain,
                        crate::error::ErrorCode::InvalidIdentifier,
                        path.clone(),
                        message,
                    )
                })
            }
            _ => Err(type_error()),
        }
    }

    /// Validate the reference against a validated snapshot.
    pub fn validate(
        &self,
        index: &SnapshotIndex,
        path: &crate::error::Path,
    ) -> Result<(), crate::error::Diagnostic> {
        match self {
            Reference::Local { target, kind } => {
                resolve(index, *target, *kind, path)?;
            }
            Reference::Pinned {
                target,
                revision,
                kind,
            } => {
                let entry = resolve(index, *target, *kind, path)?;
                if entry.revision != *revision && !index.knows_revision(target, revision) {
                    return Err(crate::error::Diagnostic::new(
                        crate::error::Stage::Domain,
                        crate::error::ErrorCode::UnresolvedReference,
                        path.clone(),
                        format!(
                            "pinned revision {revision} is not present in the validated snapshot"
                        ),
                    ));
                }
            }
            Reference::External { .. } | Reference::Unresolved { .. } => {}
        }
        Ok(())
    }
}

fn resolve<'a>(
    index: &'a SnapshotIndex,
    target: crate::ids::RecordId,
    kind: crate::schema::RecordKind,
    path: &crate::error::Path,
) -> Result<&'a RevisionEntry, crate::error::Diagnostic> {
    let entry = index.get(&target).ok_or_else(|| {
        crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::UnresolvedReference,
            path.clone(),
            format!("reference target {target} is not present in the validated snapshot"),
        )
    })?;
    if entry.kind != kind {
        return Err(crate::error::Diagnostic::new(
            crate::error::Stage::Domain,
            crate::error::ErrorCode::ReferenceKindMismatch,
            path.clone(),
            format!(
                "reference expects kind {}, but {target} is {}",
                kind.symbol(),
                entry.kind.symbol()
            ),
        ));
    }
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: u8) -> crate::ids::RecordId {
        crate::ids::RecordId::from_bytes([byte; 16])
    }

    fn revision(byte: u8) -> crate::ids::RevisionId {
        crate::ids::RevisionId::from_bytes([byte; 16])
    }

    #[test]
    fn all_reference_forms_roundtrip() {
        let references = [
            Reference::local(id(1), crate::schema::RecordKind::Entity),
            Reference::pinned(id(2), revision(3), crate::schema::RecordKind::Assertion),
            Reference::external(
                "https://example.invalid/doc",
                crate::schema::RecordKind::Document,
            )
            .expect("locator"),
            Reference::unresolved(id(4), crate::schema::RecordKind::Entity, "merge pending")
                .expect("reason"),
        ];
        for reference in references {
            assert_eq!(
                Reference::from_value(&reference.to_value(), &crate::error::Path::root())
                    .expect("decode"),
                reference
            );
        }
    }

    #[test]
    fn local_reference_requires_a_present_target_of_the_declared_kind() {
        let mut index = SnapshotIndex::new();
        assert!(index.insert(id(1), crate::schema::RecordKind::Entity, revision(10)));
        let good = Reference::local(id(1), crate::schema::RecordKind::Entity);
        good.validate(&index, &crate::error::Path::root())
            .expect("resolves");
        let mismatch = Reference::local(id(1), crate::schema::RecordKind::Assertion);
        assert_eq!(
            mismatch
                .validate(&index, &crate::error::Path::root())
                .expect_err("kind mismatch")
                .code,
            crate::error::ErrorCode::ReferenceKindMismatch
        );
        let missing = Reference::local(id(9), crate::schema::RecordKind::Entity);
        assert_eq!(
            missing
                .validate(&index, &crate::error::Path::root())
                .expect_err("missing")
                .code,
            crate::error::ErrorCode::UnresolvedReference
        );
    }

    #[test]
    fn pinned_revision_must_be_known() {
        let mut index = SnapshotIndex::new();
        assert!(index.insert(id(1), crate::schema::RecordKind::Document, revision(10)));
        index.record_revision(id(1), revision(9));
        Reference::pinned(id(1), revision(10), crate::schema::RecordKind::Document)
            .validate(&index, &crate::error::Path::root())
            .expect("current revision");
        Reference::pinned(id(1), revision(9), crate::schema::RecordKind::Document)
            .validate(&index, &crate::error::Path::root())
            .expect("retained revision");
        assert_eq!(
            Reference::pinned(id(1), revision(8), crate::schema::RecordKind::Document)
                .validate(&index, &crate::error::Path::root())
                .expect_err("unknown revision")
                .code,
            crate::error::ErrorCode::UnresolvedReference
        );
    }

    #[test]
    fn external_and_unresolved_references_carry_explicit_state() {
        assert!(
            Reference::external("", crate::schema::RecordKind::Entity).is_err(),
            "empty locators are invalid"
        );
        assert!(
            Reference::unresolved(id(1), crate::schema::RecordKind::Entity, " ").is_err(),
            "empty reasons are invalid"
        );
        assert!(
            Reference::external("urn:example:thing", crate::schema::RecordKind::Entity)
                .expect("locator")
                .is_external()
        );
        assert!(
            Reference::unresolved(id(1), crate::schema::RecordKind::Entity, "pending")
                .expect("reason")
                .is_unresolved()
        );
    }
}
