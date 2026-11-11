//! Explicit typed references and the snapshot index used to validate them.
//!
//! A reference names a target record identity and its expected kind. It may pin
//! an exact revision, name an external target explicitly, or carry a typed
//! unresolved state when the owning schema permits one. Validation against a
//! snapshot index rejects missing targets, kind mismatches, and pinned
//! revisions the snapshot does not contain.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{Diagnostic, ErrorCode, Path, Stage};
use crate::ids::{RecordId, RevisionId};
use crate::schema::RecordKind;
use crate::value::Value;

const LOCAL_REF: &str = "local-ref";
const PINNED_REF: &str = "pinned-ref";
const EXTERNAL_REF: &str = "external-ref";
const UNRESOLVED_REF: &str = "unresolved-ref";

/// The current kind and revision of one record in a validated snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RevisionEntry {
    pub kind: RecordKind,
    pub revision: RevisionId,
}

/// Record identities and revisions known to one validated snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotIndex {
    current: BTreeMap<RecordId, RevisionEntry>,
    revisions: BTreeSet<(RecordId, RevisionId)>,
}

impl SnapshotIndex {
    /// An empty index.
    pub fn new() -> Self {
        SnapshotIndex::default()
    }

    /// Insert a current record. Returns `false` when the identity is already
    /// present; a snapshot cannot contain two current revisions of one record.
    pub fn insert(&mut self, record: RecordId, kind: RecordKind, revision: RevisionId) -> bool {
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
        record: RecordId,
        kind: RecordKind,
        revision: RevisionId,
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
    pub fn record_revision(&mut self, record: RecordId, revision: RevisionId) {
        self.revisions.insert((record, revision));
    }

    /// The current entry for a record identity.
    pub fn get(&self, record: &RecordId) -> Option<&RevisionEntry> {
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
    pub fn knows_revision(&self, record: &RecordId, revision: &RevisionId) -> bool {
        self.revisions.contains(&(*record, *revision))
    }

    /// Iterate over current records.
    pub fn iter(&self) -> impl Iterator<Item = (&RecordId, &RevisionEntry)> + '_ {
        self.current.iter()
    }
}

/// An explicit application reference.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reference {
    /// A target resolved within the pinned snapshot, without a revision pin.
    Local { target: RecordId, kind: RecordKind },
    /// A target pinned to one immutable record revision.
    Pinned {
        target: RecordId,
        revision: RevisionId,
        kind: RecordKind,
    },
    /// A target outside the local workspace, explicitly marked external.
    External { locator: String, kind: RecordKind },
    /// A typed unresolved state permitted only where the schema says so.
    Unresolved {
        target: RecordId,
        kind: RecordKind,
        reason: String,
    },
}

impl Reference {
    /// A snapshot-local reference.
    pub fn local(target: RecordId, kind: RecordKind) -> Self {
        Reference::Local { target, kind }
    }

    /// A revision-pinned reference.
    pub fn pinned(target: RecordId, revision: RevisionId, kind: RecordKind) -> Self {
        Reference::Pinned {
            target,
            revision,
            kind,
        }
    }

    /// An explicitly external reference.
    pub fn external(locator: impl Into<String>, kind: RecordKind) -> Result<Self, &'static str> {
        let locator = locator.into();
        if locator.trim().is_empty() {
            return Err("external reference requires a non-empty locator");
        }
        Ok(Reference::External { locator, kind })
    }

    /// A typed unresolved reference with an explicit reason.
    pub fn unresolved(
        target: RecordId,
        kind: RecordKind,
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
    pub const fn kind(&self) -> RecordKind {
        match self {
            Reference::Local { kind, .. }
            | Reference::Pinned { kind, .. }
            | Reference::External { kind, .. }
            | Reference::Unresolved { kind, .. } => *kind,
        }
    }

    /// The target identity, if the reference names a local record.
    pub fn target(&self) -> Option<RecordId> {
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
    pub fn to_value(&self) -> Value {
        match self {
            Reference::Local { target, kind } => {
                Value::record_named(LOCAL_REF, vec![target.to_value(), kind.to_value()])
            }
            Reference::Pinned {
                target,
                revision,
                kind,
            } => Value::record_named(
                PINNED_REF,
                vec![target.to_value(), revision.to_value(), kind.to_value()],
            ),
            Reference::External { locator, kind } => Value::record_named(
                EXTERNAL_REF,
                vec![Value::string(locator.clone()), kind.to_value()],
            ),
            Reference::Unresolved {
                target,
                kind,
                reason,
            } => Value::record_named(
                UNRESOLVED_REF,
                vec![
                    target.to_value(),
                    kind.to_value(),
                    Value::string(reason.clone()),
                ],
            ),
        }
    }

    /// Decode a reference record.
    pub fn from_value(value: &Value, path: &Path) -> Result<Self, Diagnostic> {
        let type_error = || {
            Diagnostic::new(
                Stage::Domain,
                ErrorCode::TypeMismatch,
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
                let target = RecordId::from_value(&record.fields()[0], &path.index(0))?;
                let kind = RecordKind::from_value(&record.fields()[1], &path.index(1))?;
                Ok(Reference::local(target, kind))
            }
            PINNED_REF if record.fields().len() == 3 => {
                let target = RecordId::from_value(&record.fields()[0], &path.index(0))?;
                let revision = RevisionId::from_value(&record.fields()[1], &path.index(1))?;
                let kind = RecordKind::from_value(&record.fields()[2], &path.index(2))?;
                Ok(Reference::pinned(target, revision, kind))
            }
            EXTERNAL_REF if record.fields().len() == 2 => {
                let locator = record.fields()[0].as_string().ok_or_else(type_error)?;
                let kind = RecordKind::from_value(&record.fields()[1], &path.index(1))?;
                Reference::external(locator, kind).map_err(|message| {
                    Diagnostic::new(
                        Stage::Domain,
                        ErrorCode::InvalidIdentifier,
                        path.clone(),
                        message,
                    )
                })
            }
            UNRESOLVED_REF if record.fields().len() == 3 => {
                let target = RecordId::from_value(&record.fields()[0], &path.index(0))?;
                let kind = RecordKind::from_value(&record.fields()[1], &path.index(1))?;
                let reason = record.fields()[2].as_string().ok_or_else(type_error)?;
                Reference::unresolved(target, kind, reason).map_err(|message| {
                    Diagnostic::new(
                        Stage::Domain,
                        ErrorCode::InvalidIdentifier,
                        path.clone(),
                        message,
                    )
                })
            }
            _ => Err(type_error()),
        }
    }

    /// Validate the reference against a validated snapshot.
    pub fn validate(&self, index: &SnapshotIndex, path: &Path) -> Result<(), Diagnostic> {
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
                    return Err(Diagnostic::new(
                        Stage::Domain,
                        ErrorCode::UnresolvedReference,
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
    target: RecordId,
    kind: RecordKind,
    path: &Path,
) -> Result<&'a RevisionEntry, Diagnostic> {
    let entry = index.get(&target).ok_or_else(|| {
        Diagnostic::new(
            Stage::Domain,
            ErrorCode::UnresolvedReference,
            path.clone(),
            format!("reference target {target} is not present in the validated snapshot"),
        )
    })?;
    if entry.kind != kind {
        return Err(Diagnostic::new(
            Stage::Domain,
            ErrorCode::ReferenceKindMismatch,
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

    fn id(byte: u8) -> RecordId {
        RecordId::from_bytes([byte; 16])
    }

    fn revision(byte: u8) -> RevisionId {
        RevisionId::from_bytes([byte; 16])
    }

    #[test]
    fn all_reference_forms_roundtrip() {
        let references = [
            Reference::local(id(1), RecordKind::Entity),
            Reference::pinned(id(2), revision(3), RecordKind::Assertion),
            Reference::external("https://example.invalid/doc", RecordKind::Document)
                .expect("locator"),
            Reference::unresolved(id(4), RecordKind::Entity, "merge pending").expect("reason"),
        ];
        for reference in references {
            assert_eq!(
                Reference::from_value(&reference.to_value(), &Path::root()).expect("decode"),
                reference
            );
        }
    }

    #[test]
    fn local_reference_requires_a_present_target_of_the_declared_kind() {
        let mut index = SnapshotIndex::new();
        assert!(index.insert(id(1), RecordKind::Entity, revision(10)));
        let good = Reference::local(id(1), RecordKind::Entity);
        good.validate(&index, &Path::root()).expect("resolves");
        let mismatch = Reference::local(id(1), RecordKind::Assertion);
        assert_eq!(
            mismatch
                .validate(&index, &Path::root())
                .expect_err("kind mismatch")
                .code,
            ErrorCode::ReferenceKindMismatch
        );
        let missing = Reference::local(id(9), RecordKind::Entity);
        assert_eq!(
            missing
                .validate(&index, &Path::root())
                .expect_err("missing")
                .code,
            ErrorCode::UnresolvedReference
        );
    }

    #[test]
    fn pinned_revision_must_be_known() {
        let mut index = SnapshotIndex::new();
        assert!(index.insert(id(1), RecordKind::Document, revision(10)));
        index.record_revision(id(1), revision(9));
        Reference::pinned(id(1), revision(10), RecordKind::Document)
            .validate(&index, &Path::root())
            .expect("current revision");
        Reference::pinned(id(1), revision(9), RecordKind::Document)
            .validate(&index, &Path::root())
            .expect("retained revision");
        assert_eq!(
            Reference::pinned(id(1), revision(8), RecordKind::Document)
                .validate(&index, &Path::root())
                .expect_err("unknown revision")
                .code,
            ErrorCode::UnresolvedReference
        );
    }

    #[test]
    fn external_and_unresolved_references_carry_explicit_state() {
        assert!(
            Reference::external("", RecordKind::Entity).is_err(),
            "empty locators are invalid"
        );
        assert!(
            Reference::unresolved(id(1), RecordKind::Entity, " ").is_err(),
            "empty reasons are invalid"
        );
        assert!(
            Reference::external("urn:example:thing", RecordKind::Entity)
                .expect("locator")
                .is_external()
        );
        assert!(
            Reference::unresolved(id(1), RecordKind::Entity, "pending")
                .expect("reason")
                .is_unresolved()
        );
    }
}
