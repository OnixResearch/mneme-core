//! The committed workspace manifest.
//!
//! A manifest names the workspace revision, its parent, every current record
//! revision, and every blob the revision requires. It is encoded with canonical
//! Preserves binary and hashed with the payload profile; the ledger stores both
//! the bytes and the digest.

use std::collections::BTreeSet;

use mneme_core::{
    ContentDigest, RecordId, RecordKind, RevisionId, Value, WorkspaceRevisionId, binary,
};

/// One record revision included in a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestRecord {
    pub record_id: RecordId,
    pub revision_id: RevisionId,
    pub kind: RecordKind,
}

/// A complete manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub revision: WorkspaceRevisionId,
    pub parent: Option<WorkspaceRevisionId>,
    pub records: BTreeSet<ManifestRecord>,
    pub blobs: BTreeSet<ContentDigest>,
}

impl Manifest {
    /// Construct an empty genesis manifest.
    pub fn genesis(revision: WorkspaceRevisionId) -> Self {
        Manifest {
            revision,
            parent: None,
            records: BTreeSet::new(),
            blobs: BTreeSet::new(),
        }
    }

    /// Encode as `<workspace-manifest …>`.
    pub fn to_value(&self) -> Value {
        let parent = match self.parent {
            Some(revision) => revision.to_value(),
            None => Value::symbol("none"),
        };
        Value::record_named(
            "workspace-manifest",
            vec![
                self.revision.to_value(),
                parent,
                Value::set(self.records.iter().map(record_value)),
                Value::set(self.blobs.iter().map(|digest| digest.to_value())),
            ],
        )
    }

    /// Decode a manifest value.
    pub fn from_value(value: &Value) -> Result<Self, String> {
        let record = value
            .as_record()
            .ok_or_else(|| "manifest must be a record".to_owned())?;
        if record.label() != &Value::symbol("workspace-manifest") || record.fields().len() != 4 {
            return Err("expected <workspace-manifest revision parent records blobs>".to_owned());
        }
        let revision = WorkspaceRevisionId::from_value(
            &record.fields()[0],
            &mneme_core::Path::root().field("revision"),
        )
        .map_err(|diagnostic| diagnostic.to_string())?;
        let parent = match &record.fields()[1] {
            Value::Symbol(symbol) if symbol.as_str() == "none" => None,
            other => Some(
                WorkspaceRevisionId::from_value(other, &mneme_core::Path::root().field("parent"))
                    .map_err(|diagnostic| diagnostic.to_string())?,
            ),
        };
        let Some(record_values) = record.fields()[2].as_set() else {
            return Err("manifest records must be a set".to_owned());
        };
        let mut records = BTreeSet::new();
        for item in record_values {
            records.insert(parse_manifest_record(item)?);
        }
        let Some(blob_values) = record.fields()[3].as_set() else {
            return Err("manifest blobs must be a set".to_owned());
        };
        let mut blobs = BTreeSet::new();
        for item in blob_values {
            blobs.insert(
                ContentDigest::from_value(item, &mneme_core::Path::root().field("blobs"))
                    .map_err(|diagnostic| diagnostic.to_string())?,
            );
        }
        Ok(Manifest {
            revision,
            parent,
            records,
            blobs,
        })
    }

    /// Canonical binary bytes.
    pub fn encode(&self) -> Vec<u8> {
        binary::encode(&self.to_value())
    }

    /// Content digest over the manifest value.
    pub fn digest(&self) -> ContentDigest {
        ContentDigest::of_payload(&self.to_value())
    }
}

fn record_value(record: &ManifestRecord) -> Value {
    Value::record_named(
        "manifest-record",
        vec![
            record.record_id.to_value(),
            record.revision_id.to_value(),
            record.kind.to_value(),
        ],
    )
}

fn parse_manifest_record(value: &Value) -> Result<ManifestRecord, String> {
    let record = value
        .as_record()
        .ok_or_else(|| "manifest record entry must be a record".to_owned())?;
    if record.label() != &Value::symbol("manifest-record") || record.fields().len() != 3 {
        return Err("expected <manifest-record record-id revision-id kind>".to_owned());
    }
    Ok(ManifestRecord {
        record_id: RecordId::from_value(
            &record.fields()[0],
            &mneme_core::Path::root().field("record"),
        )
        .map_err(|diagnostic| diagnostic.to_string())?,
        revision_id: RevisionId::from_value(
            &record.fields()[1],
            &mneme_core::Path::root().field("revision"),
        )
        .map_err(|diagnostic| diagnostic.to_string())?,
        kind: RecordKind::from_value(&record.fields()[2], &mneme_core::Path::root().field("kind"))
            .map_err(|diagnostic| diagnostic.to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrips_with_records_and_blobs() {
        let revision = WorkspaceRevisionId::from_bytes([1; 16]);
        let parent = WorkspaceRevisionId::from_bytes([2; 16]);
        let mut manifest = Manifest {
            revision,
            parent: Some(parent),
            records: BTreeSet::from([ManifestRecord {
                record_id: RecordId::from_bytes([3; 16]),
                revision_id: RevisionId::from_bytes([4; 16]),
                kind: RecordKind::Assertion,
            }]),
            blobs: BTreeSet::from([ContentDigest::of_source_bytes(b"bytes")]),
        };
        let decoded = Manifest::from_value(&manifest.to_value()).expect("decode");
        assert_eq!(decoded, manifest);
        assert_eq!(
            Manifest::from_value(&decoded.to_value()).expect("redecode"),
            manifest
        );
        manifest.parent = None;
        assert_ne!(decoded, manifest);
    }

    #[test]
    fn manifest_digest_is_order_independent() {
        let revision = WorkspaceRevisionId::from_bytes([1; 16]);
        let records = BTreeSet::from([
            ManifestRecord {
                record_id: RecordId::from_bytes([3; 16]),
                revision_id: RevisionId::from_bytes([4; 16]),
                kind: RecordKind::Entity,
            },
            ManifestRecord {
                record_id: RecordId::from_bytes([5; 16]),
                revision_id: RevisionId::from_bytes([6; 16]),
                kind: RecordKind::Relation,
            },
        ]);
        let left = Manifest {
            revision,
            parent: None,
            records: records.clone(),
            blobs: BTreeSet::new(),
        };
        let right = Manifest {
            revision,
            parent: None,
            records: records.into_iter().rev().collect(),
            blobs: BTreeSet::new(),
        };
        assert_eq!(left.encode(), right.encode());
        assert_eq!(left.digest(), right.digest());
    }
}
