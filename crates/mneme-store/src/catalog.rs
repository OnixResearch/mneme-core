//! The committed workspace manifest.
//!
//! A manifest names the workspace revision, its parent, every current record
//! revision, and every blob the revision requires. It is encoded with canonical
//! Preserves binary and hashed with the payload profile; the ledger stores both
//! the bytes and the digest.
#![allow(unknown_lints, module_file_count)] // documented boundary allowance
// Octet structural exception: domain-qualified names and macro-only imports are intentional

/// One record revision included in a manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestRecord {
    pub record_id: mneme_core::RecordId,
    pub revision_id: mneme_core::RevisionId,
    pub kind: mneme_core::RecordKind,
}

/// A complete manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub revision: mneme_core::WorkspaceRevisionId,
    pub parent: Option<mneme_core::WorkspaceRevisionId>,
    pub records: std::collections::BTreeSet<ManifestRecord>,
    pub blobs: std::collections::BTreeSet<mneme_core::ContentDigest>,
}

impl Manifest {
    /// Construct an empty genesis manifest.
    pub fn genesis(revision: mneme_core::WorkspaceRevisionId) -> Self {
        Manifest {
            revision,
            parent: None,
            records: std::collections::BTreeSet::new(),
            blobs: std::collections::BTreeSet::new(),
        }
    }

    /// Encode as `<workspace-manifest …>`.
    pub fn to_value(&self) -> mneme_core::Value {
        let parent = match self.parent {
            Some(revision) => revision.to_value(),
            None => mneme_core::Value::symbol("none"),
        };
        mneme_core::Value::record_named(
            "workspace-manifest",
            vec![
                self.revision.to_value(),
                parent,
                mneme_core::Value::set(self.records.iter().map(record_value)),
                mneme_core::Value::set(self.blobs.iter().map(|digest| digest.to_value())),
            ],
        )
    }

    /// Decode a manifest value.
    pub fn from_value(value: &mneme_core::Value) -> Result<Self, String> {
        let record = value
            .as_record()
            .ok_or_else(|| "manifest must be a record".to_owned())?;
        if record.label() != &mneme_core::Value::symbol("workspace-manifest")
            || record.fields().len() != 4
        {
            return Err("expected <workspace-manifest revision parent records blobs>".to_owned());
        }
        let revision = mneme_core::WorkspaceRevisionId::from_value(
            &record.fields()[0],
            &mneme_core::Path::root().field("revision"),
        )
        .map_err(|diagnostic| diagnostic.to_string())?;
        let parent = match &record.fields()[1] {
            mneme_core::Value::Symbol(symbol) if symbol.as_str() == "none" => None,
            other => Some(
                mneme_core::WorkspaceRevisionId::from_value(
                    other,
                    &mneme_core::Path::root().field("parent"),
                )
                .map_err(|diagnostic| diagnostic.to_string())?,
            ),
        };
        let Some(record_values) = record.fields()[2].as_set() else {
            return Err("manifest records must be a set".to_owned());
        };
        let mut records = std::collections::BTreeSet::new();
        for item in record_values {
            records.insert(parse_manifest_record(item)?);
        }
        let Some(blob_values) = record.fields()[3].as_set() else {
            return Err("manifest blobs must be a set".to_owned());
        };
        let mut blobs = std::collections::BTreeSet::new();
        for item in blob_values {
            blobs.insert(
                mneme_core::ContentDigest::from_value(
                    item,
                    &mneme_core::Path::root().field("blobs"),
                )
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
        mneme_core::binary::encode(&self.to_value())
    }

    /// Content digest over the manifest value.
    pub fn digest(&self) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_payload(&self.to_value())
    }
}

fn record_value(record: &ManifestRecord) -> mneme_core::Value {
    mneme_core::Value::record_named(
        "manifest-record",
        vec![
            record.record_id.to_value(),
            record.revision_id.to_value(),
            record.kind.to_value(),
        ],
    )
}

fn parse_manifest_record(value: &mneme_core::Value) -> Result<ManifestRecord, String> {
    let record = value
        .as_record()
        .ok_or_else(|| "manifest record entry must be a record".to_owned())?;
    if record.label() != &mneme_core::Value::symbol("manifest-record") || record.fields().len() != 3
    {
        return Err("expected <manifest-record record-id revision-id kind>".to_owned());
    }
    Ok(ManifestRecord {
        record_id: mneme_core::RecordId::from_value(
            &record.fields()[0],
            &mneme_core::Path::root().field("record"),
        )
        .map_err(|diagnostic| diagnostic.to_string())?,
        revision_id: mneme_core::RevisionId::from_value(
            &record.fields()[1],
            &mneme_core::Path::root().field("revision"),
        )
        .map_err(|diagnostic| diagnostic.to_string())?,
        kind: mneme_core::RecordKind::from_value(
            &record.fields()[2],
            &mneme_core::Path::root().field("kind"),
        )
        .map_err(|diagnostic| diagnostic.to_string())?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrips_with_records_and_blobs() {
        let revision = mneme_core::WorkspaceRevisionId::from_bytes([1; 16]);
        let parent = mneme_core::WorkspaceRevisionId::from_bytes([2; 16]);
        let mut manifest = Manifest {
            revision,
            parent: Some(parent),
            records: std::collections::BTreeSet::from([ManifestRecord {
                record_id: mneme_core::RecordId::from_bytes([3; 16]),
                revision_id: mneme_core::RevisionId::from_bytes([4; 16]),
                kind: mneme_core::RecordKind::Assertion,
            }]),
            blobs: std::collections::BTreeSet::from([mneme_core::ContentDigest::of_source_bytes(
                b"bytes",
            )]),
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
        let revision = mneme_core::WorkspaceRevisionId::from_bytes([1; 16]);
        let records = std::collections::BTreeSet::from([
            ManifestRecord {
                record_id: mneme_core::RecordId::from_bytes([3; 16]),
                revision_id: mneme_core::RevisionId::from_bytes([4; 16]),
                kind: mneme_core::RecordKind::Entity,
            },
            ManifestRecord {
                record_id: mneme_core::RecordId::from_bytes([5; 16]),
                revision_id: mneme_core::RevisionId::from_bytes([6; 16]),
                kind: mneme_core::RecordKind::Relation,
            },
        ]);
        let left = Manifest {
            revision,
            parent: None,
            records: records.clone(),
            blobs: std::collections::BTreeSet::new(),
        };
        let right = Manifest {
            revision,
            parent: None,
            records: records.into_iter().rev().collect(),
            blobs: std::collections::BTreeSet::new(),
        };
        assert_eq!(left.encode(), right.encode());
        assert_eq!(left.digest(), right.digest());
    }
}
