//! The committed workspace manifest.
//!
//! A manifest names the workspace revision, its parent, every current record
//! revision, and every blob the revision requires. It is encoded with canonical
//! Preserves binary and hashed with the payload profile. The ledger stores the
//! digest, not a copy of the bytes: the same value is rebuilt from the stored
//! snapshot membership and required-digest journal whenever a read verifies a
//! revision.
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
    pub parents: std::collections::BTreeSet<mneme_core::WorkspaceRevisionId>,
    pub records: std::collections::BTreeSet<ManifestRecord>,
    pub blobs: std::collections::BTreeSet<mneme_core::ContentDigest>,
}

impl Manifest {
    /// Construct an empty genesis manifest.
    pub fn genesis(revision: mneme_core::WorkspaceRevisionId) -> Self {
        Manifest {
            revision,
            parents: std::collections::BTreeSet::new(),
            records: std::collections::BTreeSet::new(),
            blobs: std::collections::BTreeSet::new(),
        }
    }

    /// Canonical single parent, if at least one parent is present.
    pub fn parent(&self) -> Option<mneme_core::WorkspaceRevisionId> {
        self.parents.iter().next().copied()
    }

    /// Encode as `<workspace-manifest …>`.
    ///
    /// Zero or one parent encodes identically to v1 (`none` or
    /// `<workspace-revision-id>`); multi-parent merge manifests encode field 1
    /// as a canonical sorted Preserves set.
    pub fn to_value(&self) -> mneme_core::Value {
        let parents = if self.parents.is_empty() {
            mneme_core::Value::symbol("none")
        } else if self.parents.len() == 1 {
            match self.parents.iter().next() {
                Some(revision) => revision.to_value(),
                None => mneme_core::Value::symbol("none"),
            }
        } else {
            mneme_core::Value::set(self.parents.iter().map(|revision| revision.to_value()))
        };
        mneme_core::Value::record_named(
            "workspace-manifest",
            vec![
                self.revision.to_value(),
                parents,
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
        let parents = parse_manifest_parents(&record.fields()[1])?;
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
            parents,
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
        self.digest_with(mneme_core::HashAlgorithm::default())
    }

    /// Content digest over the manifest value using an explicit hash algorithm.
    pub fn digest_with(&self, algorithm: mneme_core::HashAlgorithm) -> mneme_core::ContentDigest {
        mneme_core::ContentDigest::of_payload_with(&self.to_value(), algorithm)
    }
}

fn parse_manifest_parents(
    value: &mneme_core::Value,
) -> Result<std::collections::BTreeSet<mneme_core::WorkspaceRevisionId>, String> {
    let path = mneme_core::Path::root().field("parent");
    match value {
        mneme_core::Value::Symbol(symbol) if symbol.as_str() == "none" => {
            Ok(std::collections::BTreeSet::new())
        }
        mneme_core::Value::Set(items) => {
            let mut parents = std::collections::BTreeSet::new();
            for item in items {
                let rev = mneme_core::WorkspaceRevisionId::from_value(item, &path)
                    .map_err(|diagnostic| diagnostic.to_string())?;
                parents.insert(rev);
            }
            Ok(parents)
        }
        other => {
            let rev = mneme_core::WorkspaceRevisionId::from_value(other, &path)
                .map_err(|diagnostic| diagnostic.to_string())?;
            Ok(std::collections::BTreeSet::from([rev]))
        }
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
            parents: std::collections::BTreeSet::from([parent]),
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
        manifest.parents.clear();
        assert_ne!(decoded, manifest);

        // Multi-parent merge manifest roundtrips cleanly.
        let parent_b = mneme_core::WorkspaceRevisionId::from_bytes([9; 16]);
        let multi = Manifest {
            revision,
            parents: std::collections::BTreeSet::from([parent, parent_b]),
            records: decoded.records.clone(),
            blobs: decoded.blobs.clone(),
        };
        let decoded_multi = Manifest::from_value(&multi.to_value()).expect("decode multi");
        assert_eq!(decoded_multi, multi);
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
            parents: std::collections::BTreeSet::new(),
            records: records.clone(),
            blobs: std::collections::BTreeSet::new(),
        };
        let right = Manifest {
            revision,
            parents: std::collections::BTreeSet::new(),
            records: records.into_iter().rev().collect(),
            blobs: std::collections::BTreeSet::new(),
        };
        assert_eq!(left.encode(), right.encode());
        assert_eq!(left.digest(), right.digest());
    }
}
