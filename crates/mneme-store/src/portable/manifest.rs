//! The typed, bounded manifest of one portable vault archive.
//!
//! The manifest is canonical Preserves. It names the exported scope, the
//! workspace state the export pinned, every included record revision with the
//! workspace commit that introduced it, the current revision of each included
//! record, every exact source blob the included revisions retain, and the
//! retention decisions an imported copy must keep. Blob bytes live in the
//! archive body, never in the manifest.
//!
//! Parsing is structural; [`PortableManifest::validate`] then re-runs the
//! engine's envelope validator and checks the closure between histories,
//! current records, blobs, and retention decisions. An archive that cannot be
//! restored is refused before any destination is written.

use crate::error::Failure;
use crate::portable::{
    MAX_PORTABLE_BLOBS, MAX_PORTABLE_BLOB_BYTES, MAX_PORTABLE_RECORDS,
    MAX_PORTABLE_REVISIONS, PORTABLE_ARCHIVE_FORMAT, PORTABLE_ARCHIVE_VERSION, PortableBlob,
    PortableCurrent, PortableManifest, PortableOmission, PortablePruning, PortableRecord,
    PortableRevision, PortableSuppression,
};

/// A manifest-shaped failure.
pub(super) fn invalid(message: impl Into<String>) -> Failure {
    Failure::PortableArchive(message.into())
}

/// Read a record with an exact label and field count.
fn record_fields<'a>(
    value: &'a mneme_core::Value,
    label: &str,
    count: usize,
) -> crate::error::Result<&'a [mneme_core::Value]> {
    let record = value
        .as_record()
        .ok_or_else(|| invalid(format!("expected a <{label} …> record")))?;
    if record.label() != &mneme_core::Value::symbol(label) || record.fields().len() != count {
        return Err(invalid(format!(
            "expected <{label} …> with {count} fields"
        )));
    }
    Ok(record.fields())
}

/// Read a bounded sequence.
fn sequence<'a>(
    value: &'a mneme_core::Value,
    what: &str,
    max: usize,
) -> crate::error::Result<&'a [mneme_core::Value]> {
    let items = value
        .as_sequence()
        .ok_or_else(|| invalid(format!("{what} must be a sequence")))?;
    if items.len() > max {
        return Err(Failure::HistoryLimitExceeded);
    }
    Ok(items)
}

/// Read a non-negative integer as `u64`.
fn unsigned(value: &mneme_core::Value, what: &str) -> crate::error::Result<u64> {
    value
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .and_then(|integer| u64::try_from(integer).ok())
        .ok_or_else(|| invalid(format!("{what} must be a non-negative integer")))
}

/// Read a signed integer as `i64`.
fn signed(value: &mneme_core::Value, what: &str) -> crate::error::Result<i64> {
    value
        .as_integer()
        .and_then(|integer| integer.to_i64())
        .ok_or_else(|| invalid(format!("{what} must be a signed integer")))
}

/// Read a string field.
fn text<'a>(value: &'a mneme_core::Value, what: &str) -> crate::error::Result<&'a str> {
    value
        .as_string()
        .ok_or_else(|| invalid(format!("{what} must be text")))
}

/// Whether a value is the `none` symbol.
fn is_none(value: &mneme_core::Value) -> bool {
    value
        .as_symbol()
        .is_some_and(|symbol| symbol.as_str() == "none")
}

/// Decode an optional revision identity.
fn optional_revision(
    value: &mneme_core::Value,
    what: &str,
) -> crate::error::Result<Option<mneme_core::RevisionId>> {
    if is_none(value) {
        return Ok(None);
    }
    mneme_core::RevisionId::from_value(value, &mneme_core::Path::root().field(what))
        .map(Some)
        .map_err(|diagnostic| invalid(format!("{what}: {diagnostic}")))
}

/// Decode a scope identity.
fn scope(value: &mneme_core::Value) -> crate::error::Result<mneme_core::ScopeId> {
    mneme_core::ScopeId::from_value(value, &mneme_core::Path::root().field("scope"))
        .map_err(|diagnostic| invalid(format!("scope: {diagnostic}")))
}

/// Decode a content digest.
fn digest(value: &mneme_core::Value, what: &str) -> crate::error::Result<mneme_core::ContentDigest> {
    mneme_core::ContentDigest::from_value(value, &mneme_core::Path::root().field(what))
        .map_err(|diagnostic| invalid(format!("{what}: {diagnostic}")))
}

/// Whether a digest names exact source bytes.
fn require_source_digest(
    value: &mneme_core::ContentDigest,
    what: &str,
) -> crate::error::Result<()> {
    if value.profile() != mneme_core::EncodingProfile::RawBytesV1
        || value.boundary() != mneme_core::ValueBoundary::SourceBytes
    {
        return Err(invalid(format!(
            "{what} must be a raw source-byte digest"
        )));
    }
    Ok(())
}

/// Decode a bounded opaque label.
fn label(value: &mneme_core::Value, what: &str) -> crate::error::Result<String> {
    let symbol = value
        .as_symbol()
        .ok_or_else(|| invalid(format!("{what} must be a symbol")))?;
    let text = symbol.as_str();
    if text.is_empty()
        || text.len() > 64
        || !text
            .bytes()
            .all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
            })
    {
        return Err(invalid(format!(
            "{what} must be 1-64 lowercase ASCII letters, digits, hyphens or underscores"
        )));
    }
    Ok(text.to_owned())
}

/// Decode a retained source description from one envelope.
fn retained_source(
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<Option<mneme_core::RetainedSource>> {
    if record.kind != mneme_core::RecordKind::SourceRevision {
        return Ok(None);
    }
    let Some(value) = record.payload.get("content") else {
        return Ok(None);
    };
    let content = mneme_core::SourceContent::from_value(value, &mneme_core::Path::root())
        .map_err(|diagnostic| invalid(format!("source content: {diagnostic}")))?;
    match content {
        mneme_core::SourceContent::Retained(retained) => Ok(Some(retained)),
        mneme_core::SourceContent::Unavailable { .. } => Ok(None),
    }
}

impl PortableManifest {
    /// Encode as `<mneme-portable-vault …>`.
    pub(super) fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            PORTABLE_ARCHIVE_FORMAT,
            vec![
                mneme_core::Value::integer(PORTABLE_ARCHIVE_VERSION),
                self.scope.to_value(),
                self.revision.to_value(),
                mneme_core::Value::integer(self.sequence),
                mneme_core::Value::integer(self.generation),
                mneme_core::Value::sequence(
                    self.records.iter().map(PortableRecord::to_value).collect(),
                ),
                mneme_core::Value::sequence(
                    self.current.iter().map(PortableCurrent::to_value).collect(),
                ),
                mneme_core::Value::sequence(
                    self.blobs.iter().map(PortableBlob::to_value).collect(),
                ),
                mneme_core::Value::sequence(
                    self.suppressions
                        .iter()
                        .map(PortableSuppression::to_value)
                        .collect(),
                ),
                mneme_core::Value::sequence(
                    self.prunings.iter().map(PortablePruning::to_value).collect(),
                ),
                mneme_core::Value::sequence(
                    self.omissions
                        .iter()
                        .map(PortableOmission::to_value)
                        .collect(),
                ),
            ],
        )
    }

    /// Canonical binary bytes of the manifest.
    pub(super) fn encode(&self) -> Vec<u8> {
        mneme_core::binary::encode(&self.to_value())
    }

    /// Decode a structural manifest.
    pub(super) fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, PORTABLE_ARCHIVE_FORMAT, 11)?;
        let version = unsigned(&fields[0], "archive version")?;
        if version != PORTABLE_ARCHIVE_VERSION {
            return Err(Failure::UnsupportedLayout(format!(
                "portable archive version {version} is not supported"
            )));
        }
        let scope = scope(&fields[1])?;
        let revision = mneme_core::WorkspaceRevisionId::from_value(
            &fields[2],
            &mneme_core::Path::root().field("revision"),
        )
        .map_err(|diagnostic| invalid(format!("revision: {diagnostic}")))?;
        let sequence = unsigned(&fields[3], "sequence")?;
        let generation = unsigned(&fields[4], "generation")?;
        let records = sequence(&fields[5], "records", MAX_PORTABLE_RECORDS)?
            .iter()
            .map(PortableRecord::from_value)
            .collect::<crate::error::Result<Vec<_>>>()?;
        let current = sequence(&fields[6], "current records", MAX_PORTABLE_RECORDS)?
            .iter()
            .map(PortableCurrent::from_value)
            .collect::<crate::error::Result<Vec<_>>>()?;
        let blobs = sequence(&fields[7], "blobs", MAX_PORTABLE_BLOBS)?
            .iter()
            .map(PortableBlob::from_value)
            .collect::<crate::error::Result<Vec<_>>>()?;
        let suppressions = sequence(&fields[8], "suppressions", MAX_PORTABLE_REVISIONS)?
            .iter()
            .map(PortableSuppression::from_value)
            .collect::<crate::error::Result<Vec<_>>>()?;
        let prunings = sequence(&fields[9], "prunings", MAX_PORTABLE_REVISIONS)?
            .iter()
            .map(PortablePruning::from_value)
            .collect::<crate::error::Result<Vec<_>>>()?;
        let omissions = sequence(&fields[10], "omissions", 64)?
            .iter()
            .map(PortableOmission::from_value)
            .collect::<crate::error::Result<Vec<_>>>()?;
        Ok(PortableManifest {
            scope,
            revision,
            sequence,
            generation,
            records,
            current,
            blobs,
            suppressions,
            prunings,
            omissions,
        })
    }

    /// Check that this manifest is complete, closed, and restorable.
    pub(super) fn validate(&self) -> crate::error::Result<()> {
        if self.generation == 0 {
            return Err(invalid("archive generation must be at least one"));
        }
        let registry = mneme_core::SchemaRegistry::production();
        let mut revision_ids = std::collections::BTreeSet::new();
        let mut record_ids = std::collections::BTreeSet::new();
        let mut referenced = std::collections::BTreeMap::new();
        let mut revision_count = 0_usize;
        let mut previous_record: Option<mneme_core::RecordId> = None;
        for record in &self.records {
            if previous_record.is_some_and(|previous| previous >= record.record_id) {
                return Err(invalid("archive records are not in unique identity order"));
            }
            previous_record = Some(record.record_id);
            if !record_ids.insert(record.record_id) {
                return Err(invalid("archive repeats one record identity"));
            }
            if record.scope != self.scope {
                return Err(invalid("archive record is outside the exported scope"));
            }
            if record.revisions.is_empty() {
                return Err(invalid("archive record has no retained revision"));
            }
            let mut previous_sequence: Option<u64> = None;
            for revision in &record.revisions {
                revision_count = revision_count.saturating_add(1);
                if revision_count > MAX_PORTABLE_REVISIONS {
                    return Err(Failure::HistoryLimitExceeded);
                }
                let envelope = &revision.envelope;
                if envelope.record_id != record.record_id || envelope.scope != self.scope {
                    return Err(invalid(
                        "archive revision does not belong to its record and scope",
                    ));
                }
                if !revision_ids.insert(envelope.revision_id) {
                    return Err(invalid("archive repeats one record revision identity"));
                }
                if previous_sequence.is_some_and(|previous| previous >= revision.commit.sequence)
                {
                    return Err(invalid(
                        "archive record revisions are not in increasing commit order",
                    ));
                }
                previous_sequence = Some(revision.commit.sequence);
                let value = envelope.to_value();
                let validated = mneme_core::validate_record_value(&value, &registry, None)
                    .map_err(|diagnostics| {
                        invalid(format!(
                            "archive revision {} is not valid: {}",
                            envelope.revision_id,
                            mneme_core::render_diagnostics(&diagnostics)
                        ))
                    })?;
                if &validated != envelope {
                    return Err(invalid(format!(
                        "archive revision {} does not roundtrip through the record validator",
                        envelope.revision_id
                    )));
                }
                let Some(retained) = retained_source(envelope)? else {
                    continue;
                };
                require_source_digest(&retained.digest(), "retained source digest")?;
                if retained.byte_length() > MAX_PORTABLE_BLOB_BYTES {
                    return Err(Failure::HistoryLimitExceeded);
                }
                if let Some((_, length)) =
                    referenced.insert(*retained.digest().as_bytes(), retained.byte_length())
                    && length != retained.byte_length()
                {
                    return Err(invalid(
                        "archive declares conflicting lengths for one source digest",
                    ));
                }
            }
        }

        self.validate_current()?;
        self.validate_blobs(&referenced)?;
        self.validate_retention(&referenced)?;
        self.validate_omissions()?;
        Ok(())
    }

    /// Check the current-record list against every included history.
    fn validate_current(&self) -> crate::error::Result<()> {
        let mut current_records = std::collections::BTreeMap::new();
        for entry in &self.current {
            if current_records
                .insert(entry.record_id, (entry.revision_id, entry.kind))
                .is_some()
            {
                return Err(invalid("archive repeats one current record"));
            }
        }
        if current_records.len() != self.records.len() {
            return Err(invalid(
                "archive current records do not cover every included record",
            ));
        }
        for record in &self.records {
            let Some((revision, kind)) = current_records.get(&record.record_id) else {
                return Err(invalid("archive record has no current entry"));
            };
            let Some(last) = record.revisions.last() else {
                return Err(invalid("archive record has no retained revision"));
            };
            if last.envelope.revision_id != *revision || last.envelope.kind != *kind {
                return Err(invalid(
                    "archive current entry does not name the newest retained revision",
                ));
            }
        }
        Ok(())
    }

    /// Check the blob list against every retained source digest.
    fn validate_blobs(
        &self,
        referenced: &std::collections::BTreeMap<[u8; 32], u64>,
    ) -> crate::error::Result<()> {
        let mut declared = std::collections::BTreeMap::new();
        let mut previous: Option<[u8; 32]> = None;
        for blob in &self.blobs {
            require_source_digest(&blob.digest, "archive blob digest")?;
            let key = *blob.digest.as_bytes();
            if previous.is_some_and(|previous| previous >= key) {
                return Err(invalid("archive blobs are not in unique digest order"));
            }
            previous = Some(key);
            if blob.length > MAX_PORTABLE_BLOB_BYTES {
                return Err(Failure::HistoryLimitExceeded);
            }
            if declared.insert(key, blob.length).is_some() {
                return Err(invalid("archive repeats one blob"));
            }
        }
        if declared.len() != referenced.len() {
            return Err(invalid(
                "archive blob set does not match the sources its records retain",
            ));
        }
        for (key, length) in referenced {
            if declared.get(key) != Some(length) {
                return Err(invalid(
                    "archive blob length does not match the source revision that names it",
                ));
            }
        }
        Ok(())
    }

    /// Check retention decisions against the included content.
    fn validate_retention(
        &self,
        referenced: &std::collections::BTreeMap<[u8; 32], u64>,
    ) -> crate::error::Result<()> {
        let mut suppressions = std::collections::BTreeSet::new();
        for suppression in &self.suppressions {
            if suppression.generation == 0 || suppression.generation > self.generation {
                return Err(invalid(
                    "archive suppression generation is outside the archive generation",
                ));
            }
            if suppression.target_kind.is_empty()
                || suppression.target_kind.len() > 64
                || !suppression.target_kind.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'-'
                        || byte == b'_'
                })
            {
                return Err(invalid("archive suppression target kind is malformed"));
            }
            if let Some(content) = suppression.content_digest {
                require_source_digest(&content, "suppression content digest")?;
                if suppression.mode == crate::lifecycle::SuppressionMode::Forgotten
                    && referenced.contains_key(content.as_bytes())
                {
                    return Err(invalid(
                        "archive includes source bytes a suppression declares forgotten",
                    ));
                }
            }
            if !suppressions.insert((suppression.target, suppression.revision)) {
                return Err(invalid("archive repeats one suppression target"));
            }
            if suppression.mode != crate::lifecycle::SuppressionMode::Forgotten {
                continue;
            }
            for record in &self.records {
                if record.record_id != suppression.target {
                    continue;
                }
                if suppression.revision.is_none()
                    || record
                        .revisions
                        .iter()
                        .any(|revision| Some(revision.envelope.revision_id) == suppression.revision)
                {
                    return Err(invalid(
                        "archive includes a record a suppression declares forgotten",
                    ));
                }
            }
        }

        let mut prunings = std::collections::BTreeSet::new();
        for pruning in &self.prunings {
            require_source_digest(&pruning.digest, "pruning digest")?;
            if referenced.contains_key(pruning.digest.as_bytes()) {
                return Err(invalid(
                    "archive includes source bytes a pruning decision declares absent",
                ));
            }
            if !prunings.insert((pruning.source, pruning.revision)) {
                return Err(invalid("archive repeats one pruning target"));
            }
            if self.records.iter().any(|record| {
                record.record_id == pruning.source
                    && record
                        .revisions
                        .iter()
                        .any(|revision| revision.envelope.revision_id == pruning.revision)
            }) {
                return Err(invalid(
                    "archive includes a revision a pruning decision suppresses",
                ));
            }
        }
        Ok(())
    }

    /// Check omission entries are bounded and canonical.
    fn validate_omissions(&self) -> crate::error::Result<()> {
        let mut previous: Option<&str> = None;
        for omission in &self.omissions {
            if omission.count == 0 {
                return Err(invalid("archive omission count must be positive"));
            }
            if omission.reason.is_empty()
                || omission.reason.len() > 64
                || !omission.reason.bytes().all(|byte| {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                })
            {
                return Err(invalid("archive omission reason is malformed"));
            }
            if previous.is_some_and(|previous| previous >= omission.reason.as_str()) {
                return Err(invalid("archive omissions are not in unique reason order"));
            }
            previous = Some(omission.reason.as_str());
        }
        Ok(())
    }
}

impl PortableRecord {
    /// Encode as `<portable-record …>`.
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "portable-record",
            vec![
                self.record_id.to_value(),
                self.scope.to_value(),
                mneme_core::Value::sequence(
                    self.revisions
                        .iter()
                        .map(PortableRevision::to_value)
                        .collect(),
                ),
            ],
        )
    }

    /// Decode a record history.
    fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, "portable-record", 3)?;
        let record_id = mneme_core::RecordId::from_value(
            &fields[0],
            &mneme_core::Path::root().field("record"),
        )
        .map_err(|diagnostic| invalid(format!("record: {diagnostic}")))?;
        let scope = scope(&fields[1])?;
        let revisions = sequence(&fields[2], "record revisions", MAX_PORTABLE_REVISIONS)?
            .iter()
            .map(PortableRevision::from_value)
            .collect::<crate::error::Result<Vec<_>>>()?;
        Ok(PortableRecord {
            record_id,
            scope,
            revisions,
        })
    }
}

impl PortableRevision {
    /// Encode as `<portable-revision …>`.
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "portable-revision",
            vec![
                self.envelope.to_value(),
                self.commit.to_value(),
            ],
        )
    }

    /// Decode one revision and its introducing commit.
    fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, "portable-revision", 2)?;
        let envelope = mneme_core::RecordEnvelope::from_value(&fields[0])
            .map_err(|diagnostics| invalid(mneme_core::render_diagnostics(&diagnostics)))?;
        let commit = crate::coordinator::RevisionCommit::from_value(&fields[1])?;
        Ok(PortableRevision { envelope, commit })
    }
}

impl PortableCurrent {
    /// Encode as `<portable-current …>`.
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "portable-current",
            vec![
                self.record_id.to_value(),
                self.revision_id.to_value(),
                self.kind.to_value(),
            ],
        )
    }

    /// Decode one current-record entry.
    fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, "portable-current", 3)?;
        Ok(PortableCurrent {
            record_id: mneme_core::RecordId::from_value(
                &fields[0],
                &mneme_core::Path::root().field("record"),
            )
            .map_err(|diagnostic| invalid(format!("record: {diagnostic}")))?,
            revision_id: mneme_core::RevisionId::from_value(
                &fields[1],
                &mneme_core::Path::root().field("revision"),
            )
            .map_err(|diagnostic| invalid(format!("revision: {diagnostic}")))?,
            kind: mneme_core::RecordKind::from_value(
                &fields[2],
                &mneme_core::Path::root().field("kind"),
            )
            .map_err(|diagnostic| invalid(format!("kind: {diagnostic}")))?,
        })
    }
}

impl PortableBlob {
    /// Encode as `<portable-blob …>`.
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "portable-blob",
            vec![
                self.digest.to_value(),
                mneme_core::Value::integer(self.length),
            ],
        )
    }

    /// Decode one blob descriptor.
    fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, "portable-blob", 2)?;
        Ok(PortableBlob {
            digest: digest(&fields[0], "blob digest")?,
            length: unsigned(&fields[1], "blob length")?,
        })
    }
}

impl PortableSuppression {
    /// Encode as `<portable-suppression …>`.
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "portable-suppression",
            vec![
                self.target.to_value(),
                match self.revision {
                    Some(revision) => revision.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                mneme_core::Value::symbol(self.target_kind.clone()),
                mneme_core::Value::symbol(self.mode.as_str()),
                match self.content_digest {
                    Some(digest) => digest.to_value(),
                    None => mneme_core::Value::symbol("none"),
                },
                mneme_core::Value::integer(self.generation),
            ],
        )
    }

    /// Decode one suppression.
    fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, "portable-suppression", 6)?;
        let mode = fields[3]
            .as_symbol()
            .and_then(|symbol| crate::lifecycle::SuppressionMode::parse(symbol.as_str()))
            .ok_or_else(|| invalid("suppression mode is unknown"))?;
        let content_digest = if is_none(&fields[4]) {
            None
        } else {
            Some(digest(&fields[4], "suppression digest")?)
        };
        Ok(PortableSuppression {
            target: mneme_core::RecordId::from_value(
                &fields[0],
                &mneme_core::Path::root().field("target"),
            )
            .map_err(|diagnostic| invalid(format!("target: {diagnostic}")))?,
            revision: optional_revision(&fields[1], "suppression revision")?,
            target_kind: label(&fields[2], "suppression target kind")?,
            mode,
            content_digest,
            generation: unsigned(&fields[5], "suppression generation")?,
        })
    }
}

impl PortablePruning {
    /// Encode as `<portable-pruning …>`.
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "portable-pruning",
            vec![
                self.source.to_value(),
                self.revision.to_value(),
                self.digest.to_value(),
            ],
        )
    }

    /// Decode one pruning decision.
    fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, "portable-pruning", 3)?;
        Ok(PortablePruning {
            source: mneme_core::RecordId::from_value(
                &fields[0],
                &mneme_core::Path::root().field("source"),
            )
            .map_err(|diagnostic| invalid(format!("source: {diagnostic}")))?,
            revision: mneme_core::RevisionId::from_value(
                &fields[1],
                &mneme_core::Path::root().field("revision"),
            )
            .map_err(|diagnostic| invalid(format!("revision: {diagnostic}")))?,
            digest: digest(&fields[2], "pruning digest")?,
        })
    }
}

impl PortableOmission {
    /// Encode as `<portable-omission …>`.
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "portable-omission",
            vec![
                mneme_core::Value::symbol(self.reason.clone()),
                mneme_core::Value::integer(self.count),
            ],
        )
    }

    /// Decode one omission.
    fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, "portable-omission", 2)?;
        Ok(PortableOmission {
            reason: label(&fields[0], "omission reason")?,
            count: unsigned(&fields[1], "omission count")?,
        })
    }
}

impl crate::coordinator::RevisionCommit {
    /// Encode as `<portable-commit …>`.
    fn to_value(&self) -> mneme_core::Value {
        mneme_core::Value::record_named(
            "portable-commit",
            vec![
                self.revision.to_value(),
                mneme_core::Value::integer(self.sequence),
                mneme_core::Value::string(self.actor.clone()),
                mneme_core::Value::integer(self.committed_at_ns),
            ],
        )
    }

    /// Decode one workspace commit attribution.
    fn from_value(value: &mneme_core::Value) -> crate::error::Result<Self> {
        let fields = record_fields(value, "portable-commit", 4)?;
        let actor = text(&fields[2], "commit actor")?;
        if actor.is_empty() || actor.len() > 128 || actor.chars().any(char::is_control) {
            return Err(invalid("commit actor is malformed"));
        }
        Ok(crate::coordinator::RevisionCommit {
            revision: mneme_core::WorkspaceRevisionId::from_value(
                &fields[0],
                &mneme_core::Path::root().field("revision"),
            )
            .map_err(|diagnostic| invalid(format!("revision: {diagnostic}")))?,
            sequence: unsigned(&fields[1], "commit sequence")?,
            actor: actor.to_owned(),
            committed_at_ns: signed(&fields[3], "commit time")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omission_labels_are_bounded_and_lowercase() {
        let reason = PortableOmission {
            reason: "foreign-scope-record".to_owned(),
            count: 1,
        };
        let decoded = PortableOmission::from_value(&reason.to_value()).expect("roundtrip");
        assert_eq!(decoded, reason);
        let invalid_reason = PortableOmission {
            reason: "Upper Case".to_owned(),
            count: 1,
        };
        assert!(PortableOmission::from_value(&invalid_reason.to_value()).is_err());
    }
}
