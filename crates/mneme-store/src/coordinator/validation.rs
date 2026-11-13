//! Command validation: working paths, record scopes, bindings and the source
//! bytes a commit or publication must satisfy before anything reaches the ledger.

pub(super) fn validate_command(
    command: &crate::requests::CommitCommand,
) -> crate::error::Result<()> {
    validate_command_paths(command)?;
    if command.actor.trim().is_empty()
        || command.actor.len() > 128
        || command.actor.chars().any(char::is_control)
    {
        return Err(crate::error::Failure::InvalidCommand(
            "actor must be non-empty, at most 128 bytes, and contain no control characters"
                .to_owned(),
        ));
    }
    if command.idempotency_key.trim().is_empty()
        || command.idempotency_key.len() > 256
        || command.idempotency_key.chars().any(char::is_control)
    {
        return Err(crate::error::Failure::InvalidCommand(
            "idempotency key must be non-empty, at most 256 bytes, and contain no control characters"
                .to_owned(),
        ));
    }
    for record in &command.records {
        if record.scope != command.scope {
            return Err(crate::error::Failure::ScopeMismatch {
                record_scope: record.scope.to_string(),
                command_scope: command.scope.to_string(),
            });
        }
    }
    Ok(())
}

/// Validate every logical working path a command names.
///
/// Publication, import-candidate and source-binding paths must be canonical
/// relative paths, checked here before any other use of the path. Since no
/// alias reaches validation, paths can only be compared as exact strings: one
/// spelling names at most one working file.
fn validate_command_paths(command: &crate::requests::CommitCommand) -> crate::error::Result<()> {
    for publication in &command.publications {
        crate::payload::validate_relative_path(&publication.path)?;
    }
    for candidate in &command.import_candidates {
        crate::payload::validate_relative_path(&candidate.path)?;
    }
    for record in &command.records {
        if record.kind != mneme_core::RecordKind::SourceRevision {
            continue;
        }
        let Some(path) = record
            .payload
            .get("path-hint")
            .and_then(mneme_core::Value::as_string)
        else {
            continue;
        };
        crate::payload::validate_relative_path(path)?;
    }
    Ok(())
}

pub(super) fn validate_publication_paths(
    publications: &[crate::requests::PublicationDraft],
    candidates: &[crate::requests::ImportCandidateDraft],
) -> crate::error::Result<()> {
    let mut paths = std::collections::BTreeSet::new();
    for publication in publications {
        if !paths.insert(publication.path.clone()) {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "publication path {:?} appears more than once",
                publication.path
            )));
        }
    }
    let mut candidate_paths = std::collections::BTreeSet::new();
    for candidate in candidates {
        if !candidate_paths.insert(candidate.path.clone()) {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "import candidate {:?} appears more than once",
                candidate.path
            )));
        }
        if paths.contains(&candidate.path) {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "path {:?} is both published and imported",
                candidate.path
            )));
        }
    }
    Ok(())
}

/// Enforce scope structure between a proposed revision and its predecessor.
///
/// A revision stays in its record's scope, or it promotes a hypothesis record
/// to an operational one; nothing else may move a record between scopes. The
/// refusal names neither the record's current revision nor its scope.
pub(super) fn validate_record_scopes(
    command_scope: &mneme_core::ScopeId,
    prior: &[mneme_core::RecordEnvelope],
    proposed: &[mneme_core::RecordEnvelope],
) -> crate::error::Result<()> {
    for record in proposed {
        if record.scope != *command_scope {
            return Err(crate::error::Failure::InvalidCommand(
                "every proposed record must be in the command's scope".to_owned(),
            ));
        }
        if record.predecessor.is_none() {
            continue;
        }
        let Some(previous) = prior
            .iter()
            .find(|candidate| candidate.record_id == record.record_id)
        else {
            return Err(crate::error::Failure::InvalidCommand(
                "a revision must name the current revision of a record in this workspace"
                    .to_owned(),
            ));
        };
        let is_structurally_allowed = mneme_kernel::isolation::revision_scope_structural(
            &mneme_kernel::isolation::ScopeChange {
                same_scope: previous.scope == record.scope,
                prior_class: previous.scope.class().to_kernel(),
                next_class: record.scope.class().to_kernel(),
            },
        );
        if !is_structurally_allowed {
            return Err(crate::error::Failure::InvalidCommand(
                "a revision cannot move a record into a different scope".to_owned(),
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_bindings(
    prior: &[mneme_core::RecordEnvelope],
    proposed: &[mneme_core::RecordEnvelope],
) -> crate::error::Result<()> {
    let mut bindings: std::collections::BTreeMap<String, mneme_core::RecordId> =
        std::collections::BTreeMap::new();
    for record in prior {
        if let Some((path, entity)) = source_binding(record)?
            && let Some(existing) = bindings.insert(path.clone(), entity)
            && existing != entity
        {
            return Err(crate::error::Failure::BindingConflict(format!(
                "source path {path:?} is bound to both {existing} and {entity}"
            )));
        }
    }
    for record in prior {
        if record.kind != mneme_core::RecordKind::SourceRevision {
            continue;
        }
        if let Some(replacement) = proposed
            .iter()
            .find(|candidate| candidate.record_id == record.record_id)
        {
            let before = source_binding(record)?;
            let after = source_binding(replacement)?;
            if let (Some((_, before_entity)), Some((_, after_entity))) = (before, after)
                && before_entity != after_entity
            {
                return Err(crate::error::Failure::BindingConflict(format!(
                    "source record {} cannot be reassigned from entity {before_entity} to {after_entity} implicitly",
                    record.record_id
                )));
            }
        }
    }
    for record in proposed {
        if let Some((path, entity)) = source_binding(record)?
            && let Some(existing) = bindings.insert(path.clone(), entity)
            && existing != entity
        {
            return Err(crate::error::Failure::BindingConflict(format!(
                "source path {path:?} is bound to both {existing} and {entity}"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_snapshot_bindings(
    records: &std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
) -> crate::error::Result<()> {
    let mut bindings: std::collections::BTreeMap<String, mneme_core::RecordId> =
        std::collections::BTreeMap::new();
    for record in records.values() {
        if let Some((path, entity)) = source_binding(record)?
            && let Some(existing) = bindings.insert(path.clone(), entity)
            && existing != entity
        {
            return Err(crate::error::Failure::BindingConflict(format!(
                "source path {path:?} is bound to both {existing} and {entity}"
            )));
        }
    }
    Ok(())
}

/// Validate the source bytes a command supplies and the digests it claims.
///
/// A new retained source revision either supplies its bytes (as a source blob
/// or as an import candidate whose bytes the staging step matches against this
/// record) or names a digest that a retained record of the command's scope
/// already binds. Knowing another scope's digest is not access to its bytes.
pub(super) fn validate_sources(
    supplied: &[crate::requests::SourceBlobDraft],
    candidates: &[crate::requests::ImportCandidateDraft],
    prior: &[mneme_core::RecordEnvelope],
    command_scope: &mneme_core::ScopeId,
    proposed: &[mneme_core::RecordEnvelope],
) -> crate::error::Result<()> {
    let mut supplied_digests = std::collections::BTreeMap::new();
    for source in supplied {
        let digest = source.digest();
        if let Some(existing) = supplied_digests.insert(digest, source)
            && existing.bytes != source.bytes
        {
            return Err(crate::error::Failure::InvalidCommand(
                "source blobs with the same digest have different bytes".to_owned(),
            ));
        }
    }
    let mut referenced = std::collections::BTreeSet::new();
    for record in proposed {
        let Some((digest, declared_length, media_type)) = retained_source(record)? else {
            continue;
        };
        referenced.insert(digest);
        if let Some(source) = supplied_digests.get(&digest) {
            if source.bytes.len() as u64 != declared_length {
                return Err(crate::error::Failure::SourceLengthMismatch {
                    digest: digest.to_hex(),
                    declared: declared_length,
                    supplied: source.bytes.len() as u64,
                });
            }
            if source.media_type != media_type {
                return Err(crate::error::Failure::InvalidCommand(format!(
                    "source blob {digest} media type does not match its source revision"
                )));
            }
            continue;
        }
        let is_bytes_supplied = candidates
            .iter()
            .any(|candidate| candidate.digest() == digest);
        let is_bound_in_scope = prior.iter().any(|earlier| {
            earlier.scope == *command_scope && retained_source_digest(earlier) == Some(digest)
        });
        let facts = mneme_kernel::isolation::BlobClaimFacts {
            bytes_supplied: is_bytes_supplied,
            bound_in_scope: is_bound_in_scope,
        };
        if !mneme_kernel::isolation::blob_claim_allowed(&facts) {
            return Err(crate::error::Failure::InvalidCommand(
                "a source revision must supply the bytes of a digest that is not already bound in its scope"
                    .to_owned(),
            ));
        }
    }
    for digest in supplied_digests.keys() {
        if !referenced.contains(digest) {
            return Err(crate::error::Failure::InvalidCommand(format!(
                "source blob {digest} is not referenced by a new retained source revision"
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_snapshot_sources(
    records: &std::collections::BTreeMap<mneme_core::RecordId, mneme_core::RecordEnvelope>,
    blobs: &super::BlobIndex,
) -> crate::error::Result<()> {
    for record in records.values() {
        let Some((digest, declared_length, _)) = retained_source(record)? else {
            continue;
        };
        if let Some((_, length, _, _)) = blobs.get(digest.as_bytes()) {
            if *length != declared_length {
                return Err(crate::error::Failure::SourceLengthMismatch {
                    digest: digest.to_hex(),
                    declared: declared_length,
                    supplied: *length,
                });
            }
        } else {
            // The inherited blob must already be registered.
            return Err(crate::error::Failure::MissingSource {
                digest: digest.to_hex(),
            });
        }
    }
    Ok(())
}

pub(super) fn candidate_matches(
    candidate: &crate::requests::ImportCandidateDraft,
    record: &mneme_core::RecordEnvelope,
) -> bool {
    if record.kind != mneme_core::RecordKind::SourceRevision {
        return false;
    }
    let path = record
        .payload
        .get("path-hint")
        .and_then(mneme_core::Value::as_string);
    let content = record.payload.get("content").and_then(|value| {
        mneme_core::SourceContent::from_value(value, &mneme_core::Path::root()).ok()
    });
    let retained = match content {
        Some(mneme_core::SourceContent::Retained(retained)) => Some(retained),
        _ => None,
    };
    path == Some(candidate.path.as_str())
        && retained
            .map(|retained| {
                retained.digest() == candidate.digest()
                    && retained.byte_length() == candidate.bytes.len() as u64
            })
            .unwrap_or(false)
}

fn source_binding(
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<Option<(String, mneme_core::RecordId)>> {
    if record.kind != mneme_core::RecordKind::SourceRevision {
        return Ok(None);
    }
    let Some(path) = record
        .payload
        .get("path-hint")
        .and_then(mneme_core::Value::as_string)
    else {
        return Ok(None);
    };
    let Some(entity) = record.payload.get("entity") else {
        return Ok(None);
    };
    let reference = mneme_core::Reference::from_value(entity, &mneme_core::Path::root()).map_err(
        |diagnostic| {
            crate::error::Failure::InvalidCommand(format!(
                "source record {} has an invalid entity reference: {diagnostic}",
                record.record_id
            ))
        },
    )?;
    Ok(reference.target().map(|target| (path.to_owned(), target)))
}

fn retained_source(
    record: &mneme_core::RecordEnvelope,
) -> crate::error::Result<Option<(mneme_core::ContentDigest, u64, mneme_core::Symbol)>> {
    retained_source_fields(record.kind, &record.payload)
}

pub(super) fn retained_source_draft(
    draft: &crate::requests::RecordDraft,
) -> crate::error::Result<Option<(mneme_core::ContentDigest, u64, mneme_core::Symbol)>> {
    retained_source_fields(draft.kind, &draft.payload)
}

/// The digest, declared length and media type a source revision retains.
///
/// The read works on the payload alone so a proposed draft can be checked for
/// forgotten content before its envelope exists.
fn retained_source_fields(
    kind: mneme_core::RecordKind,
    payload: &mneme_core::Payload,
) -> crate::error::Result<Option<(mneme_core::ContentDigest, u64, mneme_core::Symbol)>> {
    if kind != mneme_core::RecordKind::SourceRevision {
        return Ok(None);
    }
    let Some(content) = payload.get("content") else {
        return Ok(None);
    };
    let content = mneme_core::SourceContent::from_value(content, &mneme_core::Path::root())
        .map_err(|diagnostic| {
            crate::error::Failure::InvalidCommand(format!(
                "a source revision has invalid content: {diagnostic}"
            ))
        })?;
    match content {
        mneme_core::SourceContent::Retained(retained) => Ok(Some((
            retained.digest(),
            retained.byte_length(),
            retained.media_type().clone(),
        ))),
        mneme_core::SourceContent::Unavailable { .. } => Ok(None),
    }
}

pub(super) fn retained_source_digest(
    record: &mneme_core::RecordEnvelope,
) -> Option<mneme_core::ContentDigest> {
    retained_source(record)
        .ok()
        .flatten()
        .map(|(digest, _, _)| digest)
}
