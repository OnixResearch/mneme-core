//! Bounded, revision-pinned PNG/JPEG source import and reads.

/// Maximum encoded image size accepted from a file or retained source.
pub const MAX_ENCODED_BYTES: usize = 8 * 1024 * 1024;
/// Maximum caption length accepted by attachment commands.
pub const MAX_CAPTION_CHARS: usize = 1024;

const MAX_IMAGE_DIMENSION: u32 = 8_192;
const MAX_IMAGE_PIXELS: u64 = 16_777_216;
const MAX_DECODER_ALLOCATION: u64 = 128 * 1024 * 1024;
const IMAGE_UNAVAILABLE: &str = "image is unavailable";

/// An import request bound to a caller, scope, base revision, and idempotency key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportRequest {
    pub actor: String,
    pub scope: mneme_core::ScopeId,
    pub base: mneme_core::WorkspaceRevisionId,
    pub key: String,
}

/// A committed image source revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imported {
    pub pin: crate::SourcePin,
    pub digest: mneme_core::ContentDigest,
    pub media_type: &'static str,
    pub width: u32,
    pub height: u32,
    pub workspace_revision: mneme_core::WorkspaceRevisionId,
}

/// An authorized retained image source revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded {
    pub pin: crate::SourcePin,
    pub digest: mneme_core::ContentDigest,
    pub media_type: &'static str,
    pub width: u32,
    pub height: u32,
    pub bytes: Vec<u8>,
    pub generation: u64,
    pub workspace_revision: mneme_core::WorkspaceRevisionId,
}

/// Fully decoded RGBA8 image pixels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub media_type: &'static str,
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SupportedFormat {
    Png,
    Jpeg,
}

impl SupportedFormat {
    const fn media_type(self) -> &'static str {
        match self {
            SupportedFormat::Png => "image/png",
            SupportedFormat::Jpeg => "image/jpeg",
        }
    }

    const fn image_format(self) -> image::ImageFormat {
        match self {
            SupportedFormat::Png => image::ImageFormat::Png,
            SupportedFormat::Jpeg => image::ImageFormat::Jpeg,
        }
    }
}

/// Parse the sole accepted image target spelling.
pub fn parse_target(target: &str) -> crate::Result<crate::SourcePin> {
    let target = target
        .strip_prefix("mneme-image:")
        .ok_or(crate::DocumentError::Invalid("invalid image target"))?;
    let (source_text, revision_text) = target
        .split_once('/')
        .ok_or(crate::DocumentError::Invalid("invalid image target"))?;
    if revision_text.contains('/') {
        return Err(crate::DocumentError::Invalid("invalid image target"));
    }
    let source = mneme_core::RecordId::from_hex(source_text)
        .map_err(|_| crate::DocumentError::Invalid("invalid image target"))?;
    let revision = mneme_core::RevisionId::from_hex(revision_text)
        .map_err(|_| crate::DocumentError::Invalid("invalid image target"))?;
    if source.to_hex() != source_text || revision.to_hex() != revision_text {
        return Err(crate::DocumentError::Invalid("invalid image target"));
    }
    Ok(crate::SourcePin { source, revision })
}

/// Format a canonical pinned image target.
pub fn target(pin: crate::SourcePin) -> String {
    format!(
        "mneme-image:{}/{}",
        pin.source.to_hex(),
        pin.revision.to_hex()
    )
}

/// Validate and escape an authored caption for a single-line image block.
pub fn encode_caption(caption: &str) -> crate::Result<String> {
    if caption.chars().take(MAX_CAPTION_CHARS + 1).count() > MAX_CAPTION_CHARS
        || caption
            .chars()
            .any(|character| matches!(character, '\n' | '\r'))
    {
        return Err(crate::DocumentError::Invalid(
            "image caption must be one line of at most 1024 characters",
        ));
    }
    let mut encoded = String::with_capacity(caption.len());
    for character in caption.chars() {
        if matches!(character, '\\' | '[' | ']') {
            encoded.push('\\');
        }
        encoded.push(character);
    }
    Ok(encoded)
}

/// Parse passive image-block syntax shared by native and HTML previews.
/// A malformed block has an empty target, so it renders as unavailable.
pub fn parse_block(line: &str) -> Option<(&str, std::borrow::Cow<'_, str>)> {
    let rest = line.strip_prefix("image::")?;
    let Some((target, caption)) = rest.split_once('[') else {
        return Some(("", std::borrow::Cow::Borrowed("")));
    };
    let Some(raw) = caption.strip_suffix(']') else {
        return Some(("", std::borrow::Cow::Borrowed("")));
    };
    if !raw.contains(['\\', ']']) {
        return Some((target, std::borrow::Cow::Borrowed(raw)));
    }
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        match character {
            '\\' => match characters.next() {
                Some(escaped @ ('\\' | '[' | ']')) => decoded.push(escaped),
                Some(other) => {
                    decoded.push('\\');
                    decoded.push(other);
                }
                None => return Some(("", std::borrow::Cow::Borrowed(""))),
            },
            ']' => return Some(("", std::borrow::Cow::Borrowed(""))),
            other => decoded.push(other),
        }
    }
    Some((target, std::borrow::Cow::Owned(decoded)))
}

/// Read one bounded regular local file for an image import.
pub fn read_file(path: &std::path::Path) -> crate::Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|error| crate::DocumentError::Io(error.to_string()))?;
    if !before.file_type().is_file() {
        return Err(crate::DocumentError::Invalid(
            "image path must name a regular file",
        ));
    }
    if before.len() > MAX_ENCODED_BYTES as u64 {
        return Err(crate::DocumentError::Invalid("image file is oversized"));
    }

    let mut file =
        std::fs::File::open(path).map_err(|error| crate::DocumentError::Io(error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| crate::DocumentError::Io(error.to_string()))?;
    if !opened.is_file() || opened.len() > MAX_ENCODED_BYTES as u64 || !same_file(&before, &opened)
    {
        return Err(crate::DocumentError::Invalid(
            "image path changed during import",
        ));
    }

    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(&mut file, MAX_ENCODED_BYTES as u64 + 1);
    std::io::Read::read_to_end(&mut bounded, &mut bytes)
        .map_err(|error| crate::DocumentError::Io(error.to_string()))?;
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(crate::DocumentError::Invalid("image file is oversized"));
    }

    let after = file
        .metadata()
        .map_err(|error| crate::DocumentError::Io(error.to_string()))?;
    let path_after = std::fs::symlink_metadata(path)
        .map_err(|error| crate::DocumentError::Io(error.to_string()))?;
    if !after.is_file()
        || !path_after.file_type().is_file()
        || after.len() > MAX_ENCODED_BYTES as u64
        || after.len() != bytes.len() as u64
        || !same_file(&opened, &after)
        || !same_file(&after, &path_after)
    {
        return Err(crate::DocumentError::Invalid(
            "image path changed during import",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

/// Fully validate and decode supported PNG/JPEG bytes to bounded RGBA8 pixels.
pub fn decode(bytes: &[u8]) -> crate::Result<Decoded> {
    let (format, width, height) = inspect_format(bytes)?;
    let mut reader =
        image::ImageReader::with_format(std::io::Cursor::new(bytes), format.image_format());
    reader.limits(decoder_limits());
    let mut decoder = reader
        .into_decoder()
        .map_err(|_| crate::DocumentError::Invalid("malformed or unsupported image"))?;
    let dimensions = image::ImageDecoder::dimensions(&decoder);
    if dimensions != (width, height) {
        return Err(crate::DocumentError::Invalid("malformed image dimensions"));
    }
    image::ImageDecoder::set_limits(&mut decoder, decoder_limits())
        .map_err(|_| crate::DocumentError::Invalid("image exceeds decoder limits"))?;
    if image::ImageDecoder::total_bytes(&decoder) > MAX_DECODER_ALLOCATION {
        return Err(crate::DocumentError::Invalid(
            "image exceeds decoder limits",
        ));
    }
    let orientation = image::ImageDecoder::orientation(&mut decoder)
        .map_err(|_| crate::DocumentError::Invalid("malformed image metadata"))?;
    let mut decoded = image::DynamicImage::from_decoder(decoder)
        .map_err(|_| crate::DocumentError::Invalid("malformed or unsupported image"))?;
    decoded.apply_orientation(orientation);
    let width = decoded.width();
    let height = decoded.height();
    check_dimensions(width, height)?;
    let expected = u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|pixels| pixels.checked_mul(4))
        .and_then(|length| usize::try_from(length).ok())
        .ok_or(crate::DocumentError::Invalid(
            "image exceeds decoder limits",
        ))?;
    let rgba = decoded.into_rgba8().into_raw();
    if rgba.len() != expected {
        return Err(crate::DocumentError::Invalid("malformed decoded image"));
    }
    Ok(Decoded {
        media_type: format.media_type(),
        width,
        height,
        rgba,
    })
}

/// Import exact validated source bytes under the workspace coordinator.
pub fn import(
    workspace: &mut mneme_store::Workspace,
    request: ImportRequest,
    bytes: &[u8],
) -> crate::Result<Imported> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(crate::DocumentError::Invalid("image is oversized"));
    }
    let digest = mneme_core::ContentDigest::of_source_bytes(bytes);
    let fingerprint = import_fingerprint(&request, digest);
    if let Some(outcome) =
        workspace.replay_outcome(&request.actor, &request.scope, &request.key, &fingerprint)?
    {
        let pin = replayed_pin(workspace, &request.scope, digest, &outcome)?;
        let loaded = load(workspace, &request.scope, pin, Some(outcome.revision))?;
        return Ok(Imported {
            pin,
            digest: loaded.digest,
            media_type: loaded.media_type,
            width: loaded.width,
            height: loaded.height,
            workspace_revision: outcome.revision,
        });
    }

    let decoded = decode(bytes)?;
    let source_id = mneme_core::RecordId::from_bytes(mneme_store::payload::random_bytes()?);
    let source_revision = mneme_core::RevisionId::from_bytes(mneme_store::payload::random_bytes()?);
    let (source, source_blob) = mneme_memory::build_source(
        source_id,
        source_revision,
        &request.scope,
        mneme_memory::SourceOptions {
            bytes,
            media_type: decoded.media_type,
            entity: None,
            path_hint: None,
        },
    )?;
    let outcome = workspace.commit_bound(
        mneme_store::CommitCommand {
            base: request.base,
            actor: request.actor,
            scope: request.scope.clone(),
            idempotency_key: request.key,
            records: vec![source],
            source_blobs: vec![source_blob],
            publications: Vec::new(),
            import_candidates: Vec::new(),
            retention: None,
        },
        fingerprint,
    )?;
    let snapshot = workspace.snapshot_at(outcome.revision, Some(outcome.eligibility_generation))?;
    let pin = if snapshot
        .records
        .iter()
        .any(|record| record.record_id == source_id)
    {
        crate::SourcePin {
            source: source_id,
            revision: source_revision,
        }
    } else {
        // A competing identical request may have committed after the initial
        // replay lookup. Return its committed pin, not our unused random IDs.
        replayed_pin(workspace, &request.scope, digest, &outcome)?
    };
    workspace.recheck(&snapshot)?;
    Ok(Imported {
        pin,
        digest,
        media_type: decoded.media_type,
        width: decoded.width,
        height: decoded.height,
        workspace_revision: outcome.revision,
    })
}

fn import_fingerprint(
    request: &ImportRequest,
    digest: mneme_core::ContentDigest,
) -> mneme_core::ContentDigest {
    mneme_core::request_fingerprint(&mneme_core::Value::record_named(
        "image-import-request/v1",
        vec![
            mneme_core::Value::symbol("image-import"),
            mneme_core::Value::string(request.actor.clone()),
            request.scope.to_value(),
            digest.to_value(),
        ],
    ))
}

/// Load exact retained bytes under an equal source scope and current eligibility generation.
pub fn load(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    pin: crate::SourcePin,
    revision: Option<mneme_core::WorkspaceRevisionId>,
) -> crate::Result<Loaded> {
    load_decoded(workspace, scope, pin, revision).map(|(loaded, _decoded)| loaded)
}

/// Load and fully decode one exact retained image without repeating codec work.
pub fn load_decoded(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    pin: crate::SourcePin,
    revision: Option<mneme_core::WorkspaceRevisionId>,
) -> crate::Result<(Loaded, Decoded)> {
    let revision = match revision {
        Some(revision) => revision,
        None => workspace.current_revision()?,
    };
    let snapshot = workspace.snapshot_at(revision, None)?;
    let context = mneme_memory::view_context(workspace, &snapshot)?;
    let suppressions = workspace.active_suppressions()?;
    let view = mneme_memory::View::with_retention(
        snapshot.clone(),
        workspace.root(),
        context.history,
        context.revision_sequences,
        suppressions,
    )
    .with_access(mneme_memory::Access::scopes([scope.clone()]));
    let source = view
        .source_at(pin.source, pin.revision)
        .map_err(|_| unavailable())?;
    if source.record.scope != *scope || view.suppression_for(&source.record).is_some() {
        return Err(unavailable());
    }
    let expected_byte_length = source.byte_length().ok_or_else(unavailable)?;
    if source.availability != mneme_memory::SourceAvailability::Retained
        || expected_byte_length > MAX_ENCODED_BYTES as u64
    {
        return Err(unavailable());
    }
    let digest = source.digest().ok_or_else(unavailable)?;
    let bytes = read_file(&mneme_store::payload::blob_path(workspace.root(), digest))
        .map_err(|_| unavailable())?;
    if bytes.len() as u64 != expected_byte_length || bytes.len() > MAX_ENCODED_BYTES {
        return Err(unavailable());
    }
    if mneme_core::ContentDigest::of_source_bytes(&bytes) != digest {
        return Err(unavailable());
    }
    let declared_media_type = source
        .media_type
        .as_ref()
        .map(mneme_core::Symbol::as_str)
        .ok_or_else(unavailable)?;
    let decoded = decode(&bytes).map_err(|_| unavailable())?;
    if decoded.media_type != declared_media_type {
        return Err(unavailable());
    }
    workspace.recheck(&snapshot)?;
    Ok((
        Loaded {
            pin,
            digest,
            media_type: decoded.media_type,
            width: decoded.width,
            height: decoded.height,
            bytes,
            generation: snapshot.eligibility_generation,
            workspace_revision: snapshot.revision,
        },
        decoded,
    ))
}

fn replayed_pin(
    workspace: &mut mneme_store::Workspace,
    scope: &mneme_core::ScopeId,
    digest: mneme_core::ContentDigest,
    outcome: &mneme_store::CommitOutcome,
) -> crate::Result<crate::SourcePin> {
    if outcome.sequence == 0 {
        return Err(unavailable());
    }
    let snapshot = workspace.snapshot_at(outcome.revision, None)?;
    let previous_revision = workspace
        .revision_at_sequence(outcome.sequence - 1)?
        .ok_or_else(unavailable)?;
    let previous = workspace.snapshot_at(previous_revision, None)?;
    let previous_records = previous
        .records
        .iter()
        .map(|record| record.record_id)
        .collect::<std::collections::BTreeSet<_>>();
    let mut found = None;
    for record in snapshot.records.iter().filter(|record| {
        record.kind == mneme_core::RecordKind::SourceRevision
            && record.scope == *scope
            && !previous_records.contains(&record.record_id)
    }) {
        let Ok(source) = mneme_memory::SourceView::parse(record.clone()) else {
            continue;
        };
        if source.digest().or(source.prior_digest) != Some(digest) {
            continue;
        }
        if found.is_some() {
            return Err(unavailable());
        }
        found = Some(crate::SourcePin {
            source: record.record_id,
            revision: record.revision_id,
        });
    }
    found.ok_or_else(unavailable)
}

fn inspect_format(bytes: &[u8]) -> crate::Result<(SupportedFormat, u32, u32)> {
    if bytes.is_empty() || bytes.len() > MAX_ENCODED_BYTES {
        return Err(crate::DocumentError::Invalid("image is empty or oversized"));
    }
    let format = image::guess_format(bytes)
        .map_err(|_| crate::DocumentError::Invalid("malformed or unsupported image"))?;
    let format = match format {
        image::ImageFormat::Png => SupportedFormat::Png,
        image::ImageFormat::Jpeg => SupportedFormat::Jpeg,
        _ => return Err(crate::DocumentError::Invalid("unsupported image format")),
    };
    let mut reader =
        image::ImageReader::with_format(std::io::Cursor::new(bytes), format.image_format());
    reader.limits(decoder_limits());
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| crate::DocumentError::Invalid("malformed or unsupported image"))?;
    check_dimensions(width, height)?;
    Ok((format, width, height))
}

fn check_dimensions(width: u32, height: u32) -> crate::Result<()> {
    let pixels = u64::from(width)
        .checked_mul(u64::from(height))
        .ok_or(crate::DocumentError::Invalid("image dimensions overflow"))?;
    if width == 0
        || height == 0
        || width > MAX_IMAGE_DIMENSION
        || height > MAX_IMAGE_DIMENSION
        || pixels > MAX_IMAGE_PIXELS
    {
        return Err(crate::DocumentError::Invalid(
            "image dimensions exceed supported limits",
        ));
    }
    Ok(())
}

fn decoder_limits() -> image::Limits {
    // The non-exhaustive type requires a constructor; set every supported
    // limit explicitly before passing it to a decoder.
    let mut limits = image::Limits::no_limits();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    limits.max_alloc = Some(MAX_DECODER_ALLOCATION);
    limits
}

fn unavailable() -> crate::DocumentError {
    crate::DocumentError::Invalid(IMAGE_UNAVAILABLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captions_preserve_brackets_backslashes_and_literal_markup() {
        let pin = crate::SourcePin {
            source: mneme_core::RecordId::from_bytes([0xab; 16]),
            revision: mneme_core::RevisionId::from_bytes([0xcd; 16]),
        };
        let target = super::target(pin);
        let caption = "Chart [draft] \\ <not HTML> & final\\";
        let encoded = encode_caption(caption).expect("valid caption");
        let line = format!("image::{target}[{encoded}]");
        let (parsed_target, parsed_caption) = parse_block(&line).expect("image block");
        assert_eq!(parse_target(parsed_target).expect("canonical pin"), pin);
        assert_eq!(parsed_caption, caption);
        for malformed in [
            format!("image::{target}[unclosed"),
            format!("image::{target}[extra]text]"),
            format!("image::{target}[escaped\\]"),
        ] {
            let (invalid_target, _) = parse_block(&malformed).expect("malformed image block");
            assert!(parse_target(invalid_target).is_err());
        }
        assert!(encode_caption("new\nline").is_err());
        assert!(encode_caption(&"x".repeat(MAX_CAPTION_CHARS + 1)).is_err());
    }

    fn scope(local: &str) -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, local).expect("scope")
    }

    fn png() -> Vec<u8> {
        let image = image::RgbaImage::from_raw(2, 1, vec![255, 0, 0, 255, 0, 255, 0, 255])
            .expect("fixture pixels");
        let mut output = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut output, image::ImageFormat::Png)
            .expect("encode fixture PNG");
        output.into_inner()
    }

    fn jpeg() -> Vec<u8> {
        let image =
            image::RgbImage::from_raw(2, 1, vec![255, 0, 0, 0, 255, 0]).expect("fixture pixels");
        let mut output = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut output, image::ImageFormat::Jpeg)
            .expect("encode fixture JPEG");
        output.into_inner()
    }

    fn oversized_dimension_png() -> Vec<u8> {
        let image =
            image::RgbaImage::from_pixel(MAX_IMAGE_DIMENSION + 1, 1, image::Rgba([255, 0, 0, 255]));
        let mut output = std::io::Cursor::new(Vec::new());
        image
            .write_to(&mut output, image::ImageFormat::Png)
            .expect("encode wide fixture PNG");
        output.into_inner()
    }

    fn workspace() -> (tempfile::TempDir, mneme_store::Workspace) {
        let temp = tempfile::tempdir().expect("temporary workspace");
        let workspace = mneme_store::Workspace::create(
            temp.path(),
            mneme_store::WorkspaceConfig {
                clock: Box::new(mneme_store::FixedClock::new(
                    mneme_core::Timestamp::from_nanos(1_000),
                )),
                faults: Box::new(mneme_store::NoFaults),
            },
        )
        .expect("create workspace");
        (temp, workspace)
    }

    fn request(
        workspace: &mneme_store::Workspace,
        key: &str,
        request_scope: mneme_core::ScopeId,
    ) -> ImportRequest {
        ImportRequest {
            actor: "image-test".to_owned(),
            scope: request_scope,
            base: workspace.current_revision().expect("current revision"),
            key: key.to_owned(),
        }
    }

    #[test]
    fn targets_use_one_canonical_pin_spelling() {
        let pin = crate::SourcePin {
            source: mneme_core::RecordId::from_bytes([0x11; 16]),
            revision: mneme_core::RevisionId::from_bytes([0x22; 16]),
        };
        let target = super::target(pin);
        assert_eq!(parse_target(&target).expect("parse target"), pin);
        assert!(parse_target("https://example.invalid/a.png").is_err());
        assert!(parse_target(&target.to_uppercase()).is_err());
        assert!(
            parse_target(
                "mneme-image:11111111111111111111111111111111/22222222222222222222222222222222/"
            )
            .is_err()
        );
    }

    #[test]
    fn imported_bytes_are_pinned_even_when_the_working_file_changes() {
        let (temp, mut workspace) = workspace();
        let path = temp.path().join("candidate.png");
        let original = png();
        std::fs::write(&path, &original).expect("write image");
        let read = read_file(&path).expect("read image");
        let request = request(&workspace, "image-import", scope("cedar"));
        let imported = import(&mut workspace, request, &read).expect("import image");
        std::fs::write(&path, b"changed external file").expect("change external file");
        let loaded = load(
            &mut workspace,
            &scope("cedar"),
            imported.pin,
            Some(imported.workspace_revision),
        )
        .expect("load retained image");
        assert_eq!(loaded.bytes, original);
        assert_eq!(loaded.digest, imported.digest);
    }

    #[test]
    fn retries_replay_the_same_pin_and_reject_different_bytes() {
        let (_temp, mut workspace) = workspace();
        let bytes = png();
        let first_request = request(&workspace, "same-key", scope("cedar"));
        let first = import(&mut workspace, first_request, &bytes).expect("first import");
        let retry_request = request(&workspace, "same-key", scope("cedar"));
        let retry = import(&mut workspace, retry_request, &bytes).expect("retry");
        assert_eq!(retry.pin, first.pin);
        assert_eq!(retry.workspace_revision, first.workspace_revision);

        let changed = image::DynamicImage::ImageRgba8(
            image::RgbaImage::from_raw(1, 1, vec![0, 0, 255, 255]).expect("fixture pixels"),
        );
        let mut changed_bytes = std::io::Cursor::new(Vec::new());
        changed
            .write_to(&mut changed_bytes, image::ImageFormat::Png)
            .expect("encode changed image");
        let changed_request = request(&workspace, "same-key", scope("cedar"));
        let error = import(&mut workspace, changed_request, changed_bytes.get_ref())
            .expect_err("reused key must conflict");
        assert!(matches!(
            error,
            crate::DocumentError::Store(mneme_store::Failure::IdempotencyConflict { .. })
        ));
    }

    #[test]
    fn malformed_and_oversized_imports_leave_the_workspace_unchanged() {
        let (_temp, mut workspace) = workspace();
        let before = workspace.current_revision().expect("before revision");
        let malformed_request = request(&workspace, "malformed", scope("cedar"));
        assert!(import(&mut workspace, malformed_request, b"not an image").is_err());
        let oversized_request = request(&workspace, "oversized", scope("cedar"));
        let oversized = vec![0; MAX_ENCODED_BYTES + 1];
        assert!(import(&mut workspace, oversized_request, &oversized).is_err());
        let wide_request = request(&workspace, "wide-image", scope("cedar"));
        assert!(import(&mut workspace, wide_request, &oversized_dimension_png()).is_err());
        assert_eq!(
            workspace.current_revision().expect("after revision"),
            before
        );
    }

    #[test]
    fn wrong_scope_and_unknown_pins_are_indistinguishable() {
        let (_temp, mut workspace) = workspace();
        let import_request = request(&workspace, "scope", scope("cedar"));
        let imported = import(&mut workspace, import_request, &png()).expect("import image");
        let wrong_scope = load(&mut workspace, &scope("birch"), imported.pin, None)
            .expect_err("cross-scope source must be hidden");
        let unknown = load(
            &mut workspace,
            &scope("cedar"),
            crate::SourcePin {
                source: mneme_core::RecordId::from_bytes([0xaa; 16]),
                revision: mneme_core::RevisionId::from_bytes([0xbb; 16]),
            },
            None,
        )
        .expect_err("unknown source must be hidden");
        assert!(matches!(
            wrong_scope,
            crate::DocumentError::Invalid(IMAGE_UNAVAILABLE)
        ));
        assert!(matches!(
            unknown,
            crate::DocumentError::Invalid(IMAGE_UNAVAILABLE)
        ));
    }

    #[test]
    fn forgotten_sources_are_withheld_from_historical_loads() {
        let (_temp, mut workspace) = workspace();
        let import_request = request(&workspace, "forget-me", scope("cedar"));
        let imported = import(&mut workspace, import_request, &png()).expect("import image");
        let generation = workspace
            .eligibility_generation()
            .expect("eligibility generation")
            .saturating_add(1);
        workspace
            .commit(mneme_store::CommitCommand {
                base: workspace.current_revision().expect("current revision"),
                actor: "retention-test".to_owned(),
                scope: scope("cedar"),
                idempotency_key: "forget-image".to_owned(),
                records: Vec::new(),
                source_blobs: Vec::new(),
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: Some(mneme_store::RetentionCommit {
                    operation_id: "forget-image".to_owned(),
                    operation_kind: "forget".to_owned(),
                    policy_version: "1".to_owned(),
                    selectors: Vec::new(),
                    suppressions: vec![mneme_store::RetentionSuppression {
                        operation_id: "forget-image".to_owned(),
                        target: imported.pin.source,
                        revision: Some(imported.pin.revision),
                        target_kind: "source-revision".to_owned(),
                        mode: mneme_store::SuppressionMode::Forgotten,
                        content_digest: Some(imported.digest),
                        generation,
                    }],
                    locations: Vec::new(),
                    retained_metadata: Vec::new(),
                }),
            })
            .expect("forget image");
        let current = load(&mut workspace, &scope("cedar"), imported.pin, None);
        let historical = load(
            &mut workspace,
            &scope("cedar"),
            imported.pin,
            Some(imported.workspace_revision),
        );
        assert!(matches!(
            current,
            Err(crate::DocumentError::Invalid(IMAGE_UNAVAILABLE))
        ));
        assert!(matches!(
            historical,
            Err(crate::DocumentError::Invalid(IMAGE_UNAVAILABLE))
        ));
    }

    #[test]
    fn decoding_enforces_limits_and_returns_oriented_rgba8() {
        let decoded = decode(&png()).expect("decode fixture");
        assert_eq!(decoded.media_type, "image/png");
        assert_eq!((decoded.width, decoded.height), (2, 1));
        assert_eq!(decoded.rgba.len(), 8);
        let jpeg_decoded = decode(&jpeg()).expect("decode fixture JPEG");
        assert_eq!(jpeg_decoded.media_type, "image/jpeg");
        assert_eq!((jpeg_decoded.width, jpeg_decoded.height), (2, 1));
        assert!(check_dimensions(4_096, 4_096).is_ok());
        assert!(check_dimensions(4_096, 4_097).is_err());
        assert!(decode(b"<svg></svg>").is_err());
        assert!(decode(&vec![0; MAX_ENCODED_BYTES + 1]).is_err());
        assert!(decode(&oversized_dimension_png()).is_err());
    }

    #[test]
    fn bounded_file_reader_rejects_directories_and_symlinks() {
        let temp = tempfile::tempdir().expect("temporary directory");
        assert!(read_file(temp.path()).is_err());
        let path = temp.path().join("image.png");
        std::fs::write(&path, png()).expect("write image");
        #[cfg(unix)]
        {
            let link = temp.path().join("link.png");
            std::os::unix::fs::symlink(&path, &link).expect("create symlink");
            assert!(read_file(&link).is_err());
        }
        let oversized = temp.path().join("oversized.png");
        std::fs::write(&oversized, vec![0; MAX_ENCODED_BYTES + 1]).expect("write oversized input");
        assert!(read_file(&oversized).is_err());
    }

    #[test]
    fn generic_malformed_image_source_cannot_bypass_import_validation() {
        let (_temp, mut workspace) = workspace();
        let bytes = b"not actually a PNG";
        let scope = scope("cedar");
        let base = workspace.current_revision().expect("base revision");
        let source_id = mneme_core::RecordId::from_bytes([0x31; 16]);
        let source_revision = mneme_core::RevisionId::from_bytes([0x32; 16]);
        let (source, blob) = mneme_memory::build_source(
            source_id,
            source_revision,
            &scope,
            mneme_memory::SourceOptions {
                bytes,
                media_type: "image/png",
                entity: None,
                path_hint: None,
            },
        )
        .expect("build generic source");
        workspace
            .commit(mneme_store::CommitCommand {
                base,
                actor: "generic-source".to_owned(),
                scope: scope.clone(),
                idempotency_key: "generic-image-source".to_owned(),
                records: vec![source],
                source_blobs: vec![blob],
                publications: Vec::new(),
                import_candidates: Vec::new(),
                retention: None,
            })
            .expect("commit generic source");
        let error = load(
            &mut workspace,
            &scope,
            crate::SourcePin {
                source: source_id,
                revision: source_revision,
            },
            None,
        )
        .expect_err("malformed generic source must not load");
        assert!(matches!(
            error,
            crate::DocumentError::Invalid(IMAGE_UNAVAILABLE)
        ));
    }
}
