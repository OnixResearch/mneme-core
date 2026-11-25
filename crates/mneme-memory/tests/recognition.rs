//! Regression tests for recognition provenance and correction lineage.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

mod common;

struct Fixture {
    input: mneme_core::SourcePin,
    output: mneme_core::SourcePin,
    run: mneme_core::RecordId,
    segment: mneme_core::RecordId,
    input_digest: mneme_core::ContentDigest,
    location: mneme_core::MediaLocation,
}

fn commit_recognition(workspace: &mut mneme_store::Workspace) -> Fixture {
    let audio = b"recognition fixture audio";
    let text = b"hello world";
    let input = mneme_core::SourcePin::new(common::rid(0xa1), common::rev(0xb1));
    let output = mneme_core::SourcePin::new(common::rid(0xa2), common::rev(0xb2));
    let input_digest = mneme_core::ContentDigest::of_source_bytes(audio);
    let output_digest = mneme_core::ContentDigest::of_source_bytes(text);
    let time_base = mneme_core::TimeBase::new(1, 100).expect("time base");
    let location = mneme_core::MediaLocation::Audio {
        start_tick: 20,
        end_tick: 40,
        time_base,
        channel: 0,
    };
    let (input_record, input_blob, output_record, output_blob) =
        recognition_source_records(input, output, audio, text, time_base);
    let (run_id, segment_id) = (common::rid(0xa3), common::rid(0xa4));
    let run = mneme_memory::build_recognition_run(
        run_id,
        common::rev(0xb3),
        &common::scope(),
        mneme_memory::RecognitionRunOptions {
            page: None,
            input,
            input_digest,
            output,
            output_digest,
            model: "test-model@sha256:01",
            runtime: "test-runtime@sha256:02",
            adapter: "test-adapter@sha256:03",
            preprocessing: "test-preprocess@sha256:04",
            configuration: "test-config@sha256:05",
            segments: &[segment_id],
            coverage: mneme_core::RecognitionCoverage::new(1, 1).expect("coverage"),
            status: mneme_core::RecognitionStatus::Complete,
            scores: &[],
            alternatives: &[],
            covers: mneme_core::CapturePart::Whole,
        },
    )
    .expect("recognition run");
    let segment = mneme_memory::build_recognition_segment(
        segment_id,
        common::rev(0xb4),
        &common::scope(),
        mneme_memory::RecognitionSegmentOptions {
            block: None,
            run: Some(run_id),
            text_source: output,
            span: mneme_core::SourceSpan::new(0, 4).expect("text span"),
            media_source: input,
            media_digest: input_digest,
            location: &location,
        },
    )
    .expect("recognition segment");
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .commit(common::batch(
            "recognition-fixture",
            vec![input_record, output_record, run, segment],
            vec![input_blob, output_blob],
        ))
        .expect("commit recognition");
    Fixture {
        input,
        output,
        run: run_id,
        segment: segment_id,
        input_digest,
        location,
    }
}

fn recognition_source_records(
    input: mneme_core::SourcePin,
    output: mneme_core::SourcePin,
    audio: &[u8],
    text: &[u8],
    time_base: mneme_core::TimeBase,
) -> (
    mneme_store::RecordDraft,
    mneme_store::SourceBlobDraft,
    mneme_store::RecordDraft,
    mneme_store::SourceBlobDraft,
) {
    let (input_record, input_blob) = mneme_memory::build_captured_source(
        input.source(),
        input.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: audio,
            media_type: "audio/wav",
            entity: None,
            path_hint: None,
        },
        mneme_core::MediaExtent::Audio {
            duration_ticks: 100,
            time_base,
            channels: 1,
        },
    )
    .expect("captured source");
    let (output_record, output_blob) = mneme_memory::build_recognized_source(
        output.source(),
        output.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: text,
            media_type: "text/plain; charset=utf-8",
            entity: None,
            path_hint: None,
        },
        input,
    )
    .expect("recognized text");
    (input_record, input_blob, output_record, output_blob)
}

#[test]
fn recognition_and_correction_keep_exact_pins_and_shared_evidence_roots() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let corrected = mneme_core::SourcePin::new(fixture.output.source(), common::rev(0xb5));
    let correction = mneme_core::CorrectionProvenance::new(
        "human-reviewer",
        "inserted a leading word",
        mneme_core::AlignmentDisposition::Updated,
    )
    .expect("correction provenance");
    let (corrected_record, corrected_blob) = mneme_memory::build_corrected_source(
        fixture.output,
        corrected.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: b"well hello world",
            media_type: "text/plain; charset=utf-8",
            entity: None,
            path_hint: None,
        },
        &correction,
    )
    .expect("corrected source");
    let corrected_segment = mneme_memory::build_recognition_segment(
        common::rid(0xa5),
        common::rev(0xb6),
        &common::scope(),
        mneme_memory::RecognitionSegmentOptions {
            block: None,
            run: None,
            text_source: corrected,
            span: mneme_core::SourceSpan::new(5, 9).expect("updated text span"),
            media_source: fixture.input,
            media_digest: fixture.input_digest,
            location: &fixture.location,
        },
    )
    .expect("corrected alignment");
    mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .commit(common::batch(
            "correction-fixture",
            vec![corrected_record, corrected_segment],
            vec![corrected_blob],
        ))
        .expect("commit correction and fresh alignment");

    let view = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view");
    let original_text = view
        .source_at(fixture.output.source(), fixture.output.revision())
        .expect("machine text");
    let corrected_text = view
        .source_at(corrected.source(), corrected.revision())
        .expect("corrected text");
    assert_eq!(
        original_text.acquisition,
        mneme_core::Acquisition::MachineRecognized
    );
    assert_eq!(
        corrected_text.acquisition,
        mneme_core::Acquisition::Corrected
    );
    assert_eq!(corrected_text.derived_from, Some(fixture.output));
    assert_eq!(corrected_text.correction, Some(correction));
    assert_eq!(
        view.source_status_for(&original_text)
            .expect("original bytes"),
        mneme_memory::SourceStatus::Retained(b"hello world".to_vec())
    );
    assert_eq!(
        view.source_status_for(&corrected_text)
            .expect("corrected bytes"),
        mneme_memory::SourceStatus::Retained(b"well hello world".to_vec())
    );
    assert_eq!(
        view.recognition_run(fixture.run).expect("run").segments,
        std::collections::BTreeSet::from([fixture.segment])
    );
    let corrected_segments =
        view.recognition_segments_for_source(corrected.source(), corrected.revision());
    assert_eq!(corrected_segments.len(), 1);
    assert_eq!(
        corrected_segments[0].text_span,
        mneme_core::SourceSpan::new(5, 9).expect("new span")
    );
    assert_eq!(corrected_segments[0].run, None);
    assert_eq!(
        view.source_roots(fixture.input).expect("input root"),
        view.source_roots(fixture.output)
            .expect("machine text root")
    );
    assert_eq!(
        view.source_roots(fixture.input).expect("input root"),
        view.source_roots(corrected).expect("corrected root")
    );
}

#[test]
fn recognition_refuses_changed_input_digest_and_out_of_range_media_locations() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let invalid_run = mneme_memory::build_recognition_run(
        common::rid(0xa6),
        common::rev(0xb6),
        &common::scope(),
        mneme_memory::RecognitionRunOptions {
            page: None,
            input: fixture.input,
            input_digest: mneme_core::ContentDigest::of_source_bytes(b"changed bytes"),
            output: fixture.output,
            output_digest: mneme_core::ContentDigest::of_source_bytes(b"hello world"),
            model: "test-model@sha256:01",
            runtime: "test-runtime@sha256:02",
            adapter: "test-adapter@sha256:03",
            preprocessing: "test-preprocess@sha256:04",
            configuration: "test-config@sha256:05",
            segments: &[],
            coverage: mneme_core::RecognitionCoverage::new(1, 1).expect("coverage"),
            status: mneme_core::RecognitionStatus::Complete,
            scores: &[],
            alternatives: &[],
            covers: mneme_core::CapturePart::Whole,
        },
    )
    .expect("typed run draft");
    assert!(
        mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
            .commit(common::batch(
                "wrong-input-digest",
                vec![invalid_run],
                Vec::new()
            ))
            .is_err()
    );

    let outside = mneme_core::MediaLocation::Audio {
        start_tick: 90,
        end_tick: 101,
        time_base: mneme_core::TimeBase::new(1, 100).expect("time base"),
        channel: 0,
    };
    let invalid_segment = mneme_memory::build_recognition_segment(
        common::rid(0xa7),
        common::rev(0xb7),
        &common::scope(),
        mneme_memory::RecognitionSegmentOptions {
            block: None,
            run: Some(common::rid(0xa8)),
            text_source: fixture.output,
            span: mneme_core::SourceSpan::new(0, 4).expect("span"),
            media_source: fixture.input,
            media_digest: fixture.input_digest,
            location: &outside,
        },
    )
    .expect("well-formed but out-of-range segment draft");
    let run = mneme_memory::build_recognition_run(
        common::rid(0xa8),
        common::rev(0xb8),
        &common::scope(),
        mneme_memory::RecognitionRunOptions {
            page: None,
            input: fixture.input,
            input_digest: fixture.input_digest,
            output: fixture.output,
            output_digest: mneme_core::ContentDigest::of_source_bytes(b"hello world"),
            model: "test-model@sha256:01",
            runtime: "test-runtime@sha256:02",
            adapter: "test-adapter@sha256:03",
            preprocessing: "test-preprocess@sha256:04",
            configuration: "test-config@sha256:05",
            segments: &[common::rid(0xa7)],
            coverage: mneme_core::RecognitionCoverage::new(1, 1).expect("coverage"),
            status: mneme_core::RecognitionStatus::Complete,
            scores: &[],
            alternatives: &[],
            covers: mneme_core::CapturePart::Whole,
        },
    )
    .expect("typed run draft");
    assert!(
        mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
            .commit(common::batch(
                "outside-media-location",
                vec![run, invalid_segment],
                Vec::new()
            ))
            .is_err()
    );
}

#[test]
fn a_legacy_acquisition_symbol_reads_as_imported_and_survives_pruning() {
    let mut source = mneme_core::fixtures::source_revision();
    let mut payload = source.payload.as_map().clone();
    payload.insert(
        mneme_core::Symbol::from("acquisition"),
        mneme_core::Value::symbol("scanned-by-peer"),
    );
    source.payload = mneme_core::Payload::new(payload);
    let view = mneme_memory::SourceView::parse(source).expect("a v1 source stays readable");
    assert_eq!(view.acquisition, mneme_core::Acquisition::Imported);
    assert_eq!(
        view.acquisition_value,
        mneme_core::Value::symbol("scanned-by-peer")
    );
    let pruned = mneme_memory::build_unavailable_source_preserving(
        &view,
        common::rev(0xee),
        "pruned for the test",
        "pruned",
    );
    assert_eq!(
        pruned.payload.get("acquisition"),
        Some(&mneme_core::Value::symbol("scanned-by-peer")),
        "rewriting a source keeps its stored acquisition symbol"
    );
}

#[test]
fn a_later_run_cannot_claim_existing_machine_text() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let claimant = mneme_memory::build_recognition_run(
        common::rid(0xa9),
        common::rev(0xb9),
        &common::scope(),
        mneme_memory::RecognitionRunOptions {
            page: None,
            input: fixture.input,
            input_digest: fixture.input_digest,
            output: fixture.output,
            output_digest: mneme_core::ContentDigest::of_source_bytes(b"hello world"),
            model: "other-model@sha256:09",
            runtime: "test-runtime@sha256:02",
            adapter: "test-adapter@sha256:03",
            preprocessing: "test-preprocess@sha256:04",
            configuration: "test-config@sha256:05",
            segments: &[],
            coverage: mneme_core::RecognitionCoverage::new(1, 1).expect("coverage"),
            status: mneme_core::RecognitionStatus::Complete,
            scores: &[],
            alternatives: &[],
            covers: mneme_core::CapturePart::Whole,
        },
    )
    .expect("run draft");
    let refused = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .commit(common::batch("claimant-run", vec![claimant], Vec::new()));
    assert!(
        refused.is_err(),
        "a run must commit the text it produced, not claim another run's"
    );
}

fn image_source(
    pin: mneme_core::SourcePin,
    bytes: &[u8],
    frame: mneme_core::CoordinateFrame,
    derived: Option<(mneme_core::SourcePin, mneme_core::MediaTransform)>,
) -> (mneme_store::RecordDraft, mneme_store::SourceBlobDraft) {
    paged_image_source(pin, (bytes, 1), frame, derived)
}

fn paged_image_source(
    pin: mneme_core::SourcePin,
    (bytes, page_count): (&[u8], u32),
    frame: mneme_core::CoordinateFrame,
    derived: Option<(mneme_core::SourcePin, mneme_core::MediaTransform)>,
) -> (mneme_store::RecordDraft, mneme_store::SourceBlobDraft) {
    mneme_memory::build_source_with_provenance(
        pin.source(),
        pin.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes,
            media_type: "image/png",
            entity: None,
            path_hint: None,
        },
        mneme_memory::SourceProvenance {
            derivation: None,
            acquisition: mneme_core::Acquisition::Captured,
            derived_from: derived.map(|(parent, _)| parent),
            media_extent: Some(mneme_core::MediaExtent::Pages { page_count }),
            media_transform: derived.map(|(_, transform)| transform),
            media_frame: Some(frame),
            ink_inventory: None,
            correction: None,
        },
    )
    .expect("image source")
}

/// Commit machine text recognized from `media` with one segment at
/// `location`, as one batch.
fn recognize(
    workspace: &mut mneme_store::Workspace,
    media: (mneme_core::SourcePin, &[u8]),
    location: &mneme_core::MediaLocation,
    seed: u8,
) -> mneme_memory::Result<mneme_store::CommitOutcome> {
    let (input, input_bytes) = media;
    let text = mneme_core::SourcePin::new(common::rid(seed), common::rev(seed));
    let (run_id, segment_id) = (common::rid(seed + 1), common::rid(seed + 2));
    let (text_record, text_blob) = mneme_memory::build_recognized_source(
        text.source(),
        text.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: b"page words",
            media_type: "text/plain; charset=utf-8",
            entity: None,
            path_hint: None,
        },
        input,
    )
    .expect("recognized text");
    let input_digest = mneme_core::ContentDigest::of_source_bytes(input_bytes);
    let run = mneme_memory::build_recognition_run(
        run_id,
        common::rev(seed + 1),
        &common::scope(),
        mneme_memory::RecognitionRunOptions {
            page: None,
            input,
            input_digest,
            output: text,
            output_digest: mneme_core::ContentDigest::of_source_bytes(b"page words"),
            model: "ocr-model@sha256:01",
            runtime: "test-runtime@sha256:02",
            adapter: "test-adapter@sha256:03",
            preprocessing: "none",
            configuration: "test-config@sha256:05",
            segments: &[segment_id],
            coverage: mneme_core::RecognitionCoverage::new(1, 1).expect("coverage"),
            status: mneme_core::RecognitionStatus::Complete,
            scores: &[],
            alternatives: &[],
            covers: mneme_core::CapturePart::Whole,
        },
    )
    .expect("run");
    let segment = mneme_memory::build_recognition_segment(
        segment_id,
        common::rev(seed + 2),
        &common::scope(),
        mneme_memory::RecognitionSegmentOptions {
            block: None,
            run: Some(run_id),
            text_source: text,
            span: mneme_core::SourceSpan::new(0, 3).expect("span"),
            media_source: input,
            media_digest: input_digest,
            location,
        },
    )
    .expect("segment");
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator).commit(common::batch(
        &format!("recognize-{seed}"),
        vec![text_record, run, segment],
        vec![text_blob],
    ))
}

#[test]
fn page_regions_are_checked_against_the_image_and_its_crop() {
    let (_temp, mut workspace) = common::setup();
    let image = mneme_core::CoordinateFrame::Pixels {
        width: 400,
        height: 300,
    };
    let crop_frame = mneme_core::CoordinateFrame::Pixels {
        width: 200,
        height: 150,
    };
    let original = mneme_core::SourcePin::new(common::rid(0xd0), common::rev(0xd0));
    let crop = mneme_core::SourcePin::new(common::rid(0xd1), common::rev(0xd1));
    let transform =
        mneme_core::MediaTransform::new(crop_frame, image, [2.0, 0.0, 0.0, 0.0, 2.0, 0.0])
            .expect("2x transform");
    let (original_record, original_blob) = image_source(original, b"original image", image, None);
    let (crop_record, crop_blob) = image_source(
        crop,
        b"cropped image",
        crop_frame,
        Some((original, transform)),
    );
    mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .commit(common::batch(
            "images",
            vec![original_record, crop_record],
            vec![original_blob, crop_blob],
        ))
        .expect("a crop whose transform maps its frame onto the original's");
    let on_crop = mneme_core::MediaLocation::PageRegion {
        page: 0,
        frame: crop_frame,
        x: 10.0,
        y: 20.0,
        width: 30.0,
        height: 30.0,
    };
    recognize(&mut workspace, (crop, b"cropped image"), &on_crop, 0xe0)
        .expect("a region on the crop, in the crop's frame");
    let oversized = mneme_core::MediaLocation::PageRegion {
        page: 0,
        frame: mneme_core::CoordinateFrame::Pixels {
            width: 10_000,
            height: 10_000,
        },
        x: 5_000.0,
        y: 10.0,
        width: 20.0,
        height: 20.0,
    };
    assert!(
        recognize(
            &mut workspace,
            (original, b"original image"),
            &oversized,
            0xe4
        )
        .is_err(),
        "a region outside the 400x300 image is refused"
    );
    let mismatched = mneme_core::SourcePin::new(common::rid(0xd2), common::rev(0xd2));
    let (mismatched_record, mismatched_blob) = image_source(
        mismatched,
        b"mislabelled crop",
        mneme_core::CoordinateFrame::Pixels {
            width: 100,
            height: 75,
        },
        Some((original, transform)),
    );
    assert!(
        mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
            .commit(common::batch(
                "mismatched-crop",
                vec![mismatched_record],
                vec![mismatched_blob],
            ))
            .is_err(),
        "a transform must start from the derivative's own frame"
    );
}

#[test]
fn a_transform_must_land_on_its_parents_frame_and_pages() {
    let (_temp, mut workspace) = common::setup();
    let image = mneme_core::CoordinateFrame::Pixels {
        width: 400,
        height: 300,
    };
    let half = mneme_core::CoordinateFrame::Pixels {
        width: 200,
        height: 150,
    };
    let original = mneme_core::SourcePin::new(common::rid(0xf0), common::rev(0xf0));
    let (original_record, original_blob) = image_source(original, b"original image", image, None);
    mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .commit(common::batch(
            "original",
            vec![original_record],
            vec![original_blob],
        ))
        .expect("original image");
    let commit =
        |workspace: &mut mneme_store::Workspace,
         (record, blob): (mneme_store::RecordDraft, mneme_store::SourceBlobDraft),
         key: &str| {
            mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
                .commit(common::batch(key, vec![record], vec![blob]))
        };
    // Maps the half-size image onto an 800x600 plane the parent never declared.
    let elsewhere = mneme_core::MediaTransform::new(
        half,
        mneme_core::CoordinateFrame::Pixels {
            width: 800,
            height: 600,
        },
        [4.0, 0.0, 0.0, 0.0, 4.0, 0.0],
    )
    .expect("4x transform");
    let wrong_target = mneme_core::SourcePin::new(common::rid(0xf1), common::rev(0xf1));
    assert!(
        commit(
            &mut workspace,
            image_source(
                wrong_target,
                b"misplaced scale",
                half,
                Some((original, elsewhere))
            ),
            "wrong-target",
        )
        .is_err(),
        "a transform must land on the parent's declared frame"
    );
    let onto_parent =
        mneme_core::MediaTransform::new(half, image, [2.0, 0.0, 0.0, 0.0, 2.0, 0.0]).expect("2x");
    let extra_page = mneme_core::SourcePin::new(common::rid(0xf2), common::rev(0xf2));
    assert!(
        commit(
            &mut workspace,
            paged_image_source(
                extra_page,
                (b"two processed pages", 2),
                half,
                Some((original, onto_parent)),
            ),
            "extra-page",
        )
        .is_err(),
        "a transform carries no page offset, so the pages must match"
    );
    let resampled = mneme_core::SourcePin::new(common::rid(0xf3), common::rev(0xf3));
    commit(
        &mut workspace,
        image_source(resampled, b"half size", half, Some((original, onto_parent))),
        "resampled",
    )
    .expect("a transform onto the parent's frame and pages");
}

fn audio_location(start_tick: u64, end_tick: u64) -> mneme_core::MediaLocation {
    mneme_core::MediaLocation::Audio {
        start_tick,
        end_tick,
        time_base: mneme_core::TimeBase::new(1, 100).expect("time base"),
        channel: 0,
    }
}

/// One recognition run to commit over a capture.
struct Run<'a> {
    /// Identities derive from this byte.
    byte: u8,
    text: &'a str,
    segment: Option<mneme_core::MediaLocation>,
    covers: mneme_core::CapturePart,
    status: mneme_core::RecognitionStatus,
    /// Write the `covers` field; without it the run covers its whole capture.
    has_covers_field: bool,
}

/// Unit coverage consistent with a run's status.
fn coverage_for(status: mneme_core::RecognitionStatus) -> mneme_core::RecognitionCoverage {
    let (completed, total) = match status {
        mneme_core::RecognitionStatus::Complete => (1, 1),
        mneme_core::RecognitionStatus::Partial => (1, 2),
        mneme_core::RecognitionStatus::Failed
        | mneme_core::RecognitionStatus::Unsupported
        | mneme_core::RecognitionStatus::Cancelled => (0, 1),
    };
    mneme_core::RecognitionCoverage::new(completed, total).expect("coverage")
}

/// Commit a new text record recognized from `capture`, with at most one
/// segment.
fn recognize_run(
    workspace: &mut mneme_store::Workspace,
    (capture, capture_digest): (mneme_core::SourcePin, mneme_core::ContentDigest),
    run: &Run<'_>,
) -> mneme_memory::Result<mneme_core::SourcePin> {
    let output = mneme_core::SourcePin::new(common::rid(run.byte), common::rev(run.byte));
    let run_id = common::rid(run.byte.wrapping_add(1));
    let segment_id = common::rid(run.byte.wrapping_add(2));
    let (text_record, text_blob) = mneme_memory::build_recognized_source(
        output.source(),
        output.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: run.text.as_bytes(),
            media_type: "text/plain; charset=utf-8",
            entity: None,
            path_hint: None,
        },
        capture,
    )?;
    let segments = run
        .segment
        .as_ref()
        .map_or(Vec::new(), |_| vec![segment_id]);
    let mut run_record = mneme_memory::build_recognition_run(
        run_id,
        common::rev(run.byte.wrapping_add(1)),
        &common::scope(),
        mneme_memory::RecognitionRunOptions {
            page: None,
            input: capture,
            input_digest: capture_digest,
            output,
            output_digest: mneme_core::ContentDigest::of_source_bytes(run.text.as_bytes()),
            model: "test-model@sha256:01",
            runtime: "test-runtime@sha256:02",
            adapter: "test-adapter@sha256:03",
            preprocessing: "test-preprocess@sha256:04",
            configuration: "test-config@sha256:05",
            segments: &segments,
            coverage: coverage_for(run.status),
            status: run.status,
            scores: &[],
            alternatives: &[],
            covers: run.covers,
        },
    )?;
    if !run.has_covers_field {
        run_record.payload.remove("covers");
    }
    let mut records = vec![text_record, run_record];
    if let Some(location) = &run.segment {
        records.push(mneme_memory::build_recognition_segment(
            segment_id,
            common::rev(run.byte.wrapping_add(2)),
            &common::scope(),
            mneme_memory::RecognitionSegmentOptions {
                block: None,
                run: Some(run_id),
                text_source: output,
                span: mneme_core::SourceSpan::new(0, 0).expect("text span"),
                media_source: capture,
                media_digest: capture_digest,
                location,
            },
        )?);
    }
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator).commit(common::batch(
        &format!("rerecognize-{}", run.byte),
        records,
        vec![text_blob],
    ))?;
    Ok(output)
}

/// Recognize the fixture's audio capture again as a complete run covering
/// `covers`.
fn rerecognize(
    workspace: &mut mneme_store::Workspace,
    fixture: &Fixture,
    (byte, text): (u8, &str),
    segment: Option<mneme_core::MediaLocation>,
    covers: mneme_core::CapturePart,
) -> mneme_memory::Result<mneme_core::SourcePin> {
    recognize_run(
        workspace,
        (fixture.input, fixture.input_digest),
        &Run {
            byte,
            text,
            segment,
            covers,
            status: mneme_core::RecognitionStatus::Complete,
            has_covers_field: true,
        },
    )
}

/// Correct `text` as a new revision. With a segment the alignment is
/// updated; without one it is declared invalidated.
fn correct(
    workspace: &mut mneme_store::Workspace,
    fixture: &Fixture,
    (text, revision): (mneme_core::SourcePin, u8),
    content: &str,
    segment: Option<u8>,
) -> mneme_core::SourcePin {
    let corrected = mneme_core::SourcePin::new(text.source(), common::rev(revision));
    let alignment = if segment.is_some() {
        mneme_core::AlignmentDisposition::Updated
    } else {
        mneme_core::AlignmentDisposition::Invalidated
    };
    let correction = mneme_core::CorrectionProvenance::new("reviewer", "edited", alignment)
        .expect("correction provenance");
    let (record, blob) = mneme_memory::build_corrected_source(
        text,
        corrected.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: content.as_bytes(),
            media_type: "text/plain; charset=utf-8",
            entity: None,
            path_hint: None,
        },
        &correction,
    )
    .expect("corrected source");
    let mut records = vec![record];
    if let Some(segment) = segment {
        records.push(
            mneme_memory::build_recognition_segment(
                common::rid(segment),
                common::rev(segment),
                &common::scope(),
                mneme_memory::RecognitionSegmentOptions {
                    block: None,
                    run: None,
                    text_source: corrected,
                    span: mneme_core::SourceSpan::new(0, 0).expect("text span"),
                    media_source: fixture.input,
                    media_digest: fixture.input_digest,
                    location: &fixture.location,
                },
            )
            .expect("aligned segment"),
        );
    }
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .commit(common::batch(
            &format!("correct-{revision}"),
            records,
            vec![blob],
        ))
        .expect("commit correction");
    corrected
}

fn capture_selection(
    workspace: &mut mneme_store::Workspace,
    fixture: &Fixture,
) -> mneme_memory::beliefs::captures::Selection {
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view")
        .capture_texts(fixture.input, &common::scope())
}

fn pins(texts: &[mneme_memory::beliefs::captures::Text]) -> Vec<mneme_core::SourcePin> {
    texts.iter().map(|text| text.pin).collect()
}

#[test]
fn a_corrected_text_stays_selected_until_a_reprocessed_result_is_chosen() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let whole = mneme_core::CapturePart::Whole;
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![fixture.output]);
    assert!(selection.alternatives.is_empty());

    // Later machine output replaces earlier machine output.
    let second = rerecognize(
        &mut workspace,
        &fixture,
        (0xc0, "hello word"),
        Some(fixture.location.clone()),
        whole,
    )
    .expect("second run");
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![second]);
    assert_eq!(pins(&selection.alternatives), vec![fixture.output]);

    // A correction outranks machine output published before or after it.
    let corrected = correct(
        &mut workspace,
        &fixture,
        (fixture.output, 0xb5),
        "hello, world",
        Some(0xa5),
    );
    let third = rerecognize(
        &mut workspace,
        &fixture,
        (0xd0, "hello world!"),
        Some(fixture.location.clone()),
        whole,
    )
    .expect("third run");
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![corrected]);
    assert!(selection.selected[0].is_corrected);
    assert_eq!(selection.selected[0].segments.len(), 1);
    assert_eq!(pins(&selection.alternatives), vec![third, second]);
    let view = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view");
    assert_eq!(
        view.unselected_recognized_texts(),
        std::collections::BTreeSet::from([second.source(), third.source()])
    );

    // Choosing the third result is a correction of it; this one declares its
    // alignment invalidated, so it carries no segments.
    let chosen = correct(
        &mut workspace,
        &fixture,
        (third, 0xd8),
        "hello world!",
        None,
    );
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![chosen]);
    assert!(selection.selected[0].is_alignment_invalidated);
    assert!(selection.selected[0].segments.is_empty());
    assert_eq!(pins(&selection.alternatives), vec![corrected, second]);

    // A caller who cannot read the capture's scope sees no texts at all.
    let other = common::project_scope("elsewhere");
    let hidden = mneme_memory::Engine::new(
        &mut workspace,
        mneme_memory::Access::scopes([other.clone()]),
    )
    .view()
    .expect("view")
    .capture_texts(fixture.input, &other);
    assert!(hidden.selected.is_empty());
    assert!(hidden.alternatives.is_empty());
}

#[test]
fn texts_of_different_parts_are_selected_side_by_side() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let first_half = mneme_core::CapturePart::Audio {
        start_tick: 0,
        end_tick: 50,
    };
    let second_half = mneme_core::CapturePart::Audio {
        start_tick: 50,
        end_tick: 100,
    };
    let early = rerecognize(
        &mut workspace,
        &fixture,
        (0xc0, "early"),
        Some(audio_location(20, 40)),
        first_half,
    )
    .expect("first half");
    let late = rerecognize(
        &mut workspace,
        &fixture,
        (0xd0, "late"),
        Some(audio_location(60, 80)),
        second_half,
    )
    .expect("second half");
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![early, late]);
    // The original whole-capture text shares both halves.
    assert_eq!(pins(&selection.alternatives), vec![fixture.output]);

    // Reprocessing the first half finds no segments, and still replaces only
    // the first half's text: the run declares the part it covers.
    let again = rerecognize(&mut workspace, &fixture, (0xe0, "um"), None, first_half)
        .expect("reprocessed first half");
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![again, late]);
    assert_eq!(pins(&selection.alternatives), vec![early, fixture.output]);
}

#[test]
fn a_run_must_cover_a_part_of_its_input_that_holds_its_segments() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let refused = |result: mneme_memory::Result<mneme_core::SourcePin>, expected: &str| {
        assert!(
            matches!(&result, Err(error) if error.to_string().contains(expected)),
            "{result:?}"
        );
    };
    refused(
        rerecognize(
            &mut workspace,
            &fixture,
            (0xc0, "outside"),
            Some(audio_location(20, 40)),
            mneme_core::CapturePart::Audio {
                start_tick: 0,
                end_tick: 10,
            },
        ),
        "outside the part",
    );
    refused(
        rerecognize(
            &mut workspace,
            &fixture,
            (0xc4, "beyond"),
            None,
            mneme_core::CapturePart::Audio {
                start_tick: 0,
                end_tick: 200,
            },
        ),
        "within its capture's extent",
    );
    refused(
        rerecognize(
            &mut workspace,
            &fixture,
            (0xc8, "page"),
            None,
            mneme_core::CapturePart::Page(0),
        ),
        "within its capture's extent",
    );
    refused(
        rerecognize(
            &mut workspace,
            &fixture,
            (0xcc, "empty"),
            None,
            mneme_core::CapturePart::Audio {
                start_tick: 30,
                end_tick: 30,
            },
        ),
        "non-empty",
    );
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![fixture.output]);
    assert!(selection.alternatives.is_empty());
}

#[test]
fn a_partial_reprocess_leaves_the_rest_of_the_capture_its_text() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let first_half = mneme_core::CapturePart::Audio {
        start_tick: 0,
        end_tick: 50,
    };
    let early = rerecognize(
        &mut workspace,
        &fixture,
        (0xc0, "early"),
        Some(audio_location(20, 40)),
        first_half,
    )
    .expect("first half");
    // Nothing newer covers ticks 50 to 100, so the whole transcript stays.
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(
        pins(&selection.selected)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([fixture.output, early])
    );
    assert!(selection.alternatives.is_empty());
}

#[test]
fn choosing_a_reprocessed_half_keeps_the_corrected_whole() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let corrected = correct(
        &mut workspace,
        &fixture,
        (fixture.output, 0xb5),
        "hello, world",
        Some(0xa5),
    );
    let first_half = mneme_core::CapturePart::Audio {
        start_tick: 0,
        end_tick: 50,
    };
    let second_half = mneme_core::CapturePart::Audio {
        start_tick: 50,
        end_tick: 100,
    };
    let early = rerecognize(
        &mut workspace,
        &fixture,
        (0xc0, "early"),
        Some(audio_location(20, 40)),
        first_half,
    )
    .expect("first half");
    let late = rerecognize(
        &mut workspace,
        &fixture,
        (0xd0, "late"),
        Some(audio_location(60, 80)),
        second_half,
    )
    .expect("second half");
    let chosen = correct(&mut workspace, &fixture, (late, 0xd8), "late", None);
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(
        pins(&selection.selected)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([corrected, chosen])
    );
    assert_eq!(pins(&selection.alternatives), vec![early]);
}

#[test]
fn an_incomplete_newer_run_never_displaces_a_complete_text() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let cancelled = recognize_run(
        &mut workspace,
        (fixture.input, fixture.input_digest),
        &Run {
            byte: 0xc0,
            text: "hel",
            segment: None,
            covers: mneme_core::CapturePart::Whole,
            status: mneme_core::RecognitionStatus::Cancelled,
            has_covers_field: true,
        },
    )
    .expect("cancelled run");
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![fixture.output]);
    assert_eq!(pins(&selection.alternatives), vec![cancelled]);
}

#[test]
fn a_run_without_a_declared_part_covers_its_whole_capture() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let undeclared = recognize_run(
        &mut workspace,
        (fixture.input, fixture.input_digest),
        &Run {
            byte: 0xc0,
            text: "hello there",
            segment: None,
            covers: mneme_core::CapturePart::Audio {
                start_tick: 0,
                end_tick: 10,
            },
            status: mneme_core::RecognitionStatus::Complete,
            has_covers_field: false,
        },
    )
    .expect("run without covers");
    let view = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view");
    assert_eq!(
        view.recognition_run(common::rid(0xc1)).expect("run").covers,
        mneme_core::CapturePart::Whole
    );
    // As a whole-capture text, the newer run replaces the original.
    let selection = view.capture_texts(fixture.input, &common::scope());
    assert_eq!(pins(&selection.selected), vec![undeclared]);
    assert_eq!(pins(&selection.alternatives), vec![fixture.output]);
}

#[test]
fn page_parts_are_selected_page_by_page() {
    let (_temp, mut workspace) = common::setup();
    let bytes = b"two page scan";
    let capture = mneme_core::SourcePin::new(common::rid(0x61), common::rev(0x61));
    let (record, blob) = paged_image_source(
        capture,
        (bytes, 2),
        mneme_core::CoordinateFrame::Normalized,
        None,
    );
    mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .commit(common::batch("scan", vec![record], vec![blob]))
        .expect("scan");
    let digest = mneme_core::ContentDigest::of_source_bytes(bytes);
    let region = |page: u32| mneme_core::MediaLocation::PageRegion {
        page,
        frame: mneme_core::CoordinateFrame::Normalized,
        x: 0.1,
        y: 0.1,
        width: 0.5,
        height: 0.1,
    };
    let page_run = |byte: u8, page: u32| Run {
        byte,
        text: "page words",
        segment: Some(region(page)),
        covers: mneme_core::CapturePart::Page(page),
        status: mneme_core::RecognitionStatus::Complete,
        has_covers_field: true,
    };
    let first =
        recognize_run(&mut workspace, (capture, digest), &page_run(0xc0, 0)).expect("page 0");
    let second =
        recognize_run(&mut workspace, (capture, digest), &page_run(0xc4, 1)).expect("page 1");
    let again =
        recognize_run(&mut workspace, (capture, digest), &page_run(0xc8, 0)).expect("page 0 again");
    let selection = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view")
        .capture_texts(capture, &common::scope());
    assert_eq!(pins(&selection.selected), vec![again, second]);
    assert_eq!(pins(&selection.alternatives), vec![first]);
    // A segment outside its run's page is refused.
    let misplaced = Run {
        segment: Some(region(1)),
        ..page_run(0xcc, 0)
    };
    assert!(recognize_run(&mut workspace, (capture, digest), &misplaced).is_err());
}

#[test]
fn a_text_two_runs_name_is_selected_once() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let text = mneme_core::SourcePin::new(common::rid(0xc0), common::rev(0xc0));
    let (text_record, text_blob) = mneme_memory::build_recognized_source(
        text.source(),
        text.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: b"hello again",
            media_type: "text/plain; charset=utf-8",
            entity: None,
            path_hint: None,
        },
        fixture.input,
    )
    .expect("text");
    let first_half = mneme_core::CapturePart::Audio {
        start_tick: 0,
        end_tick: 50,
    };
    let run = |byte: u8, covers: mneme_core::CapturePart| {
        mneme_memory::build_recognition_run(
            common::rid(byte),
            common::rev(byte),
            &common::scope(),
            mneme_memory::RecognitionRunOptions {
                page: None,
                input: fixture.input,
                input_digest: fixture.input_digest,
                output: text,
                output_digest: mneme_core::ContentDigest::of_source_bytes(b"hello again"),
                model: "test-model@sha256:01",
                runtime: "test-runtime@sha256:02",
                adapter: "test-adapter@sha256:03",
                preprocessing: "test-preprocess@sha256:04",
                configuration: "test-config@sha256:05",
                segments: &[],
                coverage: mneme_core::RecognitionCoverage::new(1, 1).expect("coverage"),
                status: mneme_core::RecognitionStatus::Complete,
                scores: &[],
                alternatives: &[],
                covers,
            },
        )
        .expect("run")
    };
    mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .commit(common::batch(
            "two-runs",
            vec![
                text_record,
                run(0xc1, first_half),
                run(0xc2, mneme_core::CapturePart::Whole),
            ],
            vec![text_blob],
        ))
        .expect("two runs naming one text");
    let view = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view");
    // The text appears once, with the part of the run with the lower id,
    // so the original whole transcript still covers the rest of the capture.
    let selection = view.capture_texts(fixture.input, &common::scope());
    assert_eq!(
        pins(&selection.selected)
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        std::collections::BTreeSet::from([fixture.output, text])
    );
    let shown = selection
        .selected
        .iter()
        .find(|selected| selected.pin == text)
        .expect("text");
    assert_eq!(shown.run.covers, first_half);
    assert!(selection.alternatives.is_empty());
    assert!(view.unselected_recognized_texts().is_empty());
}

#[test]
fn choosing_a_partial_reprocess_selects_it_over_an_earlier_correction() {
    let (_temp, mut workspace) = common::setup();
    let fixture = commit_recognition(&mut workspace);
    let corrected = correct(
        &mut workspace,
        &fixture,
        (fixture.output, 0xb5),
        "hello, world",
        Some(0xa5),
    );
    let partial = recognize_run(
        &mut workspace,
        (fixture.input, fixture.input_digest),
        &Run {
            byte: 0xc0,
            text: "hello wor",
            segment: None,
            covers: mneme_core::CapturePart::Whole,
            status: mneme_core::RecognitionStatus::Partial,
            has_covers_field: true,
        },
    )
    .expect("partial run");
    // Machine output from a partial run never displaces the correction ...
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![corrected]);
    // ... but a person choosing it makes it the most recent corrected text.
    let chosen = correct(
        &mut workspace,
        &fixture,
        (partial, 0xc8),
        "hello world",
        None,
    );
    let selection = capture_selection(&mut workspace, &fixture);
    assert_eq!(pins(&selection.selected), vec![chosen]);
    assert_eq!(pins(&selection.alternatives), vec![corrected]);
}
fn text_options(bytes: &[u8]) -> mneme_memory::SourceOptions<'_> {
    mneme_memory::SourceOptions {
        bytes,
        media_type: "text/plain; charset=utf-8",
        entity: None,
        path_hint: None,
    }
}

fn commit_original(workspace: &mut mneme_store::Workspace) -> mneme_core::SourcePin {
    let pin = mneme_core::SourcePin::new(common::rid(0xd1), common::rev(0xe1));
    let opts = mneme_memory::SourceOptions {
        bytes: b"%PDF original",
        media_type: "application/pdf",
        entity: None,
        path_hint: None,
    };
    let extent = mneme_core::MediaExtent::Pages { page_count: 1 };
    let (record, blob) = mneme_memory::build_captured_source(
        pin.source(),
        pin.revision(),
        &common::scope(),
        opts,
        extent,
    )
    .expect("original");
    let _outcome = common::engine(workspace)
        .commit(common::batch("original", vec![record], vec![blob]))
        .expect("commit original");
    assert_eq!(pin.source(), common::rid(0xd1));
    pin
}

fn derive(
    upstream: mneme_core::SourcePin,
    id: u8,
) -> (mneme_store::RecordDraft, mneme_store::SourceBlobDraft) {
    let derivation =
        mneme_core::DerivedAcquisition::new(upstream, "pdftotext", "24.02.0").expect("derivation");
    mneme_memory::build_derived_source(
        common::rid(id),
        common::rev(id),
        &common::scope(),
        text_options(b"companion text"),
        &derivation,
    )
    .expect("derived draft")
}

#[test]
fn a_derived_source_commits_and_reads_back_its_upstream_and_backend() {
    let (_temp, mut workspace) = common::setup();
    let upstream = commit_original(&mut workspace);
    let (record, blob) = derive(upstream, 0xd2);
    assert_eq!(
        record.schema_version,
        mneme_core::DERIVED_ACQUISITION_SCHEMA_VERSION
    );
    common::engine(&mut workspace)
        .commit(common::batch("derived", vec![record], vec![blob]))
        .expect("a derived source over an existing source commits");
    let stored = common::latest(&workspace, common::rid(0xd2));
    let view = mneme_memory::SourceView::parse(stored).expect("derived view");
    assert_eq!(view.acquisition, mneme_core::Acquisition::Derived);
    let derivation = view.derivation.as_ref().expect("derivation");
    assert_eq!(derivation.source(), upstream);
    assert_eq!(derivation.backend().as_str(), "pdftotext");
    assert_eq!(derivation.backend_version(), "24.02.0");
    assert_eq!(view.derived_from, Some(upstream));
    let pruned = mneme_memory::build_unavailable_source_preserving(
        &view,
        common::rev(0xee),
        "pruned for the test",
        "pruned",
    );
    assert_eq!(
        pruned.schema_version,
        mneme_core::DERIVED_ACQUISITION_SCHEMA_VERSION
    );
    assert_eq!(
        pruned.payload.get("acquisition"),
        Some(&derivation.to_value())
    );
}

#[test]
fn a_dangling_or_self_referencing_derived_source_is_refused() {
    let (_temp, mut workspace) = common::setup();
    let dangling = mneme_core::SourcePin::new(common::rid(0xdf), common::rev(0xef));
    let (record, blob) = derive(dangling, 0xd3);
    assert!(
        common::engine(&mut workspace)
            .commit(common::batch("dangling", vec![record], vec![blob]))
            .is_err(),
        "a missing upstream source must be refused"
    );
    let upstream = commit_original(&mut workspace);
    let wrong_revision = mneme_core::SourcePin::new(upstream.source(), common::rev(0xe9));
    let (record, blob) = derive(wrong_revision, 0xd4);
    assert!(
        common::engine(&mut workspace)
            .commit(common::batch("wrong-revision", vec![record], vec![blob]))
            .is_err(),
        "an unknown upstream revision must be refused"
    );
    let own = mneme_core::SourcePin::new(common::rid(0xd5), common::rev(0xe5));
    let (record, blob) = derive(own, 0xd5);
    assert!(
        common::engine(&mut workspace)
            .commit(common::batch("self", vec![record], vec![blob]))
            .is_err(),
        "a derivative cannot name itself as upstream"
    );
}

#[test]
fn a_derived_record_needs_schema_six_and_a_matching_pin() {
    let registry = mneme_core::SchemaRegistry::production();
    let upstream = mneme_core::SourcePin::new(common::rid(0xd1), common::rev(0xe1));
    let (draft, _) = derive(upstream, 0xd6);
    let envelope = |draft: &mneme_store::RecordDraft, version: u32, payload| {
        let mut record = mneme_core::fixtures::source_revision();
        record.schema_version = version;
        record.payload = payload;
        let _ = draft;
        record
    };
    let ok = envelope(&draft, 6, draft.payload.clone());
    mneme_core::validate_record_value(&ok.to_value(), &registry, None)
        .expect("a v6 derived source validates");
    let old = envelope(&draft, 5, draft.payload.clone());
    assert!(
        mneme_core::validate_record_value(&old.to_value(), &registry, None).is_err(),
        "schema 5 keeps a closed symbol acquisition"
    );
    let mut payload = draft.payload.as_map().clone();
    payload.remove(&mneme_core::Symbol::from("derived-from"));
    let unpinned = envelope(&draft, 6, mneme_core::Payload::new(payload.clone()));
    assert!(mneme_core::validate_record_value(&unpinned.to_value(), &registry, None).is_err());
    payload.insert(
        mneme_core::Symbol::from("derived-from"),
        mneme_core::SourcePin::new(common::rid(0xaa), common::rev(0xbb)).to_value(),
    );
    let mismatched = envelope(&draft, 6, mneme_core::Payload::new(payload));
    assert!(mneme_core::validate_record_value(&mismatched.to_value(), &registry, None).is_err());
    let bare = mneme_core::Acquisition::from_value(
        &mneme_core::Value::symbol("derived"),
        &mneme_core::Path::root(),
    );
    assert!(bare.is_err(), "the bare symbol carries no upstream");
}

#[test]
fn authored_and_imported_sources_still_decode_unchanged() {
    for symbol in ["authored", "imported"] {
        let mut source = mneme_core::fixtures::source_revision();
        let mut payload = source.payload.as_map().clone();
        payload.insert(
            mneme_core::Symbol::from("acquisition"),
            mneme_core::Value::symbol(symbol),
        );
        source.payload = mneme_core::Payload::new(payload);
        let registry = mneme_core::SchemaRegistry::production();
        for version in [1, 5, 6] {
            source.schema_version = version;
            mneme_core::validate_record_value(&source.to_value(), &registry, None)
                .expect("authored and imported validate at prior and current schema versions");
        }
        let view = mneme_memory::SourceView::parse(source).expect("view");
        assert!(view.derivation.is_none());
        assert!(!view.acquisition.is_reproducible());
    }
}
