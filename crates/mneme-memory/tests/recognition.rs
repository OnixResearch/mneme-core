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
    let run_id = common::rid(0xa3);
    let segment_id = common::rid(0xa4);
    let run = mneme_memory::build_recognition_run(
        run_id,
        common::rev(0xb3),
        &common::scope(),
        mneme_memory::RecognitionRunOptions {
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
        },
    )
    .expect("recognition run");
    let segment = mneme_memory::build_recognition_segment(
        segment_id,
        common::rev(0xb4),
        &common::scope(),
        mneme_memory::RecognitionSegmentOptions {
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
    assert!(view.assertions().expect("assertion records").is_empty());
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
            acquisition: mneme_core::Acquisition::Captured,
            derived_from: derived.map(|(parent, _)| parent),
            media_extent: Some(mneme_core::MediaExtent::Pages { page_count: 1 }),
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
        },
    )
    .expect("run");
    let segment = mneme_memory::build_recognition_segment(
        segment_id,
        common::rev(seed + 2),
        &common::scope(),
        mneme_memory::RecognitionSegmentOptions {
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
