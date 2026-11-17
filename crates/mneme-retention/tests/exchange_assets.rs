//! Forgetting reaches large sources whose chunks are still arriving.
#![allow(unknown_lints, no_unwrap)] // test inputs are deterministic fixtures
#![allow(clippy::unwrap_used, clippy::expect_used)]

const SECRET: [u8; 32] = [0x6b; 32];
const ISSUER: &str = "device-a";
const AUDIO_BYTES: usize = 2 * 1024 * 1024 + 99;

struct Recording {
    audio: mneme_core::SourcePin,
    transcript: mneme_core::SourcePin,
    segment: mneme_core::RecordId,
    bytes: Vec<u8>,
}

fn config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(3_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn workspace(root: &std::path::Path) -> mneme_store::Workspace {
    mneme_store::Workspace::create(root, config()).expect("workspace")
}

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn shared() -> std::collections::BTreeSet<mneme_core::ScopeId> {
    std::collections::BTreeSet::from([scope()])
}

fn rid(byte: u8) -> mneme_core::RecordId {
    mneme_core::RecordId::from_bytes([byte; 16])
}

fn rev(byte: u8) -> mneme_core::RevisionId {
    mneme_core::RevisionId::from_bytes([byte; 16])
}

fn audio_bytes() -> Vec<u8> {
    let mut state = 0x2468_u32;
    (0..AUDIO_BYTES)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[1]
        })
        .collect()
}

fn options<'a>(bytes: &'a [u8], media_type: &'static str) -> mneme_memory::SourceOptions<'a> {
    mneme_memory::SourceOptions {
        bytes,
        media_type,
        entity: None,
        path_hint: None,
    }
}

fn commit(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    records: Vec<mneme_store::RecordDraft>,
    sources: Vec<mneme_store::SourceBlobDraft>,
) {
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .commit(mneme_memory::Batch {
            actor: "device-owner".to_owned(),
            scope: scope(),
            idempotency_key: key.to_owned(),
            records,
            source_blobs: sources,
            publications: Vec::new(),
        })
        .expect("commit");
}

fn captured(
    pin: mneme_core::SourcePin,
    bytes: &[u8],
) -> (mneme_store::RecordDraft, mneme_store::SourceBlobDraft) {
    mneme_memory::build_captured_source(
        pin.source(),
        pin.revision(),
        &scope(),
        options(bytes, "audio/wav"),
        mneme_core::MediaExtent::Audio {
            duration_ticks: 30_000,
            time_base: mneme_core::TimeBase::new(1, 1_000).expect("time base"),
            channels: 1,
        },
    )
    .expect("captured audio")
}

fn record(workspace: &mut mneme_store::Workspace) -> Recording {
    let audio = mneme_core::SourcePin::new(rid(0x40), rev(0x41));
    let transcript = mneme_core::SourcePin::new(rid(0x42), rev(0x43));
    let (segment, run) = (rid(0x44), rid(0x46));
    let bytes = audio_bytes();
    let digest = mneme_core::ContentDigest::of_source_bytes(&bytes);
    let (audio_record, audio_blob) = captured(audio, &bytes);
    let (text, text_blob) = mneme_memory::build_recognized_source(
        transcript.source(),
        transcript.revision(),
        &scope(),
        options(b"so my fellow", "text/plain; charset=utf-8"),
        audio,
    )
    .expect("recognized text");
    let run_record = mneme_memory::build_recognition_run(
        run,
        rev(0x47),
        &scope(),
        mneme_memory::RecognitionRunOptions {
            input: audio,
            input_digest: digest,
            output: transcript,
            output_digest: mneme_core::ContentDigest::of_source_bytes(b"so my fellow"),
            model: "test-model@sha256:01",
            runtime: "test-runtime@sha256:02",
            adapter: "test-adapter@sha256:03",
            preprocessing: "test-preprocess@sha256:04",
            configuration: "test-config@sha256:05",
            segments: &[segment],
            coverage: mneme_core::RecognitionCoverage::new(1, 1).expect("coverage"),
            status: mneme_core::RecognitionStatus::Complete,
            scores: &[],
            alternatives: &[],
            covers: mneme_core::CapturePart::Whole,
        },
    )
    .expect("recognition run");
    let segment_record = mneme_memory::build_recognition_segment(
        segment,
        rev(0x45),
        &scope(),
        mneme_memory::RecognitionSegmentOptions {
            run: Some(run),
            text_source: transcript,
            span: mneme_core::SourceSpan::new(0, 2).expect("span"),
            media_source: audio,
            media_digest: digest,
            location: &mneme_core::MediaLocation::Audio {
                start_tick: 400,
                end_tick: 600,
                time_base: mneme_core::TimeBase::new(1, 1_000).expect("time base"),
                channel: 0,
            },
        },
    )
    .expect("aligned passage");
    commit(
        workspace,
        "recording",
        vec![audio_record, text, run_record, segment_record],
        vec![audio_blob, text_blob],
    );
    Recording {
        audio,
        transcript,
        segment,
        bytes,
    }
}

fn forget(
    workspace: &mut mneme_store::Workspace,
    source: mneme_core::RecordId,
) -> mneme_retention::Outcome {
    let request = mneme_retention::Request {
        actor: "device-owner".to_owned(),
        scope: scope(),
        base_revision: workspace.current_revision().expect("base"),
        idempotency_key: format!("forget-{source:?}"),
        operation: mneme_retention::OperationKind::Forget,
        selector: mneme_retention::Selector::Source(source),
        effective: None,
        policy: mneme_retention::Policy {
            version: mneme_retention::POLICY_VERSION.to_owned(),
            retain_assertion_after_prune: true,
            block_content_replay: true,
            retain_withdrawn_evidence_metadata: true,
        },
    };
    mneme_retention::Engine::new(workspace)
        .execute(request)
        .expect("forget")
}

fn authenticate(document: &str) -> mneme_memory::exchange::AuthenticatedBundle {
    let policy = mneme_memory::exchange::Policy::new([mneme_memory::exchange::Peer {
        issuer: ISSUER.to_owned(),
        public_key: mneme_memory::exchange::public_key(&SECRET),
        scopes: shared(),
    }])
    .expect("peer trust");
    mneme_memory::exchange::authenticate_json(document.as_bytes(), &policy)
        .expect("authenticated bundle")
}

fn import(
    workspace: &mut mneme_store::Workspace,
    document: &str,
) -> mneme_memory::exchange::ImportOutcome {
    mneme_memory::exchange::import_records(workspace, authenticate(document), "local-reviewer")
        .expect("import")
}

fn deliver(
    origin: &mneme_store::Workspace,
    receiver: &mneme_store::Workspace,
    export: &mneme_memory::exchange::Export,
    index: u32,
) -> Result<mneme_memory::exchange::ChunkReceipt, mneme_memory::exchange::Error> {
    let asset = &export.assets[0];
    let chunk = mneme_memory::exchange::asset_chunk(origin, asset, index).expect("chunk");
    mneme_memory::exchange::receive_chunk(
        receiver,
        &authenticate(&export.bundle),
        asset.digest(),
        index,
        &chunk,
    )
}

fn assert_media_and_text_absent(workspace: &mut mneme_store::Workspace, recording: &Recording) {
    let view = mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view");
    for record in [
        recording.audio.source(),
        recording.transcript.source(),
        recording.segment,
    ] {
        assert!(view.source(record).is_err());
        assert!(view.recognition_segment(record).is_err());
    }
}

#[test]
fn forgetting_during_a_transfer_and_a_delayed_replay_suppress_the_media_and_its_text() {
    let origin_temp = tempfile::tempdir().expect("origin");
    let mut origin = workspace(origin_temp.path());
    let recording = record(&mut origin);
    let old = mneme_memory::exchange::export_workspace(&origin, ISSUER, &SECRET, &shared())
        .expect("export before forgetting");
    let receiver_temp = tempfile::tempdir().expect("receiver");
    let mut receiver = workspace(receiver_temp.path());
    let started = import(&mut receiver, &old.bundle);
    assert_eq!(started.pending.len(), 1);
    deliver(&origin, &receiver, &old, 0).expect("first chunk");
    // A chunk already on its way when the origin forgets the recording.
    let in_flight = mneme_memory::exchange::asset_chunk(&origin, &old.assets[0], 1).expect("chunk");

    forget(&mut origin, recording.audio.source());
    let current = mneme_memory::exchange::export_workspace(&origin, ISSUER, &SECRET, &shared())
        .expect("export with the barrier");
    assert!(
        current.assets.is_empty(),
        "a forgotten source is never offered"
    );
    for barrier in authenticate(&current.bundle).barriers() {
        mneme_retention::Engine::new(&mut receiver)
            .apply_exchange_barrier(ISSUER, barrier)
            .expect("barrier");
    }
    assert!(matches!(
        mneme_memory::exchange::receive_chunk(
            &receiver,
            &authenticate(&old.bundle),
            old.assets[0].digest(),
            1,
            &in_flight
        ),
        Err(mneme_memory::exchange::Error::AssetForgotten)
    ));
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default(),
        "what the transfer held is gone"
    );
    let delayed = import(&mut receiver, &old.bundle);
    assert_eq!(
        delayed.refused,
        vec![mneme_core::ContentDigest::of_source_bytes(&recording.bytes)]
    );
    assert!(delayed.imported.is_empty());
    assert!(delayed.pending.is_empty());
    assert_media_and_text_absent(&mut receiver, &recording);

    drop(receiver);
    let mut receiver =
        mneme_store::Workspace::open(receiver_temp.path(), config()).expect("reopen");
    let replayed = import(&mut receiver, &old.bundle);
    assert!(replayed.imported.is_empty());
    assert_media_and_text_absent(&mut receiver, &recording);
    assert!(
        mneme_memory::exchange::pending_assets(&receiver)
            .expect("pending")
            .is_empty()
    );
    assert_eq!(
        mneme_memory::exchange::media_arrival(
            &receiver,
            recording.audio.source(),
            recording.audio.revision()
        )
        .expect("arrival"),
        mneme_memory::exchange::MediaArrival::Forgotten
    );
}

#[test]
fn forgetting_local_bytes_removes_a_pending_transfer_of_them() {
    let origin_temp = tempfile::tempdir().expect("origin");
    let mut origin = workspace(origin_temp.path());
    let recording = record(&mut origin);
    let export = mneme_memory::exchange::export_workspace(&origin, ISSUER, &SECRET, &shared())
        .expect("export");
    let receiver_temp = tempfile::tempdir().expect("receiver");
    let mut receiver = workspace(receiver_temp.path());
    import(&mut receiver, &export.bundle);
    deliver(&origin, &receiver, &export, 1).expect("one chunk");
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver)
            .expect("usage")
            .chunks,
        1
    );
    // The same bytes reach this device another way while the transfer waits.
    let local = mneme_core::SourcePin::new(rid(0x60), rev(0x61));
    let (local_record, local_blob) = captured(local, &recording.bytes);
    commit(
        &mut receiver,
        "same-bytes",
        vec![local_record],
        vec![local_blob],
    );

    let outcome = forget(&mut receiver, local.source());
    let location = outcome
        .locations
        .iter()
        .find(|location| location.location_kind == "asset-transfers")
        .expect("the forget searched pending transfers");
    assert_eq!(location.state, mneme_store::RetentionLocationState::Purged);
    assert!(location.verified);
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default()
    );
    let refused = import(&mut receiver, &export.bundle);
    assert_eq!(refused.refused.len(), 1, "the forgotten bytes stay refused");
    assert_media_and_text_absent(&mut receiver, &recording);
}

#[test]
fn a_barrier_removes_what_arrived_of_its_source_without_the_old_bundle() {
    let origin_temp = tempfile::tempdir().expect("origin");
    let mut origin = workspace(origin_temp.path());
    let recording = record(&mut origin);
    let old = mneme_memory::exchange::export_workspace(&origin, ISSUER, &SECRET, &shared())
        .expect("export before forgetting");
    let receiver_temp = tempfile::tempdir().expect("receiver");
    let mut receiver = workspace(receiver_temp.path());
    import(&mut receiver, &old.bundle);
    deliver(&origin, &receiver, &old, 0).expect("first chunk");
    forget(&mut origin, recording.audio.source());
    let current = mneme_memory::exchange::export_workspace(&origin, ISSUER, &SECRET, &shared())
        .expect("export with the barrier");
    assert!(
        current.forgotten.contains(&old.assets[0].digest()),
        "the sender learns which chunks to stop offering"
    );
    // Only the barriers are applied: the old bundle is gone from the folder.
    for barrier in authenticate(&current.bundle).barriers() {
        mneme_retention::Engine::new(&mut receiver)
            .apply_exchange_barrier(ISSUER, barrier)
            .expect("barrier");
    }
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default()
    );
    assert!(
        mneme_memory::exchange::pending_assets(&receiver)
            .expect("pending")
            .is_empty()
    );
    assert_eq!(
        mneme_memory::exchange::media_arrival(
            &receiver,
            recording.audio.source(),
            recording.audio.revision()
        )
        .expect("arrival"),
        mneme_memory::exchange::MediaArrival::Forgotten
    );
}
