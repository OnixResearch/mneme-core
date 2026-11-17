//! Large sources that travel beside a signed bundle as verified chunks.
#![allow(unknown_lints, no_unwrap)] // test inputs are deterministic fixtures
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod common;

use ed25519_dalek::Signer as _;

const SECRET: [u8; 32] = [0x5a; 32];
const ISSUER: &str = "device-a";
/// Three whole chunks and a partial fourth.
const AUDIO_BYTES: usize = 3 * 1024 * 1024 + 4_321;
const TRANSCRIPT: &[u8] = b"ask not what your country can do for you";

/// A recording with recognized text, a run and one aligned passage.
struct Recording {
    audio: mneme_core::SourcePin,
    transcript: mneme_core::SourcePin,
    run: mneme_core::RecordId,
    segment: mneme_core::RecordId,
    bytes: Vec<u8>,
}

fn config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(2_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn receiver() -> (tempfile::TempDir, mneme_store::Workspace) {
    let temp = tempfile::tempdir().expect("receiver directory");
    let workspace = mneme_store::Workspace::create(temp.path(), config()).expect("receiver");
    (temp, workspace)
}

fn reopen(temp: &tempfile::TempDir) -> mneme_store::Workspace {
    mneme_store::Workspace::open(temp.path(), config()).expect("reopened receiver")
}

fn shared() -> std::collections::BTreeSet<mneme_core::ScopeId> {
    std::collections::BTreeSet::from([common::scope()])
}

fn policy_for(
    scopes: std::collections::BTreeSet<mneme_core::ScopeId>,
) -> mneme_memory::exchange::Policy {
    mneme_memory::exchange::Policy::new([mneme_memory::exchange::Peer {
        issuer: ISSUER.to_owned(),
        public_key: mneme_memory::exchange::public_key(&SECRET),
        scopes,
    }])
    .expect("trusted device policy")
}

fn authenticate(document: &str) -> mneme_memory::exchange::AuthenticatedBundle {
    mneme_memory::exchange::authenticate_json(document.as_bytes(), &policy_for(shared()))
        .expect("trusted signature")
}

/// Deterministic bytes that differ from chunk to chunk.
fn audio_bytes(length: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect()
}

fn record(workspace: &mut mneme_store::Workspace, seed: u8, length: usize) -> Recording {
    record_with(workspace, seed, length, TRANSCRIPT)
}

/// A recording of `length` bytes whose recognized text is `spoken`.
fn record_with(
    workspace: &mut mneme_store::Workspace,
    seed: u8,
    length: usize,
    spoken: &[u8],
) -> Recording {
    let audio = mneme_core::SourcePin::new(common::rid(seed), common::rev(seed.wrapping_add(1)));
    let transcript = mneme_core::SourcePin::new(
        common::rid(seed.wrapping_add(2)),
        common::rev(seed.wrapping_add(3)),
    );
    let (run, segment) = (
        common::rid(seed.wrapping_add(4)),
        common::rid(seed.wrapping_add(6)),
    );
    let bytes = audio_bytes(length, u32::from(seed) | 0x100);
    let time_base = mneme_core::TimeBase::new(1, 1_000).expect("time base");
    let (audio_record, audio_blob) = mneme_memory::build_captured_source(
        audio.source(),
        audio.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: &bytes,
            media_type: "audio/wav",
            entity: None,
            path_hint: None,
        },
        mneme_core::MediaExtent::Audio {
            duration_ticks: 60_000,
            time_base,
            channels: 1,
        },
    )
    .expect("captured audio");
    let (text, text_blob) = mneme_memory::build_recognized_source(
        transcript.source(),
        transcript.revision(),
        &common::scope(),
        mneme_memory::SourceOptions {
            bytes: spoken,
            media_type: "text/plain; charset=utf-8",
            entity: None,
            path_hint: None,
        },
        audio,
    )
    .expect("recognized text");
    let (run_record, segment_record) = recognition(
        audio,
        transcript,
        (run, segment),
        (
            mneme_core::ContentDigest::of_source_bytes(&bytes),
            mneme_core::ContentDigest::of_source_bytes(spoken),
        ),
        seed,
    );
    common::engine(workspace)
        .commit(common::batch(
            &format!("recording-{seed}"),
            vec![audio_record, text, run_record, segment_record],
            vec![audio_blob, text_blob],
        ))
        .expect("commit recording");
    Recording {
        audio,
        transcript,
        run,
        segment,
        bytes,
    }
}

/// The run that recognized `transcript` from `audio`, and its one passage.
fn recognition(
    audio: mneme_core::SourcePin,
    transcript: mneme_core::SourcePin,
    (run, segment): (mneme_core::RecordId, mneme_core::RecordId),
    (audio_digest, text_digest): (mneme_core::ContentDigest, mneme_core::ContentDigest),
    seed: u8,
) -> (mneme_store::RecordDraft, mneme_store::RecordDraft) {
    let time_base = mneme_core::TimeBase::new(1, 1_000).expect("time base");
    let run_record = mneme_memory::build_recognition_run(
        run,
        common::rev(seed.wrapping_add(5)),
        &common::scope(),
        mneme_memory::RecognitionRunOptions {
            input: audio,
            input_digest: audio_digest,
            output: transcript,
            output_digest: text_digest,
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
        common::rev(seed.wrapping_add(7)),
        &common::scope(),
        mneme_memory::RecognitionSegmentOptions {
            block: None,
            run: Some(run),
            text_source: transcript,
            span: mneme_core::SourceSpan::new(0, 7).expect("span"),
            media_source: audio,
            media_digest: audio_digest,
            location: &mneme_core::MediaLocation::Audio {
                start_tick: 1_200,
                end_tick: 1_900,
                time_base,
                channel: 0,
            },
        },
    )
    .expect("recognition segment");
    (run_record, segment_record)
}

fn origin_with_recording() -> (tempfile::TempDir, mneme_store::Workspace, Recording) {
    let (temp, mut origin) = common::setup();
    let recording = record(&mut origin, 0xa0, AUDIO_BYTES);
    (temp, origin, recording)
}

fn export(origin: &mneme_store::Workspace) -> mneme_memory::exchange::Export {
    mneme_memory::exchange::export_workspace(origin, ISSUER, &SECRET, &shared())
        .expect("signed export")
}

fn import(
    workspace: &mut mneme_store::Workspace,
    document: &str,
) -> mneme_memory::exchange::ImportOutcome {
    mneme_memory::exchange::import_records(workspace, authenticate(document), "local-reviewer")
        .expect("import")
}

fn send(
    origin: &mneme_store::Workspace,
    receiver: &mneme_store::Workspace,
    export: &mneme_memory::exchange::Export,
    indices: &[u32],
) -> Vec<mneme_memory::exchange::ChunkReceipt> {
    let bundle = authenticate(&export.bundle);
    let asset = &export.assets[0];
    indices
        .iter()
        .map(|index| {
            let chunk = mneme_memory::exchange::asset_chunk(origin, asset, *index).expect("chunk");
            mneme_memory::exchange::receive_chunk(receiver, &bundle, asset.digest(), *index, &chunk)
                .expect("chunk received")
        })
        .collect()
}

/// Re-sign a version 2 bundle after `edit` changes its signed asset entry, as
/// a trusted but faulty peer could.
fn resign_asset(document: &str, edit: impl FnOnce(&mut Vec<mneme_core::Value>)) -> String {
    resign_assets(document, |assets| {
        if let Some(first) = assets.first_mut() {
            edit(first);
        }
    })
}

/// Edit the fields of every asset a bundle names, and sign it again.
fn resign_assets(document: &str, edit: impl FnOnce(&mut Vec<Vec<mneme_core::Value>>)) -> String {
    let value = mneme_core::decode_document(document).expect("bundle document");
    let outer = value.as_record().expect("bundle record");
    let signed = outer.fields()[0].as_record().expect("signed record");
    let mut fields = signed.fields().to_vec();
    let mut assets = fields[8]
        .as_set()
        .expect("asset set")
        .iter()
        .map(|asset| asset.as_record().expect("asset record").fields().to_vec())
        .collect::<Vec<_>>();
    edit(&mut assets);
    fields[8] = mneme_core::Value::set(
        assets
            .into_iter()
            .map(|asset| mneme_core::Value::record_named("exchange-asset", asset)),
    );
    let signed = mneme_core::Value::record_named("mneme-record-exchange-signed-v2", fields);
    let mut message = b"mneme.record-exchange.v2\0".to_vec();
    message.extend_from_slice(&mneme_core::encode(&signed));
    let signature = ed25519_dalek::SigningKey::from_bytes(&SECRET).sign(&message);
    mneme_core::encode_document_string(&mneme_core::Value::record_named(
        "mneme-record-exchange-v2",
        vec![
            signed,
            mneme_core::Value::bytes(signature.to_bytes().to_vec()),
        ],
    ))
}

#[test]
fn a_recording_larger_than_a_bundle_arrives_in_chunks_and_its_passage_opens() {
    let (_origin_temp, origin, recording) = origin_with_recording();
    let export = export(&origin);
    assert!(export.bundle.contains("mneme-record-exchange-v2"));
    assert_eq!(export.assets.len(), 1);
    let asset = &export.assets[0];
    assert_eq!(asset.source(), recording.audio.source());
    assert_eq!(asset.byte_length(), AUDIO_BYTES as u64);
    assert_eq!(asset.chunk_count(), 4);
    // The transcript names the capture it was recognized from, so it waits
    // for the capture too.
    assert_eq!(
        asset.dependents(),
        vec![
            recording.transcript.source(),
            recording.run,
            recording.segment
        ]
    );
    assert!(export.bundle.len() < mneme_memory::exchange::MAX_EXCHANGE_BUNDLE_BYTES);

    let (_receiver_temp, mut receiver) = receiver();
    let first = import(&mut receiver, &export.bundle);
    let waiting = vec![
        recording.audio.source(),
        recording.transcript.source(),
        recording.run,
        recording.segment,
    ];
    assert_eq!(first.deferred, waiting);
    assert_eq!(first.pending, vec![asset.digest()]);
    assert!(
        first.imported.contains(&common::SOURCE_ID),
        "the rest imports"
    );
    assert!(
        first
            .imported
            .iter()
            .all(|record| !waiting.contains(record))
    );

    let receipts = send(&origin, &receiver, &export, &[2, 0, 2, 3, 1]);
    let news = receipts
        .iter()
        .map(|receipt| receipt.is_new)
        .collect::<Vec<_>>();
    assert_eq!(news, vec![true, true, false, true, true]);
    assert_eq!(receipts.last().map(|receipt| receipt.received), Some(4));

    let second = import(&mut receiver, &export.bundle);
    assert_eq!(second.imported, waiting);
    assert!(second.deferred.is_empty());
    assert!(second.pending.is_empty());
    let view = common::engine(&mut receiver).view().expect("receiver view");
    assert_eq!(
        view.source_status(recording.audio.source()).expect("audio"),
        mneme_memory::SourceStatus::Retained(recording.bytes.clone())
    );
    let segment = view
        .recognition_segment(recording.segment)
        .expect("passage");
    assert_eq!(
        view.source_status(segment.text_source.source())
            .expect("transcript"),
        mneme_memory::SourceStatus::Retained(TRANSCRIPT.to_vec())
    );
    let span = segment.text_span;
    let (start, end) = (
        usize::try_from(span.start()).expect("start"),
        usize::try_from(span.end()).expect("end"),
    );
    assert_eq!(&TRANSCRIPT[start..end], b"ask not");
    assert_eq!(segment.media_source, recording.audio);
    assert_eq!(
        segment.media_digest,
        mneme_core::ContentDigest::of_source_bytes(&recording.bytes)
    );
    assert_eq!(
        mneme_memory::exchange::media_arrival(
            &receiver,
            recording.audio.source(),
            recording.audio.revision()
        )
        .expect("arrival"),
        mneme_memory::exchange::MediaArrival::Retained
    );
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default()
    );
}

#[test]
fn an_interrupted_transfer_resumes_after_a_restart_without_duplicates() {
    let (_origin_temp, origin, recording) = origin_with_recording();
    let export = export(&origin);
    let (receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &export.bundle);
    send(&origin, &receiver, &export, &[3, 1]);
    drop(receiver);

    let mut receiver = reopen(&receiver_temp);
    let resumed = import(&mut receiver, &export.bundle);
    assert!(resumed.imported.is_empty(), "{resumed:?}");
    assert_eq!(resumed.pending.len(), 1);
    let pending = mneme_memory::exchange::pending_assets(&receiver).expect("pending");
    assert_eq!(
        pending
            .iter()
            .map(|asset| (asset.source, asset.received, asset.total))
            .collect::<Vec<_>>(),
        vec![(recording.audio.source(), 2, 4)]
    );
    let receipts = send(&origin, &receiver, &export, &[1, 0, 2]);
    assert_eq!(
        receipts
            .iter()
            .map(|receipt| receipt.is_new)
            .collect::<Vec<_>>(),
        vec![false, true, true]
    );
    let finished = import(&mut receiver, &export.bundle);
    assert_eq!(
        finished.imported,
        vec![
            recording.audio.source(),
            recording.transcript.source(),
            recording.run,
            recording.segment
        ]
    );
    let replayed = import(&mut receiver, &export.bundle);
    assert!(replayed.imported.is_empty());
    assert!(replayed.already_present.contains(&recording.audio.source()));
    assert!(replayed.already_present.contains(&recording.segment));
    let late = send(&origin, &receiver, &export, &[0]);
    assert_eq!(late[0].received, late[0].total);
    assert!(!late[0].is_new);
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default(),
        "a chunk arriving after publication is not kept"
    );
}

#[test]
fn corrupt_substituted_and_oversized_assets_fail_explicitly() {
    let (_origin_temp, mut origin, _recording) = origin_with_recording();
    let other = record(&mut origin, 0xd0, 2 * 1024 * 1024);
    let export = export(&origin);
    let (receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &export.bundle);
    let bundle = authenticate(&export.bundle);
    let first = &export.assets[0];
    let second = export
        .assets
        .iter()
        .find(|asset| asset.source() == other.audio.source())
        .expect("the other recording's asset");
    let mut chunk = mneme_memory::exchange::asset_chunk(&origin, first, 0).expect("chunk");
    chunk[17] ^= 0x40;
    assert!(matches!(
        mneme_memory::exchange::receive_chunk(&receiver, &bundle, first.digest(), 0, &chunk),
        Err(mneme_memory::exchange::Error::CorruptChunk)
    ));
    let substituted = mneme_memory::exchange::asset_chunk(&origin, second, 0).expect("chunk");
    assert!(matches!(
        mneme_memory::exchange::receive_chunk(&receiver, &bundle, first.digest(), 0, &substituted),
        Err(mneme_memory::exchange::Error::CorruptChunk)
    ));
    let short = mneme_memory::exchange::asset_chunk(&origin, first, 1).expect("chunk");
    assert!(matches!(
        mneme_memory::exchange::receive_chunk(&receiver, &bundle, first.digest(), 1, &short[1..]),
        Err(mneme_memory::exchange::Error::CorruptChunk)
    ));
    assert!(matches!(
        mneme_memory::exchange::receive_chunk(
            &receiver,
            &bundle,
            mneme_core::ContentDigest::of_source_bytes(b"never offered"),
            0,
            &short
        ),
        Err(mneme_memory::exchange::Error::UnknownAsset)
    ));

    let single = {
        let (_temp, mut lone) = common::setup();
        record(&mut lone, 0xa0, AUDIO_BYTES);
        mneme_memory::exchange::export_workspace(&lone, ISSUER, &SECRET, &shared())
            .expect("export")
            .bundle
    };
    let swapped = resign_asset(&single, |fields| {
        fields[3] = mneme_core::ContentDigest::of_source_bytes(b"other bytes").to_value();
    });
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(swapped.as_bytes(), &policy_for(shared())),
        Err(mneme_memory::exchange::Error::MalformedBundle)
    ));
    let oversized = resign_asset(&single, |fields| {
        fields[4] =
            mneme_core::Value::integer(mneme_memory::exchange::MAX_EXCHANGE_ASSET_BYTES + 1);
    });
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(oversized.as_bytes(), &policy_for(shared())),
        Err(mneme_memory::exchange::Error::AssetTooLarge)
    ));
    let other_dependents = resign_asset(&single, |fields| {
        fields[8] = mneme_core::Value::set([common::rid(0x01).to_value()]);
    });
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(
            other_dependents.as_bytes(),
            &policy_for(shared())
        ),
        Err(mneme_memory::exchange::Error::MalformedBundle)
    ));
    let untrusted = mneme_memory::exchange::Policy::new(std::iter::empty()).expect("policy");
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(export.bundle.as_bytes(), &untrusted),
        Err(mneme_memory::exchange::Error::UntrustedIssuer)
    ));
    let elsewhere =
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "oak").expect("scope");
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(
            export.bundle.as_bytes(),
            &policy_for(std::collections::BTreeSet::from([elsewhere]))
        ),
        Err(mneme_memory::exchange::Error::ScopeNotAccepted(_))
    ));

    // A write a crash interrupted fills the bound but for the first asset:
    // its transfer may start and fills the bound exactly, and once started it
    // keeps every chunk; another asset's transfer cannot start.
    leftover_write(
        receiver_temp.path(),
        mneme_memory::exchange::MAX_TRANSFER_BYTES - first.byte_length(),
    );
    let fits = mneme_memory::exchange::asset_chunk(&origin, first, 2).expect("chunk");
    mneme_memory::exchange::receive_chunk(&receiver, &bundle, first.digest(), 2, &fits)
        .expect("a transfer that fills the bound exactly starts");
    let later = mneme_memory::exchange::asset_chunk(&origin, first, 1).expect("chunk");
    mneme_memory::exchange::receive_chunk(&receiver, &bundle, first.digest(), 1, &later)
        .expect("a started transfer keeps its chunks");
    let over = mneme_memory::exchange::asset_chunk(&origin, second, 0).expect("chunk");
    assert!(matches!(
        mneme_memory::exchange::receive_chunk(&receiver, &bundle, second.digest(), 0, &over),
        Err(mneme_memory::exchange::Error::TransferQuotaExceeded)
    ));
    assert!(import(&mut receiver, &export.bundle).imported.is_empty());
}

#[test]
fn a_missing_asset_stays_pending_and_is_never_retained() {
    let (_origin_temp, origin, recording) = origin_with_recording();
    let export = export(&origin);
    let (receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &export.bundle);
    send(&origin, &receiver, &export, &[0]);
    drop(receiver);
    let mut receiver = reopen(&receiver_temp);
    let arrival = mneme_memory::exchange::media_arrival(
        &receiver,
        recording.audio.source(),
        recording.audio.revision(),
    )
    .expect("arrival");
    assert_eq!(
        arrival,
        mneme_memory::exchange::MediaArrival::Pending {
            received: 1,
            total: 4
        }
    );
    let view = common::engine(&mut receiver).view().expect("receiver view");
    assert!(view.source(recording.audio.source()).is_err());
    assert!(
        view.source(recording.transcript.source()).is_err(),
        "recognized text never shows without the capture it came from"
    );
    assert!(view.recognition_segment(recording.segment).is_err());
    assert!(view.recognition_run(recording.run).is_err());
    let snapshot = receiver.snapshot().expect("snapshot");
    assert!(
        snapshot
            .records
            .iter()
            .all(|record| record.record_id != recording.audio.source()),
        "a pending source is never in the ledger"
    );
    let usage = mneme_memory::exchange::transfer_usage(&receiver).expect("usage");
    assert_eq!((usage.transfers, usage.chunks), (1, 1));
    assert_eq!(
        usage.bytes,
        u64::from(mneme_memory::exchange::ASSET_CHUNK_BYTES)
    );
    assert_eq!(
        mneme_memory::exchange::media_arrival(&receiver, common::rid(0x77), common::rev(0x78))
            .expect("arrival"),
        mneme_memory::exchange::MediaArrival::Missing
    );
}

#[test]
fn small_exchanges_stay_version_one_and_a_later_version_is_refused() {
    let (_origin_temp, origin) = common::setup();
    let export = export(&origin);
    assert!(export.assets.is_empty());
    assert!(export.bundle.contains("mneme-record-exchange-v1"));
    assert!(!export.bundle.contains("mneme-record-exchange-v2"));
    let (_receiver_temp, mut receiver) = receiver();
    let outcome = import(&mut receiver, &export.bundle);
    assert!(outcome.imported.contains(&common::SOURCE_ID));
    let later = export
        .bundle
        .replace("mneme-record-exchange-v1", "mneme-record-exchange-v3");
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(later.as_bytes(), &policy_for(shared())),
        Err(mneme_memory::exchange::Error::UnsupportedProfile)
    ));
}

#[test]
fn an_asset_request_names_one_shared_source_and_learns_nothing_of_others() {
    let (_origin_temp, origin, recording) = origin_with_recording();
    let granted = mneme_memory::exchange::grant_asset(
        &origin,
        &shared(),
        recording.audio.source(),
        recording.audio.revision(),
    )
    .expect("a shared source is granted");
    assert_eq!(
        granted.digest(),
        mneme_core::ContentDigest::of_source_bytes(&recording.bytes)
    );
    let elsewhere = std::collections::BTreeSet::from([mneme_core::ScopeId::new(
        mneme_core::ScopeClass::Project,
        "oak",
    )
    .expect("scope")]);
    let refusals = [
        mneme_memory::exchange::grant_asset(
            &origin,
            &elsewhere,
            recording.audio.source(),
            recording.audio.revision(),
        ),
        mneme_memory::exchange::grant_asset(
            &origin,
            &shared(),
            recording.audio.source(),
            common::rev(0x99),
        ),
        mneme_memory::exchange::grant_asset(
            &origin,
            &shared(),
            common::rid(0x98),
            common::rev(0x99),
        ),
        mneme_memory::exchange::grant_asset(
            &origin,
            &shared(),
            recording.run,
            recording.audio.revision(),
        ),
        // A record that is not a source, with its own revision.
        mneme_memory::exchange::grant_asset(&origin, &shared(), recording.run, common::rev(0xa5)),
    ];
    for refusal in refusals {
        assert!(matches!(
            refusal,
            Err(mneme_memory::exchange::Error::AssetUnavailable)
        ));
    }
}

#[test]
fn a_derived_original_waits_until_what_it_needs_is_here() {
    let (_origin_temp, mut origin) = common::setup();
    let text = TRANSCRIPT
        .iter()
        .chain(b" ")
        .copied()
        .cycle()
        .take(100 * 1024)
        .collect::<Vec<_>>();
    let recording = record_with(&mut origin, 0xa0, AUDIO_BYTES, &text);
    let export = export(&origin);
    assert_eq!(export.assets.len(), 2, "the transcript is an asset too");
    let (receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &export.bundle);
    let bundle = authenticate(&export.bundle);
    let transcript = export
        .assets
        .iter()
        .find(|asset| asset.source() == recording.transcript.source())
        .expect("the transcript's asset");
    // The transcript needs its recording: none of its chunks is taken, and no
    // room is held for it, before the recording is here whole.
    let chunk = mneme_memory::exchange::asset_chunk(&origin, transcript, 0).expect("chunk");
    assert!(matches!(
        mneme_memory::exchange::receive_chunk(&receiver, &bundle, transcript.digest(), 0, &chunk),
        Err(mneme_memory::exchange::Error::AssetWaiting)
    ));
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver)
            .expect("usage")
            .chunks,
        0
    );
    assert_eq!(
        mneme_memory::exchange::wanted_chunks(&receiver, &bundle).expect("wanted"),
        vec![(recording_digest(&recording), vec![0, 1, 2, 3])],
        "only the recording is wanted"
    );
    drop(receiver);
    let mut receiver = reopen(&receiver_temp);
    send(&origin, &receiver, &export, &[0, 1, 2, 3]);
    assert_eq!(
        mneme_memory::exchange::wanted_chunks(&receiver, &bundle).expect("wanted"),
        vec![(transcript.digest(), vec![0])],
        "then the transcript"
    );
    mneme_memory::exchange::receive_chunk(&receiver, &bundle, transcript.digest(), 0, &chunk)
        .expect("the transcript's only chunk");
    let finished = import(&mut receiver, &export.bundle);
    assert!(finished.imported.contains(&recording.transcript.source()));
    assert!(finished.imported.contains(&recording.audio.source()));
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default()
    );
}

#[test]
fn a_second_source_with_bytes_already_here_arrives_without_chunks() {
    let (_origin_temp, mut origin, recording) = origin_with_recording();
    let first = export(&origin);
    let (_receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &first.bundle);
    send(&origin, &receiver, &first, &[0, 1, 2, 3]);
    import(&mut receiver, &first.bundle);
    let copy = capture(&mut origin, (0xe0, &common::scope()), &recording.bytes);
    let second = export(&origin);
    assert!(
        mneme_memory::exchange::wanted_chunks(&receiver, &authenticate(&second.bundle))
            .expect("wanted")
            .is_empty(),
        "bytes already here are not wanted again"
    );
    let outcome = import(&mut receiver, &second.bundle);
    assert!(outcome.imported.contains(&copy.source()), "{outcome:?}");
    assert!(outcome.pending.is_empty());
}

#[test]
fn chunks_that_make_other_bytes_are_refused_and_removed() {
    let (_temp, mut lone) = common::setup();
    let recording = record(&mut lone, 0xa0, AUDIO_BYTES);
    let document = mneme_memory::exchange::export_workspace(&lone, ISSUER, &SECRET, &shared())
        .expect("export")
        .bundle;
    // A faulty peer signs the chunk digests of other bytes of the same length.
    let other = audio_bytes(AUDIO_BYTES, 0x7777);
    let other_chunks = other
        .chunks(usize::try_from(mneme_memory::exchange::ASSET_CHUNK_BYTES).expect("chunk size"))
        .map(mneme_core::ContentDigest::of_source_bytes)
        .collect::<Vec<_>>();
    let forged = resign_asset(&document, |fields| {
        fields[7] = mneme_core::Value::sequence(
            other_chunks
                .iter()
                .map(|digest| digest.to_value())
                .collect(),
        );
    });
    let (_receiver_temp, mut receiver) = receiver();
    let bundle = authenticate(&forged);
    let digest = recording_digest(&recording);
    for (index, chunk) in other
        .chunks(usize::try_from(mneme_memory::exchange::ASSET_CHUNK_BYTES).expect("chunk size"))
        .enumerate()
    {
        mneme_memory::exchange::receive_chunk(
            &receiver,
            &bundle,
            digest,
            u32::try_from(index).expect("index"),
            chunk,
        )
        .expect("each chunk matches its signed digest");
    }
    let outcome = import(&mut receiver, &forged);
    assert_eq!(outcome.refused, vec![digest]);
    assert!(outcome.deferred.contains(&recording.audio.source()));
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default()
    );
}

fn recording_digest(recording: &Recording) -> mneme_core::ContentDigest {
    mneme_core::ContentDigest::of_source_bytes(&recording.bytes)
}

/// Commit a capture of `bytes` in `scope` as source `seed`.
fn capture(
    workspace: &mut mneme_store::Workspace,
    (seed, scope): (u8, &mneme_core::ScopeId),
    bytes: &[u8],
) -> mneme_core::SourcePin {
    let pin = mneme_core::SourcePin::new(common::rid(seed), common::rev(seed.wrapping_add(1)));
    let (record, blob) = mneme_memory::build_captured_source(
        pin.source(),
        pin.revision(),
        scope,
        mneme_memory::SourceOptions {
            bytes,
            media_type: "audio/wav",
            entity: None,
            path_hint: None,
        },
        mneme_core::MediaExtent::Audio {
            duration_ticks: 60_000,
            time_base: mneme_core::TimeBase::new(1, 1_000).expect("time base"),
            channels: 1,
        },
    )
    .expect("a capture");
    common::engine(workspace)
        .commit(common::batch_in(scope, "capture", vec![record], vec![blob]))
        .expect("commit the capture");
    pin
}

/// A sparse file a crashed write left in a transfer of no bundle here.
fn leftover_write(root: &std::path::Path, length: u64) {
    let leftover = root
        .join("transfers")
        .join("ab".repeat(32))
        .join("cd".repeat(32));
    std::fs::create_dir_all(&leftover).expect("leftover transfer");
    std::fs::File::create(leftover.join(".incoming-crashed"))
        .and_then(|file| file.set_len(length))
        .expect("sparse leftover write");
}

#[test]
fn transfers_already_started_finish_when_the_bound_is_reached() {
    let (_origin_temp, mut origin) = common::setup();
    for seed in [0xa0, 0xb0, 0xc0] {
        record(&mut origin, seed, AUDIO_BYTES);
    }
    let export = export(&origin);
    let (receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &export.bundle);
    let bundle = authenticate(&export.bundle);
    // Room for two whole recordings, though the first chunks of all three
    // would fit: a third transfer must not start, or none could finish.
    let chunk_bytes = u64::from(mneme_memory::exchange::ASSET_CHUNK_BYTES);
    leftover_write(
        receiver_temp.path(),
        mneme_memory::exchange::MAX_TRANSFER_BYTES - 9 * chunk_bytes - 1,
    );
    let deliver = |asset: &mneme_memory::exchange::Asset, index: u32| {
        let chunk = mneme_memory::exchange::asset_chunk(&origin, asset, index).expect("chunk");
        mneme_memory::exchange::receive_chunk(&receiver, &bundle, asset.digest(), index, &chunk)
    };
    let outcomes = export
        .assets
        .iter()
        .flat_map(|asset| (0..asset.chunk_count() - 1).map(move |index| (asset, index)))
        .map(|(asset, index)| deliver(asset, index))
        .collect::<Vec<_>>();
    assert!(
        outcomes.iter().all(|outcome| matches!(
            outcome,
            Ok(_) | Err(mneme_memory::exchange::Error::TransferQuotaExceeded)
        )),
        "{outcomes:?}"
    );
    let refused = outcomes.iter().filter(|outcome| outcome.is_err()).count();
    assert_eq!(refused, 3, "the third recording's transfer does not start");
    let (started, waiting) = export.assets.split_at(2);
    for asset in started {
        deliver(asset, asset.chunk_count() - 1).expect("a started transfer finishes");
    }
    let outcome = import(&mut receiver, &export.bundle);
    for asset in started {
        assert!(outcome.imported.contains(&asset.source()), "{outcome:?}");
    }
    assert_eq!(
        outcome.pending,
        waiting
            .iter()
            .map(|asset| asset.digest())
            .collect::<Vec<_>>()
    );
}

#[test]
fn bytes_held_in_another_scope_are_not_taken_for_a_peers_source() {
    let (_origin_temp, origin, recording) = origin_with_recording();
    let export = export(&origin);
    let (_receiver_temp, mut receiver) = receiver();
    // The same bytes are here already, in a scope the peer does not share.
    capture(
        &mut receiver,
        (0x70, &common::project_scope("oak")),
        &recording.bytes,
    );
    let wanted = mneme_memory::exchange::wanted_chunks(&receiver, &authenticate(&export.bundle))
        .expect("wanted");
    assert_eq!(
        wanted,
        vec![(recording_digest(&recording), vec![0, 1, 2, 3])]
    );
    let receipt = send(&origin, &receiver, &export, &[0]);
    assert!(receipt[0].is_new, "the chunk is kept, not taken as held");
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver)
            .expect("usage")
            .chunks,
        1
    );
    let outcome = import(&mut receiver, &export.bundle);
    assert!(!outcome.imported.contains(&recording.audio.source()));
    assert_eq!(outcome.pending, vec![recording_digest(&recording)]);
}

#[test]
fn sources_of_the_same_bytes_share_one_chunk_layout() {
    let (_origin_temp, mut origin, recording) = origin_with_recording();
    capture(&mut origin, (0xe0, &common::scope()), &recording.bytes);
    let document = export(&origin).bundle;
    let twice = 2 * mneme_memory::exchange::ASSET_CHUNK_BYTES;
    let pieces = recording
        .bytes
        .chunks(usize::try_from(twice).expect("chunk size"))
        .map(|piece| mneme_core::ContentDigest::of_source_bytes(piece).to_value())
        .collect::<Vec<_>>();
    let other_layout = resign_assets(&document, |assets| {
        if let Some(second) = assets.get_mut(1) {
            second[6] = mneme_core::Value::integer(twice);
            second[7] = mneme_core::Value::sequence(pieces);
        }
    });
    assert!(matches!(
        mneme_memory::exchange::authenticate_json(other_layout.as_bytes(), &policy_for(shared())),
        Err(mneme_memory::exchange::Error::MalformedBundle)
    ));
}

#[test]
fn transfers_of_devices_no_longer_trusted_are_released() {
    let (_origin_temp, origin, _recording) = origin_with_recording();
    let export = export(&origin);
    let (_receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &export.bundle);
    send(&origin, &receiver, &export, &[0]);
    let trusted = policy_for(shared());
    assert_eq!(
        mneme_memory::exchange::release_untrusted(&receiver, &trusted).expect("release"),
        0
    );
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver)
            .expect("usage")
            .chunks,
        1
    );
    let revoked = mneme_memory::exchange::Policy::new(std::iter::empty()).expect("policy");
    assert_eq!(
        mneme_memory::exchange::release_untrusted(&receiver, &revoked).expect("release"),
        1
    );
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default()
    );
}

#[test]
fn a_transfer_cannot_start_in_room_started_transfers_need() {
    let (_origin_temp, mut origin) = common::setup();
    for seed in [0xa0, 0xb0] {
        record(&mut origin, seed, AUDIO_BYTES);
    }
    let export = export(&origin);
    let (receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &export.bundle);
    let bundle = authenticate(&export.bundle);
    let [first, second] = export.assets.as_slice() else {
        return assert_eq!(export.assets.len(), 2);
    };
    // One byte short of room for both whole recordings.
    leftover_write(
        receiver_temp.path(),
        mneme_memory::exchange::MAX_TRANSFER_BYTES - first.byte_length() - second.byte_length() + 1,
    );
    let deliver = |asset: &mneme_memory::exchange::Asset, index: u32| {
        let chunk = mneme_memory::exchange::asset_chunk(&origin, asset, index).expect("chunk");
        mneme_memory::exchange::receive_chunk(&receiver, &bundle, asset.digest(), index, &chunk)
    };
    deliver(first, 0).expect("the first transfer starts");
    // The first holds one chunk so far, yet room for all of it.
    assert!(matches!(
        deliver(second, 0),
        Err(mneme_memory::exchange::Error::TransferQuotaExceeded)
    ));
    for index in 1..first.chunk_count() {
        deliver(first, index).expect("the started transfer finishes");
    }
    assert!(
        mneme_memory::exchange::transfer_usage(&receiver)
            .expect("usage")
            .bytes
            <= mneme_memory::exchange::MAX_TRANSFER_BYTES
    );
    let outcome = import(&mut receiver, &export.bundle);
    assert!(outcome.imported.contains(&first.source()));
}

#[test]
fn bytes_published_for_one_scope_stay_for_a_source_of_another_still_waiting() {
    let (_origin_temp, mut origin) = common::setup();
    let text = TRANSCRIPT
        .iter()
        .chain(b" ")
        .copied()
        .cycle()
        .take(100 * 1024)
        .collect::<Vec<_>>();
    // A large transcript recognized from a recording, and a capture of the
    // same bytes in another shared scope.
    let recording = record_with(&mut origin, 0xa0, AUDIO_BYTES, &text);
    let elsewhere = common::project_scope("elsewhere");
    let copy = capture(&mut origin, (0x90, &elsewhere), &text);
    let scopes = std::collections::BTreeSet::from([common::scope(), elsewhere]);
    let export = mneme_memory::exchange::export_workspace(&origin, ISSUER, &SECRET, &scopes)
        .expect("export");
    let policy = policy_for(scopes);
    let authenticated = || {
        mneme_memory::exchange::authenticate_json(export.bundle.as_bytes(), &policy)
            .expect("authenticated")
    };
    let (_receiver_temp, mut receiver) = receiver();
    let bundle = authenticated();
    deliver_digest(
        (&origin, &receiver),
        &export,
        &bundle,
        mneme_core::ContentDigest::of_source_bytes(&text),
    );
    let first = mneme_memory::exchange::import_records(&mut receiver, authenticated(), "reviewer")
        .expect("first import");
    assert!(first.imported.contains(&copy.source()));
    assert!(first.deferred.contains(&recording.transcript.source()));
    deliver_digest(
        (&origin, &receiver),
        &export,
        &bundle,
        recording_digest(&recording),
    );
    let second = mneme_memory::exchange::import_records(&mut receiver, authenticated(), "reviewer")
        .expect("second import");
    assert!(
        second.imported.contains(&recording.transcript.source()),
        "{second:?}"
    );
}

/// Deliver every chunk of the asset of `digest` from the origin.
fn deliver_digest(
    (origin, receiver): (&mneme_store::Workspace, &mneme_store::Workspace),
    export: &mneme_memory::exchange::Export,
    bundle: &mneme_memory::exchange::AuthenticatedBundle,
    digest: mneme_core::ContentDigest,
) {
    let asset = export
        .assets
        .iter()
        .find(|asset| asset.digest() == digest)
        .expect("asset");
    for index in 0..asset.chunk_count() {
        let chunk = mneme_memory::exchange::asset_chunk(origin, asset, index).expect("chunk");
        mneme_memory::exchange::receive_chunk(receiver, bundle, digest, index, &chunk)
            .expect("chunk received");
    }
}

#[test]
fn an_unreadable_transfer_manifest_names_nothing_arriving() {
    let (_origin_temp, origin, recording) = origin_with_recording();
    let export = export(&origin);
    let (receiver_temp, mut receiver) = receiver();
    let broken = receiver_temp
        .path()
        .join("transfers")
        .join("ab".repeat(32))
        .join("cd".repeat(32));
    std::fs::create_dir_all(&broken).expect("broken transfer");
    std::fs::write(broken.join("manifest"), b"not a manifest").expect("broken manifest");
    import(&mut receiver, &export.bundle);
    send(&origin, &receiver, &export, &[0]);
    let pending = mneme_memory::exchange::pending_assets(&receiver).expect("pending");
    assert_eq!(
        pending.iter().map(|asset| asset.source).collect::<Vec<_>>(),
        vec![recording.audio.source()]
    );
    assert_eq!(
        mneme_memory::exchange::media_arrival(
            &receiver,
            recording.audio.source(),
            recording.audio.revision()
        )
        .expect("arrival"),
        mneme_memory::exchange::MediaArrival::Pending {
            received: 1,
            total: 4
        }
    );
}

#[test]
fn a_transfer_no_current_bundle_names_is_released() {
    let (_origin_temp, origin, _recording) = origin_with_recording();
    let first = export(&origin);
    let (_receiver_temp, mut receiver) = receiver();
    import(&mut receiver, &first.bundle);
    send(&origin, &receiver, &first, &[0]);
    let naming = authenticate(&first.bundle);
    assert_eq!(
        mneme_memory::exchange::release_unnamed(&receiver, &[&naming]).expect("release"),
        0
    );
    // The same device's only bundle now names another recording.
    let (_other_temp, mut other) = common::setup();
    record(&mut other, 0xb0, AUDIO_BYTES);
    let later = authenticate(&export(&other).bundle);
    assert_eq!(
        mneme_memory::exchange::release_unnamed(&receiver, &[&later]).expect("release"),
        1
    );
    assert_eq!(
        mneme_memory::exchange::transfer_usage(&receiver).expect("usage"),
        mneme_memory::exchange::TransferUsage::default()
    );
}
