//! Durable media recognition jobs, run through the real worker supervisor.
#![allow(unknown_lints, no_unwrap)] // test code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)]

const SCAN: &[u8] = b"synthetic scan bytes, one image per page";

/// Answers every page with a short text and one region on that page.
const GOOD: &str = r#"case "$header" in
  *'"page":0'*) t='first page' ;;
  *'"page":1'*) t='second page' ;;
  *) t='third page' ;;
esac
printf '{"status":"complete","text":"%s","segments":[{"start":0,"end":4,"location":{"kind":"region","x":10,"y":20,"width":30,"height":40,"frame":{"pixels":{"width":400,"height":300}}}}]}' "$t""#;

/// Page 0 is good; page 1 answers past the output bound, page 2 is not JSON,
/// and page 3 aligns a span past the end of its text.
const MIXED: &str = r#"case "$header" in
  *'"page":0'*) printf '{"status":"complete","text":"kept"}' ;;
  *'"page":1'*) i=0; while [ "$i" -lt 5000 ]; do printf x; i=$((i+1)); done ;;
  *'"page":2'*) printf 'not json' ;;
  *) printf '{"status":"complete","text":"short","segments":[{"start":0,"end":99,"location":{"kind":"region","x":0,"y":0,"width":1,"height":1,"frame":"normalized"}}]}' ;;
esac"#;

/// Waits for the release file named by the second argument, then answers.
const BLOCKING: &str = r#"while [ ! -e "$2" ]; do :; done
printf '{"status":"complete","text":"late words"}'"#;

/// Never answers.
const ENDLESS: &str = "while :; do :; done";

fn scope() -> mneme_core::ScopeId {
    mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
}

fn config() -> mneme_store::WorkspaceConfig {
    mneme_store::WorkspaceConfig {
        clock: Box::new(mneme_store::FixedClock::new(
            mneme_core::Timestamp::from_nanos(1_000),
        )),
        faults: Box::new(mneme_store::NoFaults),
    }
}

fn open(root: &std::path::Path) -> mneme_store::Workspace {
    mneme_store::Workspace::open(root, config()).expect("fresh handle")
}

fn commit(
    workspace: &mut mneme_store::Workspace,
    key: &str,
    (records, blobs): (
        Vec<mneme_store::RecordDraft>,
        Vec<mneme_store::SourceBlobDraft>,
    ),
) {
    mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .commit(mneme_memory::Batch {
            actor: "capture-author".to_owned(),
            scope: scope(),
            idempotency_key: key.to_owned(),
            records,
            source_blobs: blobs,
            publications: Vec::new(),
        })
        .expect("commit");
}

/// A workspace holding a captured scan of `pages` 400x300 pages.
fn scan(
    pages: u32,
) -> (
    tempfile::TempDir,
    mneme_store::Workspace,
    mneme_core::SourcePin,
) {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config()).expect("create");
    let media = mneme_core::SourcePin::new(
        mneme_core::RecordId::from_bytes([0x51; 16]),
        mneme_core::RevisionId::from_bytes([0x52; 16]),
    );
    let (record, blob) = mneme_memory::build_source_with_provenance(
        media.source(),
        media.revision(),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: SCAN,
            media_type: "image/png",
            entity: None,
            path_hint: None,
        },
        mneme_memory::SourceProvenance {
            acquisition: mneme_core::Acquisition::Captured,
            derived_from: None,
            media_extent: Some(mneme_core::MediaExtent::Pages { page_count: pages }),
            media_transform: None,
            media_frame: Some(mneme_core::CoordinateFrame::Pixels {
                width: 400,
                height: 300,
            }),
            ink_inventory: None,
            correction: None,
        },
    )
    .expect("captured scan");
    commit(&mut workspace, "capture", (vec![record], vec![blob]));
    (temp, workspace, media)
}

/// A shell worker that reads its header, drains the media, records its start
/// in `log`, then runs `answer`. Builtins only: its environment is cleared.
fn worker(
    answer: &str,
    log: &std::path::Path,
    release: &std::path::Path,
) -> mneme_recall::inference::WorkerCommand {
    let script = format!(
        "IFS= read -r header; while IFS= read -r line || [ -n \"$line\" ]; do :; done; \
         printf 'start\\n' >> \"$1\"; {answer}"
    );
    mneme_recall::inference::WorkerCommand {
        executable: std::path::PathBuf::from("/bin/sh"),
        args: vec![
            "-c".into(),
            script.into(),
            "worker".into(),
            log.as_os_str().to_owned(),
            release.as_os_str().to_owned(),
        ],
    }
}

fn job(
    media: mneme_core::SourcePin,
    worker: mneme_recall::inference::WorkerCommand,
    unit_time: std::time::Duration,
) -> mneme_consolidation::recognition::Job {
    mneme_consolidation::recognition::Job {
        job_id: "scan-job".to_owned(),
        actor: "recognition-test".to_owned(),
        scope: scope(),
        access: mneme_memory::Access::Operator,
        media,
        recognizer: mneme_consolidation::recognition::Recognizer {
            worker,
            model: "ocr-model@sha256:01".to_owned(),
            runtime: "test-runtime@sha256:02".to_owned(),
            adapter: "test-adapter@sha256:03".to_owned(),
            preprocessing: "none".to_owned(),
            configuration: "test-config@sha256:05".to_owned(),
        },
        plan: mneme_consolidation::recognition::UnitPlan::Pages,
        limits: mneme_consolidation::recognition::Limits {
            max_units: 16,
            max_attempts_per_unit: 3,
            unit: mneme_recall::inference::MediaInvocationLimits {
                max_media_bytes: 1_048_576,
                max_output_bytes: 4_096,
                max_wall_time: unit_time,
            },
            max_run_time: std::time::Duration::from_secs(600),
        },
    }
}

fn starts(log: &std::path::Path) -> usize {
    std::fs::read_to_string(log).map_or(0, |text| text.lines().count())
}

fn states(
    report: &mneme_consolidation::recognition::Report,
) -> Vec<mneme_consolidation::recognition::UnitState> {
    report.units.iter().map(|unit| unit.state).collect()
}

/// The one progress file the job keeps beside its claim.
fn progress_file(root: &std::path::Path) -> std::path::PathBuf {
    std::fs::read_dir(root.join("jobs"))
        .expect("jobs directory")
        .map(|entry| entry.expect("entry").path())
        .find(|path| {
            path.extension()
                .is_some_and(|extension| extension == "progress")
        })
        .expect("progress file")
}

/// Every recognition run committed in the workspace.
fn runs(workspace: &mut mneme_store::Workspace) -> Vec<mneme_memory::RecognitionRunView> {
    let view = mneme_memory::Engine::new(workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view");
    view.snapshot()
        .records
        .iter()
        .filter(|record| record.kind == mneme_core::RecordKind::RecognitionRun)
        .map(|record| mneme_memory::RecognitionRunView::parse(record.clone()).expect("run"))
        .collect()
}

/// Wait until a worker has recorded its start, while `runner` still runs.
fn await_start<T>(log: &std::path::Path, runner: &std::thread::ScopedJoinHandle<'_, T>) {
    while starts(log) == 0 && !runner.is_finished() {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    assert_eq!(starts(log), 1, "the runner dispatched its first unit");
}

#[test]
fn a_capture_is_queued_without_a_recognizer_and_recognized_later() {
    let (temp, mut workspace, media) = scan(3);
    let log = temp.path().join("starts");
    let job = job(
        media,
        worker(GOOD, &log, &log),
        std::time::Duration::from_secs(60),
    );
    let queued = mneme_consolidation::recognition::queue(&mut workspace, &job).expect("queue");
    assert_eq!(
        queued.state,
        mneme_consolidation::recognition::JobState::Queued
    );
    assert_eq!((queued.published, queued.total), (0, 3));
    assert_eq!(starts(&log), 0, "queueing runs nothing");
    assert_eq!(
        mneme_consolidation::recognition::status(&workspace, &job).expect("status"),
        Some(queued)
    );
    let report = mneme_consolidation::recognition::run(
        &mut workspace,
        &job,
        &mneme_recall::inference::InvocationControl::new(),
    )
    .expect("run");
    assert_eq!(
        report.state,
        mneme_consolidation::recognition::JobState::Complete
    );
    assert_eq!((report.published, starts(&log)), (3, 3));
    let committed = runs(&mut workspace);
    assert_eq!(committed.len(), 3, "each page is its own run");
    for run in &committed {
        assert_eq!(run.input, media);
        assert_eq!(run.segments.len(), 1);
    }
    // Progress holds no recognized text and no media, and the job keeps
    // nothing but its claim and its progress.
    let progress = std::fs::read(progress_file(temp.path())).expect("progress");
    let progress = String::from_utf8(progress).expect("JSON");
    for recognized in ["first page", "second page", "third page"] {
        assert!(
            !progress.contains(recognized),
            "progress holds no recognized text"
        );
    }
    assert!(
        !progress.contains("synthetic scan"),
        "progress holds no media"
    );
    assert_eq!(
        std::fs::read_dir(temp.path().join("jobs"))
            .expect("jobs")
            .count(),
        2
    );
}

#[test]
fn a_restart_reconciles_committed_units_and_never_redispatches_uncertain_ones() {
    let (temp, mut workspace, media) = scan(3);
    let log = temp.path().join("starts");
    let job = job(
        media,
        worker(GOOD, &log, &log),
        std::time::Duration::from_secs(60),
    );
    let control = mneme_recall::inference::InvocationControl::new();
    let first =
        mneme_consolidation::recognition::run(&mut workspace, &job, &control).expect("first run");
    // As if a runner had stopped twice: after committing unit 1 but before
    // saving it, and after reserving a new attempt of unit 2.
    let path = progress_file(temp.path());
    let mut progress: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("progress");
    progress["units"][1]["state"] = "dispatched".into();
    progress["units"][2]["state"] = "dispatched".into();
    progress["units"][2]["attempts"] = 2.into();
    std::fs::write(&path, serde_json::to_vec(&progress).expect("encode")).expect("write");
    let mut resumed = open(temp.path());
    let report =
        mneme_consolidation::recognition::run(&mut resumed, &job, &control).expect("resume");
    assert_eq!(
        report.units[1].state,
        mneme_consolidation::recognition::UnitState::Published
    );
    assert_eq!(
        report.units[1].run, first.units[1].run,
        "reconciled, not repeated"
    );
    assert_eq!(
        report.units[2].state,
        mneme_consolidation::recognition::UnitState::Uncertain
    );
    assert_eq!(
        starts(&log),
        3,
        "nothing was dispatched again automatically"
    );
    let retried = mneme_consolidation::recognition::retry(&mut resumed, &job).expect("retry");
    assert_eq!(
        retried.units[2].state,
        mneme_consolidation::recognition::UnitState::Pending
    );
    let rerun = mneme_consolidation::recognition::run(&mut resumed, &job, &control).expect("rerun");
    assert_eq!(
        rerun.state,
        mneme_consolidation::recognition::JobState::Complete
    );
    assert_eq!((rerun.units[2].attempts, starts(&log)), (3, 4));
    assert_eq!(
        runs(&mut resumed).len(),
        4,
        "the retried attempt is a new, charged run"
    );
}

#[test]
fn a_second_runner_is_refused_while_a_unit_runs() {
    let (temp, mut workspace, media) = scan(1);
    let (log, release) = (temp.path().join("starts"), temp.path().join("release"));
    let job = job(
        media,
        worker(BLOCKING, &log, &release),
        std::time::Duration::from_secs(60),
    );
    let control = mneme_recall::inference::InvocationControl::new();
    std::thread::scope(|threads| {
        let runner =
            threads.spawn(|| mneme_consolidation::recognition::run(&mut workspace, &job, &control));
        await_start(&log, &runner);
        let mut second = open(temp.path());
        assert!(matches!(
            mneme_consolidation::recognition::run(&mut second, &job, &control),
            Err(mneme_consolidation::recognition::Failure::Busy(_))
        ));
        let status = mneme_consolidation::recognition::status(&second, &job)
            .expect("status")
            .expect("saved progress");
        assert_eq!(
            states(&status),
            [mneme_consolidation::recognition::UnitState::Dispatched]
        );
        std::fs::write(&release, b"").expect("release");
        let report = runner.join().expect("runner").expect("run");
        assert_eq!(
            report.state,
            mneme_consolidation::recognition::JobState::Complete
        );
    });
    assert_eq!(starts(&log), 1);
}

#[test]
fn forgetting_the_capture_during_a_unit_suppresses_its_publication() {
    let (temp, mut workspace, media) = scan(2);
    let (log, release) = (temp.path().join("starts"), temp.path().join("release"));
    let job = job(
        media,
        worker(BLOCKING, &log, &release),
        std::time::Duration::from_secs(60),
    );
    let control = mneme_recall::inference::InvocationControl::new();
    std::thread::scope(|threads| {
        let runner =
            threads.spawn(|| mneme_consolidation::recognition::run(&mut workspace, &job, &control));
        await_start(&log, &runner);
        let mut other = open(temp.path());
        let base = other.current_revision().expect("base");
        mneme_retention::Engine::new(&mut other)
            .execute(mneme_retention::Request {
                actor: "retention-author".to_owned(),
                scope: scope(),
                base_revision: base,
                idempotency_key: "forget-scan".to_owned(),
                operation: mneme_retention::OperationKind::Forget,
                selector: mneme_retention::Selector::Source(media.source()),
                effective: None,
                policy: mneme_retention::Policy {
                    version: mneme_retention::POLICY_VERSION.to_owned(),
                    retain_assertion_after_prune: true,
                    block_content_replay: true,
                    retain_withdrawn_evidence_metadata: true,
                },
            })
            .expect("forget the capture while its unit runs");
        std::fs::write(&release, b"").expect("release");
        let report = runner.join().expect("runner").expect("run");
        assert_eq!(
            states(&report),
            [mneme_consolidation::recognition::UnitState::Suppressed; 2],
            "the late answer and the unit not yet run are both suppressed"
        );
        assert_eq!(
            report.state,
            mneme_consolidation::recognition::JobState::Failed
        );
    });
    assert_eq!(starts(&log), 1);
    assert!(
        runs(&mut open(temp.path())).is_empty(),
        "nothing was published"
    );
}

#[test]
fn bad_answers_are_rejected_before_publication_and_good_units_survive() {
    let (temp, mut workspace, media) = scan(4);
    let log = temp.path().join("starts");
    let job = job(
        media,
        worker(MIXED, &log, &log),
        std::time::Duration::from_secs(60),
    );
    let report = mneme_consolidation::recognition::run(
        &mut workspace,
        &job,
        &mneme_recall::inference::InvocationControl::new(),
    )
    .expect("run");
    assert_eq!(
        states(&report),
        [
            mneme_consolidation::recognition::UnitState::Published,
            mneme_consolidation::recognition::UnitState::Rejected,
            mneme_consolidation::recognition::UnitState::Rejected,
            mneme_consolidation::recognition::UnitState::Rejected,
        ]
    );
    assert_eq!(
        report.state,
        mneme_consolidation::recognition::JobState::Partial
    );
    assert_eq!((report.published, report.total), (1, 4));
    assert_eq!(runs(&mut workspace).len(), 1);
    let view = mneme_memory::Engine::new(&mut workspace, mneme_memory::Access::Operator)
        .view()
        .expect("view");
    let capture = view
        .source_at(media.source(), media.revision())
        .expect("capture");
    assert_eq!(
        capture.availability,
        mneme_memory::SourceAvailability::Retained
    );
}

#[test]
fn a_timed_out_or_cancelled_worker_is_reaped_and_publishes_nothing() {
    let (temp, mut workspace, media) = scan(1);
    let log = temp.path().join("starts");
    let slow = job(
        media,
        worker(ENDLESS, &log, &log),
        std::time::Duration::from_secs(1),
    );
    let report = mneme_consolidation::recognition::run(
        &mut workspace,
        &slow,
        &mneme_recall::inference::InvocationControl::new(),
    )
    .expect("timed out run");
    assert_eq!(
        states(&report),
        [mneme_consolidation::recognition::UnitState::Timeout]
    );

    let (temp, mut workspace, media) = scan(2);
    let (log, release) = (temp.path().join("starts"), temp.path().join("release"));
    let blocked = job(
        media,
        worker(BLOCKING, &log, &release),
        std::time::Duration::from_secs(60),
    );
    let control = mneme_recall::inference::InvocationControl::new();
    std::thread::scope(|threads| {
        let runner = threads
            .spawn(|| mneme_consolidation::recognition::run(&mut workspace, &blocked, &control));
        await_start(&log, &runner);
        control.cancel();
        let report = runner.join().expect("runner").expect("cancelled run");
        assert_eq!(
            states(&report),
            [
                mneme_consolidation::recognition::UnitState::Cancelled,
                mneme_consolidation::recognition::UnitState::Pending,
            ]
        );
        assert_eq!(
            report.state,
            mneme_consolidation::recognition::JobState::Cancelled
        );
    });
    // A release after cancellation reaches no worker: it was reaped.
    std::fs::write(&release, b"").expect("release");
    assert!(runs(&mut workspace).is_empty());
    let retried = mneme_consolidation::recognition::retry(&mut workspace, &blocked).expect("retry");
    assert_eq!(
        retried.state,
        mneme_consolidation::recognition::JobState::Queued
    );
}

#[test]
fn an_unavailable_recognizer_leaves_the_capture_and_the_job_waiting() {
    let (temp, mut workspace, media) = scan(2);
    let missing = mneme_recall::inference::WorkerCommand {
        executable: temp.path().join("no-recognizer"),
        args: Vec::new(),
    };
    let job = job(media, missing, std::time::Duration::from_secs(60));
    let report = mneme_consolidation::recognition::run(
        &mut workspace,
        &job,
        &mneme_recall::inference::InvocationControl::new(),
    )
    .expect("run");
    assert_eq!(
        report.state,
        mneme_consolidation::recognition::JobState::Queued
    );
    assert_eq!(
        states(&report),
        [mneme_consolidation::recognition::UnitState::Pending; 2]
    );
    assert_eq!(report.units[0].attempts, 1, "the attempt stays charged");
    assert!(runs(&mut workspace).is_empty());
}

#[test]
fn audio_is_divided_into_bounded_chunks_and_a_mismatched_plan_is_refused() {
    let temp = tempfile::tempdir().expect("temp");
    let mut workspace = mneme_store::Workspace::create(temp.path(), config()).expect("create");
    let media = mneme_core::SourcePin::new(
        mneme_core::RecordId::from_bytes([0x61; 16]),
        mneme_core::RevisionId::from_bytes([0x62; 16]),
    );
    let captured = mneme_memory::build_captured_source(
        media.source(),
        media.revision(),
        &scope(),
        mneme_memory::SourceOptions {
            bytes: b"synthetic audio bytes",
            media_type: "audio/wav",
            entity: None,
            path_hint: None,
        },
        mneme_core::MediaExtent::Audio {
            duration_ticks: 250,
            time_base: mneme_core::TimeBase::new(1, 100).expect("time base"),
            channels: 1,
        },
    )
    .expect("captured audio");
    commit(
        &mut workspace,
        "audio",
        (vec![captured.0], vec![captured.1]),
    );
    let log = temp.path().join("starts");
    let mut audio = job(
        media,
        worker(GOOD, &log, &log),
        std::time::Duration::from_secs(60),
    );
    assert!(matches!(
        mneme_consolidation::recognition::queue(&mut workspace, &audio),
        Err(mneme_consolidation::recognition::Failure::Invalid(_))
    ));
    audio.plan = mneme_consolidation::recognition::UnitPlan::AudioChunks { ticks: 100 };
    let queued = mneme_consolidation::recognition::queue(&mut workspace, &audio).expect("queue");
    let selectors: Vec<_> = queued.units.iter().map(|unit| unit.selector).collect();
    assert_eq!(
        selectors,
        [(0, 100), (100, 200), (200, 250)].map(|(start_tick, end_tick)| {
            mneme_consolidation::recognition::UnitSelector::Audio {
                start_tick,
                end_tick,
            }
        })
    );
}
