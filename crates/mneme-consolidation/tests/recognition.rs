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

/// Waits for the release file, then declines the unit.
const BLOCKING_UNSUPPORTED: &str = r#"while [ ! -e "$2" ]; do :; done
printf '{"status":"unsupported"}'"#;

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
    let media = capture_scan(&mut workspace, pages);
    (temp, workspace, media)
}

/// Commit a captured scan of `pages` 400x300 pages.
fn capture_scan(workspace: &mut mneme_store::Workspace, pages: u32) -> mneme_core::SourcePin {
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
    commit(workspace, "capture", (vec![record], vec![blob]));
    media
}

/// Rewrite the job's saved progress, as a runner that stopped might have left it.
fn edit_progress(root: &std::path::Path, edit: impl FnOnce(&mut serde_json::Value)) {
    let path = progress_file(root);
    let mut progress: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("progress");
    edit(&mut progress);
    std::fs::write(&path, serde_json::to_vec(&progress).expect("encode")).expect("write");
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
         printf '%s' \"$\" > \"$1.pid\"; printf 'start\\n' >> \"$1\"; {answer}"
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
    // Each run declares the page its unit covered.
    let mut covered: Vec<mneme_core::CapturePart> =
        committed.iter().map(|run| run.covers).collect();
    covered.sort_by_key(|part| match part {
        mneme_core::CapturePart::Page(page) => *page,
        mneme_core::CapturePart::Whole | mneme_core::CapturePart::Audio { .. } => u32::MAX,
    });
    assert_eq!(
        covered,
        (0..3)
            .map(mneme_core::CapturePart::Page)
            .collect::<Vec<_>>()
    );
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
    mneme_consolidation::recognition::queue(&mut workspace, &job).expect("queue");
    // As if a runner had reserved unit 2 and stopped before its worker answered.
    edit_progress(temp.path(), |progress| {
        progress["units"][2]["state"] = "dispatched".into();
        progress["units"][2]["attempts"] = 1.into();
    });
    let first =
        mneme_consolidation::recognition::run(&mut open(temp.path()), &job, &control).expect("run");
    assert_eq!(
        states(&first),
        [
            mneme_consolidation::recognition::UnitState::Published,
            mneme_consolidation::recognition::UnitState::Published,
            mneme_consolidation::recognition::UnitState::Uncertain,
        ]
    );
    assert_eq!(
        starts(&log),
        2,
        "the uncertain unit was not dispatched again"
    );
    // As if a runner had committed unit 0's run and stopped before saving that.
    edit_progress(temp.path(), |progress| {
        progress["units"][0]["state"] = "dispatched".into();
        progress["units"][0]["run"] = serde_json::Value::Null;
    });
    let mut resumed = open(temp.path());
    let reconciled =
        mneme_consolidation::recognition::run(&mut resumed, &job, &control).expect("resume");
    assert_eq!(
        reconciled.units[0].state,
        mneme_consolidation::recognition::UnitState::Published
    );
    assert_eq!(
        reconciled.units[0].run, first.units[0].run,
        "reconciled to the committed run"
    );
    assert_eq!(starts(&log), 2, "a committed unit is not dispatched again");
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
    assert_eq!((rerun.units[2].attempts, starts(&log)), (2, 3));
    assert_eq!(runs(&mut resumed).len(), 3, "no unit was published twice");
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

/// Forget the capture while the first unit's worker runs, then let it answer
/// with `answer`. Returns the run's report and the workers started.
fn forget_during_first_unit(answer: &str) -> (mneme_consolidation::recognition::Report, usize) {
    let (temp, mut workspace, media) = scan(3);
    let (log, release) = (temp.path().join("starts"), temp.path().join("release"));
    let job = job(
        media,
        worker(answer, &log, &release),
        std::time::Duration::from_secs(60),
    );
    let control = mneme_recall::inference::InvocationControl::new();
    let report = std::thread::scope(|threads| {
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
        runner.join().expect("runner").expect("run")
    });
    assert!(
        runs(&mut open(temp.path())).is_empty(),
        "nothing was published"
    );
    (report, starts(&log))
}

#[test]
fn forgetting_the_capture_during_a_unit_suppresses_its_publication() {
    let (report, started) = forget_during_first_unit(BLOCKING);
    assert_eq!(
        states(&report),
        [mneme_consolidation::recognition::UnitState::Suppressed; 3],
        "the late answer and the units not yet run are suppressed"
    );
    assert_eq!(
        report.state,
        mneme_consolidation::recognition::JobState::Failed
    );
    assert_eq!(started, 1);
}

#[test]
fn a_forgotten_capture_is_never_sent_to_another_worker() {
    let (report, started) = forget_during_first_unit(BLOCKING_UNSUPPORTED);
    assert_eq!(
        states(&report),
        [
            mneme_consolidation::recognition::UnitState::Unsupported,
            mneme_consolidation::recognition::UnitState::Suppressed,
            mneme_consolidation::recognition::UnitState::Suppressed,
        ]
    );
    assert_eq!(started, 1, "no later unit received the forgotten capture");
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
    let pid = std::fs::read_to_string(format!("{}.pid", log.display())).expect("worker pid");
    assert!(
        !std::path::Path::new(&format!("/proc/{}", pid.trim())).exists(),
        "the cancelled worker was killed and reaped"
    );
    assert!(runs(&mut workspace).is_empty());
    let retried = mneme_consolidation::recognition::retry(&mut workspace, &blocked).expect("retry");
    assert_eq!(
        retried.state,
        mneme_consolidation::recognition::JobState::Queued
    );
}

#[test]
fn a_recognizer_installed_after_capture_recognizes_the_waiting_units() {
    let (temp, mut workspace, media) = scan(2);
    let recognizer = temp.path().join("recognizer");
    let missing = mneme_recall::inference::WorkerCommand {
        executable: recognizer.clone(),
        args: Vec::new(),
    };
    let job = job(media, missing, std::time::Duration::from_secs(60));
    let control = mneme_recall::inference::InvocationControl::new();
    // More runs than the job allows attempts per unit.
    for _ in 0..4 {
        let waiting = mneme_consolidation::recognition::run(&mut workspace, &job, &control)
            .expect("run without a recognizer");
        assert_eq!(
            waiting.state,
            mneme_consolidation::recognition::JobState::Queued
        );
        assert_eq!(
            states(&waiting),
            [mneme_consolidation::recognition::UnitState::Pending; 2]
        );
        assert_eq!(
            waiting.units[0].attempts, 0,
            "nothing ran, so no attempt is spent"
        );
    }
    assert!(runs(&mut workspace).is_empty());
    let log = temp.path().join("starts");
    let script = format!(
        "#!/bin/sh\nIFS= read -r header; while IFS= read -r line || [ -n \"$line\" ]; do :; done\n\
         printf 'start\\n' >> '{}'\n{GOOD}\n",
        log.display()
    );
    std::fs::write(&recognizer, script).expect("install the recognizer");
    std::fs::set_permissions(
        &recognizer,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )
    .expect("make it executable");
    let report = mneme_consolidation::recognition::run(&mut workspace, &job, &control)
        .expect("run with the recognizer");
    assert_eq!(
        report.state,
        mneme_consolidation::recognition::JobState::Complete
    );
    assert_eq!(report.units[0].attempts, 1);
    assert_eq!(
        report.charged.invocations, 6,
        "the four unavailable tries stay charged"
    );
    assert_eq!(starts(&log), 2);
}

#[test]
fn a_job_whose_access_excludes_its_scope_is_refused() {
    let (temp, mut workspace, media) = scan(1);
    let log = temp.path().join("starts");
    let mut job = job(
        media,
        worker(GOOD, &log, &log),
        std::time::Duration::from_secs(60),
    );
    job.access = mneme_memory::Access::scopes([mneme_core::ScopeId::new(
        mneme_core::ScopeClass::Project,
        "elsewhere",
    )
    .expect("scope")]);
    let control = mneme_recall::inference::InvocationControl::new();
    assert!(matches!(
        mneme_consolidation::recognition::run(&mut workspace, &job, &control),
        Err(mneme_consolidation::recognition::Failure::Invalid(_))
    ));
    assert!(matches!(
        mneme_consolidation::recognition::status(&workspace, &job),
        Err(mneme_consolidation::recognition::Failure::Invalid(_))
    ));
    assert_eq!(starts(&log), 0);
    assert!(runs(&mut workspace).is_empty());
}

/// Commits an unrelated record through a second handle just before the armed
/// handle's next commit transaction starts.
struct ConcurrentWriter {
    root: std::path::PathBuf,
    armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl mneme_store::FaultInjector for ConcurrentWriter {
    fn inject(&self, point: mneme_store::FaultPoint) -> bool {
        if point == mneme_store::FaultPoint::BeforeCommitTransaction
            && self.armed.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            let note = mneme_memory::build_source(
                mneme_core::RecordId::from_bytes([0x71; 16]),
                mneme_core::RevisionId::from_bytes([0x72; 16]),
                &scope(),
                mneme_memory::SourceOptions {
                    bytes: b"an unrelated note",
                    media_type: "text/plain",
                    entity: None,
                    path_hint: None,
                },
            )
            .expect("note");
            commit(
                &mut open(&self.root),
                "unrelated",
                (vec![note.0], vec![note.1]),
            );
        }
        false
    }
}

#[test]
fn a_commit_racing_a_publication_is_retried_not_lost() {
    let temp = tempfile::tempdir().expect("temp");
    let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut workspace = mneme_store::Workspace::create(
        temp.path(),
        mneme_store::WorkspaceConfig {
            clock: Box::new(mneme_store::FixedClock::new(
                mneme_core::Timestamp::from_nanos(1_000),
            )),
            faults: Box::new(ConcurrentWriter {
                root: temp.path().to_path_buf(),
                armed: std::sync::Arc::clone(&armed),
            }),
        },
    )
    .expect("create");
    let media = capture_scan(&mut workspace, 2);
    let log = temp.path().join("starts");
    let job = job(
        media,
        worker(GOOD, &log, &log),
        std::time::Duration::from_secs(60),
    );
    armed.store(true, std::sync::atomic::Ordering::SeqCst);
    let report = mneme_consolidation::recognition::run(
        &mut workspace,
        &job,
        &mneme_recall::inference::InvocationControl::new(),
    )
    .expect("a racing commit does not abort the run");
    assert!(
        !armed.load(std::sync::atomic::Ordering::SeqCst),
        "the race was injected"
    );
    assert_eq!(
        report.state,
        mneme_consolidation::recognition::JobState::Complete
    );
    assert_eq!((starts(&log), runs(&mut workspace).len()), (2, 2));
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
    let mut whole_scan = job(
        capture_scan(&mut workspace, 3),
        worker(GOOD, &log, &log),
        std::time::Duration::from_secs(60),
    );
    whole_scan.job_id = "whole-scan".to_owned();
    whole_scan.plan = mneme_consolidation::recognition::UnitPlan::Whole;
    assert!(
        matches!(
            mneme_consolidation::recognition::queue(&mut workspace, &whole_scan),
            Err(mneme_consolidation::recognition::Failure::Invalid(_))
        ),
        "a multi-page capture is recognized page by page"
    );
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
    // Spans placed by the caller divide the capture exactly, or are refused.
    let mut spans = audio.clone();
    spans.job_id = "spans".to_owned();
    for refused in [
        vec![],
        vec![120, 240],
        vec![120, 120, 250],
        vec![130, 120, 250],
        vec![0, 250],
        vec![50, 100, 150, 200, 250],
    ] {
        spans.plan = mneme_consolidation::recognition::UnitPlan::AudioSpans {
            ends: refused.clone(),
        };
        if refused.len() == 5 {
            spans.limits.max_units = 4;
        }
        assert!(
            matches!(
                mneme_consolidation::recognition::queue(&mut workspace, &spans),
                Err(mneme_consolidation::recognition::Failure::Invalid(_))
            ),
            "{refused:?} was planned"
        );
    }
    spans.limits.max_units = audio.limits.max_units;
    spans.plan = mneme_consolidation::recognition::UnitPlan::AudioSpans {
        ends: vec![120, 250],
    };
    let queued =
        mneme_consolidation::recognition::queue(&mut workspace, &spans).expect("queue spans");
    let selectors: Vec<_> = queued.units.iter().map(|unit| unit.selector).collect();
    assert_eq!(
        selectors,
        [(0, 120), (120, 250)].map(|(start_tick, end_tick)| {
            mneme_consolidation::recognition::UnitSelector::Audio {
                start_tick,
                end_tick,
            }
        })
    );
}
