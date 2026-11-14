//! Per-request process isolation for bounded Prolog execution.
//!
//! Each request gets a fresh temporary directory, script and child process. The
//! engine starts with a cleared environment whose only entry is the pinned
//! [`WORKER_ENV_PATH`], the temporary directory as its working directory, and
//! its own process group. Host polling drains stdout and stderr through
//! nonblocking pipes and enforces one combined byte budget while the engine is
//! producing output. The whole process group is signalled and the child is
//! reaped before an outcome is reported. No workspace lock is held by the
//! worker, and reset means discarding the child and temporary directory.
// Octet structural exception: domain-qualified names and macro-only imports are intentional

use std::io::{Read, Write};

/// Host-side worker limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerLimits {
    pub max_wall_ms: u64,
    pub max_output_bytes: usize,
}

/// Cooperative cancellation for one worker request.
#[derive(Clone, Debug, Default)]
pub struct WorkerControl {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl WorkerControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// Cancellation and host budgets that govern one worker run.
#[derive(Clone, Copy, Debug)]
pub struct WorkerRuntime<'a> {
    /// Cooperative cancellation polled while the engine runs.
    pub control: &'a WorkerControl,
    /// Wall-clock and output-byte budgets for this run.
    pub limits: WorkerLimits,
}

/// Qualified worker outcome. Complete does not imply logical exhaustion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerStatus {
    Complete,
    Partial,
    Timeout,
    Cancelled,
    Failed,
}

/// Bounded worker output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerOutcome {
    pub status: WorkerStatus,
    pub output: String,
    pub stderr: String,
    /// Number of stdout and stderr bytes retained under the combined budget.
    pub captured_bytes: usize,
    /// Whether stdout was valid UTF-8 before diagnostic conversion.
    pub output_utf8_valid: bool,
    pub elapsed_ms: u64,
    pub output_limit_exceeded: bool,
    pub solution_limit_exceeded: bool,
    pub reason: Option<String>,
}

/// Value of `PATH` the worker provides to the engine.
///
/// The engine starts with a cleared environment and then `PATH` is pinned to
/// this empty string. Setting it explicitly (rather than leaving it unset)
/// keeps the engine's own shell from installing a compiled-in default, so the
/// engine can never resolve an external command and the environment it sees is
/// exactly what this module specifies. The engine binary itself is always
/// executed by its absolute path.
pub(crate) const WORKER_ENV_PATH: &str = "";

/// Run one request against one immutable image in a fresh engine process.
///
/// The caller supplies an already authorized request and enabled capability.
/// `engine` must be the pinned Scryer-compatible executable. The worker refuses
/// an image whose context or digest does not match the request, so a mismatched
/// image never reaches the engine.
#[allow(unknown_lints, ambient_clock)] // worker wall-clock budget is the process shell
pub fn run_worker(
    engine: &std::path::Path,
    metadata: &crate::CapabilityMetadata,
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    runtime: &WorkerRuntime<'_>,
) -> Result<WorkerOutcome, crate::CapabilityError> {
    metadata.ensure_request(request)?;
    if image.verify_for_request(request).is_err() {
        return Err(crate::CapabilityError::InvalidRequest(
            "input image does not match the request".to_owned(),
        ));
    }
    if runtime.limits.max_wall_ms == 0 || runtime.limits.max_output_bytes == 0 {
        return Err(crate::CapabilityError::LimitExceeded(
            "worker limits must be positive".to_owned(),
        ));
    }
    if runtime.control.is_cancelled() {
        return Ok(WorkerOutcome {
            status: WorkerStatus::Cancelled,
            output: String::new(),
            stderr: String::new(),
            captured_bytes: 0,
            output_utf8_valid: true,
            elapsed_ms: 0,
            output_limit_exceeded: false,
            solution_limit_exceeded: false,
            reason: Some("cancelled before worker start".to_owned()),
        });
    }
    let started = std::time::Instant::now();
    let mut worker = start_worker(
        engine,
        metadata,
        image,
        request,
        runtime.limits.max_output_bytes,
    )?;
    let deadline = started + std::time::Duration::from_millis(runtime.limits.max_wall_ms);
    let waited = wait_for_worker(
        &mut worker,
        runtime.control,
        deadline,
        worker_solution_limit(request),
        runtime.limits.max_output_bytes,
    )?;
    drain_output(&mut worker, runtime.limits.max_output_bytes)?;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).map_err(|_| {
        crate::CapabilityError::LimitExceeded(
            "worker elapsed time exceeds u64 milliseconds".to_owned(),
        )
    })?;
    Ok(WorkerOutcome {
        status: waited.status,
        output: String::from_utf8_lossy(&worker.output).into_owned(),
        stderr: String::from_utf8_lossy(&worker.stderr_output).into_owned(),
        captured_bytes: worker.captured_bytes,
        output_utf8_valid: std::str::from_utf8(&worker.output).is_ok(),
        elapsed_ms,
        output_limit_exceeded: worker.output_limit_exceeded,
        solution_limit_exceeded: worker.solution_limit_exceeded,
        reason: waited.reason,
    })
}

fn worker_solution_limit(request: &crate::Request) -> usize {
    match request.mode {
        crate::QueryMode::GroundTest => 0,
        crate::QueryMode::FindOne => 1,
        crate::QueryMode::Enumerate => request.limits.max_solutions,
        crate::QueryMode::Collect => request.limits.max_solutions,
    }
}

/// Note appended to a reason when only the worker's leader could be stopped.
const GROUP_SIGNAL_NOTE: &str = "the worker process group could not be signalled";

struct RunningWorker {
    child: std::process::Child,
    _workspace: WorkerDir,
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
    output: Vec<u8>,
    stderr_output: Vec<u8>,
    scanned_output_bytes: usize,
    output_line_start: usize,
    solution_count: usize,
    collect_rows: Option<std::collections::BTreeSet<Vec<u8>>>,
    captured_bytes: usize,
    output_limit_exceeded: bool,
    solution_limit_exceeded: bool,
}

struct Waited {
    status: WorkerStatus,
    reason: Option<String>,
}

/// What host polling observed about the worker's output so far.
struct Observation {
    /// Combined stdout and stderr exceeded the configured budget.
    over_limit: bool,
    /// Derivation rows, or distinct binding rows for collection.
    solutions: usize,
}

fn start_worker(
    engine: &std::path::Path,
    metadata: &crate::CapabilityMetadata,
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    max_output_bytes: usize,
) -> Result<RunningWorker, crate::CapabilityError> {
    let workspace = WorkerDir::new()?;
    let script = workspace.path().join("request.pl");
    write_program(&script, image, request, metadata)?;
    let mut command = std::process::Command::new(engine);
    command
        .arg("-f")
        .arg("--no-add-history")
        .arg(&script)
        .current_dir(workspace.path())
        .env_clear()
        .env("PATH", WORKER_ENV_PATH)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // A fresh process group keeps the host's terminal signals off the engine
    // and lets termination reach everything the engine started.
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let mut child = command.spawn().map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot start Prolog worker: {error}"))
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        crate::CapabilityError::InvalidRequest("worker stdout pipe is unavailable".to_owned())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        crate::CapabilityError::InvalidRequest("worker stderr pipe is unavailable".to_owned())
    })?;
    let mut worker = RunningWorker {
        _workspace: workspace,
        child,
        stdout,
        stderr,
        output: Vec::with_capacity(max_output_bytes.min(4096)),
        stderr_output: Vec::new(),
        scanned_output_bytes: 0,
        output_line_start: 0,
        solution_count: 0,
        collect_rows: (request.mode == crate::QueryMode::Collect)
            .then(std::collections::BTreeSet::new),
        captured_bytes: 0,
        output_limit_exceeded: false,
        solution_limit_exceeded: false,
    };
    if let Err(error) =
        set_nonblocking(&worker.stdout).and_then(|()| set_nonblocking(&worker.stderr))
    {
        terminate(&mut worker);
        return Err(error);
    }
    Ok(worker)
}

fn set_nonblocking(fd: &impl std::os::fd::AsFd) -> Result<(), crate::CapabilityError> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("worker pipe flags: {error}"))
    })?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("worker pipe nonblocking mode: {error}"))
    })
}

fn wait_for_worker(
    worker: &mut RunningWorker,
    control: &WorkerControl,
    deadline: std::time::Instant,
    max_solutions: usize,
    max_output_bytes: usize,
) -> Result<Waited, crate::CapabilityError> {
    loop {
        if let Some(waited) = cancelled_wait(worker, control, max_output_bytes)? {
            return Ok(waited);
        }
        if let Some(waited) = exited_wait(worker, max_solutions, max_output_bytes)? {
            return Ok(waited);
        }
        if let Some(waited) = deadline_wait(worker, deadline, max_output_bytes)? {
            return Ok(waited);
        }
        if let Some(waited) = observed_limit_wait(worker, max_solutions, max_output_bytes)? {
            return Ok(waited);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn cancelled_wait(
    worker: &mut RunningWorker,
    control: &WorkerControl,
    max_output_bytes: usize,
) -> Result<Option<Waited>, crate::CapabilityError> {
    if !control.is_cancelled() {
        return Ok(None);
    }
    let reason = termination_reason(worker, "worker was cancelled");
    drain_output(worker, max_output_bytes)?;
    Ok(Some(Waited {
        status: WorkerStatus::Cancelled,
        reason: Some(reason),
    }))
}

fn exited_wait(
    worker: &mut RunningWorker,
    max_solutions: usize,
    max_output_bytes: usize,
) -> Result<Option<Waited>, crate::CapabilityError> {
    let exit = match worker.child.try_wait() {
        Ok(Some(exit)) => exit,
        Ok(None) => return Ok(None),
        Err(error) => {
            terminate(worker);
            return Err(crate::CapabilityError::InvalidRequest(format!(
                "worker wait failed: {error}"
            )));
        }
    };
    drain_output(worker, max_output_bytes)?;
    if !exit.success() {
        return Ok(Some(Waited {
            status: WorkerStatus::Failed,
            reason: None,
        }));
    }
    if worker.output_limit_exceeded {
        return Ok(Some(Waited {
            status: WorkerStatus::Partial,
            reason: Some("worker output exceeded the configured byte budget".to_owned()),
        }));
    }
    if worker.solution_count > max_solutions {
        worker.solution_limit_exceeded = true;
        return Ok(Some(Waited {
            status: WorkerStatus::Partial,
            reason: Some("worker exceeded the configured solution budget".to_owned()),
        }));
    }
    Ok(Some(Waited {
        status: WorkerStatus::Complete,
        reason: None,
    }))
}

#[allow(unknown_lints, ambient_clock)] // wall-clock deadline is part of worker admission
fn deadline_wait(
    worker: &mut RunningWorker,
    deadline: std::time::Instant,
    max_output_bytes: usize,
) -> Result<Option<Waited>, crate::CapabilityError> {
    if std::time::Instant::now() < deadline {
        return Ok(None);
    }
    let reason = termination_reason(worker, "worker exceeded its wall-clock budget");
    drain_output(worker, max_output_bytes)?;
    Ok(Some(Waited {
        status: WorkerStatus::Timeout,
        reason: Some(reason),
    }))
}

fn observed_limit_wait(
    worker: &mut RunningWorker,
    max_solutions: usize,
    max_output_bytes: usize,
) -> Result<Option<Waited>, crate::CapabilityError> {
    let observation = match observe_output(worker, max_output_bytes) {
        Ok(observation) => observation,
        Err(error) => {
            terminate(worker);
            return Err(error);
        }
    };
    if observation.over_limit {
        worker.output_limit_exceeded = true;
        let reason =
            termination_reason(worker, "worker output exceeded the configured byte budget");
        drain_output(worker, max_output_bytes)?;
        return Ok(Some(Waited {
            status: WorkerStatus::Partial,
            reason: Some(reason),
        }));
    }
    if observation.solutions > max_solutions {
        worker.solution_limit_exceeded = true;
        let reason = termination_reason(worker, "worker exceeded the configured solution budget");
        drain_output(worker, max_output_bytes)?;
        return Ok(Some(Waited {
            status: WorkerStatus::Partial,
            reason: Some(reason),
        }));
    }
    Ok(None)
}

/// Inspect the output written so far without waiting for the engine to stop.
fn observe_output(
    worker: &mut RunningWorker,
    limit: usize,
) -> Result<Observation, crate::CapabilityError> {
    drain_output(worker, limit)?;
    Ok(Observation {
        over_limit: worker.output_limit_exceeded,
        solutions: worker.solution_count,
    })
}

fn drain_output(worker: &mut RunningWorker, limit: usize) -> Result<(), crate::CapabilityError> {
    drain_pipe(
        &mut worker.stdout,
        &mut worker.output,
        &mut worker.captured_bytes,
        &mut worker.output_limit_exceeded,
        limit,
    )?;
    observe_solution_frames(worker);
    drain_pipe(
        &mut worker.stderr,
        &mut worker.stderr_output,
        &mut worker.captured_bytes,
        &mut worker.output_limit_exceeded,
        limit,
    )
}

/// Count complete response rows while stdout is drained. Enumerate counts each
/// derivation; Collect counts each distinct serialized binding tuple. The
/// latter is byte-exact because the worker emitter uses one canonical encoding
/// for each finite term and the request fixes binding order.
fn observe_solution_frames(worker: &mut RunningWorker) {
    while worker.scanned_output_bytes < worker.output.len() {
        let index = worker.scanned_output_bytes;
        if worker.output[index] == b'\n' {
            let line_start = worker.output_line_start;
            let line = &worker.output[line_start..index];
            count_solution_frame(&mut worker.collect_rows, &mut worker.solution_count, line);
            worker.output_line_start = index + 1;
        }
        worker.scanned_output_bytes += 1;
    }
}

fn count_solution_frame(
    collect_rows: &mut Option<std::collections::BTreeSet<Vec<u8>>>,
    solution_count: &mut usize,
    line: &[u8],
) {
    if !line.starts_with(crate::RESPONSE_ROW_PREFIX.as_bytes()) {
        return;
    }
    if let Some(rows) = collect_rows.as_mut() {
        if rows.contains(line) {
            return;
        }
        rows.insert(line.to_vec());
        *solution_count = rows.len();
    } else {
        *solution_count = (*solution_count).saturating_add(1);
    }
}

fn drain_pipe<R: Read>(
    pipe: &mut R,
    captured: &mut Vec<u8>,
    captured_bytes: &mut usize,
    over_limit: &mut bool,
    limit: usize,
) -> Result<(), crate::CapabilityError> {
    let mut buffer = [0_u8; 4096];
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                let available = limit.saturating_sub(*captured_bytes);
                let retained = read.min(available);
                captured.extend_from_slice(&buffer[..retained]);
                *captured_bytes = captured_bytes.saturating_add(retained);
                if retained < read {
                    *over_limit = true;
                    return Ok(());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(crate::CapabilityError::InvalidRequest(format!(
                    "worker output pipe: {error}"
                )));
            }
        }
    }
}

/// Kill the worker's process group and leader, then reap the leader.
///
/// Returns whether the whole group could be signalled. The leader is always
/// killed and reaped before this returns, so no outcome is reported while the
/// worker's own process is still running.
#[allow(unknown_lints, ignored_result)] // the leader is killed even when the group signal fails
fn terminate(worker: &mut RunningWorker) -> bool {
    let is_grouped = kill_process_group(worker.child.id());
    let _ = worker.child.kill();
    let _ = worker.child.wait();
    is_grouped
}

/// Kill the worker's process group with one system call.
///
/// No shell or external utility is involved, so the result does not depend on
/// what the host's `/bin/sh` provides. A process identifier of zero would name
/// the caller's own group and is refused. Returns whether the signal was
/// accepted.
fn kill_process_group(pid: u32) -> bool {
    let Some(group) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    rustix::process::kill_process_group(group, rustix::process::Signal::KILL).is_ok()
}

/// Terminate the worker and phrase its outcome reason.
///
/// A group signal that could not be issued is reported in the reason, so a
/// caller can tell that only the direct child was killed.
fn termination_reason(worker: &mut RunningWorker, reason: &str) -> String {
    if terminate(worker) {
        reason.to_owned()
    } else {
        format!("{reason}; {GROUP_SIGNAL_NOTE}")
    }
}

/// Write the one script that can reach the engine.
fn write_program(
    path: &std::path::Path,
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    metadata: &crate::CapabilityMetadata,
) -> Result<(), crate::CapabilityError> {
    let identity = request.protocol_identity(metadata, image)?;
    let mut text = String::from(EMITTER_SOURCE);
    for clause in program_clauses(image, request, metadata)? {
        text.push_str(&clause);
        text.push('\n');
    }
    let output_variables = request
        .variables
        .iter()
        .filter(|variable| variable.role == crate::VariableRole::Output)
        .map(|variable| variable.name.clone())
        .collect::<Vec<_>>();
    text.push_str(&emit_solution_clause(&output_variables, &identity));
    text.push('\n');
    text.push_str(&goal_directive(request, metadata, &identity)?);
    let mut file = std::fs::File::create(path).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot write script: {error}"))
    })?;
    file.write_all(text.as_bytes()).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot write script: {error}"))
    })
}

/// Every data clause, grouped so one predicate's clauses stay contiguous.
fn program_clauses(
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    metadata: &crate::CapabilityMetadata,
) -> Result<Vec<String>, crate::CapabilityError> {
    let budget = metadata.limits.max_output_bytes;
    let mut groups: std::collections::BTreeMap<(String, usize), Vec<String>> =
        std::collections::BTreeMap::new();
    for fact in &image.canonical {
        let atom = crate::Atom {
            predicate: crate::ASSERTION_RELATION.to_owned(),
            terms: vec![
                crate::Term::String(fact.predicate.clone()),
                crate::Term::String(fact.subject.to_hex()),
                crate::snapshot::value_term(&fact.value).map_err(|_| unrepresentable_image())?,
            ],
        };
        push_clause(&mut groups, &atom, metadata.terms, budget)?;
    }
    for relation in &image.relations {
        for row in &relation.rows {
            let atom = crate::Atom {
                predicate: crate::RELATION_RELATION.to_owned(),
                terms: vec![
                    crate::Term::String(relation.predicate.clone()),
                    crate::Term::List(
                        row.values
                            .iter()
                            .map(crate::snapshot::value_term)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|_| unrepresentable_image())?,
                    ),
                ],
            };
            push_clause(&mut groups, &atom, metadata.terms, budget)?;
        }
    }
    for assumption in &request.assumptions {
        push_clause(&mut groups, &assumption.atom, metadata.terms, budget)?;
    }
    for rule in &request.rules {
        let clause = rule_clause(rule, metadata.terms, budget)?;
        groups
            .entry((rule.head.predicate.clone(), rule.head.terms.len()))
            .or_default()
            .push(clause);
    }
    for (name, arity) in referenced_predicates(request) {
        if groups.contains_key(&(name.clone(), arity)) {
            continue;
        }
        // An undefined predicate would abort the search; a clause that never
        // succeeds makes an empty relation answer "no solutions" instead.
        groups
            .entry((name.clone(), arity))
            .or_default()
            .push(empty_relation_clause(&name, arity));
    }
    Ok(groups.into_values().flatten().collect())
}

fn unrepresentable_image() -> crate::CapabilityError {
    crate::CapabilityError::InvalidRequest(
        "input image contains a value that cannot be rendered".to_owned(),
    )
}

fn push_clause(
    groups: &mut std::collections::BTreeMap<(String, usize), Vec<String>>,
    atom: &crate::Atom,
    profile: crate::TermProfile,
    budget: usize,
) -> Result<(), crate::CapabilityError> {
    let clause = format!("{}.", crate::encode_atom(atom, profile, budget)?);
    groups
        .entry((atom.predicate.clone(), atom.terms.len()))
        .or_default()
        .push(clause);
    Ok(())
}

fn rule_clause(
    rule: &crate::Rule,
    profile: crate::TermProfile,
    budget: usize,
) -> Result<String, crate::CapabilityError> {
    let head = crate::encode_atom(&rule.head, profile, budget)?;
    let mut body = Vec::with_capacity(rule.body.len());
    for literal in &rule.body {
        match literal {
            crate::Literal::Positive(atom) => body.push(crate::encode_atom(atom, profile, budget)?),
            crate::Literal::Negative(_) => {
                return Err(crate::CapabilityError::UnsupportedFeature(
                    crate::Feature::GuardedNegation,
                ));
            }
        }
    }
    if body.is_empty() {
        return Ok(format!("{head}."));
    }
    Ok(format!("{head} :- {}.", body.join(", ")))
}

/// Every predicate name and arity the request calls.
fn referenced_predicates(request: &crate::Request) -> Vec<(String, usize)> {
    let mut found = std::collections::BTreeSet::new();
    found.insert((request.goal.predicate.clone(), request.goal.terms.len()));
    for rule in &request.rules {
        found.insert((rule.head.predicate.clone(), rule.head.terms.len()));
        for literal in &rule.body {
            match literal {
                crate::Literal::Positive(atom) | crate::Literal::Negative(atom) => {
                    found.insert((atom.predicate.clone(), atom.terms.len()));
                }
            }
        }
    }
    for assumption in &request.assumptions {
        found.insert((
            assumption.atom.predicate.clone(),
            assumption.atom.terms.len(),
        ));
    }
    found.into_iter().collect()
}

fn empty_relation_clause(name: &str, arity: usize) -> String {
    if arity == 0 {
        return format!("{name} :- fail.");
    }
    let placeholders = vec!["_"; arity].join(",");
    format!("{name}({placeholders}) :- fail.")
}

fn goal_directive(
    request: &crate::Request,
    metadata: &crate::CapabilityMetadata,
    identity: &crate::ProtocolIdentity,
) -> Result<String, crate::CapabilityError> {
    let goal = crate::encode_query_goal(request, metadata)?;
    let variables = request
        .variables
        .iter()
        .filter(|variable| variable.role == crate::VariableRole::Output)
        .map(|variable| variable.name.clone())
        .collect::<Vec<_>>();
    let emit = if variables.is_empty() {
        "mneme_emit_solution".to_owned()
    } else {
        format!("mneme_emit_solution({})", variables.join(","))
    };
    let header = emit_frame(&[
        crate::RESPONSE_HEADER_PREFIX,
        &identity.request_digest,
        &identity.profile_digest,
        &identity.rule_manifest_digest,
        &identity.input_order_digest,
        &identity.image_digest,
        request.mode.name(),
    ]);
    let stop = |name| emit_frame(&[crate::RESPONSE_STOP_PREFIX, &identity.request_digest, name]);
    let body = match request.mode {
        crate::QueryMode::GroundTest => format!(
            "({goal} -> {truth}; {falsehood}), halt(0)",
            truth = stop("ground-success"),
            falsehood = stop("ground-failure"),
        ),
        crate::QueryMode::FindOne => format!(
            "(({goal}, {emit}) -> {found}; {missing}), halt(0)",
            found = stop("found-one"),
            missing = stop("exhausted"),
        ),
        crate::QueryMode::Enumerate => format!(
            "(({goal}), {emit}, fail ; {exhausted}), halt(0)",
            exhausted = stop("exhausted"),
        ),
        crate::QueryMode::Collect => format!(
            "(({goal}), {emit}, fail ; {exhausted}), halt(0)",
            exhausted = stop("exhausted"),
        ),
    };
    Ok(format!(
        ":- initialization(mneme_main).\nmneme_main :- catch(({header}, {body}), _, halt(2))."
    ))
}

/// Render the clause that prints one solution line.
///
/// A line is `Name=Term,Name=Term…` in the restricted syntax, so the separator
/// between bindings must be *printed*; a `,` in the clause body is a
/// conjunction and would let the engine print `Name=aName=b`. An answer that is
/// not ground is not a finite binding set, so it is reported on the
/// [`crate::UNBOUND_MARKER`] line instead of a partially written solution.
fn emit_solution_clause(variables: &[String], identity: &crate::ProtocolIdentity) -> String {
    let head = if variables.is_empty() {
        "mneme_emit_solution".to_owned()
    } else {
        format!("mneme_emit_solution({})", variables.join(","))
    };
    let grounds = variables
        .iter()
        .map(|name| format!("ground({name})"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = format!(
        "write('{}') , put_code(9), write('{}'), put_code(9), ",
        crate::RESPONSE_ROW_PREFIX,
        identity.request_digest
    );
    for (index, name) in variables.iter().enumerate() {
        if index > 0 {
            body.push_str("write(','), ");
        }
        body.push_str("write('");
        body.push_str(name);
        body.push_str("='), mneme_emit_term(");
        body.push_str(name);
        body.push_str("), ");
    }
    if variables.is_empty() {
        return format!("{head} :- {body}nl.");
    }
    format!(
        "{head} :- ( {grounds} -> {body}nl ; write('{unbound}'), put_code(9), write('{digest}'), nl, halt(2) ).",
        unbound = crate::UNBOUND_MARKER,
        digest = identity.request_digest
    )
}

/// Emit a tab-delimited protocol frame without placing raw control characters
/// inside a Prolog source literal. Fields are fixed prefixes, validated hashes,
/// mode names, or the reserved output-variable names.
fn emit_frame(fields: &[&str]) -> String {
    let mut output = String::new();
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            output.push_str(", put_code(9), ");
        }
        output.push_str("write('");
        output.push_str(field);
        output.push_str("')");
    }
    output.push_str(", nl");
    output
}

/// Fixed wrapper predicates: the only code that prints or reads terms.
///
/// Every predicate here is inside the reserved `mneme_` namespace, which
/// request text cannot name, so no request can redefine the protocol.
const EMITTER_SOURCE: &str = r#"mneme_emit_term(V) :- ( ground(V) -> mneme_emit_ground(V) ; write('$unsupported') ).
mneme_emit_ground(V) :- ( integer(V) -> write(V) ; atom(V) -> mneme_emit_atom(V) ; compound(V) -> V =.. [F|Args], mneme_emit_compound(F, Args) ; write('$unsupported') ).
mneme_emit_compound('.', [H, T]) :- !, mneme_emit_cons(H, T).
mneme_emit_compound(F, Args) :- mneme_emit_atom(F), write('('), mneme_emit_args(Args), write(')').
mneme_emit_args([A]) :- mneme_emit_term(A).
mneme_emit_args([A|As]) :- As \== [], mneme_emit_term(A), write(','), mneme_emit_args(As).
mneme_emit_cons(H, T) :- ( mneme_char_list([H|T]) -> write('"'), mneme_emit_chars([H|T]), write('"') ; write('['), mneme_emit_term(H), mneme_emit_list_tail(T) ).
mneme_char_list([]).
mneme_char_list([C|Cs]) :- atom(C), atom_chars(C, [_]), mneme_char_list(Cs).
mneme_emit_list_tail(T) :- ( T == [] -> write(']') ; compound(T), T =.. ['.', H, Rest] -> write(','), mneme_emit_term(H), mneme_emit_list_tail(Rest) ; write('|'), mneme_emit_term(T), write(']') ).
mneme_emit_chars([]).
mneme_emit_chars([C|Cs]) :- char_code(C, N), mneme_emit_char(N, C), mneme_emit_chars(Cs).
mneme_emit_char(34, _) :- !, write('\\"').
mneme_emit_char(92, _) :- !, write('\\\\').
mneme_emit_char(N, _) :- N < 32, !, write('\\x'), mneme_hex2(N), write('\\').
mneme_emit_char(N, _) :- N >= 127, N < 160, !, write('\\x'), mneme_hex2(N), write('\\').
mneme_emit_char(_, C) :- write(C).
mneme_hex2(N) :- H is N // 16, L is N mod 16, mneme_hexd(H), mneme_hexd(L).
mneme_hexd(D) :- D < 10, !, W is 48 + D, put_code(W).
mneme_hexd(D) :- W is 87 + D, put_code(W).
mneme_emit_atom(A) :- ( A == [] -> write('[]') ; atom_chars(A, [First|Rest]), mneme_atom_start(First), mneme_atom_rest(Rest) -> write(A) ; write('$atom') ).
mneme_atom_start(C) :- char_code(C, N), N >= 97, N =< 122.
mneme_atom_rest([]).
mneme_atom_rest([C|Cs]) :- char_code(C, N), ( (N >= 97, N =< 122) ; (N >= 65, N =< 90) ; (N >= 48, N =< 57) ; N =:= 95 ), mneme_atom_rest(Cs).
"#;

struct WorkerDir {
    dir: tempfile::TempDir,
}

impl WorkerDir {
    fn new() -> Result<Self, crate::CapabilityError> {
        let dir = tempfile::tempdir().map_err(|error| {
            crate::CapabilityError::InvalidRequest(format!("worker tempdir: {error}"))
        })?;
        Ok(WorkerDir { dir })
    }

    fn path(&self) -> &std::path::Path {
        self.dir.path()
    }
}

impl Drop for WorkerDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.dir.path());
    }
}

/// Render a goal for diagnostics without executing it.
pub fn render_goal(
    atom: &crate::Atom,
    metadata: &crate::CapabilityMetadata,
) -> Result<String, crate::CapabilityError> {
    crate::encode_atom(atom, metadata.terms, metadata.limits.max_output_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> mneme_core::ScopeId {
        mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar").expect("scope")
    }

    fn revision() -> mneme_core::WorkspaceRevisionId {
        mneme_core::WorkspaceRevisionId::from_bytes([0xb0; 16])
    }

    fn metadata() -> crate::CapabilityMetadata {
        crate::CapabilityMetadata {
            adapter_version: "1".to_owned(),
            profile: "positive-minimal/v1".to_owned(),
            engine: Some(crate::EngineIdentity {
                name: "fake".to_owned(),
                version: "1".to_owned(),
                source_revision: "test".to_owned(),
            }),
            state: crate::CapabilityState::Enabled,
            features: std::collections::BTreeSet::from([crate::Feature::PositiveQuery]),
            allowed_predicates: std::collections::BTreeSet::from([
                "path".to_owned(),
                "assertion".to_owned(),
            ]),
            limits: crate::ProfileLimits {
                max_time_ms: 1000,
                max_solutions: 4,
                max_output_bytes: 256,
                max_term_depth: 4,
                max_rule_count: 2,
            },
            terms: crate::TermProfile {
                max_depth: 4,
                max_collection: 8,
                references_allowed: false,
            },
        }
    }

    fn request() -> crate::Request {
        crate::Request {
            actor: "agent".to_owned(),
            scope: scope(),
            revision: revision(),
            eligibility_generation: 0,
            image_digest: String::new(),
            mode: crate::QueryMode::GroundTest,
            goal: crate::Atom {
                predicate: "path".to_owned(),
                terms: vec![crate::Term::String("a".to_owned())],
            },
            variables: Vec::new(),
            rules: Vec::new(),
            assumptions: Vec::new(),
            features: std::collections::BTreeSet::from([crate::Feature::PositiveQuery]),
            limits: crate::RequestLimits {
                max_time_ms: 100,
                max_solutions: 2,
                max_output_bytes: 128,
            },
        }
    }

    fn image() -> crate::snapshot::InputImage {
        let mut image = crate::snapshot::InputImage {
            context: crate::SearchContext {
                revision: revision(),
                scope: scope(),
                eligibility_generation: 0,
                image_digest: String::new(),
                profile: "positive-minimal/v1".to_owned(),
                rule_versions: std::collections::BTreeMap::new(),
            },
            canonical: Vec::new(),
            relations: Vec::new(),
            coverage: crate::InputCoverage {
                complete: true,
                reason: None,
            },
        };
        image.seal();
        image
    }

    fn paired() -> (crate::Request, crate::snapshot::InputImage) {
        let image = image();
        let mut request = request();
        request.image_digest = image.context.image_digest.clone();
        (request, image)
    }

    fn output_request(mode: crate::QueryMode) -> (crate::Request, crate::snapshot::InputImage) {
        let (mut request, image) = paired();
        request.mode = mode;
        request.goal.terms = vec![crate::Term::Variable("X".to_owned())];
        request.variables = vec![crate::QueryVariable {
            name: "X".to_owned(),
            role: crate::VariableRole::Output,
        }];
        (request, image)
    }

    fn response_row(
        request: &crate::Request,
        metadata: &crate::CapabilityMetadata,
        image: &crate::snapshot::InputImage,
        value: &str,
    ) -> String {
        let identity = request
            .protocol_identity(metadata, image)
            .expect("request identity");
        format!(
            "{}\t{}\tX={value}",
            crate::RESPONSE_ROW_PREFIX,
            identity.request_digest
        )
    }

    // Executing a freshly written script can fail with ETXTBSY when another
    // test thread forks while the write descriptor is still open: the forked
    // child inherits the descriptor until its own exec. Serialize script
    // writes and worker spawns so no fork can observe an open write descriptor.
    static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn spawn_guard() -> std::sync::MutexGuard<'static, ()> {
        SPAWN_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn worker(
        engine: &std::path::Path,
        metadata: &crate::CapabilityMetadata,
        image: &crate::snapshot::InputImage,
        request: &crate::Request,
        control: &WorkerControl,
        limits: WorkerLimits,
    ) -> Result<WorkerOutcome, crate::CapabilityError> {
        let _guard = spawn_guard();
        super::run_worker(
            engine,
            metadata,
            image,
            request,
            &WorkerRuntime { control, limits },
        )
    }

    /// Resolve an absolute path to `name` from this test process's `PATH`.
    ///
    /// The worker clears the environment and uses its temporary directory as
    /// its working directory, so a fake engine can only call absolute paths.
    /// Resolve them here, before the worker starts, and interpolate them into
    /// the script text. `None` means the test cannot build a fake engine.
    ///
    /// This is the file's only `PATH` read: because the worker clears its
    /// environment, the shell path a fake engine execs has to be resolved here
    /// first.
    #[allow(unknown_lints, ambient_env)]
    fn path_binary(name: &str) -> Option<std::path::PathBuf> {
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path) {
                let candidate = directory.join(name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
        // NixOS keeps `/bin`, but not every binary lives there; this is only a
        // last resort.
        let fallback = std::path::Path::new("/bin").join(name);
        if fallback.is_file() {
            return Some(fallback);
        }
        None
    }

    fn shell() -> String {
        path_binary("sh")
            .expect("sh is on PATH or in /bin")
            .to_string_lossy()
            .into_owned()
    }

    fn script(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let _guard = spawn_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("fake-engine");
        let interpreter = shell();
        std::fs::write(&path, format!("#!{interpreter}\n{body}\n")).expect("script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        (temp, path)
    }

    fn pid_exists(pid: u32) -> bool {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }

    /// Wait briefly for a killed process to leave the process table.
    fn wait_for_exit(pid: u32) -> bool {
        let mut attempt = 0_u32;
        while attempt < 400 {
            if !pid_exists(pid) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
            attempt += 1;
        }
        false
    }

    #[test]
    fn completes_and_resets_with_fresh_state() {
        let (_temp, engine) = script("printf 'ok'");
        let (request, image) = paired();
        let outcome = worker(
            &engine,
            &metadata(),
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 1000,
                max_output_bytes: 1024,
            },
        )
        .expect("worker");
        assert_eq!(outcome.status, WorkerStatus::Complete);
        assert_eq!(outcome.output, "ok");
    }

    #[test]
    fn cancellation_before_start_spawns_nothing() {
        let (_temp, engine) = script("printf 'ok'");
        let (request, image) = paired();
        let control = WorkerControl::new();
        control.cancel();
        let cancelled = worker(
            &engine,
            &metadata(),
            &image,
            &request,
            &control,
            WorkerLimits {
                max_wall_ms: 1000,
                max_output_bytes: 1024,
            },
        )
        .expect("cancelled");
        assert_eq!(cancelled.status, WorkerStatus::Cancelled);
    }

    #[test]
    fn engine_starts_with_a_cleared_environment_in_the_worker_directory() {
        // The engine sees its own environment and working directory only; the
        // test never reads this process's environment, which keeps it free of
        // an ambient-environment waiver. `HOME` and `MNEME_SCRYER_PROLOG` are
        // exported by the check environment, so their absence proves the worker
        // cleared it; `PATH` must equal the pinned production value, so an
        // inherited `PATH` fails even though the parent value is never read;
        // and the directory is absolute and outside this crate.
        let (_temp, engine) =
            script("printf '%s|%s|%s|%s' \"$HOME\" \"$MNEME_SCRYER_PROLOG\" \"$PATH\" \"$(pwd)\"");
        let (request, image) = paired();
        let outcome = worker(
            &engine,
            &metadata(),
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 1000,
                max_output_bytes: 1024,
            },
        )
        .expect("worker");
        assert_eq!(outcome.status, WorkerStatus::Complete);
        let fields = outcome.output.split('|').collect::<Vec<_>>();
        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "", "HOME was inherited by the engine");
        assert_eq!(
            fields[1], "",
            "MNEME_SCRYER_PROLOG was inherited by the engine"
        );
        assert_eq!(
            fields[2], WORKER_ENV_PATH,
            "PATH was not the pinned worker value"
        );
        assert!(fields[3].starts_with('/'));
        assert!(
            !fields[3].starts_with(env!("CARGO_MANIFEST_DIR")),
            "the engine ran in the caller's directory"
        );
    }

    #[test]
    fn timeout_terminates_the_whole_group() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("pids");
        let shell = shell();
        let (_engine_temp, engine) = script(&format!(
            "{shell} -c 'while :; do :; done' &\necho $! > {file}\nwait",
            file = pid_file.display()
        ));
        let (request, image) = paired();
        let timeout = worker(
            &engine,
            &metadata(),
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                // Long enough that the engine has certainly started its
                // grandchild, short enough to keep the test quick.
                max_wall_ms: 300,
                max_output_bytes: 1024,
            },
        )
        .expect("timeout");
        assert_eq!(timeout.status, WorkerStatus::Timeout);
        assert!(timeout.elapsed_ms < 2000);
        let child = wait_for_pid(&pid_file).expect("recorded grandchild pid");
        assert!(
            wait_for_exit(child),
            "worker grandchild {child} survived the timeout"
        );
    }

    #[test]
    fn cancellation_terminates_the_running_worker() {
        let temp = tempfile::tempdir().expect("tempdir");
        let pid_file = temp.path().join("pids");
        let shell = shell();
        let (_engine_temp, engine) = script(&format!(
            "{shell} -c 'while :; do :; done' &\necho $! > {file}\nwait",
            file = pid_file.display()
        ));
        let (request, image) = paired();
        let control = WorkerControl::new();
        let cancelling = control.clone();
        // Cancel only after the engine recorded its grandchild, so this test
        // exercises cancellation of a running worker and the recorded pid is
        // guaranteed to exist whether the engine is fast or slow.
        let pid_path = pid_file.clone();
        let watcher = std::thread::spawn(move || {
            let pid = wait_for_pid(&pid_path).expect("recorded grandchild pid");
            cancelling.cancel();
            pid
        });
        let outcome = worker(
            &engine,
            &metadata(),
            &image,
            &request,
            &control,
            WorkerLimits {
                max_wall_ms: 5000,
                max_output_bytes: 1024,
            },
        )
        .expect("cancelled worker");
        let child = watcher.join().expect("cancel thread");
        assert_eq!(outcome.status, WorkerStatus::Cancelled);
        assert!(outcome.elapsed_ms < 2000);
        assert!(
            wait_for_exit(child),
            "worker grandchild {child} survived cancellation"
        );
    }

    /// Read the grandchild pid the fake engine recorded, waiting briefly while
    /// the worker is still starting.
    fn wait_for_pid(path: &std::path::Path) -> Option<u32> {
        let mut attempt = 0_u32;
        while attempt < 200 {
            if let Some(pid) = std::fs::read_to_string(path)
                .ok()
                .and_then(|text| text.trim().parse::<u32>().ok())
            {
                return Some(pid);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
            attempt += 1;
        }
        None
    }

    #[test]
    fn output_flood_is_stopped_at_the_byte_limit() {
        // The engine floods forever, so only the in-flight check can stop it.
        // The captured output is exactly the first budget bytes of the stream,
        // which starts with one full `0123456789` chunk.
        let (_temp, engine) = script("while true; do printf '0123456789'; done");
        let (request, image) = paired();
        let limited = worker(
            &engine,
            &metadata(),
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 5000,
                max_output_bytes: 10,
            },
        )
        .expect("output limit");
        assert_eq!(limited.status, WorkerStatus::Partial);
        assert_eq!(limited.output, "0123456789");
        assert!(
            limited.elapsed_ms < 2000,
            "output limit was applied too late"
        );
    }

    #[test]
    fn fast_output_flood_is_stopped_at_the_byte_limit() {
        // The engine writes more than the budget and exits on its own, so this
        // exercises the post-mortem byte count: the limit must hold whether the
        // worker is caught mid-flight or not, and the captured output is
        // exactly the first budget bytes of the sixteen the engine writes.
        let (_temp, engine) = script("printf '0123456789abcdef'");
        let (request, image) = paired();
        let limited = worker(
            &engine,
            &metadata(),
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 5000,
                max_output_bytes: 8,
            },
        )
        .expect("output limit");
        assert_eq!(limited.status, WorkerStatus::Partial);
        assert_eq!(limited.output, "01234567");
        assert_eq!(
            limited.reason.as_deref(),
            Some("worker output exceeded the configured byte budget")
        );
    }

    #[test]
    fn stderr_flood_is_stopped_during_production() {
        // Diagnostics are output too: a worker that floods stderr must be
        // contained by the same live byte budget, not allowed to fill its
        // temporary filesystem while stdout remains quiet.
        let (_temp, engine) = script("while true; do printf '0123456789' >&2; sleep 0.01; done");
        let (request, image) = paired();
        let limited = worker(
            &engine,
            &metadata(),
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 1000,
                max_output_bytes: 10,
            },
        )
        .expect("stderr output limit");
        assert_eq!(limited.status, WorkerStatus::Partial);
        assert!(
            limited.elapsed_ms < 500,
            "stderr output limit was applied too late"
        );
    }

    #[test]
    fn solution_flood_is_stopped_at_the_solution_limit() {
        // The engine records more solutions than the request allows and exits
        // on its own, so this exercises the post-mortem count: the limit must
        // hold whether the worker is caught mid-flight or not.
        let metadata = metadata();
        let (mut request, image) = output_request(crate::QueryMode::Enumerate);
        request.limits.max_solutions = 3;
        let identity = request
            .protocol_identity(&metadata, &image)
            .expect("request identity");
        let body = format!(
            "i=0\nwhile [ $i -lt 10 ]; do\n  printf '%s\\t%s\\tX=%s\\n' '{}' '{}' \"$i\"\n  i=$((i+1))\ndone",
            crate::RESPONSE_ROW_PREFIX,
            identity.request_digest
        );
        let (_temp, engine) = script(&body);
        let limited = worker(
            &engine,
            &metadata,
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 5000,
                max_output_bytes: 4096,
            },
        )
        .expect("solution limit");
        assert_eq!(limited.status, WorkerStatus::Partial);
        assert_eq!(
            limited.reason.as_deref(),
            Some("worker exceeded the configured solution budget")
        );
    }

    #[test]
    fn slow_solution_stream_is_stopped_in_flight() {
        // The engine records more solutions than the request allows and never
        // exits, so only the in-flight check can stop it.
        let metadata = metadata();
        let (mut request, image) = output_request(crate::QueryMode::Enumerate);
        request.limits.max_solutions = 3;
        let first = response_row(&request, &metadata, &image, "1");
        let second = response_row(&request, &metadata, &image, "2");
        let third = response_row(&request, &metadata, &image, "3");
        let fourth = response_row(&request, &metadata, &image, "4");
        let body = format!(
            "printf '%s\\n' '{first}' '{second}' '{third}' '{fourth}'\nwhile :; do :; done"
        );
        let (_temp, engine) = script(&body);
        let limited = worker(
            &engine,
            &metadata,
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 5000,
                max_output_bytes: 4096,
            },
        )
        .expect("solution limit");
        assert_eq!(limited.status, WorkerStatus::Partial);
        assert_eq!(
            limited.reason.as_deref(),
            Some("worker exceeded the configured solution budget")
        );
        assert!(
            limited.elapsed_ms < 2000,
            "solution limit was applied too late"
        );
    }

    #[test]
    fn collect_counts_unique_binding_frames_during_production() {
        let metadata = metadata();
        let (mut request, image) = output_request(crate::QueryMode::Collect);
        request.limits.max_solutions = 1;
        let repeated = response_row(&request, &metadata, &image, "1");
        let distinct = response_row(&request, &metadata, &image, "2");
        let body = format!(
            "printf '%s\\n' '{repeated}' '{repeated}' '{repeated}' '{repeated}' '{distinct}'\nwhile :; do :; done"
        );
        let (_temp, engine) = script(&body);
        let limited = worker(
            &engine,
            &metadata,
            &image,
            &request,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 5000,
                max_output_bytes: 4096,
            },
        )
        .expect("distinct collect solution limit");
        assert_eq!(limited.status, WorkerStatus::Partial);
        assert!(limited.solution_limit_exceeded);
        assert_eq!(
            limited.reason.as_deref(),
            Some("worker exceeded the configured solution budget")
        );
        assert_eq!(
            limited
                .output
                .lines()
                .filter(|line| line.starts_with(crate::RESPONSE_ROW_PREFIX))
                .count(),
            5,
            "duplicate derivations must not spend the unique-binding cap"
        );
    }

    #[test]
    fn an_image_from_another_context_is_refused_before_start() {
        let (_temp, engine) = script("printf 'should-not-run'");
        let image = image();
        let mut request = request();
        request.image_digest = "sha256:different".to_owned();
        assert!(matches!(
            worker(
                &engine,
                &metadata(),
                &image,
                &request,
                &WorkerControl::new(),
                WorkerLimits {
                    max_wall_ms: 1000,
                    max_output_bytes: 1024,
                },
            ),
            Err(crate::CapabilityError::InvalidRequest(_))
        ));
    }

    #[test]
    fn zero_or_oversized_worker_limits_are_refused() {
        let (_temp, engine) = script("printf 'ok'");
        let (request, image) = paired();
        assert!(matches!(
            worker(
                &engine,
                &metadata(),
                &image,
                &request,
                &WorkerControl::new(),
                WorkerLimits {
                    max_wall_ms: 0,
                    max_output_bytes: 1024,
                },
            ),
            Err(crate::CapabilityError::LimitExceeded(_))
        ));
        assert!(matches!(
            worker(
                &engine,
                &metadata(),
                &image,
                &request,
                &WorkerControl::new(),
                WorkerLimits {
                    max_wall_ms: 1000,
                    max_output_bytes: 0,
                },
            ),
            Err(crate::CapabilityError::LimitExceeded(_))
        ));
    }
}
