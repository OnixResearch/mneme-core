//! Per-request process isolation for bounded Prolog execution.
//!
//! Each request gets a fresh temporary directory, script and child process. The
//! engine starts with a cleared environment whose only entry is the pinned
//! [`WORKER_ENV_PATH`], the temporary directory as its working directory, and
//! its own process group. Host polling enforces the
//! wall-clock, output-byte and solution-count limits and cooperative
//! cancellation; the whole process group is signalled and the child is reaped
//! before any outcome is reported. No workspace lock is held by the worker, and
//! reset means discarding the child and the temporary directory. When the group
//! signal cannot be issued the direct child is still killed and reaped, and the
//! outcome reason says that only the leader was stopped.
//!
//! The in-flight byte and solution checks are early stops, not the only ones: a
//! fast engine can finish and exit between polls, so the captured output is
//! measured once more after the worker ends and the outcome is reported as
//! partial when it holds more bytes or more solutions than the request allows.
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
    pub elapsed_ms: u64,
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
            elapsed_ms: 0,
            reason: Some("cancelled before worker start".to_owned()),
        });
    }
    let started = std::time::Instant::now();
    let mut worker = start_worker(engine, metadata, image, request)?;
    let deadline = started + std::time::Duration::from_millis(runtime.limits.max_wall_ms);
    let waited = wait_for_worker(
        &mut worker,
        runtime.control,
        deadline,
        request.limits.max_solutions,
        runtime.limits.max_output_bytes,
    )?;
    let (output, over_output_limit) =
        read_bounded(&worker.stdout_path, runtime.limits.max_output_bytes)?;
    let (status, reason) = apply_output_budget(
        waited.status,
        waited.reason,
        &output,
        over_output_limit,
        request.limits.max_solutions,
    );
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).map_err(|_| {
        crate::CapabilityError::LimitExceeded(
            "worker elapsed time exceeds u64 milliseconds".to_owned(),
        )
    })?;
    Ok(WorkerOutcome {
        status,
        output,
        elapsed_ms,
        reason,
    })
}

/// Count complete solution lines in the captured worker output.
///
/// Only newline-terminated lines count, and the completion marker is not a
/// solution, so a fragment cut by the byte budget is never counted.
fn counted_solution_lines(output: &str) -> usize {
    let complete_len = output.rfind('\n').map_or(0, |index| index + 1);
    let mut lines = output[..complete_len]
        .split_terminator('\n')
        .collect::<Vec<_>>();
    if lines.last() == Some(&crate::COMPLETION_MARKER) {
        lines.pop();
    }
    lines.len()
}

/// Apply the byte and solution budgets to the worker's final status.
///
/// A limit the in-flight poll did not catch is still a limit: an engine that
/// finished and exited between two polls still wrote more output, or more
/// solutions, than the request allows. The captured output is therefore
/// measured once more after the worker ends. A failed engine keeps its status,
/// because its output never becomes an answer.
fn apply_output_budget(
    status: WorkerStatus,
    reason: Option<String>,
    output: &str,
    over_output_limit: bool,
    max_solutions: usize,
) -> (WorkerStatus, Option<String>) {
    if status == WorkerStatus::Failed {
        return (status, reason);
    }
    let previous = reason.as_deref();
    if over_output_limit {
        return (
            WorkerStatus::Partial,
            Some(limit_reason(
                "worker output exceeded the configured byte budget",
                previous,
            )),
        );
    }
    if counted_solution_lines(output) > max_solutions {
        return (
            WorkerStatus::Partial,
            Some(limit_reason(
                "worker exceeded the configured solution budget",
                previous,
            )),
        );
    }
    (status, reason)
}

/// Note appended to a reason when only the worker's leader could be stopped.
const GROUP_SIGNAL_NOTE: &str = "the worker process group could not be signalled";

/// Phrase a post-mortem limit reason, keeping a termination note the in-flight
/// path already recorded.
fn limit_reason(base: &str, previous: Option<&str>) -> String {
    match previous {
        Some(reason) if reason.contains(GROUP_SIGNAL_NOTE) => {
            format!("{base}; {GROUP_SIGNAL_NOTE}")
        }
        _ => base.to_owned(),
    }
}

struct RunningWorker {
    child: std::process::Child,
    _workspace: WorkerDir,
    stdout_path: std::path::PathBuf,
}

struct Waited {
    status: WorkerStatus,
    reason: Option<String>,
}

/// What host polling observed about the worker's output so far.
struct Observation {
    /// The output file is larger than the configured budget.
    over_limit: bool,
    /// Complete solution lines written so far.
    solutions: usize,
    /// The completion marker is the last complete line.
    finished: bool,
}

fn start_worker(
    engine: &std::path::Path,
    metadata: &crate::CapabilityMetadata,
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
) -> Result<RunningWorker, crate::CapabilityError> {
    let workspace = WorkerDir::new()?;
    let script = workspace.path().join("request.pl");
    write_program(&script, image, request, metadata)?;
    let stdout_path = workspace.path().join("stdout");
    let stderr_path = workspace.path().join("stderr");
    let stdout = std::fs::File::create(&stdout_path).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot create worker output: {error}"))
    })?;
    let stderr = std::fs::File::create(&stderr_path).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot create worker error: {error}"))
    })?;
    let mut command = std::process::Command::new(engine);
    command
        .arg("-f")
        .arg("--no-add-history")
        .arg(&script)
        .current_dir(workspace.path())
        .env_clear()
        .env("PATH", WORKER_ENV_PATH)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr));
    // A fresh process group keeps the host's terminal signals off the engine
    // and lets termination reach everything the engine started.
    std::os::unix::process::CommandExt::process_group(&mut command, 0);
    let child = command.spawn().map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot start Prolog worker: {error}"))
    })?;
    Ok(RunningWorker {
        _workspace: workspace,
        child,
        stdout_path,
    })
}

#[allow(unknown_lints, ambient_clock)] // wait-loop deadline is the worker timeout shell
fn wait_for_worker(
    worker: &mut RunningWorker,
    control: &WorkerControl,
    deadline: std::time::Instant,
    max_solutions: usize,
    max_output_bytes: usize,
) -> Result<Waited, crate::CapabilityError> {
    loop {
        if control.is_cancelled() {
            let reason = termination_reason(worker, "worker was cancelled");
            return Ok(Waited {
                status: WorkerStatus::Cancelled,
                reason: Some(reason),
            });
        }
        match worker.child.try_wait() {
            Ok(Some(exit)) => {
                return Ok(Waited {
                    status: if exit.success() {
                        WorkerStatus::Complete
                    } else {
                        WorkerStatus::Failed
                    },
                    reason: None,
                });
            }
            Ok(None) => {}
            Err(error) => {
                terminate(worker);
                return Err(crate::CapabilityError::InvalidRequest(format!(
                    "worker wait failed: {error}"
                )));
            }
        }
        let observation = match observe_output(&worker.stdout_path, max_output_bytes) {
            Ok(observation) => observation,
            Err(error) => {
                terminate(worker);
                return Err(error);
            }
        };
        if observation.over_limit {
            let reason =
                termination_reason(worker, "worker output exceeded the configured byte budget");
            return Ok(Waited {
                status: WorkerStatus::Partial,
                reason: Some(reason),
            });
        }
        if !observation.finished && observation.solutions > max_solutions {
            let reason =
                termination_reason(worker, "worker exceeded the configured solution budget");
            return Ok(Waited {
                status: WorkerStatus::Partial,
                reason: Some(reason),
            });
        }
        if std::time::Instant::now() >= deadline {
            let reason = termination_reason(worker, "worker exceeded its wall-clock budget");
            return Ok(Waited {
                status: WorkerStatus::Timeout,
                reason: Some(reason),
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// Inspect the output written so far without waiting for the engine to stop.
fn observe_output(
    path: &std::path::Path,
    limit: usize,
) -> Result<Observation, crate::CapabilityError> {
    let bytes = read_prefix(path, limit)?;
    let is_over_limit = bytes.len() > limit;
    let visible = &bytes[..bytes.len().min(limit)];
    let complete_len = visible
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let complete = &visible[..complete_len];
    let line_count = complete.iter().filter(|byte| **byte == b'\n').count();
    let mut marker = crate::COMPLETION_MARKER.as_bytes().to_vec();
    marker.push(b'\n');
    let is_finished = complete.ends_with(marker.as_slice());
    Ok(Observation {
        over_limit: is_over_limit,
        solutions: if is_finished {
            line_count.saturating_sub(1)
        } else {
            line_count
        },
        finished: is_finished,
    })
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

/// Read at most `limit + 1` bytes, so a caller can tell "at the limit" from
/// "over the limit" without reading the whole file.
fn read_prefix(path: &std::path::Path, limit: usize) -> Result<Vec<u8>, crate::CapabilityError> {
    let file = std::fs::File::open(path).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("worker output: {error}"))
    })?;
    let mut bytes = Vec::new();
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            crate::CapabilityError::InvalidRequest(format!("worker output: {error}"))
        })?;
    Ok(bytes)
}

/// Read the captured output, truncated to the byte budget, and report whether
/// the engine wrote more than the budget allows.
fn read_bounded(
    path: &std::path::Path,
    limit: usize,
) -> Result<(String, bool), crate::CapabilityError> {
    let mut bytes = read_prefix(path, limit)?;
    let is_over_limit = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), is_over_limit))
}

/// Write the one script that can reach the engine.
fn write_program(
    path: &std::path::Path,
    image: &crate::snapshot::InputImage,
    request: &crate::Request,
    metadata: &crate::CapabilityMetadata,
) -> Result<(), crate::CapabilityError> {
    let mut text = String::from(EMITTER_SOURCE);
    for clause in program_clauses(image, request, metadata)? {
        text.push_str(&clause);
        text.push('\n');
    }
    text.push_str(&emit_solution_clause(&crate::goal_variables(&request.goal)));
    text.push('\n');
    text.push_str(&goal_directive(request, metadata)?);
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
) -> Result<String, crate::CapabilityError> {
    let goal = crate::encode_atom(
        &request.goal,
        metadata.terms,
        metadata.limits.max_output_bytes,
    )?;
    let variables = crate::goal_variables(&request.goal);
    let emit = if variables.is_empty() {
        "mneme_emit_solution".to_owned()
    } else {
        format!("mneme_emit_solution({})", variables.join(","))
    };
    Ok(format!(
        ":- initialization(mneme_main).\nmneme_main :- catch(( ({goal}), {emit}, fail ; write('{marker}'), nl, halt(0) ), _, halt(2)).",
        marker = crate::COMPLETION_MARKER
    ))
}

/// Render the clause that prints one solution line.
///
/// A line is `Name=Term,Name=Term…` in the restricted syntax, so the separator
/// between bindings must be *printed*; a `,` in the clause body is a
/// conjunction and would let the engine print `Name=aName=b`. An answer that is
/// not ground is not a finite binding set, so it is reported on the
/// [`crate::UNBOUND_MARKER`] line instead of a partially written solution.
fn emit_solution_clause(variables: &[String]) -> String {
    if variables.is_empty() {
        return "mneme_emit_solution :- nl.".to_owned();
    }
    let head = format!("mneme_emit_solution({})", variables.join(","));
    let grounds = variables
        .iter()
        .map(|name| format!("ground({name})"))
        .collect::<Vec<_>>()
        .join(", ");
    let mut body = String::new();
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
    format!(
        "{head} :- ( {grounds} -> {body}nl ; write('{unbound}'), nl ).",
        unbound = crate::UNBOUND_MARKER
    )
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
            goal: crate::Atom {
                predicate: "path".to_owned(),
                terms: vec![crate::Term::String("a".to_owned())],
            },
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
    fn solution_flood_is_stopped_at_the_solution_limit() {
        // The engine records more solutions than the request allows and exits
        // on its own, so this exercises the post-mortem count: the limit must
        // hold whether the worker is caught mid-flight or not.
        let (_temp, engine) =
            script("i=0\nwhile [ $i -lt 100 ]; do\n  printf 'X=%s\\n' \"$i\"\n  i=$((i+1))\ndone");
        let (mut request, image) = paired();
        request.limits.max_solutions = 3;
        let limited = worker(
            &engine,
            &metadata(),
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
        let (_temp, engine) = script("printf 'X=1\\nX=2\\nX=3\\nX=4\\n'\nwhile :; do :; done");
        let (mut request, image) = paired();
        request.limits.max_solutions = 3;
        let limited = worker(
            &engine,
            &metadata(),
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
