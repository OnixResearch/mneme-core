//! Per-request process isolation for bounded Prolog execution.
//!
//! Each request gets a fresh temporary script and child process. Host polling
//! enforces wall-clock/output limits and cancellation; the child is killed and
//! reaped before an outcome is returned. No workspace lock is held by the
//! worker, and reset means discarding the child and temporary directory.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::{Atom, CapabilityError, CapabilityMetadata, Literal, PrologRequest, encode_atom};

/// Host-side worker limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerLimits {
    pub max_wall_ms: u64,
    pub max_output_bytes: usize,
}

/// Cooperative cancellation for one worker request.
#[derive(Clone, Default)]
pub struct WorkerControl {
    cancelled: Arc<AtomicBool>,
}

impl WorkerControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
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

/// Run one request in a fresh external engine process.
///
/// The caller supplies an already authorized request and enabled capability.
/// `engine` must be the pinned Scryer-compatible executable.
#[allow(unknown_lints, ambient_clock)] // worker wall-clock budget is the process shell
pub fn run_worker(
    engine: &Path,
    metadata: &CapabilityMetadata,
    request: &PrologRequest,
    control: &WorkerControl,
    limits: WorkerLimits,
) -> Result<WorkerOutcome, CapabilityError> {
    metadata.ensure_request(request)?;
    if control.is_cancelled() {
        return Ok(WorkerOutcome {
            status: WorkerStatus::Cancelled,
            output: String::new(),
            elapsed_ms: 0,
            reason: Some("cancelled before worker start".to_owned()),
        });
    }
    if limits.max_wall_ms == 0 || limits.max_output_bytes == 0 {
        return Err(CapabilityError::LimitExceeded(
            "worker limits must be positive".to_owned(),
        ));
    }
    let started = Instant::now();
    let workspace = WorkerDir::new()?;
    let script = workspace.path().join("request.pl");
    write_program(&script, request, metadata)?;
    let stdout_path = workspace.path().join("stdout");
    let stderr_path = workspace.path().join("stderr");
    let stdout = std::fs::File::create(&stdout_path).map_err(|error| {
        CapabilityError::InvalidRequest(format!("cannot create worker output: {error}"))
    })?;
    let stderr = std::fs::File::create(&stderr_path).map_err(|error| {
        CapabilityError::InvalidRequest(format!("cannot create worker error: {error}"))
    })?;
    let mut child = Command::new(engine)
        .arg("-f")
        .arg("--no-add-history")
        .arg(&script)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| {
            CapabilityError::InvalidRequest(format!("cannot start Prolog worker: {error}"))
        })?;
    let deadline = started + Duration::from_millis(limits.max_wall_ms);
    let status = loop {
        if control.is_cancelled() {
            terminate(&mut child);
            break WorkerStatus::Cancelled;
        }
        match child.try_wait() {
            Ok(Some(exit)) => {
                break if exit.success() {
                    WorkerStatus::Complete
                } else {
                    WorkerStatus::Failed
                };
            }
            Ok(None) => {}
            Err(error) => {
                terminate(&mut child);
                return Err(CapabilityError::InvalidRequest(format!(
                    "worker wait failed: {error}"
                )));
            }
        }
        if Instant::now() >= deadline {
            terminate(&mut child);
            break WorkerStatus::Timeout;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let stdout = read_bounded(&stdout_path, limits.max_output_bytes)?;
    let output_limited = stdout.1;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).map_err(|_| {
        CapabilityError::LimitExceeded("worker elapsed time exceeds u64 milliseconds".to_owned())
    })?;
    Ok(WorkerOutcome {
        status: if output_limited {
            WorkerStatus::Partial
        } else {
            status
        },
        output: stdout.0,
        elapsed_ms,
        reason: if output_limited {
            Some("worker output exceeded the configured budget".to_owned())
        } else if status == WorkerStatus::Timeout {
            Some("worker exceeded its wall-clock budget".to_owned())
        } else if status == WorkerStatus::Cancelled {
            Some("worker was cancelled".to_owned())
        } else {
            None
        },
    })
}

#[allow(unknown_lints, ignored_result)] // process teardown is best-effort
fn terminate(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_bounded(path: &Path, limit: usize) -> Result<(String, bool), CapabilityError> {
    let file = std::fs::File::open(path)
        .map_err(|error| CapabilityError::InvalidRequest(format!("worker output: {error}")))?;
    let mut bytes = Vec::new();
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| CapabilityError::InvalidRequest(format!("worker output: {error}")))?;
    let limited = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), limited))
}

fn write_program(
    path: &Path,
    request: &PrologRequest,
    metadata: &CapabilityMetadata,
) -> Result<(), CapabilityError> {
    let mut file = std::fs::File::create(path).map_err(|error| {
        CapabilityError::InvalidRequest(format!("cannot write script: {error}"))
    })?;
    for rule in &request.rules {
        let head = encode_atom(&rule.head, metadata.terms, metadata.limits.max_output_bytes)?;
        let mut body = Vec::new();
        for literal in &rule.body {
            let text = match literal {
                Literal::Positive(atom) => {
                    encode_atom(atom, metadata.terms, metadata.limits.max_output_bytes)?
                }
                Literal::Negative(atom) => format!(
                    "\\+({})",
                    encode_atom(atom, metadata.terms, metadata.limits.max_output_bytes)?
                ),
            };
            body.push(text);
        }
        writeln!(file, "{head} :- {}.", body.join(", ")).map_err(|error| {
            CapabilityError::InvalidRequest(format!("cannot write rule: {error}"))
        })?;
    }
    let goal = encode_atom(
        &request.goal,
        metadata.terms,
        metadata.limits.max_output_bytes,
    )?;
    writeln!(file, ":- initialization((({goal}) -> halt(0) ; halt(1))).")
        .map_err(|error| CapabilityError::InvalidRequest(format!("cannot write goal: {error}")))?;
    Ok(())
}

struct WorkerDir {
    dir: tempfile::TempDir,
}

impl WorkerDir {
    fn new() -> Result<Self, CapabilityError> {
        let dir = tempfile::tempdir()
            .map_err(|error| CapabilityError::InvalidRequest(format!("worker tempdir: {error}")))?;
        Ok(WorkerDir { dir })
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for WorkerDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.dir.path());
    }
}

/// Render a goal for diagnostics without executing it.
pub fn render_goal(atom: &Atom, metadata: &CapabilityMetadata) -> Result<String, CapabilityError> {
    encode_atom(atom, metadata.terms, metadata.limits.max_output_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Feature, ProfileLimits, Term, TermProfile};
    use mneme_core::{ScopeClass, ScopeId, WorkspaceRevisionId};
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn metadata() -> CapabilityMetadata {
        CapabilityMetadata {
            adapter_version: "1".to_owned(),
            profile: "positive-minimal/v1".to_owned(),
            engine: Some(crate::EngineIdentity {
                name: "fake".to_owned(),
                version: "1".to_owned(),
                source_revision: "test".to_owned(),
            }),
            state: crate::CapabilityState::Enabled,
            features: BTreeSet::from([Feature::PositiveQuery]),
            allowed_predicates: BTreeSet::from(["path".to_owned()]),
            limits: ProfileLimits {
                max_time_ms: 1000,
                max_solutions: 4,
                max_output_bytes: 64,
                max_term_depth: 4,
                max_rule_count: 2,
            },
            terms: TermProfile {
                max_depth: 4,
                max_collection: 8,
                references_allowed: false,
            },
        }
    }

    fn request() -> PrologRequest {
        PrologRequest {
            actor: "agent".to_owned(),
            scope: ScopeId::new(ScopeClass::Project, "cedar").expect("scope"),
            revision: WorkspaceRevisionId::from_bytes([0xb0; 16]),
            eligibility_generation: 0,
            image_digest: "sha256:image".to_owned(),
            goal: Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::String("a".to_owned())],
            },
            rules: Vec::new(),
            assumptions: Vec::new(),
            features: BTreeSet::from([Feature::PositiveQuery]),
            limits: crate::RequestLimits {
                max_time_ms: 100,
                max_solutions: 2,
                max_output_bytes: 64,
            },
        }
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

    fn run_worker(
        engine: &Path,
        metadata: &CapabilityMetadata,
        request: &PrologRequest,
        control: &WorkerControl,
        limits: WorkerLimits,
    ) -> Result<WorkerOutcome, CapabilityError> {
        let _guard = spawn_guard();
        super::run_worker(engine, metadata, request, control, limits)
    }

    fn script(body: &str) -> (tempfile::TempDir, PathBuf) {
        let _guard = spawn_guard();
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("fake-engine");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).expect("script");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        }
        (temp, path)
    }

    #[test]
    fn completes_and_resets_with_a_fresh_process() {
        let (_temp, engine) = script("printf 'ok'");
        let outcome = run_worker(
            &engine,
            &metadata(),
            &request(),
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 1000,
                max_output_bytes: 1024,
            },
        )
        .expect("worker");
        assert_eq!(outcome.status, WorkerStatus::Complete);
        assert_eq!(outcome.output, "ok");
        let control = WorkerControl::new();
        control.cancel();
        let cancelled = run_worker(
            &engine,
            &metadata(),
            &request(),
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
    fn timeout_and_output_limits_are_qualified() {
        let (_sleep_temp, sleep_engine) = script("sleep 10");
        let timeout = run_worker(
            &sleep_engine,
            &metadata(),
            &request(),
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 30,
                max_output_bytes: 1024,
            },
        )
        .expect("timeout");
        assert_eq!(timeout.status, WorkerStatus::Timeout);
        assert!(timeout.elapsed_ms < 1000);

        let (_output_temp, output_engine) = script("printf '0123456789abcdef'");
        let limited = run_worker(
            &output_engine,
            &metadata(),
            &request(),
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 1000,
                max_output_bytes: 4,
            },
        )
        .expect("output limit");
        assert_eq!(limited.status, WorkerStatus::Partial);
        assert_eq!(limited.output, "0123");
    }

    #[test]
    fn timeout_does_not_block_baseline_workspace_operations() {
        let (_temp, engine) = script("sleep 10");
        let timeout = run_worker(
            &engine,
            &metadata(),
            &request(),
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 20,
                max_output_bytes: 1024,
            },
        )
        .expect("timeout");
        assert_eq!(timeout.status, WorkerStatus::Timeout);
        let workspace_dir = tempfile::tempdir().expect("workspace tempdir");
        let workspace = mneme_store::Workspace::create(
            workspace_dir.path(),
            mneme_store::WorkspaceConfig::default(),
        )
        .expect("workspace");
        assert!(workspace.status().is_ok());
    }

    #[test]
    fn real_scryer_worker_when_configured() {
        let Ok(engine) = std::env::var("MNEME_SCRYER_PROLOG") else {
            return;
        };
        let mut meta = metadata();
        meta.allowed_predicates.insert("true".to_owned());
        meta.allowed_predicates.insert("loop".to_owned());
        meta.limits.max_output_bytes = 64;
        let mut req = request();
        req.rules = vec![crate::PrologRule {
            id: "path-fact".to_owned(),
            version: "1".to_owned(),
            head: Atom {
                predicate: "path".to_owned(),
                terms: vec![Term::String("a".to_owned())],
            },
            body: vec![Literal::Positive(Atom {
                predicate: "true".to_owned(),
                terms: Vec::new(),
            })],
        }];
        let outcome = run_worker(
            std::path::Path::new(&engine),
            &meta,
            &req,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 1000,
                max_output_bytes: 1024,
            },
        )
        .expect("real worker");
        assert_eq!(outcome.status, WorkerStatus::Complete);

        let mut looping = req;
        looping.goal = Atom {
            predicate: "loop".to_owned(),
            terms: Vec::new(),
        };
        looping.rules = vec![crate::PrologRule {
            id: "loop".to_owned(),
            version: "1".to_owned(),
            head: looping.goal.clone(),
            body: vec![Literal::Positive(looping.goal.clone())],
        }];
        let timeout = run_worker(
            std::path::Path::new(&engine),
            &meta,
            &looping,
            &WorkerControl::new(),
            WorkerLimits {
                max_wall_ms: 30,
                max_output_bytes: 1024,
            },
        )
        .expect("real timeout");
        assert_eq!(timeout.status, WorkerStatus::Timeout);
    }
}
