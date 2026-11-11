//! Per-request process isolation for bounded Prolog execution.
//!
//! Each request gets a fresh temporary script and child process. Host polling
//! enforces wall-clock/output limits and cancellation; the child is killed and
//! reaped before an outcome is returned. No workspace lock is held by the
//! worker, and reset means discarding the child and temporary directory.

use std::io::{Read, Write};

/// Host-side worker limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkerLimits {
    pub max_wall_ms: u64,
    pub max_output_bytes: usize,
}

/// Cooperative cancellation for one worker request.
#[derive(Clone, Default)]
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
    engine: &std::path::Path,
    metadata: &crate::CapabilityMetadata,
    request: &crate::PrologRequest,
    control: &WorkerControl,
    limits: WorkerLimits,
) -> Result<WorkerOutcome, crate::CapabilityError> {
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
        return Err(crate::CapabilityError::LimitExceeded(
            "worker limits must be positive".to_owned(),
        ));
    }
    let started = std::time::Instant::now();
    let workspace = WorkerDir::new()?;
    let script = workspace.path().join("request.pl");
    write_program(&script, request, metadata)?;
    let stdout_path = workspace.path().join("stdout");
    let stderr_path = workspace.path().join("stderr");
    let stdout = std::fs::File::create(&stdout_path).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot create worker output: {error}"))
    })?;
    let stderr = std::fs::File::create(&stderr_path).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot create worker error: {error}"))
    })?;
    let mut child = std::process::Command::new(engine)
        .arg("-f")
        .arg("--no-add-history")
        .arg(&script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(stdout))
        .stderr(std::process::Stdio::from(stderr))
        .spawn()
        .map_err(|error| {
            crate::CapabilityError::InvalidRequest(format!("cannot start Prolog worker: {error}"))
        })?;
    let deadline = started + std::time::Duration::from_millis(limits.max_wall_ms);
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
                return Err(crate::CapabilityError::InvalidRequest(format!(
                    "worker wait failed: {error}"
                )));
            }
        }
        if std::time::Instant::now() >= deadline {
            terminate(&mut child);
            break WorkerStatus::Timeout;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let stdout = read_bounded(&stdout_path, limits.max_output_bytes)?;
    let is_output_limited = stdout.1;
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).map_err(|_| {
        crate::CapabilityError::LimitExceeded(
            "worker elapsed time exceeds u64 milliseconds".to_owned(),
        )
    })?;
    Ok(WorkerOutcome {
        status: if is_output_limited {
            WorkerStatus::Partial
        } else {
            status
        },
        output: stdout.0,
        elapsed_ms,
        reason: if is_output_limited {
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
fn terminate(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn read_bounded(
    path: &std::path::Path,
    limit: usize,
) -> Result<(String, bool), crate::CapabilityError> {
    let file = std::fs::File::open(path).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("worker output: {error}"))
    })?;
    let mut bytes = Vec::new();
    file.take((limit as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| {
            crate::CapabilityError::InvalidRequest(format!("worker output: {error}"))
        })?;
    let is_limited = bytes.len() > limit;
    bytes.truncate(limit);
    Ok((String::from_utf8_lossy(&bytes).into_owned(), is_limited))
}

fn write_program(
    path: &std::path::Path,
    request: &crate::PrologRequest,
    metadata: &crate::CapabilityMetadata,
) -> Result<(), crate::CapabilityError> {
    let mut file = std::fs::File::create(path).map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot write script: {error}"))
    })?;
    for rule in &request.rules {
        let head =
            crate::encode_atom(&rule.head, metadata.terms, metadata.limits.max_output_bytes)?;
        let mut body = Vec::new();
        for literal in &rule.body {
            let text = match literal {
                crate::Literal::Positive(atom) => {
                    crate::encode_atom(atom, metadata.terms, metadata.limits.max_output_bytes)?
                }
                crate::Literal::Negative(atom) => format!(
                    "\\+({})",
                    crate::encode_atom(atom, metadata.terms, metadata.limits.max_output_bytes)?
                ),
            };
            body.push(text);
        }
        writeln!(file, "{head} :- {}.", body.join(", ")).map_err(|error| {
            crate::CapabilityError::InvalidRequest(format!("cannot write rule: {error}"))
        })?;
    }
    let goal = crate::encode_atom(
        &request.goal,
        metadata.terms,
        metadata.limits.max_output_bytes,
    )?;
    writeln!(file, ":- initialization((({goal}) -> halt(0) ; halt(1))).").map_err(|error| {
        crate::CapabilityError::InvalidRequest(format!("cannot write goal: {error}"))
    })?;
    Ok(())
}

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
            allowed_predicates: std::collections::BTreeSet::from(["path".to_owned()]),
            limits: crate::ProfileLimits {
                max_time_ms: 1000,
                max_solutions: 4,
                max_output_bytes: 64,
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

    fn request() -> crate::PrologRequest {
        crate::PrologRequest {
            actor: "agent".to_owned(),
            scope: mneme_core::ScopeId::new(mneme_core::ScopeClass::Project, "cedar")
                .expect("scope"),
            revision: mneme_core::WorkspaceRevisionId::from_bytes([0xb0; 16]),
            eligibility_generation: 0,
            image_digest: "sha256:image".to_owned(),
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
        engine: &std::path::Path,
        metadata: &crate::CapabilityMetadata,
        request: &crate::PrologRequest,
        control: &WorkerControl,
        limits: WorkerLimits,
    ) -> Result<WorkerOutcome, crate::CapabilityError> {
        let _guard = spawn_guard();
        super::run_worker(engine, metadata, request, control, limits)
    }

    fn script(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
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
            head: crate::Atom {
                predicate: "path".to_owned(),
                terms: vec![crate::Term::String("a".to_owned())],
            },
            body: vec![crate::Literal::Positive(crate::Atom {
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
        looping.goal = crate::Atom {
            predicate: "loop".to_owned(),
            terms: Vec::new(),
        };
        looping.rules = vec![crate::PrologRule {
            id: "loop".to_owned(),
            version: "1".to_owned(),
            head: looping.goal.clone(),
            body: vec![crate::Literal::Positive(looping.goal.clone())],
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
