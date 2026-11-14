//! Bounded, cancellable invocation of an operator-configured JSON worker.
//!
//! The request bytes are passed unchanged on standard input; source text is
//! never placed in command arguments, environment variables, files, or logs.
//! The executable and arguments are fixed operator configuration and are
//! invoked directly, without a shell. A worker process group is killed and the
//! child is reaped before timeout, cancellation, and output-limit outcomes are
//! returned. This module does not retry or interpret model-specific schemas.

/// Maximum input size accepted by any configured invocation.
pub const MAX_INVOCATION_INPUT_BYTES: usize = 1_048_576;
/// Maximum output size retained by any configured invocation.
pub const MAX_INVOCATION_OUTPUT_BYTES: usize = 4_194_304;
/// Maximum wall time accepted by any configured invocation.
pub const MAX_INVOCATION_WALL_TIME: std::time::Duration = std::time::Duration::from_secs(300);

const MAX_COMMAND_ARGS: usize = 128;
const MAX_COMMAND_BYTES: usize = 65_536;
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(5);

/// Pinned identities for the actual model-serving invocation.
///
/// `adapter_id` and `adapter_version` identify the configured serving runtime
/// (for example, the exact llama.cpp build), not a Mneme request serializer.
/// Every digest is a canonical `sha256:<64 lowercase hex digits>` identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelDescriptor {
    pub adapter_id: String,
    pub adapter_version: String,
    pub model_id: String,
    pub model_revision: String,
    pub artifact_digest: String,
    pub tokenizer_id: String,
    pub tokenizer_digest: String,
    pub prompt_template_digest: String,
    pub output_schema_digest: String,
    pub settings_digest: String,
}

impl ModelDescriptor {
    pub(crate) fn validate(&self) -> Result<(), String> {
        for (name, value) in [
            ("runtime id", self.adapter_id.as_str()),
            ("runtime version", self.adapter_version.as_str()),
            ("model id", self.model_id.as_str()),
            ("model revision", self.model_revision.as_str()),
            ("tokenizer id", self.tokenizer_id.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{name} is required"));
            }
        }
        for (name, digest) in [
            ("model artifact", self.artifact_digest.as_str()),
            ("tokenizer", self.tokenizer_digest.as_str()),
            ("prompt template", self.prompt_template_digest.as_str()),
            ("output schema", self.output_schema_digest.as_str()),
            ("model settings", self.settings_digest.as_str()),
        ] {
            if !is_sha256(digest) {
                return Err(format!("{name} digest is not a canonical SHA-256"));
            }
        }
        Ok(())
    }
}

/// Operator-owned executable and fixed arguments for one worker.
///
/// The executable path must be absolute. `args` must not contain request or
/// source content; the caller supplies that content only as JSON on stdin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerCommand {
    pub executable: std::path::PathBuf,
    pub args: Vec<std::ffi::OsString>,
}

/// The pinned worker and model identity for an invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationConfig {
    pub descriptor: ModelDescriptor,
    pub worker: WorkerCommand,
}

impl InvocationConfig {
    /// Digest every identity that affects which model worker is executed.
    pub fn configuration_digest(&self) -> String {
        let mut digest = sha2::Sha256::new();
        use sha2::Digest as _;
        digest.update(b"mneme.inference.configuration.v1\0");
        for field in [
            self.descriptor.adapter_id.as_bytes(),
            self.descriptor.adapter_version.as_bytes(),
            self.descriptor.model_id.as_bytes(),
            self.descriptor.model_revision.as_bytes(),
            self.descriptor.artifact_digest.as_bytes(),
            self.descriptor.tokenizer_id.as_bytes(),
            self.descriptor.tokenizer_digest.as_bytes(),
            self.descriptor.prompt_template_digest.as_bytes(),
            self.descriptor.output_schema_digest.as_bytes(),
            self.descriptor.settings_digest.as_bytes(),
        ] {
            hash_field(&mut digest, field);
        }
        hash_field(
            &mut digest,
            os_str_bytes(self.worker.executable.as_os_str()),
        );
        let arg_count = canonical_u64(self.worker.args.len());
        digest.update(arg_count.to_le_bytes());
        for argument in &self.worker.args {
            hash_field(&mut digest, os_str_bytes(argument));
        }
        let finished = digest.finalize();
        format_digest(&finished)
    }

    /// Bind per-call limits to the worker/model configuration identity.
    pub fn invocation_digest(&self, limits: InvocationLimits) -> String {
        let mut digest = sha2::Sha256::new();
        use sha2::Digest as _;
        digest.update(b"mneme.inference.invocation.v1\0");
        hash_field(&mut digest, self.configuration_digest().as_bytes());
        let input_limit = canonical_u64(limits.max_input_bytes);
        let output_limit = canonical_u64(limits.max_output_bytes);
        hash_field(&mut digest, &input_limit.to_le_bytes());
        hash_field(&mut digest, &output_limit.to_le_bytes());
        hash_field(&mut digest, &limits.max_wall_time.as_nanos().to_le_bytes());
        let finished = digest.finalize();
        format_digest(&finished)
    }

    /// Validate the operator-owned worker command and pinned model identity.
    pub fn validate(&self) -> Result<(), String> {
        self.descriptor.validate()?;
        if !self.worker.executable.is_absolute() {
            return Err("worker executable must be an absolute path".to_owned());
        }
        if self.worker.args.len() > MAX_COMMAND_ARGS {
            return Err("worker argument count exceeds the configured hard limit".to_owned());
        }
        let argument_bytes = self.worker.args.iter().fold(0_usize, |total, argument| {
            total.saturating_add(os_str_bytes(argument).len())
        });
        if argument_bytes > MAX_COMMAND_BYTES {
            return Err("worker arguments exceed the configured hard byte limit".to_owned());
        }
        Ok(())
    }
}

/// Finite host-side input, output, and wall-clock limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationLimits {
    pub max_input_bytes: usize,
    pub max_output_bytes: usize,
    pub max_wall_time: std::time::Duration,
}

impl InvocationLimits {
    /// Reject limits outside the shared invocation envelope before any effects.
    pub fn validate(self) -> Result<(), String> {
        if self.max_input_bytes == 0
            || self.max_input_bytes > MAX_INVOCATION_INPUT_BYTES
            || self.max_output_bytes == 0
            || self.max_output_bytes > MAX_INVOCATION_OUTPUT_BYTES
            || self.max_wall_time.is_zero()
            || self.max_wall_time > MAX_INVOCATION_WALL_TIME
        {
            return Err("invocation limits are outside the finite hard bounds".to_owned());
        }
        Ok(())
    }
}

/// Validate the complete pinned worker configuration and finite invocation limits.
pub fn validate_invocation(
    config: &InvocationConfig,
    limits: InvocationLimits,
) -> Result<(), String> {
    config.validate()?;
    limits.validate()
}

/// Cooperative cancellation observed by the host supervisor.
#[derive(Clone, Debug, Default)]
pub struct InvocationControl {
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl InvocationControl {
    pub fn new() -> Self {
        Self::default()
    }

    /// Share a caller's cancellation flag without starting a second watcher.
    pub fn from_shared(cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>) -> Self {
        InvocationControl { cancelled }
    }

    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Clone the cancellation flag for sibling bounded workers.
    pub fn shared_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.cancelled)
    }
}

/// A token count supplied by the configured inference endpoint.
///
/// A missing component remains `None`; it is never silently treated as zero.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TokenUsage {
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

/// Whether the endpoint supplied token-usage telemetry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsageTelemetry {
    Measured(TokenUsage),
    Unavailable,
}

/// Host-supervised result of one invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InvocationStatus {
    Complete,
    Timeout,
    Cancelled,
    Unavailable,
    Failed,
    Oversized,
    Malformed,
}

/// One bounded invocation outcome with content-free provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvocationOutcome {
    pub status: InvocationStatus,
    /// Exact serialized JSON request bytes handed to the invocation path.
    pub input_bytes: usize,
    /// Present only for complete, syntactically valid JSON output.
    pub output: Option<Vec<u8>>,
    /// Exact output bytes observed when the worker completed output capture.
    /// `None` means the child failed before an exact count was available.
    pub observed_output_bytes: Option<usize>,
    /// Digest of the exact fully captured worker stdout, before model parsing.
    pub observed_output_digest: Option<String>,
    /// Host-measured monotonic wall time, including process cleanup.
    pub elapsed: std::time::Duration,
    pub usage: UsageTelemetry,
    pub input_digest: String,
    pub configuration_digest: String,
    /// The model identifier returned by an OpenAI-compatible JSON response.
    pub reported_model: Option<String>,
    /// Content-free reason for a non-complete result.
    pub detail: Option<String>,
}

/// Invoke one JSON worker with exact bounded input and supervised termination.
///
/// `input` is moved into the stdin writer thread, so the source request is not
/// duplicated or serialized to a file. The worker inherits no environment and
/// no implicit shell. There are no retries. Only successful JSON output is
/// exposed; timeout, cancellation, launch failure, malformed output, and
/// oversized output have no payload a caller could accidentally commit.
#[allow(unknown_lints, ambient_clock)] // the host shell enforces the actual monotonic deadline
pub fn invoke_json(
    config: &InvocationConfig,
    input: Vec<u8>,
    limits: InvocationLimits,
    control: &InvocationControl,
) -> InvocationOutcome {
    let started = std::time::Instant::now();
    let input_bytes = input.len();
    let request_digest = input_digest(&input);
    let configuration_digest = config.invocation_digest(limits);
    let mut metadata = OutcomeMetadata {
        started,
        input_bytes,
        input_digest: request_digest,
        configuration_digest,
    };
    if let Some(failure) = preflight_failure(config, &input, limits, control) {
        return metadata.finish(
            failure.status,
            None,
            UsageTelemetry::Unavailable,
            None,
            Some(failure.detail),
        );
    }
    let child = match spawn_worker(config) {
        Ok(child) => child,
        Err(failure) => {
            return metadata.finish(
                failure.status,
                None,
                UsageTelemetry::Unavailable,
                None,
                Some(failure.detail),
            );
        }
    };
    let execution = supervise_worker(child, input, limits, control, started);
    finish_execution(&mut metadata, execution)
}

struct InvocationFailure {
    status: InvocationStatus,
    detail: String,
}

fn preflight_failure(
    config: &InvocationConfig,
    input: &[u8],
    limits: InvocationLimits,
    control: &InvocationControl,
) -> Option<InvocationFailure> {
    if let Err(detail) = limits.validate().and_then(|()| config.validate()) {
        return Some(InvocationFailure {
            status: InvocationStatus::Failed,
            detail,
        });
    }
    if control.is_cancelled() {
        return Some(InvocationFailure {
            status: InvocationStatus::Cancelled,
            detail: "cancelled before worker start".to_owned(),
        });
    }
    if input.len() > limits.max_input_bytes {
        return Some(InvocationFailure {
            status: InvocationStatus::Oversized,
            detail: "JSON input exceeds its configured byte limit".to_owned(),
        });
    }
    if serde_json::from_slice::<serde_json::Value>(input).is_err() {
        return Some(InvocationFailure {
            status: InvocationStatus::Malformed,
            detail: "invocation input is not valid JSON".to_owned(),
        });
    }
    None
}

fn spawn_worker(config: &InvocationConfig) -> Result<std::process::Child, InvocationFailure> {
    let mut command = std::process::Command::new(&config.worker.executable);
    command
        .args(&config.worker.args)
        .env_clear()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        command.current_dir("/");
        std::os::unix::process::CommandExt::process_group(&mut command, 0);
    }
    command.spawn().map_err(|error| {
        let (status, detail) = if error.kind() == std::io::ErrorKind::NotFound {
            (
                InvocationStatus::Unavailable,
                "configured inference worker is unavailable",
            )
        } else {
            (
                InvocationStatus::Failed,
                "configured inference worker could not be started",
            )
        };
        InvocationFailure {
            status,
            detail: detail.to_owned(),
        }
    })
}

fn finish_execution(
    metadata: &mut OutcomeMetadata,
    execution: WorkerExecution,
) -> InvocationOutcome {
    match execution.status {
        InvocationStatus::Complete => {
            let Some(output) = execution.output else {
                return metadata.finish_with_observed_bytes(OutcomeCompletion {
                    status: InvocationStatus::Failed,
                    output: None,
                    usage: UsageTelemetry::Unavailable,
                    reported_model: None,
                    detail: Some("worker output was not captured completely".to_owned()),
                    observed_output_bytes: execution.observed_output_bytes,
                    observed_output_digest: None,
                });
            };
            match serde_json::from_slice::<serde_json::Value>(&output) {
                Ok(value) => {
                    let reported_model = value
                        .get("model")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned);
                    let usage = parse_usage(&value);
                    metadata.finish(
                        InvocationStatus::Complete,
                        Some(output),
                        usage,
                        reported_model,
                        None,
                    )
                }
                Err(_) => metadata.finish_with_observed_bytes(OutcomeCompletion {
                    status: InvocationStatus::Malformed,
                    output: None,
                    usage: UsageTelemetry::Unavailable,
                    reported_model: None,
                    detail: Some("inference worker returned non-JSON output".to_owned()),
                    observed_output_bytes: Some(output.len()),
                    observed_output_digest: Some(input_digest(&output)),
                }),
            }
        }
        status => metadata.finish_with_observed_bytes(OutcomeCompletion {
            status,
            output: None,
            usage: UsageTelemetry::Unavailable,
            reported_model: None,
            detail: execution.detail,
            observed_output_bytes: execution.observed_output_bytes,
            observed_output_digest: None,
        }),
    }
}

struct OutcomeMetadata {
    started: std::time::Instant,
    input_bytes: usize,
    input_digest: String,
    configuration_digest: String,
}

impl OutcomeMetadata {
    fn finish(
        &mut self,
        status: InvocationStatus,
        output: Option<Vec<u8>>,
        usage: UsageTelemetry,
        reported_model: Option<String>,
        detail: Option<String>,
    ) -> InvocationOutcome {
        let observed_output_bytes = output.as_ref().map(Vec::len);
        let observed_output_digest = output.as_ref().map(|bytes| input_digest(bytes));
        self.finish_with_observed_bytes(OutcomeCompletion {
            status,
            output,
            usage,
            reported_model,
            detail,
            observed_output_bytes,
            observed_output_digest,
        })
    }

    #[allow(unknown_lints, ambient_clock)] // elapsed duration belongs to the bounded worker-shell telemetry receipt
    fn finish_with_observed_bytes(&mut self, completion: OutcomeCompletion) -> InvocationOutcome {
        let OutcomeCompletion {
            status,
            output,
            usage,
            reported_model,
            detail,
            observed_output_bytes,
            observed_output_digest,
        } = completion;
        InvocationOutcome {
            status,
            input_bytes: self.input_bytes,
            output,
            observed_output_bytes,
            observed_output_digest,
            elapsed: self.started.elapsed(),
            usage,
            input_digest: std::mem::take(&mut self.input_digest),
            configuration_digest: std::mem::take(&mut self.configuration_digest),
            reported_model,
            detail,
        }
    }
}

struct OutcomeCompletion {
    status: InvocationStatus,
    output: Option<Vec<u8>>,
    usage: UsageTelemetry,
    reported_model: Option<String>,
    detail: Option<String>,
    observed_output_bytes: Option<usize>,
    observed_output_digest: Option<String>,
}

struct WorkerExecution {
    status: InvocationStatus,
    output: Option<Vec<u8>>,
    observed_output_bytes: Option<usize>,
    detail: Option<String>,
}

enum CapturedOutput {
    Complete(Vec<u8>),
    Oversized,
    Failed,
}

struct WorkerIo {
    writer: std::thread::JoinHandle<bool>,
    reader: std::thread::JoinHandle<bool>,
    output_receiver: std::sync::mpsc::Receiver<CapturedOutput>,
}

fn start_worker_io(
    child: &mut std::process::Child,
    input: Vec<u8>,
    output_limit: usize,
) -> Result<WorkerIo, WorkerExecution> {
    let Some(stdin) = child.stdin.take() else {
        return Err(terminate_after_start_failure(
            child,
            "worker stdin was unavailable",
        ));
    };
    let Some(stdout) = child.stdout.take() else {
        return Err(terminate_after_start_failure(
            child,
            "worker stdout was unavailable",
        ));
    };
    let (output_sender, output_receiver) = std::sync::mpsc::sync_channel(1);
    let reader = match std::thread::Builder::new()
        .name("mneme-inference-output".to_owned())
        .spawn(move || {
            let captured = capture_output(stdout, output_limit);
            output_sender.send(captured).is_ok()
        }) {
        Ok(thread) => thread,
        Err(_) => {
            return Err(terminate_after_start_failure(
                child,
                "cannot start bounded output reader",
            ));
        }
    };
    let writer = match std::thread::Builder::new()
        .name("mneme-inference-input".to_owned())
        .spawn(move || write_input(stdin, &input))
    {
        Ok(thread) => thread,
        Err(_) => {
            let cleanup = terminate_worker(child);
            let is_output_sent = matches!(reader.join(), Ok(true));
            return Err(match cleanup {
                Err(detail) => WorkerExecution::failed(&detail),
                Ok(()) if is_output_sent => {
                    WorkerExecution::failed("cannot start bounded input writer")
                }
                Ok(()) => WorkerExecution::failed("bounded output reader stopped unexpectedly"),
            });
        }
    };
    Ok(WorkerIo {
        writer,
        reader,
        output_receiver,
    })
}

fn terminate_after_start_failure(child: &mut std::process::Child, detail: &str) -> WorkerExecution {
    match terminate_worker(child) {
        Ok(()) => WorkerExecution::failed(detail),
        Err(cleanup_error) => WorkerExecution::failed(&cleanup_error),
    }
}

/// Start concurrent bounded pipe handling, then supervise the worker process.
#[allow(unknown_lints, ambient_clock)] // one loop owns the monotonic worker deadline
fn supervise_worker(
    mut child: std::process::Child,
    input: Vec<u8>,
    limits: InvocationLimits,
    control: &InvocationControl,
    started: std::time::Instant,
) -> WorkerExecution {
    let io = match start_worker_io(&mut child, input, limits.max_output_bytes) {
        Ok(io) => io,
        Err(failure) => return failure,
    };
    let deadline = started + limits.max_wall_time;
    let mut captured = None;
    loop {
        if control.is_cancelled() {
            return terminate_with_status(
                &mut child,
                io,
                InvocationStatus::Cancelled,
                "worker cancelled and reaped",
            );
        }
        if let Some(failure) = poll_worker_output(&io, &mut captured) {
            return terminate_and_collect(&mut child, io, failure);
        }
        match child.try_wait() {
            Ok(Some(exit)) => {
                return classify_worker_exit(&mut child, io, exit, captured);
            }
            Ok(None) => {}
            Err(_) => {
                return terminate_and_collect(
                    &mut child,
                    io,
                    WorkerExecution::failed("worker status could not be observed"),
                );
            }
        }
        if std::time::Instant::now() >= deadline {
            return terminate_with_status(
                &mut child,
                io,
                InvocationStatus::Timeout,
                "worker exceeded its monotonic wall-time limit and was reaped",
            );
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn poll_worker_output(
    io: &WorkerIo,
    captured: &mut Option<CapturedOutput>,
) -> Option<WorkerExecution> {
    if captured.is_some() {
        return None;
    }
    match io.output_receiver.try_recv() {
        Ok(CapturedOutput::Oversized) => Some(WorkerExecution {
            status: InvocationStatus::Oversized,
            output: None,
            observed_output_bytes: None,
            detail: Some("worker output exceeded its configured byte limit".to_owned()),
        }),
        Ok(CapturedOutput::Failed) => {
            Some(WorkerExecution::failed("worker output could not be read"))
        }
        Ok(output) => {
            *captured = Some(output);
            None
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => None,
        Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(WorkerExecution::failed(
            "worker output reader stopped unexpectedly",
        )),
    }
}

fn classify_worker_exit(
    child: &mut std::process::Child,
    io: WorkerIo,
    exit: std::process::ExitStatus,
    captured: Option<CapturedOutput>,
) -> WorkerExecution {
    let is_process_group_terminated = kill_process_group(child.id());
    let joined = collect_worker_threads(io);
    if is_process_group_terminated {
        classify_exit(exit, captured, joined)
    } else {
        WorkerExecution::failed("worker process group could not be terminated")
    }
}

fn terminate_with_status(
    child: &mut std::process::Child,
    io: WorkerIo,
    status: InvocationStatus,
    detail: &str,
) -> WorkerExecution {
    terminate_and_collect(
        child,
        io,
        WorkerExecution {
            status,
            output: None,
            observed_output_bytes: None,
            detail: Some(detail.to_owned()),
        },
    )
}

fn terminate_and_collect(
    child: &mut std::process::Child,
    io: WorkerIo,
    expected: WorkerExecution,
) -> WorkerExecution {
    let termination = terminate_worker(child);
    collect_worker_threads(io);
    match termination {
        Ok(()) => expected,
        Err(detail) => WorkerExecution::failed(&detail),
    }
}

impl WorkerExecution {
    fn failed(detail: &str) -> Self {
        WorkerExecution {
            status: InvocationStatus::Failed,
            output: None,
            observed_output_bytes: None,
            detail: Some(detail.to_owned()),
        }
    }
}

/// Result of both I/O helpers after joining them.
struct WorkerThreads {
    is_input_written: bool,
    is_output_sent: bool,
    output: Option<CapturedOutput>,
}

fn collect_worker_threads(io: WorkerIo) -> WorkerThreads {
    let is_input_written = matches!(io.writer.join(), Ok(true));
    let is_output_sent = matches!(io.reader.join(), Ok(true));
    let output = io.output_receiver.try_recv().ok();
    WorkerThreads {
        is_input_written,
        is_output_sent,
        output,
    }
}

fn classify_exit(
    exit: std::process::ExitStatus,
    captured: Option<CapturedOutput>,
    threads: WorkerThreads,
) -> WorkerExecution {
    let captured = captured.or(threads.output);
    if matches!(&captured, Some(CapturedOutput::Oversized)) {
        return WorkerExecution {
            status: InvocationStatus::Oversized,
            output: None,
            observed_output_bytes: None,
            detail: Some("worker output exceeded its configured byte limit".to_owned()),
        };
    }
    if !exit.success() || !threads.is_input_written || !threads.is_output_sent {
        let observed_output_bytes = match &captured {
            Some(CapturedOutput::Complete(output)) => Some(output.len()),
            Some(CapturedOutput::Oversized | CapturedOutput::Failed) | None => None,
        };
        let mut failed =
            WorkerExecution::failed("worker exited unsuccessfully or did not consume its input");
        failed.observed_output_bytes = observed_output_bytes;
        return failed;
    }
    match captured {
        Some(CapturedOutput::Complete(output)) => WorkerExecution {
            status: InvocationStatus::Complete,
            observed_output_bytes: Some(output.len()),
            output: Some(output),
            detail: None,
        },
        Some(CapturedOutput::Failed) | None => {
            WorkerExecution::failed("worker output was not captured completely")
        }
        Some(CapturedOutput::Oversized) => WorkerExecution {
            status: InvocationStatus::Oversized,
            output: None,
            observed_output_bytes: None,
            detail: Some("worker output exceeded its configured byte limit".to_owned()),
        },
    }
}

fn write_input(mut stdin: std::process::ChildStdin, input: &[u8]) -> bool {
    use std::io::Write as _;
    stdin.write_all(input).is_ok()
}

fn capture_output(mut stdout: std::process::ChildStdout, limit: usize) -> CapturedOutput {
    use std::io::Read as _;
    let mut output = Vec::with_capacity(limit.min(8_192));
    let mut chunk = [0_u8; 8_192];
    loop {
        match stdout.read(&mut chunk) {
            Ok(0) => return CapturedOutput::Complete(output),
            Ok(bytes) if bytes > limit.saturating_sub(output.len()) => {
                return CapturedOutput::Oversized;
            }
            Ok(bytes) => output.extend_from_slice(&chunk[..bytes]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return CapturedOutput::Failed,
        }
    }
}

/// Kill the worker's process group and reap its direct child.
fn terminate_worker(child: &mut std::process::Child) -> Result<(), String> {
    let is_process_group_terminated = kill_process_group(child.id());
    let killed = child.kill();
    let reaped = child.wait();
    match (is_process_group_terminated, killed, reaped) {
        (true, _, Ok(_)) => Ok(()),
        (false, _, Ok(_)) => Err("worker process group could not be terminated".to_owned()),
        (_, Ok(()), Err(error)) => Err(format!("worker could not be reaped: {error}")),
        (_, Err(kill_error), Err(wait_error)) => Err(format!(
            "worker kill failed ({kill_error}) and reaping failed ({wait_error})"
        )),
    }
}

#[cfg(unix)]
fn kill_process_group(pid: u32) -> bool {
    let Some(group) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    match rustix::process::kill_process_group(group, rustix::process::Signal::KILL) {
        Ok(()) => true,
        Err(error) => error == rustix::io::Errno::SRCH,
    }
}

#[cfg(not(unix))]
fn kill_process_group(_pid: u32) -> bool {
    true
}

fn parse_usage(value: &serde_json::Value) -> UsageTelemetry {
    let usage = value.get("usage").unwrap_or(value);
    let tokens = TokenUsage {
        prompt_tokens: usage
            .get("prompt_tokens")
            .and_then(serde_json::Value::as_u64),
        completion_tokens: usage
            .get("completion_tokens")
            .and_then(serde_json::Value::as_u64),
        total_tokens: usage
            .get("total_tokens")
            .and_then(serde_json::Value::as_u64),
    };
    if tokens.prompt_tokens.is_some()
        || tokens.completion_tokens.is_some()
        || tokens.total_tokens.is_some()
    {
        UsageTelemetry::Measured(tokens)
    } else {
        UsageTelemetry::Unavailable
    }
}

fn is_sha256(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let finished = sha2::Sha256::digest(bytes);
    format_digest(&finished)
}

/// Compute the canonical digest used for reservation before dispatch.
pub fn input_digest(bytes: &[u8]) -> String {
    sha256(bytes)
}

#[allow(unknown_lints, unchecked_narrowing)] // canonical wire lengths are u64 and supported targets have at most 64-bit usize
fn canonical_u64(value: usize) -> u64 {
    value as u64
}

fn hash_field(digest: &mut sha2::Sha256, value: &[u8]) {
    use sha2::Digest as _;
    let length = canonical_u64(value.len());
    digest.update(length.to_le_bytes());
    digest.update(value);
}

fn format_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity("sha256:".len() + bytes.len().saturating_mul(2));
    text.push_str("sha256:");
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

#[cfg(unix)]
fn os_str_bytes(value: &std::ffi::OsStr) -> &[u8] {
    use std::os::unix::ffi::OsStrExt as _;
    value.as_bytes()
}

#[cfg(not(unix))]
fn os_str_bytes(value: &std::ffi::OsStr) -> &[u8] {
    value.to_str().unwrap_or("").as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> ModelDescriptor {
        ModelDescriptor {
            adapter_id: "test-runtime".to_owned(),
            adapter_version: "v1".to_owned(),
            model_id: "test-model".to_owned(),
            model_revision: "revision-1".to_owned(),
            artifact_digest: format!("sha256:{}", "1".repeat(64)),
            tokenizer_id: "test-tokenizer".to_owned(),
            tokenizer_digest: format!("sha256:{}", "2".repeat(64)),
            prompt_template_digest: format!("sha256:{}", "3".repeat(64)),
            output_schema_digest: format!("sha256:{}", "4".repeat(64)),
            settings_digest: format!("sha256:{}", "5".repeat(64)),
        }
    }

    fn command(executable: &str, args: &[&str]) -> InvocationConfig {
        let executable = match executable.strip_prefix("/usr/bin/") {
            Some(program) => std::env::var_os("PATH")
                .and_then(|path| {
                    std::env::split_paths(&path)
                        .map(|directory| directory.join(program))
                        .find(|path| path.is_file())
                })
                .unwrap_or_else(|| std::path::PathBuf::from(executable)),
            None => std::path::PathBuf::from(executable),
        };
        InvocationConfig {
            descriptor: descriptor(),
            worker: WorkerCommand {
                executable,
                args: args.iter().map(std::ffi::OsString::from).collect(),
            },
        }
    }

    fn limits() -> InvocationLimits {
        InvocationLimits {
            max_input_bytes: 1_024,
            max_output_bytes: 1_024,
            max_wall_time: std::time::Duration::from_secs(1),
        }
    }

    #[test]
    fn complete_worker_without_captured_output_fails_closed() {
        let mut metadata = OutcomeMetadata {
            started: std::time::Instant::now(),
            input_bytes: 2,
            input_digest: input_digest(b"{}"),
            configuration_digest: format!("sha256:{}", "c".repeat(64)),
        };
        let outcome = finish_execution(
            &mut metadata,
            WorkerExecution {
                status: InvocationStatus::Complete,
                output: None,
                observed_output_bytes: Some(0),
                detail: None,
            },
        );
        assert_eq!(outcome.status, InvocationStatus::Failed);
        assert!(outcome.output.is_none());
        assert_eq!(outcome.observed_output_bytes, Some(0));
        assert!(outcome.observed_output_digest.is_none());
        assert_eq!(outcome.usage, UsageTelemetry::Unavailable);
        assert_eq!(
            outcome.detail.as_deref(),
            Some("worker output was not captured completely")
        );
    }

    #[test]
    fn worker_output_is_bounded_json_with_measured_usage_and_identity() {
        let input = br#"{"model":"reported-model","usage":{"prompt_tokens":4,"completion_tokens":3,"total_tokens":7}}"#.to_vec();
        let config = command("/usr/bin/cat", &[]);
        let limits = limits();
        let outcome = invoke_json(&config, input.clone(), limits, &InvocationControl::new());
        assert_eq!(outcome.status, InvocationStatus::Complete);
        assert_eq!(outcome.output.as_deref(), Some(input.as_slice()));
        assert_eq!(outcome.input_bytes, input.len());
        assert_eq!(
            outcome.configuration_digest,
            config.invocation_digest(limits)
        );
        assert_eq!(outcome.reported_model.as_deref(), Some("reported-model"));
        assert_eq!(
            outcome.usage,
            UsageTelemetry::Measured(TokenUsage {
                prompt_tokens: Some(4),
                completion_tokens: Some(3),
                total_tokens: Some(7),
            })
        );
        assert_ne!(outcome.input_digest, outcome.configuration_digest);
        assert!(!outcome.elapsed.is_zero());
    }

    #[test]
    fn invocation_identity_changes_when_any_worker_limit_changes() {
        let config = command("/usr/bin/cat", &[]);
        let limits = limits();
        let digest = config.invocation_digest(limits);
        let changed = InvocationLimits {
            max_wall_time: std::time::Duration::from_millis(999),
            ..limits
        };
        assert_ne!(digest, config.invocation_digest(changed));
    }

    #[test]
    fn worker_reports_unavailable_when_the_operator_command_is_missing() {
        let outcome = invoke_json(
            &command("/definitely/not/a/model-worker", &[]),
            b"{}".to_vec(),
            limits(),
            &InvocationControl::new(),
        );
        assert_eq!(outcome.status, InvocationStatus::Unavailable);
        assert!(outcome.output.is_none());
        assert_eq!(outcome.usage, UsageTelemetry::Unavailable);
    }

    #[test]
    fn output_limit_terminates_a_worker_without_returning_partial_json() {
        let mut limits = limits();
        limits.max_output_bytes = 64;
        let outcome = invoke_json(
            &command("/usr/bin/yes", &["x"]),
            b"{}".to_vec(),
            limits,
            &InvocationControl::new(),
        );
        assert_eq!(outcome.status, InvocationStatus::Oversized);
        assert!(outcome.output.is_none());
    }

    #[test]
    fn timeout_kills_worker_and_next_worker_remains_usable() {
        let mut limits = limits();
        limits.max_wall_time = std::time::Duration::from_millis(20);
        let timeout = invoke_json(
            &command("/usr/bin/sleep", &["2"]),
            b"{}".to_vec(),
            limits,
            &InvocationControl::new(),
        );
        assert_eq!(timeout.status, InvocationStatus::Timeout);
        let next = invoke_json(
            &command("/usr/bin/cat", &[]),
            b"{}".to_vec(),
            self::limits(),
            &InvocationControl::new(),
        );
        assert_eq!(next.status, InvocationStatus::Complete);
    }

    #[test]
    fn cancellation_kills_worker_and_discards_late_output() {
        let control = InvocationControl::new();
        let worker_control = control.clone();
        let worker = std::thread::spawn(move || {
            invoke_json(
                &command("/usr/bin/sleep", &["2"]),
                b"{}".to_vec(),
                limits(),
                &worker_control,
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        control.cancel();
        let outcome = worker.join().expect("worker join");
        assert_eq!(outcome.status, InvocationStatus::Cancelled);
        assert!(outcome.output.is_none());
    }

    #[test]
    fn non_json_worker_output_is_malformed_and_not_exposed() {
        let outcome = invoke_json(
            &command("/usr/bin/printf", &["not-json"]),
            b"{}".to_vec(),
            limits(),
            &InvocationControl::new(),
        );
        assert_eq!(outcome.status, InvocationStatus::Malformed);
        assert!(outcome.output.is_none());
    }
}
