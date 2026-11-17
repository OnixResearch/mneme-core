//! Running a job: claim it, plan or resume it, dispatch units and publish.

/// Whether a run continues with the next unit.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Flow {
    Continue,
    Stop,
}

/// How one dispatched unit ended.
struct Settled {
    state: super::UnitState,
    run: Option<mneme_core::RecordId>,
    detail: Option<String>,
    flow: Flow,
}

impl Settled {
    fn new(state: super::UnitState, detail: Option<&str>, flow: Flow) -> Self {
        Settled {
            state,
            run: None,
            detail: detail.map(str::to_owned),
            flow,
        }
    }
}

/// Plan a job over its committed capture and save its progress, without
/// running anything. The capture needs no recognizer to exist; a queued job
/// can run later.
pub fn queue(
    workspace: &mut mneme_store::Workspace,
    job: &super::Job,
) -> Result<super::Report, super::Failure> {
    Ok(Claimed::open(workspace, job)?.progress.report())
}

/// Dispatch a job's pending units until they are done, the run's time runs
/// out, the recognizer is unavailable, the capture can no longer be read, or
/// `control` cancels the run.
pub fn run(
    workspace: &mut mneme_store::Workspace,
    job: &super::Job,
    control: &mneme_recall::inference::InvocationControl,
) -> Result<super::Report, super::Failure> {
    let mut session = Claimed::open(workspace, job)?;
    session.run(control)?;
    Ok(session.progress.report())
}

/// Return units that ended without publication, and have attempts left, to
/// pending. Attempts and charges are kept: a retry is a new, charged attempt,
/// not a claim that the earlier one never ran.
pub fn retry(
    workspace: &mut mneme_store::Workspace,
    job: &super::Job,
) -> Result<super::Report, super::Failure> {
    let mut session = Claimed::open(workspace, job)?;
    let max_attempts = job.limits.max_attempts_per_unit;
    for unit in &mut session.progress.units {
        if unit.state.is_retryable() && unit.attempts < max_attempts {
            unit.state = super::UnitState::Pending;
            unit.detail = None;
        }
    }
    session.save()?;
    Ok(session.progress.report())
}

/// A job's saved progress, read without claiming the job, or `None` when the
/// job was never queued.
pub fn status(
    workspace: &mneme_store::Workspace,
    job: &super::Job,
) -> Result<Option<super::Report>, super::Failure> {
    job.validate()?;
    let identity = super::plan::JobIdentity::of(job);
    let Some(bytes) = workspace
        .job_progress(&identity.claim)
        .map_err(|error| super::Failure::Store(error.to_string()))?
    else {
        return Ok(None);
    };
    let progress = super::durable::Progress::decode(&bytes)?;
    if progress.definition != identity.definition {
        return Err(different_definition());
    }
    Ok(Some(progress.report()))
}

fn different_definition() -> super::Failure {
    super::Failure::Invalid("this job id already names a different recognition job".to_owned())
}

/// A claimed job and its progress. Only the claim's holder saves progress.
struct Claimed<'w> {
    workspace: &'w mut mneme_store::Workspace,
    job: &'w super::Job,
    identity: super::plan::JobIdentity,
    claim: mneme_store::JobClaim,
    progress: super::durable::Progress,
}

impl<'w> Claimed<'w> {
    /// Claim the job, load or plan its progress, and settle units a stopped
    /// runner left dispatched.
    fn open(
        workspace: &'w mut mneme_store::Workspace,
        job: &'w super::Job,
    ) -> Result<Self, super::Failure> {
        job.validate()?;
        let identity = super::plan::JobIdentity::of(job);
        // Progress lives beside the claim, so the job is its own destination.
        let claim = workspace
            .claim_job(&identity.claim, &identity.claim)
            .map_err(|error| match error {
                mneme_store::Failure::JobBusy | mneme_store::Failure::JobBound => {
                    super::Failure::Busy(error.to_string())
                }
                other => super::Failure::Store(other.to_string()),
            })?;
        let saved = claim
            .load_progress()
            .map_err(|error| super::Failure::Store(error.to_string()))?;
        let progress = match saved {
            Some(bytes) => {
                let progress = super::durable::Progress::decode(&bytes)?;
                if progress.definition != identity.definition {
                    return Err(different_definition());
                }
                progress
            }
            None => plan(workspace, job, &identity)?,
        };
        let mut session = Claimed {
            workspace,
            job,
            identity,
            claim,
            progress,
        };
        session.settle_interrupted()?;
        session.save()?;
        Ok(session)
    }

    fn save(&self) -> Result<(), super::Failure> {
        let bytes = self.progress.encode()?;
        self.claim
            .save_progress(&bytes)
            .map_err(|error| super::Failure::Store(error.to_string()))
    }

    fn attempt(&self, index: usize) -> Result<super::publication::UnitAttempt<'_>, super::Failure> {
        let unit = u32::try_from(index)
            .map_err(|_| super::Failure::Invalid("unit index out of range".to_owned()))?;
        Ok(super::publication::UnitAttempt {
            identity: &self.identity,
            unit,
            attempt: self.progress.units[index].attempts,
        })
    }

    /// A unit left dispatched was published if its run is committed, and is
    /// otherwise uncertain: it is never dispatched again automatically.
    fn settle_interrupted(&mut self) -> Result<(), super::Failure> {
        for index in 0..self.progress.units.len() {
            if self.progress.units[index].state != super::UnitState::Dispatched {
                continue;
            }
            let run = self.attempt(index)?.run();
            let is_committed = super::publication::is_committed(self.workspace, self.job, run)?;
            let unit = &mut self.progress.units[index];
            if is_committed {
                unit.state = super::UnitState::Published;
                unit.run = Some(run.to_hex());
                unit.detail = None;
            } else {
                unit.state = super::UnitState::Uncertain;
                unit.detail = Some(
                    "a runner stopped after dispatching this unit; its outcome is unknown"
                        .to_owned(),
                );
            }
        }
        Ok(())
    }

    #[allow(unknown_lints, ambient_clock)] // the run's own monotonic dispatch budget
    fn run(
        &mut self,
        control: &mneme_recall::inference::InvocationControl,
    ) -> Result<(), super::Failure> {
        let started = std::time::Instant::now();
        let Some((capture, digest)) = self.readable_capture()? else {
            return self.save();
        };
        let Some(media) = self.read_media(&capture, digest)? else {
            return self.save();
        };
        for index in 0..self.progress.units.len() {
            if self.progress.units[index].state != super::UnitState::Pending {
                continue;
            }
            if control.is_cancelled() || started.elapsed() >= self.job.limits.max_run_time {
                break;
            }
            // The capture is checked again before its bytes reach each worker:
            // a capture forgotten or revised during an earlier unit is never
            // sent again.
            if let Err(reason) =
                super::publication::eligible_capture(self.workspace, self.job, digest)?
            {
                self.progress
                    .settle_pending(super::UnitState::Suppressed, &reason);
                break;
            }
            let unit = UnitRun {
                index,
                capture: &capture,
                digest,
                media: &media,
                control,
            };
            if self.dispatch(&unit)? == Flow::Stop {
                break;
            }
        }
        self.save()
    }

    /// The capture, if it is still the one planned and readable; otherwise
    /// every pending unit is suppressed.
    fn readable_capture(
        &mut self,
    ) -> Result<Option<(mneme_memory::SourceView, mneme_core::ContentDigest)>, super::Failure> {
        let current = current_digest(self.workspace, self.job)?;
        let planned = current.filter(|digest| digest.to_hex() == self.progress.media_digest);
        let Some(digest) = planned else {
            self.progress.settle_pending(
                super::UnitState::Suppressed,
                "the capture changed since the job was planned",
            );
            return Ok(None);
        };
        match super::publication::eligible_capture(self.workspace, self.job, digest)? {
            Ok(eligible) => Ok(Some((eligible.capture, digest))),
            Err(reason) => {
                self.progress
                    .settle_pending(super::UnitState::Suppressed, &reason);
                Ok(None)
            }
        }
    }

    /// The capture's bytes, shared by every unit, or `None` when they exceed
    /// a unit's media bound: a truthful capability outcome for every unit.
    fn read_media(
        &mut self,
        capture: &mneme_memory::SourceView,
        digest: mneme_core::ContentDigest,
    ) -> Result<Option<std::sync::Arc<[u8]>>, super::Failure> {
        let length = match &capture.content {
            mneme_core::SourceContent::Retained(retained) => retained.byte_length(),
            mneme_core::SourceContent::Unavailable { .. } => u64::MAX,
        };
        let limit = self.job.limits.unit.max_media_bytes;
        if !usize::try_from(length).is_ok_and(|length| length <= limit) {
            self.progress.settle_pending(
                super::UnitState::Unsupported,
                "the capture exceeds the unit's media byte limit",
            );
            return Ok(None);
        }
        let bytes = mneme_store::payload::read(self.workspace.root(), digest)
            .map_err(|error| super::Failure::Store(error.to_string()))?;
        Ok(Some(std::sync::Arc::from(bytes)))
    }
}

/// One unit to dispatch and what it is dispatched against.
struct UnitRun<'a> {
    index: usize,
    capture: &'a mneme_memory::SourceView,
    digest: mneme_core::ContentDigest,
    media: &'a std::sync::Arc<[u8]>,
    control: &'a mneme_recall::inference::InvocationControl,
}

impl Claimed<'_> {
    /// Reserve one unit durably, run its worker on the capture, and settle the
    /// outcome; the progress is saved before and after the worker runs.
    fn dispatch(&mut self, unit: &UnitRun<'_>) -> Result<Flow, super::Failure> {
        let selector = self.progress.units[unit.index].selector;
        if self.progress.units[unit.index].attempts >= self.job.limits.max_attempts_per_unit {
            let settled = Settled::new(
                super::UnitState::Failed,
                Some("the unit used all its attempts"),
                Flow::Continue,
            );
            self.record(unit.index, settled);
            return Ok(Flow::Continue);
        }
        let header = super::plan::header(
            (unit.index, self.progress.units.len()),
            selector,
            unit.capture,
            unit.media.len(),
        )?;
        let input = header
            .len()
            .saturating_add(1)
            .saturating_add(unit.media.len());
        self.reserve(unit.index, input)?;
        let outcome = mneme_recall::inference::invoke_media(
            mneme_recall::inference::MediaInvocation {
                worker: &self.job.recognizer.worker,
                configuration_digest: self.identity.definition.clone(),
                header,
                media: std::sync::Arc::clone(unit.media),
                limits: self.job.limits.unit,
            },
            unit.control,
        );
        self.charge_outcome(&outcome)?;
        if outcome.status == mneme_recall::inference::InvocationStatus::Unavailable {
            // Nothing ran, so nothing was published under this attempt: the
            // attempt is given back and only the invocation stays charged.
            let reserved = &mut self.progress.units[unit.index];
            reserved.attempts = reserved.attempts.saturating_sub(1);
        }
        let settled = self.settle(unit, selector, &outcome)?;
        let flow = settled.flow;
        self.record(unit.index, settled);
        self.save()?;
        Ok(flow)
    }

    /// Mark a unit dispatched and charge its attempt and input before its
    /// worker starts. The reservation is saved, so it outlives the runner.
    fn reserve(&mut self, index: usize, input_bytes: usize) -> Result<(), super::Failure> {
        let unit = &mut self.progress.units[index];
        unit.attempts = unit.attempts.saturating_add(1);
        unit.state = super::UnitState::Dispatched;
        unit.detail = None;
        let charged = &mut self.progress.charged;
        charged.invocations = charged.invocations.saturating_add(1);
        charged.input_bytes = add_bytes(charged.input_bytes, input_bytes)?;
        self.save()
    }

    fn charge_outcome(
        &mut self,
        outcome: &mneme_recall::inference::InvocationOutcome,
    ) -> Result<(), super::Failure> {
        let charged = &mut self.progress.charged;
        charged.output_bytes = add_bytes(
            charged.output_bytes,
            outcome.observed_output_bytes.unwrap_or(0),
        )?;
        let millis = u64::try_from(outcome.elapsed.as_millis())
            .map_err(|_| super::Failure::Store("charged time is out of range".to_owned()))?;
        charged.elapsed_ms = charged.elapsed_ms.saturating_add(millis);
        Ok(())
    }

    /// Record how a unit ended. A suppressed unit means the capture can no
    /// longer be read, so every unit still pending is suppressed with it.
    fn record(&mut self, index: usize, settled: Settled) {
        if settled.state == super::UnitState::Suppressed
            && let Some(reason) = &settled.detail
        {
            self.progress
                .settle_pending(super::UnitState::Suppressed, reason);
        }
        let unit = &mut self.progress.units[index];
        unit.state = settled.state;
        unit.run = settled.run.map(mneme_core::RecordId::to_hex);
        unit.detail = settled.detail;
    }

    /// A unit's outcome: a valid answer is published, anything else is named.
    fn settle(
        &mut self,
        unit: &UnitRun<'_>,
        selector: super::UnitSelector,
        outcome: &mneme_recall::inference::InvocationOutcome,
    ) -> Result<Settled, super::Failure> {
        let detail = outcome.detail.as_deref();
        Ok(match outcome.status {
            mneme_recall::inference::InvocationStatus::Complete => {
                return match outcome.output.as_deref() {
                    Some(output) => self.publish_answer(unit, selector, output),
                    None => Ok(Settled::new(
                        super::UnitState::Failed,
                        Some("the worker's answer was not captured"),
                        Flow::Continue,
                    )),
                };
            }
            mneme_recall::inference::InvocationStatus::Timeout => {
                Settled::new(super::UnitState::Timeout, detail, Flow::Continue)
            }
            mneme_recall::inference::InvocationStatus::Cancelled => {
                Settled::new(super::UnitState::Cancelled, detail, Flow::Stop)
            }
            // Nothing ran: the unit waits for a run with a recognizer.
            mneme_recall::inference::InvocationStatus::Unavailable => Settled::new(
                super::UnitState::Pending,
                Some("the recognizer is unavailable"),
                Flow::Stop,
            ),
            mneme_recall::inference::InvocationStatus::Failed => {
                Settled::new(super::UnitState::Failed, detail, Flow::Continue)
            }
            mneme_recall::inference::InvocationStatus::Oversized => Settled::new(
                super::UnitState::Rejected,
                Some("the answer exceeded the unit's output bound"),
                Flow::Continue,
            ),
            mneme_recall::inference::InvocationStatus::Malformed => Settled::new(
                super::UnitState::Rejected,
                Some("the answer was not JSON"),
                Flow::Continue,
            ),
        })
    }

    fn publish_answer(
        &mut self,
        unit: &UnitRun<'_>,
        selector: super::UnitSelector,
        output: &[u8],
    ) -> Result<Settled, super::Failure> {
        let recognized = match super::protocol::parse(output, selector, unit.capture) {
            Ok(super::protocol::Answer::Recognized(recognized)) => recognized,
            Ok(super::protocol::Answer::Unsupported) => {
                return Ok(Settled::new(
                    super::UnitState::Unsupported,
                    Some("the recognizer cannot recognize this unit"),
                    Flow::Continue,
                ));
            }
            Err(reason) => {
                return Ok(Settled::new(
                    super::UnitState::Rejected,
                    Some(&reason),
                    Flow::Continue,
                ));
            }
        };
        let attempt = super::publication::UnitAttempt {
            identity: &self.identity,
            unit: u32::try_from(unit.index)
                .map_err(|_| super::Failure::Invalid("unit index out of range".to_owned()))?,
            attempt: self.progress.units[unit.index].attempts,
        };
        let publication = super::publication::publish(
            self.workspace,
            self.job,
            &attempt,
            unit.digest,
            &recognized,
        )?;
        Ok(match publication {
            super::publication::Outcome::Published(run) => Settled {
                state: super::UnitState::Published,
                run: Some(run),
                detail: None,
                flow: Flow::Continue,
            },
            super::publication::Outcome::Empty => Settled::new(
                super::UnitState::Published,
                Some("no text was recognized"),
                Flow::Continue,
            ),
            super::publication::Outcome::Rejected(reason) => {
                Settled::new(super::UnitState::Rejected, Some(&reason), Flow::Continue)
            }
            super::publication::Outcome::Suppressed(reason) => {
                Settled::new(super::UnitState::Suppressed, Some(&reason), Flow::Stop)
            }
            super::publication::Outcome::Conflicted(reason) => {
                Settled::new(super::UnitState::Failed, Some(&reason), Flow::Continue)
            }
        })
    }
}

/// Add a byte count to a charge.
fn add_bytes(total: u64, amount: usize) -> Result<u64, super::Failure> {
    u64::try_from(amount)
        .map(|amount| total.saturating_add(amount))
        .map_err(|_| super::Failure::Store("charged bytes are out of range".to_owned()))
}

/// The digest of the job's capture revision, if it has retained bytes.
fn current_digest(
    workspace: &mut mneme_store::Workspace,
    job: &super::Job,
) -> Result<Option<mneme_core::ContentDigest>, super::Failure> {
    let view = mneme_memory::Engine::new(workspace, job.access.clone())
        .view()
        .map_err(|error| super::Failure::Store(error.to_string()))?;
    Ok(view
        .source_at(job.media.source(), job.media.revision())
        .ok()
        .and_then(|capture| capture.digest()))
}

/// Divide the job's capture into units: it must be readable now.
fn plan(
    workspace: &mut mneme_store::Workspace,
    job: &super::Job,
    identity: &super::plan::JobIdentity,
) -> Result<super::durable::Progress, super::Failure> {
    let Some(digest) = current_digest(workspace, job)? else {
        return Err(super::Failure::Invalid(
            "the capture is not a visible source revision with retained bytes".to_owned(),
        ));
    };
    let capture = super::publication::eligible_capture(workspace, job, digest)?
        .map_err(super::Failure::Invalid)?
        .capture;
    let selectors = super::plan::units(job.plan, capture.media_extent, job.limits.max_units)?;
    Ok(super::durable::Progress::new(
        identity.definition.clone(),
        digest,
        selectors,
    ))
}
