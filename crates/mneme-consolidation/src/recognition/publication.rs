//! Publishing one unit's answer as a recognition run, after rechecking that
//! the capture may still be read.

/// The media type of published recognized text.
const TEXT_MEDIA_TYPE: &str = "text/plain; charset=utf-8";

/// How often publication rechecks the capture and retries when the workspace
/// moved between the check and the commit.
const PUBLISH_TRIES: u32 = 3;

/// How a unit's publication ended.
pub(super) enum Outcome {
    /// The run was committed.
    Published(mneme_core::RecordId),
    /// The answer recognized no text; nothing was committed.
    Empty,
    /// The answer did not validate against the capture.
    Rejected(String),
    /// The capture can no longer be read under the job.
    Suppressed(String),
    /// The workspace kept moving between the recheck and the commit.
    Conflicted(String),
}

/// The capture as the job may read it, and the revision it was read at.
pub(super) struct Eligible {
    pub capture: mneme_memory::SourceView,
    pub revision: mneme_core::WorkspaceRevisionId,
}

/// The capture as the job may read it now: still the current revision,
/// retained, unchanged, unsuppressed and visible under the job's access.
pub(super) fn eligible_capture(
    workspace: &mut mneme_store::Workspace,
    job: &super::Job,
    digest: mneme_core::ContentDigest,
) -> Result<Result<Eligible, String>, super::Failure> {
    let view = mneme_memory::Engine::new(workspace, job.access.clone())
        .view()
        .map_err(|error| super::Failure::Store(error.to_string()))?;
    let Ok(record) = view.record(job.media.source()) else {
        return Ok(Err("the capture is not visible to the job".to_owned()));
    };
    if record.revision_id != job.media.revision() || record.scope != job.scope {
        return Ok(Err(
            "the capture changed since the job was planned".to_owned()
        ));
    }
    if view.suppression_for(record).is_some() {
        return Ok(Err("the capture was forgotten".to_owned()));
    }
    let Ok(capture) = view.source_at(job.media.source(), job.media.revision()) else {
        return Ok(Err("the capture is not a source revision".to_owned()));
    };
    if capture.availability != mneme_memory::SourceAvailability::Retained
        || capture.digest() != Some(digest)
    {
        return Ok(Err("the capture's bytes are no longer retained".to_owned()));
    }
    Ok(Ok(Eligible {
        capture,
        revision: view.revision(),
    }))
}

/// Whether the run a unit attempt would publish is already committed: a
/// runner can stop after committing and before saving its progress.
pub(super) fn is_committed(
    workspace: &mut mneme_store::Workspace,
    job: &super::Job,
    run: mneme_core::RecordId,
) -> Result<bool, super::Failure> {
    let view = mneme_memory::Engine::new(workspace, job.access.clone())
        .view()
        .map_err(|error| super::Failure::Store(error.to_string()))?;
    Ok(view.record(run).is_ok())
}

/// The identities one unit attempt publishes under.
pub(super) struct UnitAttempt<'a> {
    pub identity: &'a super::plan::JobIdentity,
    pub unit: u32,
    pub attempt: u32,
    /// The part of the capture the unit covers, declared on its run.
    pub covers: mneme_core::CapturePart,
}

impl UnitAttempt<'_> {
    fn record(&self, role: &str, ordinal: u32) -> mneme_core::RecordId {
        mneme_core::RecordId::from_bytes(self.identity.identity(
            self.unit,
            self.attempt,
            role,
            ordinal,
        ))
    }

    fn revision(&self, role: &str, ordinal: u32) -> mneme_core::RevisionId {
        let role = format!("{role}-revision");
        mneme_core::RevisionId::from_bytes(self.identity.identity(
            self.unit,
            self.attempt,
            &role,
            ordinal,
        ))
    }

    /// The run this attempt publishes.
    pub(super) fn run(&self) -> mneme_core::RecordId {
        self.record("run", 0)
    }
}

/// Publish one unit's recognized text, rechecking the capture first.
pub(super) fn publish(
    workspace: &mut mneme_store::Workspace,
    job: &super::Job,
    attempt: &UnitAttempt<'_>,
    media_digest: mneme_core::ContentDigest,
    recognized: &super::protocol::Recognized,
) -> Result<Outcome, super::Failure> {
    if recognized.text.is_empty() && recognized.segments.is_empty() && recognized.page.is_none() {
        return Ok(Outcome::Empty);
    }
    for _ in 0..PUBLISH_TRIES {
        // The commit is made at the revision the capture was checked at, so a
        // capture revised, pruned or withdrawn since cannot slip through.
        let eligible = match eligible_capture(workspace, job, media_digest)? {
            Ok(eligible) => eligible,
            Err(reason) => return Ok(Outcome::Suppressed(reason)),
        };
        let batch = match records(job, (attempt, media_digest), recognized) {
            Ok(batch) => batch,
            Err(reason) => return Ok(Outcome::Rejected(reason)),
        };
        match mneme_memory::Engine::new(workspace, job.access.clone())
            .commit_at_base(batch, eligible.revision)
        {
            Ok(_) => return Ok(Outcome::Published(attempt.run())),
            Err(mneme_memory::EvidenceError::Store(
                mneme_store::Failure::StaleBase { .. }
                | mneme_store::Failure::BarrierAdvanced { .. },
            )) => {}
            Err(
                error @ (mneme_memory::EvidenceError::Policy(_)
                | mneme_memory::EvidenceError::Validation(_)
                | mneme_memory::EvidenceError::Invalid(_)
                | mneme_memory::EvidenceError::InvalidRecord { .. }),
            ) => return Ok(Outcome::Rejected(error.to_string())),
            Err(error) => return Err(super::Failure::Store(error.to_string())),
        }
    }
    Ok(Outcome::Conflicted(
        "the workspace kept changing while the unit was published".to_owned(),
    ))
}

/// The text, run and segment records of one unit attempt, as one batch.
fn records(
    job: &super::Job,
    (attempt, media_digest): (&UnitAttempt<'_>, mneme_core::ContentDigest),
    recognized: &super::protocol::Recognized,
) -> Result<mneme_memory::Batch, String> {
    let text = mneme_core::SourcePin::new(attempt.record("text", 0), attempt.revision("text", 0));
    let (text_record, text_blob) = mneme_memory::build_recognized_source(
        text.source(),
        text.revision(),
        &job.scope,
        mneme_memory::SourceOptions {
            bytes: recognized.text.as_bytes(),
            media_type: TEXT_MEDIA_TYPE,
            entity: None,
            path_hint: None,
        },
        job.media,
    )
    .map_err(|error| error.to_string())?;
    let segment_ids = (0..recognized.segments.len())
        .map(|ordinal| u32::try_from(ordinal).map(|ordinal| attempt.record("segment", ordinal)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "too many segments".to_owned())?;
    let mut drafts = Vec::with_capacity(segment_ids.len().saturating_add(2));
    drafts.push(text_record);
    drafts.push(run_record(
        job,
        (attempt, media_digest),
        (text, recognized),
        &segment_ids,
    )?);
    for (ordinal, (segment, id)) in recognized.segments.iter().zip(&segment_ids).enumerate() {
        let ordinal = u32::try_from(ordinal).map_err(|_| "too many segments".to_owned())?;
        drafts.push(
            mneme_memory::build_recognition_segment(
                *id,
                attempt.revision("segment", ordinal),
                &job.scope,
                mneme_memory::RecognitionSegmentOptions {
                    run: Some(attempt.run()),
                    text_source: text,
                    span: segment.span,
                    media_source: job.media,
                    media_digest,
                    location: &segment.location,
                    block: segment.block.as_ref(),
                },
            )
            .map_err(|error| error.to_string())?,
        );
    }
    Ok(mneme_memory::Batch {
        actor: job.actor.clone(),
        scope: job.scope.clone(),
        idempotency_key: format!(
            "recognition:{}:{}:{}",
            super::plan::hex(&attempt.identity.seed),
            attempt.unit,
            attempt.attempt
        ),
        records: drafts,
        source_blobs: vec![text_blob],
        publications: Vec::new(),
    })
}

fn run_record(
    job: &super::Job,
    (attempt, media_digest): (&UnitAttempt<'_>, mneme_core::ContentDigest),
    (text, recognized): (mneme_core::SourcePin, &super::protocol::Recognized),
    segments: &[mneme_core::RecordId],
) -> Result<mneme_store::RecordDraft, String> {
    let recognizer = &job.recognizer;
    mneme_memory::build_recognition_run(
        attempt.run(),
        attempt.revision("run", 0),
        &job.scope,
        mneme_memory::RecognitionRunOptions {
            page: recognized.page.as_ref(),
            input: job.media,
            input_digest: media_digest,
            output: text,
            output_digest: mneme_core::ContentDigest::of_source_bytes(recognized.text.as_bytes()),
            model: &recognizer.model,
            runtime: &recognizer.runtime,
            adapter: &recognizer.adapter,
            preprocessing: &recognizer.preprocessing,
            configuration: &recognizer.configuration,
            segments,
            coverage: recognized.coverage,
            status: recognized.status,
            scores: &recognized.scores,
            alternatives: &recognized.alternatives,
            covers: attempt.covers,
        },
    )
    .map_err(|error| error.to_string())
}
