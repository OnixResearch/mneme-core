//! Units, worker headers and the job's identity.

/// The worker protocol a header announces.
const PROTOCOL: &str = "mneme.recognition/1";

/// Which part of the capture one unit covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case"
)]
pub enum UnitSelector {
    /// The whole capture.
    Whole,
    /// One page of a page or ink capture.
    Page { page: u32 },
    /// The half-open tick interval `[start_tick, end_tick)` of an audio capture.
    Audio { start_tick: u64, end_tick: u64 },
}

/// Divide a capture with `extent` into units under `plan`.
pub(super) fn units(
    plan: super::UnitPlan,
    extent: Option<mneme_core::MediaExtent>,
    max_units: u32,
) -> Result<Vec<UnitSelector>, super::Failure> {
    match plan {
        super::UnitPlan::Whole => Ok(vec![UnitSelector::Whole]),
        super::UnitPlan::Pages => page_units(extent, max_units),
        super::UnitPlan::AudioChunks { ticks } => audio_units(extent, ticks, max_units),
    }
}

fn page_units(
    extent: Option<mneme_core::MediaExtent>,
    max_units: u32,
) -> Result<Vec<UnitSelector>, super::Failure> {
    let page_count = match extent {
        Some(
            mneme_core::MediaExtent::Pages { page_count }
            | mneme_core::MediaExtent::InkPages { page_count },
        ) => page_count,
        Some(mneme_core::MediaExtent::Audio { .. }) | None => {
            return Err(super::Failure::Invalid(
                "a page plan needs a page or ink capture".to_owned(),
            ));
        }
    };
    if page_count > max_units {
        return Err(super::Failure::Invalid(
            "the capture has more pages than the job admits".to_owned(),
        ));
    }
    Ok((0..page_count)
        .map(|page| UnitSelector::Page { page })
        .collect())
}

fn audio_units(
    extent: Option<mneme_core::MediaExtent>,
    ticks: u64,
    max_units: u32,
) -> Result<Vec<UnitSelector>, super::Failure> {
    let duration = match extent {
        Some(mneme_core::MediaExtent::Audio { duration_ticks, .. }) => duration_ticks,
        Some(mneme_core::MediaExtent::Pages { .. } | mneme_core::MediaExtent::InkPages { .. })
        | None => {
            return Err(super::Failure::Invalid(
                "an audio plan needs an audio capture".to_owned(),
            ));
        }
    };
    let Some(whole) = duration.checked_div(ticks) else {
        return Err(super::Failure::Invalid(
            "an audio plan needs a positive chunk length".to_owned(),
        ));
    };
    let has_rest = duration.checked_rem(ticks).is_some_and(|rest| rest > 0);
    let count = whole.saturating_add(u64::from(has_rest));
    let capacity = usize::try_from(count)
        .ok()
        .filter(|count| u32::try_from(*count).is_ok_and(|count| count <= max_units))
        .ok_or_else(|| {
            super::Failure::Invalid(
                "the capture has more audio chunks than the job admits".to_owned(),
            )
        })?;
    let mut selectors = Vec::with_capacity(capacity);
    let mut start = 0_u64;
    while start < duration && selectors.len() < capacity {
        let end = start.saturating_add(ticks).min(duration);
        selectors.push(UnitSelector::Audio {
            start_tick: start,
            end_tick: end,
        });
        start = end;
    }
    Ok(selectors)
}

/// The JSON header a worker reads before the capture's bytes: the protocol,
/// which unit of how many, the media type and length, the unit's selector, and
/// the capture's time base or page frame when it declares one.
pub(super) fn header(
    unit: (usize, usize),
    selector: UnitSelector,
    capture: &mneme_memory::SourceView,
    media_bytes: usize,
) -> Result<Vec<u8>, super::Failure> {
    let (index, total) = unit;
    let mut fields = serde_json::Map::new();
    fields.insert("protocol".to_owned(), PROTOCOL.into());
    fields.insert("unit".to_owned(), index.into());
    fields.insert("units".to_owned(), total.into());
    let media_type = capture
        .media_type
        .as_ref()
        .map(|symbol| symbol.as_str().to_owned());
    fields.insert("media-type".to_owned(), media_type.into());
    fields.insert("media-bytes".to_owned(), media_bytes.into());
    let selector = serde_json::to_value(selector)
        .map_err(|error| super::Failure::Invalid(error.to_string()))?;
    fields.insert("selector".to_owned(), selector);
    if let Some(mneme_core::MediaExtent::Audio {
        time_base,
        channels,
        ..
    }) = capture.media_extent
    {
        fields.insert(
            "time-base".to_owned(),
            serde_json::json!([time_base.numerator(), time_base.denominator()]),
        );
        fields.insert("channels".to_owned(), channels.into());
    }
    if let Some(frame) = capture.media_frame {
        fields.insert("frame".to_owned(), frame_value(frame));
    }
    serde_json::to_vec(&serde_json::Value::Object(fields))
        .map_err(|error| super::Failure::Invalid(error.to_string()))
}

fn frame_value(frame: mneme_core::CoordinateFrame) -> serde_json::Value {
    match frame {
        mneme_core::CoordinateFrame::Normalized => serde_json::json!("normalized"),
        mneme_core::CoordinateFrame::Pixels { width, height } => {
            serde_json::json!({ "pixels": { "width": width, "height": height } })
        }
        mneme_core::CoordinateFrame::PagePoints { width, height } => {
            serde_json::json!({ "page-points": { "width": width, "height": height } })
        }
    }
}

/// The identities one job is known by.
pub(super) struct JobIdentity {
    /// Names the job's claim: its scope and id.
    pub claim: Vec<u8>,
    /// Digest of the complete job definition, so saved progress is resumed
    /// only by the job that wrote it.
    pub definition: String,
    /// Seed of the job's deterministic record identities.
    pub seed: [u8; 32],
}

impl JobIdentity {
    pub(super) fn of(job: &super::RecognitionJob) -> Self {
        let claim = format!("recognition\0{}\0{}", job.scope, job.job_id).into_bytes();
        let seed: [u8; 32] = digest(&[b"mneme.recognition.job.v1", &claim]);
        let fields = definition_fields(job, &seed);
        let slices: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        JobIdentity {
            definition: hex(&digest(&slices)),
            claim,
            seed,
        }
    }

    /// A record or revision identity for one unit attempt: `role` names what
    /// the identity is for and `ordinal` which one of its kind.
    pub(super) fn identity(&self, unit: u32, attempt: u32, role: &str, ordinal: u32) -> [u8; 16] {
        let full = digest(&[
            &self.seed,
            &unit.to_le_bytes(),
            &attempt.to_le_bytes(),
            role.as_bytes(),
            &ordinal.to_le_bytes(),
        ]);
        let mut identity = [0_u8; 16];
        identity.copy_from_slice(&full[..16]);
        identity
    }
}

/// Every field that determines what a job does, in a fixed order.
fn definition_fields(job: &super::RecognitionJob, seed: &[u8; 32]) -> Vec<Vec<u8>> {
    let recognizer = &job.recognizer;
    let limits = job.limits;
    let mut fields = vec![
        seed.to_vec(),
        job.actor.as_bytes().to_vec(),
        job.media.source().to_hex().into_bytes(),
        job.media.revision().to_hex().into_bytes(),
        recognizer
            .worker
            .executable
            .as_os_str()
            .as_encoded_bytes()
            .to_vec(),
        recognizer.model.as_bytes().to_vec(),
        recognizer.runtime.as_bytes().to_vec(),
        recognizer.adapter.as_bytes().to_vec(),
        recognizer.preprocessing.as_bytes().to_vec(),
        recognizer.configuration.as_bytes().to_vec(),
        format!("{:?}", job.plan).into_bytes(),
        limits.max_units.to_le_bytes().to_vec(),
        limits.max_attempts_per_unit.to_le_bytes().to_vec(),
        limits.unit.max_media_bytes.to_le_bytes().to_vec(),
        limits.unit.max_output_bytes.to_le_bytes().to_vec(),
        limits.unit.max_wall_time.as_nanos().to_le_bytes().to_vec(),
    ];
    fields.reserve(recognizer.worker.args.len());
    for argument in &recognizer.worker.args {
        fields.push(argument.as_encoded_bytes().to_vec());
    }
    fields
}

/// SHA-256 over length-prefixed fields, so no two field lists collide.
pub(super) fn digest(fields: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    for field in fields {
        hasher.update(field.len().to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}

/// Lowercase hexadecimal of a digest.
pub(super) fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}
