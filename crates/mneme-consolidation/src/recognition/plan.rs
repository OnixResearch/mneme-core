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
    /// A selected region of one page, under the caller's key for it.
    Region { page: u32, key: [u8; 16] },
    /// The half-open tick interval `[start_tick, end_tick)` of an audio capture.
    Audio { start_tick: u64, end_tick: u64 },
}

impl UnitSelector {
    /// The part of the capture this unit covers.
    pub(super) const fn part(self) -> mneme_core::CapturePart {
        match self {
            UnitSelector::Whole => mneme_core::CapturePart::Whole,
            UnitSelector::Page { page } => mneme_core::CapturePart::Page(page),
            UnitSelector::Region { page, key } => mneme_core::CapturePart::Region { page, key },
            UnitSelector::Audio {
                start_tick,
                end_tick,
            } => mneme_core::CapturePart::Audio {
                start_tick,
                end_tick,
            },
        }
    }
}

/// Divide a capture with `extent` into units under `plan`.
pub(super) fn units(
    plan: &super::UnitPlan,
    extent: Option<mneme_core::MediaExtent>,
    max_units: u32,
) -> Result<Vec<UnitSelector>, super::Failure> {
    match plan {
        super::UnitPlan::Whole => whole_unit(extent),
        super::UnitPlan::Pages => page_units(extent, max_units),
        super::UnitPlan::Page { page } => selected_page(extent, *page),
        super::UnitPlan::Region { page, key } => check_selected(extent, *page).map(|()| {
            vec![UnitSelector::Region {
                page: *page,
                key: *key,
            }]
        }),
        super::UnitPlan::AudioChunks { ticks } => audio_units(extent, *ticks, max_units),
        super::UnitPlan::AudioSpans { ends } => audio_spans(extent, ends, max_units),
    }
}

/// The audio capture's duration in ticks.
fn audio_duration(extent: Option<mneme_core::MediaExtent>) -> Result<u64, super::Failure> {
    match extent {
        Some(mneme_core::MediaExtent::Audio { duration_ticks, .. }) => Ok(duration_ticks),
        Some(mneme_core::MediaExtent::Pages { .. } | mneme_core::MediaExtent::InkPages { .. })
        | None => Err(super::Failure::Invalid(
            "an audio plan needs an audio capture".to_owned(),
        )),
    }
}

/// Units ending at `ends`, which must divide the whole capture: strictly
/// increasing, the last at its duration, and no more than the job admits.
fn audio_spans(
    extent: Option<mneme_core::MediaExtent>,
    ends: &[u64],
    max_units: u32,
) -> Result<Vec<UnitSelector>, super::Failure> {
    let duration = audio_duration(extent)?;
    let is_admitted = u32::try_from(ends.len()).is_ok_and(|count| count <= max_units);
    if !is_admitted {
        return Err(super::Failure::Invalid(
            "the capture has more audio spans than the job admits".to_owned(),
        ));
    }
    if ends.last() != Some(&duration) {
        return Err(super::Failure::Invalid(
            "audio spans must end at the capture's duration".to_owned(),
        ));
    }
    let mut selectors = Vec::with_capacity(ends.len());
    let mut start = 0_u64;
    for &end in ends {
        if end <= start {
            return Err(super::Failure::Invalid(
                "audio spans must be nonempty and in order".to_owned(),
            ));
        }
        selectors.push(UnitSelector::Audio {
            start_tick: start,
            end_tick: end,
        });
        start = end;
    }
    Ok(selectors)
}

/// A whole-capture unit: its answers carry no page, so a multi-page capture is
/// recognized page by page, and a capture without an extent cannot be aligned
/// or published at all.
fn whole_unit(
    extent: Option<mneme_core::MediaExtent>,
) -> Result<Vec<UnitSelector>, super::Failure> {
    match extent {
        Some(mneme_core::MediaExtent::Audio { .. }) => Ok(vec![UnitSelector::Whole]),
        Some(
            mneme_core::MediaExtent::Pages { page_count }
            | mneme_core::MediaExtent::InkPages { page_count },
        ) => {
            if page_count == 1 {
                Ok(vec![UnitSelector::Whole])
            } else {
                Err(super::Failure::Invalid(
                    "a capture with several pages is recognized page by page".to_owned(),
                ))
            }
        }
        None => Err(super::Failure::Invalid(
            "a capture without a media extent cannot be recognized".to_owned(),
        )),
    }
}

fn page_count(extent: Option<mneme_core::MediaExtent>) -> Result<u32, super::Failure> {
    match extent {
        Some(
            mneme_core::MediaExtent::Pages { page_count }
            | mneme_core::MediaExtent::InkPages { page_count },
        ) => Ok(page_count),
        Some(mneme_core::MediaExtent::Audio { .. }) | None => Err(super::Failure::Invalid(
            "a page plan needs a page or ink capture".to_owned(),
        )),
    }
}

fn selected_page(
    extent: Option<mneme_core::MediaExtent>,
    page: u32,
) -> Result<Vec<UnitSelector>, super::Failure> {
    check_selected(extent, page)?;
    Ok(vec![UnitSelector::Page { page }])
}

/// A selected page or region must name a page of the capture.
fn check_selected(
    extent: Option<mneme_core::MediaExtent>,
    page: u32,
) -> Result<(), super::Failure> {
    if page >= page_count(extent)? {
        return Err(super::Failure::Invalid(
            "the selected page is outside the capture".to_owned(),
        ));
    }
    Ok(())
}

fn page_units(
    extent: Option<mneme_core::MediaExtent>,
    max_units: u32,
) -> Result<Vec<UnitSelector>, super::Failure> {
    let page_count = page_count(extent)?;
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
    let duration = audio_duration(extent)?;
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
    pub(super) fn of(job: &super::Job) -> Self {
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
fn definition_fields(job: &super::Job, seed: &[u8; 32]) -> Vec<Vec<u8>> {
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
