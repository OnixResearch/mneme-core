//! A worker's answer for one unit, parsed strictly and checked against the
//! capture before anything is published.

/// What a worker says about one unit.
#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct WorkerAnswer {
    status: AnswerStatus,
    #[serde(default = "String::new")]
    text: String,
    #[serde(default = "Vec::new")]
    segments: Vec<AnswerSegment>,
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AnswerStatus {
    Complete,
    Unsupported,
}

/// One recognized span: inclusive byte offsets into the answer's text and
/// where the span lies within the unit.
#[derive(serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct AnswerSegment {
    start: u64,
    end: u64,
    location: AnswerLocation,
}

#[derive(serde::Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "kebab-case",
    deny_unknown_fields
)]
enum AnswerLocation {
    /// Ticks in the capture's own time base.
    Audio {
        start_tick: u64,
        end_tick: u64,
        channel: u32,
    },
    /// A region of the unit's page.
    Region {
        x: f64,
        y: f64,
        width: f64,
        height: f64,
        frame: AnswerFrame,
    },
    /// Strokes of one layer of the unit's page.
    Strokes { layer: String, strokes: Vec<String> },
}

#[derive(Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
enum AnswerFrame {
    Normalized,
    Pixels { width: u32, height: u32 },
    PagePoints { width: f64, height: f64 },
}

/// A validated answer for one unit.
pub(super) enum Answer {
    Recognized(Recognized),
    /// The recognizer reports it cannot recognize this unit.
    Unsupported,
}

/// Recognized text and its alignment to the capture.
pub(super) struct Recognized {
    pub text: String,
    pub segments: Vec<(mneme_core::SourceSpan, mneme_core::MediaLocation)>,
}

/// Parse and check one worker answer for the unit at `selector`.
pub(super) fn parse(
    output: &[u8],
    selector: super::UnitSelector,
    capture: &mneme_memory::SourceView,
) -> Result<Answer, String> {
    let answer: WorkerAnswer = serde_json::from_slice(output)
        .map_err(|_| "the worker's answer does not follow the recognition protocol".to_owned())?;
    match answer.status {
        AnswerStatus::Unsupported => Ok(Answer::Unsupported),
        AnswerStatus::Complete => {
            if answer.segments.len() > mneme_core::MAX_RECOGNITION_SEGMENTS {
                return Err("the answer has more segments than a run admits".to_owned());
            }
            let mut segments = Vec::with_capacity(answer.segments.len());
            for segment in answer.segments {
                segments.push(check_segment(segment, &answer.text, selector, capture)?);
            }
            Ok(Answer::Recognized(Recognized {
                text: answer.text,
                segments,
            }))
        }
    }
}

fn check_segment(
    segment: AnswerSegment,
    text: &str,
    selector: super::UnitSelector,
    capture: &mneme_memory::SourceView,
) -> Result<(mneme_core::SourceSpan, mneme_core::MediaLocation), String> {
    let span = mneme_core::SourceSpan::new(segment.start, segment.end)
        .map_err(|message| message.to_owned())?;
    let start = usize::try_from(segment.start).ok();
    let stop = segment
        .end
        .checked_add(1)
        .and_then(|stop| usize::try_from(stop).ok());
    let is_on_boundaries = start
        .zip(stop)
        .is_some_and(|(start, stop)| text.get(start..stop).is_some());
    if !is_on_boundaries {
        return Err("a segment's span is outside the text or splits a character".to_owned());
    }
    let location = locate(segment.location, selector, capture)?;
    let Some(extent) = capture.media_extent else {
        return Err("a capture without a media extent cannot be aligned".to_owned());
    };
    location
        .validate_source(extent, capture.media_frame, capture.ink_inventory.as_ref())
        .map_err(|message| message.to_owned())?;
    Ok((span, location))
}

/// The capture location of an answer location given within one unit.
fn locate(
    location: AnswerLocation,
    selector: super::UnitSelector,
    capture: &mneme_memory::SourceView,
) -> Result<mneme_core::MediaLocation, String> {
    match location {
        AnswerLocation::Audio {
            start_tick,
            end_tick,
            channel,
        } => {
            let Some(mneme_core::MediaExtent::Audio { time_base, .. }) = capture.media_extent
            else {
                return Err("an audio segment needs an audio capture".to_owned());
            };
            if let super::UnitSelector::Audio {
                start_tick: unit_start,
                end_tick: unit_end,
            } = selector
                && (start_tick < unit_start || end_tick > unit_end)
            {
                return Err("an audio segment lies outside its unit".to_owned());
            }
            Ok(mneme_core::MediaLocation::Audio {
                start_tick,
                end_tick,
                time_base,
                channel,
            })
        }
        AnswerLocation::Region {
            x,
            y,
            width,
            height,
            frame,
        } => Ok(mneme_core::MediaLocation::PageRegion {
            page: unit_page(selector)?,
            frame: coordinate_frame(frame),
            x,
            y,
            width,
            height,
        }),
        AnswerLocation::Strokes { layer, strokes } => Ok(mneme_core::MediaLocation::InkStrokes {
            page: unit_page(selector)?,
            layer,
            strokes,
        }),
    }
}

/// The page a region or stroke answer refers to: the unit's page, or the
/// only page of a whole-capture unit.
fn unit_page(selector: super::UnitSelector) -> Result<u32, String> {
    match selector {
        super::UnitSelector::Page { page } => Ok(page),
        super::UnitSelector::Whole => Ok(0),
        super::UnitSelector::Audio { .. } => {
            Err("a page location cannot belong to an audio unit".to_owned())
        }
    }
}

fn coordinate_frame(frame: AnswerFrame) -> mneme_core::CoordinateFrame {
    match frame {
        AnswerFrame::Normalized => mneme_core::CoordinateFrame::Normalized,
        AnswerFrame::Pixels { width, height } => {
            mneme_core::CoordinateFrame::Pixels { width, height }
        }
        AnswerFrame::PagePoints { width, height } => {
            mneme_core::CoordinateFrame::PagePoints { width, height }
        }
    }
}
