//! The recognized texts of a capture, and which of them are presented.
//!
//! A capture may be recognized more than once: reprocessing publishes another
//! run with its own text, and a person may correct any text. Texts are taken
//! in order of preference:
//!
//! 1. a text whose bytes are retained, before a pruned or erased one;
//! 2. a corrected text, before machine output;
//! 3. among machine output, a complete run's text before a partial, failed or
//!    cancelled one;
//! 4. the most recently committed.
//!
//! A text is selected unless the more preferred texts already selected cover
//! all of the part of the capture it covers. Otherwise it is an alternative:
//! kept in history and offered for comparison and choice, but not presented or
//! searched as the capture's text. A reprocessed part therefore replaces older
//! machine output of that part only, a part nothing newer covers keeps its
//! text, and a background result never displaces retained text a person
//! corrected. Choosing an alternative is a correction of it, which makes it the
//! most recent corrected text.

/// Processed derivatives between a segment's media and its capture, at most.
const MAX_TRANSFORM_STEPS: usize = 64;

/// One recognized text of a capture, at its current revision.
#[derive(Clone, Debug, PartialEq)]
pub struct Text {
    /// The text record at its current revision.
    pub pin: mneme_core::SourcePin,
    /// A person corrected the text: its current revision is a correction.
    pub is_corrected: bool,
    /// The current revision's bytes are retained.
    pub is_available: bool,
    /// The run whose output was the text's first revision.
    pub run: crate::model::RecognitionRunView,
    /// Segments aligned to the current revision, when they were read. A
    /// correction that invalidated alignment has none.
    pub segments: Vec<crate::model::RecognitionSegmentView>,
    /// The current revision is a correction that declared its alignment
    /// invalidated.
    pub is_alignment_invalidated: bool,
    /// The commit order of the current revision.
    pub revision_order: u64,
}

/// A capture's recognized texts: those presented, and the rest.
#[derive(Clone, Debug, PartialEq)]
pub struct Selection {
    pub capture: mneme_core::SourcePin,
    /// Texts presented for the capture, in capture order.
    pub selected: Vec<Text>,
    /// Texts whose whole part is covered by selected texts, most preferred
    /// first.
    pub alternatives: Vec<Text>,
}

impl Selection {
    const fn empty(capture: mneme_core::SourcePin) -> Self {
        Selection {
            capture,
            selected: Vec::new(),
            alternatives: Vec::new(),
        }
    }
}

impl super::View {
    /// Where `location`, given on `media`, lies on `capture`: each processed
    /// derivative's transform maps it one step back toward the capture. `None`
    /// when a step has no transform or does not map the location, or the chain
    /// does not reach the capture.
    pub fn location_on_capture(
        &self,
        capture: mneme_core::SourcePin,
        media: mneme_core::SourcePin,
        location: &mneme_core::MediaLocation,
    ) -> Option<mneme_core::MediaLocation> {
        let mut pin = media;
        let mut mapped = location.clone();
        for _ in 0..=MAX_TRANSFORM_STEPS {
            if pin == capture {
                return Some(mapped);
            }
            let step = self.source_at(pin.source(), pin.revision()).ok()?;
            mapped = step.media_transform?.map_region(&mapped)?;
            pin = step.derived_from?;
        }
        None
    }

    /// The recognized texts of `capture` that a caller working in `base` may
    /// read, with the segments of every text.
    pub fn capture_texts(
        &self,
        capture: mneme_core::SourcePin,
        base: &mneme_core::ScopeId,
    ) -> Selection {
        let mut selection = self
            .text_candidates(Some(base), Some(capture))
            .remove(&capture)
            .map_or_else(
                || Selection::empty(capture),
                |texts| self.select(capture, texts),
            );
        self.attach_segments(std::slice::from_mut(&mut selection), true);
        selection
    }

    /// Selections for every capture with recognized text, restricted to texts
    /// readable from `base` when one is given, with the segments of their
    /// selected texts.
    pub fn capture_selections(
        &self,
        base: Option<&mneme_core::ScopeId>,
    ) -> std::collections::BTreeMap<mneme_core::SourcePin, Selection> {
        let mut selections: Vec<Selection> = self
            .text_candidates(base, None)
            .into_iter()
            .map(|(capture, texts)| self.select(capture, texts))
            .collect();
        self.attach_segments(&mut selections, false);
        selections
            .into_iter()
            .map(|selection| (selection.capture, selection))
            .collect()
    }

    /// Text records that are not selected for any capture. No segment is read.
    pub fn unselected_recognized_texts(&self) -> std::collections::BTreeSet<mneme_core::RecordId> {
        let selections: Vec<Selection> = self
            .text_candidates(None, None)
            .into_iter()
            .map(|(capture, texts)| self.select(capture, texts))
            .collect();
        let selected: std::collections::BTreeSet<mneme_core::RecordId> = selections
            .iter()
            .flat_map(|selection| &selection.selected)
            .map(|text| text.pin.source())
            .collect();
        selections
            .iter()
            .flat_map(|selection| &selection.alternatives)
            .map(|text| text.pin.source())
            .filter(|record| !selected.contains(record))
            .collect()
    }

    /// One text per text record for each capture, claimed by the run naming it
    /// that was committed first, the lowest record id among runs committed
    /// together; segments are not read.
    fn text_candidates(
        &self,
        base: Option<&mneme_core::ScopeId>,
        capture: Option<mneme_core::SourcePin>,
    ) -> std::collections::BTreeMap<mneme_core::SourcePin, Vec<Text>> {
        let mut runs: Vec<crate::model::RecognitionRunView> = self
            .current_runs()
            .filter(|run| {
                capture.is_none_or(|capture| run.input == capture)
                    && base.is_none_or(|base| self.content_readable_in(&run.record.scope, base))
            })
            .collect();
        runs.sort_by_key(|run| {
            (
                run.output.source(),
                run.record.recorded.revision_order(),
                run.record.record_id,
            )
        });
        runs.dedup_by_key(|run| run.output.source());
        let mut texts: std::collections::BTreeMap<mneme_core::SourcePin, Vec<Text>> =
            std::collections::BTreeMap::new();
        for run in runs {
            let capture = run.input;
            if let Some(text) = self.current_text(run) {
                texts.entry(capture).or_default().push(text);
            }
        }
        texts
    }

    fn current_runs(&self) -> impl Iterator<Item = crate::model::RecognitionRunView> + '_ {
        self.records
            .values()
            .filter(|record| {
                record.kind == mneme_core::RecordKind::RecognitionRun
                    && self.suppression_for(record).is_none()
            })
            .filter_map(|record| crate::model::RecognitionRunView::parse(record.clone()).ok())
    }

    /// The run's text at its current revision: its machine output, a pruned
    /// or erased revision of it, or a correction.
    fn current_text(&self, run: crate::model::RecognitionRunView) -> Option<Text> {
        let record = self.records.get(&run.output.source())?;
        if self.suppression_for(record).is_some() {
            return None;
        }
        let source = crate::model::SourceView::parse(record.clone()).ok()?;
        let is_corrected = match source.acquisition {
            mneme_core::Acquisition::Corrected => true,
            mneme_core::Acquisition::MachineRecognized => false,
            mneme_core::Acquisition::Authored
            | mneme_core::Acquisition::Imported
            | mneme_core::Acquisition::Captured => return None,
        };
        Some(Text {
            pin: mneme_core::SourcePin::new(record.record_id, record.revision_id),
            is_corrected,
            is_available: source.availability == crate::model::SourceAvailability::Retained,
            segments: Vec::new(),
            is_alignment_invalidated: source
                .correction
                .as_ref()
                .is_some_and(|correction| !correction.alignment_updated()),
            revision_order: record.recorded.revision_order(),
            run,
        })
    }

    /// Select texts in order of preference: each is selected unless the texts
    /// already selected cover its whole part.
    fn select(&self, capture: mneme_core::SourcePin, mut texts: Vec<Text>) -> Selection {
        texts.sort_by(|left, right| {
            right
                .is_available
                .cmp(&left.is_available)
                .then(right.is_corrected.cmp(&left.is_corrected))
                .then(is_complete(right).cmp(&is_complete(left)))
                .then(right.revision_order.cmp(&left.revision_order))
                .then(left.pin.cmp(&right.pin))
        });
        let extent = self.capture_extent(capture, texts.first().map(|text| text.run.input_digest));
        let mut selection = Selection {
            capture,
            selected: Vec::with_capacity(texts.len()),
            alternatives: Vec::with_capacity(texts.len()),
        };
        let mut covered: Vec<mneme_core::CapturePart> = Vec::with_capacity(texts.len());
        for text in texts {
            if is_covered(text.run.covers, &covered, extent) {
                selection.alternatives.push(text);
            } else {
                covered.push(text.run.covers);
                selection.selected.push(text);
            }
        }
        selection
            .selected
            .sort_by_key(|text| (part_position(text.run.covers), text.pin));
        selection
    }

    /// The capture's extent. A pruned capture is rewritten as a new revision
    /// that keeps its extent, so when the view does not hold the revision the
    /// runs name, the current revision serves if it replaced exactly those
    /// bytes.
    fn capture_extent(
        &self,
        capture: mneme_core::SourcePin,
        input_digest: Option<mneme_core::ContentDigest>,
    ) -> Option<mneme_core::MediaExtent> {
        if let Ok(source) = self.source_at(capture.source(), capture.revision()) {
            return source.media_extent;
        }
        let current = self.source(capture.source()).ok()?;
        let is_rewrite = input_digest.is_some() && current.prior_digest == input_digest;
        is_rewrite.then_some(current.media_extent).flatten()
    }

    /// Read the segments of the selected texts, and of the alternatives when
    /// asked, in one pass over the view.
    fn attach_segments(&self, selections: &mut [Selection], has_alternatives: bool) {
        let wanted: std::collections::BTreeSet<mneme_core::SourcePin> = selections
            .iter()
            .flat_map(|selection| {
                let alternatives: &[Text] = if has_alternatives {
                    &selection.alternatives
                } else {
                    &[]
                };
                selection.selected.iter().chain(alternatives)
            })
            .map(|text| text.pin)
            .collect();
        if wanted.is_empty() {
            return;
        }
        let mut segments: std::collections::BTreeMap<
            mneme_core::SourcePin,
            Vec<crate::model::RecognitionSegmentView>,
        > = std::collections::BTreeMap::new();
        for record in self.records.values() {
            if record.kind != mneme_core::RecordKind::RecognitionSegment
                || self.suppression_for(record).is_some()
            {
                continue;
            }
            let Ok(segment) = crate::model::RecognitionSegmentView::parse(record.clone()) else {
                continue;
            };
            if wanted.contains(&segment.text_source) {
                segments
                    .entry(segment.text_source)
                    .or_default()
                    .push(segment);
            }
        }
        for selection in selections {
            for text in &mut selection.selected {
                text.segments = segments.remove(&text.pin).unwrap_or_default();
            }
            if has_alternatives {
                for text in &mut selection.alternatives {
                    text.segments = segments.remove(&text.pin).unwrap_or_default();
                }
            }
        }
    }
}

/// A corrected text counts as complete: a person chose it, whatever the run
/// that produced it reported.
const fn is_complete(text: &Text) -> bool {
    text.is_corrected || matches!(text.run.status, mneme_core::RecognitionStatus::Complete)
}

/// Whether the parts in `covered` together cover all of `part`. A whole
/// capture is covered by a selected whole, or by pages or intervals spanning
/// its extent.
fn is_covered(
    part: mneme_core::CapturePart,
    covered: &[mneme_core::CapturePart],
    extent: Option<mneme_core::MediaExtent>,
) -> bool {
    if covered
        .iter()
        .any(|chosen| matches!(chosen, mneme_core::CapturePart::Whole))
    {
        return true;
    }
    match part {
        mneme_core::CapturePart::Whole => match extent {
            Some(
                mneme_core::MediaExtent::Pages { page_count }
                | mneme_core::MediaExtent::InkPages { page_count },
            ) => all_pages_covered(covered, page_count),
            Some(mneme_core::MediaExtent::Audio { duration_ticks, .. }) => {
                ticks_covered(covered, (0, duration_ticks))
            }
            None => false,
        },
        mneme_core::CapturePart::Page(page) => {
            covered.contains(&mneme_core::CapturePart::Page(page))
        }
        mneme_core::CapturePart::Audio {
            start_tick,
            end_tick,
        } => ticks_covered(covered, (start_tick, end_tick)),
    }
}

/// Whether every page below `page_count` is covered.
fn all_pages_covered(covered: &[mneme_core::CapturePart], page_count: u32) -> bool {
    let pages: std::collections::BTreeSet<u32> = covered
        .iter()
        .filter_map(|chosen| match chosen {
            mneme_core::CapturePart::Page(page) if *page < page_count => Some(*page),
            mneme_core::CapturePart::Page(_)
            | mneme_core::CapturePart::Whole
            | mneme_core::CapturePart::Audio { .. } => None,
        })
        .collect();
    usize::try_from(page_count).is_ok_and(|count| pages.len() == count)
}

/// Whether the covered audio intervals span `[start, end)` without a gap.
fn ticks_covered(covered: &[mneme_core::CapturePart], (start, end): (u64, u64)) -> bool {
    let mut intervals: Vec<(u64, u64)> = covered
        .iter()
        .filter_map(|chosen| match chosen {
            mneme_core::CapturePart::Audio {
                start_tick,
                end_tick,
            } => Some((*start_tick, *end_tick)),
            mneme_core::CapturePart::Whole | mneme_core::CapturePart::Page(_) => None,
        })
        .collect();
    intervals.sort_unstable();
    let mut reached = start;
    for (from, to) in intervals {
        if from > reached {
            break;
        }
        reached = reached.max(to);
        if reached >= end {
            return true;
        }
    }
    reached >= end
}

/// Where a part begins within its capture.
fn part_position(part: mneme_core::CapturePart) -> u64 {
    match part {
        mneme_core::CapturePart::Whole => 0,
        mneme_core::CapturePart::Page(page) => u64::from(page),
        mneme_core::CapturePart::Audio { start_tick, .. } => start_tick,
    }
}
