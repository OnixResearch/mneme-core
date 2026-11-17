//! The recognized texts of a capture, and the one presented for each part.
//!
//! A capture may be recognized more than once: reprocessing publishes another
//! run with its own text, and a person may correct any text. For each part of
//! the capture one text is selected: a corrected text before machine output,
//! then the most recently committed. The rest are alternatives. They stay in
//! history and can be compared and chosen, but they are not presented or
//! searched as the capture's text. Choosing an alternative is a correction of
//! it, which makes it the most recent corrected text, so a background result can
//! never displace text a person corrected.

/// One recognized text of a capture, at its current revision.
#[derive(Clone, Debug, PartialEq)]
pub struct Text {
    /// The text record at its current revision.
    pub pin: mneme_core::SourcePin,
    /// A person corrected the text: its current revision is a correction.
    pub is_corrected: bool,
    /// The run whose output was the text's first revision.
    pub run: crate::model::RecognitionRunView,
    /// Segments aligned to the current revision. A correction that
    /// invalidated alignment has none.
    pub segments: Vec<crate::model::RecognitionSegmentView>,
    /// The current revision is a correction that declared its alignment
    /// invalidated.
    pub is_alignment_invalidated: bool,
    /// The commit order of the current revision.
    pub revision_order: u64,
}

/// A capture's recognized texts: the one selected for each part, and the rest.
#[derive(Clone, Debug, PartialEq)]
pub struct Selection {
    pub capture: mneme_core::SourcePin,
    /// At most one text for any part of the capture, in capture order.
    pub selected: Vec<Text>,
    /// Texts sharing a part with a selected text, most preferred first.
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
    /// The recognized texts of `capture` that a caller working in `base` may
    /// read, selected per part.
    pub fn capture_texts(
        &self,
        capture: mneme_core::SourcePin,
        base: &mneme_core::ScopeId,
    ) -> Selection {
        self.capture_selections(Some(base))
            .remove(&capture)
            .unwrap_or_else(|| Selection::empty(capture))
    }

    /// Selections for every capture with recognized text, restricted to
    /// texts readable from `base` when one is given.
    pub fn capture_selections(
        &self,
        base: Option<&mneme_core::ScopeId>,
    ) -> std::collections::BTreeMap<mneme_core::SourcePin, Selection> {
        let mut texts: std::collections::BTreeMap<mneme_core::SourcePin, Vec<Text>> =
            std::collections::BTreeMap::new();
        for run in self.current_runs() {
            let is_readable =
                base.is_none_or(|base| self.content_readable_in(&run.record.scope, base));
            if !is_readable {
                continue;
            }
            let capture = run.input;
            if let Some(text) = self.current_text(run) {
                texts.entry(capture).or_default().push(text);
            }
        }
        texts
            .into_iter()
            .map(|(capture, texts)| (capture, select(capture, texts)))
            .collect()
    }

    /// Text records that are not selected for their part of their capture.
    pub fn unselected_recognized_texts(&self) -> std::collections::BTreeSet<mneme_core::RecordId> {
        self.capture_selections(None)
            .into_values()
            .flat_map(|selection| selection.alternatives)
            .map(|text| text.pin.source())
            .collect()
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

    /// The run's text at its current revision: its own output, or a later
    /// correction of it. A later machine revision belongs to another run.
    fn current_text(&self, run: crate::model::RecognitionRunView) -> Option<Text> {
        let record = self.records.get(&run.output.source())?;
        if self.suppression_for(record).is_some() {
            return None;
        }
        let source = crate::model::SourceView::parse(record.clone()).ok()?;
        let is_corrected = source.acquisition == mneme_core::Acquisition::Corrected;
        if !is_corrected && record.revision_id != run.output.revision() {
            return None;
        }
        let pin = mneme_core::SourcePin::new(record.record_id, record.revision_id);
        Some(Text {
            pin,
            is_corrected,
            segments: self.recognition_segments_for_source(pin.source(), pin.revision()),
            is_alignment_invalidated: source
                .correction
                .as_ref()
                .is_some_and(|correction| !correction.alignment_updated()),
            revision_order: record.recorded.revision_order(),
            run,
        })
    }
}

/// Select the most preferred text for each part; a text sharing a part with
/// one already selected is an alternative.
fn select(capture: mneme_core::SourcePin, mut texts: Vec<Text>) -> Selection {
    texts.sort_by(|left, right| {
        right
            .is_corrected
            .cmp(&left.is_corrected)
            .then(right.revision_order.cmp(&left.revision_order))
            .then(left.pin.cmp(&right.pin))
    });
    let mut selection = Selection {
        capture,
        selected: Vec::with_capacity(texts.len()),
        alternatives: Vec::with_capacity(texts.len()),
    };
    for text in texts {
        let is_shared = selection
            .selected
            .iter()
            .any(|chosen| chosen.run.covers.overlaps(&text.run.covers));
        if is_shared {
            selection.alternatives.push(text);
        } else {
            selection.selected.push(text);
        }
    }
    selection
        .selected
        .sort_by_key(|text| (part_position(text.run.covers), text.pin));
    selection
}

/// Where a part begins within its capture.
fn part_position(part: mneme_core::CapturePart) -> u64 {
    match part {
        mneme_core::CapturePart::Whole => 0,
        mneme_core::CapturePart::Page(page) => u64::from(page),
        mneme_core::CapturePart::Audio { start_tick, .. } => start_tick,
    }
}
