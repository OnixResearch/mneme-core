//! Typed acquisition, media locations, recognition, and exact correction provenance.
//!
//! `SourceSpan` remains an inclusive byte interval. These types describe
//! locations in non-text media and carry the units needed to interpret them.

/// The first schema version whose sources must declare one of the closed
/// [`Acquisition`] classes. Earlier versions declared any symbol.
pub const ACQUISITION_SCHEMA_VERSION: u32 = 5;

/// The most segments one recognition run may name.
pub const MAX_RECOGNITION_SEGMENTS: usize = 4096;

/// The most stroke ids one ink location, or one declared ink layer, may name.
pub const MAX_INK_STROKES: usize = 4096;

/// The most page layers one ink source may declare.
pub const MAX_INK_LAYERS: usize = 4096;

/// The longest ink layer name or stroke id, in bytes.
const MAX_INK_ID_BYTES: usize = 256;

/// How source content entered the workspace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Acquisition {
    Authored,
    Imported,
    Captured,
    MachineRecognized,
    Corrected,
}

impl Acquisition {
    /// Stable schema symbol.
    pub const fn symbol(self) -> &'static str {
        match self {
            Acquisition::Authored => "authored",
            Acquisition::Imported => "imported",
            Acquisition::Captured => "captured",
            Acquisition::MachineRecognized => "machine-recognized",
            Acquisition::Corrected => "corrected",
        }
    }

    /// Encode as a schema symbol.
    pub fn to_value(self) -> crate::typed::Value {
        crate::typed::Value::symbol(self.symbol())
    }

    /// Decode a known acquisition label.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let Some(symbol) = value.as_symbol() else {
            return Err(type_error(path, "acquisition symbol"));
        };
        match symbol.as_str() {
            "authored" => Ok(Acquisition::Authored),
            "imported" | "authenticated-import-v1" => Ok(Acquisition::Imported),
            "captured" => Ok(Acquisition::Captured),
            "machine-recognized" => Ok(Acquisition::MachineRecognized),
            "corrected" => Ok(Acquisition::Corrected),
            _ => Err(type_error(path, "declared acquisition symbol")),
        }
    }
}

/// Exact source record and immutable revision pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourcePin {
    source: crate::ids::RecordId,
    revision: crate::ids::RevisionId,
}

impl SourcePin {
    /// Construct an exact source pin.
    pub const fn new(source: crate::ids::RecordId, revision: crate::ids::RevisionId) -> Self {
        SourcePin { source, revision }
    }

    /// Source record identity.
    pub const fn source(self) -> crate::ids::RecordId {
        self.source
    }

    /// Immutable source revision identity.
    pub const fn revision(self) -> crate::ids::RevisionId {
        self.revision
    }

    /// Encode as an exact pinned source-revision reference.
    pub fn to_value(self) -> crate::typed::Value {
        crate::pointer::Reference::pinned(
            self.source,
            self.revision,
            crate::fields::RecordKind::SourceRevision,
        )
        .to_value()
    }

    /// Decode only an exact source-revision pin.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        match crate::pointer::Reference::from_value(value, path)? {
            crate::pointer::Reference::Pinned {
                target,
                revision,
                kind: crate::fields::RecordKind::SourceRevision,
            } => Ok(SourcePin::new(target, revision)),
            crate::pointer::Reference::Pinned { .. }
            | crate::pointer::Reference::Local { .. }
            | crate::pointer::Reference::External { .. }
            | crate::pointer::Reference::Unresolved { .. } => {
                Err(type_error(path, "pinned source-revision reference"))
            }
        }
    }
}

/// A rational number of seconds per media tick.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TimeBase {
    numerator: u64,
    denominator: u64,
}

impl TimeBase {
    /// Construct a positive seconds-per-tick rational.
    pub fn new(numerator: u64, denominator: u64) -> Result<Self, &'static str> {
        if numerator == 0 || denominator == 0 {
            return Err("time-base numerator and denominator must be positive");
        }
        Ok(TimeBase {
            numerator,
            denominator,
        })
    }

    /// Numerator of seconds per tick.
    pub const fn numerator(self) -> u64 {
        self.numerator
    }

    /// Denominator of seconds per tick.
    pub const fn denominator(self) -> u64 {
        self.denominator
    }
}

/// Validated extent metadata for an immutable media source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaExtent {
    /// Audio timeline and channel count.
    Audio {
        duration_ticks: u64,
        time_base: TimeBase,
        channels: u32,
    },
    /// Number of zero-based addressable document pages.
    Pages { page_count: u32 },
    /// Number of zero-based addressable ink pages.
    InkPages { page_count: u32 },
}

impl MediaExtent {
    /// Validate publicly constructible extent variants.
    pub fn validate(self) -> Result<(), &'static str> {
        let is_bounded = match self {
            MediaExtent::Audio {
                duration_ticks,
                time_base,
                channels,
            } => {
                duration_ticks > 0
                    && time_base.numerator > 0
                    && time_base.denominator > 0
                    && channels > 0
            }
            MediaExtent::Pages { page_count } | MediaExtent::InkPages { page_count } => {
                page_count > 0
            }
        };
        if is_bounded {
            Ok(())
        } else {
            Err("media extent must have positive, unit-bearing bounds")
        }
    }

    /// Encode an extent with explicit units.
    pub fn to_value(self) -> crate::typed::Value {
        match self {
            MediaExtent::Audio {
                duration_ticks,
                time_base,
                channels,
            } => crate::typed::Value::record_named(
                "media-extent",
                vec![
                    crate::typed::Value::symbol("audio"),
                    crate::typed::Value::integer(duration_ticks),
                    crate::typed::Value::integer(time_base.numerator),
                    crate::typed::Value::integer(time_base.denominator),
                    crate::typed::Value::integer(channels),
                ],
            ),
            MediaExtent::Pages { page_count } => crate::typed::Value::record_named(
                "media-extent",
                vec![
                    crate::typed::Value::symbol("pages"),
                    crate::typed::Value::integer(page_count),
                ],
            ),
            MediaExtent::InkPages { page_count } => crate::typed::Value::record_named(
                "media-extent",
                vec![
                    crate::typed::Value::symbol("ink-pages"),
                    crate::typed::Value::integer(page_count),
                ],
            ),
        }
    }

    /// Decode and validate a source extent.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "media-extent", path)?;
        let Some(kind) = record
            .fields()
            .first()
            .and_then(crate::typed::Value::as_symbol)
        else {
            return Err(type_error(path, "media extent"));
        };
        match kind.as_str() {
            "audio" if record.fields().len() == 5 => {
                let duration_ticks = unsigned(&record.fields()[1])
                    .ok_or_else(|| type_error(path, "positive audio duration"))?;
                let numerator = unsigned(&record.fields()[2])
                    .ok_or_else(|| type_error(path, "positive time-base numerator"))?;
                let denominator = unsigned(&record.fields()[3])
                    .ok_or_else(|| type_error(path, "positive time-base denominator"))?;
                let channels = positive_u32(&record.fields()[4])
                    .ok_or_else(|| type_error(path, "positive channel count"))?;
                let time_base = TimeBase::new(numerator, denominator)
                    .map_err(|message| invalid_interval(path, message))?;
                if duration_ticks == 0 {
                    return Err(invalid_interval(path, "audio duration must be positive"));
                }
                Ok(MediaExtent::Audio {
                    duration_ticks,
                    time_base,
                    channels,
                })
            }
            "pages" if record.fields().len() == 2 => {
                let page_count = positive_u32(&record.fields()[1])
                    .ok_or_else(|| type_error(path, "positive page count"))?;
                Ok(MediaExtent::Pages { page_count })
            }
            "ink-pages" if record.fields().len() == 2 => {
                let page_count = positive_u32(&record.fields()[1])
                    .ok_or_else(|| type_error(path, "positive ink page count"))?;
                Ok(MediaExtent::InkPages { page_count })
            }
            _ => Err(type_error(path, "valid media extent")),
        }
    }
}

/// The stroke ids an ink source declares, by zero-based page and layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InkInventory {
    layers: std::collections::BTreeMap<(u32, String), std::collections::BTreeSet<String>>,
}

impl InkInventory {
    /// Construct from `(page, layer, strokes)` entries, each layer once, with
    /// non-empty, bounded and unique names and stroke ids.
    pub fn new(
        entries: impl IntoIterator<Item = (u32, String, Vec<String>)>,
    ) -> Result<Self, &'static str> {
        let mut layers = std::collections::BTreeMap::new();
        for (page, layer, strokes) in entries {
            if layers.len() >= MAX_INK_LAYERS {
                return Err("an ink source declares at most 4096 layers");
            }
            if !is_ink_id(&layer) || strokes.is_empty() || strokes.len() > MAX_INK_STROKES {
                return Err("an ink layer needs a name and between 1 and 4096 stroke ids");
            }
            let declared = strokes
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>();
            if !declared.iter().all(|stroke| is_ink_id(stroke)) {
                return Err("ink stroke ids must be non-empty and bounded");
            }
            if layers.insert((page, layer), declared).is_some() {
                return Err("an ink layer is declared once per page");
            }
        }
        Ok(InkInventory { layers })
    }

    /// Whether the layer on `page` declares every one of `strokes`.
    pub fn holds(&self, page: u32, layer: &str, strokes: &[String]) -> bool {
        self.layers
            .get(&(page, layer.to_owned()))
            .is_some_and(|declared| strokes.iter().all(|stroke| declared.contains(stroke)))
    }

    /// The highest page any layer is declared on.
    pub fn last_page(&self) -> Option<u32> {
        self.layers.keys().map(|(page, _)| *page).max()
    }

    /// Encode as `<ink-strokes [<ink-layer page layer [stroke ...]> ...]>`.
    pub fn to_value(&self) -> crate::typed::Value {
        let layers = self
            .layers
            .iter()
            .map(|((page, layer), strokes)| {
                crate::typed::Value::record_named(
                    "ink-layer",
                    vec![
                        crate::typed::Value::integer(*page),
                        crate::typed::Value::string(layer.clone()),
                        crate::typed::Value::sequence(
                            strokes
                                .iter()
                                .cloned()
                                .map(crate::typed::Value::string)
                                .collect(),
                        ),
                    ],
                )
            })
            .collect();
        crate::typed::Value::record_named(
            "ink-strokes",
            vec![crate::typed::Value::sequence(layers)],
        )
    }

    /// Decode, refusing oversized sequences before copying them.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "ink-strokes", path)?;
        let [layers] = record.fields() else {
            return Err(type_error(path, "ink layer sequence"));
        };
        let layers = layers
            .as_sequence()
            .filter(|layers| layers.len() <= MAX_INK_LAYERS)
            .ok_or_else(|| type_error(path, "at most 4096 ink layers"))?;
        let mut entries = Vec::with_capacity(layers.len());
        for (index, layer) in layers.iter().enumerate() {
            entries.push(ink_layer(layer, &path.index(index))?);
        }
        Self::new(entries).map_err(|message| invalid_interval(path, message))
    }
}

fn ink_layer(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
) -> Result<(u32, String, Vec<String>), crate::problem::Diagnostic> {
    let record = expect_record(value, "ink-layer", path)?;
    let [page, layer, strokes] = record.fields() else {
        return Err(type_error(path, "ink layer page, name and strokes"));
    };
    let page = u32_value(page).ok_or_else(|| type_error(path, "non-negative page index"))?;
    let layer = layer
        .as_string()
        .ok_or_else(|| type_error(path, "ink layer name"))?
        .to_owned();
    let items = strokes
        .as_sequence()
        .filter(|items| !items.is_empty() && items.len() <= MAX_INK_STROKES)
        .ok_or_else(|| type_error(path, "between 1 and 4096 ink stroke ids"))?;
    let strokes = items
        .iter()
        .map(|item| {
            item.as_string()
                .map(str::to_owned)
                .ok_or_else(|| type_error(path, "ink stroke id text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((page, layer, strokes))
}

fn is_ink_id(text: &str) -> bool {
    !text.trim().is_empty() && text.len() <= MAX_INK_ID_BYTES
}

/// Coordinate units and bounds for one page plane.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CoordinateFrame {
    /// Coordinates normalized to the closed unit square.
    Normalized,
    /// Pixel coordinates in the declared decoded image dimensions.
    Pixels { width: u32, height: u32 },
    /// PDF/user-space points in the declared page dimensions.
    PagePoints { width: f64, height: f64 },
}

impl CoordinateFrame {
    fn bounds(self) -> (f64, f64) {
        match self {
            CoordinateFrame::Normalized => (1.0, 1.0),
            CoordinateFrame::Pixels { width, height } => (f64::from(width), f64::from(height)),
            CoordinateFrame::PagePoints { width, height } => (width, height),
        }
    }

    /// Encode units and dimensions.
    pub fn to_value(self) -> crate::typed::Value {
        match self {
            CoordinateFrame::Normalized => crate::typed::Value::record_named(
                "coordinate-frame",
                vec![crate::typed::Value::symbol("normalized")],
            ),
            CoordinateFrame::Pixels { width, height } => crate::typed::Value::record_named(
                "coordinate-frame",
                vec![
                    crate::typed::Value::symbol("pixels"),
                    crate::typed::Value::integer(width),
                    crate::typed::Value::integer(height),
                ],
            ),
            CoordinateFrame::PagePoints { width, height } => crate::typed::Value::record_named(
                "coordinate-frame",
                vec![
                    crate::typed::Value::symbol("page-points"),
                    crate::typed::Value::double(width),
                    crate::typed::Value::double(height),
                ],
            ),
        }
    }

    /// Decode and validate coordinate units and dimensions.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "coordinate-frame", path)?;
        let Some(kind) = record
            .fields()
            .first()
            .and_then(crate::typed::Value::as_symbol)
        else {
            return Err(type_error(path, "coordinate frame"));
        };
        match kind.as_str() {
            "normalized" if record.fields().len() == 1 => Ok(CoordinateFrame::Normalized),
            "pixels" if record.fields().len() == 3 => {
                let width = positive_u32(&record.fields()[1])
                    .ok_or_else(|| type_error(path, "positive pixel width"))?;
                let height = positive_u32(&record.fields()[2])
                    .ok_or_else(|| type_error(path, "positive pixel height"))?;
                Ok(CoordinateFrame::Pixels { width, height })
            }
            "page-points" if record.fields().len() == 3 => {
                let width = finite_double(&record.fields()[1])
                    .ok_or_else(|| type_error(path, "finite page width"))?;
                let height = finite_double(&record.fields()[2])
                    .ok_or_else(|| type_error(path, "finite page height"))?;
                if width <= 0.0 || height <= 0.0 {
                    return Err(invalid_interval(path, "page dimensions must be positive"));
                }
                Ok(CoordinateFrame::PagePoints { width, height })
            }
            _ => Err(type_error(path, "valid coordinate frame")),
        }
    }
}

/// A media-native interval, page rectangle, or set of ink strokes.
#[derive(Clone, Debug, PartialEq)]
pub enum MediaLocation {
    /// Half-open interval in ticks; channel is zero-based.
    Audio {
        start_tick: u64,
        end_tick: u64,
        time_base: TimeBase,
        channel: u32,
    },
    /// Rectangle within a zero-based page and declared coordinate frame.
    PageRegion {
        page: u32,
        frame: CoordinateFrame,
        x: f64,
        y: f64,
        width: f64,
        height: f64,
    },
    /// Stable stroke identifiers within one zero-based ink page and layer.
    InkStrokes {
        page: u32,
        layer: String,
        strokes: Vec<String>,
    },
}

impl MediaLocation {
    /// Validate units, finite coordinates and bounds internal to the location.
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            MediaLocation::Audio {
                start_tick,
                end_tick,
                time_base,
                ..
            } => {
                if start_tick >= end_tick || time_base.numerator == 0 || time_base.denominator == 0
                {
                    return Err("audio interval or time base is invalid");
                }
            }
            MediaLocation::PageRegion {
                frame,
                x,
                y,
                width,
                height,
                ..
            } => {
                let (max_x, max_y) = frame.bounds();
                let end_x = x + width;
                let end_y = y + height;
                if ![x, y, width, height, &end_x, &end_y]
                    .into_iter()
                    .all(|value| value.is_finite())
                    || *x < 0.0
                    || *y < 0.0
                    || *width <= 0.0
                    || *height <= 0.0
                    || end_x > max_x
                    || end_y > max_y
                {
                    return Err(
                        "page region must be finite, non-empty, and inside its coordinate frame",
                    );
                }
            }
            MediaLocation::InkStrokes { layer, strokes, .. } => {
                if layer.trim().is_empty()
                    || layer.len() > 256
                    || strokes.is_empty()
                    || strokes.len() > MAX_INK_STROKES
                {
                    return Err("ink location needs a layer and between 1 and 4096 stroke ids");
                }
                let mut unique = std::collections::BTreeSet::new();
                if strokes.iter().any(|stroke| {
                    stroke.trim().is_empty() || stroke.len() > 256 || !unique.insert(stroke)
                }) {
                    return Err("ink stroke ids must be non-empty, bounded, and unique");
                }
            }
        }
        Ok(())
    }

    /// Validate the location against its pinned source's declared extent.
    pub fn validate_extent(&self, extent: MediaExtent) -> Result<(), &'static str> {
        self.validate()?;
        match (self, extent) {
            (
                MediaLocation::Audio {
                    end_tick,
                    time_base,
                    channel,
                    ..
                },
                MediaExtent::Audio {
                    duration_ticks,
                    time_base: source_time_base,
                    channels,
                },
            ) if end_tick <= &duration_ticks
                && time_base == &source_time_base
                && *channel < channels =>
            {
                Ok(())
            }
            (MediaLocation::PageRegion { page, .. }, MediaExtent::Pages { page_count })
                if *page < page_count =>
            {
                Ok(())
            }
            (MediaLocation::InkStrokes { page, .. }, MediaExtent::InkPages { page_count })
                if *page < page_count =>
            {
                Ok(())
            }
            (MediaLocation::Audio { .. }, MediaExtent::Audio { .. }) => Err(
                "audio location exceeds duration, uses a different time base, or selects an absent channel",
            ),
            _ => Err("media location kind does not match the pinned source extent"),
        }
    }

    /// Validate the location against everything its pinned source declares:
    /// its extent, its page frame and its ink strokes. A page region must use
    /// the source's declared frame, or normalized coordinates when it
    /// declares none; ink strokes must be declared by the source.
    pub fn validate_source(
        &self,
        extent: MediaExtent,
        frame: Option<CoordinateFrame>,
        ink: Option<&InkInventory>,
    ) -> Result<(), &'static str> {
        self.validate_extent(extent)?;
        match self {
            MediaLocation::Audio { .. } => Ok(()),
            MediaLocation::PageRegion { frame: used, .. } => {
                if *used == CoordinateFrame::Normalized || frame == Some(*used) {
                    Ok(())
                } else {
                    Err("a page region must use its source's frame or normalized coordinates")
                }
            }
            MediaLocation::InkStrokes {
                page,
                layer,
                strokes,
            } => {
                if ink.is_some_and(|inventory| inventory.holds(*page, layer, strokes)) {
                    Ok(())
                } else {
                    Err("ink strokes must be declared by their ink source")
                }
            }
        }
    }

    /// Encode the typed media-native location.
    pub fn to_value(&self) -> crate::typed::Value {
        match self {
            MediaLocation::Audio {
                start_tick,
                end_tick,
                time_base,
                channel,
            } => crate::typed::Value::record_named(
                "media-location",
                vec![
                    crate::typed::Value::symbol("audio"),
                    crate::typed::Value::integer(*start_tick),
                    crate::typed::Value::integer(*end_tick),
                    crate::typed::Value::integer(time_base.numerator),
                    crate::typed::Value::integer(time_base.denominator),
                    crate::typed::Value::integer(*channel),
                ],
            ),
            MediaLocation::PageRegion {
                page,
                frame,
                x,
                y,
                width,
                height,
            } => crate::typed::Value::record_named(
                "media-location",
                vec![
                    crate::typed::Value::symbol("page-region"),
                    crate::typed::Value::integer(*page),
                    frame.to_value(),
                    crate::typed::Value::double(*x),
                    crate::typed::Value::double(*y),
                    crate::typed::Value::double(*width),
                    crate::typed::Value::double(*height),
                ],
            ),
            MediaLocation::InkStrokes {
                page,
                layer,
                strokes,
            } => crate::typed::Value::record_named(
                "media-location",
                vec![
                    crate::typed::Value::symbol("ink-strokes"),
                    crate::typed::Value::integer(*page),
                    crate::typed::Value::string(layer.clone()),
                    crate::typed::Value::sequence(
                        strokes
                            .iter()
                            .cloned()
                            .map(crate::typed::Value::string)
                            .collect(),
                    ),
                ],
            ),
        }
    }

    /// Decode and validate a media-native location.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "media-location", path)?;
        let fields = record.fields();
        let Some(kind) = fields.first().and_then(crate::typed::Value::as_symbol) else {
            return Err(type_error(path, "media location"));
        };
        let location = match kind.as_str() {
            "audio" => parse_audio_location(fields, path)?,
            "page-region" => parse_page_region(fields, path)?,
            "ink-strokes" => parse_ink_strokes(fields, path)?,
            _ => return Err(type_error(path, "valid media location")),
        };
        location
            .validate()
            .map_err(|message| invalid_interval(path, message))?;
        Ok(location)
    }
}

fn parse_audio_location(
    fields: &[crate::typed::Value],
    path: &crate::problem::Path,
) -> Result<MediaLocation, crate::problem::Diagnostic> {
    if fields.len() != 6 {
        return Err(type_error(path, "valid audio location"));
    }
    let start_tick =
        unsigned(&fields[1]).ok_or_else(|| type_error(path, "non-negative audio start"))?;
    let end_tick =
        unsigned(&fields[2]).ok_or_else(|| type_error(path, "non-negative audio end"))?;
    let numerator =
        unsigned(&fields[3]).ok_or_else(|| type_error(path, "positive time-base numerator"))?;
    let denominator =
        unsigned(&fields[4]).ok_or_else(|| type_error(path, "positive time-base denominator"))?;
    let channel =
        u32_value(&fields[5]).ok_or_else(|| type_error(path, "non-negative channel index"))?;
    let time_base =
        TimeBase::new(numerator, denominator).map_err(|message| invalid_interval(path, message))?;
    Ok(MediaLocation::Audio {
        start_tick,
        end_tick,
        time_base,
        channel,
    })
}

fn parse_page_region(
    fields: &[crate::typed::Value],
    path: &crate::problem::Path,
) -> Result<MediaLocation, crate::problem::Diagnostic> {
    if fields.len() != 7 {
        return Err(type_error(path, "valid page region"));
    }
    Ok(MediaLocation::PageRegion {
        page: u32_value(&fields[1]).ok_or_else(|| type_error(path, "non-negative page index"))?,
        frame: CoordinateFrame::from_value(&fields[2], &path.index(2))?,
        x: finite_double(&fields[3]).ok_or_else(|| type_error(path, "finite x coordinate"))?,
        y: finite_double(&fields[4]).ok_or_else(|| type_error(path, "finite y coordinate"))?,
        width: finite_double(&fields[5]).ok_or_else(|| type_error(path, "finite region width"))?,
        height: finite_double(&fields[6])
            .ok_or_else(|| type_error(path, "finite region height"))?,
    })
}

fn parse_ink_strokes(
    fields: &[crate::typed::Value],
    path: &crate::problem::Path,
) -> Result<MediaLocation, crate::problem::Diagnostic> {
    if fields.len() != 4 {
        return Err(type_error(path, "valid ink location"));
    }
    let page = u32_value(&fields[1]).ok_or_else(|| type_error(path, "non-negative page index"))?;
    let layer = fields[2]
        .as_string()
        .ok_or_else(|| type_error(path, "ink layer text"))?
        .to_owned();
    let items = fields[3]
        .as_sequence()
        .ok_or_else(|| type_error(path, "ink stroke sequence"))?;
    // Refuse an oversized location before copying any stroke id.
    if items.is_empty() || items.len() > MAX_INK_STROKES {
        return Err(type_error(path, "between 1 and 4096 ink stroke ids"));
    }
    let strokes = items
        .iter()
        .map(|item| {
            item.as_string()
                .map(str::to_owned)
                .ok_or_else(|| type_error(path, "ink stroke id text"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MediaLocation::InkStrokes {
        page,
        layer,
        strokes,
    })
}

/// Affine map from a processed page plane into its exact parent source plane.
///
/// A six-coefficient matrix represents crop translations, rotation and
/// resampling. If no affine map exists, a segment must pin the processed source
/// directly so a consumer can highlight that retained source instead.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MediaTransform {
    from: CoordinateFrame,
    to: CoordinateFrame,
    coefficients: [f64; 6],
}

impl MediaTransform {
    /// Construct and validate an invertible affine mapping.
    pub fn new(
        from: CoordinateFrame,
        to: CoordinateFrame,
        coefficients: [f64; 6],
    ) -> Result<Self, &'static str> {
        let transform = MediaTransform {
            from,
            to,
            coefficients,
        };
        transform.validate()?;
        Ok(transform)
    }

    /// Source coordinate frame of the processed image.
    pub const fn from_frame(self) -> CoordinateFrame {
        self.from
    }

    /// Target coordinate frame of the original image.
    pub const fn to_frame(self) -> CoordinateFrame {
        self.to
    }

    /// Coefficients `[a, b, tx, c, d, ty]` for the affine mapping.
    pub const fn coefficients(self) -> [f64; 6] {
        self.coefficients
    }

    /// The region of the original image that a region of the processed image
    /// covers: the bounding box of its mapped corners in the original's frame,
    /// clamped to that frame. A normalized region is first scaled to the
    /// processed image's frame. `None` for any other location or frame.
    pub fn map_region(&self, location: &MediaLocation) -> Option<MediaLocation> {
        let MediaLocation::PageRegion {
            page,
            frame,
            x,
            y,
            width,
            height,
        } = location
        else {
            return None;
        };
        let is_normalized = *frame == CoordinateFrame::Normalized;
        if !is_normalized && *frame != self.from {
            return None;
        }
        let (scale_x, scale_y) = if is_normalized {
            self.from.bounds()
        } else {
            (1.0, 1.0)
        };
        let (left, top) = (x * scale_x, y * scale_y);
        let (right, bottom) = ((x + width) * scale_x, (y + height) * scale_y);
        let corners = [(left, top), (right, top), (left, bottom), (right, bottom)]
            .map(|(corner_x, corner_y)| self.map(corner_x, corner_y));
        let (max_x, max_y) = self.to.bounds();
        let low_x = corners
            .iter()
            .map(|corner| corner.0)
            .fold(max_x, f64::min)
            .max(0.0);
        let low_y = corners
            .iter()
            .map(|corner| corner.1)
            .fold(max_y, f64::min)
            .max(0.0);
        let high_x = corners
            .iter()
            .map(|corner| corner.0)
            .fold(0.0, f64::max)
            .min(max_x);
        let high_y = corners
            .iter()
            .map(|corner| corner.1)
            .fold(0.0, f64::max)
            .min(max_y);
        let mapped = MediaLocation::PageRegion {
            page: *page,
            frame: self.to,
            x: low_x,
            y: low_y,
            width: high_x - low_x,
            height: high_y - low_y,
        };
        mapped.validate().ok().map(|()| mapped)
    }

    /// Check finite, invertible mapping and all transformed plane corners.
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.coefficients.into_iter().all(f64::is_finite) {
            return Err("media transform coefficients must be finite");
        }
        let [a, b, _, c, d, _] = self.coefficients;
        let determinant = a * d - b * c;
        if !determinant.is_finite() || determinant == 0.0 {
            return Err("media transform must be invertible");
        }
        let (from_width, from_height) = self.from.bounds();
        let (to_width, to_height) = self.to.bounds();
        if ![from_width, from_height, to_width, to_height]
            .into_iter()
            .all(f64::is_finite)
            || from_width <= 0.0
            || from_height <= 0.0
            || to_width <= 0.0
            || to_height <= 0.0
        {
            return Err("media transform frames must have positive finite dimensions");
        }
        for (x, y) in [
            (0.0, 0.0),
            (from_width, 0.0),
            (0.0, from_height),
            (from_width, from_height),
        ] {
            let (mapped_x, mapped_y) = self.map(x, y);
            if !mapped_x.is_finite()
                || !mapped_y.is_finite()
                || mapped_x < 0.0
                || mapped_y < 0.0
                || mapped_x > to_width
                || mapped_y > to_height
            {
                return Err("media transform maps outside the parent coordinate frame");
            }
        }
        Ok(())
    }

    fn map(&self, x: f64, y: f64) -> (f64, f64) {
        let [a, b, tx, c, d, ty] = self.coefficients;
        (a * x + b * y + tx, c * x + d * y + ty)
    }

    /// Encode the two frames and six affine coefficients.
    pub fn to_value(self) -> crate::typed::Value {
        crate::typed::Value::record_named(
            "media-transform",
            vec![
                self.from.to_value(),
                self.to.to_value(),
                crate::typed::Value::sequence(
                    self.coefficients
                        .into_iter()
                        .map(crate::typed::Value::double)
                        .collect(),
                ),
            ],
        )
    }

    /// Decode and validate an affine mapping.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "media-transform", path)?;
        if record.fields().len() != 3 {
            return Err(type_error(
                path,
                "media transform with two frames and six coefficients",
            ));
        }
        let from = CoordinateFrame::from_value(&record.fields()[0], &path.index(0))?;
        let to = CoordinateFrame::from_value(&record.fields()[1], &path.index(1))?;
        let values = record.fields()[2]
            .as_sequence()
            .ok_or_else(|| type_error(path, "six affine coefficients"))?;
        if values.len() != 6 {
            return Err(type_error(path, "six affine coefficients"));
        }
        let mut coefficients = [0.0; 6];
        for (index, value) in values.iter().enumerate() {
            coefficients[index] = finite_double(value).ok_or_else(|| {
                type_error(&path.index(2).index(index), "finite affine coefficient")
            })?;
        }
        Self::new(from, to, coefficients).map_err(|message| invalid_interval(path, message))
    }
}

/// Recognition unit coverage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecognitionCoverage {
    completed: u64,
    total: u64,
}

impl RecognitionCoverage {
    /// Construct bounded coverage with a positive total.
    pub fn new(completed: u64, total: u64) -> Result<Self, &'static str> {
        if total == 0 || completed > total {
            return Err("recognition coverage requires 0 <= completed <= positive total");
        }
        Ok(RecognitionCoverage { completed, total })
    }

    /// Completed units.
    pub const fn completed(self) -> u64 {
        self.completed
    }

    /// Total admitted units.
    pub const fn total(self) -> u64 {
        self.total
    }

    /// Encode unit coverage.
    pub fn to_value(self) -> crate::typed::Value {
        crate::typed::Value::record_named(
            "recognition-coverage",
            vec![
                crate::typed::Value::integer(self.completed),
                crate::typed::Value::integer(self.total),
            ],
        )
    }

    /// Decode and validate unit coverage.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "recognition-coverage", path)?;
        if record.fields().len() != 2 {
            return Err(type_error(path, "recognition coverage pair"));
        }
        let completed = unsigned(&record.fields()[0])
            .ok_or_else(|| type_error(path, "non-negative completed unit count"))?;
        let total = unsigned(&record.fields()[1])
            .ok_or_else(|| type_error(path, "positive total unit count"))?;
        Self::new(completed, total).map_err(|message| invalid_interval(path, message))
    }
}

/// Terminal or partial state of a recognition run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecognitionStatus {
    Complete,
    Partial,
    Failed,
    Unsupported,
    Cancelled,
}

impl RecognitionStatus {
    /// Stable schema symbol.
    pub const fn symbol(self) -> &'static str {
        match self {
            RecognitionStatus::Complete => "complete",
            RecognitionStatus::Partial => "partial",
            RecognitionStatus::Failed => "failed",
            RecognitionStatus::Unsupported => "unsupported",
            RecognitionStatus::Cancelled => "cancelled",
        }
    }

    /// Parse a declared status.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "complete" => Some(RecognitionStatus::Complete),
            "partial" => Some(RecognitionStatus::Partial),
            "failed" => Some(RecognitionStatus::Failed),
            "unsupported" => Some(RecognitionStatus::Unsupported),
            "cancelled" => Some(RecognitionStatus::Cancelled),
            _ => None,
        }
    }

    /// Check the state against recorded coverage.
    pub fn validate_coverage(self, coverage: RecognitionCoverage) -> Result<(), &'static str> {
        match self {
            RecognitionStatus::Complete if coverage.completed == coverage.total => Ok(()),
            RecognitionStatus::Partial if coverage.completed < coverage.total => Ok(()),
            RecognitionStatus::Complete | RecognitionStatus::Partial => {
                Err("recognition status disagrees with unit coverage")
            }
            RecognitionStatus::Failed
            | RecognitionStatus::Unsupported
            | RecognitionStatus::Cancelled => Ok(()),
        }
    }
}

/// Provider-specific finite score attached to a recognition result.
#[derive(Clone, Debug, PartialEq)]
pub struct RecognitionScore {
    provider: String,
    metric: String,
    value: f64,
}

impl RecognitionScore {
    /// Construct a score without assuming that provider metrics share a range.
    pub fn new(
        provider: impl Into<String>,
        metric: impl Into<String>,
        value: f64,
    ) -> Result<Self, &'static str> {
        let score = RecognitionScore {
            provider: provider.into(),
            metric: metric.into(),
            value,
        };
        score.validate()?;
        Ok(score)
    }

    /// Provider identity.
    pub fn provider(&self) -> &str {
        &self.provider
    }

    /// Provider metric identity.
    pub fn metric(&self) -> &str {
        &self.metric
    }

    /// Finite provider score.
    pub const fn value(&self) -> f64 {
        self.value
    }

    /// Check score identity and finite value.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.provider.trim().is_empty()
            || self.metric.trim().is_empty()
            || !self.value.is_finite()
        {
            return Err("recognition score requires provider, metric, and finite value");
        }
        Ok(())
    }

    /// Encode a score tuple.
    pub fn to_value(&self) -> crate::typed::Value {
        crate::typed::Value::record_named(
            "recognition-score",
            vec![
                crate::typed::Value::string(self.provider.clone()),
                crate::typed::Value::string(self.metric.clone()),
                crate::typed::Value::double(self.value),
            ],
        )
    }

    /// Decode and validate one provider score.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "recognition-score", path)?;
        if record.fields().len() != 3 {
            return Err(type_error(path, "recognition score"));
        }
        let provider = record.fields()[0]
            .as_string()
            .ok_or_else(|| type_error(path, "score provider"))?
            .to_owned();
        let metric = record.fields()[1]
            .as_string()
            .ok_or_else(|| type_error(path, "score metric"))?
            .to_owned();
        let value = finite_double(&record.fields()[2])
            .ok_or_else(|| type_error(path, "finite recognition score"))?;
        let score = RecognitionScore {
            provider,
            metric,
            value,
        };
        score
            .validate()
            .map_err(|message| invalid_interval(path, message))?;
        Ok(score)
    }
}

/// Bounded provider alternative for one recognized segment.
#[derive(Clone, Debug, PartialEq)]
pub struct RecognitionAlternative {
    text: String,
    score: Option<f64>,
}

impl RecognitionAlternative {
    /// Construct a non-empty alternative with an optional finite score.
    pub fn new(text: impl Into<String>, score: Option<f64>) -> Result<Self, &'static str> {
        let alternative = RecognitionAlternative {
            text: text.into(),
            score,
        };
        alternative.validate()?;
        Ok(alternative)
    }

    /// Alternative text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Optional provider score.
    pub const fn score(&self) -> Option<f64> {
        self.score
    }

    /// Check text and optional score bounds.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.text.is_empty()
            || self.text.len() > 16384
            || self.score.is_some_and(|score| !score.is_finite())
        {
            return Err("recognition alternative text or score is invalid");
        }
        Ok(())
    }

    /// Encode the text and optional score.
    pub fn to_value(&self) -> crate::typed::Value {
        crate::typed::Value::record_named(
            "recognition-alternative",
            vec![
                crate::typed::Value::string(self.text.clone()),
                self.score.map_or_else(
                    || crate::typed::Value::symbol("none"),
                    crate::typed::Value::double,
                ),
            ],
        )
    }

    /// Decode and validate one provider alternative.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "recognition-alternative", path)?;
        if record.fields().len() != 2 {
            return Err(type_error(path, "recognition alternative"));
        }
        let text = record.fields()[0]
            .as_string()
            .ok_or_else(|| type_error(path, "alternative text"))?
            .to_owned();
        let score =
            match &record.fields()[1] {
                value
                    if value
                        .as_symbol()
                        .is_some_and(|symbol| symbol.as_str() == "none") =>
                {
                    None
                }
                value => Some(finite_double(value).ok_or_else(|| {
                    type_error(&path.index(1), "finite alternative score or none")
                })?),
            };
        let alternative = RecognitionAlternative { text, score };
        alternative
            .validate()
            .map_err(|message| invalid_interval(path, message))?;
        Ok(alternative)
    }
}

/// Whether a corrected text revision carries fresh alignment or invalidates it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlignmentDisposition {
    Updated,
    Invalidated,
}

/// Human correction metadata on a corrected source revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorrectionProvenance {
    actor: String,
    edit: String,
    alignment: AlignmentDisposition,
}

impl CorrectionProvenance {
    /// Construct correction provenance, explicitly stating alignment handling.
    pub fn new(
        actor: impl Into<String>,
        edit: impl Into<String>,
        alignment: AlignmentDisposition,
    ) -> Result<Self, &'static str> {
        let provenance = CorrectionProvenance {
            actor: actor.into(),
            edit: edit.into(),
            alignment,
        };
        provenance.validate()?;
        Ok(provenance)
    }

    /// Human editor identity.
    pub fn actor(&self) -> &str {
        &self.actor
    }

    /// Edit provenance supplied by the editor.
    pub fn edit(&self) -> &str {
        &self.edit
    }

    /// Whether fresh alignment records were supplied for this text revision.
    pub const fn alignment_updated(&self) -> bool {
        matches!(self.alignment, AlignmentDisposition::Updated)
    }

    /// Validate the required provenance fields.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.actor.trim().is_empty()
            || self.actor.len() > 1024
            || self.edit.trim().is_empty()
            || self.edit.len() > 16384
        {
            return Err("correction actor and edit provenance must be non-empty and bounded");
        }
        Ok(())
    }

    /// Encode correction identity and alignment disposition.
    pub fn to_value(&self) -> crate::typed::Value {
        crate::typed::Value::record_named(
            "correction-provenance",
            vec![
                crate::typed::Value::string(self.actor.clone()),
                crate::typed::Value::string(self.edit.clone()),
                crate::typed::Value::symbol(match self.alignment {
                    AlignmentDisposition::Updated => "updated",
                    AlignmentDisposition::Invalidated => "invalidated",
                }),
            ],
        )
    }

    /// Decode and validate correction provenance.
    pub fn from_value(
        value: &crate::typed::Value,
        path: &crate::problem::Path,
    ) -> Result<Self, crate::problem::Diagnostic> {
        let record = expect_record(value, "correction-provenance", path)?;
        if record.fields().len() != 3 {
            return Err(type_error(path, "correction provenance"));
        }
        let actor = record.fields()[0]
            .as_string()
            .ok_or_else(|| type_error(path, "correction actor"))?
            .to_owned();
        let edit = record.fields()[1]
            .as_string()
            .ok_or_else(|| type_error(path, "correction edit provenance"))?
            .to_owned();
        let alignment = match record.fields()[2]
            .as_symbol()
            .map(crate::typed::Symbol::as_str)
        {
            Some("updated") => AlignmentDisposition::Updated,
            Some("invalidated") => AlignmentDisposition::Invalidated,
            _ => {
                return Err(type_error(
                    &path.index(2),
                    "updated or invalidated alignment",
                ));
            }
        };
        let provenance = CorrectionProvenance {
            actor,
            edit,
            alignment,
        };
        provenance
            .validate()
            .map_err(|message| invalid_interval(path, message))?;
        Ok(provenance)
    }
}

fn expect_record<'a>(
    value: &'a crate::typed::Value,
    label: &str,
    path: &crate::problem::Path,
) -> Result<&'a crate::typed::Record, crate::problem::Diagnostic> {
    let record = value.as_record().ok_or_else(|| type_error(path, label))?;
    if record.label() != &crate::typed::Value::symbol(label) {
        return Err(type_error(path, label));
    }
    Ok(record)
}

fn type_error(path: &crate::problem::Path, expected: &str) -> crate::problem::Diagnostic {
    crate::problem::Diagnostic::new(
        crate::problem::Stage::Domain,
        crate::problem::ErrorCode::TypeMismatch,
        path.clone(),
        format!("expected {expected}"),
    )
}

fn invalid_interval(path: &crate::problem::Path, message: &str) -> crate::problem::Diagnostic {
    crate::problem::Diagnostic::new(
        crate::problem::Stage::Domain,
        crate::problem::ErrorCode::InvalidInterval,
        path.clone(),
        message,
    )
}

fn unsigned(value: &crate::typed::Value) -> Option<u64> {
    use num_traits::ToPrimitive;
    value
        .as_integer()
        .and_then(|integer| integer.as_bigint().to_u64())
}

fn u32_value(value: &crate::typed::Value) -> Option<u32> {
    use num_traits::ToPrimitive;
    value
        .as_integer()
        .and_then(|integer| integer.as_bigint().to_u32())
}

fn positive_u32(value: &crate::typed::Value) -> Option<u32> {
    u32_value(value).filter(|value| *value > 0)
}

fn finite_double(value: &crate::typed::Value) -> Option<f64> {
    value
        .as_double()
        .map(crate::typed::Double::value)
        .filter(|value| value.is_finite())
}

/// Validate a bounded sequence of provider scores.
pub fn validate_scores(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    let items = value
        .as_sequence()
        .ok_or_else(|| type_error(path, "recognition score sequence"))?;
    if items.len() > 128 {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::LimitExceeded,
            path.clone(),
            "recognition scores exceed the 128-item bound",
        ));
    }
    for (index, item) in items.iter().enumerate() {
        RecognitionScore::from_value(item, &path.index(index))?;
    }
    Ok(())
}

/// Validate a bounded sequence of provider alternatives.
pub fn validate_alternatives(
    value: &crate::typed::Value,
    path: &crate::problem::Path,
) -> Result<(), crate::problem::Diagnostic> {
    let items = value
        .as_sequence()
        .ok_or_else(|| type_error(path, "recognition alternative sequence"))?;
    if items.len() > 128 {
        return Err(crate::problem::Diagnostic::new(
            crate::problem::Stage::Domain,
            crate::problem::ErrorCode::LimitExceeded,
            path.clone(),
            "recognition alternatives exceed the 128-item bound",
        ));
    }
    for (index, item) in items.iter().enumerate() {
        RecognitionAlternative::from_value(item, &path.index(index))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_locations_roundtrip_with_units_and_extent_bounds() {
        let time_base = TimeBase::new(1, 48_000).expect("time base");
        let audio = MediaLocation::Audio {
            start_tick: 100,
            end_tick: 200,
            time_base,
            channel: 1,
        };
        let decoded = MediaLocation::from_value(&audio.to_value(), &crate::problem::Path::root())
            .expect("audio location");
        assert_eq!(decoded, audio);
        assert!(
            audio
                .validate_extent(MediaExtent::Audio {
                    duration_ticks: 400,
                    time_base,
                    channels: 2
                })
                .is_ok()
        );
        assert!(
            audio
                .validate_extent(MediaExtent::Audio {
                    duration_ticks: 199,
                    time_base,
                    channels: 2
                })
                .is_err()
        );

        let region = MediaLocation::PageRegion {
            page: 0,
            frame: CoordinateFrame::Pixels {
                width: 400,
                height: 300,
            },
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 80.0,
        };
        assert_eq!(
            MediaLocation::from_value(&region.to_value(), &crate::problem::Path::root())
                .expect("page region"),
            region
        );
        assert!(
            region
                .validate_extent(MediaExtent::Pages { page_count: 1 })
                .is_ok()
        );
    }

    #[test]
    fn media_locations_refuse_non_finite_or_out_of_frame_geometry() {
        let invalid = MediaLocation::PageRegion {
            page: 0,
            frame: CoordinateFrame::Normalized,
            x: 0.8,
            y: 0.1,
            width: 0.3,
            height: 0.2,
        };
        assert!(invalid.validate().is_err());
        let mut encoded = invalid.to_value();
        let record = encoded.as_record().expect("record");
        let mut fields = record.fields().to_vec();
        fields[3] = crate::typed::Value::double(f64::INFINITY);
        encoded = crate::typed::Value::record_named("media-location", fields);
        assert!(MediaLocation::from_value(&encoded, &crate::problem::Path::root()).is_err());
    }

    #[test]
    fn transformed_source_mapping_roundtrips_crop_and_resample() {
        let from = CoordinateFrame::Pixels {
            width: 100,
            height: 50,
        };
        let to = CoordinateFrame::Pixels {
            width: 400,
            height: 300,
        };
        let transform = MediaTransform::new(from, to, [2.0, 0.0, 20.0, 0.0, 2.0, 10.0])
            .expect("crop and resample map");
        let decoded =
            MediaTransform::from_value(&transform.to_value(), &crate::problem::Path::root())
                .expect("transform");
        assert_eq!(decoded, transform);
        assert!(MediaTransform::new(from, to, [1.0, 0.0, 350.0, 0.0, 1.0, 0.0]).is_err());
    }

    #[test]
    fn ink_locations_bind_page_layer_and_unique_strokes() {
        let ink = MediaLocation::InkStrokes {
            page: 2,
            layer: "foreground".to_owned(),
            strokes: vec!["stroke-a".to_owned(), "stroke-b".to_owned()],
        };
        assert_eq!(
            MediaLocation::from_value(&ink.to_value(), &crate::problem::Path::root())
                .expect("ink location"),
            ink
        );
        assert!(
            ink.validate_extent(MediaExtent::InkPages { page_count: 3 })
                .is_ok()
        );
        let duplicate = MediaLocation::InkStrokes {
            page: 2,
            layer: "foreground".to_owned(),
            strokes: vec!["same".to_owned(), "same".to_owned()],
        };
        assert!(duplicate.validate().is_err());
    }

    fn region(frame: CoordinateFrame, x: f64, y: f64, size: f64) -> MediaLocation {
        MediaLocation::PageRegion {
            page: 0,
            frame,
            x,
            y,
            width: size,
            height: size,
        }
    }

    #[test]
    fn a_page_region_must_use_its_sources_frame_or_normalized_coordinates() {
        let pages = MediaExtent::Pages { page_count: 1 };
        let image = CoordinateFrame::Pixels {
            width: 400,
            height: 300,
        };
        let oversized = CoordinateFrame::Pixels {
            width: 10_000,
            height: 10_000,
        };
        assert!(
            region(image, 10.0, 10.0, 20.0)
                .validate_source(pages, Some(image), None)
                .is_ok()
        );
        assert!(
            region(oversized, 5_000.0, 10.0, 20.0)
                .validate_source(pages, Some(image), None)
                .is_err(),
            "a region in a frame larger than the image is refused"
        );
        let normalized = region(CoordinateFrame::Normalized, 0.25, 0.25, 0.5);
        assert!(normalized.validate_source(pages, Some(image), None).is_ok());
        assert!(normalized.validate_source(pages, None, None).is_ok());
        assert!(
            region(image, 10.0, 10.0, 20.0)
                .validate_source(pages, None, None)
                .is_err(),
            "without a declared frame only normalized regions can be checked"
        );
    }

    #[test]
    fn ink_strokes_must_be_declared_by_their_source() {
        let pages = MediaExtent::InkPages { page_count: 2 };
        let inventory =
            InkInventory::new([(1, "pen".to_owned(), vec!["s1".to_owned(), "s2".to_owned()])])
                .expect("inventory");
        let strokes = |page: u32, layer: &str, ids: &[&str]| MediaLocation::InkStrokes {
            page,
            layer: layer.to_owned(),
            strokes: ids.iter().map(|id| (*id).to_owned()).collect(),
        };
        assert!(
            strokes(1, "pen", &["s2"])
                .validate_source(pages, None, Some(&inventory))
                .is_ok()
        );
        for refused in [
            strokes(1, "pen", &["s3"]),
            strokes(0, "pen", &["s1"]),
            strokes(1, "marker", &["s1"]),
        ] {
            assert!(
                refused
                    .validate_source(pages, None, Some(&inventory))
                    .is_err()
            );
        }
        assert!(
            strokes(1, "pen", &["s1"])
                .validate_source(pages, None, None)
                .is_err()
        );
        let decoded =
            InkInventory::from_value(&inventory.to_value(), &crate::problem::Path::root())
                .expect("inventory roundtrip");
        assert_eq!(decoded, inventory);
        assert!(
            InkInventory::new([
                (0, "pen".to_owned(), vec!["s1".to_owned()]),
                (0, "pen".to_owned(), vec!["s2".to_owned()]),
            ])
            .is_err(),
            "a layer is declared once per page"
        );
    }

    #[test]
    fn a_processed_region_maps_onto_the_original() {
        let processed = CoordinateFrame::Pixels {
            width: 200,
            height: 150,
        };
        let original = CoordinateFrame::Pixels {
            width: 400,
            height: 300,
        };
        let transform =
            MediaTransform::new(processed, original, [2.0, 0.0, 0.0, 0.0, 2.0, 0.0]).expect("2x");
        assert_eq!(
            transform.map_region(&region(processed, 10.0, 20.0, 30.0)),
            Some(region(original, 20.0, 40.0, 60.0))
        );
        assert_eq!(
            transform.map_region(&region(CoordinateFrame::Normalized, 0.5, 0.0, 0.5)),
            Some(MediaLocation::PageRegion {
                page: 0,
                frame: original,
                x: 200.0,
                y: 0.0,
                width: 200.0,
                height: 150.0,
            })
        );
        assert_eq!(
            transform.map_region(&region(original, 10.0, 10.0, 10.0)),
            None,
            "a region in another frame does not map"
        );
    }

    #[test]
    fn acquisition_correction_and_coverage_are_typed() {
        for acquisition in [
            Acquisition::Authored,
            Acquisition::Imported,
            Acquisition::Captured,
            Acquisition::MachineRecognized,
            Acquisition::Corrected,
        ] {
            assert_eq!(
                Acquisition::from_value(&acquisition.to_value(), &crate::problem::Path::root())
                    .expect("acquisition"),
                acquisition
            );
        }
        let corrected = CorrectionProvenance::new(
            "editor",
            "replace mistaken word",
            AlignmentDisposition::Invalidated,
        )
        .expect("correction");
        assert_eq!(
            CorrectionProvenance::from_value(&corrected.to_value(), &crate::problem::Path::root())
                .expect("decode correction"),
            corrected
        );
        let coverage = RecognitionCoverage::new(3, 4).expect("coverage");
        assert!(
            RecognitionStatus::Partial
                .validate_coverage(coverage)
                .is_ok()
        );
        assert!(
            RecognitionStatus::Complete
                .validate_coverage(coverage)
                .is_err()
        );
    }
}
