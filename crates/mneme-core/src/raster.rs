//! Bounded recognition page provenance. These are raster-processing frames,
//! not an assertion that every word or region of the original was detected.

mod codec;
#[cfg(test)]
mod tests;

const MAX_REGIONS: usize = 128;
const COVERAGE_BASIS: &str = "detected-blocks-not-exhaustive-page";

/// A worker's strict page report, admitted with its optional reported coverage.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RecognitionPageReport {
    index: u32,
    source_width: u32,
    source_height: u32,
    processed_width: u32,
    processed_height: u32,
    orientation_ccw_degrees: u32,
    #[serde(rename = "nonlinear-unwarping")]
    has_nonlinear_unwarping: bool,
    coverage_basis: String,
    missing: Vec<RecognitionRegion>,
    detections: Vec<RecognitionRegion>,
}

/// Exact page frames, inverse orientation and unread/detected regions retained
/// on a machine run. Missing detected coverage stays unknown, not a fake 0/0.
#[derive(Clone, Debug, PartialEq)]
pub struct RecognitionPage {
    report: RecognitionPageReport,
    reported_coverage: Option<crate::RecognitionCoverage>,
}

/// A provider region without invented words, confidence or interpretation.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecognitionRegion {
    identity: String,
    label: String,
    order: Option<u32>,
    region: Geometry,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Geometry {
    kind: Shape,
    frame: Units,
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Deserialize)]
enum Shape {
    #[serde(rename = "region")]
    Rectangle,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Deserialize)]
enum Units {
    #[serde(rename = "normalized")]
    Fraction,
}

impl RecognitionPageReport {
    /// Preserve whether block coverage was actually supplied by the worker.
    pub fn bind(
        self,
        reported_coverage: Option<crate::RecognitionCoverage>,
    ) -> Result<RecognitionPage, &'static str> {
        let page = RecognitionPage {
            report: self,
            reported_coverage,
        };
        page.validate()?;
        Ok(page)
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.has_nonlinear_unwarping || self.coverage_basis != COVERAGE_BASIS {
            return Err("page provenance requires a non-exhaustive, invertible raster map");
        }
        let source = (self.source_width, self.source_height);
        if source.0 == 0 || source.1 == 0 {
            return Err("recognition raster dimensions must be positive");
        }
        let expected = match self.orientation_ccw_degrees {
            0 | 180 => source,
            90 | 270 => (source.1, source.0),
            _ => return Err("page orientation must be an exact quarter turn"),
        };
        if (self.processed_width, self.processed_height) != expected {
            return Err("recognition raster dimensions disagree with orientation");
        }
        validate_regions(&self.missing, self.index)?;
        validate_regions(&self.detections, self.index)
    }
}

impl RecognitionPage {
    pub const fn index(&self) -> u32 {
        self.report.index
    }
    pub const fn source_dimensions(&self) -> (u32, u32) {
        (self.report.source_width, self.report.source_height)
    }
    pub const fn processed_dimensions(&self) -> (u32, u32) {
        (self.report.processed_width, self.report.processed_height)
    }
    pub const fn orientation_ccw_degrees(&self) -> u32 {
        self.report.orientation_ccw_degrees
    }
    pub const fn has_nonlinear_unwarping(&self) -> bool {
        self.report.has_nonlinear_unwarping
    }
    pub fn coverage_basis(&self) -> &str {
        &self.report.coverage_basis
    }
    pub fn missing(&self) -> &[RecognitionRegion] {
        &self.report.missing
    }
    pub fn detections(&self) -> &[RecognitionRegion] {
        &self.report.detections
    }
    pub const fn reported_coverage(&self) -> Option<crate::RecognitionCoverage> {
        self.reported_coverage
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        self.report.validate()?;
        let missing = u64::try_from(self.missing().len()).map_err(|_| "too many unread regions")?;
        match self.reported_coverage {
            Some(coverage)
                if usize::try_from(coverage.completed())
                    .is_ok_and(|count| count <= MAX_REGIONS)
                    && coverage.completed().checked_add(missing) == Some(coverage.total()) =>
            {
                Ok(())
            }
            Some(_) => Err("reported block coverage disagrees with unread regions"),
            None if missing == 0 => Ok(()),
            None => Err("unread detected regions need explicit partial coverage"),
        }
    }

    /// The v1 page protocol publishes one aligned segment per readable block.
    /// No-detection reports omit block coverage; a legacy unit's 1/1 is not a
    /// claim that one block was detected or that the page is blank.
    pub fn validate_result(
        &self,
        (coverage, status): (crate::RecognitionCoverage, crate::RecognitionStatus),
        covers: crate::CapturePart,
        segments: u64,
    ) -> Result<(), &'static str> {
        self.validate()?;
        status.validate_coverage(coverage)?;
        let has_page = match covers {
            crate::CapturePart::Page(page) | crate::CapturePart::Region { page, .. } => {
                page == self.index()
            }
            crate::CapturePart::Whole => self.index() == 0,
            crate::CapturePart::Audio { .. } => false,
        };
        if !has_page {
            return Err("page provenance names another part of the capture");
        }
        match self.reported_coverage {
            Some(reported) if reported == coverage && reported.completed() == segments => Ok(()),
            Some(_) => Err("page coverage does not match its readable block segments"),
            None if segments == 0 && self.detections().is_empty() => Ok(()),
            None => Err("a page with detected or readable blocks needs reported coverage"),
        }
    }

    pub fn validate_source(
        &self,
        extent: crate::MediaExtent,
        frame: Option<crate::CoordinateFrame>,
        covers: crate::CapturePart,
    ) -> Result<(), &'static str> {
        let count = match extent {
            crate::MediaExtent::Pages { page_count }
            | crate::MediaExtent::InkPages { page_count } => page_count,
            crate::MediaExtent::Audio { .. } => {
                return Err("page provenance cannot describe an audio capture");
            }
        };
        if self.index() >= count || (covers == crate::CapturePart::Whole && count != 1) {
            return Err("page provenance is outside the selected original page");
        }
        if matches!(extent, crate::MediaExtent::Pages { .. })
            && let Some(crate::CoordinateFrame::Pixels { width, height }) = frame
            && (width, height) != self.source_dimensions()
        {
            return Err("recognition raster dimensions disagree with the retained image frame");
        }
        Ok(())
    }
}

impl RecognitionRegion {
    pub fn identity(&self) -> &str {
        &self.identity
    }
    pub fn label(&self) -> &str {
        &self.label
    }
    pub const fn order(&self) -> Option<u32> {
        self.order
    }
    pub fn location(&self, page: u32) -> crate::MediaLocation {
        crate::MediaLocation::PageRegion {
            page,
            frame: crate::CoordinateFrame::Normalized,
            x: self.region.x,
            y: self.region.y,
            width: self.region.width,
            height: self.region.height,
        }
    }
}

fn validate_regions(regions: &[RecognitionRegion], page: u32) -> Result<(), &'static str> {
    if regions.len() > MAX_REGIONS {
        return Err("recognition page has more than 128 regions in one role");
    }
    let mut identities = std::collections::BTreeSet::new();
    for region in regions {
        crate::layout::validate_identity_label(region.identity(), region.label())?;
        if !identities.insert(region.identity()) {
            return Err("recognition region identities must be unique within their role");
        }
        region.location(page).validate()?;
    }
    Ok(())
}
