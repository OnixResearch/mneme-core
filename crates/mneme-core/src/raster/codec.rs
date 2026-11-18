//! Canonical typed records; no opaque JSON or fabricated missing counts.

impl super::RecognitionPage {
    pub fn to_value(&self) -> crate::Value {
        let source = self.source_dimensions();
        let processed = self.processed_dimensions();
        crate::Value::record_named(
            "recognition-page-v1",
            vec![
                crate::Value::integer(self.index()),
                crate::CoordinateFrame::Pixels {
                    width: source.0,
                    height: source.1,
                }
                .to_value(),
                crate::CoordinateFrame::Pixels {
                    width: processed.0,
                    height: processed.1,
                }
                .to_value(),
                crate::Value::integer(self.orientation_ccw_degrees()),
                crate::Value::Boolean(self.has_nonlinear_unwarping()),
                crate::Value::symbol(self.coverage_basis()),
                regions_value(self.missing(), self.index()),
                regions_value(self.detections(), self.index()),
                self.reported_coverage().map_or_else(
                    || crate::Value::symbol("none"),
                    crate::RecognitionCoverage::to_value,
                ),
            ],
        )
    }

    pub fn from_value(value: &crate::Value, path: &crate::Path) -> Result<Self, crate::Diagnostic> {
        let fields = record_fields(value, "recognition-page-v1", 9, path)?;
        let source = dimensions(&fields[1], &path.index(1))?;
        let processed = dimensions(&fields[2], &path.index(2))?;
        let index = unsigned(&fields[0], &path.index(0))?;
        let report = super::RecognitionPageReport {
            index,
            source_width: source.0,
            source_height: source.1,
            processed_width: processed.0,
            processed_height: processed.1,
            orientation_ccw_degrees: unsigned(&fields[3], &path.index(3))?,
            has_nonlinear_unwarping: fields[4]
                .as_boolean()
                .ok_or_else(|| invalid(&path.index(4), "expected an unwarping boolean"))?,
            coverage_basis: fields[5]
                .as_symbol()
                .ok_or_else(|| invalid(&path.index(5), "expected a coverage basis"))?
                .as_str()
                .to_owned(),
            missing: regions(&fields[6], index, &path.index(6))?,
            detections: regions(&fields[7], index, &path.index(7))?,
        };
        let coverage = if is_none(&fields[8]) {
            None
        } else {
            Some(crate::RecognitionCoverage::from_value(
                &fields[8],
                &path.index(8),
            )?)
        };
        report
            .bind(coverage)
            .map_err(|message| invalid(path, message))
    }
}

fn regions_value(regions: &[super::RecognitionRegion], page: u32) -> crate::Value {
    crate::Value::sequence(
        regions
            .iter()
            .map(|region| {
                crate::Value::record_named(
                    "recognition-region",
                    vec![
                        crate::Value::string(region.identity().to_owned()),
                        crate::Value::string(region.label().to_owned()),
                        region
                            .order()
                            .map_or_else(|| crate::Value::symbol("none"), crate::Value::integer),
                        region.location(page).to_value(),
                    ],
                )
            })
            .collect(),
    )
}

fn regions(
    value: &crate::Value,
    page: u32,
    path: &crate::Path,
) -> Result<Vec<super::RecognitionRegion>, crate::Diagnostic> {
    let values = value
        .as_sequence()
        .filter(|values| values.len() <= super::MAX_REGIONS)
        .ok_or_else(|| invalid(path, "expected at most 128 recognition regions"))?;
    values
        .iter()
        .enumerate()
        .map(|(index, value)| region(value, page, &path.index(index)))
        .collect()
}

fn region(
    value: &crate::Value,
    page: u32,
    path: &crate::Path,
) -> Result<super::RecognitionRegion, crate::Diagnostic> {
    let fields = record_fields(value, "recognition-region", 4, path)?;
    let location = crate::MediaLocation::from_value(&fields[3], &path.index(3))?;
    let geometry = match location {
        crate::MediaLocation::PageRegion {
            page: located,
            frame: crate::CoordinateFrame::Normalized,
            x,
            y,
            width,
            height,
        } if located == page => super::Geometry {
            kind: super::Shape::Rectangle,
            frame: super::Units::Fraction,
            x,
            y,
            width,
            height,
        },
        crate::MediaLocation::PageRegion { .. }
        | crate::MediaLocation::Audio { .. }
        | crate::MediaLocation::InkStrokes { .. } => {
            return Err(invalid(
                path,
                "expected a normalized region of the report's page",
            ));
        }
    };
    Ok(super::RecognitionRegion {
        identity: fields[0]
            .as_string()
            .ok_or_else(|| invalid(&path.index(0), "expected a region identity"))?
            .to_owned(),
        label: fields[1]
            .as_string()
            .ok_or_else(|| invalid(&path.index(1), "expected a region label"))?
            .to_owned(),
        order: if is_none(&fields[2]) {
            None
        } else {
            Some(unsigned(&fields[2], &path.index(2))?)
        },
        region: geometry,
    })
}

fn record_fields<'a>(
    value: &'a crate::Value,
    label: &str,
    count: usize,
    path: &crate::Path,
) -> Result<&'a [crate::Value], crate::Diagnostic> {
    value
        .as_record()
        .filter(|record| {
            record.label() == &crate::Value::symbol(label) && record.fields().len() == count
        })
        .map(crate::typed::Record::fields)
        .ok_or_else(|| invalid(path, "expected a versioned recognition metadata tuple"))
}

fn dimensions(value: &crate::Value, path: &crate::Path) -> Result<(u32, u32), crate::Diagnostic> {
    match crate::CoordinateFrame::from_value(value, path)? {
        crate::CoordinateFrame::Pixels { width, height } => Ok((width, height)),
        crate::CoordinateFrame::Normalized | crate::CoordinateFrame::PagePoints { .. } => Err(
            invalid(path, "recognition raster dimensions must use pixels"),
        ),
    }
}

fn unsigned(value: &crate::Value, path: &crate::Path) -> Result<u32, crate::Diagnostic> {
    use num_traits::ToPrimitive;
    value
        .as_integer()
        .and_then(|integer| integer.as_bigint().to_u32())
        .ok_or_else(|| invalid(path, "expected an unsigned page metadata integer"))
}

fn is_none(value: &crate::Value) -> bool {
    value
        .as_symbol()
        .is_some_and(|symbol| symbol.as_str() == "none")
}

fn invalid(path: &crate::Path, message: &str) -> crate::Diagnostic {
    crate::Diagnostic::new(
        crate::Stage::Domain,
        crate::ErrorCode::TypeMismatch,
        path.clone(),
        message,
    )
}
