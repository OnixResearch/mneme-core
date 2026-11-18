fn report() -> super::RecognitionPageReport {
    serde_json::from_value(serde_json::json!({
        "index":2,"source-width":100,"source-height":200,
        "processed-width":200,"processed-height":100,
        "orientation-ccw-degrees":90,"nonlinear-unwarping":false,
        "coverage-basis":"detected-blocks-not-exhaustive-page",
        "missing":[{"identity":"block-2","label":"formula","order":null,
            "region":{"kind":"region","frame":"normalized","x":0.2,"y":0.3,"width":0.1,"height":0.2}}],
        "detections":[]
    })).expect("strict report")
}

#[test]
fn unread_regions_roundtrip_without_words_scores_or_invented_order() {
    let coverage = crate::RecognitionCoverage::new(0, 1).expect("coverage");
    let page = report().bind(Some(coverage)).expect("page");
    let decoded =
        super::RecognitionPage::from_value(&page.to_value(), &crate::Path::root()).expect("decode");
    assert_eq!(decoded, page);
    assert_eq!(decoded.source_dimensions(), (100, 200));
    assert_eq!(decoded.processed_dimensions(), (200, 100));
    assert_eq!(decoded.missing()[0].identity(), "block-2");
    assert_eq!(decoded.missing()[0].order(), None);
    assert_eq!(decoded.reported_coverage(), Some(coverage));
    assert!(
        decoded
            .validate_result(
                (coverage, crate::RecognitionStatus::Partial),
                crate::CapturePart::Page(2),
                0
            )
            .is_ok()
    );
}

#[test]
fn no_detections_preserve_unknown_block_coverage_and_do_not_certify_blankness() {
    let mut report = report();
    report.missing.clear();
    let page = report.bind(None).expect("unknown block coverage");
    let decoded =
        super::RecognitionPage::from_value(&page.to_value(), &crate::Path::root()).expect("decode");
    assert_eq!(decoded.reported_coverage(), None);
    assert_eq!(decoded.coverage_basis(), super::COVERAGE_BASIS);
    let unit = crate::RecognitionCoverage::new(1, 1).expect("processed unit");
    assert!(
        decoded
            .validate_result(
                (unit, crate::RecognitionStatus::Complete),
                crate::CapturePart::Page(2),
                0
            )
            .is_ok()
    );
    assert!(
        decoded
            .validate_result(
                (unit, crate::RecognitionStatus::Complete),
                crate::CapturePart::Page(2),
                1
            )
            .is_err()
    );
}

#[test]
fn malformed_geometry_dimensions_identity_and_coverage_never_bind() {
    let missing = crate::RecognitionCoverage::new(0, 1).expect("coverage");
    assert!(report().bind(None).is_err());
    assert!(
        report()
            .bind(Some(
                crate::RecognitionCoverage::new(1, 1).expect("coverage")
            ))
            .is_err()
    );
    let mut changed = report();
    changed.orientation_ccw_degrees = 45;
    assert!(changed.bind(Some(missing)).is_err());
    changed = report();
    changed.processed_height = 101;
    assert!(changed.bind(Some(missing)).is_err());
    changed = report();
    changed.has_nonlinear_unwarping = true;
    assert!(changed.bind(Some(missing)).is_err());
    changed = report();
    changed.missing[0].region.x = f64::NAN;
    assert!(changed.bind(Some(missing)).is_err());
    changed = report();
    changed.missing.push(changed.missing[0].clone());
    assert!(
        changed
            .bind(Some(
                crate::RecognitionCoverage::new(0, 2).expect("coverage")
            ))
            .is_err()
    );
    let page = report().bind(Some(missing)).expect("page");
    assert!(
        page.validate_source(
            crate::MediaExtent::Pages { page_count: 2 },
            None,
            crate::CapturePart::Page(2)
        )
        .is_err()
    );
    assert!(
        page.validate_source(
            crate::MediaExtent::Pages { page_count: 3 },
            Some(crate::CoordinateFrame::Pixels {
                width: 101,
                height: 200
            }),
            crate::CapturePart::Page(2)
        )
        .is_err()
    );
    assert!(
        page.validate_result(
            (missing, crate::RecognitionStatus::Partial),
            crate::CapturePart::Page(1),
            0
        )
        .is_err()
    );
}
