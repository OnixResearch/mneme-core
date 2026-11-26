//! Unit/property tests for `mneme_kernel::temporal`.
#![allow(unknown_lints, no_unwrap)] // test/fixture code fails by panic, not a production path
#![allow(clippy::unwrap_used, clippy::expect_used)] // test/fixture code fails by panic, not a production path

#[test]
fn half_open_period_membership_and_legacy_instant_decoding() {
    let period = mneme_kernel::temporal::Period {
        start: 100,
        stop: 200,
    };
    assert!(mneme_kernel::temporal::is_valid(period));
    assert!(!mneme_kernel::temporal::contains(period, 99));
    assert!(mneme_kernel::temporal::contains(period, 100));
    assert!(mneme_kernel::temporal::contains(period, 199));
    assert!(!mneme_kernel::temporal::contains(period, 200));

    let instant = mneme_kernel::temporal::from_legacy_bounds(Some(500), Some(500))
        .expect("legacy instant decodes");
    assert_eq!(instant.start, 500);
    assert_eq!(instant.stop, 501);
    assert!(!mneme_kernel::temporal::contains(instant, 499));
    assert!(mneme_kernel::temporal::contains(instant, 500));
    assert!(!mneme_kernel::temporal::contains(instant, 501));

    assert_eq!(
        mneme_kernel::temporal::from_legacy_bounds(Some(600), Some(500)),
        None
    );
    let always = mneme_kernel::temporal::from_legacy_bounds(None, None).expect("always");
    assert_eq!(always.start, mneme_kernel::temporal::NEG_INF);
    assert_eq!(always.stop, mneme_kernel::temporal::POS_INF);
}

#[test]
fn intersect_monoid_laws_and_empty_annihilation() {
    let a = Some(mneme_kernel::temporal::Period {
        start: 10,
        stop: 50,
    });
    let b = Some(mneme_kernel::temporal::Period {
        start: 20,
        stop: 40,
    });
    let c = Some(mneme_kernel::temporal::Period {
        start: 30,
        stop: 60,
    });
    assert_eq!(mneme_kernel::temporal::intersect_option(None, a), None);
    assert_eq!(mneme_kernel::temporal::intersect_option(a, None), None);
    assert_eq!(
        mneme_kernel::temporal::intersect_option(a, b),
        mneme_kernel::temporal::intersect_option(b, a)
    );
    let left_assoc =
        mneme_kernel::temporal::intersect_option(mneme_kernel::temporal::intersect_option(a, b), c);
    let right_assoc =
        mneme_kernel::temporal::intersect_option(a, mneme_kernel::temporal::intersect_option(b, c));
    assert_eq!(left_assoc, right_assoc);
    assert_eq!(
        left_assoc,
        Some(mneme_kernel::temporal::Period {
            start: 30,
            stop: 40,
        })
    );
}

#[test]
fn coalesce_sorted_preserves_snapshots_and_is_idempotent() {
    let original = [
        mneme_kernel::temporal::Period { start: 0, stop: 10 },
        mneme_kernel::temporal::Period {
            start: 10,
            stop: 20,
        },
        mneme_kernel::temporal::Period {
            start: 15,
            stop: 25,
        },
        mneme_kernel::temporal::Period {
            start: 25,
            stop: 25,
        },
        mneme_kernel::temporal::Period {
            start: 30,
            stop: 40,
        },
    ];
    let mut work = original;
    let len = mneme_kernel::temporal::coalesce_sorted(&mut work);
    assert_eq!(len, 2);
    let coalesced = mneme_kernel::temporal::IntervalSet {
        periods: &work[..len],
    };
    assert!(mneme_kernel::temporal::interval_set_is_coalesced(coalesced));
    assert_eq!(
        work[..len],
        [
            mneme_kernel::temporal::Period { start: 0, stop: 25 },
            mneme_kernel::temporal::Period {
                start: 30,
                stop: 40,
            },
        ]
    );
    let orig_set = mneme_kernel::temporal::IntervalSet { periods: &original };
    for t in -5_i128..=45_i128 {
        assert_eq!(
            mneme_kernel::temporal::interval_set_contains(orig_set, t),
            mneme_kernel::temporal::interval_set_contains(coalesced, t)
        );
    }
    let mut second = [work[0], work[1]];
    let len2 = mneme_kernel::temporal::coalesce_sorted(&mut second);
    assert_eq!(len2, 2);
    assert_eq!(second, [work[0], work[1]]);
}

#[test]
fn allen_13_relations_and_fail_closed_unknown() {
    let base = mneme_kernel::temporal::Period {
        start: 10,
        stop: 20,
    };
    let cases = [
        (
            mneme_kernel::temporal::Period {
                start: 25,
                stop: 30,
            },
            mneme_kernel::temporal::AllenRelation::Before,
        ),
        (
            mneme_kernel::temporal::Period {
                start: 20,
                stop: 30,
            },
            mneme_kernel::temporal::AllenRelation::Meets,
        ),
        (
            mneme_kernel::temporal::Period {
                start: 15,
                stop: 25,
            },
            mneme_kernel::temporal::AllenRelation::Overlaps,
        ),
        (
            mneme_kernel::temporal::Period {
                start: 15,
                stop: 20,
            },
            mneme_kernel::temporal::AllenRelation::FinishedBy,
        ),
        (
            mneme_kernel::temporal::Period {
                start: 12,
                stop: 18,
            },
            mneme_kernel::temporal::AllenRelation::Contains,
        ),
        (
            mneme_kernel::temporal::Period {
                start: 10,
                stop: 25,
            },
            mneme_kernel::temporal::AllenRelation::Starts,
        ),
        (
            mneme_kernel::temporal::Period {
                start: 10,
                stop: 20,
            },
            mneme_kernel::temporal::AllenRelation::Equals,
        ),
        (
            mneme_kernel::temporal::Period {
                start: 10,
                stop: 15,
            },
            mneme_kernel::temporal::AllenRelation::StartedBy,
        ),
        (
            mneme_kernel::temporal::Period { start: 5, stop: 25 },
            mneme_kernel::temporal::AllenRelation::During,
        ),
        (
            mneme_kernel::temporal::Period { start: 5, stop: 20 },
            mneme_kernel::temporal::AllenRelation::Finishes,
        ),
        (
            mneme_kernel::temporal::Period { start: 5, stop: 15 },
            mneme_kernel::temporal::AllenRelation::OverlappedBy,
        ),
        (
            mneme_kernel::temporal::Period { start: 5, stop: 10 },
            mneme_kernel::temporal::AllenRelation::MetBy,
        ),
        (
            mneme_kernel::temporal::Period { start: 0, stop: 5 },
            mneme_kernel::temporal::AllenRelation::After,
        ),
    ];
    for (other, expected) in cases {
        assert_eq!(
            mneme_kernel::temporal::allen_relation(base, other),
            Some(expected)
        );
        assert!(mneme_kernel::temporal::allen_holds(
            mneme_kernel::temporal::Validity::Known(base),
            mneme_kernel::temporal::Validity::Known(other),
            expected,
        ));
    }

    let window = mneme_kernel::temporal::MetricWindow {
        lower: 0,
        upper: 10,
    };
    assert!(!mneme_kernel::temporal::validity_contains(
        mneme_kernel::temporal::Validity::Unknown,
        15,
    ));
    assert_eq!(
        mneme_kernel::temporal::expire_bounds(mneme_kernel::temporal::Validity::Unknown, 15),
        mneme_kernel::temporal::ExpiryDecision::UnknownValidity
    );
    assert!(!mneme_kernel::temporal::allen_holds(
        mneme_kernel::temporal::Validity::Unknown,
        mneme_kernel::temporal::Validity::Known(base),
        mneme_kernel::temporal::AllenRelation::Equals,
    ));
    assert_eq!(
        mneme_kernel::temporal::diamond_minus(mneme_kernel::temporal::Validity::Unknown, window),
        None
    );
    assert_eq!(
        mneme_kernel::temporal::box_minus(mneme_kernel::temporal::Validity::Unknown, window),
        None
    );
    assert_eq!(
        mneme_kernel::temporal::since(
            mneme_kernel::temporal::Validity::Unknown,
            mneme_kernel::temporal::Validity::Known(base),
            window,
        ),
        None
    );
    assert_eq!(
        mneme_kernel::temporal::since(
            mneme_kernel::temporal::Validity::Known(base),
            mneme_kernel::temporal::Validity::Unknown,
            window,
        ),
        None
    );
}
