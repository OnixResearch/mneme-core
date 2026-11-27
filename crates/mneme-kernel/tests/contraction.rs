// Test helpers intentionally unwrap deterministic fixtures and assert exact kernel invariants.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[test]
fn entrenchment_order_respects_origin_roots_and_record_id() {
    let model_single = mneme_kernel::contraction::EntrenchmentKey {
        origin: mneme_kernel::contraction::OriginTier::ModelExtraction,
        root_count: 1,
        record_id: 0xFF,
    };
    let model_multi = mneme_kernel::contraction::EntrenchmentKey {
        origin: mneme_kernel::contraction::OriginTier::ModelExtraction,
        root_count: 3,
        record_id: 0x01,
    };
    let imported_single = mneme_kernel::contraction::EntrenchmentKey {
        origin: mneme_kernel::contraction::OriginTier::Imported,
        root_count: 1,
        record_id: 0x01,
    };
    let authored_lo = mneme_kernel::contraction::EntrenchmentKey {
        origin: mneme_kernel::contraction::OriginTier::Authored,
        root_count: 1,
        record_id: 0x01,
    };
    let authored_hi = mneme_kernel::contraction::EntrenchmentKey {
        origin: mneme_kernel::contraction::OriginTier::Authored,
        root_count: 1,
        record_id: 0x02,
    };

    assert_eq!(
        mneme_kernel::contraction::origin_rank(
            mneme_kernel::contraction::OriginTier::ModelExtraction
        ),
        0
    );
    assert_eq!(
        mneme_kernel::contraction::origin_rank(mneme_kernel::contraction::OriginTier::Imported),
        1
    );
    assert_eq!(
        mneme_kernel::contraction::origin_rank(mneme_kernel::contraction::OriginTier::Authored),
        2
    );

    let chain = [
        model_single,
        model_multi,
        imported_single,
        authored_lo,
        authored_hi,
    ];
    for i in 0..chain.len() {
        assert!(!mneme_kernel::contraction::less_entrenched(
            &chain[i], &chain[i]
        ));
        for j in (i.saturating_add(1))..chain.len() {
            assert!(mneme_kernel::contraction::less_entrenched(
                &chain[i], &chain[j]
            ));
            assert!(!mneme_kernel::contraction::less_entrenched(
                &chain[j], &chain[i]
            ));
        }
    }
}

#[test]
fn hansson_postulates_and_uniformity_hold() {
    let k1 = mneme_kernel::contraction::EntrenchmentKey {
        origin: mneme_kernel::contraction::OriginTier::Authored,
        root_count: 2,
        record_id: 10,
    };
    let k2 = mneme_kernel::contraction::EntrenchmentKey {
        origin: mneme_kernel::contraction::OriginTier::ModelExtraction,
        root_count: 1,
        record_id: 20,
    };
    let k3 = mneme_kernel::contraction::EntrenchmentKey {
        origin: mneme_kernel::contraction::OriginTier::Imported,
        root_count: 1,
        record_id: 30,
    };
    let base = [10_u128, 20, 30, 40];

    let members_a = [k1, k2, k2, k3];
    let spans_a = [
        mneme_kernel::contraction::RangeSpan { start: 0, len: 2 },
        mneme_kernel::contraction::RangeSpan { start: 2, len: 2 },
    ];
    // Reversed kernel order and reversed element order within each kernel.
    let members_b = [k3, k2, k2, k1];
    let spans_b = [
        mneme_kernel::contraction::RangeSpan { start: 0, len: 2 },
        mneme_kernel::contraction::RangeSpan { start: 2, len: 2 },
    ];

    assert!(!mneme_kernel::contraction::any_proof_survives(
        &base, &members_a, &spans_a
    ));
    assert!(mneme_kernel::contraction::is_incised(
        20, &members_a, &spans_a
    ));
    assert!(!mneme_kernel::contraction::is_incised(
        10, &members_a, &spans_a
    ));
    assert!(!mneme_kernel::contraction::is_incised(
        30, &members_a, &spans_a
    ));
    assert!(!mneme_kernel::contraction::is_incised(
        40, &members_a, &spans_a
    ));

    for id in [10_u128, 20, 30, 40, 99] {
        let is_surviving_a =
            mneme_kernel::contraction::survives_incision(id, &base, &members_a, &spans_a);
        let is_surviving_b =
            mneme_kernel::contraction::survives_incision(id, &base, &members_b, &spans_b);
        assert_eq!(is_surviving_a, is_surviving_b);
        if is_surviving_a {
            assert!(base.contains(&id));
        }
    }
    assert!(mneme_kernel::contraction::survives_incision(
        10, &base, &members_a, &spans_a
    ));
    assert!(mneme_kernel::contraction::survives_incision(
        40, &base, &members_a, &spans_a
    ));
    assert!(!mneme_kernel::contraction::survives_incision(
        20, &base, &members_a, &spans_a
    ));
}

#[test]
fn well_founded_grounding_never_grounds_self_supporting_cycle() {
    // Nodes: 0 = withdrawn root S, 1 = A, 2 = B, 3 = surviving root S2, 4 = C
    // Edges: S -> A, A -> B, B -> A, S2 -> C
    let premises = [0_usize, 1, 2, 3];
    let edges = [
        mneme_kernel::contraction::SupportEdge {
            target: 1,
            premises: mneme_kernel::contraction::RangeSpan { start: 0, len: 1 },
        },
        mneme_kernel::contraction::SupportEdge {
            target: 2,
            premises: mneme_kernel::contraction::RangeSpan { start: 1, len: 1 },
        },
        mneme_kernel::contraction::SupportEdge {
            target: 1,
            premises: mneme_kernel::contraction::RangeSpan { start: 2, len: 1 },
        },
        mneme_kernel::contraction::SupportEdge {
            target: 4,
            premises: mneme_kernel::contraction::RangeSpan { start: 3, len: 1 },
        },
    ];
    let mut grounded = [false, false, false, true, false];
    for _ in 0..grounded.len() {
        let next: Vec<bool> = (0..grounded.len())
            .map(|node| {
                mneme_kernel::contraction::node_next_grounded(node, &edges, &premises, &grounded)
            })
            .collect();
        grounded.copy_from_slice(&next);
    }
    assert!(!grounded[0]);
    assert!(!grounded[1]);
    assert!(!grounded[2]);
    assert!(grounded[3]);
    assert!(grounded[4]);
}
